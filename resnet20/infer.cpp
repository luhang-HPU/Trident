#include "infer.h"

#include "cnn.h"
#include "plain_cnn.h"

#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <chrono>
#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sstream>
#include <utility>
#include <vector>

using namespace std;
using namespace poseidon;

namespace fs = std::filesystem;

namespace
{

const fs::path kResNet20Root = fs::path(__FILE__).parent_path();
const fs::path kWeightsRoot = kResNet20Root / "pretrained_parameters";
const fs::path kDataRoot = kResNet20Root / "testFile";
const fs::path kReluParamRoot = kResNet20Root / "relu_param";
constexpr size_t kResNet20LayerNum = 20;
constexpr int kResNet20EndNum = 2;
constexpr const char *kResNet20ParameterDir = "resnet20_new";
constexpr const char *kResNet20ResultPrefix = "resnet20_cifar10";
constexpr double kBatchNormEpsilon = 1.0e-5;
constexpr bool kEnableBootstrap = true;

struct ReluConfig
{
    long comp_no = 0;
    vector<int> deg;
    long alpha = 0;
    vector<Tree> tree;
    double scaled_val = 0.0;
    long scalingfactor = 0;
    vector<vector<double>> plain_coeffs;
};

struct PoseidonStagePlan
{
    const char *name = "";
    int out_channels = 0;
    int block_count = 0;
    int first_block_stride = 1;
    uint32_t bootstrap_log_slots = 0;
};

struct PoseidonInferPlan
{
    double boundary = 40.0;
    long logN = 16;
    long log_slots = 15;
    long init_p = 8;
    int log_scale = 46;
    int remaining_level = 16;
    int boot_level = 14;
    vector<uint32_t> logq_chain;
    vector<PoseidonStagePlan> stages;
};

struct PoseidonRuntime
{
    PoseidonContext context;
    std::unique_ptr<EvaluatorCkksBase> evaluator;
    CKKSEncoder encoder;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    Encryptor encryptor;
    Decryptor decryptor;
    std::unique_ptr<EvalModPoly> bootstrap_poly;
    double scale = 0.0;
    int slot_count = 0;

    PoseidonRuntime(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva, PublicKey pk,
                    SecretKey sk, RelinKeys rk, GaloisKeys gk,
                    std::unique_ptr<EvalModPoly> poly, double scale_value)
        : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
          public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
          galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
          bootstrap_poly(std::move(poly)), scale(scale_value),
          slot_count(static_cast<int>(encoder.slot_count()))
    {
    }
};

vector<uint32_t> logq_chain()
{
    return {
        46, 46, 46, 46, 46, 46, 46, 46, 46, 
        46, 46, 46, 46, 46, 46, 46, 46, 46, 51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51};
}

fs::path result_dir()
{
    return fs::path(__FILE__).parent_path() / "result";
}

string make_run_timestamp()
{
    const auto now = chrono::system_clock::now();
    const auto time = chrono::system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif

    ostringstream stamp;
    stamp << put_time(&local_tm, "%Y%m%d_%H%M%S");
    return stamp.str();
}

vector<double> read_exact_values(const fs::path &path, size_t count)
{
    ifstream input(path);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open file: " + path.string());
    }

    vector<double> values;
    values.reserve(count);
    double value = 0.0;
    for (size_t i = 0; i < count; ++i)
    {
        if (!(input >> value))
        {
            throw std::runtime_error("failed to read expected number of values from: " + path.string());
        }
        values.emplace_back(value);
    }
    return values;
}

vector<double> read_image_slots(size_t image_id, long log_slots, long init_p, double boundary)
{
    ifstream input(kDataRoot / "test_values.txt");
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open CIFAR-10 test values");
    }

    const long total_slots = 1L << log_slots;
    vector<double> image(static_cast<size_t>(total_slots), 0.0);

    double value = 0.0;
    const size_t image_values = 32 * 32 * 3;
    for (size_t i = 0; i < image_values * image_id; ++i)
    {
        input >> value;
    }
    for (size_t i = 0; i < image_values; ++i)
    {
        input >> value;
        image[i] = value;
    }

    const long base_slots = total_slots / init_p;
    for (long i = base_slots; i < total_slots; ++i)
    {
        image[static_cast<size_t>(i)] = image[static_cast<size_t>(i % base_slots)];
    }
    for (double &slot : image)
    {
        slot /= boundary;
    }
    return image;
}

int read_image_label(size_t image_id)
{
    ifstream input(kDataRoot / "test_label.txt");
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open CIFAR-10 test labels");
    }

    int label = -1;
    for (size_t i = 0; i <= image_id; ++i)
    {
        if (!(input >> label))
        {
            throw std::runtime_error("failed to read CIFAR-10 test label");
        }
    }
    return label;
}

PoseidonInferPlan default_poseidon_plan()
{
    PoseidonInferPlan plan;
    plan.logq_chain = logq_chain();
    plan.stages = {
        {"stage1", 16, 3, 1, 14},
        {"stage2", 32, 3, 2, 13},
        {"stage3", 64, 3, 2, 12},
    };
    return plan;
}

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan)
{
    ParametersLiteral ckks_param_literal{
        CKKS, static_cast<uint32_t>(plan.logN), static_cast<uint32_t>(plan.logN - 1),
        static_cast<uint32_t>(plan.log_scale), 5, 1, 0, {}, {}};
    ckks_param_literal.set_log_modulus(plan.logq_chain, {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    auto bootstrap_poly = std::make_unique<EvalModPoly>(
        context, CosDiscrete, static_cast<uint64_t>(1) << 51, 1, 16, 3, 16, 0, 30);

    return PoseidonRuntime(std::move(context), std::move(evaluator), std::move(public_key),
                           keygen.secret_key(), std::move(relin_keys), std::move(galois_keys),
                           std::move(bootstrap_poly), ckks_param_literal.scale());
}

size_t cipher_chain_index(const PoseidonRuntime &runtime, const Ciphertext &cipher)
{
    auto context_data = runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

void log_stage_plan(ofstream &output, const PoseidonStagePlan &stage, int block_index)
{
    output << stage.name << " block " << block_index << ": conv1 -> bn1 -> bootstrap(log_slots="
           << stage.bootstrap_log_slots << ") -> relu -> conv2 -> bn2";
    if (stage.first_block_stride == 2 && block_index == 0)
    {
        output << " -> downsample shortcut";
    }
    output << " -> add -> bootstrap(log_slots=" << stage.bootstrap_log_slots
           << ") -> relu" << endl;
}

void log_plain_logits(const vector<double> &logits, ofstream &output)
{
    output << "plain logits:";
    for (double value : logits)
    {
        output << ' ' << value;
    }
    output << '\n';
}

vector<double> decode_real_slots(const TensorCipher &tensor, PoseidonRuntime &runtime, size_t count)
{
    Plaintext plain;
    runtime.decryptor.decrypt(tensor.cipher(), plain);

    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);

    const size_t copy_count = min(count, decoded.size());
    vector<double> values(copy_count, 0.0);
    for (size_t i = 0; i < copy_count; ++i)
    {
        values[i] = decoded[i].real();
    }
    return values;
}

int argmax_index(const vector<double> &values)
{
    if (values.empty())
    {
        throw std::invalid_argument("argmax input should not be empty");
    }
    return static_cast<int>(max_element(values.begin(), values.end()) - values.begin());
}

void align_for_add(TensorCipher &lhs, TensorCipher &rhs, PoseidonRuntime &runtime)
{
    const size_t lhs_chain = cipher_chain_index(runtime, lhs.cipher());
    const size_t rhs_chain = cipher_chain_index(runtime, rhs.cipher());

    if (lhs_chain > rhs_chain)
    {
        runtime.evaluator->drop_modulus(lhs.cipher(), lhs.cipher(), rhs.cipher().parms_id());
    }
    else if (rhs_chain > lhs_chain)
    {
        runtime.evaluator->drop_modulus(rhs.cipher(), rhs.cipher(), lhs.cipher().parms_id());
    }
}

void maybe_bootstrap(TensorCipher &tensor, PoseidonRuntime &runtime, ofstream &output, size_t stage)
{
    if (!kEnableBootstrap)
    {
        output << "bootstrap stage " << stage << " skipped" << endl;
        return;
    }

    PoseidonBootstrapContext bootstrap_ctx;
    bootstrap_ctx.context = &runtime.context;
    bootstrap_ctx.evaluator = runtime.evaluator.get();
    bootstrap_ctx.encoder = &runtime.encoder;
    bootstrap_ctx.relin_keys = &runtime.relin_keys;
    bootstrap_ctx.galois_keys = &runtime.galois_keys;
    bootstrap_ctx.bootstrap_poly = runtime.bootstrap_poly.get();

    TensorCipher bootstrapped;
    bootstrap_print(tensor, bootstrapped, bootstrap_ctx, output, runtime.decryptor,
                    runtime.encoder, runtime.context, stage);
    tensor = std::move(bootstrapped);
}

void run_relu(TensorCipher &input, TensorCipher &output, PlainTensor &plain_input,
              PlainTensor &plain_output, PoseidonRuntime &runtime, ofstream &log, size_t stage,
              ReluConfig &relu_config)
{
    approx_ReLU_seal_print(input, output, relu_config.comp_no, relu_config.deg, relu_config.alpha,
                           relu_config.tree, relu_config.scaled_val, relu_config.scalingfactor,
                           runtime.encryptor, *runtime.evaluator, runtime.decryptor, runtime.encoder,
                           runtime.public_key, runtime.secret_key, runtime.relin_keys,
                           runtime.scale, log, runtime.context, runtime.galois_keys, stage);
    plain_output = plain_relu_reference(plain_input, relu_config.plain_coeffs);
    log_plain_tensor("plain relu output", plain_output, log);
}

void run_stem(TensorCipher &cnn, PlainTensor &plain_cnn, vector<vector<double>> &conv_weight,
              vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean,
              vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight,
              size_t &conv_idx, size_t &bn_idx, PoseidonRuntime &runtime,
              ReluConfig &relu_config, ofstream &output)
{
    vector<Ciphertext> cipher_pool;
    TensorCipher conv_out;
    TensorCipher bn_out;
    TensorCipher relu_out;
    PlainTensor plain_conv_out;
    PlainTensor plain_bn_out;
    PlainTensor plain_relu_out;

    output << "\n========== Stem (layer 0) ==========\n";
    multiplexed_parallel_convolution_print(
        cnn, conv_out, 16, 1, 3, 3, conv_weight.at(conv_idx), bn_running_var.at(bn_idx),
        bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder, runtime.encryptor,
        *runtime.evaluator, runtime.galois_keys, cipher_pool, output, runtime.decryptor,
        runtime.context, 0, false);
    plain_conv_out =
        plain_convolution(plain_cnn, 16, 1, 3, 3, conv_weight.at(conv_idx), bn_running_var.at(bn_idx),
                          bn_weight.at(bn_idx), kBatchNormEpsilon);
    log_plain_tensor("plain conv output", plain_conv_out, output);
    ++conv_idx;

    multiplexed_parallel_batch_norm_seal_print(
        conv_out, bn_out, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx), bn_running_var.at(bn_idx),
        bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder, runtime.encryptor,
        *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context, 0, false);
    plain_bn_out =
        plain_batch_norm(plain_conv_out, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx),
                         bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, 40.0);
    log_plain_tensor("plain batchnorm output", plain_bn_out, output);
    ++bn_idx;

    run_relu(bn_out, relu_out, plain_bn_out, plain_relu_out, runtime, output, 0, relu_config);
    cnn = std::move(relu_out);
    plain_cnn = std::move(plain_relu_out);
}

void run_residual_block(TensorCipher &cnn, PlainTensor &plain_cnn, const PoseidonStagePlan &stage_plan,
                        int stage_index, int block_index, vector<vector<double>> &conv_weight,
                        vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean,
                        vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight,
                        size_t &conv_idx, size_t &bn_idx, PoseidonRuntime &runtime,
                        ReluConfig &relu_config, ofstream &output, int &logical_layer)
{
    vector<Ciphertext> cipher_pool;
    TensorCipher shortcut = cnn;
    TensorCipher branch_conv1;
    TensorCipher branch_bn1;
    TensorCipher branch_relu1;
    TensorCipher branch_conv2;
    TensorCipher branch_bn2;
    TensorCipher shortcut_down;
    TensorCipher added;
    TensorCipher block_output;
    PlainTensor plain_shortcut = plain_cnn;
    PlainTensor plain_branch_conv1;
    PlainTensor plain_branch_bn1;
    PlainTensor plain_branch_relu1;
    PlainTensor plain_branch_conv2;
    PlainTensor plain_branch_bn2;
    PlainTensor plain_shortcut_down;
    PlainTensor plain_added;
    PlainTensor plain_block_output;

    const int stride = (block_index == 0) ? stage_plan.first_block_stride : 1;
    output << "\n========== Stage " << (stage_index + 1) << " Block " << block_index
           << " / Layer " << logical_layer << " ==========\n";
    log_stage_plan(output, stage_plan, block_index);
    output << "layer " << logical_layer++ << endl;
    multiplexed_parallel_convolution_print(
        cnn, branch_conv1, stage_plan.out_channels, stride, 3, 3, conv_weight.at(conv_idx),
        bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool, output,
        runtime.decryptor, runtime.context, logical_layer, false);
    plain_branch_conv1 =
        plain_convolution(plain_cnn, stage_plan.out_channels, stride, 3, 3,
                          conv_weight.at(conv_idx), bn_running_var.at(bn_idx),
                          bn_weight.at(bn_idx), kBatchNormEpsilon);
    log_plain_tensor("plain conv1 output", plain_branch_conv1, output);
    ++conv_idx;

    multiplexed_parallel_batch_norm_seal_print(
        branch_conv1, branch_bn1, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx),
        bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context,
        logical_layer, false);
    plain_branch_bn1 =
        plain_batch_norm(plain_branch_conv1, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx),
                         bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, 40.0);
    log_plain_tensor("plain bn1 output", plain_branch_bn1, output);
    ++bn_idx;

    maybe_bootstrap(branch_bn1, runtime, output, logical_layer);
    run_relu(branch_bn1, branch_relu1, plain_branch_bn1, plain_branch_relu1, runtime, output,
             logical_layer, relu_config);

    output << "layer " << logical_layer++ << endl;
    multiplexed_parallel_convolution_print(
        branch_relu1, branch_conv2, stage_plan.out_channels, 1, 3, 3, conv_weight.at(conv_idx),
        bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool, output,
        runtime.decryptor, runtime.context, logical_layer, false);
    plain_branch_conv2 =
        plain_convolution(plain_branch_relu1, stage_plan.out_channels, 1, 3, 3,
                          conv_weight.at(conv_idx), bn_running_var.at(bn_idx),
                          bn_weight.at(bn_idx), kBatchNormEpsilon);
    log_plain_tensor("plain conv2 output", plain_branch_conv2, output);
    ++conv_idx;

    multiplexed_parallel_batch_norm_seal_print(
        branch_conv2, branch_bn2, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx),
        bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context,
        logical_layer, false);
    plain_branch_bn2 =
        plain_batch_norm(plain_branch_conv2, bn_bias.at(bn_idx), bn_running_mean.at(bn_idx),
                         bn_running_var.at(bn_idx), bn_weight.at(bn_idx), kBatchNormEpsilon, 40.0);
    log_plain_tensor("plain bn2 output", plain_branch_bn2, output);
    ++bn_idx;

    if (stage_index > 0 && block_index == 0)
    {
        multiplexed_parallel_downsampling_seal_print(shortcut, shortcut_down, *runtime.evaluator,
                                                     runtime.decryptor, runtime.encoder,
                                                     runtime.context, runtime.galois_keys, output);
        plain_shortcut_down = plain_downsample_shortcut(plain_shortcut);
        log_plain_tensor("plain shortcut output", plain_shortcut_down, output);
        shortcut = std::move(shortcut_down);
        plain_shortcut = std::move(plain_shortcut_down);
    }

    align_for_add(branch_bn2, shortcut, runtime);
    cipher_add_seal_print(branch_bn2, shortcut, added, *runtime.evaluator, output,
                          runtime.decryptor, runtime.encoder, runtime.context);
    plain_added = plain_add(plain_branch_bn2, plain_shortcut);
    log_plain_tensor("plain add output", plain_added, output);

    maybe_bootstrap(added, runtime, output, logical_layer);
    run_relu(added, block_output, plain_added, plain_block_output, runtime, output, logical_layer,
             relu_config);
    cnn = std::move(block_output);
    plain_cnn = std::move(plain_block_output);
}

vector<double> run_head(TensorCipher &cnn, PlainTensor &plain_cnn, const vector<double> &linear_weight,
                        const vector<double> &linear_bias, PoseidonRuntime &runtime, ofstream &output,
                        vector<double> &plain_logits)
{
    TensorCipher pooled;
    TensorCipher logits;
    PlainTensor plain_pooled;

    averagepooling_seal_scale_print(cnn, pooled, *runtime.evaluator, runtime.galois_keys, 40.0,
                                    output, runtime.decryptor, runtime.encoder, runtime.context);
    plain_pooled = plain_average_pool(plain_cnn, 40.0);
    log_plain_tensor("plain average pool output", plain_pooled, output);
    fully_connected_seal_print(pooled, logits, linear_weight, linear_bias, 10, 64,
                               *runtime.evaluator, runtime.galois_keys, output, runtime.decryptor,
                               runtime.encoder, runtime.context);
    plain_logits = plain_fully_connected(plain_pooled, linear_weight, linear_bias, 10, 64);
    cnn = std::move(logits);
    plain_cnn = std::move(plain_pooled);
    return decode_real_slots(cnn, runtime, 10);
}

} // namespace

void import_resnet20_parameters(vector<double> &linear_weight, vector<double> &linear_bias,
                                vector<vector<double>> &conv_weight,
                                vector<vector<double>> &bn_bias,
                                vector<vector<double>> &bn_running_mean,
                                vector<vector<double>> &bn_running_var,
                                vector<vector<double>> &bn_weight)
{
    const fs::path root = kWeightsRoot / kResNet20ParameterDir;

    size_t num_c = 0;
    size_t num_b = 0;
    size_t num_m = 0;
    size_t num_v = 0;
    size_t num_w = 0;

    conv_weight.clear();
    conv_weight.resize(kResNet20LayerNum - 1);
    bn_bias.clear();
    bn_bias.resize(kResNet20LayerNum - 1);
    bn_running_mean.clear();
    bn_running_mean.resize(kResNet20LayerNum - 1);
    bn_running_var.clear();
    bn_running_var.resize(kResNet20LayerNum - 1);
    bn_weight.clear();
    bn_weight.resize(kResNet20LayerNum - 1);

    const int fh = 3;
    const int fw = 3;
    int ci = 3;
    int co = 16;

    conv_weight[num_c++] = read_exact_values(root / "conv1_weight.txt", fh * fw * ci * co);

    for (int stage = 1; stage <= 3; ++stage)
    {
        for (int block = 0; block <= kResNet20EndNum; ++block)
        {
            if (stage == 1)
            {
                co = 16;
            }
            else if (stage == 2)
            {
                co = 32;
            }
            else
            {
                co = 64;
            }

            if (stage == 1 || (stage == 2 && block == 0))
            {
                ci = 16;
            }
            else if ((stage == 2 && block != 0) || (stage == 3 && block == 0))
            {
                ci = 32;
            }
            else
            {
                ci = 64;
            }

            conv_weight[num_c++] = read_exact_values(
                root / ("layer" + to_string(stage) + "_" + to_string(block) + "_conv1_weight.txt"),
                fh * fw * ci * co);

            if (stage == 1)
            {
                ci = 16;
            }
            else if (stage == 2)
            {
                ci = 32;
            }
            else
            {
                ci = 64;
            }

            conv_weight[num_c++] = read_exact_values(
                root / ("layer" + to_string(stage) + "_" + to_string(block) + "_conv2_weight.txt"),
                fh * fw * ci * co);
        }
    }

    ci = 16;
    bn_bias[num_b++] = read_exact_values(root / "bn1_bias.txt", ci);
    bn_running_mean[num_m++] = read_exact_values(root / "bn1_running_mean.txt", ci);
    bn_running_var[num_v++] = read_exact_values(root / "bn1_running_var.txt", ci);
    bn_weight[num_w++] = read_exact_values(root / "bn1_weight.txt", ci);

    for (int stage = 1; stage <= 3; ++stage)
    {
        if (stage == 1)
        {
            ci = 16;
        }
        else if (stage == 2)
        {
            ci = 32;
        }
        else
        {
            ci = 64;
        }

        for (int block = 0; block <= kResNet20EndNum; ++block)
        {
            const string prefix = "layer" + to_string(stage) + "_" + to_string(block);
            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn1_bias.txt"), ci);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn1_running_mean.txt"), ci);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn1_running_var.txt"), ci);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn1_weight.txt"), ci);

            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn2_bias.txt"), ci);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn2_running_mean.txt"), ci);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn2_running_var.txt"), ci);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn2_weight.txt"), ci);
        }
    }

    linear_weight = read_exact_values(root / "linear_weight.txt", 10 * 64);
    linear_bias = read_exact_values(root / "linear_bias.txt", 10);
}

void ResNet_cifar10_sparse(size_t start_image_id, size_t end_image_id)
{
    const PoseidonInferPlan plan = default_poseidon_plan();
    const string run_timestamp = make_run_timestamp();
    ReluConfig relu_config;
    relu_config.comp_no = 3;
    relu_config.deg = {15, 15, 27};
    relu_config.alpha = 13;
    relu_config.scaled_val = 1.7;
    relu_config.scalingfactor = plan.log_scale;
    relu_config.tree.reserve(relu_config.deg.size());
    for (int degree : relu_config.deg)
    {
        Tree tr(EvalType::OddBaby);
        upgrade_oddbaby(degree, tr);
        relu_config.tree.emplace_back(std::move(tr));
    }
    relu_config.plain_coeffs = load_plain_relu_component_coeffs(
        kReluParamRoot.string(), relu_config.alpha, relu_config.deg, relu_config.scaled_val);

    cout << "Setting Poseidon Parameters" << endl;
    PoseidonRuntime runtime = make_poseidon_runtime(plan);
    cout << "Poseidon slot count: " << runtime.slot_count << endl;
    cout << "Poseidon scale: " << runtime.scale << endl;
    cout << "ReLU parameter root: " << kReluParamRoot << endl;

    fs::create_directories(result_dir());
    const fs::path shared_result_path =
        result_dir() / (string(kResNet20ResultPrefix) + "_label_" + to_string(start_image_id) +
                        "_" + to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream out_share(shared_result_path);
    if (!out_share.is_open())
    {
        throw std::runtime_error("failed to open shared result file");
    }

    const auto all_time_start = chrono::high_resolution_clock::now();
    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const fs::path image_result_path =
            result_dir() / (string(kResNet20ResultPrefix) + "_image" + to_string(image_id) + "_" +
                            run_timestamp + ".txt");
        ofstream output(image_result_path);
        if (!output.is_open())
        {
            throw std::runtime_error("failed to open per-image result file");
        }

        output << "\n==================== run_start ====================\n";
        output << "image_id: " << image_id << '\n';
        output << "run_timestamp: " << run_timestamp << '\n';
        output << "log_file: " << image_result_path << '\n';

        vector<double> image_slots;
        vector<double> linear_weight;
        vector<double> linear_bias;
        vector<vector<double>> conv_weight;
        vector<vector<double>> bn_bias;
        vector<vector<double>> bn_running_mean;
        vector<vector<double>> bn_running_var;
        vector<vector<double>> bn_weight;

        import_resnet20_parameters(linear_weight, linear_bias, conv_weight, bn_bias,
                                   bn_running_mean, bn_running_var, bn_weight);

        image_slots = read_image_slots(image_id, plan.log_slots, plan.init_p, plan.boundary);
        const int image_label = read_image_label(image_id);
        PlainTensor plain_cnn = plain_input_tensor_from_image_slots(image_slots);

        output << "runtime: poseidon ready\n";
        output << "weights: conv=" << conv_weight.size() << ", bn=" << bn_weight.size()
               << ", fc=" << linear_weight.size() << '\n';
        output << "relu parameter root: " << kReluParamRoot << '\n';

        TensorCipher cnn(static_cast<int>(plan.logN), 1, 32, 32, 3, 3, static_cast<int>(plan.init_p),
                         image_slots, runtime.encryptor, runtime.encoder, plan.log_scale);
        output << "input ciphertext: level=" << cipher_chain_index(runtime, cnn.cipher())
               << ", scale=" << cnn.cipher().scale() << '\n';
        log_plain_tensor("plain input", plain_cnn, output);

        for (int i = 0; i < plan.boot_level + 5; ++i)
        {
            runtime.evaluator->drop_modulus_to_next(cnn.cipher(), cnn.cipher());
        }
        output << "post-alignment ciphertext: level="
               << cipher_chain_index(runtime, cnn.cipher())
               << ", scale=" << cnn.cipher().scale() << '\n';

        size_t conv_idx = 0;
        size_t bn_idx = 0;
        run_stem(cnn, plain_cnn, conv_weight, bn_bias, bn_running_mean, bn_running_var, bn_weight,
                 conv_idx, bn_idx, runtime, relu_config, output);

        int logical_layer = 1;
        for (size_t stage_index = 0; stage_index < plan.stages.size(); ++stage_index)
        {
            const PoseidonStagePlan &stage = plan.stages[stage_index];
            for (int block = 0; block < stage.block_count; ++block)
            {
                run_residual_block(cnn, plain_cnn, stage, static_cast<int>(stage_index), block,
                                   conv_weight, bn_bias, bn_running_mean, bn_running_var, bn_weight,
                                   conv_idx, bn_idx, runtime, relu_config, output, logical_layer);
            }
        }

        output << "\n========== Head (layer " << (kResNet20LayerNum - 1)
               << ") ==========\n";
        output << "head: average_pool -> fully_connected -> argmax\n";
        vector<double> plain_logits;
        vector<double> logits = run_head(cnn, plain_cnn, linear_weight, linear_bias, runtime, output,
                                         plain_logits);
        const int predicted_label = argmax_index(logits);
        const int plain_predicted_label = argmax_index(plain_logits);

        output << "logits:";
        for (double logit : logits)
        {
            output << ' ' << logit;
        }
        output << endl;
        output << "predicted label: " << predicted_label << endl;
        log_plain_logits(plain_logits, output);
        output << "plain predicted label: " << plain_predicted_label << '\n';

        out_share << "image_id: " << image_id << ", image label: " << image_label
                  << ", predicted label: " << predicted_label
                  << ", plain predicted label: " << plain_predicted_label << endl;
    }

    const auto all_time_end = chrono::high_resolution_clock::now();
    const auto all_time_diff =
        chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
    cout << "all threads time : " << all_time_diff.count() << " ms" << endl;
    out_share << endl << "all threads time : " << all_time_diff.count() << " ms" << endl;
}
