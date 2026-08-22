#include "infer.h"

#include "encrypted_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "parameter_loader.h"
#include "plain_cnn.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace std;
using namespace poseidon;

namespace fs = std::filesystem;

namespace
{

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

void log_stage_plan(ofstream &output, const PoseidonStagePlan &stage, int block_index)
{
    output << stage.name << " block " << block_index
           << ": conv1 -> bn1 -> bootstrap -> relu -> conv2 -> bn2";
    if (stage.first_block_stride == 2 && block_index == 0)
    {
        output << " -> downsample shortcut";
    }
    output << " -> add -> bootstrap -> relu" << endl;
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

struct RunContext
{
    PoseidonRuntime &runtime;
    ReluConfig &relu;
    const ModelWeights &weights;
};

struct InferenceState
{
    TensorCipher cipher;
    PlainTensor plain;
    size_t conv_idx = 0;
    size_t bn_idx = 0;
    int logical_layer = 1;
};

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
    bootstrap_ctx.config = &runtime.bootstrap_config;
    bootstrap_ctx.expected_level_consumption = 14;

    TensorCipher bootstrapped;
    bootstrap_print(tensor, bootstrapped, bootstrap_ctx, output, runtime.decryptor,
                    runtime.encoder, runtime.context, stage);
    tensor = std::move(bootstrapped);
}

void run_relu(TensorCipher &input, TensorCipher &output, PlainTensor &plain_input,
              PlainTensor &plain_output, RunContext &ctx, ofstream &log, size_t stage)
{
    PoseidonRuntime &runtime = ctx.runtime;
    ReluConfig &relu_config = ctx.relu;
    approx_relu_print(input, output, relu_config.comp_no, relu_config.deg, relu_config.alpha,
                      relu_config.tree, relu_config.scaled_val, runtime.encryptor,
                      *runtime.evaluator, runtime.decryptor, runtime.encoder,
                      runtime.relin_keys, runtime.scale, log, runtime.context, stage);
    plain_output = plain_relu_reference(plain_input);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain relu output", plain_output, log);
    }
}

void run_stem(InferenceState &state, RunContext &ctx, ofstream &output)
{
    PoseidonRuntime &runtime = ctx.runtime;
    const ModelWeights &weights = ctx.weights;
    vector<Ciphertext> cipher_pool;
    TensorCipher conv_out;
    TensorCipher bn_out;
    TensorCipher relu_out;
    PlainTensor plain_conv_out;
    PlainTensor plain_bn_out;
    PlainTensor plain_relu_out;

    output << "\n========== Stem (layer 0) ==========\n";
    multiplexed_convolution_print(
        state.cipher, conv_out, 16, 1, 3, 3, weights.conv_weight.at(state.conv_idx),
        weights.bn_running_var.at(state.bn_idx), weights.bn_weight.at(state.bn_idx),
        kBatchNormEpsilon, runtime.encoder, runtime.encryptor,
        *runtime.evaluator, runtime.galois_keys, cipher_pool, output, runtime.decryptor,
        runtime.context, 0, false);
    plain_conv_out =
        plain_convolution(state.plain, 16, 1, 3, 3, weights.conv_weight.at(state.conv_idx),
                          weights.bn_running_var.at(state.bn_idx),
                          weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain conv output", plain_conv_out, output);
    }
    ++state.conv_idx;

    multiplexed_batch_norm_print(
        conv_out, bn_out, weights.bn_bias.at(state.bn_idx),
        weights.bn_running_mean.at(state.bn_idx), weights.bn_running_var.at(state.bn_idx),
        weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, runtime.encoder, runtime.encryptor,
        *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context, 0, false);
    plain_bn_out =
        plain_batch_norm(plain_conv_out, weights.bn_bias.at(state.bn_idx),
                         weights.bn_running_mean.at(state.bn_idx),
                         weights.bn_running_var.at(state.bn_idx),
                         weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, 40.0);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain batchnorm output", plain_bn_out, output);
    }
    ++state.bn_idx;

    run_relu(bn_out, relu_out, plain_bn_out, plain_relu_out, ctx, output, 0);
    state.cipher = std::move(relu_out);
    state.plain = std::move(plain_relu_out);
}

void run_residual_block(InferenceState &state, const PoseidonStagePlan &stage_plan,
                        int stage_index, int block_index, RunContext &ctx, ofstream &output)
{
    PoseidonRuntime &runtime = ctx.runtime;
    const ModelWeights &weights = ctx.weights;
    vector<Ciphertext> cipher_pool;
    TensorCipher shortcut = state.cipher;
    TensorCipher branch_conv1;
    TensorCipher branch_bn1;
    TensorCipher branch_relu1;
    TensorCipher branch_conv2;
    TensorCipher branch_bn2;
    TensorCipher shortcut_down;
    TensorCipher added;
    TensorCipher block_output;
    PlainTensor plain_shortcut = state.plain;
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
           << " / Layer " << state.logical_layer << " ==========\n";
    log_stage_plan(output, stage_plan, block_index);
    output << "layer " << state.logical_layer++ << endl;
    multiplexed_convolution_print(
        state.cipher, branch_conv1, stage_plan.out_channels, stride, 3, 3,
        weights.conv_weight.at(state.conv_idx), weights.bn_running_var.at(state.bn_idx),
        weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool, output,
        runtime.decryptor, runtime.context, state.logical_layer, false);
    plain_branch_conv1 =
        plain_convolution(state.plain, stage_plan.out_channels, stride, 3, 3,
                          weights.conv_weight.at(state.conv_idx),
                          weights.bn_running_var.at(state.bn_idx),
                          weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain conv1 output", plain_branch_conv1, output);
    }
    ++state.conv_idx;

    multiplexed_batch_norm_print(
        branch_conv1, branch_bn1, weights.bn_bias.at(state.bn_idx),
        weights.bn_running_mean.at(state.bn_idx), weights.bn_running_var.at(state.bn_idx),
        weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context,
        state.logical_layer, false);
    plain_branch_bn1 =
        plain_batch_norm(plain_branch_conv1, weights.bn_bias.at(state.bn_idx),
                         weights.bn_running_mean.at(state.bn_idx),
                         weights.bn_running_var.at(state.bn_idx),
                         weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, 40.0);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain bn1 output", plain_branch_bn1, output);
    }
    ++state.bn_idx;

    maybe_bootstrap(branch_bn1, runtime, output, state.logical_layer);
    run_relu(branch_bn1, branch_relu1, plain_branch_bn1, plain_branch_relu1, ctx, output,
             state.logical_layer);

    output << "layer " << state.logical_layer++ << endl;
    multiplexed_convolution_print(
        branch_relu1, branch_conv2, stage_plan.out_channels, 1, 3, 3,
        weights.conv_weight.at(state.conv_idx), weights.bn_running_var.at(state.bn_idx),
        weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool, output,
        runtime.decryptor, runtime.context, state.logical_layer, false);
    plain_branch_conv2 =
        plain_convolution(plain_branch_relu1, stage_plan.out_channels, 1, 3, 3,
                          weights.conv_weight.at(state.conv_idx),
                          weights.bn_running_var.at(state.bn_idx),
                          weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain conv2 output", plain_branch_conv2, output);
    }
    ++state.conv_idx;

    multiplexed_batch_norm_print(
        branch_conv2, branch_bn2, weights.bn_bias.at(state.bn_idx),
        weights.bn_running_mean.at(state.bn_idx), weights.bn_running_var.at(state.bn_idx),
        weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, runtime.encoder,
        runtime.encryptor, *runtime.evaluator, 40.0, output, runtime.decryptor, runtime.context,
        state.logical_layer, false);
    plain_branch_bn2 =
        plain_batch_norm(plain_branch_conv2, weights.bn_bias.at(state.bn_idx),
                         weights.bn_running_mean.at(state.bn_idx),
                         weights.bn_running_var.at(state.bn_idx),
                         weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon, 40.0);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain bn2 output", plain_branch_bn2, output);
    }
    ++state.bn_idx;

    if (stage_index > 0 && block_index == 0)
    {
        multiplexed_downsampling_print(shortcut, shortcut_down, *runtime.evaluator,
                                                     runtime.decryptor, runtime.encoder,
                                                     runtime.context, runtime.galois_keys, output);
        plain_shortcut_down = plain_downsample_shortcut(plain_shortcut);
        if (kLogPlainIntermediate)
        {
            log_plain_tensor("plain shortcut output", plain_shortcut_down, output);
        }
        shortcut = std::move(shortcut_down);
        plain_shortcut = std::move(plain_shortcut_down);
    }

    align_for_add(branch_bn2, shortcut, runtime);
    cipher_add_stage_print(branch_bn2, shortcut, added, *runtime.evaluator, output,
                          runtime.decryptor, runtime.encoder, runtime.context);
    plain_added = plain_add(plain_branch_bn2, plain_shortcut);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain add output", plain_added, output);
    }

    maybe_bootstrap(added, runtime, output, state.logical_layer);
    run_relu(added, block_output, plain_added, plain_block_output, ctx, output,
             state.logical_layer);
    state.cipher = std::move(block_output);
    state.plain = std::move(plain_block_output);
}

vector<double> run_head(InferenceState &state, RunContext &ctx, ofstream &output,
                        vector<double> &plain_logits)
{
    PoseidonRuntime &runtime = ctx.runtime;
    const ModelWeights &weights = ctx.weights;
    TensorCipher pooled;
    TensorCipher logits;
    PlainTensor plain_pooled;

    averagepooling_scale_print(state.cipher, pooled, *runtime.evaluator, runtime.galois_keys, 40.0,
                                    output, runtime.decryptor, runtime.encoder, runtime.context);
    plain_pooled = plain_average_pool(state.plain, 40.0);
    if (kLogPlainIntermediate)
    {
        log_plain_tensor("plain average pool output", plain_pooled, output);
    }
    fully_connected_print(pooled, logits, weights.linear_weight, weights.linear_bias, 10, 64,
                               *runtime.evaluator, runtime.galois_keys, output, runtime.decryptor,
                               runtime.encoder, runtime.context);
    plain_logits =
        plain_fully_connected(plain_pooled, weights.linear_weight, weights.linear_bias, 10, 64);
    state.cipher = std::move(logits);
    state.plain = std::move(plain_pooled);
    return decode_real_slots(state.cipher, runtime, 10);
}

} // namespace

void ResNet_cifar10_sparse(size_t start_image_id, size_t end_image_id)
{
    const PoseidonInferPlan plan = default_poseidon_plan();
    const string run_timestamp = make_run_timestamp();
    ReluConfig relu_config = default_relu_config(plan);

    cout << "Setting Poseidon Parameters" << endl;
    PoseidonRuntime runtime = make_poseidon_runtime(plan);
    cout << "Poseidon slot count: " << runtime.slot_count << endl;
    cout << "Poseidon scale: " << runtime.scale << endl;
    cout << "Poseidon Q primes: " << plan.logq_chain.size()
         << " (q0=1, application=" << plan.remaining_level
         << ", bootstrap=" << plan.boot_level << ")" << endl;

    fs::create_directories(result_dir());
    const fs::path shared_result_path =
        result_dir() / (string(kResNet20ResultPrefix) + "_label_" + to_string(start_image_id) +
                        "_" + to_string(end_image_id) + "_" + run_timestamp + ".txt");
    const fs::path status_result_path =
        result_dir() / (string(kResNet20ResultPrefix) + "_status_" + to_string(start_image_id) +
                        "_" + to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream out_share(shared_result_path);
    if (!out_share.is_open())
    {
        throw std::runtime_error("failed to open shared result file");
    }
    ofstream out_status(status_result_path);
    if (!out_status.is_open())
    {
        throw std::runtime_error("failed to open status result file");
    }

    out_status << "run_start: start_image_id=" << start_image_id
               << ", end_image_id=" << end_image_id
               << ", run_timestamp=" << run_timestamp << '\n';

    ModelWeights weights = load_resnet20_parameters();
    RunContext ctx{runtime, relu_config, weights};

    const auto all_time_start = chrono::high_resolution_clock::now();
    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const auto image_time_start = chrono::high_resolution_clock::now();
        out_status << "image_start: " << image_id << '\n';
        out_status.flush();

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

        vector<double> image_slots =
            read_image_slots(image_id, plan.log_slots, plan.init_p, plan.boundary);
        const int image_label = read_image_label(image_id);
        InferenceState state;
        state.plain = plain_input_tensor_from_image_slots(image_slots);

        output << "runtime: poseidon ready\n";
        output << "ckks_config: log_scale=" << plan.log_scale
               << ", q0_bits=" << plan.logq_chain.front()
               << ", compute_q_bits=" << plan.logq_chain.at(plan.q0_level + 1)
               << ", compute_levels=" << plan.remaining_level
               << ", bootstrap_q_bits=" << plan.logq_chain.back()
               << ", bootstrap_levels=" << plan.boot_level
               << ", bootstrap_scaling_log=" << runtime.bootstrap_config.scaling_log
               << ", bootstrap_output_scaling_log="
               << runtime.bootstrap_config.output_scaling_log
               << ", q_count=" << plan.logq_chain.size() << '\n';
        output << "weights: conv=" << weights.conv_weight.size()
               << ", bn=" << weights.bn_weight.size()
               << ", fc=" << weights.linear_weight.size() << '\n';

        state.cipher = TensorCipher(static_cast<int>(plan.logN), 1, 32, 32, 3, 3,
                                    static_cast<int>(plan.init_p), image_slots,
                                    runtime.encryptor, runtime.encoder, plan.log_scale);
        output << "input ciphertext: level=" << cipher_chain_index(runtime, state.cipher.cipher())
               << ", scale=" << state.cipher.cipher().scale() << '\n';
        if (kLogPlainIntermediate)
        {
            log_plain_tensor("plain input", state.plain, output);
        }

        // Before the first bootstrap the path is stem convolution (2), ReLU
        // (14), then the first block convolution (2). After that bootstrap,
        // every steady-state path is ReLU (14) plus convolution (2).
        const std::size_t initial_level = static_cast<std::size_t>(
            plan.remaining_level + plan.convolution_levels);
        while (cipher_chain_index(runtime, state.cipher.cipher()) > initial_level)
        {
            runtime.evaluator->drop_modulus_to_next(state.cipher.cipher(), state.cipher.cipher());
        }
        output << "post-alignment ciphertext: level="
               << cipher_chain_index(runtime, state.cipher.cipher())
               << ", initial_budget=" << initial_level
               << ", scale=" << state.cipher.cipher().scale() << '\n';

        run_stem(state, ctx, output);

        for (size_t stage_index = 0; stage_index < plan.stages.size(); ++stage_index)
        {
            const PoseidonStagePlan &stage = plan.stages[stage_index];
            for (int block = 0; block < stage.block_count; ++block)
            {
                run_residual_block(state, stage, static_cast<int>(stage_index), block, ctx, output);
            }
        }

        output << "\n========== Head (layer " << (kResNet20LayerNum - 1)
               << ") ==========\n";
        output << "head: average_pool -> fully_connected -> argmax\n";
        vector<double> plain_logits;
        vector<double> logits = run_head(state, ctx, output, plain_logits);
        const int predicted_label = argmax_index(logits);
        const int plain_predicted_label = argmax_index(plain_logits);
        const auto image_time_end = chrono::high_resolution_clock::now();
        const auto image_time_diff =
            chrono::duration_cast<chrono::milliseconds>(image_time_end - image_time_start);

        output << "logits:";
        for (double logit : logits)
        {
            output << ' ' << logit;
        }
        output << endl;
        output << "predicted label: " << predicted_label << endl;
        log_plain_logits(plain_logits, output);
        output << "plain predicted label: " << plain_predicted_label << '\n';
        output << "image time : " << image_time_diff.count() << " ms" << endl;

        out_share << "image_id: " << image_id << ", image label: " << image_label
                  << ", predicted label: " << predicted_label
                  << ", plain predicted label: " << plain_predicted_label
                  << ", image time : " << image_time_diff.count() << " ms" << endl;
        cout << "image_id: " << image_id << ", image label: " << image_label
             << ", predicted label: " << predicted_label
             << ", plain predicted label: " << plain_predicted_label
             << ", image time : " << image_time_diff.count() << " ms" << endl;
        out_status << "image_done: " << image_id
                   << ", image label: " << image_label
                   << ", predicted label: " << predicted_label
                   << ", plain predicted label: " << plain_predicted_label
                   << ", image_time_ms=" << image_time_diff.count() << '\n';
        out_status.flush();
    }

    const auto all_time_end = chrono::high_resolution_clock::now();
    const auto all_time_diff =
        chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
    cout << "total time : " << all_time_diff.count() << " ms" << endl;
    out_share << endl << "total time : " << all_time_diff.count() << " ms" << endl;
    out_status << "run_done: total_time_ms=" << all_time_diff.count() << '\n';
}
