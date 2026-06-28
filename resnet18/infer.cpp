#include "infer.h"

#include "encrypted_ops.h"
#include "encrypted_group_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "parameter_loader.h"
#include "plain_cnn.h"
#include "progress_log.h"
#include "tensor_cipher_group.h"

#include "poseidon/advance/homomorphic_dft.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <set>
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

constexpr bool kRunFullConv1GroupCheck = false;
constexpr bool kRunConv1SingleOutputPreview = false;
constexpr bool kRunFullStemCheck = true;
constexpr bool kBootstrapAfterConv1ReluPreview = true;
constexpr bool kUseDecryptReencryptRefresh = true;
constexpr size_t kMaxPoolPreviewCount = 16;

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
        output << " -> projection shortcut";
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

void log_tensor_cipher_state(const string &label, const TensorCipher &tensor,
                             PoseidonRuntime &runtime)
{
    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << tensor.h() << ", w=" << tensor.w()
                            << ", c=" << tensor.c()
                            << "), chain_index=" << cipher_chain_index(runtime, tensor.cipher())
                            << ", scale=" << tensor.cipher().scale() << endl;
}

void log_channel_group_cipher_state(const string &label, const ChannelCipherGroup &group,
                                    PoseidonRuntime &runtime)
{
    if (group.channels.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label << ": empty channel group" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, group.channels.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = group.channels.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;

    for (const Ciphertext &cipher : group.channels)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        const double scale = cipher.scale();
        min_scale = min(min_scale, scale);
        max_scale = max(max_scale, scale);
    }

    resnet18_progress_log() << "[cipher-state] " << label
                            << ": shape(h=" << group.h << ", w=" << group.w
                            << ", c=" << group.c << ", spatial=" << group.spatial_count
                            << "), channels=" << group.channels.size()
                            << ", chain_index(first/min/max)=" << first_chain << "/"
                            << min_chain << "/" << max_chain
                            << ", scale(first/min/max)=" << first_scale << "/" << min_scale
                            << "/" << max_scale << endl;
}

void prepare_bootstrap_runtime(PoseidonRuntime &runtime)
{
    runtime.bootstrap_poly.reset(new EvalModPoly(
        runtime.context, CosDiscrete, static_cast<uint64_t>(1) << 51, 1, 16, 3, 16, 0, 30));

    auto params = runtime.context.parameters_literal();
    set<int> rotation_steps;
    rotation_steps.insert(0);

    const double coeffs_to_slots_scaling =
        runtime.bootstrap_poly->q_div() /
        (runtime.bootstrap_poly->k() * runtime.bootstrap_poly->sc_fac() *
         runtime.bootstrap_poly->q_diff());
    HomomorphicDFTMatrixLiteral coeff_to_slot_matrix(
        0, params->log_n(), params->log_slots(), static_cast<uint32_t>(params->q().size() - 1),
        vector<uint32_t>(3, 1), true, coeffs_to_slots_scaling, false, 1);
    LinearMatrixGroup coeff_to_slot_group;
    coeff_to_slot_matrix.create(coeff_to_slot_group, runtime.encoder, 2);
    rotation_steps.insert(coeff_to_slot_group.rot_index().begin(),
                          coeff_to_slot_group.rot_index().end());

    const double slots_to_coeffs_scaling =
        params->scale() /
        (runtime.bootstrap_poly->scaling_factor() / runtime.bootstrap_poly->message_ratio());
    HomomorphicDFTMatrixLiteral slot_to_coeff_matrix(
        1, params->log_n(), params->log_slots(), static_cast<uint32_t>(params->q().size() - 1),
        vector<uint32_t>(3, 1), true, slots_to_coeffs_scaling, false, 1);
    LinearMatrixGroup slot_to_coeff_group;
    slot_to_coeff_matrix.create(slot_to_coeff_group, runtime.encoder, 1);
    rotation_steps.insert(slot_to_coeff_group.rot_index().begin(),
                          slot_to_coeff_group.rot_index().end());

    vector<int> steps(rotation_steps.begin(), rotation_steps.end());
    resnet18_progress_log() << "bootstrap preview generating relin/bootstrap rotation keys: "
         << steps.size() << endl;
    KeyGenerator keygen(runtime.context, runtime.secret_key);
    keygen.create_relin_keys(runtime.relin_keys);
    keygen.create_galois_keys(steps, runtime.galois_keys);
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
        throw invalid_argument("argmax input should not be empty");
    }
    return static_cast<int>(max_element(values.begin(), values.end()) - values.begin());
}

vector<double> make_channelwise_average_pool_weights(int channels, int kernel)
{
    vector<double> weights(static_cast<size_t>(kernel * kernel * channels * channels), 0.0);
    const double scale = 1.0 / static_cast<double>(kernel * kernel);
    for (int oc = 0; oc < channels; ++oc)
    {
        for (int kh = 0; kh < kernel; ++kh)
        {
            for (int kw = 0; kw < kernel; ++kw)
            {
                const size_t index = static_cast<size_t>(
                    kernel * kernel * channels * oc + kernel * kernel * oc + kernel * kh + kw);
                weights[index] = scale;
            }
        }
    }
    return weights;
}

vector<double> make_channelwise_pick_kernel_weights(int channels, int kernel, int pick_row,
                                                    int pick_col)
{
    vector<double> weights(static_cast<size_t>(kernel * kernel * channels * channels), 0.0);
    for (int channel = 0; channel < channels; ++channel)
    {
        const size_t index = static_cast<size_t>(kernel * kernel * channels * channel +
                                                 kernel * kernel * channel +
                                                 kernel * pick_row + pick_col);
        weights[index] = 1.0;
    }
    return weights;
}

vector<double> filled_vector(int count, double value)
{
    return vector<double>(static_cast<size_t>(count), value);
}

ReluConfig make_low_degree_maxpool_relu_config()
{
    ReluConfig relu_config;
    relu_config.comp_no = 1;
    relu_config.deg = {3};
    relu_config.alpha = 13;
    relu_config.scaled_val = 1.7;
    relu_config.scalingfactor = 46;
    Tree tr(EvalType::OddBaby);
    upgrade_oddbaby(3, tr);
    relu_config.tree.emplace_back(std::move(tr));
    return relu_config;
}

TensorCipher run_quadratic_relu_preview(const TensorCipher &input, PoseidonRuntime &runtime)
{
    Ciphertext square;
    runtime.evaluator->multiply_relin_dynamic(input.cipher(), input.cipher(), square,
                                              runtime.relin_keys);
    runtime.evaluator->rescale_dynamic(square, square, input.cipher().scale());

    Ciphertext half_input;
    runtime.evaluator->multiply_const(input.cipher(), 0.5, runtime.scale, half_input,
                                      runtime.encoder);
    runtime.evaluator->rescale_dynamic(half_input, half_input, input.cipher().scale());

    Ciphertext half_square;
    runtime.evaluator->multiply_const(square, 0.5, runtime.scale, half_square, runtime.encoder);
    runtime.evaluator->rescale_dynamic(half_square, half_square, square.scale());

    Ciphertext result;
    runtime.evaluator->add_dynamic(half_input, half_square, result, runtime.encoder);
    result.scale() = input.cipher().scale();
    return TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                        input.p(), result);
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

void subtract_tensors(const TensorCipher &lhs, const TensorCipher &rhs, TensorCipher &difference,
                      PoseidonRuntime &runtime)
{
    if (lhs.k() != rhs.k() || lhs.h() != rhs.h() || lhs.w() != rhs.w() ||
        lhs.c() != rhs.c() || lhs.t() != rhs.t() || lhs.p() != rhs.p() ||
        lhs.logn() != rhs.logn())
    {
        throw invalid_argument("subtract_tensors shape mismatch");
    }

    Ciphertext diff_cipher;
    runtime.evaluator->sub_dynamic(lhs.cipher(), rhs.cipher(), diff_cipher, runtime.encoder);
    difference = TensorCipher(lhs.logn(), lhs.k(), lhs.h(), lhs.w(), lhs.c(), lhs.t(), lhs.p(),
                              diff_cipher);
}

size_t tensor_value_count(const TensorCipher &tensor)
{
    if (tensor.h() <= 0 || tensor.w() <= 0 || tensor.c() <= 0)
    {
        throw invalid_argument("tensor shape is invalid for debug refresh");
    }
    return static_cast<size_t>(tensor.h()) * static_cast<size_t>(tensor.w()) *
           static_cast<size_t>(tensor.c());
}

TensorCipher decrypt_reencrypt_tensor(const TensorCipher &tensor, PoseidonRuntime &runtime,
                                      size_t value_count = 0)
{
    const size_t count = value_count == 0 ? tensor_value_count(tensor) : value_count;
    vector<double> values = decode_real_slots(tensor, runtime, count);
    const int logp = static_cast<int>(llround(log2(runtime.scale)));
    return TensorCipher(tensor.logn(), tensor.k(), tensor.h(), tensor.w(), tensor.c(),
                        tensor.t(), tensor.p(), values, runtime.encryptor, runtime.encoder,
                        logp);
}

double channel_group_max_abs_error(const ChannelCipherGroup &group, const PlainTensor &plain,
                                   PoseidonRuntime &runtime)
{
    vector<double> decrypted = decrypt_channel_cipher_group(group, runtime);
    if (decrypted.size() != plain.values.size())
    {
        throw invalid_argument("channel group/plain tensor size mismatch");
    }

    double max_abs_error = 0.0;
    for (size_t i = 0; i < decrypted.size(); ++i)
    {
        max_abs_error = max(max_abs_error, abs(decrypted[i] - plain.values.at(i)));
    }
    return max_abs_error;
}

double sparse_stride_channel_group_max_abs_error(const ChannelCipherGroup &group,
                                                 const PlainTensor &plain, int stride, int logN,
                                                 PoseidonRuntime &runtime)
{
    if (stride <= 0 || group.c != plain.c || group.h < plain.h * stride ||
        group.w < plain.w * stride)
    {
        throw invalid_argument("sparse stride group/plain tensor shape mismatch");
    }

    double max_abs_error = 0.0;
    for (int channel = 0; channel < group.c; ++channel)
    {
        TensorCipher channel_cipher(logN, 1, group.h, group.w, 1, 1, 1,
                                    group.channels.at(static_cast<size_t>(channel)));
        vector<double> values = decode_real_slots(channel_cipher, runtime, group.spatial_count);
        for (int oh = 0; oh < plain.h; ++oh)
        {
            for (int ow = 0; ow < plain.w; ++ow)
            {
                const size_t sparse_slot =
                    static_cast<size_t>((oh * stride) * group.w + ow * stride);
                max_abs_error =
                    max(max_abs_error,
                        abs(values.at(sparse_slot) - plain.at(channel, oh, ow)));
            }
        }
    }
    return max_abs_error;
}

ChannelCipherGroup compact_sparse_stride_channel_group(const ChannelCipherGroup &sparse_group,
                                                       int dense_h, int dense_w, int stride,
                                                       int logN, int logp,
                                                       PoseidonRuntime &runtime)
{
    if (stride <= 0 || dense_h <= 0 || dense_w <= 0 ||
        sparse_group.h < dense_h * stride || sparse_group.w < dense_w * stride)
    {
        throw invalid_argument("compact sparse stride group shape is invalid");
    }

    ChannelCipherGroup dense_group;
    dense_group.h = dense_h;
    dense_group.w = dense_w;
    dense_group.c = sparse_group.c;
    dense_group.spatial_count = static_cast<size_t>(dense_h * dense_w);
    dense_group.slot_count = runtime.encoder.slot_count();
    dense_group.channels.reserve(sparse_group.channels.size());

    for (int channel = 0; channel < sparse_group.c; ++channel)
    {
        TensorCipher sparse_channel(logN, 1, sparse_group.h, sparse_group.w, 1, 1, 1,
                                    sparse_group.channels.at(static_cast<size_t>(channel)));
        vector<double> sparse_values =
            decode_real_slots(sparse_channel, runtime, sparse_group.spatial_count);
        vector<double> dense_values(dense_group.spatial_count, 0.0);
        for (int oh = 0; oh < dense_h; ++oh)
        {
            for (int ow = 0; ow < dense_w; ++ow)
            {
                const size_t sparse_slot =
                    static_cast<size_t>((oh * stride) * sparse_group.w + ow * stride);
                dense_values[static_cast<size_t>(oh * dense_w + ow)] =
                    sparse_values.at(sparse_slot);
            }
        }
        TensorCipher dense_channel(logN, 1, dense_h, dense_w, 1, 1, 1, dense_values,
                                   runtime.encryptor, runtime.encoder, logp);
        dense_group.channels.emplace_back(dense_channel.cipher());
    }

    log_channel_group_cipher_state("compact_sparse_stride_channel_group output", dense_group,
                                   runtime);
    return dense_group;
}

ChannelCipherGroup encrypted_channel_relu_refresh(const ChannelCipherGroup &input,
                                                  const string &progress_label, int logN,
                                                  ReluConfig &relu_config,
                                                  PoseidonRuntime &runtime)
{
    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = input.c;
    output.spatial_count = input.spatial_count;
    output.slot_count = input.slot_count;
    output.channels.reserve(input.channels.size());

    for (int channel = 0; channel < input.c; ++channel)
    {
        if (channel % 8 == 0)
        {
            resnet18_progress_log() << progress_label << " channel progress: " << channel << "/"
                 << input.c << endl;
        }
        TensorCipher input_channel(logN, 1, input.h, input.w, 1, 1, 1,
                                   input.channels.at(static_cast<size_t>(channel)));
        TensorCipher relu_channel;
        relu(input_channel, relu_channel, relu_config.comp_no, relu_config.deg,
             relu_config.alpha, relu_config.tree, relu_config.scaled_val,
             runtime.encryptor, *runtime.evaluator, runtime.encoder, runtime.relin_keys,
             runtime.scale);
        TensorCipher refreshed_channel =
            decrypt_reencrypt_tensor(relu_channel, runtime, input.spatial_count);
        output.channels.emplace_back(refreshed_channel.cipher());
    }
    resnet18_progress_log() << progress_label << " channel progress: " << input.c << "/" << input.c
         << endl;
    log_channel_group_cipher_state(progress_label + " refresh output", output, runtime);

    return output;
}

vector<int> fully_connected_rotation_steps(int q, int r)
{
    if (q <= 0 || r <= 0)
    {
        throw invalid_argument("fully connected rotation shape is invalid");
    }

    set<int> steps;
    for (int s = 0; s < q + r - 1; ++s)
    {
        const int step = r - 1 - s;
        if (step != 0)
        {
            steps.insert(step);
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

void maybe_bootstrap(TensorCipher &tensor, PoseidonRuntime &runtime, ofstream &output, size_t stage)
{
    if (!kEnableBootstrap)
    {
        output << "bootstrap stage " << stage << " skipped" << endl;
        return;
    }

    if (kUseDecryptReencryptRefresh)
    {
        output << "bootstrap stage " << stage
               << " replaced by debug decrypt-reencrypt refresh" << endl;
        resnet18_progress_log() << "bootstrap stage " << stage
             << " replaced by debug decrypt-reencrypt refresh" << endl;
        tensor = decrypt_reencrypt_tensor(tensor, runtime);
        output << "debug refresh chain index: " << cipher_chain_index(runtime, tensor.cipher())
               << ", scale: " << tensor.cipher().scale() << '\n';
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

void run_relu_cipher_only(TensorCipher &input, TensorCipher &output, RunContext &ctx,
                          ofstream &log, size_t stage)
{
    PoseidonRuntime &runtime = ctx.runtime;
    ReluConfig &relu_config = ctx.relu;
    approx_relu_print(input, output, relu_config.comp_no, relu_config.deg, relu_config.alpha,
                      relu_config.tree, relu_config.scaled_val, runtime.encryptor,
                      *runtime.evaluator, runtime.decryptor, runtime.encoder,
                      runtime.relin_keys, runtime.scale, log, runtime.context, stage);
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

TensorCipher run_approx_pairwise_max(const TensorCipher &lhs, const TensorCipher &rhs,
                                     RunContext &ctx, ofstream &output, size_t stage)
{
    PoseidonRuntime &runtime = ctx.runtime;
    TensorCipher diff;
    TensorCipher positive_diff;
    TensorCipher rhs_copy = rhs;
    TensorCipher result;

    output << "\n========== approximate max pair " << stage << " ==========\n";
    output << "max(a,b) ~= b + relu(a-b)\n";
    subtract_tensors(lhs, rhs, diff, runtime);
    maybe_bootstrap(diff, runtime, output, stage);
    run_relu_cipher_only(diff, positive_diff, ctx, output, stage);
    align_for_add(positive_diff, rhs_copy, runtime);
    cipher_add_stage_print(positive_diff, rhs_copy, result, *runtime.evaluator, output,
                           runtime.decryptor, runtime.encoder, runtime.context);
    return result;
}

TensorCipher run_approx_pairwise_max_preview(const TensorCipher &lhs, const TensorCipher &rhs,
                                             RunContext &ctx, bool log_chain = true)
{
    PoseidonRuntime &runtime = ctx.runtime;
    TensorCipher diff;
    TensorCipher positive_diff;
    TensorCipher rhs_copy = rhs;
    Ciphertext result_cipher;

    subtract_tensors(lhs, rhs, diff, runtime);
    if (log_chain)
    {
        resnet18_progress_log() << "maxpool pair diff chain index: " << cipher_chain_index(runtime, diff.cipher())
             << ", scale: " << diff.cipher().scale() << endl;
    }
    positive_diff = run_quadratic_relu_preview(diff, runtime);
    if (log_chain)
    {
        resnet18_progress_log() << "maxpool pair relu(diff) chain index: "
             << cipher_chain_index(runtime, positive_diff.cipher())
             << ", scale: " << positive_diff.cipher().scale() << endl;
    }
    align_for_add(positive_diff, rhs_copy, runtime);
    runtime.evaluator->add_dynamic(positive_diff.cipher(), rhs_copy.cipher(), result_cipher,
                                   runtime.encoder);
    return TensorCipher(lhs.logn(), lhs.k(), lhs.h(), lhs.w(), lhs.c(), lhs.t(), lhs.p(),
                        result_cipher);
}

TensorCipher run_sparse_maxpool_channel(const TensorCipher &input, int input_h, int input_w,
                                        RunContext &ctx, bool log_chain)
{
    PoseidonRuntime &runtime = ctx.runtime;
    vector<TensorCipher> candidates;
    candidates.reserve(9);
    for (int kh = 0; kh < 3; ++kh)
    {
        for (int kw = 0; kw < 3; ++kw)
        {
            Ciphertext candidate_cipher = encrypted_maxpool_candidate_sparse(
                input.cipher(), input_h, input_w, 3, 2, 1, kh, kw, runtime);
            candidates.emplace_back(input.logn(), 1, input_h, input_w, 1, input.t(), input.p(),
                                    candidate_cipher);
        }
    }

    while (candidates.size() > 1)
    {
        vector<TensorCipher> reduced;
        reduced.reserve((candidates.size() + 1) / 2);
        for (size_t i = 0; i < candidates.size(); i += 2)
        {
            if (i + 1 == candidates.size())
            {
                reduced.emplace_back(std::move(candidates[i]));
            }
            else
            {
                reduced.emplace_back(run_approx_pairwise_max_preview(candidates[i],
                                                                     candidates[i + 1],
                                                                     ctx, log_chain));
            }
        }
        candidates = std::move(reduced);
    }

    return std::move(candidates.front());
}

double sparse_maxpool_channel_error(const TensorCipher &sparse_pool, int input_w,
                                    const PlainTensor &plain_pool, int channel,
                                    PoseidonRuntime &runtime, ostream *preview_output = nullptr)
{
    vector<double> decrypted = decode_real_slots(
        sparse_pool, runtime, static_cast<size_t>(sparse_pool.h() * sparse_pool.w()));
    double max_abs_error = 0.0;
    for (int oh = 0; oh < plain_pool.h; ++oh)
    {
        for (int ow = 0; ow < plain_pool.w; ++ow)
        {
            const size_t sparse_slot = static_cast<size_t>((oh * 2) * input_w + ow * 2);
            const size_t plain_index =
                static_cast<size_t>(channel * plain_pool.h * plain_pool.w + oh * plain_pool.w + ow);
            const double abs_error = abs(decrypted.at(sparse_slot) -
                                         plain_pool.values.at(plain_index));
            max_abs_error = max(max_abs_error, abs_error);
            if (preview_output && channel == 0 && oh == 0 && ow < static_cast<int>(kMaxPoolPreviewCount))
            {
                *preview_output << "conv1 sparse maxpool output[" << ow
                                << "]: " << decrypted.at(sparse_slot)
                                << ", plain: " << plain_pool.values.at(plain_index)
                                << ", abs_error: " << abs_error << '\n';
            }
        }
    }
    return max_abs_error;
}

TensorCipher run_approx_max_pool2d(TensorCipher &input, int channels, RunContext &ctx,
                                   ofstream &output, size_t stage)
{
    PoseidonRuntime &runtime = ctx.runtime;
    vector<Ciphertext> cipher_pool;
    vector<TensorCipher> candidates;
    const vector<double> ones = filled_vector(channels, 1.0);

    output << "\n========== approximate encrypted maxpool ==========\n";
    output << "3x3 stride-2 padding-1 maxpool via one-hot extraction + pairwise ReLU max\n";

    for (int kh = 0; kh < 3; ++kh)
    {
        for (int kw = 0; kw < 3; ++kw)
        {
            TensorCipher candidate;
            vector<double> pick_weights = make_channelwise_pick_kernel_weights(channels, 3, kh, kw);
            multiplexed_convolution_print(
                input, candidate, channels, 2, 3, 3, pick_weights, ones, ones, 0.0,
                runtime.encoder, runtime.encryptor, *runtime.evaluator, runtime.galois_keys,
                cipher_pool, output, runtime.decryptor, runtime.context,
                stage * 100 + static_cast<size_t>(kh * 3 + kw), false);
            candidates.emplace_back(std::move(candidate));
        }
    }

    size_t max_stage = stage * 100 + 20;
    while (candidates.size() > 1)
    {
        vector<TensorCipher> reduced;
        reduced.reserve((candidates.size() + 1) / 2);
        for (size_t i = 0; i < candidates.size(); i += 2)
        {
            if (i + 1 == candidates.size())
            {
                reduced.emplace_back(std::move(candidates[i]));
            }
            else
            {
                reduced.emplace_back(run_approx_pairwise_max(candidates[i], candidates[i + 1],
                                                             ctx, output, max_stage++));
            }
        }
        candidates = std::move(reduced);
    }

    return std::move(candidates.front());
}

void run_stem(InferenceState &state, RunContext &ctx, ofstream &output)
{
    PoseidonRuntime &runtime = ctx.runtime;
    const ModelWeights &weights = ctx.weights;
    vector<Ciphertext> cipher_pool;
    TensorCipher conv_out;
    TensorCipher bn_out;
    TensorCipher relu_out;
    TensorCipher pool_out;
    PlainTensor plain_conv_out;
    PlainTensor plain_bn_out;
    PlainTensor plain_relu_out;
    PlainTensor plain_pool_out;

    output << "\n========== Stem ==========\n";
    output << "stem: 7x7 stride-2 conv -> bn -> relu -> 3x3 stride-2 maxpool\n";
    output << "note: encrypted stem still uses average pool as an HE-friendly maxpool surrogate\n";

    multiplexed_convolution_print(
        state.cipher, conv_out, 64, 2, 7, 7, weights.conv_weight.at(state.conv_idx),
        weights.bn_running_var.at(state.bn_idx), weights.bn_weight.at(state.bn_idx),
        kBatchNormEpsilon, runtime.encoder, runtime.encryptor,
        *runtime.evaluator, runtime.galois_keys, cipher_pool, output, runtime.decryptor,
        runtime.context, 0, false);
    plain_conv_out =
        plain_convolution(state.plain, 64, 2, 7, 7, weights.conv_weight.at(state.conv_idx),
                          weights.bn_running_var.at(state.bn_idx),
                          weights.bn_weight.at(state.bn_idx), kBatchNormEpsilon);
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
    ++state.bn_idx;

    run_relu(bn_out, relu_out, plain_bn_out, plain_relu_out, ctx, output, 0);

    if (kUseApproximateEncryptedMaxPool)
    {
        pool_out = run_approx_max_pool2d(relu_out, 64, ctx, output, 0);
    }
    else
    {
        const vector<double> pool_weights = make_channelwise_average_pool_weights(64, 3);
        const vector<double> ones = filled_vector(64, 1.0);
        multiplexed_convolution_print(
            relu_out, pool_out, 64, 2, 3, 3, pool_weights, ones, ones, 0.0, runtime.encoder,
            runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool, output,
            runtime.decryptor, runtime.context, 0, false);
    }
    plain_pool_out = plain_max_pool2d(plain_relu_out, 3, 2, 1);
    state.cipher = std::move(pool_out);
    state.plain = std::move(plain_pool_out);
}

void run_projection_shortcut(const TensorCipher &shortcut, TensorCipher &projected,
                             const PlainTensor &plain_shortcut, PlainTensor &plain_projected,
                             int downsample_index, const PoseidonStagePlan &stage_plan,
                             RunContext &ctx, ofstream &output)
{
    PoseidonRuntime &runtime = ctx.runtime;
    const ModelWeights &weights = ctx.weights;
    vector<Ciphertext> cipher_pool;
    TensorCipher conv_out;

    multiplexed_convolution_print(
        shortcut, conv_out, stage_plan.out_channels, 2, 1, 1,
        weights.downsample_weight.at(static_cast<size_t>(downsample_index)),
        weights.downsample_bn_running_var.at(static_cast<size_t>(downsample_index)),
        weights.downsample_bn_weight.at(static_cast<size_t>(downsample_index)), kBatchNormEpsilon,
        runtime.encoder, runtime.encryptor, *runtime.evaluator, runtime.galois_keys, cipher_pool,
        output, runtime.decryptor, runtime.context, 0, false);
    PlainTensor plain_conv =
        plain_convolution(plain_shortcut, stage_plan.out_channels, 2, 1, 1,
                          weights.downsample_weight.at(static_cast<size_t>(downsample_index)),
                          weights.downsample_bn_running_var.at(static_cast<size_t>(downsample_index)),
                          weights.downsample_bn_weight.at(static_cast<size_t>(downsample_index)),
                          kBatchNormEpsilon);

    multiplexed_batch_norm_print(
        conv_out, projected, weights.downsample_bn_bias.at(static_cast<size_t>(downsample_index)),
        weights.downsample_bn_running_mean.at(static_cast<size_t>(downsample_index)),
        weights.downsample_bn_running_var.at(static_cast<size_t>(downsample_index)),
        weights.downsample_bn_weight.at(static_cast<size_t>(downsample_index)), kBatchNormEpsilon,
        runtime.encoder, runtime.encryptor, *runtime.evaluator, 40.0, output, runtime.decryptor,
        runtime.context, 0, false);
    plain_projected =
        plain_batch_norm(plain_conv,
                         weights.downsample_bn_bias.at(static_cast<size_t>(downsample_index)),
                         weights.downsample_bn_running_mean.at(static_cast<size_t>(downsample_index)),
                         weights.downsample_bn_running_var.at(static_cast<size_t>(downsample_index)),
                         weights.downsample_bn_weight.at(static_cast<size_t>(downsample_index)),
                         kBatchNormEpsilon, 40.0);
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
    TensorCipher shortcut_projected;
    TensorCipher added;
    TensorCipher block_output;
    PlainTensor plain_shortcut = state.plain;
    PlainTensor plain_branch_conv1;
    PlainTensor plain_branch_bn1;
    PlainTensor plain_branch_relu1;
    PlainTensor plain_branch_conv2;
    PlainTensor plain_branch_bn2;
    PlainTensor plain_shortcut_projected;
    PlainTensor plain_added;
    PlainTensor plain_block_output;

    const int stride = (block_index == 0) ? stage_plan.first_block_stride : 1;
    output << "\n========== " << stage_plan.name << " Block " << block_index
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
    ++state.bn_idx;

    if (stage_index > 0 && block_index == 0)
    {
        run_projection_shortcut(shortcut, shortcut_projected, plain_shortcut,
                                plain_shortcut_projected, stage_index - 1, stage_plan, ctx,
                                output);
        shortcut = std::move(shortcut_projected);
        plain_shortcut = std::move(plain_shortcut_projected);
    }

    align_for_add(branch_bn2, shortcut, runtime);
    cipher_add_stage_print(branch_bn2, shortcut, added, *runtime.evaluator, output,
                           runtime.decryptor, runtime.encoder, runtime.context);
    plain_added = plain_add(plain_branch_bn2, plain_shortcut);

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
    fully_connected_print(pooled, logits, weights.linear_weight, weights.linear_bias,
                          kImageNetClassCount, kResNet18FinalChannels, *runtime.evaluator,
                          runtime.galois_keys, output, runtime.decryptor, runtime.encoder,
                          runtime.context);
    plain_logits = plain_fully_connected(plain_pooled, weights.linear_weight, weights.linear_bias,
                                         kImageNetClassCount, kResNet18FinalChannels);
    state.cipher = std::move(logits);
    state.plain = std::move(plain_pooled);
    return decode_real_slots(state.cipher, runtime, kImageNetClassCount);
}

} // namespace

void ResNet_imagenet_sparse(size_t start_image_id, size_t end_image_id)
{
    const PoseidonInferPlan plan = default_poseidon_plan();
    const size_t image_value_count =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth * kImageNetInputChannels);
    const size_t slot_count = static_cast<size_t>(1) << plan.log_slots;
    const size_t input_chunk_count = (image_value_count + slot_count - 1) / slot_count;
    const string run_timestamp = make_run_timestamp();
    ReluConfig relu_config = default_relu_config(plan);

    fs::create_directories(result_dir());
    const fs::path run_result_path =
        result_dir() / (string(kResNet18ResultPrefix) + "_run_" + to_string(start_image_id) +
                        "_" + to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream out_log(run_result_path);
    if (!out_log.is_open())
    {
        throw runtime_error("failed to open run log file");
    }
    ScopedProgressLogTarget progress_log_target(out_log);

    resnet18_progress_log() << "Setting Poseidon Parameters" << endl;
    PoseidonRuntime runtime = make_poseidon_runtime(plan, false);
    resnet18_progress_log() << "Poseidon slot count: " << runtime.slot_count << endl;
    resnet18_progress_log() << "Poseidon scale: " << runtime.scale << endl;
    resnet18_progress_log() << "ImageNet input values: " << image_value_count
         << ", encrypted input chunks: " << input_chunk_count << endl;

    out_log << "run_start: start_image_id=" << start_image_id
            << ", end_image_id=" << end_image_id
            << ", run_timestamp=" << run_timestamp
            << ", log_file=" << run_result_path << '\n';

    const auto all_time_start = chrono::high_resolution_clock::now();
    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const auto image_time_start = chrono::high_resolution_clock::now();
        out_log << "image_start: " << image_id << '\n';
        out_log.flush();
        ofstream &output = out_log;

        output << "\n==================== run_start ====================\n";
        output << "image_id: " << image_id << '\n';
        output << "run_timestamp: " << run_timestamp << '\n';
        output << "log_file: " << run_result_path << '\n';

        vector<double> image_values = read_plain_image_values(image_id, plan.boundary);
        const int image_label = read_image_label(image_id);

        output << "runtime: poseidon ready\n";
        output << "input values=" << image_values.size() << ", slot_count=" << slot_count
               << ", input_chunk_count=" << input_chunk_count << '\n';

        TensorCipherGroup input_group(static_cast<int>(plan.logN), kImageNetInputHeight,
                                      kImageNetInputWidth, kImageNetInputChannels, image_values,
                                      runtime.encryptor, runtime.encoder, plan.log_scale);
        input_group.print_summary(output);

        vector<double> decrypted_input = input_group.decrypt_values(runtime.decryptor,
                                                                    runtime.encoder);
        double max_abs_error = 0.0;
        for (size_t i = 0; i < min(image_values.size(), decrypted_input.size()); ++i)
        {
            max_abs_error = max(max_abs_error, abs(image_values[i] - decrypted_input[i]));
        }
        output << "input decrypt max_abs_error: " << max_abs_error << '\n';

        ModelWeights weights = load_resnet18_parameters();
        constexpr size_t kConv1SingleOutputPreviewCount = 4;
        PlainTensor plain_input(kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels,
                                image_values);
        PlainTensor plain_conv1 = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight.at(0), weights.bn_running_var.at(0),
            weights.bn_weight.at(0), kBatchNormEpsilon);
        double conv1_preview_max_abs_error = -1.0;
        if (kRunConv1SingleOutputPreview)
        {
            output << "conv1 single-output preview: generating slot-sum rotation keys\n";
            vector<int> conv1_steps = slot_sum_rotation_steps(input_group);
            output << "conv1 single-output rotation key count: " << conv1_steps.size() << '\n';
            resnet18_progress_log() << "conv1 single-output rotation key count: " << conv1_steps.size() << endl;
            KeyGenerator preview_keygen(runtime.context, runtime.secret_key);
            preview_keygen.create_galois_keys(conv1_steps, runtime.galois_keys);

            output << "conv1 single-output preview: encrypted dot product evaluation\n";
            resnet18_progress_log() << "conv1 first " << kConv1SingleOutputPreviewCount
                 << " outputs encrypted evaluation" << endl;
            conv1_preview_max_abs_error = 0.0;
            for (size_t output_index = 0; output_index < kConv1SingleOutputPreviewCount;
                 ++output_index)
            {
                const double encrypted_output = encrypted_conv2d_group_single_output(
                    input_group, output_index, 64, 2, 7, 7, weights.conv_weight.at(0),
                    weights.bn_running_var.at(0), weights.bn_weight.at(0), kBatchNormEpsilon,
                    runtime);
                const double plain_output = plain_conv1.values.at(output_index);
                const double abs_error = abs(encrypted_output - plain_output);
                conv1_preview_max_abs_error = max(conv1_preview_max_abs_error, abs_error);
                output << "conv1 encrypted output[" << output_index << "]: " << encrypted_output
                       << ", plain: " << plain_output << ", abs_error: " << abs_error << '\n';
            }
            output << "conv1 preview max_abs_error: " << conv1_preview_max_abs_error << '\n';
            resnet18_progress_log() << "conv1 preview max_abs_error: " << conv1_preview_max_abs_error << endl;
        }
        else
        {
            output << "conv1 single-output preview skipped for bootstrap debug\n";
            resnet18_progress_log() << "conv1 single-output preview skipped for bootstrap debug" << endl;
        }

        output << "conv1 im2col packing: encrypting 7x7x3 patch ciphertexts\n";
        resnet18_progress_log() << "conv1 im2col encrypt patches" << endl;
        Im2ColCipherGroup conv1_im2col = encrypt_conv2d_im2col_patches(
            image_values, kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels, 2, 7,
            7, runtime, plan.log_scale);
        output << "conv1 im2col patches: " << conv1_im2col.patches.size()
               << ", spatial_count=" << conv1_im2col.spatial_count << '\n';
        resnet18_progress_log() << "conv1 im2col patches: " << conv1_im2col.patches.size() << endl;

        output << "conv1 im2col: encrypted output channel 0 evaluation\n";
        resnet18_progress_log() << "conv1 im2col output channel 0 encrypted evaluation" << endl;
        Ciphertext encrypted_conv1_channel0_cipher = encrypted_conv2d_im2col_output_channel_cipher(
            conv1_im2col, 0, 64, weights.conv_weight.at(0), weights.bn_running_var.at(0),
            weights.bn_weight.at(0), kBatchNormEpsilon, runtime);
        TensorCipher conv1_channel0_tensor(static_cast<int>(plan.logN), 1, conv1_im2col.out_h,
                                           conv1_im2col.out_w, 1, 1, 1,
                                           encrypted_conv1_channel0_cipher);
        vector<double> encrypted_conv1_channel0 =
            decode_real_slots(conv1_channel0_tensor, runtime, conv1_im2col.spatial_count);
        double conv1_channel0_max_abs_error = 0.0;
        for (size_t spatial = 0; spatial < encrypted_conv1_channel0.size(); ++spatial)
        {
            conv1_channel0_max_abs_error =
                max(conv1_channel0_max_abs_error,
                    abs(encrypted_conv1_channel0[spatial] - plain_conv1.values.at(spatial)));
        }
        output << "conv1 channel0 count: " << encrypted_conv1_channel0.size() << '\n';
        output << "conv1 channel0 max_abs_error: " << conv1_channel0_max_abs_error << '\n';
        resnet18_progress_log() << "conv1 channel0 max_abs_error: " << conv1_channel0_max_abs_error << endl;

        PlainTensor plain_conv1_bn =
            plain_batch_norm(plain_conv1, weights.bn_bias.at(0), weights.bn_running_mean.at(0),
                             weights.bn_running_var.at(0), weights.bn_weight.at(0),
                             kBatchNormEpsilon, 40.0);

        output << "conv1 batch norm offset: encrypted channel 0 evaluation\n";
        resnet18_progress_log() << "conv1 batch norm channel0 encrypted evaluation" << endl;
        const double conv1_bn_channel0_offset =
            (weights.bn_bias.at(0).at(0) -
             weights.bn_running_mean.at(0).at(0) * weights.bn_weight.at(0).at(0) /
                 sqrt(weights.bn_running_var.at(0).at(0) + kBatchNormEpsilon)) /
            40.0;
        Ciphertext encrypted_conv1_bn_channel0_cipher;
        runtime.evaluator->add_const(encrypted_conv1_channel0_cipher, conv1_bn_channel0_offset,
                                     encrypted_conv1_bn_channel0_cipher, runtime.encoder);
        TensorCipher conv1_bn_channel0_tensor(static_cast<int>(plan.logN), 1, conv1_im2col.out_h,
                                              conv1_im2col.out_w, 1, 1, 1,
                                              encrypted_conv1_bn_channel0_cipher);
        vector<double> encrypted_conv1_bn_channel0 =
            decode_real_slots(conv1_bn_channel0_tensor, runtime, conv1_im2col.spatial_count);
        double conv1_bn_channel0_max_abs_error = 0.0;
        for (size_t spatial = 0; spatial < encrypted_conv1_bn_channel0.size(); ++spatial)
        {
            conv1_bn_channel0_max_abs_error =
                max(conv1_bn_channel0_max_abs_error,
                    abs(encrypted_conv1_bn_channel0[spatial] -
                        plain_conv1_bn.values.at(spatial)));
        }
        output << "conv1 batch norm channel0 max_abs_error: "
               << conv1_bn_channel0_max_abs_error << '\n';
        resnet18_progress_log() << "conv1 batch norm channel0 max_abs_error: "
             << conv1_bn_channel0_max_abs_error << endl;

        double conv1_all_max_abs_error = -1.0;
        double conv1_bn_max_abs_error = -1.0;
        if (kRunFullConv1GroupCheck)
        {
            output << "conv1 im2col: encrypted all 64 output channels evaluation\n";
            resnet18_progress_log() << "conv1 im2col all channels encrypted evaluation" << endl;
            ChannelCipherGroup encrypted_conv1_group = encrypted_conv2d_im2col_all_channels(
                conv1_im2col, 64, weights.conv_weight.at(0), weights.bn_running_var.at(0),
                weights.bn_weight.at(0), kBatchNormEpsilon, runtime);
            vector<double> decrypted_conv1 = decrypt_channel_cipher_group(encrypted_conv1_group,
                                                                          runtime);
            conv1_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_conv1.size(); ++i)
            {
                conv1_all_max_abs_error = max(conv1_all_max_abs_error,
                                              abs(decrypted_conv1[i] - plain_conv1.values.at(i)));
            }
            output << "conv1 encrypted group channels: " << encrypted_conv1_group.channels.size()
                   << ", spatial_count=" << encrypted_conv1_group.spatial_count << '\n';
            output << "conv1 all max_abs_error: " << conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "conv1 all max_abs_error: " << conv1_all_max_abs_error << endl;

            output << "conv1 batch norm offset: encrypted all-channel evaluation\n";
            resnet18_progress_log() << "conv1 batch norm all-channel encrypted evaluation" << endl;
            ChannelCipherGroup encrypted_conv1_bn_group = encrypted_channel_batch_norm(
                encrypted_conv1_group, weights.bn_bias.at(0), weights.bn_running_mean.at(0),
                weights.bn_running_var.at(0), weights.bn_weight.at(0), kBatchNormEpsilon, 40.0,
                runtime);
            vector<double> decrypted_conv1_bn =
                decrypt_channel_cipher_group(encrypted_conv1_bn_group, runtime);
            conv1_bn_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_conv1_bn.size(); ++i)
            {
                conv1_bn_max_abs_error =
                    max(conv1_bn_max_abs_error,
                        abs(decrypted_conv1_bn[i] - plain_conv1_bn.values.at(i)));
            }
            output << "conv1 batch norm max_abs_error: " << conv1_bn_max_abs_error << '\n';
            resnet18_progress_log() << "conv1 batch norm max_abs_error: " << conv1_bn_max_abs_error << endl;
        }
        else
        {
            output << "conv1 full 64-channel check skipped for relu preview\n";
            resnet18_progress_log() << "conv1 full 64-channel check skipped for relu preview" << endl;
        }

        output << "conv1 relu preview: generating relinearization keys\n";
        resnet18_progress_log() << "conv1 relu preview generating relin keys" << endl;
        KeyGenerator relu_keygen(runtime.context, runtime.secret_key);
        relu_keygen.create_relin_keys(runtime.relin_keys);

        output << "conv1 relu preview: encrypted channel 0 evaluation\n";
        resnet18_progress_log() << "conv1 relu channel0 encrypted evaluation" << endl;
        TensorCipher conv1_bn_channel0(static_cast<int>(plan.logN), 1,
                                       conv1_im2col.out_h, conv1_im2col.out_w, 1, 1, 1,
                                       encrypted_conv1_bn_channel0_cipher);
        TensorCipher conv1_relu_channel0;
        relu(conv1_bn_channel0, conv1_relu_channel0, relu_config.comp_no, relu_config.deg,
             relu_config.alpha, relu_config.tree, relu_config.scaled_val, runtime.encryptor,
             *runtime.evaluator, runtime.encoder, runtime.relin_keys, runtime.scale);
        PlainTensor plain_conv1_relu = plain_relu_reference(plain_conv1_bn);
        vector<double> decrypted_conv1_relu_channel0 =
            decode_real_slots(conv1_relu_channel0, runtime, conv1_im2col.spatial_count);
        double conv1_relu_channel0_max_abs_error = 0.0;
        for (size_t i = 0; i < decrypted_conv1_relu_channel0.size(); ++i)
        {
            conv1_relu_channel0_max_abs_error =
                max(conv1_relu_channel0_max_abs_error,
                    abs(decrypted_conv1_relu_channel0[i] - plain_conv1_relu.values.at(i)));
        }
        output << "conv1 relu channel0 max_abs_error: "
               << conv1_relu_channel0_max_abs_error << '\n';
        resnet18_progress_log() << "conv1 relu channel0 max_abs_error: "
             << conv1_relu_channel0_max_abs_error << endl;
        log_tensor_cipher_state("conv1 relu channel0 output", conv1_relu_channel0, runtime);
        resnet18_progress_log() << "conv1 relu channel0 chain index: "
             << cipher_chain_index(runtime, conv1_relu_channel0.cipher())
             << ", scale: " << conv1_relu_channel0.cipher().scale() << endl;
        output << "conv1 relu channel0 chain index: "
               << cipher_chain_index(runtime, conv1_relu_channel0.cipher())
               << ", scale: " << conv1_relu_channel0.cipher().scale() << '\n';

        double conv1_relu_bootstrap_channel0_max_abs_error = -1.0;
        if (kBootstrapAfterConv1ReluPreview)
        {
            output << "conv1 relu channel0 debug refresh: decrypt and re-encrypt\n";
            resnet18_progress_log() << "conv1 relu channel0 debug refresh decrypt-reencrypt" << endl;
            conv1_relu_channel0 =
                decrypt_reencrypt_tensor(conv1_relu_channel0, runtime,
                                         conv1_im2col.spatial_count);
            log_tensor_cipher_state("conv1 relu channel0 debug refresh output",
                                    conv1_relu_channel0, runtime);
            resnet18_progress_log() << "conv1 relu channel0 post-refresh chain index: "
                 << cipher_chain_index(runtime, conv1_relu_channel0.cipher())
                 << ", scale: " << conv1_relu_channel0.cipher().scale() << endl;
            output << "conv1 relu channel0 post-refresh chain index: "
                   << cipher_chain_index(runtime, conv1_relu_channel0.cipher())
                   << ", scale: " << conv1_relu_channel0.cipher().scale() << '\n';

            vector<double> decrypted_refreshed_relu_channel0 =
                decode_real_slots(conv1_relu_channel0, runtime, conv1_im2col.spatial_count);
            conv1_relu_bootstrap_channel0_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_refreshed_relu_channel0.size(); ++i)
            {
                conv1_relu_bootstrap_channel0_max_abs_error =
                    max(conv1_relu_bootstrap_channel0_max_abs_error,
                        abs(decrypted_refreshed_relu_channel0[i] -
                            plain_conv1_relu.values.at(i)));
            }
            output << "conv1 relu debug refresh channel0 max_abs_error: "
                   << conv1_relu_bootstrap_channel0_max_abs_error << '\n';
            resnet18_progress_log() << "conv1 relu debug refresh channel0 max_abs_error: "
                 << conv1_relu_bootstrap_channel0_max_abs_error << endl;
        }

        output << "conv1 sparse maxpool: generating rotation keys\n";
        vector<int> maxpool_steps =
            maxpool_channel_sparse_rotation_steps(conv1_im2col.out_w, 3, 1);
        resnet18_progress_log() << "conv1 sparse maxpool rotation key count: " << maxpool_steps.size() << endl;
        output << "conv1 sparse maxpool rotation key count: " << maxpool_steps.size() << '\n';
        KeyGenerator maxpool_keygen(runtime.context, runtime.secret_key);
        maxpool_keygen.create_galois_keys(maxpool_steps, runtime.galois_keys);

        output << "conv1 sparse maxpool: encrypted full channel 0 evaluation\n";
        resnet18_progress_log() << "conv1 sparse maxpool channel0 encrypted full evaluation" << endl;
        vector<TensorCipher> maxpool_candidates;
        maxpool_candidates.reserve(9);
        for (int kh = 0; kh < 3; ++kh)
        {
            for (int kw = 0; kw < 3; ++kw)
            {
                Ciphertext candidate_cipher = encrypted_maxpool_candidate_sparse(
                    conv1_relu_channel0.cipher(), conv1_im2col.out_h, conv1_im2col.out_w, 3, 2,
                    1, kh, kw, runtime);
                maxpool_candidates.emplace_back(static_cast<int>(plan.logN), 1,
                                                conv1_im2col.out_h, conv1_im2col.out_w, 1, 1, 1,
                                                candidate_cipher);
            }
        }

        RunContext maxpool_preview_ctx{runtime, relu_config, weights};
        while (maxpool_candidates.size() > 1)
        {
            vector<TensorCipher> reduced;
            reduced.reserve((maxpool_candidates.size() + 1) / 2);
            for (size_t i = 0; i < maxpool_candidates.size(); i += 2)
            {
                if (i + 1 == maxpool_candidates.size())
                {
                    reduced.emplace_back(std::move(maxpool_candidates[i]));
                }
                else
                {
                    reduced.emplace_back(run_approx_pairwise_max_preview(
                        maxpool_candidates[i], maxpool_candidates[i + 1], maxpool_preview_ctx));
                }
            }
            maxpool_candidates = std::move(reduced);
        }

        PlainTensor plain_conv1_pool = plain_max_pool2d(plain_conv1_relu, 3, 2, 1);
        vector<double> decrypted_conv1_pool_channel0 =
            decode_real_slots(maxpool_candidates.front(), runtime, conv1_im2col.spatial_count);
        double conv1_maxpool_channel0_preview_max_abs_error = -1.0;
        double conv1_maxpool_channel0_sparse_max_abs_error = 0.0;
        const int pool_h = plain_conv1_pool.h;
        const int pool_w = plain_conv1_pool.w;
        for (int oh = 0; oh < pool_h; ++oh)
        {
            for (int ow = 0; ow < pool_w; ++ow)
            {
                const size_t sparse_slot =
                    static_cast<size_t>((oh * 2) * conv1_im2col.out_w + ow * 2);
                const size_t plain_index = static_cast<size_t>(oh * pool_w + ow);
                const double abs_error =
                    abs(decrypted_conv1_pool_channel0.at(sparse_slot) -
                        plain_conv1_pool.values.at(plain_index));
                conv1_maxpool_channel0_sparse_max_abs_error =
                    max(conv1_maxpool_channel0_sparse_max_abs_error, abs_error);
                if (plain_index < kMaxPoolPreviewCount)
                {
                    output << "conv1 sparse maxpool output[" << plain_index
                           << "]: " << decrypted_conv1_pool_channel0.at(sparse_slot)
                           << ", plain: " << plain_conv1_pool.values.at(plain_index)
                           << ", abs_error: " << abs_error << '\n';
                }
            }
        }
        output << "conv1 sparse maxpool channel0 count: "
               << static_cast<size_t>(pool_h * pool_w) << '\n';
        output << "conv1 sparse maxpool channel0 max_abs_error: "
               << conv1_maxpool_channel0_sparse_max_abs_error << '\n';
        resnet18_progress_log() << "conv1 sparse maxpool channel0 max_abs_error: "
             << conv1_maxpool_channel0_sparse_max_abs_error << endl;

        double stem_conv1_all_max_abs_error = -1.0;
        double stem_bn_all_max_abs_error = -1.0;
        double stem_relu_refresh_all_max_abs_error = -1.0;
        double stem_sparse_maxpool_all_max_abs_error = -1.0;
        double layer1_block0_conv1_channel0_max_abs_error = -1.0;
        double layer1_block0_conv1_all_max_abs_error = -1.0;
        double layer1_block0_bn1_all_max_abs_error = -1.0;
        double layer1_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer1_block0_conv2_all_max_abs_error = -1.0;
        double layer1_block0_bn2_all_max_abs_error = -1.0;
        double layer1_block0_add_all_max_abs_error = -1.0;
        double layer1_block0_output_refresh_all_max_abs_error = -1.0;
        double layer1_block1_conv1_all_max_abs_error = -1.0;
        double layer1_block1_bn1_all_max_abs_error = -1.0;
        double layer1_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer1_block1_conv2_all_max_abs_error = -1.0;
        double layer1_block1_bn2_all_max_abs_error = -1.0;
        double layer1_block1_add_all_max_abs_error = -1.0;
        double layer1_block1_output_refresh_all_max_abs_error = -1.0;
        double layer2_block0_conv1_sparse_max_abs_error = -1.0;
        double layer2_block0_bn1_sparse_max_abs_error = -1.0;
        double layer2_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer2_block0_conv2_all_max_abs_error = -1.0;
        double layer2_block0_bn2_all_max_abs_error = -1.0;
        double layer2_block0_shortcut_all_max_abs_error = -1.0;
        double layer2_block0_add_all_max_abs_error = -1.0;
        double layer2_block0_output_refresh_all_max_abs_error = -1.0;
        double layer2_block1_conv1_all_max_abs_error = -1.0;
        double layer2_block1_bn1_all_max_abs_error = -1.0;
        double layer2_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer2_block1_conv2_all_max_abs_error = -1.0;
        double layer2_block1_bn2_all_max_abs_error = -1.0;
        double layer2_block1_add_all_max_abs_error = -1.0;
        double layer2_block1_output_refresh_all_max_abs_error = -1.0;
        double layer3_block0_conv1_sparse_max_abs_error = -1.0;
        double layer3_block0_bn1_sparse_max_abs_error = -1.0;
        double layer3_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer3_block0_conv2_all_max_abs_error = -1.0;
        double layer3_block0_bn2_all_max_abs_error = -1.0;
        double layer3_block0_shortcut_all_max_abs_error = -1.0;
        double layer3_block0_add_all_max_abs_error = -1.0;
        double layer3_block0_output_refresh_all_max_abs_error = -1.0;
        double layer3_block1_conv1_all_max_abs_error = -1.0;
        double layer3_block1_bn1_all_max_abs_error = -1.0;
        double layer3_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer3_block1_conv2_all_max_abs_error = -1.0;
        double layer3_block1_bn2_all_max_abs_error = -1.0;
        double layer3_block1_add_all_max_abs_error = -1.0;
        double layer3_block1_output_refresh_all_max_abs_error = -1.0;
        double layer4_block0_conv1_sparse_max_abs_error = -1.0;
        double layer4_block0_bn1_sparse_max_abs_error = -1.0;
        double layer4_block0_relu1_refresh_all_max_abs_error = -1.0;
        double layer4_block0_conv2_all_max_abs_error = -1.0;
        double layer4_block0_bn2_all_max_abs_error = -1.0;
        double layer4_block0_shortcut_all_max_abs_error = -1.0;
        double layer4_block0_add_all_max_abs_error = -1.0;
        double layer4_block0_output_refresh_all_max_abs_error = -1.0;
        double layer4_block1_conv1_all_max_abs_error = -1.0;
        double layer4_block1_bn1_all_max_abs_error = -1.0;
        double layer4_block1_relu1_refresh_all_max_abs_error = -1.0;
        double layer4_block1_conv2_all_max_abs_error = -1.0;
        double layer4_block1_bn2_all_max_abs_error = -1.0;
        double layer4_block1_add_all_max_abs_error = -1.0;
        double layer4_block1_output_refresh_all_max_abs_error = -1.0;
        double head_avgpool_debug_pack_max_abs_error = -1.0;
        double head_logits_max_abs_error = -1.0;
        int encrypted_predicted_label = -1;
        int plain_head_predicted_label = -1;
        if (kRunFullStemCheck)
        {
            output << "stem full 64-channel: encrypted conv1 evaluation\n";
            resnet18_progress_log() << "stem full 64-channel conv1 encrypted evaluation" << endl;
            ChannelCipherGroup stem_conv1_group = encrypted_conv2d_im2col_all_channels(
                conv1_im2col, 64, weights.conv_weight.at(0), weights.bn_running_var.at(0),
                weights.bn_weight.at(0), kBatchNormEpsilon, runtime);
            vector<double> decrypted_stem_conv1 = decrypt_channel_cipher_group(stem_conv1_group,
                                                                               runtime);
            stem_conv1_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_stem_conv1.size(); ++i)
            {
                stem_conv1_all_max_abs_error =
                    max(stem_conv1_all_max_abs_error,
                        abs(decrypted_stem_conv1[i] - plain_conv1.values.at(i)));
            }
            output << "stem conv1 all max_abs_error: " << stem_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem conv1 all max_abs_error: " << stem_conv1_all_max_abs_error << endl;

            output << "stem full 64-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "stem full 64-channel BN encrypted evaluation" << endl;
            ChannelCipherGroup stem_bn_group = encrypted_channel_batch_norm(
                stem_conv1_group, weights.bn_bias.at(0), weights.bn_running_mean.at(0),
                weights.bn_running_var.at(0), weights.bn_weight.at(0), kBatchNormEpsilon, 40.0,
                runtime);
            vector<double> decrypted_stem_bn = decrypt_channel_cipher_group(stem_bn_group,
                                                                            runtime);
            stem_bn_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_stem_bn.size(); ++i)
            {
                stem_bn_all_max_abs_error =
                    max(stem_bn_all_max_abs_error,
                        abs(decrypted_stem_bn[i] - plain_conv1_bn.values.at(i)));
            }
            output << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem BN all max_abs_error: " << stem_bn_all_max_abs_error << endl;

            output << "stem full 64-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "stem full 64-channel ReLU + debug refresh evaluation" << endl;
            ChannelCipherGroup stem_relu_refresh_group;
            stem_relu_refresh_group.h = stem_bn_group.h;
            stem_relu_refresh_group.w = stem_bn_group.w;
            stem_relu_refresh_group.c = stem_bn_group.c;
            stem_relu_refresh_group.spatial_count = stem_bn_group.spatial_count;
            stem_relu_refresh_group.slot_count = stem_bn_group.slot_count;
            stem_relu_refresh_group.channels.reserve(stem_bn_group.channels.size());
            for (int channel = 0; channel < stem_bn_group.c; ++channel)
            {
                if (channel % 8 == 0)
                {
                    resnet18_progress_log() << "stem ReLU channel progress: " << channel << "/"
                         << stem_bn_group.c << endl;
                }
                TensorCipher bn_channel(static_cast<int>(plan.logN), 1, stem_bn_group.h,
                                        stem_bn_group.w, 1, 1, 1,
                                        stem_bn_group.channels.at(static_cast<size_t>(channel)));
                TensorCipher relu_channel;
                relu(bn_channel, relu_channel, relu_config.comp_no, relu_config.deg,
                     relu_config.alpha, relu_config.tree, relu_config.scaled_val,
                     runtime.encryptor, *runtime.evaluator, runtime.encoder,
                     runtime.relin_keys, runtime.scale);
                TensorCipher refreshed_relu_channel =
                    decrypt_reencrypt_tensor(relu_channel, runtime, stem_bn_group.spatial_count);
                stem_relu_refresh_group.channels.emplace_back(
                    refreshed_relu_channel.cipher());
            }
            resnet18_progress_log() << "stem ReLU channel progress: " << stem_bn_group.c << "/"
                 << stem_bn_group.c << endl;
            log_channel_group_cipher_state("stem ReLU refresh output",
                                           stem_relu_refresh_group, runtime);
            vector<double> decrypted_stem_relu =
                decrypt_channel_cipher_group(stem_relu_refresh_group, runtime);
            stem_relu_refresh_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_stem_relu.size(); ++i)
            {
                stem_relu_refresh_all_max_abs_error =
                    max(stem_relu_refresh_all_max_abs_error,
                        abs(decrypted_stem_relu[i] - plain_conv1_relu.values.at(i)));
            }
            output << "stem ReLU refresh all max_abs_error: "
                   << stem_relu_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem ReLU refresh all max_abs_error: "
                 << stem_relu_refresh_all_max_abs_error << endl;

            output << "stem full 64-channel: encrypted sparse maxpool evaluation\n";
            resnet18_progress_log() << "stem full 64-channel sparse maxpool encrypted evaluation" << endl;
            stem_sparse_maxpool_all_max_abs_error = 0.0;
            RunContext stem_maxpool_ctx{runtime, relu_config, weights};
            ChannelCipherGroup stem_dense_pool_group;
            stem_dense_pool_group.h = plain_conv1_pool.h;
            stem_dense_pool_group.w = plain_conv1_pool.w;
            stem_dense_pool_group.c = stem_relu_refresh_group.c;
            stem_dense_pool_group.spatial_count =
                static_cast<size_t>(plain_conv1_pool.h * plain_conv1_pool.w);
            stem_dense_pool_group.slot_count = runtime.encoder.slot_count();
            stem_dense_pool_group.channels.reserve(
                static_cast<size_t>(stem_relu_refresh_group.c));
            for (int channel = 0; channel < stem_relu_refresh_group.c; ++channel)
            {
                if (channel % 8 == 0)
                {
                    resnet18_progress_log() << "stem sparse maxpool channel progress: " << channel << "/"
                         << stem_relu_refresh_group.c << endl;
                }
                TensorCipher relu_channel(static_cast<int>(plan.logN), 1,
                                          stem_relu_refresh_group.h,
                                          stem_relu_refresh_group.w, 1, 1, 1,
                                          stem_relu_refresh_group.channels.at(
                                              static_cast<size_t>(channel)));
                TensorCipher sparse_pool_channel = run_sparse_maxpool_channel(
                    relu_channel, stem_relu_refresh_group.h, stem_relu_refresh_group.w,
                    stem_maxpool_ctx, false);
                stem_sparse_maxpool_all_max_abs_error =
                    max(stem_sparse_maxpool_all_max_abs_error,
                        sparse_maxpool_channel_error(sparse_pool_channel,
                                                     stem_relu_refresh_group.w,
                                                     plain_conv1_pool, channel, runtime));

                vector<double> sparse_values =
                    decode_real_slots(sparse_pool_channel, runtime,
                                      stem_relu_refresh_group.spatial_count);
                vector<double> dense_values(stem_dense_pool_group.spatial_count, 0.0);
                for (int oh = 0; oh < stem_dense_pool_group.h; ++oh)
                {
                    for (int ow = 0; ow < stem_dense_pool_group.w; ++ow)
                    {
                        const size_t sparse_slot = static_cast<size_t>(
                            (oh * 2) * stem_relu_refresh_group.w + ow * 2);
                        dense_values[static_cast<size_t>(oh * stem_dense_pool_group.w + ow)] =
                            sparse_values.at(sparse_slot);
                    }
                }
                TensorCipher dense_pool_channel(static_cast<int>(plan.logN), 1,
                                                stem_dense_pool_group.h,
                                                stem_dense_pool_group.w, 1, 1, 1,
                                                dense_values, runtime.encryptor,
                                                runtime.encoder, plan.log_scale);
                stem_dense_pool_group.channels.emplace_back(dense_pool_channel.cipher());
            }
            resnet18_progress_log() << "stem sparse maxpool channel progress: " << stem_relu_refresh_group.c
                 << "/" << stem_relu_refresh_group.c << endl;
            log_channel_group_cipher_state("stem sparse maxpool output",
                                           stem_dense_pool_group, runtime);
            output << "stem sparse maxpool all max_abs_error: "
                   << stem_sparse_maxpool_all_max_abs_error << '\n';
            resnet18_progress_log() << "stem sparse maxpool all max_abs_error: "
                 << stem_sparse_maxpool_all_max_abs_error << endl;

            output << "layer1 block0 conv1 channel0: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer1 block0 conv1 channel0 encrypted evaluation" << endl;
            vector<int> layer1_conv_steps =
                dense_conv2d_channel_rotation_steps(stem_dense_pool_group.w, 3, 3);
            resnet18_progress_log() << "layer1 block0 conv1 rotation key count: "
                 << layer1_conv_steps.size() << endl;
            output << "layer1 block0 conv1 rotation key count: "
                   << layer1_conv_steps.size() << '\n';
            KeyGenerator layer1_keygen(runtime.context, runtime.secret_key);
            layer1_keygen.create_galois_keys(layer1_conv_steps, runtime.galois_keys);

            PlainTensor plain_layer1_block0_conv1 = plain_convolution(
                plain_conv1_pool, 64, 1, 3, 3, weights.conv_weight.at(1),
                weights.bn_running_var.at(1), weights.bn_weight.at(1), kBatchNormEpsilon);
            Ciphertext encrypted_layer1_block0_conv1_channel0_cipher =
                encrypted_channel_conv2d_output_channel_cipher(
                    stem_dense_pool_group, 0, 64, 1, 3, 3, weights.conv_weight.at(1),
                    weights.bn_running_var.at(1), weights.bn_weight.at(1), kBatchNormEpsilon,
                    runtime);
            TensorCipher encrypted_layer1_block0_conv1_channel0(
                static_cast<int>(plan.logN), 1, stem_dense_pool_group.h,
                stem_dense_pool_group.w, 1, 1, 1,
                encrypted_layer1_block0_conv1_channel0_cipher);
            vector<double> decrypted_layer1_block0_conv1_channel0 = decode_real_slots(
                encrypted_layer1_block0_conv1_channel0, runtime,
                stem_dense_pool_group.spatial_count);
            layer1_block0_conv1_channel0_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_conv1_channel0.size(); ++i)
            {
                layer1_block0_conv1_channel0_max_abs_error =
                    max(layer1_block0_conv1_channel0_max_abs_error,
                        abs(decrypted_layer1_block0_conv1_channel0[i] -
                            plain_layer1_block0_conv1.values.at(i)));
            }
            output << "layer1 block0 conv1 channel0 max_abs_error: "
                   << layer1_block0_conv1_channel0_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 conv1 channel0 max_abs_error: "
                 << layer1_block0_conv1_channel0_max_abs_error << endl;

            output << "layer1 block0 conv1 full 64-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer1 block0 conv1 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block0_conv1_group =
                encrypted_channel_conv2d_all_channels(
                    stem_dense_pool_group, 64, 1, 3, 3, weights.conv_weight.at(1),
                    weights.bn_running_var.at(1), weights.bn_weight.at(1),
                    kBatchNormEpsilon, runtime);
            vector<double> decrypted_layer1_block0_conv1 =
                decrypt_channel_cipher_group(layer1_block0_conv1_group, runtime);
            layer1_block0_conv1_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_conv1.size(); ++i)
            {
                layer1_block0_conv1_all_max_abs_error =
                    max(layer1_block0_conv1_all_max_abs_error,
                        abs(decrypted_layer1_block0_conv1[i] -
                            plain_layer1_block0_conv1.values.at(i)));
            }
            output << "layer1 block0 conv1 all max_abs_error: "
                   << layer1_block0_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 conv1 all max_abs_error: "
                 << layer1_block0_conv1_all_max_abs_error << endl;

            output << "layer1 block0 bn1 full 64-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer1 block0 bn1 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block0_bn1_group = encrypted_channel_batch_norm(
                layer1_block0_conv1_group, weights.bn_bias.at(1),
                weights.bn_running_mean.at(1), weights.bn_running_var.at(1),
                weights.bn_weight.at(1), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block0_bn1 =
                plain_batch_norm(plain_layer1_block0_conv1, weights.bn_bias.at(1),
                                 weights.bn_running_mean.at(1),
                                 weights.bn_running_var.at(1), weights.bn_weight.at(1),
                                 kBatchNormEpsilon, 40.0);
            vector<double> decrypted_layer1_block0_bn1 =
                decrypt_channel_cipher_group(layer1_block0_bn1_group, runtime);
            layer1_block0_bn1_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_bn1.size(); ++i)
            {
                layer1_block0_bn1_all_max_abs_error =
                    max(layer1_block0_bn1_all_max_abs_error,
                        abs(decrypted_layer1_block0_bn1[i] -
                            plain_layer1_block0_bn1.values.at(i)));
            }
            output << "layer1 block0 bn1 all max_abs_error: "
                   << layer1_block0_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 bn1 all max_abs_error: "
                 << layer1_block0_bn1_all_max_abs_error << endl;

            output << "layer1 block0 relu1 full 64-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer1 block0 relu1 full 64-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer1_block0_relu1 =
                plain_relu_reference(plain_layer1_block0_bn1);
            ChannelCipherGroup layer1_block0_relu1_refresh_group;
            layer1_block0_relu1_refresh_group.h = layer1_block0_bn1_group.h;
            layer1_block0_relu1_refresh_group.w = layer1_block0_bn1_group.w;
            layer1_block0_relu1_refresh_group.c = layer1_block0_bn1_group.c;
            layer1_block0_relu1_refresh_group.spatial_count =
                layer1_block0_bn1_group.spatial_count;
            layer1_block0_relu1_refresh_group.slot_count = layer1_block0_bn1_group.slot_count;
            layer1_block0_relu1_refresh_group.channels.reserve(
                layer1_block0_bn1_group.channels.size());
            for (int channel = 0; channel < layer1_block0_bn1_group.c; ++channel)
            {
                if (channel % 8 == 0)
                {
                    resnet18_progress_log() << "layer1 block0 relu1 channel progress: " << channel << "/"
                         << layer1_block0_bn1_group.c << endl;
                }
                TensorCipher bn1_channel(static_cast<int>(plan.logN), 1,
                                         layer1_block0_bn1_group.h,
                                         layer1_block0_bn1_group.w, 1, 1, 1,
                                         layer1_block0_bn1_group.channels.at(
                                             static_cast<size_t>(channel)));
                TensorCipher relu1_channel;
                relu(bn1_channel, relu1_channel, relu_config.comp_no, relu_config.deg,
                     relu_config.alpha, relu_config.tree, relu_config.scaled_val,
                     runtime.encryptor, *runtime.evaluator, runtime.encoder,
                     runtime.relin_keys, runtime.scale);
                TensorCipher refreshed_relu1_channel = decrypt_reencrypt_tensor(
                    relu1_channel, runtime, layer1_block0_bn1_group.spatial_count);
                layer1_block0_relu1_refresh_group.channels.emplace_back(
                    refreshed_relu1_channel.cipher());
            }
            resnet18_progress_log() << "layer1 block0 relu1 channel progress: "
                 << layer1_block0_bn1_group.c << "/" << layer1_block0_bn1_group.c
                 << endl;
            log_channel_group_cipher_state("layer1 block0 relu1 refresh output",
                                           layer1_block0_relu1_refresh_group, runtime);
            vector<double> decrypted_layer1_block0_relu1 =
                decrypt_channel_cipher_group(layer1_block0_relu1_refresh_group, runtime);
            layer1_block0_relu1_refresh_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_relu1.size(); ++i)
            {
                layer1_block0_relu1_refresh_all_max_abs_error =
                    max(layer1_block0_relu1_refresh_all_max_abs_error,
                        abs(decrypted_layer1_block0_relu1[i] -
                            plain_layer1_block0_relu1.values.at(i)));
            }
            output << "layer1 block0 relu1 refresh all max_abs_error: "
                   << layer1_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 relu1 refresh all max_abs_error: "
                 << layer1_block0_relu1_refresh_all_max_abs_error << endl;

            output << "layer1 block0 conv2 full 64-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer1 block0 conv2 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block0_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer1_block0_relu1_refresh_group, 64, 1, 3, 3,
                    weights.conv_weight.at(2), weights.bn_running_var.at(2),
                    weights.bn_weight.at(2), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer1_block0_conv2 = plain_convolution(
                plain_layer1_block0_relu1, 64, 1, 3, 3, weights.conv_weight.at(2),
                weights.bn_running_var.at(2), weights.bn_weight.at(2), kBatchNormEpsilon);
            vector<double> decrypted_layer1_block0_conv2 =
                decrypt_channel_cipher_group(layer1_block0_conv2_group, runtime);
            layer1_block0_conv2_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_conv2.size(); ++i)
            {
                layer1_block0_conv2_all_max_abs_error =
                    max(layer1_block0_conv2_all_max_abs_error,
                        abs(decrypted_layer1_block0_conv2[i] -
                            plain_layer1_block0_conv2.values.at(i)));
            }
            output << "layer1 block0 conv2 all max_abs_error: "
                   << layer1_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 conv2 all max_abs_error: "
                 << layer1_block0_conv2_all_max_abs_error << endl;

            output << "layer1 block0 bn2 full 64-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer1 block0 bn2 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block0_bn2_group = encrypted_channel_batch_norm(
                layer1_block0_conv2_group, weights.bn_bias.at(2),
                weights.bn_running_mean.at(2), weights.bn_running_var.at(2),
                weights.bn_weight.at(2), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block0_bn2 =
                plain_batch_norm(plain_layer1_block0_conv2, weights.bn_bias.at(2),
                                 weights.bn_running_mean.at(2),
                                 weights.bn_running_var.at(2), weights.bn_weight.at(2),
                                 kBatchNormEpsilon, 40.0);
            vector<double> decrypted_layer1_block0_bn2 =
                decrypt_channel_cipher_group(layer1_block0_bn2_group, runtime);
            layer1_block0_bn2_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_bn2.size(); ++i)
            {
                layer1_block0_bn2_all_max_abs_error =
                    max(layer1_block0_bn2_all_max_abs_error,
                        abs(decrypted_layer1_block0_bn2[i] -
                            plain_layer1_block0_bn2.values.at(i)));
            }
            output << "layer1 block0 bn2 all max_abs_error: "
                   << layer1_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 bn2 all max_abs_error: "
                 << layer1_block0_bn2_all_max_abs_error << endl;

            output << "layer1 block0 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer1 block0 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block0_add_group =
                encrypted_channel_add(layer1_block0_bn2_group, stem_dense_pool_group, runtime);
            PlainTensor plain_layer1_block0_add =
                plain_add(plain_layer1_block0_bn2, plain_conv1_pool);
            vector<double> decrypted_layer1_block0_add =
                decrypt_channel_cipher_group(layer1_block0_add_group, runtime);
            layer1_block0_add_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_add.size(); ++i)
            {
                layer1_block0_add_all_max_abs_error =
                    max(layer1_block0_add_all_max_abs_error,
                        abs(decrypted_layer1_block0_add[i] -
                            plain_layer1_block0_add.values.at(i)));
            }
            output << "layer1 block0 add all max_abs_error: "
                   << layer1_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 add all max_abs_error: "
                 << layer1_block0_add_all_max_abs_error << endl;

            output << "layer1 block0 output ReLU full 64-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer1 block0 output full 64-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer1_block0_output =
                plain_relu_reference(plain_layer1_block0_add);
            ChannelCipherGroup layer1_block0_output_refresh_group;
            layer1_block0_output_refresh_group.h = layer1_block0_add_group.h;
            layer1_block0_output_refresh_group.w = layer1_block0_add_group.w;
            layer1_block0_output_refresh_group.c = layer1_block0_add_group.c;
            layer1_block0_output_refresh_group.spatial_count =
                layer1_block0_add_group.spatial_count;
            layer1_block0_output_refresh_group.slot_count =
                layer1_block0_add_group.slot_count;
            layer1_block0_output_refresh_group.channels.reserve(
                layer1_block0_add_group.channels.size());
            for (int channel = 0; channel < layer1_block0_add_group.c; ++channel)
            {
                if (channel % 8 == 0)
                {
                    resnet18_progress_log() << "layer1 block0 output ReLU channel progress: " << channel
                         << "/" << layer1_block0_add_group.c << endl;
                }
                TensorCipher add_channel(static_cast<int>(plan.logN), 1,
                                         layer1_block0_add_group.h,
                                         layer1_block0_add_group.w, 1, 1, 1,
                                         layer1_block0_add_group.channels.at(
                                             static_cast<size_t>(channel)));
                TensorCipher output_relu_channel;
                relu(add_channel, output_relu_channel, relu_config.comp_no,
                     relu_config.deg, relu_config.alpha, relu_config.tree,
                     relu_config.scaled_val, runtime.encryptor, *runtime.evaluator,
                     runtime.encoder, runtime.relin_keys, runtime.scale);
                TensorCipher refreshed_output_channel = decrypt_reencrypt_tensor(
                    output_relu_channel, runtime, layer1_block0_add_group.spatial_count);
                layer1_block0_output_refresh_group.channels.emplace_back(
                    refreshed_output_channel.cipher());
            }
            resnet18_progress_log() << "layer1 block0 output ReLU channel progress: "
                 << layer1_block0_add_group.c << "/" << layer1_block0_add_group.c
                 << endl;
            log_channel_group_cipher_state("layer1 block0 output ReLU refresh output",
                                           layer1_block0_output_refresh_group, runtime);
            vector<double> decrypted_layer1_block0_output =
                decrypt_channel_cipher_group(layer1_block0_output_refresh_group, runtime);
            layer1_block0_output_refresh_all_max_abs_error = 0.0;
            for (size_t i = 0; i < decrypted_layer1_block0_output.size(); ++i)
            {
                layer1_block0_output_refresh_all_max_abs_error =
                    max(layer1_block0_output_refresh_all_max_abs_error,
                        abs(decrypted_layer1_block0_output[i] -
                            plain_layer1_block0_output.values.at(i)));
            }
            output << "layer1 block0 output refresh all max_abs_error: "
                   << layer1_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block0 output refresh all max_abs_error: "
                 << layer1_block0_output_refresh_all_max_abs_error << endl;

            output << "layer1 block1 conv1 full 64-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer1 block1 conv1 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block1_conv1_group =
                encrypted_channel_conv2d_all_channels(
                    layer1_block0_output_refresh_group, 64, 1, 3, 3,
                    weights.conv_weight.at(3), weights.bn_running_var.at(3),
                    weights.bn_weight.at(3), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer1_block1_conv1 = plain_convolution(
                plain_layer1_block0_output, 64, 1, 3, 3, weights.conv_weight.at(3),
                weights.bn_running_var.at(3), weights.bn_weight.at(3), kBatchNormEpsilon);
            layer1_block1_conv1_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_conv1_group, plain_layer1_block1_conv1, runtime);
            output << "layer1 block1 conv1 all max_abs_error: "
                   << layer1_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 conv1 all max_abs_error: "
                 << layer1_block1_conv1_all_max_abs_error << endl;

            output << "layer1 block1 bn1 full 64-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer1 block1 bn1 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block1_bn1_group = encrypted_channel_batch_norm(
                layer1_block1_conv1_group, weights.bn_bias.at(3),
                weights.bn_running_mean.at(3), weights.bn_running_var.at(3),
                weights.bn_weight.at(3), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block1_bn1 =
                plain_batch_norm(plain_layer1_block1_conv1, weights.bn_bias.at(3),
                                 weights.bn_running_mean.at(3),
                                 weights.bn_running_var.at(3), weights.bn_weight.at(3),
                                 kBatchNormEpsilon, 40.0);
            layer1_block1_bn1_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_bn1_group, plain_layer1_block1_bn1, runtime);
            output << "layer1 block1 bn1 all max_abs_error: "
                   << layer1_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 bn1 all max_abs_error: "
                 << layer1_block1_bn1_all_max_abs_error << endl;

            output << "layer1 block1 relu1 full 64-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer1 block1 relu1 full 64-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer1_block1_relu1 =
                plain_relu_reference(plain_layer1_block1_bn1);
            ChannelCipherGroup layer1_block1_relu1_refresh_group =
                encrypted_channel_relu_refresh(layer1_block1_bn1_group,
                                               "layer1 block1 relu1",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer1_block1_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_relu1_refresh_group, plain_layer1_block1_relu1, runtime);
            output << "layer1 block1 relu1 refresh all max_abs_error: "
                   << layer1_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 relu1 refresh all max_abs_error: "
                 << layer1_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer1 block1 conv2 full 64-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer1 block1 conv2 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block1_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer1_block1_relu1_refresh_group, 64, 1, 3, 3,
                    weights.conv_weight.at(4), weights.bn_running_var.at(4),
                    weights.bn_weight.at(4), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer1_block1_conv2 = plain_convolution(
                plain_layer1_block1_relu1, 64, 1, 3, 3, weights.conv_weight.at(4),
                weights.bn_running_var.at(4), weights.bn_weight.at(4), kBatchNormEpsilon);
            layer1_block1_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_conv2_group, plain_layer1_block1_conv2, runtime);
            output << "layer1 block1 conv2 all max_abs_error: "
                   << layer1_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 conv2 all max_abs_error: "
                 << layer1_block1_conv2_all_max_abs_error << endl;

            output << "layer1 block1 bn2 full 64-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer1 block1 bn2 full 64-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block1_bn2_group = encrypted_channel_batch_norm(
                layer1_block1_conv2_group, weights.bn_bias.at(4),
                weights.bn_running_mean.at(4), weights.bn_running_var.at(4),
                weights.bn_weight.at(4), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer1_block1_bn2 =
                plain_batch_norm(plain_layer1_block1_conv2, weights.bn_bias.at(4),
                                 weights.bn_running_mean.at(4),
                                 weights.bn_running_var.at(4), weights.bn_weight.at(4),
                                 kBatchNormEpsilon, 40.0);
            layer1_block1_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_bn2_group, plain_layer1_block1_bn2, runtime);
            output << "layer1 block1 bn2 all max_abs_error: "
                   << layer1_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 bn2 all max_abs_error: "
                 << layer1_block1_bn2_all_max_abs_error << endl;

            output << "layer1 block1 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer1 block1 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer1_block1_add_group = encrypted_channel_add(
                layer1_block1_bn2_group, layer1_block0_output_refresh_group, runtime);
            PlainTensor plain_layer1_block1_add =
                plain_add(plain_layer1_block1_bn2, plain_layer1_block0_output);
            layer1_block1_add_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_add_group, plain_layer1_block1_add, runtime);
            output << "layer1 block1 add all max_abs_error: "
                   << layer1_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 add all max_abs_error: "
                 << layer1_block1_add_all_max_abs_error << endl;

            output << "layer1 block1 output ReLU full 64-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer1 block1 output full 64-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer1_block1_output =
                plain_relu_reference(plain_layer1_block1_add);
            ChannelCipherGroup layer1_block1_output_refresh_group =
                encrypted_channel_relu_refresh(layer1_block1_add_group,
                                               "layer1 block1 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer1_block1_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer1_block1_output_refresh_group, plain_layer1_block1_output, runtime);
            output << "layer1 block1 output refresh all max_abs_error: "
                   << layer1_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer1 block1 output refresh all max_abs_error: "
                 << layer1_block1_output_refresh_all_max_abs_error << endl;

            output << "layer2 block0 conv1 sparse stride-2 full 128-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer2 block0 conv1 sparse stride-2 full 128-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer2_block0_conv1_sparse_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer1_block1_output_refresh_group, 128, 2, 3, 3,
                    weights.conv_weight.at(5), weights.bn_running_var.at(5),
                    weights.bn_weight.at(5), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block0_conv1 = plain_convolution(
                plain_layer1_block1_output, 128, 2, 3, 3, weights.conv_weight.at(5),
                weights.bn_running_var.at(5), weights.bn_weight.at(5), kBatchNormEpsilon);
            layer2_block0_conv1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer2_block0_conv1_sparse_group, plain_layer2_block0_conv1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer2 block0 conv1 sparse max_abs_error: "
                   << layer2_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 conv1 sparse max_abs_error: "
                 << layer2_block0_conv1_sparse_max_abs_error << endl;

            output << "layer2 block0 bn1 sparse stride-2 full 128-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer2 block0 bn1 sparse stride-2 full 128-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer2_block0_bn1_sparse_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer2_block0_conv1_sparse_group, weights.bn_bias.at(5),
                    weights.bn_running_mean.at(5), weights.bn_running_var.at(5),
                    weights.bn_weight.at(5), kBatchNormEpsilon, 40.0,
                    plain_layer2_block0_conv1.h, plain_layer2_block0_conv1.w, 2,
                    runtime);
            PlainTensor plain_layer2_block0_bn1 =
                plain_batch_norm(plain_layer2_block0_conv1, weights.bn_bias.at(5),
                                 weights.bn_running_mean.at(5),
                                 weights.bn_running_var.at(5), weights.bn_weight.at(5),
                                 kBatchNormEpsilon, 40.0);
            layer2_block0_bn1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer2_block0_bn1_sparse_group, plain_layer2_block0_bn1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer2 block0 bn1 sparse max_abs_error: "
                   << layer2_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 bn1 sparse max_abs_error: "
                 << layer2_block0_bn1_sparse_max_abs_error << endl;

            output << "layer2 block0 relu1 sparse stride-2: encrypted ReLU + compact debug refresh evaluation\n";
            resnet18_progress_log() << "layer2 block0 relu1 sparse stride-2 ReLU + compact debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer2_block0_relu1 =
                plain_relu_reference(plain_layer2_block0_bn1);
            ChannelCipherGroup layer2_block0_relu1_sparse_refresh_group =
                encrypted_channel_relu_refresh(layer2_block0_bn1_sparse_group,
                                               "layer2 block0 relu1 sparse",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            ChannelCipherGroup layer2_block0_relu1_refresh_group =
                compact_sparse_stride_channel_group(
                    layer2_block0_relu1_sparse_refresh_group, plain_layer2_block0_relu1.h,
                    plain_layer2_block0_relu1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            layer2_block0_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_relu1_refresh_group, plain_layer2_block0_relu1, runtime);
            output << "layer2 block0 relu1 compact refresh all max_abs_error: "
                   << layer2_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 relu1 compact refresh all max_abs_error: "
                 << layer2_block0_relu1_refresh_all_max_abs_error << endl;

            vector<int> layer2_dense_conv_steps =
                dense_conv2d_channel_rotation_steps(layer2_block0_relu1_refresh_group.w, 3, 3);
            resnet18_progress_log() << "layer2 dense 28x28 conv rotation key count: "
                 << layer2_dense_conv_steps.size() << endl;
            output << "layer2 dense 28x28 conv rotation key count: "
                   << layer2_dense_conv_steps.size() << '\n';
            KeyGenerator layer2_keygen(runtime.context, runtime.secret_key);
            layer2_keygen.create_galois_keys(layer2_dense_conv_steps, runtime.galois_keys);

            output << "layer2 block0 conv2 full 128-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer2 block0 conv2 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block0_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer2_block0_relu1_refresh_group, 128, 1, 3, 3,
                    weights.conv_weight.at(6), weights.bn_running_var.at(6),
                    weights.bn_weight.at(6), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block0_conv2 = plain_convolution(
                plain_layer2_block0_relu1, 128, 1, 3, 3, weights.conv_weight.at(6),
                weights.bn_running_var.at(6), weights.bn_weight.at(6), kBatchNormEpsilon);
            layer2_block0_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_conv2_group, plain_layer2_block0_conv2, runtime);
            output << "layer2 block0 conv2 all max_abs_error: "
                   << layer2_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 conv2 all max_abs_error: "
                 << layer2_block0_conv2_all_max_abs_error << endl;

            output << "layer2 block0 bn2 full 128-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer2 block0 bn2 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block0_bn2_group = encrypted_channel_batch_norm(
                layer2_block0_conv2_group, weights.bn_bias.at(6),
                weights.bn_running_mean.at(6), weights.bn_running_var.at(6),
                weights.bn_weight.at(6), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block0_bn2 =
                plain_batch_norm(plain_layer2_block0_conv2, weights.bn_bias.at(6),
                                 weights.bn_running_mean.at(6),
                                 weights.bn_running_var.at(6), weights.bn_weight.at(6),
                                 kBatchNormEpsilon, 40.0);
            layer2_block0_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_bn2_group, plain_layer2_block0_bn2, runtime);
            output << "layer2 block0 bn2 all max_abs_error: "
                   << layer2_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 bn2 all max_abs_error: "
                 << layer2_block0_bn2_all_max_abs_error << endl;

            output << "layer2 block0 projection shortcut sparse stride-2 full 128-channel evaluation\n";
            resnet18_progress_log() << "layer2 block0 projection shortcut sparse stride-2 full 128-channel evaluation"
                 << endl;
            ChannelCipherGroup layer2_block0_shortcut_sparse_conv_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer1_block1_output_refresh_group, 128, 2, 1, 1,
                    weights.downsample_weight.at(0),
                    weights.downsample_bn_running_var.at(0),
                    weights.downsample_bn_weight.at(0), kBatchNormEpsilon, runtime);
            ChannelCipherGroup layer2_block0_shortcut_sparse_bn_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer2_block0_shortcut_sparse_conv_group,
                    weights.downsample_bn_bias.at(0),
                    weights.downsample_bn_running_mean.at(0),
                    weights.downsample_bn_running_var.at(0),
                    weights.downsample_bn_weight.at(0), kBatchNormEpsilon, 40.0,
                    plain_layer2_block0_conv1.h, plain_layer2_block0_conv1.w, 2,
                    runtime);
            ChannelCipherGroup layer2_block0_shortcut_group =
                compact_sparse_stride_channel_group(
                    layer2_block0_shortcut_sparse_bn_group, plain_layer2_block0_conv1.h,
                    plain_layer2_block0_conv1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            PlainTensor plain_layer2_block0_shortcut_conv = plain_convolution(
                plain_layer1_block1_output, 128, 2, 1, 1,
                weights.downsample_weight.at(0),
                weights.downsample_bn_running_var.at(0),
                weights.downsample_bn_weight.at(0), kBatchNormEpsilon);
            PlainTensor plain_layer2_block0_shortcut =
                plain_batch_norm(plain_layer2_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(0),
                                 weights.downsample_bn_running_mean.at(0),
                                 weights.downsample_bn_running_var.at(0),
                                 weights.downsample_bn_weight.at(0), kBatchNormEpsilon,
                                 40.0);
            layer2_block0_shortcut_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_shortcut_group, plain_layer2_block0_shortcut, runtime);
            output << "layer2 block0 shortcut all max_abs_error: "
                   << layer2_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 shortcut all max_abs_error: "
                 << layer2_block0_shortcut_all_max_abs_error << endl;

            output << "layer2 block0 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer2 block0 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block0_add_group =
                encrypted_channel_add(layer2_block0_bn2_group, layer2_block0_shortcut_group,
                                      runtime);
            PlainTensor plain_layer2_block0_add =
                plain_add(plain_layer2_block0_bn2, plain_layer2_block0_shortcut);
            layer2_block0_add_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_add_group, plain_layer2_block0_add, runtime);
            output << "layer2 block0 add all max_abs_error: "
                   << layer2_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 add all max_abs_error: "
                 << layer2_block0_add_all_max_abs_error << endl;

            output << "layer2 block0 output ReLU full 128-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer2 block0 output full 128-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer2_block0_output =
                plain_relu_reference(plain_layer2_block0_add);
            ChannelCipherGroup layer2_block0_output_refresh_group =
                encrypted_channel_relu_refresh(layer2_block0_add_group,
                                               "layer2 block0 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer2_block0_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer2_block0_output_refresh_group, plain_layer2_block0_output, runtime);
            output << "layer2 block0 output refresh all max_abs_error: "
                   << layer2_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block0 output refresh all max_abs_error: "
                 << layer2_block0_output_refresh_all_max_abs_error << endl;

            output << "layer2 block1 conv1 full 128-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer2 block1 conv1 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block1_conv1_group =
                encrypted_channel_conv2d_all_channels(
                    layer2_block0_output_refresh_group, 128, 1, 3, 3,
                    weights.conv_weight.at(7), weights.bn_running_var.at(7),
                    weights.bn_weight.at(7), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block1_conv1 = plain_convolution(
                plain_layer2_block0_output, 128, 1, 3, 3, weights.conv_weight.at(7),
                weights.bn_running_var.at(7), weights.bn_weight.at(7), kBatchNormEpsilon);
            layer2_block1_conv1_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_conv1_group, plain_layer2_block1_conv1, runtime);
            output << "layer2 block1 conv1 all max_abs_error: "
                   << layer2_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 conv1 all max_abs_error: "
                 << layer2_block1_conv1_all_max_abs_error << endl;

            output << "layer2 block1 bn1 full 128-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer2 block1 bn1 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block1_bn1_group = encrypted_channel_batch_norm(
                layer2_block1_conv1_group, weights.bn_bias.at(7),
                weights.bn_running_mean.at(7), weights.bn_running_var.at(7),
                weights.bn_weight.at(7), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block1_bn1 =
                plain_batch_norm(plain_layer2_block1_conv1, weights.bn_bias.at(7),
                                 weights.bn_running_mean.at(7),
                                 weights.bn_running_var.at(7), weights.bn_weight.at(7),
                                 kBatchNormEpsilon, 40.0);
            layer2_block1_bn1_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_bn1_group, plain_layer2_block1_bn1, runtime);
            output << "layer2 block1 bn1 all max_abs_error: "
                   << layer2_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 bn1 all max_abs_error: "
                 << layer2_block1_bn1_all_max_abs_error << endl;

            output << "layer2 block1 relu1 full 128-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer2 block1 relu1 full 128-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer2_block1_relu1 =
                plain_relu_reference(plain_layer2_block1_bn1);
            ChannelCipherGroup layer2_block1_relu1_refresh_group =
                encrypted_channel_relu_refresh(layer2_block1_bn1_group,
                                               "layer2 block1 relu1",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer2_block1_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_relu1_refresh_group, plain_layer2_block1_relu1, runtime);
            output << "layer2 block1 relu1 refresh all max_abs_error: "
                   << layer2_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 relu1 refresh all max_abs_error: "
                 << layer2_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer2 block1 conv2 full 128-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer2 block1 conv2 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block1_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer2_block1_relu1_refresh_group, 128, 1, 3, 3,
                    weights.conv_weight.at(8), weights.bn_running_var.at(8),
                    weights.bn_weight.at(8), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer2_block1_conv2 = plain_convolution(
                plain_layer2_block1_relu1, 128, 1, 3, 3, weights.conv_weight.at(8),
                weights.bn_running_var.at(8), weights.bn_weight.at(8), kBatchNormEpsilon);
            layer2_block1_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_conv2_group, plain_layer2_block1_conv2, runtime);
            output << "layer2 block1 conv2 all max_abs_error: "
                   << layer2_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 conv2 all max_abs_error: "
                 << layer2_block1_conv2_all_max_abs_error << endl;

            output << "layer2 block1 bn2 full 128-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer2 block1 bn2 full 128-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block1_bn2_group = encrypted_channel_batch_norm(
                layer2_block1_conv2_group, weights.bn_bias.at(8),
                weights.bn_running_mean.at(8), weights.bn_running_var.at(8),
                weights.bn_weight.at(8), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer2_block1_bn2 =
                plain_batch_norm(plain_layer2_block1_conv2, weights.bn_bias.at(8),
                                 weights.bn_running_mean.at(8),
                                 weights.bn_running_var.at(8), weights.bn_weight.at(8),
                                 kBatchNormEpsilon, 40.0);
            layer2_block1_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_bn2_group, plain_layer2_block1_bn2, runtime);
            output << "layer2 block1 bn2 all max_abs_error: "
                   << layer2_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 bn2 all max_abs_error: "
                 << layer2_block1_bn2_all_max_abs_error << endl;

            output << "layer2 block1 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer2 block1 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer2_block1_add_group =
                encrypted_channel_add(layer2_block1_bn2_group,
                                      layer2_block0_output_refresh_group, runtime);
            PlainTensor plain_layer2_block1_add =
                plain_add(plain_layer2_block1_bn2, plain_layer2_block0_output);
            layer2_block1_add_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_add_group, plain_layer2_block1_add, runtime);
            output << "layer2 block1 add all max_abs_error: "
                   << layer2_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 add all max_abs_error: "
                 << layer2_block1_add_all_max_abs_error << endl;

            output << "layer2 block1 output ReLU full 128-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer2 block1 output full 128-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer2_block1_output =
                plain_relu_reference(plain_layer2_block1_add);
            ChannelCipherGroup layer2_block1_output_refresh_group =
                encrypted_channel_relu_refresh(layer2_block1_add_group,
                                               "layer2 block1 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer2_block1_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer2_block1_output_refresh_group, plain_layer2_block1_output, runtime);
            output << "layer2 block1 output refresh all max_abs_error: "
                   << layer2_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer2 block1 output refresh all max_abs_error: "
                 << layer2_block1_output_refresh_all_max_abs_error << endl;

            output << "layer3 block0 conv1 sparse stride-2 full 256-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer3 block0 conv1 sparse stride-2 full 256-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer3_block0_conv1_sparse_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer2_block1_output_refresh_group, 256, 2, 3, 3,
                    weights.conv_weight.at(9), weights.bn_running_var.at(9),
                    weights.bn_weight.at(9), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block0_conv1 = plain_convolution(
                plain_layer2_block1_output, 256, 2, 3, 3, weights.conv_weight.at(9),
                weights.bn_running_var.at(9), weights.bn_weight.at(9), kBatchNormEpsilon);
            layer3_block0_conv1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer3_block0_conv1_sparse_group, plain_layer3_block0_conv1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer3 block0 conv1 sparse max_abs_error: "
                   << layer3_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 conv1 sparse max_abs_error: "
                 << layer3_block0_conv1_sparse_max_abs_error << endl;

            output << "layer3 block0 bn1 sparse stride-2 full 256-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer3 block0 bn1 sparse stride-2 full 256-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer3_block0_bn1_sparse_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer3_block0_conv1_sparse_group, weights.bn_bias.at(9),
                    weights.bn_running_mean.at(9), weights.bn_running_var.at(9),
                    weights.bn_weight.at(9), kBatchNormEpsilon, 40.0,
                    plain_layer3_block0_conv1.h, plain_layer3_block0_conv1.w, 2,
                    runtime);
            PlainTensor plain_layer3_block0_bn1 =
                plain_batch_norm(plain_layer3_block0_conv1, weights.bn_bias.at(9),
                                 weights.bn_running_mean.at(9),
                                 weights.bn_running_var.at(9), weights.bn_weight.at(9),
                                 kBatchNormEpsilon, 40.0);
            layer3_block0_bn1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer3_block0_bn1_sparse_group, plain_layer3_block0_bn1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer3 block0 bn1 sparse max_abs_error: "
                   << layer3_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 bn1 sparse max_abs_error: "
                 << layer3_block0_bn1_sparse_max_abs_error << endl;

            output << "layer3 block0 relu1 sparse stride-2: encrypted ReLU + compact debug refresh evaluation\n";
            resnet18_progress_log() << "layer3 block0 relu1 sparse stride-2 ReLU + compact debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer3_block0_relu1 =
                plain_relu_reference(plain_layer3_block0_bn1);
            ChannelCipherGroup layer3_block0_relu1_sparse_refresh_group =
                encrypted_channel_relu_refresh(layer3_block0_bn1_sparse_group,
                                               "layer3 block0 relu1 sparse",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            ChannelCipherGroup layer3_block0_relu1_refresh_group =
                compact_sparse_stride_channel_group(
                    layer3_block0_relu1_sparse_refresh_group, plain_layer3_block0_relu1.h,
                    plain_layer3_block0_relu1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            layer3_block0_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_relu1_refresh_group, plain_layer3_block0_relu1, runtime);
            output << "layer3 block0 relu1 compact refresh all max_abs_error: "
                   << layer3_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 relu1 compact refresh all max_abs_error: "
                 << layer3_block0_relu1_refresh_all_max_abs_error << endl;

            vector<int> layer3_dense_conv_steps =
                dense_conv2d_channel_rotation_steps(layer3_block0_relu1_refresh_group.w, 3, 3);
            resnet18_progress_log() << "layer3 dense 14x14 conv rotation key count: "
                 << layer3_dense_conv_steps.size() << endl;
            output << "layer3 dense 14x14 conv rotation key count: "
                   << layer3_dense_conv_steps.size() << '\n';
            KeyGenerator layer3_keygen(runtime.context, runtime.secret_key);
            layer3_keygen.create_galois_keys(layer3_dense_conv_steps, runtime.galois_keys);

            output << "layer3 block0 conv2 full 256-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer3 block0 conv2 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block0_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer3_block0_relu1_refresh_group, 256, 1, 3, 3,
                    weights.conv_weight.at(10), weights.bn_running_var.at(10),
                    weights.bn_weight.at(10), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block0_conv2 = plain_convolution(
                plain_layer3_block0_relu1, 256, 1, 3, 3, weights.conv_weight.at(10),
                weights.bn_running_var.at(10), weights.bn_weight.at(10), kBatchNormEpsilon);
            layer3_block0_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_conv2_group, plain_layer3_block0_conv2, runtime);
            output << "layer3 block0 conv2 all max_abs_error: "
                   << layer3_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 conv2 all max_abs_error: "
                 << layer3_block0_conv2_all_max_abs_error << endl;

            output << "layer3 block0 bn2 full 256-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer3 block0 bn2 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block0_bn2_group = encrypted_channel_batch_norm(
                layer3_block0_conv2_group, weights.bn_bias.at(10),
                weights.bn_running_mean.at(10), weights.bn_running_var.at(10),
                weights.bn_weight.at(10), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block0_bn2 =
                plain_batch_norm(plain_layer3_block0_conv2, weights.bn_bias.at(10),
                                 weights.bn_running_mean.at(10),
                                 weights.bn_running_var.at(10), weights.bn_weight.at(10),
                                 kBatchNormEpsilon, 40.0);
            layer3_block0_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_bn2_group, plain_layer3_block0_bn2, runtime);
            output << "layer3 block0 bn2 all max_abs_error: "
                   << layer3_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 bn2 all max_abs_error: "
                 << layer3_block0_bn2_all_max_abs_error << endl;

            output << "layer3 block0 projection shortcut sparse stride-2 full 256-channel evaluation\n";
            resnet18_progress_log() << "layer3 block0 projection shortcut sparse stride-2 full 256-channel evaluation"
                 << endl;
            ChannelCipherGroup layer3_block0_shortcut_sparse_conv_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer2_block1_output_refresh_group, 256, 2, 1, 1,
                    weights.downsample_weight.at(1),
                    weights.downsample_bn_running_var.at(1),
                    weights.downsample_bn_weight.at(1), kBatchNormEpsilon, runtime);
            ChannelCipherGroup layer3_block0_shortcut_sparse_bn_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer3_block0_shortcut_sparse_conv_group,
                    weights.downsample_bn_bias.at(1),
                    weights.downsample_bn_running_mean.at(1),
                    weights.downsample_bn_running_var.at(1),
                    weights.downsample_bn_weight.at(1), kBatchNormEpsilon, 40.0,
                    plain_layer3_block0_conv1.h, plain_layer3_block0_conv1.w, 2,
                    runtime);
            ChannelCipherGroup layer3_block0_shortcut_group =
                compact_sparse_stride_channel_group(
                    layer3_block0_shortcut_sparse_bn_group, plain_layer3_block0_conv1.h,
                    plain_layer3_block0_conv1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            PlainTensor plain_layer3_block0_shortcut_conv = plain_convolution(
                plain_layer2_block1_output, 256, 2, 1, 1,
                weights.downsample_weight.at(1),
                weights.downsample_bn_running_var.at(1),
                weights.downsample_bn_weight.at(1), kBatchNormEpsilon);
            PlainTensor plain_layer3_block0_shortcut =
                plain_batch_norm(plain_layer3_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(1),
                                 weights.downsample_bn_running_mean.at(1),
                                 weights.downsample_bn_running_var.at(1),
                                 weights.downsample_bn_weight.at(1), kBatchNormEpsilon,
                                 40.0);
            layer3_block0_shortcut_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_shortcut_group, plain_layer3_block0_shortcut, runtime);
            output << "layer3 block0 shortcut all max_abs_error: "
                   << layer3_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 shortcut all max_abs_error: "
                 << layer3_block0_shortcut_all_max_abs_error << endl;

            output << "layer3 block0 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer3 block0 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block0_add_group =
                encrypted_channel_add(layer3_block0_bn2_group, layer3_block0_shortcut_group,
                                      runtime);
            PlainTensor plain_layer3_block0_add =
                plain_add(plain_layer3_block0_bn2, plain_layer3_block0_shortcut);
            layer3_block0_add_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_add_group, plain_layer3_block0_add, runtime);
            output << "layer3 block0 add all max_abs_error: "
                   << layer3_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 add all max_abs_error: "
                 << layer3_block0_add_all_max_abs_error << endl;

            output << "layer3 block0 output ReLU full 256-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer3 block0 output full 256-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer3_block0_output =
                plain_relu_reference(plain_layer3_block0_add);
            ChannelCipherGroup layer3_block0_output_refresh_group =
                encrypted_channel_relu_refresh(layer3_block0_add_group,
                                               "layer3 block0 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer3_block0_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer3_block0_output_refresh_group, plain_layer3_block0_output, runtime);
            output << "layer3 block0 output refresh all max_abs_error: "
                   << layer3_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block0 output refresh all max_abs_error: "
                 << layer3_block0_output_refresh_all_max_abs_error << endl;

            output << "layer3 block1 conv1 full 256-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer3 block1 conv1 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block1_conv1_group =
                encrypted_channel_conv2d_all_channels(
                    layer3_block0_output_refresh_group, 256, 1, 3, 3,
                    weights.conv_weight.at(11), weights.bn_running_var.at(11),
                    weights.bn_weight.at(11), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block1_conv1 = plain_convolution(
                plain_layer3_block0_output, 256, 1, 3, 3, weights.conv_weight.at(11),
                weights.bn_running_var.at(11), weights.bn_weight.at(11), kBatchNormEpsilon);
            layer3_block1_conv1_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_conv1_group, plain_layer3_block1_conv1, runtime);
            output << "layer3 block1 conv1 all max_abs_error: "
                   << layer3_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 conv1 all max_abs_error: "
                 << layer3_block1_conv1_all_max_abs_error << endl;

            output << "layer3 block1 bn1 full 256-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer3 block1 bn1 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block1_bn1_group = encrypted_channel_batch_norm(
                layer3_block1_conv1_group, weights.bn_bias.at(11),
                weights.bn_running_mean.at(11), weights.bn_running_var.at(11),
                weights.bn_weight.at(11), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block1_bn1 =
                plain_batch_norm(plain_layer3_block1_conv1, weights.bn_bias.at(11),
                                 weights.bn_running_mean.at(11),
                                 weights.bn_running_var.at(11), weights.bn_weight.at(11),
                                 kBatchNormEpsilon, 40.0);
            layer3_block1_bn1_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_bn1_group, plain_layer3_block1_bn1, runtime);
            output << "layer3 block1 bn1 all max_abs_error: "
                   << layer3_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 bn1 all max_abs_error: "
                 << layer3_block1_bn1_all_max_abs_error << endl;

            output << "layer3 block1 relu1 full 256-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer3 block1 relu1 full 256-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer3_block1_relu1 =
                plain_relu_reference(plain_layer3_block1_bn1);
            ChannelCipherGroup layer3_block1_relu1_refresh_group =
                encrypted_channel_relu_refresh(layer3_block1_bn1_group,
                                               "layer3 block1 relu1",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer3_block1_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_relu1_refresh_group, plain_layer3_block1_relu1, runtime);
            output << "layer3 block1 relu1 refresh all max_abs_error: "
                   << layer3_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 relu1 refresh all max_abs_error: "
                 << layer3_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer3 block1 conv2 full 256-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer3 block1 conv2 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block1_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer3_block1_relu1_refresh_group, 256, 1, 3, 3,
                    weights.conv_weight.at(12), weights.bn_running_var.at(12),
                    weights.bn_weight.at(12), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer3_block1_conv2 = plain_convolution(
                plain_layer3_block1_relu1, 256, 1, 3, 3, weights.conv_weight.at(12),
                weights.bn_running_var.at(12), weights.bn_weight.at(12), kBatchNormEpsilon);
            layer3_block1_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_conv2_group, plain_layer3_block1_conv2, runtime);
            output << "layer3 block1 conv2 all max_abs_error: "
                   << layer3_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 conv2 all max_abs_error: "
                 << layer3_block1_conv2_all_max_abs_error << endl;

            output << "layer3 block1 bn2 full 256-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer3 block1 bn2 full 256-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block1_bn2_group = encrypted_channel_batch_norm(
                layer3_block1_conv2_group, weights.bn_bias.at(12),
                weights.bn_running_mean.at(12), weights.bn_running_var.at(12),
                weights.bn_weight.at(12), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer3_block1_bn2 =
                plain_batch_norm(plain_layer3_block1_conv2, weights.bn_bias.at(12),
                                 weights.bn_running_mean.at(12),
                                 weights.bn_running_var.at(12), weights.bn_weight.at(12),
                                 kBatchNormEpsilon, 40.0);
            layer3_block1_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_bn2_group, plain_layer3_block1_bn2, runtime);
            output << "layer3 block1 bn2 all max_abs_error: "
                   << layer3_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 bn2 all max_abs_error: "
                 << layer3_block1_bn2_all_max_abs_error << endl;

            output << "layer3 block1 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer3 block1 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer3_block1_add_group =
                encrypted_channel_add(layer3_block1_bn2_group,
                                      layer3_block0_output_refresh_group, runtime);
            PlainTensor plain_layer3_block1_add =
                plain_add(plain_layer3_block1_bn2, plain_layer3_block0_output);
            layer3_block1_add_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_add_group, plain_layer3_block1_add, runtime);
            output << "layer3 block1 add all max_abs_error: "
                   << layer3_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 add all max_abs_error: "
                 << layer3_block1_add_all_max_abs_error << endl;

            output << "layer3 block1 output ReLU full 256-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer3 block1 output full 256-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer3_block1_output =
                plain_relu_reference(plain_layer3_block1_add);
            ChannelCipherGroup layer3_block1_output_refresh_group =
                encrypted_channel_relu_refresh(layer3_block1_add_group,
                                               "layer3 block1 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer3_block1_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer3_block1_output_refresh_group, plain_layer3_block1_output, runtime);
            output << "layer3 block1 output refresh all max_abs_error: "
                   << layer3_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer3 block1 output refresh all max_abs_error: "
                 << layer3_block1_output_refresh_all_max_abs_error << endl;

            output << "layer4 block0 conv1 sparse stride-2 full 512-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer4 block0 conv1 sparse stride-2 full 512-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer4_block0_conv1_sparse_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer3_block1_output_refresh_group, 512, 2, 3, 3,
                    weights.conv_weight.at(13), weights.bn_running_var.at(13),
                    weights.bn_weight.at(13), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block0_conv1 = plain_convolution(
                plain_layer3_block1_output, 512, 2, 3, 3, weights.conv_weight.at(13),
                weights.bn_running_var.at(13), weights.bn_weight.at(13), kBatchNormEpsilon);
            layer4_block0_conv1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer4_block0_conv1_sparse_group, plain_layer4_block0_conv1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer4 block0 conv1 sparse max_abs_error: "
                   << layer4_block0_conv1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 conv1 sparse max_abs_error: "
                 << layer4_block0_conv1_sparse_max_abs_error << endl;

            output << "layer4 block0 bn1 sparse stride-2 full 512-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer4 block0 bn1 sparse stride-2 full 512-channel encrypted evaluation"
                 << endl;
            ChannelCipherGroup layer4_block0_bn1_sparse_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer4_block0_conv1_sparse_group, weights.bn_bias.at(13),
                    weights.bn_running_mean.at(13), weights.bn_running_var.at(13),
                    weights.bn_weight.at(13), kBatchNormEpsilon, 40.0,
                    plain_layer4_block0_conv1.h, plain_layer4_block0_conv1.w, 2,
                    runtime);
            PlainTensor plain_layer4_block0_bn1 =
                plain_batch_norm(plain_layer4_block0_conv1, weights.bn_bias.at(13),
                                 weights.bn_running_mean.at(13),
                                 weights.bn_running_var.at(13), weights.bn_weight.at(13),
                                 kBatchNormEpsilon, 40.0);
            layer4_block0_bn1_sparse_max_abs_error =
                sparse_stride_channel_group_max_abs_error(
                    layer4_block0_bn1_sparse_group, plain_layer4_block0_bn1, 2,
                    static_cast<int>(plan.logN), runtime);
            output << "layer4 block0 bn1 sparse max_abs_error: "
                   << layer4_block0_bn1_sparse_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 bn1 sparse max_abs_error: "
                 << layer4_block0_bn1_sparse_max_abs_error << endl;

            output << "layer4 block0 relu1 sparse stride-2: encrypted ReLU + compact debug refresh evaluation\n";
            resnet18_progress_log() << "layer4 block0 relu1 sparse stride-2 ReLU + compact debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer4_block0_relu1 =
                plain_relu_reference(plain_layer4_block0_bn1);
            ChannelCipherGroup layer4_block0_relu1_sparse_refresh_group =
                encrypted_channel_relu_refresh(layer4_block0_bn1_sparse_group,
                                               "layer4 block0 relu1 sparse",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            ChannelCipherGroup layer4_block0_relu1_refresh_group =
                compact_sparse_stride_channel_group(
                    layer4_block0_relu1_sparse_refresh_group, plain_layer4_block0_relu1.h,
                    plain_layer4_block0_relu1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            layer4_block0_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_relu1_refresh_group, plain_layer4_block0_relu1, runtime);
            output << "layer4 block0 relu1 compact refresh all max_abs_error: "
                   << layer4_block0_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 relu1 compact refresh all max_abs_error: "
                 << layer4_block0_relu1_refresh_all_max_abs_error << endl;

            vector<int> layer4_dense_conv_steps =
                dense_conv2d_channel_rotation_steps(layer4_block0_relu1_refresh_group.w, 3, 3);
            resnet18_progress_log() << "layer4 dense 7x7 conv rotation key count: "
                 << layer4_dense_conv_steps.size() << endl;
            output << "layer4 dense 7x7 conv rotation key count: "
                   << layer4_dense_conv_steps.size() << '\n';
            KeyGenerator layer4_keygen(runtime.context, runtime.secret_key);
            layer4_keygen.create_galois_keys(layer4_dense_conv_steps, runtime.galois_keys);

            output << "layer4 block0 conv2 full 512-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer4 block0 conv2 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block0_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer4_block0_relu1_refresh_group, 512, 1, 3, 3,
                    weights.conv_weight.at(14), weights.bn_running_var.at(14),
                    weights.bn_weight.at(14), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block0_conv2 = plain_convolution(
                plain_layer4_block0_relu1, 512, 1, 3, 3, weights.conv_weight.at(14),
                weights.bn_running_var.at(14), weights.bn_weight.at(14), kBatchNormEpsilon);
            layer4_block0_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_conv2_group, plain_layer4_block0_conv2, runtime);
            output << "layer4 block0 conv2 all max_abs_error: "
                   << layer4_block0_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 conv2 all max_abs_error: "
                 << layer4_block0_conv2_all_max_abs_error << endl;

            output << "layer4 block0 bn2 full 512-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer4 block0 bn2 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block0_bn2_group = encrypted_channel_batch_norm(
                layer4_block0_conv2_group, weights.bn_bias.at(14),
                weights.bn_running_mean.at(14), weights.bn_running_var.at(14),
                weights.bn_weight.at(14), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block0_bn2 =
                plain_batch_norm(plain_layer4_block0_conv2, weights.bn_bias.at(14),
                                 weights.bn_running_mean.at(14),
                                 weights.bn_running_var.at(14), weights.bn_weight.at(14),
                                 kBatchNormEpsilon, 40.0);
            layer4_block0_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_bn2_group, plain_layer4_block0_bn2, runtime);
            output << "layer4 block0 bn2 all max_abs_error: "
                   << layer4_block0_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 bn2 all max_abs_error: "
                 << layer4_block0_bn2_all_max_abs_error << endl;

            output << "layer4 block0 projection shortcut sparse stride-2 full 512-channel evaluation\n";
            resnet18_progress_log() << "layer4 block0 projection shortcut sparse stride-2 full 512-channel evaluation"
                 << endl;
            ChannelCipherGroup layer4_block0_shortcut_sparse_conv_group =
                encrypted_channel_conv2d_sparse_stride_all_channels(
                    layer3_block1_output_refresh_group, 512, 2, 1, 1,
                    weights.downsample_weight.at(2),
                    weights.downsample_bn_running_var.at(2),
                    weights.downsample_bn_weight.at(2), kBatchNormEpsilon, runtime);
            ChannelCipherGroup layer4_block0_shortcut_sparse_bn_group =
                encrypted_channel_batch_norm_sparse_stride(
                    layer4_block0_shortcut_sparse_conv_group,
                    weights.downsample_bn_bias.at(2),
                    weights.downsample_bn_running_mean.at(2),
                    weights.downsample_bn_running_var.at(2),
                    weights.downsample_bn_weight.at(2), kBatchNormEpsilon, 40.0,
                    plain_layer4_block0_conv1.h, plain_layer4_block0_conv1.w, 2,
                    runtime);
            ChannelCipherGroup layer4_block0_shortcut_group =
                compact_sparse_stride_channel_group(
                    layer4_block0_shortcut_sparse_bn_group, plain_layer4_block0_conv1.h,
                    plain_layer4_block0_conv1.w, 2, static_cast<int>(plan.logN),
                    plan.log_scale, runtime);
            PlainTensor plain_layer4_block0_shortcut_conv = plain_convolution(
                plain_layer3_block1_output, 512, 2, 1, 1,
                weights.downsample_weight.at(2),
                weights.downsample_bn_running_var.at(2),
                weights.downsample_bn_weight.at(2), kBatchNormEpsilon);
            PlainTensor plain_layer4_block0_shortcut =
                plain_batch_norm(plain_layer4_block0_shortcut_conv,
                                 weights.downsample_bn_bias.at(2),
                                 weights.downsample_bn_running_mean.at(2),
                                 weights.downsample_bn_running_var.at(2),
                                 weights.downsample_bn_weight.at(2), kBatchNormEpsilon,
                                 40.0);
            layer4_block0_shortcut_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_shortcut_group, plain_layer4_block0_shortcut, runtime);
            output << "layer4 block0 shortcut all max_abs_error: "
                   << layer4_block0_shortcut_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 shortcut all max_abs_error: "
                 << layer4_block0_shortcut_all_max_abs_error << endl;

            output << "layer4 block0 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer4 block0 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block0_add_group =
                encrypted_channel_add(layer4_block0_bn2_group, layer4_block0_shortcut_group,
                                      runtime);
            PlainTensor plain_layer4_block0_add =
                plain_add(plain_layer4_block0_bn2, plain_layer4_block0_shortcut);
            layer4_block0_add_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_add_group, plain_layer4_block0_add, runtime);
            output << "layer4 block0 add all max_abs_error: "
                   << layer4_block0_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 add all max_abs_error: "
                 << layer4_block0_add_all_max_abs_error << endl;

            output << "layer4 block0 output ReLU full 512-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer4 block0 output full 512-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer4_block0_output =
                plain_relu_reference(plain_layer4_block0_add);
            ChannelCipherGroup layer4_block0_output_refresh_group =
                encrypted_channel_relu_refresh(layer4_block0_add_group,
                                               "layer4 block0 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer4_block0_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer4_block0_output_refresh_group, plain_layer4_block0_output, runtime);
            output << "layer4 block0 output refresh all max_abs_error: "
                   << layer4_block0_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block0 output refresh all max_abs_error: "
                 << layer4_block0_output_refresh_all_max_abs_error << endl;

            output << "layer4 block1 conv1 full 512-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer4 block1 conv1 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block1_conv1_group =
                encrypted_channel_conv2d_all_channels(
                    layer4_block0_output_refresh_group, 512, 1, 3, 3,
                    weights.conv_weight.at(15), weights.bn_running_var.at(15),
                    weights.bn_weight.at(15), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block1_conv1 = plain_convolution(
                plain_layer4_block0_output, 512, 1, 3, 3, weights.conv_weight.at(15),
                weights.bn_running_var.at(15), weights.bn_weight.at(15), kBatchNormEpsilon);
            layer4_block1_conv1_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_conv1_group, plain_layer4_block1_conv1, runtime);
            output << "layer4 block1 conv1 all max_abs_error: "
                   << layer4_block1_conv1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 conv1 all max_abs_error: "
                 << layer4_block1_conv1_all_max_abs_error << endl;

            output << "layer4 block1 bn1 full 512-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer4 block1 bn1 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block1_bn1_group = encrypted_channel_batch_norm(
                layer4_block1_conv1_group, weights.bn_bias.at(15),
                weights.bn_running_mean.at(15), weights.bn_running_var.at(15),
                weights.bn_weight.at(15), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block1_bn1 =
                plain_batch_norm(plain_layer4_block1_conv1, weights.bn_bias.at(15),
                                 weights.bn_running_mean.at(15),
                                 weights.bn_running_var.at(15), weights.bn_weight.at(15),
                                 kBatchNormEpsilon, 40.0);
            layer4_block1_bn1_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_bn1_group, plain_layer4_block1_bn1, runtime);
            output << "layer4 block1 bn1 all max_abs_error: "
                   << layer4_block1_bn1_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 bn1 all max_abs_error: "
                 << layer4_block1_bn1_all_max_abs_error << endl;

            output << "layer4 block1 relu1 full 512-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer4 block1 relu1 full 512-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer4_block1_relu1 =
                plain_relu_reference(plain_layer4_block1_bn1);
            ChannelCipherGroup layer4_block1_relu1_refresh_group =
                encrypted_channel_relu_refresh(layer4_block1_bn1_group,
                                               "layer4 block1 relu1",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer4_block1_relu1_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_relu1_refresh_group, plain_layer4_block1_relu1, runtime);
            output << "layer4 block1 relu1 refresh all max_abs_error: "
                   << layer4_block1_relu1_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 relu1 refresh all max_abs_error: "
                 << layer4_block1_relu1_refresh_all_max_abs_error << endl;

            output << "layer4 block1 conv2 full 512-channel: encrypted dense conv evaluation\n";
            resnet18_progress_log() << "layer4 block1 conv2 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block1_conv2_group =
                encrypted_channel_conv2d_all_channels(
                    layer4_block1_relu1_refresh_group, 512, 1, 3, 3,
                    weights.conv_weight.at(16), weights.bn_running_var.at(16),
                    weights.bn_weight.at(16), kBatchNormEpsilon, runtime);
            PlainTensor plain_layer4_block1_conv2 = plain_convolution(
                plain_layer4_block1_relu1, 512, 1, 3, 3, weights.conv_weight.at(16),
                weights.bn_running_var.at(16), weights.bn_weight.at(16), kBatchNormEpsilon);
            layer4_block1_conv2_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_conv2_group, plain_layer4_block1_conv2, runtime);
            output << "layer4 block1 conv2 all max_abs_error: "
                   << layer4_block1_conv2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 conv2 all max_abs_error: "
                 << layer4_block1_conv2_all_max_abs_error << endl;

            output << "layer4 block1 bn2 full 512-channel: encrypted BN offset evaluation\n";
            resnet18_progress_log() << "layer4 block1 bn2 full 512-channel encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block1_bn2_group = encrypted_channel_batch_norm(
                layer4_block1_conv2_group, weights.bn_bias.at(16),
                weights.bn_running_mean.at(16), weights.bn_running_var.at(16),
                weights.bn_weight.at(16), kBatchNormEpsilon, 40.0, runtime);
            PlainTensor plain_layer4_block1_bn2 =
                plain_batch_norm(plain_layer4_block1_conv2, weights.bn_bias.at(16),
                                 weights.bn_running_mean.at(16),
                                 weights.bn_running_var.at(16), weights.bn_weight.at(16),
                                 kBatchNormEpsilon, 40.0);
            layer4_block1_bn2_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_bn2_group, plain_layer4_block1_bn2, runtime);
            output << "layer4 block1 bn2 all max_abs_error: "
                   << layer4_block1_bn2_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 bn2 all max_abs_error: "
                 << layer4_block1_bn2_all_max_abs_error << endl;

            output << "layer4 block1 residual add: encrypted channel add evaluation\n";
            resnet18_progress_log() << "layer4 block1 residual add encrypted evaluation" << endl;
            ChannelCipherGroup layer4_block1_add_group =
                encrypted_channel_add(layer4_block1_bn2_group,
                                      layer4_block0_output_refresh_group, runtime);
            PlainTensor plain_layer4_block1_add =
                plain_add(plain_layer4_block1_bn2, plain_layer4_block0_output);
            layer4_block1_add_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_add_group, plain_layer4_block1_add, runtime);
            output << "layer4 block1 add all max_abs_error: "
                   << layer4_block1_add_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 add all max_abs_error: "
                 << layer4_block1_add_all_max_abs_error << endl;

            output << "layer4 block1 output ReLU full 512-channel: encrypted ReLU + debug refresh evaluation\n";
            resnet18_progress_log() << "layer4 block1 output full 512-channel ReLU + debug refresh evaluation"
                 << endl;
            PlainTensor plain_layer4_block1_output =
                plain_relu_reference(plain_layer4_block1_add);
            ChannelCipherGroup layer4_block1_output_refresh_group =
                encrypted_channel_relu_refresh(layer4_block1_add_group,
                                               "layer4 block1 output ReLU",
                                               static_cast<int>(plan.logN), relu_config,
                                               runtime);
            layer4_block1_output_refresh_all_max_abs_error = channel_group_max_abs_error(
                layer4_block1_output_refresh_group, plain_layer4_block1_output, runtime);
            output << "layer4 block1 output refresh all max_abs_error: "
                   << layer4_block1_output_refresh_all_max_abs_error << '\n';
            resnet18_progress_log() << "layer4 block1 output refresh all max_abs_error: "
                 << layer4_block1_output_refresh_all_max_abs_error << endl;

            output << "head avgpool debug pack: decrypt final channel group, average-pool, re-encrypt 512 slots\n";
            resnet18_progress_log() << "head avgpool debug pack evaluation" << endl;
            PlainTensor plain_head_pooled = plain_average_pool(plain_layer4_block1_output, 40.0);
            vector<double> decrypted_layer4_block1_output =
                decrypt_channel_cipher_group(layer4_block1_output_refresh_group, runtime);
            vector<double> encrypted_pooled_values(
                static_cast<size_t>(kResNet18FinalChannels), 0.0);
            for (int channel = 0; channel < kResNet18FinalChannels; ++channel)
            {
                double sum = 0.0;
                const size_t channel_offset =
                    static_cast<size_t>(channel) *
                    layer4_block1_output_refresh_group.spatial_count;
                for (size_t i = 0; i < layer4_block1_output_refresh_group.spatial_count; ++i)
                {
                    sum += decrypted_layer4_block1_output.at(channel_offset + i);
                }
                encrypted_pooled_values[static_cast<size_t>(channel)] =
                    sum * 40.0 /
                    static_cast<double>(layer4_block1_output_refresh_group.spatial_count);
            }
            head_avgpool_debug_pack_max_abs_error = 0.0;
            for (int channel = 0; channel < kResNet18FinalChannels; ++channel)
            {
                head_avgpool_debug_pack_max_abs_error =
                    max(head_avgpool_debug_pack_max_abs_error,
                        abs(encrypted_pooled_values.at(static_cast<size_t>(channel)) -
                            plain_head_pooled.at(channel, 0, 0)));
            }
            output << "head avgpool debug pack max_abs_error: "
                   << head_avgpool_debug_pack_max_abs_error << '\n';
            resnet18_progress_log() << "head avgpool debug pack max_abs_error: "
                 << head_avgpool_debug_pack_max_abs_error << endl;

            TensorCipher encrypted_head_pooled(
                static_cast<int>(plan.logN), 1, 1, 1, kResNet18FinalChannels, 1, 1,
                encrypted_pooled_values, runtime.encryptor, runtime.encoder, plan.log_scale);
            log_tensor_cipher_state("head avgpool debug pack output", encrypted_head_pooled,
                                    runtime);

            output << "head fully connected: generating rotation keys\n";
            vector<int> fc_steps =
                fully_connected_rotation_steps(kImageNetClassCount, kResNet18FinalChannels);
            resnet18_progress_log() << "head fully connected rotation key count: " << fc_steps.size()
                 << endl;
            output << "head fully connected rotation key count: " << fc_steps.size()
                   << '\n';
            KeyGenerator fc_keygen(runtime.context, runtime.secret_key);
            fc_keygen.create_galois_keys(fc_steps, runtime.galois_keys);

            output << "head fully connected: encrypted logits evaluation\n";
            resnet18_progress_log() << "head fully connected encrypted logits evaluation" << endl;
            TensorCipher encrypted_head_logits;
            fully_connected_print(
                encrypted_head_pooled, encrypted_head_logits, weights.linear_weight,
                weights.linear_bias, kImageNetClassCount, kResNet18FinalChannels,
                *runtime.evaluator, runtime.galois_keys, output, runtime.decryptor,
                runtime.encoder, runtime.context);
            log_tensor_cipher_state("head fully connected logits output", encrypted_head_logits,
                                    runtime);

            vector<double> decrypted_head_logits =
                decode_real_slots(encrypted_head_logits, runtime, kImageNetClassCount);
            vector<double> plain_head_logits =
                plain_fully_connected(plain_head_pooled, weights.linear_weight,
                                      weights.linear_bias, kImageNetClassCount,
                                      kResNet18FinalChannels);
            head_logits_max_abs_error = 0.0;
            for (int i = 0; i < kImageNetClassCount; ++i)
            {
                head_logits_max_abs_error =
                    max(head_logits_max_abs_error,
                        abs(decrypted_head_logits.at(static_cast<size_t>(i)) -
                            plain_head_logits.at(static_cast<size_t>(i))));
            }
            encrypted_predicted_label = argmax_index(decrypted_head_logits);
            plain_head_predicted_label = argmax_index(plain_head_logits);
            output << "head logits max_abs_error: " << head_logits_max_abs_error << '\n';
            output << "head plain predicted label: " << plain_head_predicted_label
                   << ", encrypted predicted label: " << encrypted_predicted_label << '\n';
            resnet18_progress_log() << "head logits max_abs_error: " << head_logits_max_abs_error << endl;
            resnet18_progress_log() << "head plain predicted label: " << plain_head_predicted_label
                 << ", encrypted predicted label: " << encrypted_predicted_label << endl;
        }

        const auto image_time_end = chrono::high_resolution_clock::now();
        const auto image_time_diff =
            chrono::duration_cast<chrono::milliseconds>(image_time_end - image_time_start);
        output << "image label: " << image_label << '\n';
        output << "image time : " << image_time_diff.count() << " ms" << endl;

        out_log << "image_id: " << image_id << ", image label: " << image_label
                  << ", encrypted_input_chunks: " << input_group.chunk_count()
                  << ", input_decrypt_max_abs_error: " << max_abs_error
                  << ", conv1_preview_max_abs_error: " << conv1_preview_max_abs_error
                  << ", conv1_channel0_max_abs_error: " << conv1_channel0_max_abs_error
                  << ", conv1_all_max_abs_error: " << conv1_all_max_abs_error
                  << ", conv1_bn_max_abs_error: " << conv1_bn_max_abs_error
                  << ", conv1_bn_channel0_max_abs_error: "
                  << conv1_bn_channel0_max_abs_error
                  << ", conv1_relu_channel0_max_abs_error: "
                  << conv1_relu_channel0_max_abs_error
                  << ", conv1_relu_bootstrap_channel0_max_abs_error: "
                  << conv1_relu_bootstrap_channel0_max_abs_error
                  << ", conv1_maxpool_channel0_preview_max_abs_error: "
                  << conv1_maxpool_channel0_preview_max_abs_error
                  << ", conv1_maxpool_channel0_sparse_max_abs_error: "
                  << conv1_maxpool_channel0_sparse_max_abs_error
                  << ", stem_conv1_all_max_abs_error: "
                  << stem_conv1_all_max_abs_error
                  << ", stem_bn_all_max_abs_error: " << stem_bn_all_max_abs_error
                  << ", stem_relu_refresh_all_max_abs_error: "
                  << stem_relu_refresh_all_max_abs_error
                  << ", stem_sparse_maxpool_all_max_abs_error: "
                  << stem_sparse_maxpool_all_max_abs_error
                  << ", layer1_block0_conv1_channel0_max_abs_error: "
                  << layer1_block0_conv1_channel0_max_abs_error
                  << ", layer1_block0_conv1_all_max_abs_error: "
                  << layer1_block0_conv1_all_max_abs_error
                  << ", layer1_block0_bn1_all_max_abs_error: "
                  << layer1_block0_bn1_all_max_abs_error
                  << ", layer1_block0_relu1_refresh_all_max_abs_error: "
                  << layer1_block0_relu1_refresh_all_max_abs_error
                  << ", layer1_block0_conv2_all_max_abs_error: "
                  << layer1_block0_conv2_all_max_abs_error
                  << ", layer1_block0_bn2_all_max_abs_error: "
                  << layer1_block0_bn2_all_max_abs_error
                  << ", layer1_block0_add_all_max_abs_error: "
                  << layer1_block0_add_all_max_abs_error
                  << ", layer1_block0_output_refresh_all_max_abs_error: "
                  << layer1_block0_output_refresh_all_max_abs_error
                  << ", layer1_block1_conv1_all_max_abs_error: "
                  << layer1_block1_conv1_all_max_abs_error
                  << ", layer1_block1_bn1_all_max_abs_error: "
                  << layer1_block1_bn1_all_max_abs_error
                  << ", layer1_block1_relu1_refresh_all_max_abs_error: "
                  << layer1_block1_relu1_refresh_all_max_abs_error
                  << ", layer1_block1_conv2_all_max_abs_error: "
                  << layer1_block1_conv2_all_max_abs_error
                  << ", layer1_block1_bn2_all_max_abs_error: "
                  << layer1_block1_bn2_all_max_abs_error
                  << ", layer1_block1_add_all_max_abs_error: "
                  << layer1_block1_add_all_max_abs_error
                  << ", layer1_block1_output_refresh_all_max_abs_error: "
                  << layer1_block1_output_refresh_all_max_abs_error
                  << ", layer2_block0_conv1_sparse_max_abs_error: "
                  << layer2_block0_conv1_sparse_max_abs_error
                  << ", layer2_block0_bn1_sparse_max_abs_error: "
                  << layer2_block0_bn1_sparse_max_abs_error
                  << ", layer2_block0_relu1_refresh_all_max_abs_error: "
                  << layer2_block0_relu1_refresh_all_max_abs_error
                  << ", layer2_block0_conv2_all_max_abs_error: "
                  << layer2_block0_conv2_all_max_abs_error
                  << ", layer2_block0_bn2_all_max_abs_error: "
                  << layer2_block0_bn2_all_max_abs_error
                  << ", layer2_block0_shortcut_all_max_abs_error: "
                  << layer2_block0_shortcut_all_max_abs_error
                  << ", layer2_block0_add_all_max_abs_error: "
                  << layer2_block0_add_all_max_abs_error
                  << ", layer2_block0_output_refresh_all_max_abs_error: "
                  << layer2_block0_output_refresh_all_max_abs_error
                  << ", layer2_block1_conv1_all_max_abs_error: "
                  << layer2_block1_conv1_all_max_abs_error
                  << ", layer2_block1_bn1_all_max_abs_error: "
                  << layer2_block1_bn1_all_max_abs_error
                  << ", layer2_block1_relu1_refresh_all_max_abs_error: "
                  << layer2_block1_relu1_refresh_all_max_abs_error
                  << ", layer2_block1_conv2_all_max_abs_error: "
                  << layer2_block1_conv2_all_max_abs_error
                  << ", layer2_block1_bn2_all_max_abs_error: "
                  << layer2_block1_bn2_all_max_abs_error
                  << ", layer2_block1_add_all_max_abs_error: "
                  << layer2_block1_add_all_max_abs_error
                  << ", layer2_block1_output_refresh_all_max_abs_error: "
                  << layer2_block1_output_refresh_all_max_abs_error
                  << ", layer3_block0_conv1_sparse_max_abs_error: "
                  << layer3_block0_conv1_sparse_max_abs_error
                  << ", layer3_block0_bn1_sparse_max_abs_error: "
                  << layer3_block0_bn1_sparse_max_abs_error
                  << ", layer3_block0_relu1_refresh_all_max_abs_error: "
                  << layer3_block0_relu1_refresh_all_max_abs_error
                  << ", layer3_block0_conv2_all_max_abs_error: "
                  << layer3_block0_conv2_all_max_abs_error
                  << ", layer3_block0_bn2_all_max_abs_error: "
                  << layer3_block0_bn2_all_max_abs_error
                  << ", layer3_block0_shortcut_all_max_abs_error: "
                  << layer3_block0_shortcut_all_max_abs_error
                  << ", layer3_block0_add_all_max_abs_error: "
                  << layer3_block0_add_all_max_abs_error
                  << ", layer3_block0_output_refresh_all_max_abs_error: "
                  << layer3_block0_output_refresh_all_max_abs_error
                  << ", layer3_block1_conv1_all_max_abs_error: "
                  << layer3_block1_conv1_all_max_abs_error
                  << ", layer3_block1_bn1_all_max_abs_error: "
                  << layer3_block1_bn1_all_max_abs_error
                  << ", layer3_block1_relu1_refresh_all_max_abs_error: "
                  << layer3_block1_relu1_refresh_all_max_abs_error
                  << ", layer3_block1_conv2_all_max_abs_error: "
                  << layer3_block1_conv2_all_max_abs_error
                  << ", layer3_block1_bn2_all_max_abs_error: "
                  << layer3_block1_bn2_all_max_abs_error
                  << ", layer3_block1_add_all_max_abs_error: "
                  << layer3_block1_add_all_max_abs_error
                  << ", layer3_block1_output_refresh_all_max_abs_error: "
                  << layer3_block1_output_refresh_all_max_abs_error
                  << ", layer4_block0_conv1_sparse_max_abs_error: "
                  << layer4_block0_conv1_sparse_max_abs_error
                  << ", layer4_block0_bn1_sparse_max_abs_error: "
                  << layer4_block0_bn1_sparse_max_abs_error
                  << ", layer4_block0_relu1_refresh_all_max_abs_error: "
                  << layer4_block0_relu1_refresh_all_max_abs_error
                  << ", layer4_block0_conv2_all_max_abs_error: "
                  << layer4_block0_conv2_all_max_abs_error
                  << ", layer4_block0_bn2_all_max_abs_error: "
                  << layer4_block0_bn2_all_max_abs_error
                  << ", layer4_block0_shortcut_all_max_abs_error: "
                  << layer4_block0_shortcut_all_max_abs_error
                  << ", layer4_block0_add_all_max_abs_error: "
                  << layer4_block0_add_all_max_abs_error
                  << ", layer4_block0_output_refresh_all_max_abs_error: "
                  << layer4_block0_output_refresh_all_max_abs_error
                  << ", layer4_block1_conv1_all_max_abs_error: "
                  << layer4_block1_conv1_all_max_abs_error
                  << ", layer4_block1_bn1_all_max_abs_error: "
                  << layer4_block1_bn1_all_max_abs_error
                  << ", layer4_block1_relu1_refresh_all_max_abs_error: "
                  << layer4_block1_relu1_refresh_all_max_abs_error
                  << ", layer4_block1_conv2_all_max_abs_error: "
                  << layer4_block1_conv2_all_max_abs_error
                  << ", layer4_block1_bn2_all_max_abs_error: "
                  << layer4_block1_bn2_all_max_abs_error
                  << ", layer4_block1_add_all_max_abs_error: "
                  << layer4_block1_add_all_max_abs_error
                  << ", layer4_block1_output_refresh_all_max_abs_error: "
                  << layer4_block1_output_refresh_all_max_abs_error
                  << ", head_avgpool_debug_pack_max_abs_error: "
                  << head_avgpool_debug_pack_max_abs_error
                  << ", head_logits_max_abs_error: " << head_logits_max_abs_error
                  << ", plain_head_predicted_label: " << plain_head_predicted_label
                  << ", encrypted_predicted_label: " << encrypted_predicted_label
                  << ", image time : " << image_time_diff.count() << " ms" << endl;
        resnet18_progress_log() << "image_id: " << image_id << ", image label: " << image_label
             << ", encrypted_input_chunks: " << input_group.chunk_count()
             << ", input_decrypt_max_abs_error: " << max_abs_error
             << ", conv1_preview_max_abs_error: " << conv1_preview_max_abs_error
             << ", conv1_channel0_max_abs_error: " << conv1_channel0_max_abs_error
             << ", conv1_all_max_abs_error: " << conv1_all_max_abs_error
             << ", conv1_bn_max_abs_error: " << conv1_bn_max_abs_error
             << ", conv1_bn_channel0_max_abs_error: "
             << conv1_bn_channel0_max_abs_error
             << ", conv1_relu_channel0_max_abs_error: "
             << conv1_relu_channel0_max_abs_error
             << ", conv1_relu_bootstrap_channel0_max_abs_error: "
             << conv1_relu_bootstrap_channel0_max_abs_error
             << ", conv1_maxpool_channel0_preview_max_abs_error: "
             << conv1_maxpool_channel0_preview_max_abs_error
             << ", conv1_maxpool_channel0_sparse_max_abs_error: "
             << conv1_maxpool_channel0_sparse_max_abs_error
             << ", stem_conv1_all_max_abs_error: "
             << stem_conv1_all_max_abs_error
             << ", stem_bn_all_max_abs_error: " << stem_bn_all_max_abs_error
             << ", stem_relu_refresh_all_max_abs_error: "
             << stem_relu_refresh_all_max_abs_error
             << ", stem_sparse_maxpool_all_max_abs_error: "
             << stem_sparse_maxpool_all_max_abs_error
             << ", layer1_block0_conv1_channel0_max_abs_error: "
             << layer1_block0_conv1_channel0_max_abs_error
             << ", layer1_block0_conv1_all_max_abs_error: "
             << layer1_block0_conv1_all_max_abs_error
             << ", layer1_block0_bn1_all_max_abs_error: "
             << layer1_block0_bn1_all_max_abs_error
             << ", layer1_block0_relu1_refresh_all_max_abs_error: "
             << layer1_block0_relu1_refresh_all_max_abs_error
             << ", layer1_block0_conv2_all_max_abs_error: "
             << layer1_block0_conv2_all_max_abs_error
             << ", layer1_block0_bn2_all_max_abs_error: "
             << layer1_block0_bn2_all_max_abs_error
             << ", layer1_block0_add_all_max_abs_error: "
             << layer1_block0_add_all_max_abs_error
             << ", layer1_block0_output_refresh_all_max_abs_error: "
             << layer1_block0_output_refresh_all_max_abs_error
             << ", layer1_block1_conv1_all_max_abs_error: "
             << layer1_block1_conv1_all_max_abs_error
             << ", layer1_block1_bn1_all_max_abs_error: "
             << layer1_block1_bn1_all_max_abs_error
             << ", layer1_block1_relu1_refresh_all_max_abs_error: "
             << layer1_block1_relu1_refresh_all_max_abs_error
             << ", layer1_block1_conv2_all_max_abs_error: "
             << layer1_block1_conv2_all_max_abs_error
             << ", layer1_block1_bn2_all_max_abs_error: "
             << layer1_block1_bn2_all_max_abs_error
             << ", layer1_block1_add_all_max_abs_error: "
             << layer1_block1_add_all_max_abs_error
             << ", layer1_block1_output_refresh_all_max_abs_error: "
             << layer1_block1_output_refresh_all_max_abs_error
             << ", layer2_block0_conv1_sparse_max_abs_error: "
             << layer2_block0_conv1_sparse_max_abs_error
             << ", layer2_block0_bn1_sparse_max_abs_error: "
             << layer2_block0_bn1_sparse_max_abs_error
             << ", layer2_block0_relu1_refresh_all_max_abs_error: "
             << layer2_block0_relu1_refresh_all_max_abs_error
             << ", layer2_block0_conv2_all_max_abs_error: "
             << layer2_block0_conv2_all_max_abs_error
             << ", layer2_block0_bn2_all_max_abs_error: "
             << layer2_block0_bn2_all_max_abs_error
             << ", layer2_block0_shortcut_all_max_abs_error: "
             << layer2_block0_shortcut_all_max_abs_error
             << ", layer2_block0_add_all_max_abs_error: "
             << layer2_block0_add_all_max_abs_error
             << ", layer2_block0_output_refresh_all_max_abs_error: "
             << layer2_block0_output_refresh_all_max_abs_error
             << ", layer2_block1_conv1_all_max_abs_error: "
             << layer2_block1_conv1_all_max_abs_error
             << ", layer2_block1_bn1_all_max_abs_error: "
             << layer2_block1_bn1_all_max_abs_error
             << ", layer2_block1_relu1_refresh_all_max_abs_error: "
             << layer2_block1_relu1_refresh_all_max_abs_error
             << ", layer2_block1_conv2_all_max_abs_error: "
             << layer2_block1_conv2_all_max_abs_error
             << ", layer2_block1_bn2_all_max_abs_error: "
             << layer2_block1_bn2_all_max_abs_error
             << ", layer2_block1_add_all_max_abs_error: "
             << layer2_block1_add_all_max_abs_error
             << ", layer2_block1_output_refresh_all_max_abs_error: "
             << layer2_block1_output_refresh_all_max_abs_error
             << ", layer3_block0_conv1_sparse_max_abs_error: "
             << layer3_block0_conv1_sparse_max_abs_error
             << ", layer3_block0_bn1_sparse_max_abs_error: "
             << layer3_block0_bn1_sparse_max_abs_error
             << ", layer3_block0_relu1_refresh_all_max_abs_error: "
             << layer3_block0_relu1_refresh_all_max_abs_error
             << ", layer3_block0_conv2_all_max_abs_error: "
             << layer3_block0_conv2_all_max_abs_error
             << ", layer3_block0_bn2_all_max_abs_error: "
             << layer3_block0_bn2_all_max_abs_error
             << ", layer3_block0_shortcut_all_max_abs_error: "
             << layer3_block0_shortcut_all_max_abs_error
             << ", layer3_block0_add_all_max_abs_error: "
             << layer3_block0_add_all_max_abs_error
             << ", layer3_block0_output_refresh_all_max_abs_error: "
             << layer3_block0_output_refresh_all_max_abs_error
             << ", layer3_block1_conv1_all_max_abs_error: "
             << layer3_block1_conv1_all_max_abs_error
             << ", layer3_block1_bn1_all_max_abs_error: "
             << layer3_block1_bn1_all_max_abs_error
             << ", layer3_block1_relu1_refresh_all_max_abs_error: "
             << layer3_block1_relu1_refresh_all_max_abs_error
             << ", layer3_block1_conv2_all_max_abs_error: "
             << layer3_block1_conv2_all_max_abs_error
             << ", layer3_block1_bn2_all_max_abs_error: "
             << layer3_block1_bn2_all_max_abs_error
             << ", layer3_block1_add_all_max_abs_error: "
             << layer3_block1_add_all_max_abs_error
             << ", layer3_block1_output_refresh_all_max_abs_error: "
             << layer3_block1_output_refresh_all_max_abs_error
             << ", layer4_block0_conv1_sparse_max_abs_error: "
             << layer4_block0_conv1_sparse_max_abs_error
             << ", layer4_block0_bn1_sparse_max_abs_error: "
             << layer4_block0_bn1_sparse_max_abs_error
             << ", layer4_block0_relu1_refresh_all_max_abs_error: "
             << layer4_block0_relu1_refresh_all_max_abs_error
             << ", layer4_block0_conv2_all_max_abs_error: "
             << layer4_block0_conv2_all_max_abs_error
             << ", layer4_block0_bn2_all_max_abs_error: "
             << layer4_block0_bn2_all_max_abs_error
             << ", layer4_block0_shortcut_all_max_abs_error: "
             << layer4_block0_shortcut_all_max_abs_error
             << ", layer4_block0_add_all_max_abs_error: "
             << layer4_block0_add_all_max_abs_error
             << ", layer4_block0_output_refresh_all_max_abs_error: "
             << layer4_block0_output_refresh_all_max_abs_error
             << ", layer4_block1_conv1_all_max_abs_error: "
             << layer4_block1_conv1_all_max_abs_error
             << ", layer4_block1_bn1_all_max_abs_error: "
             << layer4_block1_bn1_all_max_abs_error
             << ", layer4_block1_relu1_refresh_all_max_abs_error: "
             << layer4_block1_relu1_refresh_all_max_abs_error
             << ", layer4_block1_conv2_all_max_abs_error: "
             << layer4_block1_conv2_all_max_abs_error
             << ", layer4_block1_bn2_all_max_abs_error: "
             << layer4_block1_bn2_all_max_abs_error
             << ", layer4_block1_add_all_max_abs_error: "
             << layer4_block1_add_all_max_abs_error
             << ", layer4_block1_output_refresh_all_max_abs_error: "
             << layer4_block1_output_refresh_all_max_abs_error
             << ", head_avgpool_debug_pack_max_abs_error: "
             << head_avgpool_debug_pack_max_abs_error
             << ", head_logits_max_abs_error: " << head_logits_max_abs_error
             << ", plain_head_predicted_label: " << plain_head_predicted_label
             << ", encrypted_predicted_label: " << encrypted_predicted_label
             << ", image time : " << image_time_diff.count() << " ms" << endl;
        out_log << "image_done: " << image_id
                   << ", image label: " << image_label
                   << ", encrypted_input_chunks=" << input_group.chunk_count()
                   << ", input_decrypt_max_abs_error=" << max_abs_error
                   << ", conv1_preview_max_abs_error=" << conv1_preview_max_abs_error
                   << ", conv1_channel0_max_abs_error=" << conv1_channel0_max_abs_error
                   << ", conv1_all_max_abs_error=" << conv1_all_max_abs_error
                   << ", conv1_bn_max_abs_error=" << conv1_bn_max_abs_error
                   << ", conv1_bn_channel0_max_abs_error="
                   << conv1_bn_channel0_max_abs_error
                   << ", conv1_relu_channel0_max_abs_error="
                   << conv1_relu_channel0_max_abs_error
                   << ", conv1_relu_bootstrap_channel0_max_abs_error="
                   << conv1_relu_bootstrap_channel0_max_abs_error
                   << ", conv1_maxpool_channel0_preview_max_abs_error="
                   << conv1_maxpool_channel0_preview_max_abs_error
                   << ", conv1_maxpool_channel0_sparse_max_abs_error="
                   << conv1_maxpool_channel0_sparse_max_abs_error
                   << ", stem_conv1_all_max_abs_error="
                   << stem_conv1_all_max_abs_error
                   << ", stem_bn_all_max_abs_error=" << stem_bn_all_max_abs_error
                   << ", stem_relu_refresh_all_max_abs_error="
                   << stem_relu_refresh_all_max_abs_error
                   << ", stem_sparse_maxpool_all_max_abs_error="
                   << stem_sparse_maxpool_all_max_abs_error
                   << ", layer1_block0_conv1_channel0_max_abs_error="
                   << layer1_block0_conv1_channel0_max_abs_error
                   << ", layer1_block0_conv1_all_max_abs_error="
                   << layer1_block0_conv1_all_max_abs_error
                   << ", layer1_block0_bn1_all_max_abs_error="
                   << layer1_block0_bn1_all_max_abs_error
                   << ", layer1_block0_relu1_refresh_all_max_abs_error="
                   << layer1_block0_relu1_refresh_all_max_abs_error
                   << ", layer1_block0_conv2_all_max_abs_error="
                   << layer1_block0_conv2_all_max_abs_error
                   << ", layer1_block0_bn2_all_max_abs_error="
                   << layer1_block0_bn2_all_max_abs_error
                   << ", layer1_block0_add_all_max_abs_error="
                   << layer1_block0_add_all_max_abs_error
                   << ", layer1_block0_output_refresh_all_max_abs_error="
                   << layer1_block0_output_refresh_all_max_abs_error
                   << ", layer1_block1_conv1_all_max_abs_error="
                   << layer1_block1_conv1_all_max_abs_error
                   << ", layer1_block1_bn1_all_max_abs_error="
                   << layer1_block1_bn1_all_max_abs_error
                   << ", layer1_block1_relu1_refresh_all_max_abs_error="
                   << layer1_block1_relu1_refresh_all_max_abs_error
                   << ", layer1_block1_conv2_all_max_abs_error="
                   << layer1_block1_conv2_all_max_abs_error
                   << ", layer1_block1_bn2_all_max_abs_error="
                   << layer1_block1_bn2_all_max_abs_error
                   << ", layer1_block1_add_all_max_abs_error="
                   << layer1_block1_add_all_max_abs_error
                   << ", layer1_block1_output_refresh_all_max_abs_error="
                   << layer1_block1_output_refresh_all_max_abs_error
                   << ", layer2_block0_conv1_sparse_max_abs_error="
                   << layer2_block0_conv1_sparse_max_abs_error
                   << ", layer2_block0_bn1_sparse_max_abs_error="
                   << layer2_block0_bn1_sparse_max_abs_error
                   << ", layer2_block0_relu1_refresh_all_max_abs_error="
                   << layer2_block0_relu1_refresh_all_max_abs_error
                   << ", layer2_block0_conv2_all_max_abs_error="
                   << layer2_block0_conv2_all_max_abs_error
                   << ", layer2_block0_bn2_all_max_abs_error="
                   << layer2_block0_bn2_all_max_abs_error
                   << ", layer2_block0_shortcut_all_max_abs_error="
                   << layer2_block0_shortcut_all_max_abs_error
                   << ", layer2_block0_add_all_max_abs_error="
                   << layer2_block0_add_all_max_abs_error
                   << ", layer2_block0_output_refresh_all_max_abs_error="
                   << layer2_block0_output_refresh_all_max_abs_error
                   << ", layer2_block1_conv1_all_max_abs_error="
                   << layer2_block1_conv1_all_max_abs_error
                   << ", layer2_block1_bn1_all_max_abs_error="
                   << layer2_block1_bn1_all_max_abs_error
                   << ", layer2_block1_relu1_refresh_all_max_abs_error="
                   << layer2_block1_relu1_refresh_all_max_abs_error
                   << ", layer2_block1_conv2_all_max_abs_error="
                   << layer2_block1_conv2_all_max_abs_error
                   << ", layer2_block1_bn2_all_max_abs_error="
                   << layer2_block1_bn2_all_max_abs_error
                   << ", layer2_block1_add_all_max_abs_error="
                   << layer2_block1_add_all_max_abs_error
                   << ", layer2_block1_output_refresh_all_max_abs_error="
                   << layer2_block1_output_refresh_all_max_abs_error
                   << ", layer3_block0_conv1_sparse_max_abs_error="
                   << layer3_block0_conv1_sparse_max_abs_error
                   << ", layer3_block0_bn1_sparse_max_abs_error="
                   << layer3_block0_bn1_sparse_max_abs_error
                   << ", layer3_block0_relu1_refresh_all_max_abs_error="
                   << layer3_block0_relu1_refresh_all_max_abs_error
                   << ", layer3_block0_conv2_all_max_abs_error="
                   << layer3_block0_conv2_all_max_abs_error
                   << ", layer3_block0_bn2_all_max_abs_error="
                   << layer3_block0_bn2_all_max_abs_error
                   << ", layer3_block0_shortcut_all_max_abs_error="
                   << layer3_block0_shortcut_all_max_abs_error
                   << ", layer3_block0_add_all_max_abs_error="
                   << layer3_block0_add_all_max_abs_error
                   << ", layer3_block0_output_refresh_all_max_abs_error="
                   << layer3_block0_output_refresh_all_max_abs_error
                   << ", layer3_block1_conv1_all_max_abs_error="
                   << layer3_block1_conv1_all_max_abs_error
                   << ", layer3_block1_bn1_all_max_abs_error="
                   << layer3_block1_bn1_all_max_abs_error
                   << ", layer3_block1_relu1_refresh_all_max_abs_error="
                   << layer3_block1_relu1_refresh_all_max_abs_error
                   << ", layer3_block1_conv2_all_max_abs_error="
                   << layer3_block1_conv2_all_max_abs_error
                   << ", layer3_block1_bn2_all_max_abs_error="
                   << layer3_block1_bn2_all_max_abs_error
                   << ", layer3_block1_add_all_max_abs_error="
                   << layer3_block1_add_all_max_abs_error
                   << ", layer3_block1_output_refresh_all_max_abs_error="
                   << layer3_block1_output_refresh_all_max_abs_error
                   << ", layer4_block0_conv1_sparse_max_abs_error="
                   << layer4_block0_conv1_sparse_max_abs_error
                   << ", layer4_block0_bn1_sparse_max_abs_error="
                   << layer4_block0_bn1_sparse_max_abs_error
                   << ", layer4_block0_relu1_refresh_all_max_abs_error="
                   << layer4_block0_relu1_refresh_all_max_abs_error
                   << ", layer4_block0_conv2_all_max_abs_error="
                   << layer4_block0_conv2_all_max_abs_error
                   << ", layer4_block0_bn2_all_max_abs_error="
                   << layer4_block0_bn2_all_max_abs_error
                   << ", layer4_block0_shortcut_all_max_abs_error="
                   << layer4_block0_shortcut_all_max_abs_error
                   << ", layer4_block0_add_all_max_abs_error="
                   << layer4_block0_add_all_max_abs_error
                   << ", layer4_block0_output_refresh_all_max_abs_error="
                   << layer4_block0_output_refresh_all_max_abs_error
                   << ", layer4_block1_conv1_all_max_abs_error="
                   << layer4_block1_conv1_all_max_abs_error
                   << ", layer4_block1_bn1_all_max_abs_error="
                   << layer4_block1_bn1_all_max_abs_error
                   << ", layer4_block1_relu1_refresh_all_max_abs_error="
                   << layer4_block1_relu1_refresh_all_max_abs_error
                   << ", layer4_block1_conv2_all_max_abs_error="
                   << layer4_block1_conv2_all_max_abs_error
                   << ", layer4_block1_bn2_all_max_abs_error="
                   << layer4_block1_bn2_all_max_abs_error
                   << ", layer4_block1_add_all_max_abs_error="
                   << layer4_block1_add_all_max_abs_error
                   << ", layer4_block1_output_refresh_all_max_abs_error="
                   << layer4_block1_output_refresh_all_max_abs_error
                   << ", head_avgpool_debug_pack_max_abs_error="
                   << head_avgpool_debug_pack_max_abs_error
                   << ", head_logits_max_abs_error=" << head_logits_max_abs_error
                   << ", plain_head_predicted_label=" << plain_head_predicted_label
                   << ", encrypted_predicted_label=" << encrypted_predicted_label
                   << ", image_time_ms=" << image_time_diff.count() << '\n';
        out_log.flush();
    }

    const auto all_time_end = chrono::high_resolution_clock::now();
    const auto all_time_diff =
        chrono::duration_cast<chrono::milliseconds>(all_time_end - all_time_start);
    resnet18_progress_log() << "total time : " << all_time_diff.count() << " ms" << endl;
    out_log << endl << "total time : " << all_time_diff.count() << " ms" << endl;
    out_log << "run_done: total_time_ms=" << all_time_diff.count() << '\n';
}
