#include "infer.h"

#include "encrypted_group_ops.h"
#include "encrypted_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "parallel_utils.h"
#include "parameter_loader.h"
#include "plain_cnn.h"
#include "progress_log.h"
#include "tensor_cipher.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
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

constexpr int kStagePlanes[kResNet50StageCount] = {64, 128, 256, 512};
constexpr int kStageOutputChannels[kResNet50StageCount] = {256, 512, 1024, 2048};
constexpr int kBottleneckExpansion = 4;

struct ExecutionOptions
{
    bool mock_relu = false;
    bool mock_bootstrap = false;
};

bool parse_bool_env(const char *name)
{
    const char *raw = getenv(name);
    if (raw == nullptr)
    {
        return false;
    }
    string value(raw);
    transform(value.begin(), value.end(), value.begin(),
              [](unsigned char ch) { return static_cast<char>(tolower(ch)); });
    return value == "1" || value == "true" || value == "on" || value == "yes";
}

ExecutionOptions read_execution_options()
{
    ExecutionOptions options;
    options.mock_relu = parse_bool_env("RESNET50_MOCK_RELU");
    options.mock_bootstrap = parse_bool_env("RESNET50_MOCK_BOOTSTRAP");
    return options;
}

string make_run_timestamp()
{
    const auto now = chrono::system_clock::now();
    const auto time = chrono::system_clock::to_time_t(now);
    tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif
    ostringstream stamp;
    stamp << put_time(&local_tm, "%Y%m%d_%H%M%S");
    return stamp.str();
}

double multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    return pow(2.0, static_cast<double>(context_data->coeff_modulus().back().bit_count()));
}

bool coefficient_encodes_to_zero(const Ciphertext &input, double coeff,
                                 const CKKSEncoder &encoder)
{
    return fabs(coeff * multiply_plain_scale(input, encoder)) < 0.5;
}

Ciphertext multiply_by_vector_mask(const Ciphertext &input, const vector<double> &mask,
                                   CKKSEncoder &encoder, EvaluatorCkksBase &evaluator,
                                   double plain_scale = 1.0)
{
    Plaintext plain;
    encoder.encode(mask, input.parms_id(), plain_scale, plain);
    Ciphertext output;
    evaluator.multiply_plain(input, plain, output);
    output.scale() = input.scale() * plain_scale;
    if (plain_scale != 1.0)
    {
        evaluator.rescale_dynamic(output, output, input.scale());
    }
    else
    {
        output.scale() = input.scale();
    }
    return output;
}

Ciphertext multiply_by_constant_scalar(const Ciphertext &input, double coeff,
                                       CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(coeff, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    Ciphertext output;
    evaluator.multiply_plain(input, plain, output);
    evaluator.rescale_dynamic(output, output, input.scale());
    return output;
}

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term, PoseidonRuntime &runtime)
{
    runtime.evaluator->add_dynamic(accumulator, term, accumulator, runtime.encoder);
}

void add_slot0_constant_inplace(Ciphertext &cipher, double value, PoseidonRuntime &runtime)
{
    if (coefficient_encodes_to_zero(cipher, value, runtime.encoder))
    {
        return;
    }
    vector<double> slots(runtime.encoder.slot_count(), 0.0);
    slots[0] = value;
    Plaintext plain;
    runtime.encoder.encode(slots, cipher.parms_id(), cipher.scale(), plain);
    runtime.evaluator->add_plain(cipher, plain, cipher);
}

vector<double> decrypt_slot0_values(const vector<Ciphertext> &ciphers, PoseidonRuntime &runtime)
{
    vector<double> values(ciphers.size(), 0.0);
    for (size_t i = 0; i < ciphers.size(); ++i)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(ciphers[i], plain);
        vector<complex<double>> decoded;
        runtime.encoder.decode(plain, decoded);
        values[i] = decoded.at(0).real();
    }
    return values;
}

int argmax_index(const vector<double> &values)
{
    return static_cast<int>(
        distance(values.begin(), max_element(values.begin(), values.end())));
}

double max_abs_error(const vector<double> &lhs, const vector<double> &rhs)
{
    if (lhs.size() != rhs.size())
    {
        throw invalid_argument("max_abs_error size mismatch");
    }
    double error = 0.0;
    for (size_t i = 0; i < lhs.size(); ++i)
    {
        error = max(error, fabs(lhs[i] - rhs[i]));
    }
    return error;
}

ChannelCipherGroup encrypt_channel_group_values(const PlainTensor &plain, PoseidonRuntime &runtime,
                                                int logp)
{
    ChannelCipherGroup group;
    group.h = plain.h;
    group.w = plain.w;
    group.c = plain.c;
    group.spatial_count = static_cast<size_t>(plain.h * plain.w);
    group.slot_count = runtime.encoder.slot_count();
    group.channels.resize(static_cast<size_t>(plain.c));

    for (int channel = 0; channel < plain.c; ++channel)
    {
        vector<complex<double>> slots(group.slot_count, {0.0, 0.0});
        for (int row = 0; row < plain.h; ++row)
        {
            for (int col = 0; col < plain.w; ++col)
            {
                slots[static_cast<size_t>(row * plain.w + col)] = {plain.at(channel, row, col),
                                                                    0.0};
            }
        }
        Plaintext encoded;
        runtime.encoder.encode(slots, pow(2.0, logp), encoded);
        runtime.encryptor.encrypt(encoded, group.channels[static_cast<size_t>(channel)]);
    }

    return group;
}

ChannelCipherGroup mock_refresh_from_plain(const PlainTensor &plain, PoseidonRuntime &runtime,
                                           int logp)
{
    return encrypt_channel_group_values(plain, runtime, logp);
}

ChannelCipherGroup encrypted_channel_conv2d_compact(
    const ChannelCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("compact channel conv supports stride 1 or 2");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("compact channel conv expects odd kernel sizes");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("compact channel conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("compact channel conv folded BN vectors are invalid");
    }

    ChannelCipherGroup output;
    output.h = input.h / stride;
    output.w = input.w / stride;
    output.c = out_channels;
    output.spatial_count = static_cast<size_t>(output.h * output.w);
    output.slot_count = runtime.encoder.slot_count();
    vector<Ciphertext> output_channels(static_cast<size_t>(out_channels));

    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    resnet18_progress_log() << "compact conv encrypted channel parallel threads: "
                            << resnet18_parallel_thread_count(static_cast<size_t>(out_channels))
                            << endl;

    resnet18_parallel_for(static_cast<size_t>(out_channels), [&](size_t output_channel_index) {
        const int oc = static_cast<int>(output_channel_index);
        const double folded_scale = constant_weight[oc] / sqrt(running_var[oc] + epsilon);
        Ciphertext sum;
        bool has_sum = false;

        for (int ic = 0; ic < input.c; ++ic)
        {
            const Ciphertext &source = input.channels.at(static_cast<size_t>(ic));
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const size_t weight_index = static_cast<size_t>(
                        fh * fw * input.c * oc + fh * fw * ic + fw * kh + kw);
                    const double coeff = weights[weight_index] * folded_scale;
                    if (coeff == 0.0 || coefficient_encodes_to_zero(source, coeff, runtime.encoder))
                    {
                        continue;
                    }

                    map<int, vector<double>> masks_by_rotation;
                    for (int oh = 0; oh < output.h; ++oh)
                    {
                        for (int ow = 0; ow < output.w; ++ow)
                        {
                            const int ih = oh * stride + kh - pad_h;
                            const int iw = ow * stride + kw - pad_w;
                            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                            {
                                continue;
                            }
                            const int input_slot = ih * input.w + iw;
                            const int output_slot = oh * output.w + ow;
                            const int step = input_slot - output_slot;
                            auto &mask = masks_by_rotation[step];
                            if (mask.empty())
                            {
                                mask.assign(output.slot_count, 0.0);
                            }
                            mask[static_cast<size_t>(output_slot)] = 1.0;
                        }
                    }

                    for (const auto &[step, mask] : masks_by_rotation)
                    {
                        Ciphertext rotated;
                        if (step == 0)
                        {
                            rotated = source;
                        }
                        else
                        {
                            runtime.evaluator->rotate(source, rotated, step, runtime.galois_keys);
                        }
                        Ciphertext masked =
                            multiply_by_vector_mask(rotated, mask, runtime.encoder,
                                                    *runtime.evaluator);
                        Ciphertext term = multiply_by_constant_scalar(masked, coeff,
                                                                      runtime.encoder,
                                                                      *runtime.evaluator);
                        if (!has_sum)
                        {
                            sum = std::move(term);
                            has_sum = true;
                        }
                        else
                        {
                            add_assign_dynamic(sum, term, runtime);
                        }
                    }
                }
            }
        }
        if (!has_sum)
        {
            throw runtime_error("compact channel conv output channel produced no terms");
        }
        output_channels[output_channel_index] = std::move(sum);
    });

    output.channels = std::move(output_channels);
    return output;
}

ChannelCipherGroup encrypted_average_pool2d_compact(const ChannelCipherGroup &input, int kernel,
                                                    int stride, int padding,
                                                    PoseidonRuntime &runtime)
{
    ChannelCipherGroup output;
    output.h = (input.h + 2 * padding - kernel) / stride + 1;
    output.w = (input.w + 2 * padding - kernel) / stride + 1;
    output.c = input.c;
    output.spatial_count = static_cast<size_t>(output.h * output.w);
    output.slot_count = runtime.encoder.slot_count();
    output.channels.resize(input.channels.size());

    const double coeff = 1.0 / static_cast<double>(kernel * kernel);
    resnet18_parallel_for(input.channels.size(), [&](size_t channel_index) {
        const Ciphertext &source = input.channels[channel_index];
        Ciphertext sum;
        bool has_sum = false;
        for (int kh = 0; kh < kernel; ++kh)
        {
            for (int kw = 0; kw < kernel; ++kw)
            {
                map<int, vector<double>> masks_by_rotation;
                for (int oh = 0; oh < output.h; ++oh)
                {
                    for (int ow = 0; ow < output.w; ++ow)
                    {
                        const int ih = oh * stride + kh - padding;
                        const int iw = ow * stride + kw - padding;
                        if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                        {
                            continue;
                        }
                        const int input_slot = ih * input.w + iw;
                        const int output_slot = oh * output.w + ow;
                        const int step = input_slot - output_slot;
                        auto &mask = masks_by_rotation[step];
                        if (mask.empty())
                        {
                            mask.assign(output.slot_count, 0.0);
                        }
                        mask[static_cast<size_t>(output_slot)] = 1.0;
                    }
                }
                for (const auto &[step, mask] : masks_by_rotation)
                {
                    Ciphertext rotated;
                    if (step == 0)
                    {
                        rotated = source;
                    }
                    else
                    {
                        runtime.evaluator->rotate(source, rotated, step, runtime.galois_keys);
                    }
                    Ciphertext masked =
                        multiply_by_vector_mask(rotated, mask, runtime.encoder,
                                                *runtime.evaluator);
                    Ciphertext term = multiply_by_constant_scalar(masked, coeff, runtime.encoder,
                                                                  *runtime.evaluator);
                    if (!has_sum)
                    {
                        sum = std::move(term);
                        has_sum = true;
                    }
                    else
                    {
                        add_assign_dynamic(sum, term, runtime);
                    }
                }
            }
        }
        output.channels[channel_index] = std::move(sum);
    });
    return output;
}

ChannelCipherGroup channel_relu(const ChannelCipherGroup &input, const ReluConfig &relu_config,
                                const PlainTensor &plain_output,
                                const ExecutionOptions &options, PoseidonRuntime &runtime)
{
    if (options.mock_relu)
    {
        return mock_refresh_from_plain(plain_output, runtime, runtime.scale > 0 ? 46 : 46);
    }

    ChannelCipherGroup output = input;
    output.channels.resize(input.channels.size());
    resnet18_parallel_for(input.channels.size(), [&](size_t channel_index) {
        TensorCipher in(static_cast<int>(runtime.slot_count == 0 ? 16 : log2(runtime.slot_count * 2)),
                        1, input.h, input.w, 1, 1, 1, input.channels[channel_index]);
        TensorCipher out;
        relu(in, out, relu_config.comp_no, relu_config.deg, relu_config.alpha,
             relu_config.tree, relu_config.scaled_val, runtime.encryptor, *runtime.evaluator,
             runtime.encoder, runtime.relin_keys, runtime.scale);
        output.channels[channel_index] = out.cipher();
    });
    return output;
}

ChannelCipherGroup channel_bootstrap(const ChannelCipherGroup &input, const PlainTensor &plain,
                                     const ExecutionOptions &options, PoseidonRuntime &runtime)
{
    if (options.mock_bootstrap)
    {
        return mock_refresh_from_plain(plain, runtime, 46);
    }

    PoseidonBootstrapContext bootstrapper;
    bootstrapper.context = &runtime.context;
    bootstrapper.evaluator = runtime.evaluator.get();
    bootstrapper.encoder = &runtime.encoder;
    bootstrapper.relin_keys = &runtime.relin_keys;
    bootstrapper.galois_keys = &runtime.galois_keys;
    bootstrapper.bootstrap_poly = runtime.bootstrap_poly.get();

    ChannelCipherGroup output = input;
    resnet18_parallel_for(input.channels.size(), [&](size_t channel_index) {
        TensorCipher in(16, 1, input.h, input.w, 1, 1, 1, input.channels[channel_index]);
        TensorCipher out;
        bootstrap_tensor(in, out, bootstrapper, runtime.encoder);
        output.channels[channel_index] = out.cipher();
    });
    return output;
}

PlainTensor plain_bottleneck_block(const PlainTensor &input, const ModelWeights &weights,
                                   int stage, int block, size_t &conv_index,
                                   size_t &bn_index, size_t ds_index,
                                   const ReluConfig &relu_config)
{
    const int planes = kStagePlanes[stage - 1];
    const int out_channels = kStageOutputChannels[stage - 1];
    const int stride = (stage > 1 && block == 0) ? 2 : 1;

    PlainTensor out = plain_convolution(input, planes, 1, 1, 1, weights.conv_weight[conv_index],
                                        weights.bn_running_var[bn_index],
                                        weights.bn_weight[bn_index], kBatchNormEpsilon);
    out = plain_batch_norm(out, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
                           weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                           kBatchNormEpsilon, kResNet50Boundary);
    out = plain_polynomial_relu_reference(out, relu_config);
    ++conv_index;
    ++bn_index;

    out = plain_convolution(out, planes, stride, 3, 3, weights.conv_weight[conv_index],
                            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                            kBatchNormEpsilon);
    out = plain_batch_norm(out, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
                           weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                           kBatchNormEpsilon, kResNet50Boundary);
    out = plain_polynomial_relu_reference(out, relu_config);
    ++conv_index;
    ++bn_index;

    out = plain_convolution(out, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
                            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                            kBatchNormEpsilon);
    out = plain_batch_norm(out, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
                           weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                           kBatchNormEpsilon, kResNet50Boundary);
    ++conv_index;
    ++bn_index;

    PlainTensor shortcut = input;
    if (block == 0)
    {
        shortcut = plain_convolution(input, out_channels, stride, 1, 1,
                                     weights.downsample_weight[ds_index],
                                     weights.downsample_bn_running_var[ds_index],
                                     weights.downsample_bn_weight[ds_index], kBatchNormEpsilon);
        shortcut = plain_batch_norm(shortcut, weights.downsample_bn_bias[ds_index],
                                    weights.downsample_bn_running_mean[ds_index],
                                    weights.downsample_bn_running_var[ds_index],
                                    weights.downsample_bn_weight[ds_index], kBatchNormEpsilon,
                                    kResNet50Boundary);
    }

    out = plain_add(out, shortcut);
    return plain_polynomial_relu_reference(out, relu_config);
}

ChannelCipherGroup encrypted_bottleneck_block(
    const ChannelCipherGroup &input, const PlainTensor &plain_output,
    const ModelWeights &weights, int stage, int block, size_t &conv_index, size_t &bn_index,
    size_t ds_index, const ReluConfig &relu_config, const ExecutionOptions &options,
    PoseidonRuntime &runtime)
{
    const int planes = kStagePlanes[stage - 1];
    const int out_channels = kStageOutputChannels[stage - 1];
    const int stride = (stage > 1 && block == 0) ? 2 : 1;

    ChannelCipherGroup out = encrypted_channel_conv2d_compact(
        input, planes, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    out = encrypted_channel_batch_norm(out, weights.bn_bias[bn_index],
                                       weights.bn_running_mean[bn_index],
                                       weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                                       kBatchNormEpsilon, kResNet50Boundary, runtime);
    ++conv_index;
    ++bn_index;
    out = channel_bootstrap(out, PlainTensor(out.h, out.w, out.c), options, runtime);
    out = channel_relu(out, relu_config, PlainTensor(out.h, out.w, out.c), options, runtime);

    out = encrypted_channel_conv2d_compact(
        out, planes, stride, 3, 3, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    out = encrypted_channel_batch_norm(out, weights.bn_bias[bn_index],
                                       weights.bn_running_mean[bn_index],
                                       weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                                       kBatchNormEpsilon, kResNet50Boundary, runtime);
    ++conv_index;
    ++bn_index;
    out = channel_bootstrap(out, PlainTensor(out.h, out.w, out.c), options, runtime);
    out = channel_relu(out, relu_config, PlainTensor(out.h, out.w, out.c), options, runtime);

    out = encrypted_channel_conv2d_compact(
        out, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    out = encrypted_channel_batch_norm(out, weights.bn_bias[bn_index],
                                       weights.bn_running_mean[bn_index],
                                       weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
                                       kBatchNormEpsilon, kResNet50Boundary, runtime);
    ++conv_index;
    ++bn_index;

    ChannelCipherGroup shortcut = input;
    if (block == 0)
    {
        shortcut = encrypted_channel_conv2d_compact(
            input, out_channels, stride, 1, 1, weights.downsample_weight[ds_index],
            weights.downsample_bn_running_var[ds_index], weights.downsample_bn_weight[ds_index],
            kBatchNormEpsilon, runtime);
        shortcut = encrypted_channel_batch_norm(
            shortcut, weights.downsample_bn_bias[ds_index],
            weights.downsample_bn_running_mean[ds_index],
            weights.downsample_bn_running_var[ds_index], weights.downsample_bn_weight[ds_index],
            kBatchNormEpsilon, kResNet50Boundary, runtime);
    }

    out = encrypted_channel_add(out, shortcut, runtime);
    out = channel_bootstrap(out, plain_output, options, runtime);
    return channel_relu(out, relu_config, plain_output, options, runtime);
}

ChannelCipherGroup encrypted_global_average_pool(const ChannelCipherGroup &input,
                                                 PoseidonRuntime &runtime)
{
    ChannelCipherGroup output;
    output.h = 1;
    output.w = 1;
    output.c = input.c;
    output.spatial_count = 1;
    output.slot_count = input.slot_count;
    output.channels.resize(input.channels.size());

    const double scale = kResNet50Boundary / static_cast<double>(input.h * input.w);
    vector<double> slot0_mask(output.slot_count, 0.0);
    slot0_mask[0] = 1.0;
    resnet18_parallel_for(input.channels.size(), [&](size_t channel_index) {
        Ciphertext sum = input.channels[channel_index];
        for (int step = 1; step < input.h * input.w; ++step)
        {
            Ciphertext rotated;
            runtime.evaluator->rotate(input.channels[channel_index], rotated, step,
                                      runtime.galois_keys);
            add_assign_dynamic(sum, rotated, runtime);
        }
        Ciphertext masked =
            multiply_by_vector_mask(sum, slot0_mask, runtime.encoder, *runtime.evaluator);
        output.channels[channel_index] =
            multiply_by_constant_scalar(masked, scale, runtime.encoder, *runtime.evaluator);
    });
    return output;
}

vector<Ciphertext> encrypted_fully_connected_slot0(const ChannelCipherGroup &features,
                                                   const vector<double> &matrix,
                                                   const vector<double> &bias,
                                                   PoseidonRuntime &runtime)
{
    if (features.h != 1 || features.w != 1 || features.c != kResNet50FinalChannels)
    {
        throw invalid_argument("encrypted FC expects 1x1x2048 features");
    }
    if (matrix.size() != static_cast<size_t>(kImageNetClassCount * kResNet50FinalChannels) ||
        bias.size() != static_cast<size_t>(kImageNetClassCount))
    {
        throw invalid_argument("encrypted FC parameter size mismatch");
    }

    vector<Ciphertext> logits(static_cast<size_t>(kImageNetClassCount));
    resnet18_parallel_for(static_cast<size_t>(kImageNetClassCount), [&](size_t class_index) {
        Ciphertext sum;
        bool has_sum = false;
        for (int channel = 0; channel < features.c; ++channel)
        {
            const double coeff =
                matrix[class_index * static_cast<size_t>(features.c) + static_cast<size_t>(channel)];
            if (coeff == 0.0 ||
                coefficient_encodes_to_zero(features.channels[static_cast<size_t>(channel)], coeff,
                                            runtime.encoder))
            {
                continue;
            }
            Ciphertext term = multiply_by_constant_scalar(
                features.channels[static_cast<size_t>(channel)], coeff, runtime.encoder,
                *runtime.evaluator);
            if (!has_sum)
            {
                sum = std::move(term);
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, term, runtime);
            }
        }
        if (!has_sum)
        {
            sum = features.channels.front();
            sum = multiply_by_constant_scalar(sum, 0.0, runtime.encoder, *runtime.evaluator);
        }
        add_slot0_constant_inplace(sum, bias[class_index], runtime);
        logits[class_index] = std::move(sum);
    });
    return logits;
}

void write_logits_preview(ostream &out, const vector<double> &values, size_t limit = 16)
{
    for (size_t i = 0; i < min(limit, values.size()); ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values[i];
    }
}

} // namespace

void ResNet50_imagenet_sparse(size_t start_image_id, size_t end_image_id)
{
    fs::create_directories(result_dir());
    const string stamp = make_run_timestamp();
    const fs::path run_log_path = result_dir() / (string(kResNet50ResultPrefix) + "_run_" +
                                                  to_string(start_image_id) + "_" +
                                                  to_string(end_image_id) + "_" + stamp + ".txt");
    ofstream run_log(run_log_path);
    if (!run_log.is_open())
    {
        throw runtime_error("failed to open result log: " + run_log_path.string());
    }
    ScopedProgressLogTarget progress_target(run_log);

    const PoseidonInferPlan plan = default_poseidon_plan();
    ReluConfig relu_config = default_relu_config(plan);
    const ExecutionOptions options = read_execution_options();
    ModelWeights weights = load_resnet50_parameters();
    PoseidonRuntime runtime = make_poseidon_runtime(plan);

    run_log << "ResNet50 ImageNet encrypted inference\n";
    run_log << "images=" << start_image_id << ".." << end_image_id
            << ", mock_relu=" << options.mock_relu
            << ", mock_bootstrap=" << options.mock_bootstrap << '\n';

    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        run_log << "\n[image] id=" << image_id << '\n';
        const vector<double> image_values = read_plain_image_values(image_id, kResNet50Boundary);
        const int true_label = read_image_label(image_id);
        const PlainTensor plain_input =
            plain_input_tensor_from_image_slots(image_values);

        size_t plain_conv_index = 0;
        size_t plain_bn_index = 0;
        PlainTensor plain = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight[plain_conv_index],
            weights.bn_running_var[plain_bn_index], weights.bn_weight[plain_bn_index],
            kBatchNormEpsilon);
        plain = plain_batch_norm(plain, weights.bn_bias[plain_bn_index],
                                 weights.bn_running_mean[plain_bn_index],
                                 weights.bn_running_var[plain_bn_index],
                                 weights.bn_weight[plain_bn_index], kBatchNormEpsilon,
                                 kResNet50Boundary);
        plain = plain_polynomial_relu_reference(plain, relu_config);
        plain = plain_average_pool2d(plain, 3, 2, 1);
        ++plain_conv_index;
        ++plain_bn_index;

        Im2ColCipherGroup conv1_im2col = encrypt_conv2d_im2col_patches(
            image_values, kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels, 2,
            7, 7, runtime, plan.log_scale);
        ChannelCipherGroup encrypted = encrypted_conv2d_im2col_all_channels(
            conv1_im2col, 64, weights.conv_weight[0], weights.bn_running_var[0],
            weights.bn_weight[0], kBatchNormEpsilon, runtime);
        encrypted = encrypted_channel_batch_norm(
            encrypted, weights.bn_bias[0], weights.bn_running_mean[0],
            weights.bn_running_var[0], weights.bn_weight[0], kBatchNormEpsilon,
            kResNet50Boundary, runtime);
        encrypted = channel_relu(encrypted, relu_config, plain, options, runtime);
        encrypted = encrypted_average_pool2d_compact(encrypted, 3, 2, 1, runtime);

        size_t encrypted_conv_index = 1;
        size_t encrypted_bn_index = 1;
        for (int stage = 1; stage <= kResNet50StageCount; ++stage)
        {
            const size_t ds_index = static_cast<size_t>(stage - 1);
            for (int block = 0; block < kResNet50BlocksPerStage[stage - 1]; ++block)
            {
                plain = plain_bottleneck_block(plain, weights, stage, block, plain_conv_index,
                                               plain_bn_index, ds_index, relu_config);
                encrypted = encrypted_bottleneck_block(
                    encrypted, plain, weights, stage, block, encrypted_conv_index,
                    encrypted_bn_index, ds_index, relu_config, options, runtime);
                run_log << "  stage=" << stage << " block=" << block
                        << " shape=" << encrypted.h << "x" << encrypted.w << "x"
                        << encrypted.c << '\n';
            }
        }

        PlainTensor plain_avg = plain_average_pool(plain, kResNet50Boundary);
        vector<double> plain_logits = plain_fully_connected(
            plain_avg, weights.linear_weight, weights.linear_bias, kImageNetClassCount,
            kResNet50FinalChannels);
        const int plain_pred = argmax_index(plain_logits);

        ChannelCipherGroup encrypted_avg = encrypted_global_average_pool(encrypted, runtime);
        vector<Ciphertext> encrypted_logits = encrypted_fully_connected_slot0(
            encrypted_avg, weights.linear_weight, weights.linear_bias, runtime);
        vector<double> decrypted_logits = decrypt_slot0_values(encrypted_logits, runtime);
        const int encrypted_pred = argmax_index(decrypted_logits);

        run_log << "  true_label=" << true_label << ", plain_pred=" << plain_pred
                << ", encrypted_pred=" << encrypted_pred
                << ", prediction_match=" << (plain_pred == encrypted_pred ? 1 : 0) << '\n';
        run_log << "  logit_max_abs_error=" << max_abs_error(plain_logits, decrypted_logits)
                << '\n';
        run_log << "  plain_logits_first16=";
        write_logits_preview(run_log, plain_logits);
        run_log << '\n';
        run_log << "  encrypted_logits_first16=";
        write_logits_preview(run_log, decrypted_logits);
        run_log << '\n';
    }
}
