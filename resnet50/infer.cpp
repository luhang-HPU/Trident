#include "infer.h"

#include "encrypted_group_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "multiplexed_ops.h"
#include "parameter_loader.h"
#include "plain_cnn.h"
#include "progress_log.h"

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
thread_local vector<pair<string, double>> g_image_max_abs_errors;

string summary_key(string label)
{
    for (char &ch : label)
    {
        if (!isalnum(static_cast<unsigned char>(ch)))
        {
            ch = '_';
        }
    }
    return label + "_max_abs_error";
}

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

template <typename Function>
auto profile_operation(const string &label, Function &&function)
    -> decltype(std::forward<Function>(function)())
{
    ScopedOperationMetrics metrics(label);
    return std::forward<Function>(function)();
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

vector<complex<double>> decrypt_channel_group_complex(const ChannelCipherGroup &group,
                                                      PoseidonRuntime &runtime,
                                                      const string &label = "channel_group")
{
    const auto group_start = chrono::steady_clock::now();
    resnet18_progress_log() << "[decrypt-start] " << label
                            << " shape=" << group.h << 'x' << group.w << 'x' << group.c
                            << " channels=" << group.channels.size()
                            << " spatial_per_channel=" << group.h * group.w << endl;
    vector<complex<double>> values(static_cast<size_t>(group.c) *
                                       static_cast<size_t>(group.h * group.w),
                                   complex<double>(0.0, 0.0));
    const size_t spatial_count = static_cast<size_t>(group.h * group.w);
    for (int channel = 0; channel < group.c; ++channel)
    {
        const auto channel_start = chrono::steady_clock::now();
        resnet18_progress_log() << "[decrypt-channel-start] " << label << " channel="
                                << channel + 1 << '/' << group.c << endl;
        Plaintext plain;
        runtime.decryptor.decrypt(group.channels.at(static_cast<size_t>(channel)), plain);
        const auto decrypt_end = chrono::steady_clock::now();
        resnet18_progress_log() << "[decrypt-channel-decrypted] " << label << " channel="
                                << channel + 1 << '/' << group.c << " decrypt_ms="
                                << chrono::duration_cast<chrono::milliseconds>(decrypt_end -
                                                                               channel_start)
                                       .count()
                                << endl;
        vector<complex<double>> decoded;
        runtime.encoder.decode(plain, decoded);
        const auto decode_end = chrono::steady_clock::now();
        for (size_t i = 0; i < spatial_count; ++i)
        {
            values[static_cast<size_t>(channel) * spatial_count + i] = decoded.at(i);
        }
        resnet18_progress_log() << "[decrypt-channel-done] " << label << " channel="
                                << channel + 1 << '/' << group.c << " decode_copy_ms="
                                << chrono::duration_cast<chrono::milliseconds>(decode_end -
                                                                               decrypt_end)
                                       .count()
                                << " total_ms="
                                << chrono::duration_cast<chrono::milliseconds>(decode_end -
                                                                               channel_start)
                                       .count()
                                << endl;
    }
    resnet18_progress_log() << "[decrypt-done] " << label << " channels=" << group.c
                            << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - group_start)
                                   .count()
                            << endl;
    return values;
}

void write_double_preview(ostream &out, const vector<double> &values, size_t limit)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i);
    }
}

void write_real_preview(ostream &out, const vector<complex<double>> &values, size_t limit)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i).real();
    }
}

void write_imag_preview(ostream &out, const vector<complex<double>> &values, size_t limit)
{
    const size_t count = min(limit, values.size());
    for (size_t i = 0; i < count; ++i)
    {
        if (i != 0)
        {
            out << ' ';
        }
        out << values.at(i).imag();
    }
}

void log_channel_compare(const string &label, const ChannelCipherGroup &encrypted,
                         const PlainTensor &plain, PoseidonRuntime &runtime, ostream &out,
                         size_t preview_limit = 16)
{
    ScopedOperationMetrics operation_metrics("diagnostic.compare." + label);
    if (encrypted.h != plain.h || encrypted.w != plain.w || encrypted.c != plain.c)
    {
        throw invalid_argument("channel/plain tensor shape mismatch at " + label);
    }

    const auto compare_start = chrono::steady_clock::now();
    resnet18_progress_log() << "[compare-start] " << label
                            << " shape=" << encrypted.h << 'x' << encrypted.w << 'x'
                            << encrypted.c << " values=" << plain.values.size() << endl;
    const vector<complex<double>> decrypted =
        decrypt_channel_group_complex(encrypted, runtime, "compare." + label);
    if (decrypted.size() != plain.values.size())
    {
        throw invalid_argument("channel/plain tensor value count mismatch at " + label);
    }

    double max_error = 0.0;
    double sum_error = 0.0;
    double max_imag = 0.0;
    double max_plain_abs = 0.0;
    double max_cipher_abs = 0.0;
    for (size_t i = 0; i < decrypted.size(); ++i)
    {
        const double plain_value = plain.values.at(i);
        const double cipher_real = decrypted.at(i).real();
        const double error = fabs(cipher_real - plain_value);
        max_error = max(max_error, error);
        sum_error += error;
        max_imag = max(max_imag, fabs(decrypted.at(i).imag()));
        max_plain_abs = max(max_plain_abs, fabs(plain_value));
        max_cipher_abs = max(max_cipher_abs, fabs(cipher_real));
    }

    const double mean_error =
        decrypted.empty() ? 0.0 : sum_error / static_cast<double>(decrypted.size());
    g_image_max_abs_errors.emplace_back(label, max_error);
    out << "[compare] " << label
        << " shape=" << encrypted.h << 'x' << encrypted.w << 'x' << encrypted.c
        << " values=" << decrypted.size()
        << " max_abs_error=" << max_error
        << " mean_abs_error=" << mean_error
        << " max_cipher_imag=" << max_imag
        << " max_plain_abs=" << max_plain_abs
        << " max_cipher_abs=" << max_cipher_abs << '\n';
    out << "[value-dump] " << label << " plain_first" << preview_limit << '=';
    write_double_preview(out, plain.values, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_real_first" << preview_limit << '=';
    write_real_preview(out, decrypted, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_imag_first" << preview_limit << '=';
    write_imag_preview(out, decrypted, preview_limit);
    out << '\n';
    out.flush();
    resnet18_progress_log() << "[compare-done] " << label << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - compare_start)
                                   .count()
                            << endl;
}

void log_multiplexed_compare(const string &label,
                             const MultiplexedCipherGroup &encrypted,
                             const PlainTensor &plain, PoseidonRuntime &runtime,
                             ostream &out, size_t preview_limit = 16)
{
    ScopedOperationMetrics operation_metrics("diagnostic.compare." + label);
    if (encrypted.h != plain.h || encrypted.w != plain.w || encrypted.c != plain.c)
    {
        throw invalid_argument("multiplexed/plain tensor shape mismatch at " + label);
    }

    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[compare-start] " << label << " layout=multiplexed"
                            << " shape=" << encrypted.h << 'x' << encrypted.w << 'x'
                            << encrypted.c << " k=" << encrypted.k
                            << " packs=" << encrypted.packs.size() << endl;
    const vector<complex<double>> decrypted =
        decrypt_multiplexed_group_complex(encrypted, runtime);
    if (decrypted.size() != plain.values.size())
    {
        throw invalid_argument("multiplexed/plain tensor value count mismatch at " + label);
    }

    double max_error = 0.0;
    double sum_error = 0.0;
    double max_imag = 0.0;
    double max_plain_abs = 0.0;
    double max_cipher_abs = 0.0;
    for (size_t i = 0; i < decrypted.size(); ++i)
    {
        const double plain_value = plain.values.at(i);
        const double cipher_real = decrypted.at(i).real();
        const double error = fabs(cipher_real - plain_value);
        max_error = max(max_error, error);
        sum_error += error;
        max_imag = max(max_imag, fabs(decrypted.at(i).imag()));
        max_plain_abs = max(max_plain_abs, fabs(plain_value));
        max_cipher_abs = max(max_cipher_abs, fabs(cipher_real));
    }

    const double mean_error = decrypted.empty()
                                  ? 0.0
                                  : sum_error / static_cast<double>(decrypted.size());
    g_image_max_abs_errors.emplace_back(label, max_error);
    out << "[compare] " << label << " layout=multiplexed"
        << " shape=" << encrypted.h << 'x' << encrypted.w << 'x' << encrypted.c
        << " k=" << encrypted.k << " packs=" << encrypted.packs.size()
        << " values=" << decrypted.size() << " max_abs_error=" << max_error
        << " mean_abs_error=" << mean_error << " max_cipher_imag=" << max_imag
        << " max_plain_abs=" << max_plain_abs << " max_cipher_abs=" << max_cipher_abs
        << '\n';
    out << "[value-dump] " << label << " plain_first" << preview_limit << '=';
    write_double_preview(out, plain.values, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_real_first" << preview_limit << '=';
    write_real_preview(out, decrypted, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_imag_first" << preview_limit << '=';
    write_imag_preview(out, decrypted, preview_limit);
    out << '\n';
    out.flush();
    resnet18_progress_log() << "[compare-done] " << label << " layout=multiplexed total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
}

vector<complex<double>> decrypt_slot0_complex_values(const vector<Ciphertext> &ciphers,
                                                     PoseidonRuntime &runtime,
                                                     const string &label = "slot0")
{
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[slot0-decrypt-start] " << label
                            << " ciphertexts=" << ciphers.size() << endl;
    vector<complex<double>> values(ciphers.size(), {0.0, 0.0});
    for (size_t i = 0; i < ciphers.size(); ++i)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(ciphers[i], plain);
        vector<complex<double>> decoded;
        runtime.encoder.decode(plain, decoded);
        values[i] = decoded.at(0);
    }
    resnet18_progress_log() << "[slot0-decrypt-done] " << label << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
    return values;
}

vector<double> real_values(const vector<complex<double>> &values)
{
    vector<double> real(values.size(), 0.0);
    for (size_t i = 0; i < values.size(); ++i)
    {
        real[i] = values[i].real();
    }
    return real;
}

void log_logits_cipher_state(const vector<Ciphertext> &logits, PoseidonRuntime &runtime)
{
    if (logits.empty())
    {
        resnet18_progress_log()
            << "[cipher-state] head fully connected logits output: empty" << endl;
        return;
    }
    const size_t first_chain = cipher_chain_index(runtime, logits.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = logits.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;
    for (const Ciphertext &cipher : logits)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        min_scale = min(min_scale, cipher.scale());
        max_scale = max(max_scale, cipher.scale());
    }
    resnet18_progress_log()
        << "[cipher-state] head fully connected logits output: shape(h=1, w=1, c="
        << logits.size() << "), ciphertexts=" << logits.size()
        << ", chain_index(first/min/max)=" << first_chain << "/" << min_chain << "/"
        << max_chain << ", scale(first/min/max)=" << first_scale << "/" << min_scale
        << "/" << max_scale << endl;
}

void log_logits_compare(const string &label, const vector<double> &plain,
                        const vector<complex<double>> &encrypted, ostream &out,
                        size_t preview_limit = 16)
{
    ScopedOperationMetrics operation_metrics("diagnostic.compare." + label);
    if (plain.size() != encrypted.size())
    {
        throw invalid_argument("logit vector size mismatch at " + label);
    }

    double max_error = 0.0;
    double sum_error = 0.0;
    double max_imag = 0.0;
    for (size_t i = 0; i < plain.size(); ++i)
    {
        const double error = fabs(encrypted.at(i).real() - plain.at(i));
        max_error = max(max_error, error);
        sum_error += error;
        max_imag = max(max_imag, fabs(encrypted.at(i).imag()));
    }
    const double mean_error =
        plain.empty() ? 0.0 : sum_error / static_cast<double>(plain.size());
    g_image_max_abs_errors.emplace_back(label, max_error);
    out << "[compare] " << label
        << " values=" << plain.size()
        << " max_abs_error=" << max_error
        << " mean_abs_error=" << mean_error
        << " max_cipher_imag=" << max_imag << '\n';
    out << "[value-dump] " << label << " plain_first" << preview_limit << '=';
    write_double_preview(out, plain, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_real_first" << preview_limit << '=';
    write_real_preview(out, encrypted, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_imag_first" << preview_limit << '=';
    write_imag_preview(out, encrypted, preview_limit);
    out << '\n';
}

void log_packed_feature_compare(const string &label, const PlainTensor &plain,
                                const Ciphertext &encrypted, PoseidonRuntime &runtime,
                                ostream &out, size_t preview_limit = 16)
{
    ScopedOperationMetrics operation_metrics("diagnostic.compare." + label);
    Plaintext encoded;
    runtime.decryptor.decrypt(encrypted, encoded);
    vector<complex<double>> decoded;
    runtime.encoder.decode(encoded, decoded);
    if (plain.values.size() > decoded.size())
    {
        throw invalid_argument("packed feature/plain value count mismatch at " + label);
    }
    vector<complex<double>> features(decoded.begin(),
                                     decoded.begin() + static_cast<ptrdiff_t>(plain.values.size()));
    double max_error = 0.0;
    double sum_error = 0.0;
    double max_imag = 0.0;
    for (size_t i = 0; i < plain.values.size(); ++i)
    {
        const double error = fabs(features[i].real() - plain.values[i]);
        max_error = max(max_error, error);
        sum_error += error;
        max_imag = max(max_imag, fabs(features[i].imag()));
    }
    g_image_max_abs_errors.emplace_back(label, max_error);
    out << "[compare] " << label << " layout=multiplexed-packed values="
        << plain.values.size() << " max_abs_error=" << max_error
        << " mean_abs_error="
        << (plain.values.empty() ? 0.0
                                 : sum_error / static_cast<double>(plain.values.size()))
        << " max_cipher_imag=" << max_imag << '\n';
    out << "[value-dump] " << label << " plain_first" << preview_limit << '=';
    write_double_preview(out, plain.values, preview_limit);
    out << '\n';
    out << "[value-dump] " << label << " cipher_real_first" << preview_limit << '=';
    write_real_preview(out, features, preview_limit);
    out << '\n';
    out.flush();
}

struct TracedBlockState
{
    PlainTensor plain;
    MultiplexedCipherGroup encrypted;
};

TracedBlockState traced_bottleneck_block(
    const PlainTensor &plain_input, const MultiplexedCipherGroup &encrypted_input,
    const ModelWeights &weights, int stage, int block, size_t &conv_index, size_t &bn_index,
    size_t ds_index, const ReluConfig &relu_config, const ExecutionOptions &options,
    long logn, PoseidonRuntime &runtime, ostream &run_log)
{
    const int planes = kStagePlanes[stage - 1];
    const int out_channels = kStageOutputChannels[stage - 1];
    const int stride = (stage > 1 && block == 0) ? 2 : 1;
    const string prefix = "layer" + to_string(stage) + ".block" + to_string(block);
    const MultiplexedMockOptions mock_options{options.mock_relu, options.mock_bootstrap};

    PlainTensor plain = plain_convolution(
        plain_input, planes, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon);
    MultiplexedCipherGroup encrypted = profile_operation(prefix + ".conv1", [&]() {
        return multiplexed_channel_conv2d_all_channels(
            encrypted_input, planes, 1, 1, 1, weights.conv_weight[conv_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, runtime);
    });
    log_multiplexed_compare(prefix + ".conv1", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = profile_operation(prefix + ".bn1", [&]() {
        return multiplexed_channel_batch_norm(
            encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, kResNet50Boundary, runtime);
    });
    log_multiplexed_compare(prefix + ".bn1", encrypted, plain, runtime, run_log);
    ++conv_index;
    ++bn_index;

    encrypted = profile_operation(prefix + ".bootstrap1", [&]() {
        return multiplexed_channel_bootstrap(
            encrypted, logn, runtime, prefix + ".bootstrap1", mock_options);
    });
    log_multiplexed_compare(prefix + ".bootstrap1", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = profile_operation(prefix + ".relu1", [&]() {
        return multiplexed_channel_homomorphic_relu(
            encrypted, logn, relu_config, runtime, prefix + ".relu1", mock_options);
    });
    log_multiplexed_compare(prefix + ".relu1", encrypted, plain, runtime, run_log);

    plain = plain_convolution(
        plain, planes, stride, 3, 3, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon);
    encrypted = profile_operation(prefix + ".conv2", [&]() {
        return multiplexed_channel_conv2d_all_channels(
            encrypted, planes, stride, 3, 3, weights.conv_weight[conv_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, runtime);
    });
    log_multiplexed_compare(prefix + ".conv2", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = profile_operation(prefix + ".bn2", [&]() {
        return multiplexed_channel_batch_norm(
            encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, kResNet50Boundary, runtime);
    });
    log_multiplexed_compare(prefix + ".bn2", encrypted, plain, runtime, run_log);
    ++conv_index;
    ++bn_index;

    encrypted = profile_operation(prefix + ".bootstrap2", [&]() {
        return multiplexed_channel_bootstrap(
            encrypted, logn, runtime, prefix + ".bootstrap2", mock_options);
    });
    log_multiplexed_compare(prefix + ".bootstrap2", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = profile_operation(prefix + ".relu2", [&]() {
        return multiplexed_channel_homomorphic_relu(
            encrypted, logn, relu_config, runtime, prefix + ".relu2", mock_options);
    });
    log_multiplexed_compare(prefix + ".relu2", encrypted, plain, runtime, run_log);

    plain = plain_convolution(
        plain, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon);
    encrypted = profile_operation(prefix + ".conv3", [&]() {
        return multiplexed_channel_conv2d_all_channels(
            encrypted, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, runtime);
    });
    log_multiplexed_compare(prefix + ".conv3", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = profile_operation(prefix + ".bn3", [&]() {
        return multiplexed_channel_batch_norm(
            encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon, kResNet50Boundary, runtime);
    });
    log_multiplexed_compare(prefix + ".bn3", encrypted, plain, runtime, run_log);
    ++conv_index;
    ++bn_index;

    PlainTensor plain_shortcut = plain_input;
    MultiplexedCipherGroup encrypted_shortcut = encrypted_input;
    if (block == 0)
    {
        plain_shortcut = plain_convolution(
            plain_input, out_channels, stride, 1, 1, weights.downsample_weight[ds_index],
            weights.downsample_bn_running_var[ds_index],
            weights.downsample_bn_weight[ds_index], kBatchNormEpsilon);
        encrypted_shortcut = profile_operation(prefix + ".shortcut.conv", [&]() {
            return multiplexed_channel_conv2d_all_channels(
                encrypted_input, out_channels, stride, 1, 1,
                weights.downsample_weight[ds_index],
                weights.downsample_bn_running_var[ds_index],
                weights.downsample_bn_weight[ds_index], kBatchNormEpsilon, runtime);
        });
        log_multiplexed_compare(prefix + ".shortcut.conv", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);

        plain_shortcut = plain_batch_norm(
            plain_shortcut, weights.downsample_bn_bias[ds_index],
            weights.downsample_bn_running_mean[ds_index],
            weights.downsample_bn_running_var[ds_index],
            weights.downsample_bn_weight[ds_index], kBatchNormEpsilon,
            kResNet50Boundary);
        encrypted_shortcut = profile_operation(prefix + ".shortcut.bn", [&]() {
            return multiplexed_channel_batch_norm(
                encrypted_shortcut, weights.downsample_bn_bias[ds_index],
                weights.downsample_bn_running_mean[ds_index],
                weights.downsample_bn_running_var[ds_index],
                weights.downsample_bn_weight[ds_index], kBatchNormEpsilon,
                kResNet50Boundary, runtime);
        });
        log_multiplexed_compare(prefix + ".shortcut.bn", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);
    }
    else
    {
        log_multiplexed_compare(prefix + ".shortcut.identity", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);
    }

    plain = plain_add(plain, plain_shortcut);
    encrypted = profile_operation(prefix + ".add", [&]() {
        return multiplexed_channel_add(encrypted, encrypted_shortcut, runtime);
    });
    log_multiplexed_compare(prefix + ".add", encrypted, plain, runtime, run_log);

    encrypted = profile_operation(prefix + ".bootstrap3", [&]() {
        return multiplexed_channel_bootstrap(
            encrypted, logn, runtime, prefix + ".bootstrap3", mock_options);
    });
    log_multiplexed_compare(prefix + ".bootstrap3", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = profile_operation(prefix + ".relu3", [&]() {
        return multiplexed_channel_homomorphic_relu(
            encrypted, logn, relu_config, runtime, prefix + ".relu3", mock_options);
    });
    log_multiplexed_compare(prefix + ".relu3", encrypted, plain, runtime, run_log);

    return {std::move(plain), std::move(encrypted)};
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
    const auto run_start = chrono::steady_clock::now();
    const ProcessMemorySnapshot run_memory_start = capture_process_memory();
    log_process_memory_snapshot("resnet50 run start", run_memory_start);

    resnet18_progress_log() << "[startup] build inference plan" << endl;
    const PoseidonInferPlan plan = default_poseidon_plan();
    ReluConfig relu_config = default_relu_config(plan);
    const ExecutionOptions options = read_execution_options();
    resnet18_progress_log() << "[startup] load ResNet50 parameters" << endl;
    ModelWeights weights = profile_operation("startup.load_parameters", [&]() {
        return load_resnet50_parameters();
    });
    resnet18_progress_log() << "[startup] create Poseidon runtime and keys" << endl;
    PoseidonRuntime runtime = profile_operation("startup.create_runtime_and_keys", [&]() {
        return make_poseidon_runtime(plan);
    });
    resnet18_progress_log() << "[startup] Poseidon runtime ready" << endl;

    run_log << "ResNet50 ImageNet encrypted inference\n";
    run_log << "images=" << start_image_id << ".." << end_image_id
            << ", mock_relu=" << options.mock_relu
            << ", mock_bootstrap=" << options.mock_bootstrap << '\n';

    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        g_image_max_abs_errors.clear();
        const auto image_start = chrono::steady_clock::now();
        const ProcessMemorySnapshot image_memory_start = capture_process_memory();
        log_process_memory_snapshot("image." + to_string(image_id) + " start",
                                    image_memory_start);
        run_log << "\n[image] id=" << image_id << '\n';
        const vector<double> image_values = profile_operation(
            "image." + to_string(image_id) + ".load_input", [&]() {
                return read_plain_image_values(image_id, kResNet50Boundary);
            });
        const int true_label = read_image_label(image_id);
        const PlainTensor plain_input =
            plain_input_tensor_from_image_slots(image_values);

        size_t conv_index = 0;
        size_t bn_index = 0;
        PlainTensor plain = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight[conv_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon);
        Im2ColCipherGroup conv1_im2col = profile_operation("stem.encrypt_im2col_patches", [&]() {
            return encrypt_conv2d_im2col_patches(
                image_values, kImageNetInputHeight, kImageNetInputWidth,
                kImageNetInputChannels, 2, 7, 7, runtime, plan.log_scale);
        });
        ChannelCipherGroup encrypted_stem = profile_operation("stem.conv1", [&]() {
            return encrypted_conv2d_im2col_all_channels(
                conv1_im2col, 64, weights.conv_weight[0], weights.bn_running_var[0],
                weights.bn_weight[0], kBatchNormEpsilon, runtime);
        });
        log_channel_compare("stem.conv1", encrypted_stem, plain, runtime, run_log);

        MultiplexedCipherGroup encrypted = profile_operation("stem.pack_k1", [&]() {
            return pack_channel_group_as_multiplexed_k1(encrypted_stem, runtime);
        });
        log_multiplexed_compare("stem.pack_k1", encrypted, plain, runtime, run_log);

        plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                                 weights.bn_running_mean[bn_index],
                                 weights.bn_running_var[bn_index],
                                 weights.bn_weight[bn_index], kBatchNormEpsilon,
                                 kResNet50Boundary);
        encrypted = profile_operation("stem.bn1", [&]() {
            return multiplexed_channel_batch_norm(
                encrypted, weights.bn_bias[0], weights.bn_running_mean[0],
                weights.bn_running_var[0], weights.bn_weight[0], kBatchNormEpsilon,
                kResNet50Boundary, runtime);
        });
        log_multiplexed_compare("stem.bn1", encrypted, plain, runtime, run_log);

        ++conv_index;
        ++bn_index;

        plain = plain_polynomial_relu_reference(plain, relu_config);
        encrypted = profile_operation("stem.relu1", [&]() {
            return multiplexed_channel_homomorphic_relu(
                encrypted, plan.logN, relu_config, runtime, "stem.relu1",
                MultiplexedMockOptions{options.mock_relu, options.mock_bootstrap});
        });
        log_multiplexed_compare("stem.relu1", encrypted, plain, runtime, run_log);

        plain = plain_average_pool2d(plain, 3, 2, 1);
        encrypted = profile_operation("stem.avgpool", [&]() {
            return multiplexed_average_pool2d_stride2(
                encrypted, plain.h, plain.w, encrypted.k * 2, runtime);
        });
        log_multiplexed_compare("stem.avgpool", encrypted, plain, runtime, run_log);

        for (int stage = 1; stage <= kResNet50StageCount; ++stage)
        {
            const size_t ds_index = static_cast<size_t>(stage - 1);
            for (int block = 0; block < kResNet50BlocksPerStage[stage - 1]; ++block)
            {
                const string block_label = "layer" + to_string(stage) + ".block" +
                                           to_string(block) + ".total";
                TracedBlockState state = profile_operation(block_label, [&]() {
                    return traced_bottleneck_block(
                        plain, encrypted, weights, stage, block, conv_index, bn_index,
                        ds_index, relu_config, options, plan.logN, runtime, run_log);
                });
                plain = std::move(state.plain);
                encrypted = std::move(state.encrypted);
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

        log_multiplexed_group_cipher_state("head entry after layer4.block2.relu3", encrypted,
                                           runtime);
        Ciphertext encrypted_avg = profile_operation("head.avgpool", [&]() {
            return multiplexed_global_average_pool_packed(
                encrypted, kResNet50Boundary, runtime);
        });
        log_packed_feature_compare("head.avgpool", plain_avg, encrypted_avg, runtime,
                                   run_log);

        vector<Ciphertext> encrypted_logits = profile_operation("head fully connected", [&]() {
            return multiplexed_fully_connected_packed(
                encrypted_avg, kResNet50FinalChannels, weights.linear_weight,
                weights.linear_bias, kImageNetClassCount, runtime);
        });
        log_logits_cipher_state(encrypted_logits, runtime);
        vector<complex<double>> decrypted_logits_complex = profile_operation(
            "head.decrypt_logits", [&]() {
                return decrypt_slot0_complex_values(encrypted_logits, runtime, "head.fc");
            });
        vector<double> decrypted_logits = real_values(decrypted_logits_complex);
        log_logits_compare("head logits", plain_logits, decrypted_logits_complex, run_log,
                           kImageNetClassCount);
        const int encrypted_pred = argmax_index(decrypted_logits);
        const double logit_error = max_abs_error(plain_logits, decrypted_logits);

        run_log << "[logit-decision] true_label=" << true_label
                << " plain_pred=" << plain_pred << " encrypted_pred=" << encrypted_pred
                << " prediction_match=" << (plain_pred == encrypted_pred ? 1 : 0) << '\n';
        const auto write_decision = [&](const string &role, int label) {
            run_log << "[logit-decision] role=" << role << " label=" << label
                    << " plain=" << plain_logits.at(static_cast<size_t>(label))
                    << " cipher_real="
                    << decrypted_logits_complex.at(static_cast<size_t>(label)).real()
                    << " cipher_imag="
                    << decrypted_logits_complex.at(static_cast<size_t>(label)).imag()
                    << " abs_error="
                    << fabs(plain_logits.at(static_cast<size_t>(label)) -
                            decrypted_logits.at(static_cast<size_t>(label)))
                    << '\n';
        };
        write_decision("true_label", true_label);
        write_decision("plain_pred", plain_pred);
        write_decision("encrypted_pred", encrypted_pred);

        vector<int> selected_labels{true_label, plain_pred, encrypted_pred};
        sort(selected_labels.begin(), selected_labels.end());
        selected_labels.erase(unique(selected_labels.begin(), selected_labels.end()),
                              selected_labels.end());
        run_log << "[selected-logits]";
        for (int label : selected_labels)
        {
            run_log << " label=" << label
                    << " plain=" << plain_logits.at(static_cast<size_t>(label))
                    << " cipher_real="
                    << decrypted_logits_complex.at(static_cast<size_t>(label)).real()
                    << " cipher_imag="
                    << decrypted_logits_complex.at(static_cast<size_t>(label)).imag()
                    << " abs_error="
                    << fabs(plain_logits.at(static_cast<size_t>(label)) -
                            decrypted_logits.at(static_cast<size_t>(label)));
        }
        run_log << '\n';
        run_log << "head logits max_abs_error: " << logit_error << '\n';
        run_log << "head plain predicted label: " << plain_pred
                << ", encrypted predicted label: " << encrypted_pred << '\n';
        resnet18_progress_log() << "head logits max_abs_error: " << logit_error << endl;
        resnet18_progress_log() << "head plain predicted label: " << plain_pred
                                << ", encrypted predicted label: " << encrypted_pred << endl;

        const auto image_elapsed = chrono::duration_cast<chrono::milliseconds>(
                                       chrono::steady_clock::now() - image_start)
                                       .count();
        const ProcessMemorySnapshot image_memory_end = capture_process_memory();
        run_log << "image label: " << true_label << '\n';
        run_log << "image time : " << image_elapsed << " ms\n";
        ostringstream image_summary;
        image_summary << "image_id: " << image_id << ", image label: " << true_label;
        for (const auto &entry : g_image_max_abs_errors)
        {
            image_summary << ", " << summary_key(entry.first) << "=" << entry.second;
        }
        image_summary << ", plain_head_predicted_label=" << plain_pred
                      << ", encrypted_predicted_label=" << encrypted_pred
                      << ", image_time_ms=" << image_elapsed;
        run_log << image_summary.str() << '\n';
        resnet18_progress_log() << image_summary.str() << endl;
        run_log << "image_done: " << image_id << ", image label: " << true_label;
        for (const auto &entry : g_image_max_abs_errors)
        {
            run_log << ", " << summary_key(entry.first) << "=" << entry.second;
        }
        run_log << ", plain_head_predicted_label=" << plain_pred
                << ", encrypted_predicted_label=" << encrypted_pred
                << ", image_time_ms=" << image_elapsed << '\n';
        log_process_memory_change("image." + to_string(image_id), image_memory_start,
                                  image_memory_end);
    }

    const auto total_elapsed = chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - run_start)
                                   .count();
    const ProcessMemorySnapshot run_memory_end = capture_process_memory();
    resnet18_progress_log() << "total time : " << total_elapsed << " ms" << endl;
    run_log << "total time : " << total_elapsed << " ms\n";
    run_log << "run_done: total_time_ms=" << total_elapsed << '\n';
    log_process_memory_change("resnet50 run total", run_memory_start, run_memory_end);
}
