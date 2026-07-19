#include "infer.h"

#include "encrypted_group_ops.h"
#include "encrypted_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "multiplexed_ops.h"
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

void log_logits_compare(const string &label, const vector<double> &plain,
                        const vector<complex<double>> &encrypted, ostream &out,
                        size_t preview_limit = 16)
{
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

ChannelCipherGroup encrypt_channel_group_values(const PlainTensor &plain, PoseidonRuntime &runtime,
                                                int logp)
{
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[encrypt-group-start] mock.refresh shape=" << plain.h << 'x'
                            << plain.w << 'x' << plain.c << " logp=" << logp << endl;
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
        resnet18_progress_log() << "[encrypt-channel-done] mock.refresh channel=" << channel + 1
                                << '/' << plain.c << endl;
    }

    resnet18_progress_log() << "[encrypt-group-done] mock.refresh total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
    return group;
}

ChannelCipherGroup mock_refresh_from_plain(const PlainTensor &plain, PoseidonRuntime &runtime,
                                           int logp)
{
    return encrypt_channel_group_values(plain, runtime, logp);
}

PlainTensor decrypt_channel_group_to_plain_tensor(const ChannelCipherGroup &group,
                                                  PoseidonRuntime &runtime)
{
    vector<complex<double>> decrypted =
        decrypt_channel_group_complex(group, runtime, "mock.decrypt_input");
    vector<double> values(decrypted.size(), 0.0);
    for (size_t i = 0; i < decrypted.size(); ++i)
    {
        values[i] = decrypted[i].real();
    }
    return PlainTensor(group.h, group.w, group.c, std::move(values));
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
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[relu-start] mode=" << (options.mock_relu ? "mock" : "encrypted")
                            << " shape=" << input.h << 'x' << input.w << 'x' << input.c
                            << " threads="
                            << resnet18_parallel_thread_count(input.channels.size()) << endl;
    if (options.mock_relu)
    {
        (void)plain_output;
        PlainTensor decrypted_input = decrypt_channel_group_to_plain_tensor(input, runtime);
        PlainTensor relu_output =
            plain_polynomial_relu_reference(decrypted_input, relu_config);
        ChannelCipherGroup output = mock_refresh_from_plain(relu_output, runtime, 46);
        resnet18_progress_log() << "[relu-done] mode=mock total_ms="
                                << chrono::duration_cast<chrono::milliseconds>(
                                       chrono::steady_clock::now() - start)
                                       .count()
                                << endl;
        return output;
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
    resnet18_progress_log() << "[relu-done] mode=encrypted channels=" << input.channels.size()
                            << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
    return output;
}

ChannelCipherGroup channel_bootstrap(const ChannelCipherGroup &input, const PlainTensor &plain,
                                     const ExecutionOptions &options, PoseidonRuntime &runtime)
{
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[bootstrap-start] mode="
                            << (options.mock_bootstrap ? "mock" : "encrypted")
                            << " shape=" << input.h << 'x' << input.w << 'x' << input.c
                            << " threads="
                            << resnet18_parallel_thread_count(input.channels.size()) << endl;
    if (options.mock_bootstrap)
    {
        (void)plain;
        PlainTensor decrypted_input = decrypt_channel_group_to_plain_tensor(input, runtime);
        ChannelCipherGroup output = mock_refresh_from_plain(decrypted_input, runtime, 46);
        resnet18_progress_log() << "[bootstrap-done] mode=mock total_ms="
                                << chrono::duration_cast<chrono::milliseconds>(
                                       chrono::steady_clock::now() - start)
                                       .count()
                                << endl;
        return output;
    }

    PoseidonBootstrapContext bootstrapper;
    bootstrapper.context = &runtime.context;
    bootstrapper.evaluator = runtime.evaluator.get();
    bootstrapper.encoder = &runtime.encoder;
    bootstrapper.relin_keys = &runtime.relin_keys;
    bootstrapper.galois_keys = &runtime.galois_keys;
    bootstrapper.bootstrap_config = &runtime.bootstrap_config;

    ChannelCipherGroup output = input;
    resnet18_parallel_for(input.channels.size(), [&](size_t channel_index) {
        TensorCipher in(16, 1, input.h, input.w, 1, 1, 1, input.channels[channel_index]);
        TensorCipher out;
        bootstrap_tensor(in, out, bootstrapper);
        output.channels[channel_index] = out.cipher();
    });
    resnet18_progress_log() << "[bootstrap-done] mode=encrypted channels="
                            << input.channels.size() << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
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
    MultiplexedCipherGroup encrypted = multiplexed_channel_conv2d_all_channels(
        encrypted_input, planes, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    log_multiplexed_compare(prefix + ".conv1", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = multiplexed_channel_batch_norm(
        encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
        kBatchNormEpsilon, kResNet50Boundary, runtime);
    log_multiplexed_compare(prefix + ".bn1", encrypted, plain, runtime, run_log);
    ++conv_index;
    ++bn_index;

    encrypted = multiplexed_channel_bootstrap(
        encrypted, logn, runtime, prefix + ".bootstrap1", mock_options);
    log_multiplexed_compare(prefix + ".bootstrap1", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = multiplexed_channel_homomorphic_relu(
        encrypted, logn, relu_config, runtime, prefix + ".relu1", mock_options);
    log_multiplexed_compare(prefix + ".relu1", encrypted, plain, runtime, run_log);

    plain = plain_convolution(
        plain, planes, stride, 3, 3, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon);
    encrypted = multiplexed_channel_conv2d_all_channels(
        encrypted, planes, stride, 3, 3, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    log_multiplexed_compare(prefix + ".conv2", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = multiplexed_channel_batch_norm(
        encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
        kBatchNormEpsilon, kResNet50Boundary, runtime);
    log_multiplexed_compare(prefix + ".bn2", encrypted, plain, runtime, run_log);
    ++conv_index;
    ++bn_index;

    encrypted = multiplexed_channel_bootstrap(
        encrypted, logn, runtime, prefix + ".bootstrap2", mock_options);
    log_multiplexed_compare(prefix + ".bootstrap2", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = multiplexed_channel_homomorphic_relu(
        encrypted, logn, relu_config, runtime, prefix + ".relu2", mock_options);
    log_multiplexed_compare(prefix + ".relu2", encrypted, plain, runtime, run_log);

    plain = plain_convolution(
        plain, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon);
    encrypted = multiplexed_channel_conv2d_all_channels(
        encrypted, out_channels, 1, 1, 1, weights.conv_weight[conv_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index], kBatchNormEpsilon,
        runtime);
    log_multiplexed_compare(prefix + ".conv3", encrypted, plain, runtime, run_log);

    plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                             weights.bn_running_mean[bn_index],
                             weights.bn_running_var[bn_index],
                             weights.bn_weight[bn_index], kBatchNormEpsilon,
                             kResNet50Boundary);
    encrypted = multiplexed_channel_batch_norm(
        encrypted, weights.bn_bias[bn_index], weights.bn_running_mean[bn_index],
        weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
        kBatchNormEpsilon, kResNet50Boundary, runtime);
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
        encrypted_shortcut = multiplexed_channel_conv2d_all_channels(
            encrypted_input, out_channels, stride, 1, 1,
            weights.downsample_weight[ds_index],
            weights.downsample_bn_running_var[ds_index],
            weights.downsample_bn_weight[ds_index], kBatchNormEpsilon, runtime);
        log_multiplexed_compare(prefix + ".shortcut.conv", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);

        plain_shortcut = plain_batch_norm(
            plain_shortcut, weights.downsample_bn_bias[ds_index],
            weights.downsample_bn_running_mean[ds_index],
            weights.downsample_bn_running_var[ds_index],
            weights.downsample_bn_weight[ds_index], kBatchNormEpsilon,
            kResNet50Boundary);
        encrypted_shortcut = multiplexed_channel_batch_norm(
            encrypted_shortcut, weights.downsample_bn_bias[ds_index],
            weights.downsample_bn_running_mean[ds_index],
            weights.downsample_bn_running_var[ds_index],
            weights.downsample_bn_weight[ds_index], kBatchNormEpsilon,
            kResNet50Boundary, runtime);
        log_multiplexed_compare(prefix + ".shortcut.bn", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);
    }
    else
    {
        log_multiplexed_compare(prefix + ".shortcut.identity", encrypted_shortcut,
                                plain_shortcut, runtime, run_log);
    }

    plain = plain_add(plain, plain_shortcut);
    encrypted = multiplexed_channel_add(encrypted, encrypted_shortcut, runtime);
    log_multiplexed_compare(prefix + ".add", encrypted, plain, runtime, run_log);

    encrypted = multiplexed_channel_bootstrap(
        encrypted, logn, runtime, prefix + ".bootstrap3", mock_options);
    log_multiplexed_compare(prefix + ".bootstrap3", encrypted, plain, runtime, run_log);
    plain = plain_polynomial_relu_reference(plain, relu_config);
    encrypted = multiplexed_channel_homomorphic_relu(
        encrypted, logn, relu_config, runtime, prefix + ".relu3", mock_options);
    log_multiplexed_compare(prefix + ".relu3", encrypted, plain, runtime, run_log);

    return {std::move(plain), std::move(encrypted)};
}
ChannelCipherGroup encrypted_global_average_pool(const ChannelCipherGroup &input,
                                                 PoseidonRuntime &runtime)
{
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[global-avgpool-start] shape=" << input.h << 'x' << input.w
                            << 'x' << input.c << " threads="
                            << resnet18_parallel_thread_count(input.channels.size()) << endl;
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
    resnet18_progress_log() << "[global-avgpool-done] channels=" << input.channels.size()
                            << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
    return output;
}

vector<Ciphertext> encrypted_fully_connected_slot0(const ChannelCipherGroup &features,
                                                   const vector<double> &matrix,
                                                   const vector<double> &bias,
                                                   PoseidonRuntime &runtime)
{
    const auto start = chrono::steady_clock::now();
    resnet18_progress_log() << "[fully-connected-start] classes=" << kImageNetClassCount
                            << " input_channels=" << features.c << " threads="
                            << resnet18_parallel_thread_count(kImageNetClassCount) << endl;
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
    resnet18_progress_log() << "[fully-connected-done] classes=" << logits.size()
                            << " total_ms="
                            << chrono::duration_cast<chrono::milliseconds>(
                                   chrono::steady_clock::now() - start)
                                   .count()
                            << endl;
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

    resnet18_progress_log() << "[startup] build inference plan" << endl;
    const PoseidonInferPlan plan = default_poseidon_plan();
    ReluConfig relu_config = default_relu_config(plan);
    const ExecutionOptions options = read_execution_options();
    resnet18_progress_log() << "[startup] load ResNet50 parameters" << endl;
    ModelWeights weights = load_resnet50_parameters();
    resnet18_progress_log() << "[startup] create Poseidon runtime and keys" << endl;
    PoseidonRuntime runtime = make_poseidon_runtime(plan);
    resnet18_progress_log() << "[startup] Poseidon runtime ready" << endl;

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

        size_t conv_index = 0;
        size_t bn_index = 0;
        PlainTensor plain = plain_convolution(
            plain_input, 64, 2, 7, 7, weights.conv_weight[conv_index],
            weights.bn_running_var[bn_index], weights.bn_weight[bn_index],
            kBatchNormEpsilon);
        Im2ColCipherGroup conv1_im2col = encrypt_conv2d_im2col_patches(
            image_values, kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels, 2,
            7, 7, runtime, plan.log_scale);
        ChannelCipherGroup encrypted_stem = encrypted_conv2d_im2col_all_channels(
            conv1_im2col, 64, weights.conv_weight[0], weights.bn_running_var[0],
            weights.bn_weight[0], kBatchNormEpsilon, runtime);
        log_channel_compare("stem.conv1", encrypted_stem, plain, runtime, run_log);

        MultiplexedCipherGroup encrypted =
            pack_channel_group_as_multiplexed_k1(encrypted_stem, runtime);
        log_multiplexed_compare("stem.pack_k1", encrypted, plain, runtime, run_log);

        plain = plain_batch_norm(plain, weights.bn_bias[bn_index],
                                 weights.bn_running_mean[bn_index],
                                 weights.bn_running_var[bn_index],
                                 weights.bn_weight[bn_index], kBatchNormEpsilon,
                                 kResNet50Boundary);
        encrypted = multiplexed_channel_batch_norm(
            encrypted, weights.bn_bias[0], weights.bn_running_mean[0],
            weights.bn_running_var[0], weights.bn_weight[0], kBatchNormEpsilon,
            kResNet50Boundary, runtime);
        log_multiplexed_compare("stem.bn1", encrypted, plain, runtime, run_log);

        ++conv_index;
        ++bn_index;

        plain = plain_polynomial_relu_reference(plain, relu_config);
        encrypted = multiplexed_channel_homomorphic_relu(
            encrypted, plan.logN, relu_config, runtime, "stem.relu1",
            MultiplexedMockOptions{options.mock_relu, options.mock_bootstrap});
        log_multiplexed_compare("stem.relu1", encrypted, plain, runtime, run_log);

        plain = plain_average_pool2d(plain, 3, 2, 1);
        encrypted = multiplexed_average_pool2d_stride2(
            encrypted, plain.h, plain.w, encrypted.k * 2, runtime);
        log_multiplexed_compare("stem.avgpool", encrypted, plain, runtime, run_log);

        for (int stage = 1; stage <= kResNet50StageCount; ++stage)
        {
            const size_t ds_index = static_cast<size_t>(stage - 1);
            for (int block = 0; block < kResNet50BlocksPerStage[stage - 1]; ++block)
            {
                TracedBlockState state = traced_bottleneck_block(
                    plain, encrypted, weights, stage, block, conv_index, bn_index, ds_index,
                    relu_config, options, plan.logN, runtime, run_log);
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
        Ciphertext encrypted_avg = multiplexed_global_average_pool_packed(
            encrypted, kResNet50Boundary, runtime);
        log_packed_feature_compare("head.avgpool", plain_avg, encrypted_avg, runtime,
                                   run_log);

        vector<Ciphertext> encrypted_logits = multiplexed_fully_connected_packed(
            encrypted_avg, kResNet50FinalChannels, weights.linear_weight,
            weights.linear_bias, kImageNetClassCount, runtime);
        vector<complex<double>> decrypted_logits_complex =
            decrypt_slot0_complex_values(encrypted_logits, runtime, "head.fc");
        vector<double> decrypted_logits = real_values(decrypted_logits_complex);
        log_logits_compare("head.fc", plain_logits, decrypted_logits_complex, run_log);
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
