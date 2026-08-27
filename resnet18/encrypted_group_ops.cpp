#include "encrypted_group_ops.h"

#include "parallel_utils.h"
#include "progress_log.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

class ScopedDurationLog
{
public:
    explicit ScopedDurationLog(string label)
        : label_(std::move(label)), start_(chrono::steady_clock::now())
    {
        resnet18_progress_log() << "[start] " << label_ << endl;
    }

    ~ScopedDurationLog()
    {
        const auto elapsed =
            chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start_)
                .count();
        resnet18_progress_log() << "[duration] " << label_ << ": " << elapsed << " ms" << endl;
    }

private:
    string label_;
    chrono::steady_clock::time_point start_;
};

double multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    return pow(2.0, static_cast<double>(context_data->coeff_modulus().back().bit_count()));
}

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term,
                        CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
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
        min_scale = min(min_scale, cipher.scale());
        max_scale = max(max_scale, cipher.scale());
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

void log_im2col_cipher_state(const string &label, const Im2ColCipherGroup &group,
                             PoseidonRuntime &runtime)
{
    if (group.patches.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label << ": empty im2col patch group"
                                << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, group.patches.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = group.patches.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;
    for (const Ciphertext &cipher : group.patches)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        min_scale = min(min_scale, cipher.scale());
        max_scale = max(max_scale, cipher.scale());
    }

    resnet18_progress_log()
        << "[cipher-state] " << label << ": input_shape(h=" << group.input_h
        << ", w=" << group.input_w << ", c=" << group.input_c << "), output_shape(h="
        << group.out_h << ", w=" << group.out_w << "), kernel=" << group.fh << "x"
        << group.fw << ", stride=" << group.stride << ", patches=" << group.patches.size()
        << ", slots_per_cipher=" << group.slot_count << ", chain_index(first/min/max)="
        << first_chain << "/" << min_chain << "/" << max_chain
        << ", scale(first/min/max)=" << first_scale << "/" << min_scale << "/" << max_scale
        << endl;
}

Ciphertext multiply_by_constant_scalar(const Ciphertext &input, double coefficient,
                                       CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(coefficient, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    Ciphertext output;
    evaluator.multiply_plain(input, plain, output);
    evaluator.rescale_dynamic(output, output, input.scale());
    return output;
}

bool coefficient_encodes_to_zero(const Ciphertext &input, double coefficient,
                                 const CKKSEncoder &encoder)
{
    return fabs(coefficient * multiply_plain_scale(input, encoder)) < 0.5;
}

} // namespace

Im2ColCipherGroup encrypt_conv2d_im2col_patches(const vector<double> &image_values, int input_h,
                                                int input_w, int input_c, int stride, int fh,
                                                int fw, PoseidonRuntime &runtime, int logp)
{
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("im2col encryption supports stride 1 or 2 only");
    }
    if (fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("im2col encryption expects odd kernel sizes");
    }
    if (image_values.size() != static_cast<size_t>(input_h * input_w * input_c))
    {
        throw invalid_argument("im2col input values do not match shape");
    }

    Im2ColCipherGroup group;
    group.input_h = input_h;
    group.input_w = input_w;
    group.input_c = input_c;
    group.out_h = input_h / stride;
    group.out_w = input_w / stride;
    group.fh = fh;
    group.fw = fw;
    group.stride = stride;
    group.spatial_count = static_cast<size_t>(group.out_h * group.out_w);
    group.slot_count = runtime.encoder.slot_count();
    if (group.spatial_count > group.slot_count)
    {
        throw invalid_argument("im2col spatial output does not fit in one ciphertext");
    }

    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    group.patches.reserve(static_cast<size_t>(input_c * fh * fw));
    for (int input_channel = 0; input_channel < input_c; ++input_channel)
    {
        for (int kernel_row = 0; kernel_row < fh; ++kernel_row)
        {
            for (int kernel_col = 0; kernel_col < fw; ++kernel_col)
            {
                vector<complex<double>> slots(group.slot_count, {0.0, 0.0});
                for (int output_row = 0; output_row < group.out_h; ++output_row)
                {
                    for (int output_col = 0; output_col < group.out_w; ++output_col)
                    {
                        const int input_row = output_row * stride + kernel_row - pad_h;
                        const int input_col = output_col * stride + kernel_col - pad_w;
                        if (input_row < 0 || input_row >= input_h || input_col < 0 ||
                            input_col >= input_w)
                        {
                            continue;
                        }
                        const size_t input_index = static_cast<size_t>(
                            input_channel * input_h * input_w + input_row * input_w + input_col);
                        const size_t output_slot =
                            static_cast<size_t>(output_row * group.out_w + output_col);
                        slots[output_slot] = {image_values[input_index], 0.0};
                    }
                }

                Plaintext plain;
                runtime.encoder.encode(slots, pow(2.0, logp), plain);
                Ciphertext cipher;
                runtime.encryptor.encrypt(plain, cipher);
                group.patches.emplace_back(std::move(cipher));
            }
        }
    }
    return group;
}

ChannelCipherGroup encrypted_conv2d_im2col_all_channels(
    const Im2ColCipherGroup &im2col, int out_channels, const vector<double> &weights,
    const vector<double> &running_var, const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    ScopedDurationLog duration("conv_im2col_all_channels");
    log_im2col_cipher_state("conv_im2col_all_channels input", im2col, runtime);

    ChannelCipherGroup output;
    output.h = im2col.out_h;
    output.w = im2col.out_w;
    output.c = out_channels;
    output.spatial_count = im2col.spatial_count;
    output.slot_count = im2col.slot_count;
    vector<Ciphertext> output_channels(static_cast<size_t>(out_channels));
    vector<unsigned char> quantized_zero_channels(static_cast<size_t>(out_channels), 0);

    resnet18_progress_log() << "conv im2col encrypted channel parallel threads: "
                            << resnet18_parallel_thread_count(static_cast<size_t>(out_channels))
                            << endl;
    resnet18_parallel_for(static_cast<size_t>(out_channels), [&](size_t output_channel_index) {
        const int output_channel = static_cast<int>(output_channel_index);
        Ciphertext sum;
        bool has_sum = false;
        const double folded_scale = constant_weight[output_channel] /
                                    sqrt(running_var[output_channel] + epsilon);
        for (int input_channel = 0; input_channel < im2col.input_c; ++input_channel)
        {
            for (int kernel_row = 0; kernel_row < im2col.fh; ++kernel_row)
            {
                for (int kernel_col = 0; kernel_col < im2col.fw; ++kernel_col)
                {
                    const size_t patch_index = static_cast<size_t>(
                        input_channel * im2col.fh * im2col.fw + kernel_row * im2col.fw +
                        kernel_col);
                    const size_t weight_index = static_cast<size_t>(
                        im2col.fh * im2col.fw * im2col.input_c * output_channel +
                        im2col.fh * im2col.fw * input_channel + im2col.fw * kernel_row +
                        kernel_col);
                    const double coefficient = weights[weight_index] * folded_scale;
                    if (coefficient == 0.0 ||
                        coefficient_encodes_to_zero(im2col.patches.at(patch_index), coefficient,
                                                    runtime.encoder))
                    {
                        continue;
                    }

                    Ciphertext term;
                    try
                    {
                        term = multiply_by_constant_scalar(im2col.patches.at(patch_index),
                                                           coefficient, runtime.encoder,
                                                           *runtime.evaluator);
                    }
                    catch (const exception &exception)
                    {
                        ostringstream message;
                        message << "im2col all-channel multiply failed: output_channel="
                                << output_channel << ", patch_index=" << patch_index
                                << ", coefficient=" << coefficient
                                << ", reason=" << exception.what();
                        throw runtime_error(message.str());
                    }

                    if (!has_sum)
                    {
                        sum = std::move(term);
                        has_sum = true;
                    }
                    else
                    {
                        add_assign_dynamic(sum, term, runtime.encoder, *runtime.evaluator);
                    }
                }
            }
        }

        if (!has_sum)
        {
            // A near-zero folded BN scale can make every convolution coefficient
            // encode to zero at the current CKKS plaintext scale. The mathematically
            // correct convolution output is then zero. Materialize a fresh encrypted
            // zero and drop the same modulus that multiply+rescale would consume so
            // its parms_id and scale match the nonzero output channels.
            Ciphertext encrypted_zero;
            runtime.encryptor.encrypt_zero(im2col.patches.front().parms_id(),
                                           encrypted_zero);
            encrypted_zero.scale() = im2col.patches.front().scale();
            runtime.evaluator->drop_modulus_to_next(encrypted_zero, sum);
            sum.scale() = im2col.patches.front().scale();
            quantized_zero_channels.at(output_channel_index) = 1;
        }
        output_channels.at(output_channel_index) = std::move(sum);
    });

    for (size_t output_channel_index = 0;
         output_channel_index < quantized_zero_channels.size(); ++output_channel_index)
    {
        if (quantized_zero_channels.at(output_channel_index) != 0)
        {
            resnet18_progress_log()
                << "conv im2col output channel " << output_channel_index
                << " quantized to encrypted zero at the current plaintext scale" << endl;
        }
    }

    output.channels = std::move(output_channels);
    resnet18_progress_log() << "conv im2col encrypted channel progress: " << out_channels << "/"
                            << out_channels << endl;
    log_channel_group_cipher_state("conv_im2col_all_channels output", output, runtime);
    return output;
}

vector<double> decrypt_channel_cipher_group(const ChannelCipherGroup &group,
                                            PoseidonRuntime &runtime)
{
    vector<double> values;
    values.reserve(static_cast<size_t>(group.c) * group.spatial_count);
    for (const Ciphertext &cipher : group.channels)
    {
        Plaintext plain;
        runtime.decryptor.decrypt(cipher, plain);
        vector<complex<double>> decoded;
        runtime.encoder.decode(plain, decoded);
        for (size_t index = 0; index < group.spatial_count; ++index)
        {
            values.emplace_back(decoded.at(index).real());
        }
    }
    return values;
}
