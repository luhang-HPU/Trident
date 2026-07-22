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
        const auto end = chrono::steady_clock::now();
        const auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start_).count();
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
    const int rescale_prime_bits = context_data->coeff_modulus().back().bit_count();
    return pow(2.0, static_cast<double>(rescale_prime_bits));
}

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term, CKKSEncoder &encoder,
                        EvaluatorCkksBase &evaluator)
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

void log_im2col_cipher_state(const string &label, const Im2ColCipherGroup &im2col,
                             PoseidonRuntime &runtime)
{
    if (im2col.patches.empty())
    {
        resnet18_progress_log() << "[cipher-state] " << label
                                << ": empty im2col patch group" << endl;
        return;
    }

    const size_t first_chain = cipher_chain_index(runtime, im2col.patches.front());
    size_t min_chain = first_chain;
    size_t max_chain = first_chain;
    const double first_scale = im2col.patches.front().scale();
    double min_scale = first_scale;
    double max_scale = first_scale;
    for (const Ciphertext &cipher : im2col.patches)
    {
        const size_t chain = cipher_chain_index(runtime, cipher);
        min_chain = min(min_chain, chain);
        max_chain = max(max_chain, chain);
        min_scale = min(min_scale, cipher.scale());
        max_scale = max(max_scale, cipher.scale());
    }

    resnet18_progress_log()
        << "[cipher-state] " << label
        << ": input_shape(h=" << im2col.input_h << ", w=" << im2col.input_w
        << ", c=" << im2col.input_c << "), output_shape(h=" << im2col.out_h
        << ", w=" << im2col.out_w << "), kernel=" << im2col.fh << "x" << im2col.fw
        << ", stride=" << im2col.stride << ", patches=" << im2col.patches.size()
        << ", slots_per_cipher=" << im2col.slot_count
        << ", chain_index(first/min/max)=" << first_chain << "/" << min_chain << "/"
        << max_chain << ", q_count(first/min/max)=" << first_chain + 1 << "/"
        << min_chain + 1 << "/" << max_chain + 1
        << ", scale(first/min/max)=" << first_scale << "/" << min_scale << "/"
        << max_scale << endl;
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

bool coefficient_encodes_to_zero(const Ciphertext &input, double coeff,
                                 const CKKSEncoder &encoder)
{
    return fabs(coeff * multiply_plain_scale(input, encoder)) < 0.5;
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

    Im2ColCipherGroup im2col;
    im2col.input_h = input_h;
    im2col.input_w = input_w;
    im2col.input_c = input_c;
    im2col.out_h = input_h / stride;
    im2col.out_w = input_w / stride;
    im2col.fh = fh;
    im2col.fw = fw;
    im2col.stride = stride;
    im2col.spatial_count = static_cast<size_t>(im2col.out_h * im2col.out_w);
    im2col.slot_count = runtime.encoder.slot_count();
    if (im2col.spatial_count > im2col.slot_count)
    {
        throw invalid_argument("im2col spatial output does not fit in one ciphertext");
    }

    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    im2col.patches.reserve(static_cast<size_t>(input_c * fh * fw));
    for (int ic = 0; ic < input_c; ++ic)
    {
        for (int kh = 0; kh < fh; ++kh)
        {
            for (int kw = 0; kw < fw; ++kw)
            {
                vector<complex<double>> slots(im2col.slot_count, {0.0, 0.0});
                for (int oh = 0; oh < im2col.out_h; ++oh)
                {
                    for (int ow = 0; ow < im2col.out_w; ++ow)
                    {
                        const int ih = oh * stride + kh - pad_h;
                        const int iw = ow * stride + kw - pad_w;
                        if (ih < 0 || ih >= input_h || iw < 0 || iw >= input_w)
                        {
                            continue;
                        }
                        const size_t input_index =
                            static_cast<size_t>(ic * input_h * input_w + ih * input_w + iw);
                        const size_t output_slot =
                            static_cast<size_t>(oh * im2col.out_w + ow);
                        slots[output_slot] = {image_values[input_index], 0.0};
                    }
                }

                Plaintext plain;
                runtime.encoder.encode(slots, pow(2.0, logp), plain);
                Ciphertext cipher;
                runtime.encryptor.encrypt(plain, cipher);
                im2col.patches.emplace_back(std::move(cipher));
            }
        }
    }

    return im2col;
}

ChannelCipherGroup encrypted_conv2d_im2col_all_channels(
    const Im2ColCipherGroup &im2col, int out_channels, const vector<double> &weights,
    const vector<double> &running_var, const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    ScopedDurationLog duration("conv_im2col_all_channels");
    log_im2col_cipher_state("conv_im2col_all_channels input", im2col, runtime);
    ChannelCipherGroup group;
    group.h = im2col.out_h;
    group.w = im2col.out_w;
    group.c = out_channels;
    group.spatial_count = im2col.spatial_count;
    group.slot_count = im2col.slot_count;
    vector<Ciphertext> output_channels(static_cast<size_t>(out_channels));

    resnet18_progress_log() << "conv im2col encrypted channel parallel threads: "
                            << resnet18_parallel_thread_count(static_cast<size_t>(out_channels))
                            << endl;
    resnet18_parallel_for(static_cast<size_t>(out_channels), [&](size_t output_channel_index) {
        const int output_channel = static_cast<int>(output_channel_index);
        Ciphertext sum;
        bool has_sum = false;
        const double folded_scale = constant_weight[output_channel] /
                                    sqrt(running_var[output_channel] + epsilon);
        for (int ic = 0; ic < im2col.input_c; ++ic)
        {
            for (int kh = 0; kh < im2col.fh; ++kh)
            {
                for (int kw = 0; kw < im2col.fw; ++kw)
                {
                    const size_t patch_index =
                        static_cast<size_t>(ic * im2col.fh * im2col.fw + kh * im2col.fw + kw);
                    const size_t weight_index = static_cast<size_t>(
                        im2col.fh * im2col.fw * im2col.input_c * output_channel +
                        im2col.fh * im2col.fw * ic + im2col.fw * kh + kw);
                    const double coeff = weights[weight_index] * folded_scale;
                    if (coeff == 0.0 ||
                        coefficient_encodes_to_zero(im2col.patches.at(patch_index), coeff,
                                                    runtime.encoder))
                    {
                        continue;
                    }

                    Ciphertext term;
                    try
                    {
                        term = multiply_by_constant_scalar(im2col.patches.at(patch_index), coeff,
                                                           runtime.encoder, *runtime.evaluator);
                    }
                    catch (const exception &ex)
                    {
                        ostringstream message;
                        message << "im2col all-channel multiply failed: output_channel="
                                << output_channel << ", patch_index=" << patch_index
                                << ", coeff=" << coeff << ", reason=" << ex.what();
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
            throw runtime_error("im2col output channel produced no encrypted terms");
        }
        output_channels.at(output_channel_index) = std::move(sum);
    });

    group.channels = std::move(output_channels);

    resnet18_progress_log() << "conv im2col encrypted channel progress: " << out_channels << "/"
         << out_channels << endl;
    log_channel_group_cipher_state("conv_im2col_all_channels output", group, runtime);

    return group;
}
