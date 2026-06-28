#include "encrypted_group_ops.h"

#include "progress_log.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

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

struct PreviewTerm
{
    size_t output_slot = 0;
    double weight = 0.0;
};

size_t output_value_count(const TensorCipherGroup &input, int out_channels, int stride)
{
    return static_cast<size_t>((input.h() / stride) * (input.w() / stride) * out_channels);
}

void validate_conv_args(const TensorCipherGroup &input, int out_channels, int stride, int fh, int fw,
                        const vector<double> &weights, const vector<double> &running_var,
                        const vector<double> &constant_weight)
{
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("group conv preview supports stride 1 or 2 only");
    }
    if (fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("group conv preview expects odd kernel sizes");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c() * out_channels)
    {
        throw invalid_argument("group conv preview weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("group conv preview BN fold vector size is invalid");
    }
}

map<size_t, map<int, vector<PreviewTerm>>> build_preview_plan(
    const TensorCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, size_t preview_count,
    int rotation_sign)
{
    validate_conv_args(input, out_channels, stride, fh, fw, weights, running_var,
                       constant_weight);

    const int out_h = input.h() / stride;
    const int out_w = input.w() / stride;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const size_t slot_count = input.slot_count();
    const size_t total_outputs = output_value_count(input, out_channels, stride);
    const size_t planned_outputs = min(preview_count, total_outputs);
    map<size_t, map<int, vector<PreviewTerm>>> plan;

    for (size_t output_index = 0; output_index < planned_outputs; ++output_index)
    {
        const int oc = static_cast<int>(output_index / static_cast<size_t>(out_h * out_w));
        const size_t spatial = output_index % static_cast<size_t>(out_h * out_w);
        const int oh = static_cast<int>(spatial / static_cast<size_t>(out_w));
        const int ow = static_cast<int>(spatial % static_cast<size_t>(out_w));
        const size_t output_slot = output_index;
        const double folded_scale = constant_weight[oc] / sqrt(running_var[oc] + epsilon);

        for (int ic = 0; ic < input.c(); ++ic)
        {
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const int ih = oh * stride + kh - pad_h;
                    const int iw = ow * stride + kw - pad_w;
                    if (ih < 0 || ih >= input.h() || iw < 0 || iw >= input.w())
                    {
                        continue;
                    }

                    const size_t input_index =
                        static_cast<size_t>(ic * input.h() * input.w() + ih * input.w() + iw);
                    const size_t input_chunk = input_index / slot_count;
                    const size_t input_slot = input_index % slot_count;
                    const size_t weight_index = static_cast<size_t>(
                        fh * fw * input.c() * oc + fh * fw * ic + fw * kh + kw);
                    const double weight = weights[weight_index] * folded_scale;
                    if (weight == 0.0)
                    {
                        continue;
                    }

                    const int step = rotation_sign *
                                     static_cast<int>(static_cast<long long>(input_slot) -
                                                      static_cast<long long>(output_slot));
                    plan[input_chunk][step].push_back(PreviewTerm{output_slot, weight});
                }
            }
        }
    }

    return plan;
}

Ciphertext multiply_by_mask(const Ciphertext &input, const vector<double> &mask,
                            CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(mask, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    Ciphertext output;
    evaluator.multiply_plain(input, plain, output);
    evaluator.rescale_dynamic(output, output, input.scale());
    return output;
}

Ciphertext multiply_by_binary_mask(const Ciphertext &input, const vector<double> &mask,
                                   CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(mask, input.parms_id(), 1.0, plain);
    Ciphertext output;
    evaluator.multiply_plain(input, plain, output);
    output.scale() = input.scale();
    return output;
}

Ciphertext multiply_by_constant_vector(const Ciphertext &input, double coeff,
                                       size_t slot_count, CKKSEncoder &encoder,
                                       EvaluatorCkksBase &evaluator)
{
    vector<double> mask(slot_count, coeff);
    return multiply_by_mask(input, mask, encoder, evaluator);
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

vector<int> conv2d_group_preview_rotation_steps(const TensorCipherGroup &input, int out_channels,
                                                int stride, int fh, int fw,
                                                size_t preview_count, int rotation_sign)
{
    vector<double> dummy_weights(static_cast<size_t>(fh * fw * input.c() * out_channels), 1.0);
    vector<double> dummy_running_var(static_cast<size_t>(out_channels), 1.0);
    vector<double> dummy_constant_weight(static_cast<size_t>(out_channels), 1.0);
    map<size_t, map<int, vector<PreviewTerm>>> plan =
        build_preview_plan(input, out_channels, stride, fh, fw, dummy_weights, dummy_running_var,
                           dummy_constant_weight, 0.0, preview_count, rotation_sign);

    set<int> steps;
    for (const auto &chunk_entry : plan)
    {
        for (const auto &rotation_entry : chunk_entry.second)
        {
            if (rotation_entry.first != 0)
            {
                steps.insert(rotation_entry.first);
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

vector<double> encrypted_conv2d_group_preview(
    const TensorCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, size_t preview_count,
    PoseidonRuntime &runtime, int rotation_sign)
{
    map<size_t, map<int, vector<PreviewTerm>>> plan =
        build_preview_plan(input, out_channels, stride, fh, fw, weights, running_var,
                           constant_weight, epsilon, preview_count, rotation_sign);
    const size_t slot_count = input.slot_count();
    const size_t total_outputs = output_value_count(input, out_channels, stride);
    const size_t planned_outputs = min(preview_count, total_outputs);

    Ciphertext sum;
    bool has_sum = false;
    for (const auto &chunk_entry : plan)
    {
        const size_t input_chunk = chunk_entry.first;
        if (input_chunk >= input.chunks().size())
        {
            throw out_of_range("group conv preview input chunk is out of range");
        }

        for (const auto &rotation_entry : chunk_entry.second)
        {
            Ciphertext rotated;
            if (rotation_entry.first == 0)
            {
                rotated = input.chunks().at(input_chunk);
            }
            else
            {
                runtime.evaluator->rotate(input.chunks().at(input_chunk), rotated,
                                          rotation_entry.first, runtime.galois_keys);
            }

            vector<double> mask(slot_count, 0.0);
            for (const PreviewTerm &term : rotation_entry.second)
            {
                mask[term.output_slot] += term.weight;
            }
            Ciphertext term_cipher = multiply_by_mask(rotated, mask, runtime.encoder,
                                                      *runtime.evaluator);
            if (!has_sum)
            {
                sum = std::move(term_cipher);
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, term_cipher, runtime.encoder, *runtime.evaluator);
            }
        }
    }

    if (!has_sum)
    {
        throw runtime_error("group conv preview produced no encrypted terms");
    }

    Plaintext plain;
    runtime.decryptor.decrypt(sum, plain);
    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);
    vector<double> result(planned_outputs, 0.0);
    for (size_t i = 0; i < planned_outputs; ++i)
    {
        result[i] = decoded[i].real();
    }
    return result;
}

vector<int> slot_sum_rotation_steps(const TensorCipherGroup &input)
{
    vector<int> steps;
    for (size_t step = 1; step < input.slot_count(); step <<= 1)
    {
        steps.push_back(static_cast<int>(step));
    }
    return steps;
}

double encrypted_conv2d_group_single_output(
    const TensorCipherGroup &input, size_t output_index, int out_channels, int stride, int fh,
    int fw, const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    validate_conv_args(input, out_channels, stride, fh, fw, weights, running_var,
                       constant_weight);

    const int out_h = input.h() / stride;
    const int out_w = input.w() / stride;
    if (output_index >= output_value_count(input, out_channels, stride))
    {
        throw out_of_range("single output conv index is out of range");
    }

    const int oc = static_cast<int>(output_index / static_cast<size_t>(out_h * out_w));
    const size_t spatial = output_index % static_cast<size_t>(out_h * out_w);
    const int oh = static_cast<int>(spatial / static_cast<size_t>(out_w));
    const int ow = static_cast<int>(spatial % static_cast<size_t>(out_w));
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const size_t slot_count = input.slot_count();
    const double folded_scale = constant_weight[oc] / sqrt(running_var[oc] + epsilon);

    vector<vector<double>> masks(input.chunks().size(), vector<double>(slot_count, 0.0));
    for (int ic = 0; ic < input.c(); ++ic)
    {
        for (int kh = 0; kh < fh; ++kh)
        {
            for (int kw = 0; kw < fw; ++kw)
            {
                const int ih = oh * stride + kh - pad_h;
                const int iw = ow * stride + kw - pad_w;
                if (ih < 0 || ih >= input.h() || iw < 0 || iw >= input.w())
                {
                    continue;
                }

                const size_t input_index =
                    static_cast<size_t>(ic * input.h() * input.w() + ih * input.w() + iw);
                const size_t input_chunk = input_index / slot_count;
                const size_t input_slot = input_index % slot_count;
                const size_t weight_index = static_cast<size_t>(
                    fh * fw * input.c() * oc + fh * fw * ic + fw * kh + kw);
                masks.at(input_chunk).at(input_slot) += weights[weight_index] * folded_scale;
            }
        }
    }

    Ciphertext sum;
    bool has_sum = false;
    for (size_t chunk = 0; chunk < input.chunks().size(); ++chunk)
    {
        bool has_nonzero = false;
        for (double value : masks[chunk])
        {
            if (value != 0.0)
            {
                has_nonzero = true;
                break;
            }
        }
        if (!has_nonzero)
        {
            continue;
        }

        Ciphertext term = multiply_by_mask(input.chunks().at(chunk), masks[chunk], runtime.encoder,
                                           *runtime.evaluator);
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
    if (!has_sum)
    {
        throw runtime_error("single output conv produced no encrypted terms");
    }

    for (int step : slot_sum_rotation_steps(input))
    {
        Ciphertext rotated;
        runtime.evaluator->rotate(sum, rotated, step, runtime.galois_keys);
        add_assign_dynamic(sum, rotated, runtime.encoder, *runtime.evaluator);
    }

    Plaintext plain;
    runtime.decryptor.decrypt(sum, plain);
    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);
    return decoded.at(0).real();
}

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

Ciphertext encrypted_conv2d_im2col_output_channel_cipher(
    const Im2ColCipherGroup &im2col, int output_channel, int out_channels,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    if (output_channel < 0 || output_channel >= out_channels)
    {
        throw out_of_range("im2col output channel is out of range");
    }
    if (static_cast<int>(weights.size()) !=
        im2col.fh * im2col.fw * im2col.input_c * out_channels)
    {
        throw invalid_argument("im2col conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("im2col BN fold vector size is invalid");
    }

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
                    message << "im2col channel multiply failed: output_channel="
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

    return sum;
}

vector<double> encrypted_conv2d_im2col_output_channel(
    const Im2ColCipherGroup &im2col, int output_channel, int out_channels,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    Ciphertext sum = encrypted_conv2d_im2col_output_channel_cipher(
        im2col, output_channel, out_channels, weights, running_var, constant_weight, epsilon,
        runtime);

    Plaintext plain;
    runtime.decryptor.decrypt(sum, plain);
    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);
    vector<double> output(im2col.spatial_count, 0.0);
    for (size_t i = 0; i < im2col.spatial_count; ++i)
    {
        output[i] = decoded.at(i).real();
    }
    return output;
}

ChannelCipherGroup encrypted_conv2d_im2col_all_channels(
    const Im2ColCipherGroup &im2col, int out_channels, const vector<double> &weights,
    const vector<double> &running_var, const vector<double> &constant_weight, double epsilon,
    PoseidonRuntime &runtime)
{
    ChannelCipherGroup group;
    group.h = im2col.out_h;
    group.w = im2col.out_w;
    group.c = out_channels;
    group.spatial_count = im2col.spatial_count;
    group.slot_count = im2col.slot_count;
    group.channels.reserve(static_cast<size_t>(out_channels));

    for (int output_channel = 0; output_channel < out_channels; ++output_channel)
    {
        if (output_channel % 8 == 0)
        {
            resnet18_progress_log() << "conv im2col encrypted channel progress: " << output_channel << "/"
                 << out_channels << endl;
        }

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
        group.channels.emplace_back(std::move(sum));
    }

    resnet18_progress_log() << "conv im2col encrypted channel progress: " << out_channels << "/"
         << out_channels << endl;
    log_channel_group_cipher_state("conv_im2col_all_channels output", group, runtime);

    return group;
}

ChannelCipherGroup encrypted_channel_batch_norm(
    const ChannelCipherGroup &input, const vector<double> &bias,
    const vector<double> &running_mean, const vector<double> &running_var,
    const vector<double> &weight, double epsilon, double boundary, PoseidonRuntime &runtime)
{
    if (static_cast<int>(bias.size()) != input.c ||
        static_cast<int>(running_mean.size()) != input.c ||
        static_cast<int>(running_var.size()) != input.c ||
        static_cast<int>(weight.size()) != input.c)
    {
        throw invalid_argument("channel batch norm vector sizes are invalid");
    }

    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = input.c;
    output.spatial_count = input.spatial_count;
    output.slot_count = input.slot_count;
    output.channels.reserve(input.channels.size());

    for (int channel = 0; channel < input.c; ++channel)
    {
        const double offset =
            (bias[channel] - running_mean[channel] * weight[channel] /
                                 sqrt(running_var[channel] + epsilon)) /
            boundary;

        Ciphertext adjusted;
        if (coefficient_encodes_to_zero(input.channels.at(static_cast<size_t>(channel)), offset,
                                        runtime.encoder))
        {
            adjusted = input.channels.at(static_cast<size_t>(channel));
        }
        else
        {
            runtime.evaluator->add_const(input.channels.at(static_cast<size_t>(channel)), offset,
                                         adjusted, runtime.encoder);
        }
        output.channels.emplace_back(std::move(adjusted));
    }

    log_channel_group_cipher_state("batch_norm output", output, runtime);
    return output;
}

ChannelCipherGroup encrypted_channel_batch_norm_sparse_stride(
    const ChannelCipherGroup &input, const vector<double> &bias,
    const vector<double> &running_mean, const vector<double> &running_var,
    const vector<double> &weight, double epsilon, double boundary, int dense_h,
    int dense_w, int stride, PoseidonRuntime &runtime)
{
    if (stride <= 0 || dense_h <= 0 || dense_w <= 0)
    {
        throw invalid_argument("sparse stride batch norm shape is invalid");
    }
    if (static_cast<int>(bias.size()) != input.c ||
        static_cast<int>(running_mean.size()) != input.c ||
        static_cast<int>(running_var.size()) != input.c ||
        static_cast<int>(weight.size()) != input.c)
    {
        throw invalid_argument("sparse stride batch norm vector sizes are invalid");
    }
    if (input.channels.size() != static_cast<size_t>(input.c))
    {
        throw invalid_argument("sparse stride batch norm channel count mismatch");
    }

    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = input.c;
    output.spatial_count = input.spatial_count;
    output.slot_count = input.slot_count;
    output.channels.reserve(input.channels.size());

    for (int channel = 0; channel < input.c; ++channel)
    {
        const double offset =
            (bias[channel] - running_mean[channel] * weight[channel] /
                                 sqrt(running_var[channel] + epsilon)) /
            boundary;

        if (coefficient_encodes_to_zero(input.channels.at(static_cast<size_t>(channel)), offset,
                                        runtime.encoder))
        {
            output.channels.emplace_back(input.channels.at(static_cast<size_t>(channel)));
            continue;
        }

        vector<double> offsets(output.slot_count, 0.0);
        for (int oh = 0; oh < dense_h; ++oh)
        {
            for (int ow = 0; ow < dense_w; ++ow)
            {
                const int row = oh * stride;
                const int col = ow * stride;
                if (row >= input.h || col >= input.w)
                {
                    throw invalid_argument("sparse stride batch norm slot is out of range");
                }
                offsets[static_cast<size_t>(row * input.w + col)] = offset;
            }
        }

        Plaintext plain;
        runtime.encoder.encode(offsets,
                               input.channels.at(static_cast<size_t>(channel)).parms_id(),
                               input.channels.at(static_cast<size_t>(channel)).scale(), plain);
        Ciphertext adjusted;
        runtime.evaluator->add_plain(input.channels.at(static_cast<size_t>(channel)), plain,
                                     adjusted);
        output.channels.emplace_back(std::move(adjusted));
    }

    log_channel_group_cipher_state("sparse_stride_batch_norm output", output, runtime);
    return output;
}

ChannelCipherGroup encrypted_channel_add(const ChannelCipherGroup &lhs,
                                          const ChannelCipherGroup &rhs,
                                          PoseidonRuntime &runtime)
{
    if (lhs.h != rhs.h || lhs.w != rhs.w || lhs.c != rhs.c ||
        lhs.spatial_count != rhs.spatial_count)
    {
        throw invalid_argument("channel add shape mismatch");
    }
    if (lhs.channels.size() != static_cast<size_t>(lhs.c) ||
        rhs.channels.size() != static_cast<size_t>(rhs.c))
    {
        throw invalid_argument("channel add channel count mismatch");
    }

    ChannelCipherGroup output;
    output.h = lhs.h;
    output.w = lhs.w;
    output.c = lhs.c;
    output.spatial_count = lhs.spatial_count;
    output.slot_count = lhs.slot_count;
    output.channels.reserve(lhs.channels.size());

    for (int channel = 0; channel < lhs.c; ++channel)
    {
        Ciphertext lhs_cipher = lhs.channels.at(static_cast<size_t>(channel));
        Ciphertext rhs_cipher = rhs.channels.at(static_cast<size_t>(channel));
        const size_t lhs_chain = cipher_chain_index(runtime, lhs_cipher);
        const size_t rhs_chain = cipher_chain_index(runtime, rhs_cipher);
        if (lhs_chain > rhs_chain)
        {
            runtime.evaluator->drop_modulus(lhs_cipher, lhs_cipher, rhs_cipher.parms_id());
        }
        else if (rhs_chain > lhs_chain)
        {
            runtime.evaluator->drop_modulus(rhs_cipher, rhs_cipher, lhs_cipher.parms_id());
        }

        Ciphertext sum;
        runtime.evaluator->add_dynamic(lhs_cipher, rhs_cipher, sum, runtime.encoder);
        output.channels.emplace_back(std::move(sum));
    }

    log_channel_group_cipher_state("channel_add output", output, runtime);
    return output;
}

vector<int> maxpool_channel_preview_rotation_steps(int input_h, int input_w, int kernel,
                                                   int stride, int padding,
                                                   size_t preview_count)
{
    if (input_h <= 0 || input_w <= 0 || kernel <= 0 || stride <= 0 || padding < 0)
    {
        throw invalid_argument("maxpool preview parameters are invalid");
    }

    const int out_h = (input_h + 2 * padding - kernel) / stride + 1;
    const int out_w = (input_w + 2 * padding - kernel) / stride + 1;
    const size_t output_count = static_cast<size_t>(out_h * out_w);
    const size_t planned_outputs = min(preview_count, output_count);
    set<int> steps;

    for (int kh = 0; kh < kernel; ++kh)
    {
        for (int kw = 0; kw < kernel; ++kw)
        {
            for (size_t output_index = 0; output_index < planned_outputs; ++output_index)
            {
                const int oh = static_cast<int>(output_index / static_cast<size_t>(out_w));
                const int ow = static_cast<int>(output_index % static_cast<size_t>(out_w));
                const int ih = oh * stride + kh - padding;
                const int iw = ow * stride + kw - padding;
                if (ih < 0 || ih >= input_h || iw < 0 || iw >= input_w)
                {
                    continue;
                }

                const int input_slot = ih * input_w + iw;
                const int output_slot = static_cast<int>(output_index);
                const int step = input_slot - output_slot;
                if (step != 0)
                {
                    steps.insert(step);
                }
            }
        }
    }

    return vector<int>(steps.begin(), steps.end());
}

Ciphertext encrypted_maxpool_candidate_preview(
    const Ciphertext &input, int input_h, int input_w, int kernel, int stride, int padding,
    int pick_row, int pick_col, size_t preview_count, PoseidonRuntime &runtime)
{
    if (input_h <= 0 || input_w <= 0 || kernel <= 0 || stride <= 0 || padding < 0)
    {
        throw invalid_argument("maxpool preview parameters are invalid");
    }
    if (pick_row < 0 || pick_row >= kernel || pick_col < 0 || pick_col >= kernel)
    {
        throw invalid_argument("maxpool preview pick position is invalid");
    }

    const int out_h = (input_h + 2 * padding - kernel) / stride + 1;
    const int out_w = (input_w + 2 * padding - kernel) / stride + 1;
    const size_t output_count = static_cast<size_t>(out_h * out_w);
    const size_t planned_outputs = min(preview_count, output_count);
    const size_t slot_count = runtime.encoder.slot_count();
    if (static_cast<size_t>(input_h * input_w) > slot_count)
    {
        throw invalid_argument("maxpool preview input channel does not fit in one ciphertext");
    }

    map<int, vector<size_t>> output_slots_by_step;
    for (size_t output_index = 0; output_index < planned_outputs; ++output_index)
    {
        const int oh = static_cast<int>(output_index / static_cast<size_t>(out_w));
        const int ow = static_cast<int>(output_index % static_cast<size_t>(out_w));
        const int ih = oh * stride + pick_row - padding;
        const int iw = ow * stride + pick_col - padding;
        if (ih < 0 || ih >= input_h || iw < 0 || iw >= input_w)
        {
            continue;
        }

        const int input_slot = ih * input_w + iw;
        const int output_slot = static_cast<int>(output_index);
        output_slots_by_step[input_slot - output_slot].push_back(output_index);
    }

    Ciphertext sum;
    bool has_sum = false;
    for (const auto &entry : output_slots_by_step)
    {
        Ciphertext rotated;
        if (entry.first == 0)
        {
            rotated = input;
        }
        else
        {
            runtime.evaluator->rotate(input, rotated, entry.first, runtime.galois_keys);
        }

        vector<double> mask(slot_count, 0.0);
        for (size_t output_slot : entry.second)
        {
            mask[output_slot] = 1.0;
        }

        Ciphertext term = multiply_by_binary_mask(rotated, mask, runtime.encoder,
                                                  *runtime.evaluator);
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

    if (!has_sum)
    {
        vector<complex<double>> zeros(slot_count, {0.0, 0.0});
        Plaintext plain;
        runtime.encoder.encode(zeros, input.parms_id(), 1.0, plain);
        runtime.encryptor.encrypt(plain, sum);
        sum.scale() = input.scale();
    }
    return sum;
}

vector<int> maxpool_channel_sparse_rotation_steps(int input_w, int kernel, int padding)
{
    if (input_w <= 0 || kernel <= 0 || padding < 0)
    {
        throw invalid_argument("maxpool sparse rotation parameters are invalid");
    }

    set<int> steps;
    for (int kh = 0; kh < kernel; ++kh)
    {
        for (int kw = 0; kw < kernel; ++kw)
        {
            const int step = (kh - padding) * input_w + (kw - padding);
            if (step != 0)
            {
                steps.insert(step);
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

Ciphertext encrypted_maxpool_candidate_sparse(
    const Ciphertext &input, int input_h, int input_w, int kernel, int stride, int padding,
    int pick_row, int pick_col, PoseidonRuntime &runtime)
{
    if (input_h <= 0 || input_w <= 0 || kernel <= 0 || stride <= 0 || padding < 0)
    {
        throw invalid_argument("maxpool sparse parameters are invalid");
    }
    if (pick_row < 0 || pick_row >= kernel || pick_col < 0 || pick_col >= kernel)
    {
        throw invalid_argument("maxpool sparse pick position is invalid");
    }

    const int out_h = (input_h + 2 * padding - kernel) / stride + 1;
    const int out_w = (input_w + 2 * padding - kernel) / stride + 1;
    const size_t slot_count = runtime.encoder.slot_count();
    if (static_cast<size_t>(input_h * input_w) > slot_count)
    {
        throw invalid_argument("maxpool sparse input channel does not fit in one ciphertext");
    }

    const int step = (pick_row - padding) * input_w + (pick_col - padding);
    Ciphertext rotated;
    if (step == 0)
    {
        rotated = input;
    }
    else
    {
        runtime.evaluator->rotate(input, rotated, step, runtime.galois_keys);
    }

    vector<double> mask(slot_count, 0.0);
    for (int oh = 0; oh < out_h; ++oh)
    {
        for (int ow = 0; ow < out_w; ++ow)
        {
            const int ih = oh * stride + pick_row - padding;
            const int iw = ow * stride + pick_col - padding;
            if (ih < 0 || ih >= input_h || iw < 0 || iw >= input_w)
            {
                continue;
            }

            const size_t output_slot =
                static_cast<size_t>((oh * stride) * input_w + ow * stride);
            mask[output_slot] = 1.0;
        }
    }

    return multiply_by_binary_mask(rotated, mask, runtime.encoder, *runtime.evaluator);
}

vector<int> dense_conv2d_channel_rotation_steps(int input_w, int fh, int fw)
{
    if (input_w <= 0 || fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("dense conv rotation parameters are invalid");
    }

    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    set<int> steps;
    for (int kh = 0; kh < fh; ++kh)
    {
        for (int kw = 0; kw < fw; ++kw)
        {
            const int step = (kh - pad_h) * input_w + (kw - pad_w);
            if (step != 0)
            {
                steps.insert(step);
            }
        }
    }
    return vector<int>(steps.begin(), steps.end());
}

Ciphertext encrypted_channel_conv2d_output_channel_cipher(
    const ChannelCipherGroup &input, int output_channel, int out_channels, int stride,
    int fh, int fw, const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    if (stride != 1)
    {
        throw invalid_argument("dense channel conv currently supports stride 1 only");
    }
    if (output_channel < 0 || output_channel >= out_channels)
    {
        throw out_of_range("dense channel conv output channel is out of range");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("dense channel conv expects odd kernel sizes");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("dense channel conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("dense channel conv BN fold vector size is invalid");
    }
    if (input.channels.size() != static_cast<size_t>(input.c))
    {
        throw invalid_argument("dense channel conv channel count mismatch");
    }

    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const size_t slot_count = runtime.encoder.slot_count();
    if (input.spatial_count > slot_count)
    {
        throw invalid_argument("dense channel conv input spatial count exceeds slot count");
    }

    Ciphertext sum;
    bool has_sum = false;
    const double folded_scale =
        constant_weight[output_channel] / sqrt(running_var[output_channel] + epsilon);

    for (int ic = 0; ic < input.c; ++ic)
    {
        for (int kh = 0; kh < fh; ++kh)
        {
            for (int kw = 0; kw < fw; ++kw)
            {
                const size_t weight_index = static_cast<size_t>(
                    fh * fw * input.c * output_channel + fh * fw * ic + fw * kh + kw);
                const double coeff = weights[weight_index] * folded_scale;
                if (coeff == 0.0 ||
                    coefficient_encodes_to_zero(input.channels.at(static_cast<size_t>(ic)),
                                                coeff, runtime.encoder))
                {
                    continue;
                }

                const int step = (kh - pad_h) * input.w + (kw - pad_w);
                Ciphertext rotated;
                if (step == 0)
                {
                    rotated = input.channels.at(static_cast<size_t>(ic));
                }
                else
                {
                    runtime.evaluator->rotate(input.channels.at(static_cast<size_t>(ic)),
                                              rotated, step, runtime.galois_keys);
                }

                vector<double> mask(slot_count, 0.0);
                for (int oh = 0; oh < input.h; ++oh)
                {
                    for (int ow = 0; ow < input.w; ++ow)
                    {
                        const int ih = oh + kh - pad_h;
                        const int iw = ow + kw - pad_w;
                        if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                        {
                            continue;
                        }
                        mask[static_cast<size_t>(oh * input.w + ow)] = 1.0;
                    }
                }

                Ciphertext masked =
                    multiply_by_binary_mask(rotated, mask, runtime.encoder, *runtime.evaluator);
                Ciphertext term = multiply_by_constant_scalar(masked, coeff, runtime.encoder,
                                                              *runtime.evaluator);
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
        throw runtime_error("dense channel conv output channel produced no encrypted terms");
    }
    return sum;
}

ChannelCipherGroup encrypted_channel_conv2d_all_channels(
    const ChannelCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    if (stride != 1)
    {
        throw invalid_argument("dense channel conv all-channels currently supports stride 1 only");
    }

    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = out_channels;
    output.spatial_count = static_cast<size_t>(output.h * output.w);
    output.slot_count = runtime.encoder.slot_count();
    output.channels.reserve(static_cast<size_t>(out_channels));

    for (int output_channel = 0; output_channel < out_channels; ++output_channel)
    {
        if (output_channel % 8 == 0)
        {
            resnet18_progress_log() << "dense conv encrypted channel progress: " << output_channel << "/"
                 << out_channels << endl;
        }
        output.channels.emplace_back(encrypted_channel_conv2d_output_channel_cipher(
            input, output_channel, out_channels, stride, fh, fw, weights, running_var,
            constant_weight, epsilon, runtime));
    }
    resnet18_progress_log() << "dense conv encrypted channel progress: " << out_channels << "/"
         << out_channels << endl;
    log_channel_group_cipher_state("dense_conv2d_all_channels output", output, runtime);

    return output;
}

ChannelCipherGroup encrypted_channel_conv2d_sparse_stride_all_channels(
    const ChannelCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const vector<double> &weights, const vector<double> &running_var,
    const vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime)
{
    if (stride <= 1)
    {
        throw invalid_argument("sparse stride conv expects stride greater than 1");
    }
    if (fh <= 0 || fw <= 0 || fh % 2 == 0 || fw % 2 == 0)
    {
        throw invalid_argument("sparse stride conv expects odd kernel sizes");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("sparse stride conv weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("sparse stride conv BN fold vector size is invalid");
    }
    if (input.channels.size() != static_cast<size_t>(input.c))
    {
        throw invalid_argument("sparse stride conv channel count mismatch");
    }

    const int out_h = input.h / stride;
    const int out_w = input.w / stride;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    const size_t slot_count = runtime.encoder.slot_count();
    if (input.spatial_count > slot_count)
    {
        throw invalid_argument("sparse stride conv input spatial count exceeds slot count");
    }

    ChannelCipherGroup output;
    output.h = input.h;
    output.w = input.w;
    output.c = out_channels;
    output.spatial_count = input.spatial_count;
    output.slot_count = input.slot_count;
    output.channels.reserve(static_cast<size_t>(out_channels));

    for (int output_channel = 0; output_channel < out_channels; ++output_channel)
    {
        if (output_channel % 8 == 0)
        {
            resnet18_progress_log() << "sparse stride conv encrypted channel progress: " << output_channel
                 << "/" << out_channels << endl;
        }

        Ciphertext sum;
        bool has_sum = false;
        const double folded_scale =
            constant_weight[output_channel] / sqrt(running_var[output_channel] + epsilon);

        for (int ic = 0; ic < input.c; ++ic)
        {
            for (int kh = 0; kh < fh; ++kh)
            {
                for (int kw = 0; kw < fw; ++kw)
                {
                    const size_t weight_index = static_cast<size_t>(
                        fh * fw * input.c * output_channel + fh * fw * ic + fw * kh + kw);
                    const double coeff = weights[weight_index] * folded_scale;
                    if (coeff == 0.0 ||
                        coefficient_encodes_to_zero(input.channels.at(static_cast<size_t>(ic)),
                                                    coeff, runtime.encoder))
                    {
                        continue;
                    }

                    const int step = (kh - pad_h) * input.w + (kw - pad_w);
                    Ciphertext rotated;
                    if (step == 0)
                    {
                        rotated = input.channels.at(static_cast<size_t>(ic));
                    }
                    else
                    {
                        runtime.evaluator->rotate(input.channels.at(static_cast<size_t>(ic)),
                                                  rotated, step, runtime.galois_keys);
                    }

                    vector<double> mask(slot_count, 0.0);
                    for (int oh = 0; oh < out_h; ++oh)
                    {
                        for (int ow = 0; ow < out_w; ++ow)
                        {
                            const int ih = oh * stride + kh - pad_h;
                            const int iw = ow * stride + kw - pad_w;
                            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                            {
                                continue;
                            }
                            const size_t output_slot =
                                static_cast<size_t>((oh * stride) * input.w + ow * stride);
                            mask[output_slot] = 1.0;
                        }
                    }

                    Ciphertext masked = multiply_by_binary_mask(rotated, mask, runtime.encoder,
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
                        add_assign_dynamic(sum, term, runtime.encoder, *runtime.evaluator);
                    }
                }
            }
        }

        if (!has_sum)
        {
            throw runtime_error("sparse stride conv output channel produced no encrypted terms");
        }
        output.channels.emplace_back(std::move(sum));
    }

    resnet18_progress_log() << "sparse stride conv encrypted channel progress: " << out_channels << "/"
         << out_channels << endl;
    log_channel_group_cipher_state("sparse_stride_conv2d_all_channels output", output, runtime);

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
        for (size_t i = 0; i < group.spatial_count; ++i)
        {
            values.emplace_back(decoded.at(i).real());
        }
    }
    return values;
}
