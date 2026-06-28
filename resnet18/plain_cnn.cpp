#include "plain_cnn.h"

#include "infer_config.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <utility>

using namespace std;

PlainTensor::PlainTensor(int height, int width, int channels)
    : h(height), w(width), c(channels), values(static_cast<size_t>(height * width * channels), 0.0)
{
}

PlainTensor::PlainTensor(int height, int width, int channels, vector<double> data)
    : h(height), w(width), c(channels), values(std::move(data))
{
    if (values.size() != static_cast<size_t>(h * w * c))
    {
        throw invalid_argument("plain tensor data size does not match shape");
    }
}

double &PlainTensor::at(int channel, int row, int col)
{
    return values[static_cast<size_t>(channel * h * w + row * w + col)];
}

double PlainTensor::at(int channel, int row, int col) const
{
    return values[static_cast<size_t>(channel * h * w + row * w + col)];
}

PlainTensor plain_input_tensor_from_image_slots(const vector<double> &image_slots)
{
    const size_t image_values = static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth *
                                                   kImageNetInputChannels);
    if (image_slots.size() < image_values)
    {
        throw invalid_argument("image slot vector is too small for ImageNet input");
    }

    vector<double> values(image_slots.begin(), image_slots.begin() + static_cast<long>(image_values));
    return PlainTensor(kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels,
                       std::move(values));
}

PlainTensor plain_convolution(const PlainTensor &input, int out_channels, int stride, int fh, int fw,
                              const vector<double> &weights,
                              const vector<double> &running_var,
                              const vector<double> &constant_weight, double epsilon)
{
    if (stride != 1 && stride != 2)
    {
        throw invalid_argument("plain convolution supports stride 1 or 2 only");
    }
    if (input.c <= 0 || input.h <= 0 || input.w <= 0)
    {
        throw invalid_argument("plain convolution input shape is invalid");
    }
    if (static_cast<int>(weights.size()) != fh * fw * input.c * out_channels)
    {
        throw invalid_argument("plain convolution weight size is invalid");
    }
    if (static_cast<int>(running_var.size()) != out_channels ||
        static_cast<int>(constant_weight.size()) != out_channels)
    {
        throw invalid_argument("plain convolution folded batch norm vectors are invalid");
    }

    const int out_h = input.h / stride;
    const int out_w = input.w / stride;
    const int pad_h = fh / 2;
    const int pad_w = fw / 2;
    PlainTensor output(out_h, out_w, out_channels);

    for (int oc = 0; oc < out_channels; ++oc)
    {
        const double folded_scale = constant_weight[oc] / sqrt(running_var[oc] + epsilon);
        for (int oh = 0; oh < out_h; ++oh)
        {
            for (int ow = 0; ow < out_w; ++ow)
            {
                double sum = 0.0;
                for (int ic = 0; ic < input.c; ++ic)
                {
                    for (int kh = 0; kh < fh; ++kh)
                    {
                        for (int kw = 0; kw < fw; ++kw)
                        {
                            const int ih = oh * stride + kh - pad_h;
                            const int iw = ow * stride + kw - pad_w;
                            if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                            {
                                continue;
                            }

                            const size_t weight_index = static_cast<size_t>(
                                fh * fw * input.c * oc + fh * fw * ic + fw * kh + kw);
                            sum += input.at(ic, ih, iw) * weights[weight_index];
                        }
                    }
                }
                output.at(oc, oh, ow) = sum * folded_scale;
            }
        }
    }

    return output;
}

PlainTensor plain_batch_norm(const PlainTensor &input, const vector<double> &bias,
                             const vector<double> &running_mean, const vector<double> &running_var,
                             const vector<double> &weight, double epsilon, double B)
{
    if (static_cast<int>(bias.size()) != input.c || static_cast<int>(running_mean.size()) != input.c ||
        static_cast<int>(running_var.size()) != input.c || static_cast<int>(weight.size()) != input.c)
    {
        throw invalid_argument("plain batch norm vector sizes are invalid");
    }

    PlainTensor output = input;
    for (int channel = 0; channel < input.c; ++channel)
    {
        const double offset =
            (bias[channel] - running_mean[channel] * weight[channel] /
                                 sqrt(running_var[channel] + epsilon)) /
            B;
        for (int row = 0; row < input.h; ++row)
        {
            for (int col = 0; col < input.w; ++col)
            {
                output.at(channel, row, col) += offset;
            }
        }
    }
    return output;
}

PlainTensor plain_relu_reference(const PlainTensor &input)
{
    PlainTensor output = input;
    for (size_t idx = 0; idx < input.values.size(); ++idx)
    {
        output.values[idx] = max(0.0, input.values[idx]);
    }
    return output;
}

PlainTensor plain_add(const PlainTensor &lhs, const PlainTensor &rhs)
{
    if (lhs.h != rhs.h || lhs.w != rhs.w || lhs.c != rhs.c)
    {
        throw invalid_argument("plain add shape mismatch");
    }

    PlainTensor output = lhs;
    for (size_t i = 0; i < output.values.size(); ++i)
    {
        output.values[i] += rhs.values[i];
    }
    return output;
}

PlainTensor plain_average_pool2d(const PlainTensor &input, int kernel, int stride, int padding)
{
    if (kernel <= 0 || stride <= 0 || padding < 0)
    {
        throw invalid_argument("plain average pool parameters are invalid");
    }

    const int out_h = (input.h + 2 * padding - kernel) / stride + 1;
    const int out_w = (input.w + 2 * padding - kernel) / stride + 1;
    PlainTensor output(out_h, out_w, input.c);
    const double scale = 1.0 / static_cast<double>(kernel * kernel);

    for (int channel = 0; channel < input.c; ++channel)
    {
        for (int oh = 0; oh < out_h; ++oh)
        {
            for (int ow = 0; ow < out_w; ++ow)
            {
                double sum = 0.0;
                for (int kh = 0; kh < kernel; ++kh)
                {
                    for (int kw = 0; kw < kernel; ++kw)
                    {
                        const int ih = oh * stride + kh - padding;
                        const int iw = ow * stride + kw - padding;
                        if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                        {
                            continue;
                        }
                        sum += input.at(channel, ih, iw);
                    }
                }
                output.at(channel, oh, ow) = sum * scale;
            }
        }
    }
    return output;
}

PlainTensor plain_max_pool2d(const PlainTensor &input, int kernel, int stride, int padding)
{
    if (kernel <= 0 || stride <= 0 || padding < 0)
    {
        throw invalid_argument("plain max pool parameters are invalid");
    }

    const int out_h = (input.h + 2 * padding - kernel) / stride + 1;
    const int out_w = (input.w + 2 * padding - kernel) / stride + 1;
    PlainTensor output(out_h, out_w, input.c);

    for (int channel = 0; channel < input.c; ++channel)
    {
        for (int oh = 0; oh < out_h; ++oh)
        {
            for (int ow = 0; ow < out_w; ++ow)
            {
                double max_value = -numeric_limits<double>::infinity();
                bool has_value = false;
                for (int kh = 0; kh < kernel; ++kh)
                {
                    for (int kw = 0; kw < kernel; ++kw)
                    {
                        const int ih = oh * stride + kh - padding;
                        const int iw = ow * stride + kw - padding;
                        if (ih < 0 || ih >= input.h || iw < 0 || iw >= input.w)
                        {
                            continue;
                        }
                        max_value = max(max_value, input.at(channel, ih, iw));
                        has_value = true;
                    }
                }
                if (!has_value)
                {
                    throw invalid_argument("plain max pool produced an empty pooling window");
                }
                output.at(channel, oh, ow) = max_value;
            }
        }
    }
    return output;
}

PlainTensor plain_downsample_shortcut(const PlainTensor &input)
{
    if (input.h % 2 != 0 || input.w % 2 != 0)
    {
        throw invalid_argument("plain downsample expects even spatial shape");
    }

    const int out_h = input.h / 2;
    const int out_w = input.w / 2;
    const int out_c = input.c * 2;
    PlainTensor output(out_h, out_w, out_c);

    const int channel_offset = input.c / 2;
    for (int ic = 0; ic < input.c; ++ic)
    {
        const int oc = ic + channel_offset;
        for (int oh = 0; oh < out_h; ++oh)
        {
            for (int ow = 0; ow < out_w; ++ow)
            {
                output.at(oc, oh, ow) = input.at(ic, oh * 2, ow * 2);
            }
        }
    }

    return output;
}

PlainTensor plain_average_pool(const PlainTensor &input, double B)
{
    PlainTensor output(1, 1, input.c);
    const double scale = B / static_cast<double>(input.h * input.w);
    for (int channel = 0; channel < input.c; ++channel)
    {
        double sum = 0.0;
        for (int row = 0; row < input.h; ++row)
        {
            for (int col = 0; col < input.w; ++col)
            {
                sum += input.at(channel, row, col);
            }
        }
        output.at(channel, 0, 0) = sum * scale;
    }
    return output;
}

vector<double> plain_fully_connected(const PlainTensor &input, const vector<double> &matrix,
                                     const vector<double> &bias, int q, int r)
{
    if (input.h != 1 || input.w != 1 || input.c != r)
    {
        throw invalid_argument("plain fully connected expects flattened channel vector input");
    }
    if (static_cast<int>(matrix.size()) != q * r || static_cast<int>(bias.size()) != q)
    {
        throw invalid_argument("plain fully connected parameter sizes are invalid");
    }

    vector<double> logits(static_cast<size_t>(q), 0.0);
    for (int i = 0; i < q; ++i)
    {
        double sum = bias[i];
        for (int j = 0; j < r; ++j)
        {
            sum += matrix[static_cast<size_t>(i * r + j)] * input.at(j, 0, 0);
        }
        logits[static_cast<size_t>(i)] = sum;
    }
    return logits;
}

void log_plain_tensor(const string &label, const PlainTensor &tensor, ostream &output,
                      size_t preview_count)
{
    output << "  " << label << ": shape(h=" << tensor.h << ",w=" << tensor.w << ",c=" << tensor.c
           << ")\n";
    output << "  plain preview:";
    const size_t count = min(preview_count, tensor.values.size());
    for (size_t i = 0; i < count; ++i)
    {
        output << ' ' << tensor.values[i];
    }
    output << '\n';
}
