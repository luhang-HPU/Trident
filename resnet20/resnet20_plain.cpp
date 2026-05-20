#include "resnet20_plain.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace ResNet20
{

size_t TensorShape::size() const
{
    return channels * height * width;
}

Tensor::Tensor(TensorShape tensor_shape)
    : shape(tensor_shape), values(tensor_shape.size(), 0.0)
{
}

size_t chw_index(const TensorShape &shape, size_t channel, size_t row, size_t col)
{
    return channel * shape.height * shape.width + row * shape.width + col;
}

size_t conv_weight_index(const Conv2dWeights &weights, size_t out_channel, size_t in_channel,
                         size_t kernel_row, size_t kernel_col)
{
    return ((out_channel * weights.in_channels + in_channel) * weights.kernel_h + kernel_row) *
               weights.kernel_w +
           kernel_col;
}

Tensor conv2d_plain(const Tensor &input, const Conv2dWeights &weights)
{
    if (input.shape.channels != weights.in_channels)
    {
        throw std::invalid_argument("conv2d_plain: input channels do not match weights");
    }
    if (weights.kernel_h == 0 || weights.kernel_w == 0 || weights.stride == 0)
    {
        throw std::invalid_argument("conv2d_plain: invalid kernel or stride");
    }

    const size_t output_h =
        (input.shape.height + 2 * weights.padding - weights.kernel_h) / weights.stride + 1;
    const size_t output_w =
        (input.shape.width + 2 * weights.padding - weights.kernel_w) / weights.stride + 1;
    Tensor output({weights.out_channels, output_h, output_w});

    for (size_t oc = 0; oc < weights.out_channels; ++oc)
    {
        for (size_t oh = 0; oh < output_h; ++oh)
        {
            for (size_t ow = 0; ow < output_w; ++ow)
            {
                double acc = weights.bias.empty() ? 0.0 : weights.bias[oc];
                for (size_t ic = 0; ic < weights.in_channels; ++ic)
                {
                    for (size_t kh = 0; kh < weights.kernel_h; ++kh)
                    {
                        for (size_t kw = 0; kw < weights.kernel_w; ++kw)
                        {
                            const int ih = static_cast<int>(oh * weights.stride + kh) -
                                           static_cast<int>(weights.padding);
                            const int iw = static_cast<int>(ow * weights.stride + kw) -
                                           static_cast<int>(weights.padding);
                            if (ih < 0 || iw < 0 ||
                                ih >= static_cast<int>(input.shape.height) ||
                                iw >= static_cast<int>(input.shape.width))
                            {
                                continue;
                            }

                            acc += input.values[chw_index(input.shape, ic,
                                                          static_cast<size_t>(ih),
                                                          static_cast<size_t>(iw))] *
                                   weights.weights[conv_weight_index(weights, oc, ic, kh, kw)];
                        }
                    }
                }
                output.values[chw_index(output.shape, oc, oh, ow)] = acc;
            }
        }
    }

    return output;
}

Tensor square_activation_plain(const Tensor &input)
{
    Tensor output(input.shape);
    std::transform(input.values.begin(), input.values.end(), output.values.begin(),
                   [](double value) { return value * value; });
    return output;
}

Tensor apprelu_activation_plain(const Tensor &input, const ActivationOptions &activation)
{
    if (activation.apprelu_bound <= 0.0)
    {
        throw std::invalid_argument("apprelu_activation_plain: bound must be positive");
    }

    Tensor output(input.shape);
    for (size_t i = 0; i < input.values.size(); ++i)
    {
        const double x = input.values[i];
        double sign_approx = x / activation.apprelu_bound;
        for (size_t round = 0; round < activation.apprelu_rounds; ++round)
        {
            // Odd cubic composition commonly used as a sign-sharpening building block:
            // p(x) = 1.5x - 0.5x^3. The input should be scaled into a bounded interval.
            sign_approx = 1.5 * sign_approx - 0.5 * sign_approx * sign_approx * sign_approx;
        }
        output.values[i] = 0.5 * x * (1.0 + sign_approx);
    }
    return output;
}

Tensor activate_plain(const Tensor &input, const ActivationOptions &activation)
{
    switch (activation.kind)
    {
    case ActivationKind::Square:
        return square_activation_plain(input);
    case ActivationKind::AppReLU:
        return apprelu_activation_plain(input, activation);
    }
    throw std::invalid_argument("activate_plain: unsupported activation");
}

Tensor residual_block_plain(const Tensor &input, const ResidualBlockWeights &weights)
{
    return residual_block_plain(input, weights, ActivationOptions{});
}

Tensor residual_block_plain(const Tensor &input, const ResidualBlockWeights &weights,
                            const ActivationOptions &activation)
{
    Tensor main_path = conv2d_plain(input, weights.conv1);
    main_path = conv2d_plain(main_path, weights.conv2);

    Tensor shortcut = weights.has_shortcut ? conv2d_plain(input, weights.shortcut) : input;
    if (main_path.shape.size() != shortcut.shape.size())
    {
        throw std::invalid_argument("residual_block_plain: residual shape mismatch");
    }

    for (size_t i = 0; i < main_path.values.size(); ++i)
    {
        main_path.values[i] += shortcut.values[i];
    }
    return activate_plain(main_path, activation);
}

Tensor global_average_pool_plain(const Tensor &input)
{
    Tensor output({input.shape.channels, 1, 1});
    const double area = static_cast<double>(input.shape.height * input.shape.width);
    for (size_t c = 0; c < input.shape.channels; ++c)
    {
        double acc = 0.0;
        for (size_t h = 0; h < input.shape.height; ++h)
        {
            for (size_t w = 0; w < input.shape.width; ++w)
            {
                acc += input.values[chw_index(input.shape, c, h, w)];
            }
        }
        output.values[c] = acc / area;
    }
    return output;
}

Tensor linear_plain(const Tensor &input, const ResNet20Weights &weights)
{
    if (input.values.size() != weights.fc_in)
    {
        throw std::invalid_argument("linear_plain: input size does not match fc weight");
    }

    Tensor output({weights.fc_out, 1, 1});
    for (size_t out = 0; out < weights.fc_out; ++out)
    {
        double acc = weights.fc_bias.empty() ? 0.0 : weights.fc_bias[out];
        for (size_t in = 0; in < weights.fc_in; ++in)
        {
            acc += weights.fc_weight[out * weights.fc_in + in] * input.values[in];
        }
        output.values[out] = acc;
    }
    return output;
}

Tensor forward_plain(const Tensor &input, const ResNet20Weights &weights)
{
    return forward_plain(input, weights, ActivationOptions{});
}

Tensor forward_plain(const Tensor &input, const ResNet20Weights &weights,
                     const ActivationOptions &activation)
{
    Tensor x = activate_plain(conv2d_plain(input, weights.conv1), activation);
    for (const auto &block : weights.stage1)
    {
        x = residual_block_plain(x, block, activation);
    }
    for (const auto &block : weights.stage2)
    {
        x = residual_block_plain(x, block, activation);
    }
    for (const auto &block : weights.stage3)
    {
        x = residual_block_plain(x, block, activation);
    }
    return linear_plain(global_average_pool_plain(x), weights);
}

} // namespace ResNet20
