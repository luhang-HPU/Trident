#include "resnet20_ops.h"

#include "poseidon/util/precision.h"

#include <algorithm>
#include <complex>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>

namespace ResNet20
{

namespace
{

constexpr int kSparseConvBabyStep = 128;

TensorShape logical_shape_from_physical(const TensorShape &physical_shape, size_t spacing)
{
    // 稀疏张量保留原始物理高/宽，但只有每隔 `spacing` 的槽位才是真正有效值。
    // 这个辅助函数返回这些有效槽位对应的逻辑张量形状。
    if (spacing == 0 || physical_shape.height % spacing != 0 ||
        physical_shape.width % spacing != 0)
    {
        throw std::invalid_argument("logical_shape_from_physical: invalid sparse spacing");
    }
    return {physical_shape.channels, physical_shape.height / spacing,
            physical_shape.width / spacing};
}

void visit_sparse_conv_terms(
    const TensorShape &input_physical_shape, size_t input_spacing,
    const Conv2dWeights &weights, size_t output_physical_height,
    size_t output_physical_width, size_t output_spacing,
    const std::function<void(size_t, size_t, double)> &visitor)
{
    // 枚举稀疏布局下卷积里的所有非零线性项。
    // visitor 会收到 (输入槽位, 输出槽位, 权重)，这些信息足够构造旋转步长、
    // 明文 mask，或者明文参考变换。
    const TensorShape input_logical_shape =
        logical_shape_from_physical(input_physical_shape, input_spacing);
    const TensorShape output_logical_shape = conv2d_output_shape(input_logical_shape, weights);
    if (output_logical_shape.height * output_spacing > output_physical_height ||
        output_logical_shape.width * output_spacing > output_physical_width)
    {
        throw std::invalid_argument("visit_sparse_conv_terms: sparse output does not fit");
    }

    for (size_t oc = 0; oc < weights.out_channels; ++oc)
    {
        for (size_t ic = 0; ic < weights.in_channels; ++ic)
        {
            for (size_t kh = 0; kh < weights.kernel_h; ++kh)
            {
                for (size_t kw = 0; kw < weights.kernel_w; ++kw)
                {
                    for (size_t oh = 0; oh < output_logical_shape.height; ++oh)
                    {
                        for (size_t ow = 0; ow < output_logical_shape.width; ++ow)
                        {
                            const int ih = static_cast<int>(oh * weights.stride + kh) -
                                           static_cast<int>(weights.padding);
                            const int iw = static_cast<int>(ow * weights.stride + kw) -
                                           static_cast<int>(weights.padding);
                            if (ih < 0 || iw < 0 ||
                                ih >= static_cast<int>(input_logical_shape.height) ||
                                iw >= static_cast<int>(input_logical_shape.width))
                            {
                                continue;
                            }

                            const size_t input_index =
                                ic * input_physical_shape.height * input_physical_shape.width +
                                static_cast<size_t>(ih) * input_spacing *
                                    input_physical_shape.width +
                                static_cast<size_t>(iw) * input_spacing;
                            const size_t output_index =
                                oc * output_physical_height * output_physical_width +
                                oh * output_spacing * output_physical_width +
                                ow * output_spacing;
                            const size_t weight_index =
                                ((oc * weights.in_channels + ic) * weights.kernel_h + kh) *
                                    weights.kernel_w +
                                kw;
                            visitor(input_index, output_index, weights.weights[weight_index]);
                        }
                    }
                }
            }
        }
    }
}

std::vector<int> sparse_conv_rotation_steps(const TensorShape &input_physical_shape,
                                            size_t input_spacing,
                                            const Conv2dWeights &weights,
                                            size_t output_physical_height,
                                            size_t output_physical_width,
                                            size_t output_spacing)
{
    std::set<int> steps;
    visit_sparse_conv_terms(
        input_physical_shape, input_spacing, weights, output_physical_height,
        output_physical_width, output_spacing,
        [&](size_t input_index, size_t output_index, double)
        {
            const int step = static_cast<int>(input_index) - static_cast<int>(output_index);
            if (step != 0)
            {
                steps.insert(step);
            }
        });
    return {steps.begin(), steps.end()};
}

int positive_mod(int value, int modulus)
{
    int result = value % modulus;
    return result < 0 ? result + modulus : result;
}

poseidon::Ciphertext divide_decoded_value(const poseidon::Ciphertext &input, double divisor)
{
    // CKKS 近似值可以理解成 encoded_integer / scale。只修改元数据里的 scale，
    // 等价于改变解码值；把 scale 乘以 `divisor` 就能实现除法，而且不消耗 level。
    if (divisor <= 0.0)
    {
        throw std::invalid_argument("divide_decoded_value: divisor must be positive");
    }
    poseidon::Ciphertext result = input;
    result.scale() *= divisor;
    return result;
}

poseidon::Ciphertext add_scalar(
    const poseidon::Ciphertext &input,
    double value,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator)
{
    poseidon::Plaintext plain_value;
    encoder.encode(value, input.parms_id(), input.scale(), plain_value);

    poseidon::Ciphertext result;
    evaluator.add_plain(input, plain_value, result);
    return result;
}

poseidon::Ciphertext apprelu_sign_round(
    const poseidon::Ciphertext &input,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::RelinKeys &relin_keys,
    const poseidon::CKKSEncoder &encoder,
    double scale)
{
    // 一轮奇多项式符号增强：
    // p(x) = 0.5 * (3x - x^3)。AppReLU 先在 x/bound 上迭代这个近似符号函数，
    // 再计算 0.5 * x * (1 + sign_approx)。它比完整 ReLU 电路便宜，
    // 但仍然比 square 激活消耗更多乘法深度。
    poseidon::Ciphertext square;
    evaluator.multiply_relin(input, input, square, relin_keys);
    evaluator.rescale_dynamic(square, square, scale);

    poseidon::Ciphertext cubic;
    evaluator.multiply_relin_dynamic(square, input, cubic, relin_keys);
    evaluator.rescale_dynamic(cubic, cubic, scale);

    poseidon::Ciphertext linear;
    evaluator.add(input, input, linear);
    evaluator.add(linear, input, linear);
    match_level_and_scale(linear, cubic, encoder, evaluator, scale);

    poseidon::Ciphertext result;
    evaluator.sub(linear, cubic, result);
    return divide_decoded_value(result, 2.0);
}

poseidon::Ciphertext sparse_conv_encrypted(const poseidon::Ciphertext &input,
                                           const TensorShape &input_physical_shape,
                                           size_t input_spacing,
                                           const Conv2dWeights &weights,
                                           const poseidon::CKKSEncoder &encoder,
                                           const poseidon::EvaluatorCkksBase &evaluator,
                                           const poseidon::GaloisKeys &galois_keys,
                                           double scale, size_t slot_count,
                                           size_t output_physical_height,
                                           size_t output_physical_width,
                                           size_t output_spacing)
{
    // BSGS 风格的稀疏卷积。每个卷积项都表示成 rotate-and-mask 的贡献。
    // 这里把旋转拆成 baby step 和 giant step，使原始输入的 baby rotations 可以被复用。
    const TensorShape input_logical_shape =
        logical_shape_from_physical(input_physical_shape, input_spacing);
    const TensorShape output_logical_shape = conv2d_output_shape(input_logical_shape, weights);
    const TensorShape output_physical_shape{weights.out_channels, output_physical_height,
                                            output_physical_width};
    if (input_physical_shape.size() > slot_count || output_physical_shape.size() > slot_count)
    {
        throw std::invalid_argument("sparse_conv_encrypted: packed tensor does not fit in slots");
    }

    std::map<int, std::map<int, std::vector<std::complex<double>>>> masks_by_giant_baby;
    visit_sparse_conv_terms(
        input_physical_shape, input_spacing, weights, output_physical_height,
        output_physical_width, output_spacing,
        [&](size_t input_index, size_t output_index, double weight)
        {
            const int step = static_cast<int>(input_index) - static_cast<int>(output_index);
            const int baby = positive_mod(step, kSparseConvBabyStep);
            const int giant = step - baby;
            auto &mask = masks_by_giant_baby[giant][baby];
            if (mask.empty())
            {
                mask.assign(slot_count, {0.0, 0.0});
            }
            const size_t mask_index =
                static_cast<size_t>(positive_mod(static_cast<int>(output_index) + giant,
                                                 static_cast<int>(slot_count)));
            // mask 放在最后一次 giant rotation 之前。先做 baby rotation，
            // 再用 multiply_plain 选中对应贡献，最后 giant rotation 把它移动到真实输出槽位。
            mask[mask_index] += std::complex<double>(weight, 0.0);
        });

    std::set<int> baby_steps;
    for (const auto &[_, baby_masks] : masks_by_giant_baby)
    {
        for (const auto &[baby, mask] : baby_masks)
        {
            if (std::all_of(mask.begin(), mask.end(),
                            [](const std::complex<double> &value)
                            { return value.real() == 0.0 && value.imag() == 0.0; }))
            {
                continue;
            }
            baby_steps.insert(baby);
        }
    }

    std::map<int, poseidon::Ciphertext> baby_rotations;
    for (int baby : baby_steps)
    {
        if (baby == 0)
        {
            baby_rotations[baby] = input;
        }
        else
        {
            evaluator.rotate(input, baby_rotations[baby], baby, galois_keys);
        }
    }

    poseidon::Ciphertext result;
    bool initialized = false;
    for (const auto &[giant, baby_masks] : masks_by_giant_baby)
    {
        poseidon::Ciphertext inner;
        bool inner_initialized = false;
        for (const auto &[baby, mask] : baby_masks)
        {
            if (std::all_of(mask.begin(), mask.end(),
                            [](const std::complex<double> &value)
                            { return value.real() == 0.0 && value.imag() == 0.0; }))
            {
                continue;
            }

            poseidon::Plaintext plain_mask;
            encoder.encode(mask, input.parms_id(), scale, plain_mask);

            poseidon::Ciphertext term;
            evaluator.multiply_plain(baby_rotations.at(baby), plain_mask, term);
            if (!inner_initialized)
            {
                inner = term;
                inner_initialized = true;
            }
            else
            {
                evaluator.add(inner, term, inner);
            }
        }

        if (!inner_initialized)
        {
            continue;
        }

        if (giant != 0)
        {
            evaluator.rotate(inner, inner, giant, galois_keys);
        }

        if (!initialized)
        {
            result = inner;
            initialized = true;
        }
        else
        {
            evaluator.add(result, inner, result);
        }
    }

    if (!initialized)
    {
        throw std::invalid_argument("sparse_conv_encrypted: convolution produced no terms");
    }
    evaluator.rescale_dynamic(result, result, scale);

    if (!weights.bias.empty())
    {
        std::vector<std::complex<double>> bias(slot_count, {0.0, 0.0});
        for (size_t oc = 0; oc < output_logical_shape.channels; ++oc)
        {
            for (size_t h = 0; h < output_logical_shape.height; ++h)
            {
                for (size_t w = 0; w < output_logical_shape.width; ++w)
                {
                    const size_t index =
                        oc * output_physical_height * output_physical_width +
                        h * output_spacing * output_physical_width + w * output_spacing;
                    bias[index] = {weights.bias[oc], 0.0};
                }
            }
        }

        poseidon::Plaintext plain_bias;
        encoder.encode(bias, result.parms_id(), result.scale(), plain_bias);
        evaluator.add_plain(result, plain_bias, result);
    }

    return result;
}

} // namespace

TensorShape conv2d_output_shape(const TensorShape &input_shape, const Conv2dWeights &weights)
{
    if (input_shape.channels != weights.in_channels)
    {
        throw std::invalid_argument("conv2d_output_shape: input channels do not match weights");
    }
    if (weights.kernel_h == 0 || weights.kernel_w == 0 || weights.stride == 0)
    {
        throw std::invalid_argument("conv2d_output_shape: invalid kernel or stride");
    }

    return {weights.out_channels,
            (input_shape.height + 2 * weights.padding - weights.kernel_h) / weights.stride + 1,
            (input_shape.width + 2 * weights.padding - weights.kernel_w) / weights.stride + 1};
}

std::vector<int> conv2d_rotation_steps(const TensorShape &input_shape,
                                       const Conv2dWeights &weights)
{
    const TensorShape output_shape = conv2d_output_shape(input_shape, weights);
    std::set<int> steps;

    for (size_t oc = 0; oc < weights.out_channels; ++oc)
    {
        for (size_t ic = 0; ic < weights.in_channels; ++ic)
        {
            for (size_t kh = 0; kh < weights.kernel_h; ++kh)
            {
                for (size_t kw = 0; kw < weights.kernel_w; ++kw)
                {
                    for (size_t oh = 0; oh < output_shape.height; ++oh)
                    {
                        for (size_t ow = 0; ow < output_shape.width; ++ow)
                        {
                            const int ih = static_cast<int>(oh * weights.stride + kh) -
                                           static_cast<int>(weights.padding);
                            const int iw = static_cast<int>(ow * weights.stride + kw) -
                                           static_cast<int>(weights.padding);
                            if (ih < 0 || iw < 0 ||
                                ih >= static_cast<int>(input_shape.height) ||
                                iw >= static_cast<int>(input_shape.width))
                            {
                                continue;
                            }

                            const size_t input_index =
                                ic * input_shape.height * input_shape.width +
                                static_cast<size_t>(ih) * input_shape.width +
                                static_cast<size_t>(iw);
                            const size_t output_index =
                                oc * output_shape.height * output_shape.width +
                                oh * output_shape.width + ow;
                            const int step =
                                static_cast<int>(input_index) - static_cast<int>(output_index);
                            if (step != 0)
                            {
                                steps.insert(step);
                            }
                        }
                    }
                }
            }
        }
    }

    return {steps.begin(), steps.end()};
}

poseidon::Ciphertext conv2d_encrypted(const poseidon::Ciphertext &input,
                                      const TensorShape &input_shape,
                                      const Conv2dWeights &weights,
                                      const poseidon::CKKSEncoder &encoder,
                                      const poseidon::EvaluatorCkksBase &evaluator,
                                      const poseidon::GaloisKeys &galois_keys,
                                      double scale, size_t slot_count)
{
    const TensorShape output_shape = conv2d_output_shape(input_shape, weights);
    if (input_shape.size() > slot_count || output_shape.size() > slot_count)
    {
        throw std::invalid_argument("conv2d_encrypted: packed tensor does not fit in slots");
    }

    std::map<int, std::vector<std::complex<double>>> masks_by_step;

    for (size_t oc = 0; oc < weights.out_channels; ++oc)
    {
        for (size_t ic = 0; ic < weights.in_channels; ++ic)
        {
            for (size_t kh = 0; kh < weights.kernel_h; ++kh)
            {
                for (size_t kw = 0; kw < weights.kernel_w; ++kw)
                {
                    for (size_t oh = 0; oh < output_shape.height; ++oh)
                    {
                        for (size_t ow = 0; ow < output_shape.width; ++ow)
                        {
                            const int ih = static_cast<int>(oh * weights.stride + kh) -
                                           static_cast<int>(weights.padding);
                            const int iw = static_cast<int>(ow * weights.stride + kw) -
                                           static_cast<int>(weights.padding);
                            if (ih < 0 || iw < 0 ||
                                ih >= static_cast<int>(input_shape.height) ||
                                iw >= static_cast<int>(input_shape.width))
                            {
                                continue;
                            }

                            const size_t input_index =
                                ic * input_shape.height * input_shape.width +
                                static_cast<size_t>(ih) * input_shape.width +
                                static_cast<size_t>(iw);
                            const size_t output_index =
                                oc * output_shape.height * output_shape.width +
                                oh * output_shape.width + ow;
                            const int step =
                                static_cast<int>(input_index) - static_cast<int>(output_index);
                            auto &mask = masks_by_step[step];
                            if (mask.empty())
                            {
                                mask.assign(slot_count, {0.0, 0.0});
                            }

                            const size_t weight_index =
                                ((oc * weights.in_channels + ic) * weights.kernel_h + kh) *
                                    weights.kernel_w +
                                kw;
                            mask[input_index] +=
                                std::complex<double>(weights.weights[weight_index], 0.0);
                        }
                    }
                }
            }
        }
    }

    poseidon::Ciphertext result;
    bool initialized = false;

    for (const auto &[step, mask] : masks_by_step)
    {
        if (std::all_of(mask.begin(), mask.end(),
                        [](const std::complex<double> &value)
                        { return value.real() == 0.0 && value.imag() == 0.0; }))
        {
            continue;
        }

        poseidon::Plaintext plain_mask;
        encoder.encode(mask, input.parms_id(), scale, plain_mask);

        poseidon::Ciphertext term;
        evaluator.multiply_plain(input, plain_mask, term);

        if (step != 0)
        {
            evaluator.rotate(term, term, step, galois_keys);
        }

        if (!initialized)
        {
            result = term;
            initialized = true;
        }
        else
        {
            evaluator.add(result, term, result);
        }
    }

    if (!initialized)
    {
        throw std::invalid_argument("conv2d_encrypted: convolution produced no terms");
    }
    evaluator.rescale_dynamic(result, result, scale);

    if (!weights.bias.empty())
    {
        std::vector<std::complex<double>> bias(slot_count, {0.0, 0.0});
        for (size_t oc = 0; oc < output_shape.channels; ++oc)
        {
            for (size_t h = 0; h < output_shape.height; ++h)
            {
                for (size_t w = 0; w < output_shape.width; ++w)
                {
                    const size_t index =
                        oc * output_shape.height * output_shape.width + h * output_shape.width + w;
                    bias[index] = {weights.bias[oc], 0.0};
                }
            }
        }

        poseidon::Plaintext plain_bias;
        encoder.encode(bias, result.parms_id(), result.scale(), plain_bias);
        evaluator.add_plain(result, plain_bias, result);
    }

    return result;
}

poseidon::Ciphertext residual_block_encrypted(const poseidon::Ciphertext &input,
                                              const TensorShape &input_shape,
                                              const ResidualBlockWeights &weights,
                                              const poseidon::CKKSEncoder &encoder,
                                              const poseidon::EvaluatorCkksBase &evaluator,
                                              const poseidon::GaloisKeys &galois_keys,
                                              const poseidon::RelinKeys &relin_keys,
                                              double scale, size_t slot_count)
{
    return residual_block_encrypted(input, input_shape, weights, encoder, evaluator, galois_keys,
                                    relin_keys, scale, slot_count, ActivationOptions{});
}

poseidon::Ciphertext residual_block_encrypted(const poseidon::Ciphertext &input,
                                              const TensorShape &input_shape,
                                              const ResidualBlockWeights &weights,
                                              const poseidon::CKKSEncoder &encoder,
                                              const poseidon::EvaluatorCkksBase &evaluator,
                                              const poseidon::GaloisKeys &galois_keys,
                                              const poseidon::RelinKeys &relin_keys,
                                              double scale, size_t slot_count,
                                              const ActivationOptions &activation)
{
    poseidon::Ciphertext main_path =
        conv2d_encrypted(input, input_shape, weights.conv1, encoder, evaluator, galois_keys,
                         scale, slot_count);
    const TensorShape middle_shape = conv2d_output_shape(input_shape, weights.conv1);
    main_path = conv2d_encrypted(main_path, middle_shape, weights.conv2, encoder, evaluator,
                                 galois_keys, scale, slot_count);
    const TensorShape output_shape = conv2d_output_shape(middle_shape, weights.conv2);

    poseidon::Ciphertext shortcut;
    if (weights.has_shortcut)
    {
        shortcut = conv2d_encrypted(input, input_shape, weights.shortcut, encoder, evaluator,
                                    galois_keys, scale, slot_count);
    }
    else
    {
        shortcut = input;
    }

    const TensorShape shortcut_shape =
        weights.has_shortcut ? conv2d_output_shape(input_shape, weights.shortcut) : input_shape;
    if (output_shape.channels != shortcut_shape.channels ||
        output_shape.height != shortcut_shape.height || output_shape.width != shortcut_shape.width)
    {
        throw std::invalid_argument("residual_block_encrypted: residual shape mismatch");
    }

    match_level_and_scale(main_path, shortcut, encoder, evaluator, scale);
    evaluator.add(main_path, shortcut, main_path);
    activation_inplace(main_path, evaluator, relin_keys, encoder, scale, activation);
    return main_path;
}

std::vector<int> sparse_downsample_block_rotation_steps(const TensorShape &input_shape,
                                                        const ResidualBlockWeights &weights,
                                                        size_t output_physical_height,
                                                        size_t output_physical_width,
                                                        size_t spacing)
{
    if (!weights.has_shortcut)
    {
        throw std::invalid_argument(
            "sparse_downsample_block_rotation_steps: shortcut is required");
    }

    std::vector<std::vector<int>> groups;
    groups.push_back(sparse_conv_rotation_steps(input_shape, 1, weights.conv1,
                                                output_physical_height, output_physical_width,
                                                spacing));
    TensorShape sparse_middle_shape{weights.conv1.out_channels, output_physical_height,
                                    output_physical_width};
    groups.push_back(sparse_conv_rotation_steps(sparse_middle_shape, spacing, weights.conv2,
                                                output_physical_height, output_physical_width,
                                                spacing));
    groups.push_back(sparse_conv_rotation_steps(input_shape, 1, weights.shortcut,
                                                output_physical_height, output_physical_width,
                                                spacing));

    std::set<int> merged;
    for (const auto &group : groups)
    {
        merged.insert(group.begin(), group.end());
    }
    return {merged.begin(), merged.end()};
}

poseidon::Ciphertext sparse_downsample_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t output_physical_height,
    size_t output_physical_width,
    size_t spacing)
{
    return sparse_downsample_block_encrypted(
        input, input_shape, weights, encoder, evaluator, galois_keys, relin_keys, scale,
        slot_count, output_physical_height, output_physical_width, spacing, ActivationOptions{});
}

poseidon::Ciphertext sparse_downsample_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t output_physical_height,
    size_t output_physical_width,
    size_t spacing,
    const ActivationOptions &activation)
{
    if (!weights.has_shortcut)
    {
        throw std::invalid_argument("sparse_downsample_block_encrypted: shortcut is required");
    }

    poseidon::Ciphertext main_path =
        sparse_conv_encrypted(input, input_shape, 1, weights.conv1, encoder, evaluator,
                              galois_keys, scale, slot_count, output_physical_height,
                              output_physical_width, spacing);
    TensorShape sparse_middle_shape{weights.conv1.out_channels, output_physical_height,
                                    output_physical_width};
    main_path = sparse_conv_encrypted(main_path, sparse_middle_shape, spacing, weights.conv2,
                                      encoder, evaluator, galois_keys, scale, slot_count,
                                      output_physical_height, output_physical_width, spacing);

    poseidon::Ciphertext shortcut =
        sparse_conv_encrypted(input, input_shape, 1, weights.shortcut, encoder, evaluator,
                              galois_keys, scale, slot_count, output_physical_height,
                              output_physical_width, spacing);

    match_level_and_scale(main_path, shortcut, encoder, evaluator, scale);
    evaluator.add(main_path, shortcut, main_path);
    activation_inplace(main_path, evaluator, relin_keys, encoder, scale, activation);
    return main_path;
}

std::vector<int> sparse_residual_block_rotation_steps(const TensorShape &input_physical_shape,
                                                      const ResidualBlockWeights &weights,
                                                      size_t spacing)
{
    if (weights.has_shortcut)
    {
        throw std::invalid_argument(
            "sparse_residual_block_rotation_steps: use downsample helper for shortcut blocks");
    }

    const size_t physical_height = input_physical_shape.height;
    const size_t physical_width = input_physical_shape.width;
    std::vector<std::vector<int>> groups;
    groups.push_back(sparse_conv_rotation_steps(input_physical_shape, spacing, weights.conv1,
                                                physical_height, physical_width, spacing));
    const TensorShape middle_physical_shape{weights.conv1.out_channels, physical_height,
                                            physical_width};
    groups.push_back(sparse_conv_rotation_steps(middle_physical_shape, spacing, weights.conv2,
                                                physical_height, physical_width, spacing));

    std::set<int> merged;
    for (const auto &group : groups)
    {
        merged.insert(group.begin(), group.end());
    }
    return {merged.begin(), merged.end()};
}

poseidon::Ciphertext sparse_residual_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t spacing)
{
    return sparse_residual_block_encrypted(input, input_physical_shape, weights, encoder,
                                           evaluator, galois_keys, relin_keys, scale, slot_count,
                                           spacing, ActivationOptions{});
}

poseidon::Ciphertext sparse_residual_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t spacing,
    const ActivationOptions &activation)
{
    if (weights.has_shortcut)
    {
        throw std::invalid_argument(
            "sparse_residual_block_encrypted: use downsample helper for shortcut blocks");
    }

    const size_t physical_height = input_physical_shape.height;
    const size_t physical_width = input_physical_shape.width;
    poseidon::Ciphertext main_path =
        sparse_conv_encrypted(input, input_physical_shape, spacing, weights.conv1, encoder,
                              evaluator, galois_keys, scale, slot_count, physical_height,
                              physical_width, spacing);
    const TensorShape middle_physical_shape{weights.conv1.out_channels, physical_height,
                                            physical_width};
    main_path = sparse_conv_encrypted(main_path, middle_physical_shape, spacing, weights.conv2,
                                      encoder, evaluator, galois_keys, scale, slot_count,
                                      physical_height, physical_width, spacing);

    poseidon::Ciphertext shortcut = input;
    match_level_and_scale(main_path, shortcut, encoder, evaluator, scale);
    evaluator.add(main_path, shortcut, main_path);
    activation_inplace(main_path, evaluator, relin_keys, encoder, scale, activation);
    return main_path;
}

std::vector<int> sparse_to_compact_rotation_steps(const TensorShape &input_physical_shape,
                                                  size_t spacing)
{
    // bridge 没有做一个巨大的任意置换，而是拆成三次结构化压紧：
    // 先压列，再压行，最后压 channel block。
    const TensorShape output_shape = logical_shape_from_physical(input_physical_shape, spacing);
    std::set<int> steps;

    for (size_t w = 1; w < output_shape.width; ++w)
    {
        steps.insert(static_cast<int>(w * (spacing - 1)));
    }

    const size_t row_step =
        spacing * input_physical_shape.width - output_shape.width;
    for (size_t h = 1; h < output_shape.height; ++h)
    {
        steps.insert(static_cast<int>(h * row_step));
    }

    const size_t physical_channel_size = input_physical_shape.height * input_physical_shape.width;
    const size_t compact_channel_size = output_shape.height * output_shape.width;
    for (size_t c = 1; c < input_physical_shape.channels; ++c)
    {
        steps.insert(static_cast<int>(c * (physical_channel_size - compact_channel_size)));
    }
    return {steps.begin(), steps.end()};
}

poseidon::Ciphertext sparse_to_compact_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    size_t spacing,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    double scale, size_t slot_count)
{
    // 将 stage2 的稀疏输出压成 stage3 需要的 compact 输入：
    // 物理 32x32、spacing=2 -> 逻辑 16x16。这样需要三轮 multiply-mask，
    // 但避免了成千上万个一次性旋转。
    const TensorShape output_shape = logical_shape_from_physical(input_physical_shape, spacing);
    if (input_physical_shape.size() > slot_count || output_shape.size() > slot_count)
    {
        throw std::invalid_argument("sparse_to_compact_encrypted: tensor does not fit in slots");
    }

    auto make_mask = [slot_count]() { return std::vector<std::complex<double>>(slot_count, {0.0, 0.0}); };

    auto add_mask_value = [&make_mask](std::map<int, std::vector<std::complex<double>>> &masks,
                                       int step, size_t index)
    {
        auto &mask = masks[step];
        if (mask.empty())
        {
            mask = make_mask();
        }
        mask[index] = {1.0, 0.0};
    };

    auto apply_masked_shifts =
        [&](const poseidon::Ciphertext &cipher,
            const std::map<int, std::vector<std::complex<double>>> &masks)
    {
        poseidon::Ciphertext result;
        bool initialized = false;
        for (const auto &[step, mask] : masks)
        {
            poseidon::Plaintext plain_mask;
            encoder.encode(mask, cipher.parms_id(), scale, plain_mask);

            poseidon::Ciphertext term;
            evaluator.multiply_plain(cipher, plain_mask, term);
            if (step != 0)
            {
                evaluator.rotate(term, term, step, galois_keys);
            }

            if (!initialized)
            {
                result = term;
                initialized = true;
            }
            else
            {
                evaluator.add(result, term, result);
            }
        }
        if (!initialized)
        {
            throw std::invalid_argument("sparse_to_compact_encrypted: transform produced no terms");
        }
        evaluator.rescale_dynamic(result, result, scale);
        return result;
    };

    std::map<int, std::vector<std::complex<double>>> column_masks;
    for (size_t c = 0; c < input_physical_shape.channels; ++c)
    {
        for (size_t h = 0; h < output_shape.height; ++h)
        {
            for (size_t w = 0; w < output_shape.width; ++w)
            {
                const size_t index =
                    c * input_physical_shape.height * input_physical_shape.width +
                    h * spacing * input_physical_shape.width + w * spacing;
                add_mask_value(column_masks, static_cast<int>(w * (spacing - 1)), index);
            }
        }
    }
    poseidon::Ciphertext compact_columns = apply_masked_shifts(input, column_masks);

    // 第 2 步：把有效行挪到一起。此时每一行内部的列已经是 compact 的。
    std::map<int, std::vector<std::complex<double>>> row_masks;
    const size_t row_step = spacing * input_physical_shape.width - output_shape.width;
    for (size_t c = 0; c < input_physical_shape.channels; ++c)
    {
        for (size_t h = 0; h < output_shape.height; ++h)
        {
            for (size_t w = 0; w < output_shape.width; ++w)
            {
                const size_t index =
                    c * input_physical_shape.height * input_physical_shape.width +
                    h * spacing * input_physical_shape.width + w;
                add_mask_value(row_masks, static_cast<int>(h * row_step), index);
            }
        }
    }
    poseidon::Ciphertext compact_rows = apply_masked_shifts(compact_columns, row_masks);

    // 第 3 步：压紧 channel block。稀疏物理 channel 比 compact 逻辑 channel 更大，
    // 所以第 c 个 channel block 需要左移 c * (physical-logical)。
    std::map<int, std::vector<std::complex<double>>> channel_masks;
    const size_t physical_channel_size = input_physical_shape.height * input_physical_shape.width;
    const size_t compact_channel_size = output_shape.height * output_shape.width;
    for (size_t c = 0; c < input_physical_shape.channels; ++c)
    {
        for (size_t h = 0; h < output_shape.height; ++h)
        {
            for (size_t w = 0; w < output_shape.width; ++w)
            {
                const size_t index = c * physical_channel_size + h * output_shape.width + w;
                const int step =
                    static_cast<int>(c * (physical_channel_size - compact_channel_size));
                add_mask_value(channel_masks, step, index);
            }
        }
    }
    return apply_masked_shifts(compact_rows, channel_masks);
}

std::vector<int> sparse_global_average_pool_rotation_steps(
    const TensorShape &input_physical_shape, size_t spacing)
{
    // GAP 先在每个 channel 内累加所有有效稀疏位置，
    // 再把每个 channel 的和移动到 slots [0, channels)。
    const TensorShape logical_shape = logical_shape_from_physical(input_physical_shape, spacing);
    std::set<int> steps;
    for (size_t shift = spacing; shift < logical_shape.width * spacing; shift <<= 1)
    {
        steps.insert(static_cast<int>(shift));
    }
    for (size_t shift = input_physical_shape.width * spacing;
         shift < input_physical_shape.width * input_physical_shape.height; shift <<= 1)
    {
        steps.insert(static_cast<int>(shift));
    }

    const size_t physical_channel_size = input_physical_shape.height * input_physical_shape.width;
    for (size_t c = 1; c < input_physical_shape.channels; ++c)
    {
        steps.insert(static_cast<int>(c * (physical_channel_size - 1)));
    }
    return {steps.begin(), steps.end()};
}

poseidon::Ciphertext sparse_global_average_pool_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    size_t spacing,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    double scale, size_t slot_count)
{
    const TensorShape logical_shape = logical_shape_from_physical(input_physical_shape, spacing);
    if (input_physical_shape.size() > slot_count ||
        input_physical_shape.channels > slot_count)
    {
        throw std::invalid_argument(
            "sparse_global_average_pool_encrypted: tensor does not fit in slots");
    }

    poseidon::Ciphertext sum = input;
    for (size_t shift = spacing; shift < logical_shape.width * spacing; shift <<= 1)
    {
        poseidon::Ciphertext rotated;
        evaluator.rotate(sum, rotated, static_cast<int>(shift), galois_keys);
        evaluator.add(sum, rotated, sum);
    }
    for (size_t shift = input_physical_shape.width * spacing;
         shift < input_physical_shape.width * input_physical_shape.height; shift <<= 1)
    {
        poseidon::Ciphertext rotated;
        evaluator.rotate(sum, rotated, static_cast<int>(shift), galois_keys);
        evaluator.add(sum, rotated, sum);
    }

    const double average_weight =
        1.0 / static_cast<double>(logical_shape.height * logical_shape.width);
    const size_t physical_channel_size = input_physical_shape.height * input_physical_shape.width;

    poseidon::Ciphertext pooled;
    bool initialized = false;
    for (size_t c = 0; c < input_physical_shape.channels; ++c)
    {
        std::vector<std::complex<double>> mask(slot_count, {0.0, 0.0});
        mask[c * physical_channel_size] = {average_weight, 0.0};

        poseidon::Plaintext plain_mask;
        encoder.encode(mask, sum.parms_id(), scale, plain_mask);

        poseidon::Ciphertext term;
        evaluator.multiply_plain(sum, plain_mask, term);
        const int step = static_cast<int>(c * (physical_channel_size - 1));
        if (step != 0)
        {
            evaluator.rotate(term, term, step, galois_keys);
        }

        if (!initialized)
        {
            pooled = term;
            initialized = true;
        }
        else
        {
            evaluator.add(pooled, term, pooled);
        }
    }

    if (!initialized)
    {
        throw std::invalid_argument("sparse_global_average_pool_encrypted: empty input");
    }
    evaluator.rescale_dynamic(pooled, pooled, scale);
    return pooled;
}

std::vector<int> linear_rotation_steps(size_t input_size, size_t output_size)
{
    std::set<int> steps;
    for (size_t out = 0; out < output_size; ++out)
    {
        for (size_t in = 0; in < input_size; ++in)
        {
            const int step = static_cast<int>(in) - static_cast<int>(out);
            if (step != 0)
            {
                steps.insert(step);
            }
        }
    }
    return {steps.begin(), steps.end()};
}

poseidon::Ciphertext linear_encrypted(const poseidon::Ciphertext &input,
                                      const std::vector<double> &weights,
                                      const std::vector<double> &bias,
                                      size_t input_size,
                                      size_t output_size,
                                      const poseidon::CKKSEncoder &encoder,
                                      const poseidon::EvaluatorCkksBase &evaluator,
                                      const poseidon::GaloisKeys &galois_keys,
                                      double scale, size_t slot_count)
{
    if (input_size > slot_count || output_size > slot_count ||
        weights.size() != input_size * output_size)
    {
        throw std::invalid_argument("linear_encrypted: invalid shape");
    }

    std::map<int, std::vector<std::complex<double>>> masks_by_step;
    for (size_t out = 0; out < output_size; ++out)
    {
        for (size_t in = 0; in < input_size; ++in)
        {
            const int step = static_cast<int>(in) - static_cast<int>(out);
            auto &mask = masks_by_step[step];
            if (mask.empty())
            {
                mask.assign(slot_count, {0.0, 0.0});
            }
            mask[in] += std::complex<double>(weights[out * input_size + in], 0.0);
        }
    }

    poseidon::Ciphertext result;
    bool initialized = false;
    for (const auto &[step, mask] : masks_by_step)
    {
        poseidon::Plaintext plain_mask;
        encoder.encode(mask, input.parms_id(), scale, plain_mask);

        poseidon::Ciphertext term;
        evaluator.multiply_plain(input, plain_mask, term);
        if (step != 0)
        {
            evaluator.rotate(term, term, step, galois_keys);
        }

        if (!initialized)
        {
            result = term;
            initialized = true;
        }
        else
        {
            evaluator.add(result, term, result);
        }
    }

    if (!initialized)
    {
        throw std::invalid_argument("linear_encrypted: linear layer produced no terms");
    }
    evaluator.rescale_dynamic(result, result, scale);

    if (!bias.empty())
    {
        if (bias.size() != output_size)
        {
            throw std::invalid_argument("linear_encrypted: invalid bias shape");
        }
        std::vector<std::complex<double>> bias_slots(slot_count, {0.0, 0.0});
        for (size_t out = 0; out < output_size; ++out)
        {
            bias_slots[out] = {bias[out], 0.0};
        }

        poseidon::Plaintext plain_bias;
        encoder.encode(bias_slots, result.parms_id(), result.scale(), plain_bias);
        evaluator.add_plain(result, plain_bias, result);
    }

    return result;
}

void match_level_and_scale(poseidon::Ciphertext &lhs, poseidon::Ciphertext &rhs,
                           const poseidon::CKKSEncoder &encoder,
                           const poseidon::EvaluatorCkksBase &evaluator,
                           double scale)
{
    if (lhs.level() > rhs.level())
    {
        evaluator.drop_modulus(lhs, lhs, rhs.parms_id());
    }
    else if (lhs.level() < rhs.level())
    {
        evaluator.drop_modulus(rhs, rhs, lhs.parms_id());
    }

    if (!poseidon::util::are_approximate(lhs.scale(), rhs.scale()))
    {
        lhs.scale() = rhs.scale();
        std::vector<std::complex<double>> one(1, {1.0, 0.0});
        poseidon::Plaintext plain_one;

        encoder.encode(one, rhs.parms_id(), scale * scale / rhs.scale(), plain_one);
        evaluator.multiply_plain(rhs, plain_one, rhs);
        evaluator.rescale(rhs, rhs);

        encoder.encode(one, lhs.parms_id(), scale * scale / lhs.scale(), plain_one);
        evaluator.multiply_plain(lhs, plain_one, lhs);
        evaluator.rescale(lhs, lhs);
    }
}

void square_activation_inplace(
    poseidon::Ciphertext &cipher,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::RelinKeys &relin_keys, double scale)
{
    evaluator.multiply_relin(cipher, cipher, cipher, relin_keys);
    evaluator.rescale_dynamic(cipher, cipher, scale);
}

void activation_inplace(poseidon::Ciphertext &cipher,
                        const poseidon::EvaluatorCkksBase &evaluator,
                        const poseidon::RelinKeys &relin_keys,
                        const poseidon::CKKSEncoder &encoder,
                        double scale,
                        const ActivationOptions &activation)
{
    switch (activation.kind)
    {
    case ActivationKind::Square:
        square_activation_inplace(cipher, evaluator, relin_keys, scale);
        return;
    case ActivationKind::AppReLU:
        break;
    }

    if (activation.apprelu_bound <= 0.0)
    {
        throw std::invalid_argument("activation_inplace: AppReLU bound must be positive");
    }

    const poseidon::Ciphertext original = cipher;
    poseidon::Ciphertext sign_approx = divide_decoded_value(cipher, activation.apprelu_bound);

    for (size_t round = 0; round < activation.apprelu_rounds; ++round)
    {
        sign_approx = apprelu_sign_round(sign_approx, evaluator, relin_keys, encoder, scale);
    }

    poseidon::Ciphertext one_plus_sign = add_scalar(sign_approx, 1.0, encoder, evaluator);
    poseidon::Ciphertext result;
    evaluator.multiply_relin_dynamic(original, one_plus_sign, result, relin_keys);
    evaluator.rescale_dynamic(result, result, scale);

    cipher = divide_decoded_value(result, 2.0);
}

} // namespace ResNet20
