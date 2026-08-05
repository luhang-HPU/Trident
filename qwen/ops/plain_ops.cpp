#include "ops/plain_ops.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace qwen
{
namespace
{

void require_same_shape(const Tensor &lhs, const Tensor &rhs, const char *operation)
{
    if (lhs.shape() != rhs.shape())
    {
        throw std::invalid_argument(std::string(operation) + " requires matching tensor shapes");
    }
}

void rotate_one(Tensor &tensor, std::size_t token, std::size_t head, double theta,
                std::size_t position)
{
    const std::size_t head_dim = tensor.dim(2);
    const std::size_t half = head_dim / 2;
    for (std::size_t index = 0; index < half; ++index)
    {
        const double frequency =
            std::pow(theta, -2.0 * static_cast<double>(index) / static_cast<double>(head_dim));
        const double angle = static_cast<double>(position) * frequency;
        const double cosine = std::cos(angle);
        const double sine = std::sin(angle);
        const double first = tensor.at(token, head, index);
        const double second = tensor.at(token, head, index + half);
        tensor.at(token, head, index) = first * cosine - second * sine;
        tensor.at(token, head, index + half) = second * cosine + first * sine;
    }
}

} // namespace

Tensor linear(const Tensor &input, const Tensor &weight, const Tensor *bias)
{
    if (input.rank() != 2 || weight.rank() != 2)
    {
        throw std::invalid_argument("linear expects rank-2 input and weight");
    }
    const std::size_t rows = input.dim(0);
    const std::size_t input_size = input.dim(1);
    const std::size_t output_size = weight.dim(0);
    if (weight.dim(1) != input_size)
    {
        throw std::invalid_argument("linear input size does not match weight");
    }
    if (bias != nullptr && (bias->rank() != 1 || bias->dim(0) != output_size))
    {
        throw std::invalid_argument("linear bias size does not match weight");
    }

    Tensor output({rows, output_size});
    const double *input_data = input.data().data();
    const double *weight_data = weight.data().data();
    const double *bias_data = bias == nullptr ? nullptr : bias->data().data();
    double *output_data = output.data().data();
#pragma omp parallel for schedule(static) if (rows * output_size >= 64)
    for (std::ptrdiff_t row_output = 0;
         row_output < static_cast<std::ptrdiff_t>(rows * output_size); ++row_output)
    {
        const std::size_t row = static_cast<std::size_t>(row_output) / output_size;
        const std::size_t output_index = static_cast<std::size_t>(row_output) % output_size;
        const double *input_row = input_data + row * input_size;
        const double *weight_row = weight_data + output_index * input_size;
        double sum = bias_data == nullptr ? 0.0 : bias_data[output_index];
        for (std::size_t input_index = 0; input_index < input_size; ++input_index)
        {
            sum += input_row[input_index] * weight_row[input_index];
        }
        output_data[row * output_size + output_index] = sum;
    }
    return output;
}

Tensor rms_norm(const Tensor &input, const Tensor &weight, double epsilon)
{
    if (input.rank() != 2 || weight.rank() != 1 || input.dim(1) != weight.dim(0))
    {
        throw std::invalid_argument("RMSNorm expects [tokens, hidden] input and [hidden] weight");
    }
    if (epsilon <= 0.0)
    {
        throw std::invalid_argument("RMSNorm epsilon must be positive");
    }

    Tensor output(input.shape());
    const std::size_t rows = input.dim(0);
    const std::size_t hidden = input.dim(1);
#pragma omp parallel for schedule(static) if (rows >= 4)
    for (std::ptrdiff_t row_index = 0; row_index < static_cast<std::ptrdiff_t>(rows); ++row_index)
    {
        const std::size_t row = static_cast<std::size_t>(row_index);
        double square_sum = 0.0;
        for (std::size_t column = 0; column < hidden; ++column)
        {
            const double value = input.at(row, column);
            square_sum += value * value;
        }
        const double inverse_rms =
            1.0 / std::sqrt(square_sum / static_cast<double>(hidden) + epsilon);
        for (std::size_t column = 0; column < hidden; ++column)
        {
            output.at(row, column) = input.at(row, column) * inverse_rms * weight.at(column);
        }
    }
    return output;
}

Tensor add(const Tensor &lhs, const Tensor &rhs)
{
    require_same_shape(lhs, rhs, "add");
    Tensor output(lhs.shape());
#pragma omp parallel for schedule(static) if (lhs.numel() >= 256)
    for (std::ptrdiff_t index = 0; index < static_cast<std::ptrdiff_t>(lhs.numel()); ++index)
    {
        output.data()[static_cast<std::size_t>(index)] =
            lhs.data()[static_cast<std::size_t>(index)] +
            rhs.data()[static_cast<std::size_t>(index)];
    }
    return output;
}

Tensor multiply(const Tensor &lhs, const Tensor &rhs)
{
    require_same_shape(lhs, rhs, "multiply");
    Tensor output(lhs.shape());
#pragma omp parallel for schedule(static) if (lhs.numel() >= 256)
    for (std::ptrdiff_t index = 0; index < static_cast<std::ptrdiff_t>(lhs.numel()); ++index)
    {
        output.data()[static_cast<std::size_t>(index)] =
            lhs.data()[static_cast<std::size_t>(index)] *
            rhs.data()[static_cast<std::size_t>(index)];
    }
    return output;
}

Tensor silu(const Tensor &input)
{
    Tensor output(input.shape());
#pragma omp parallel for schedule(static) if (input.numel() >= 256)
    for (std::ptrdiff_t index = 0; index < static_cast<std::ptrdiff_t>(input.numel()); ++index)
    {
        const double value = input.data()[static_cast<std::size_t>(index)];
        output.data()[static_cast<std::size_t>(index)] = value / (1.0 + std::exp(-value));
    }
    return output;
}

Tensor swiglu(const Tensor &gate, const Tensor &up)
{
    require_same_shape(gate, up, "SwiGLU");
    return multiply(silu(gate), up);
}

Tensor split_heads(const Tensor &input, std::size_t head_count, std::size_t head_dim)
{
    if (input.rank() != 2 || input.dim(1) != head_count * head_dim)
    {
        throw std::invalid_argument("cannot split tensor into requested heads");
    }
    return input.reshape({input.dim(0), head_count, head_dim});
}

Tensor merge_heads(const Tensor &input)
{
    if (input.rank() != 3)
    {
        throw std::invalid_argument("merge_heads expects [tokens, heads, head_dim]");
    }
    return input.reshape({input.dim(0), input.dim(1) * input.dim(2)});
}

void apply_rope(Tensor &query, Tensor &key, std::size_t position_offset, double theta)
{
    if (query.rank() != 3 || key.rank() != 3 || query.dim(0) != key.dim(0) ||
        query.dim(2) != key.dim(2) || query.dim(2) % 2 != 0 || theta <= 0.0)
    {
        throw std::invalid_argument("invalid Q/K tensors for RoPE");
    }

    for (std::size_t token = 0; token < query.dim(0); ++token)
    {
        const std::size_t position = position_offset + token;
        for (std::size_t head = 0; head < query.dim(1); ++head)
        {
            rotate_one(query, token, head, theta, position);
        }
        for (std::size_t head = 0; head < key.dim(1); ++head)
        {
            rotate_one(key, token, head, theta, position);
        }
    }
}

} // namespace qwen
