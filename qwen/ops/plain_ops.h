#pragma once

#include "core/tensor.h"

#include <cstddef>

namespace qwen
{

Tensor linear(const Tensor &input, const Tensor &weight, const Tensor *bias = nullptr);
Tensor rms_norm(const Tensor &input, const Tensor &weight, double epsilon);
Tensor add(const Tensor &lhs, const Tensor &rhs);
Tensor multiply(const Tensor &lhs, const Tensor &rhs);
Tensor silu(const Tensor &input);
Tensor swiglu(const Tensor &gate, const Tensor &up);

Tensor split_heads(const Tensor &input, std::size_t head_count, std::size_t head_dim);
Tensor merge_heads(const Tensor &input);

// Qwen pairs the first and second halves of each head for rotary embedding.
void apply_rope(Tensor &query, Tensor &key, std::size_t position_offset, double theta);

} // namespace qwen
