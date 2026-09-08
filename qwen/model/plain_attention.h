#pragma once

#include "core/tensor.h"
#include "model/qwen_config.h"

#include <cstddef>

namespace qwen
{

class KVCache
{
public:
    bool empty() const;
    std::size_t size() const;
    void clear();
    void append(const Tensor &key, const Tensor &value);

    const Tensor &key() const;
    const Tensor &value() const;

private:
    Tensor key_;
    Tensor value_;
};

Tensor causal_gqa_attention(const Tensor &query, const Tensor &key, const Tensor &value,
                            const QwenConfig &config, KVCache *cache = nullptr);

} // namespace qwen
