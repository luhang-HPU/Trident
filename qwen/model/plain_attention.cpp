#include "model/plain_attention.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace qwen
{
namespace
{

Tensor concatenate_tokens(const Tensor &lhs, const Tensor &rhs)
{
    if (lhs.rank() != 3 || rhs.rank() != 3 || lhs.dim(1) != rhs.dim(1) ||
        lhs.dim(2) != rhs.dim(2))
    {
        throw std::invalid_argument("KV cache append shape mismatch");
    }
    Tensor result({lhs.dim(0) + rhs.dim(0), lhs.dim(1), lhs.dim(2)});
    std::copy(lhs.data().begin(), lhs.data().end(), result.data().begin());
    std::copy(rhs.data().begin(), rhs.data().end(),
              result.data().begin() + static_cast<std::ptrdiff_t>(lhs.numel()));
    return result;
}

void validate_qkv(const Tensor &query, const Tensor &key, const Tensor &value,
                  const QwenConfig &config)
{
    config.validate();
    if (query.rank() != 3 || key.rank() != 3 || value.rank() != 3 ||
        query.dim(0) != key.dim(0) || key.shape() != value.shape() ||
        query.dim(1) != config.num_attention_heads ||
        key.dim(1) != config.num_key_value_heads || query.dim(2) != config.head_dim ||
        key.dim(2) != config.head_dim)
    {
        throw std::invalid_argument("attention Q/K/V shapes do not match Qwen config");
    }
}

} // namespace

bool KVCache::empty() const
{
    return key_.empty();
}

std::size_t KVCache::size() const
{
    return key_.empty() ? 0 : key_.dim(0);
}

void KVCache::clear()
{
    key_ = Tensor{};
    value_ = Tensor{};
}

void KVCache::append(const Tensor &key, const Tensor &value)
{
    if (key.rank() != 3 || key.shape() != value.shape())
    {
        throw std::invalid_argument("KV cache expects matching rank-3 K/V tensors");
    }
    if (empty())
    {
        key_ = key;
        value_ = value;
        return;
    }
    key_ = concatenate_tokens(key_, key);
    value_ = concatenate_tokens(value_, value);
}

const Tensor &KVCache::key() const
{
    if (empty())
    {
        throw std::logic_error("KV cache is empty");
    }
    return key_;
}

const Tensor &KVCache::value() const
{
    if (empty())
    {
        throw std::logic_error("KV cache is empty");
    }
    return value_;
}

Tensor causal_gqa_attention(const Tensor &query, const Tensor &key, const Tensor &value,
                            const QwenConfig &config, KVCache *cache)
{
    validate_qkv(query, key, value, config);

    const Tensor *all_key = &key;
    const Tensor *all_value = &value;
    std::size_t query_position_offset = 0;
    if (cache != nullptr)
    {
        query_position_offset = cache->size();
        cache->append(key, value);
        all_key = &cache->key();
        all_value = &cache->value();
    }

    const std::size_t query_tokens = query.dim(0);
    const std::size_t query_heads = query.dim(1);
    const std::size_t head_dim = query.dim(2);
    const std::size_t group_size = config.query_group_size();
    const double scale = 1.0 / std::sqrt(static_cast<double>(head_dim));
    Tensor output({query_tokens, query_heads, head_dim});

#pragma omp parallel for schedule(static) if (query_tokens * query_heads >= 8)
    for (std::ptrdiff_t task = 0;
         task < static_cast<std::ptrdiff_t>(query_tokens * query_heads); ++task)
    {
        const std::size_t query_token = static_cast<std::size_t>(task) / query_heads;
        const std::size_t query_head = static_cast<std::size_t>(task) % query_heads;
        const std::size_t kv_head = query_head / group_size;
        const std::size_t visible_tokens = query_position_offset + query_token + 1;

        std::vector<double> scores(visible_tokens, 0.0);
        double row_max = -std::numeric_limits<double>::infinity();
        for (std::size_t key_token = 0; key_token < visible_tokens; ++key_token)
        {
            double score = 0.0;
            for (std::size_t feature = 0; feature < head_dim; ++feature)
            {
                score += query.at(query_token, query_head, feature) *
                         all_key->at(key_token, kv_head, feature);
            }
            score *= scale;
            scores[key_token] = score;
            row_max = std::max(row_max, score);
        }

        double denominator = 0.0;
        for (double &score : scores)
        {
            score = std::exp(score - row_max);
            denominator += score;
        }
        for (std::size_t key_token = 0; key_token < visible_tokens; ++key_token)
        {
            const double probability = scores[key_token] / denominator;
            for (std::size_t feature = 0; feature < head_dim; ++feature)
            {
                output.at(query_token, query_head, feature) +=
                    probability * all_value->at(key_token, kv_head, feature);
            }
        }
    }
    return output;
}

} // namespace qwen
