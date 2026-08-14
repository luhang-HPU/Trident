#pragma once

#include "core/tensor.h"
#include "he/approximation.h"
#include "he/comparison.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "model/plain_attention.h"
#include "model/qwen_config.h"

namespace qwen::he
{

class EncryptedKVCache
{
public:
    bool empty() const;
    std::size_t size() const;
    void clear();
    void append(const EncryptedTensor &key,
                const EncryptedTensor &value,
                HeRuntime &runtime);

    const EncryptedTensor &key() const;
    const EncryptedTensor &value() const;

private:
    EncryptedTensor key_;
    EncryptedTensor value_;
};

struct AttentionApproximationConfig
{
    ApproximationConfig exponential;
    ApproximationConfig reciprocal;

    void validate() const;
};

struct StableAttentionApproximationConfig
{
    ComparisonConfig maximum;
    ApproximationConfig exponential;
    ApproximationConfig reciprocal;
    double maximum_bootstrap_value_scale = 1.0;
    double dual_token_bootstrap_value_scale = 1.0;

    void validate() const;
};

Tensor approximate_causal_gqa_attention(
    const Tensor &query, const Tensor &key, const Tensor &value,
    const QwenConfig &model_config,
    const AttentionApproximationConfig &approximation);

EncryptedTensor encrypted_causal_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const AttentionApproximationConfig &approximation,
    HeRuntime &runtime);

Tensor approximate_stable_causal_gqa_attention(
    const Tensor &query, const Tensor &key, const Tensor &value,
    const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    KVCache *cache = nullptr);

EncryptedTensor encrypted_stable_causal_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    HeRuntime &runtime,
    RefreshMode maximum_refresh = RefreshMode::none,
    RefreshMode denominator_refresh = RefreshMode::none);

EncryptedTensor encrypted_stable_cached_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    EncryptedKVCache &cache, HeRuntime &runtime,
    RefreshMode maximum_refresh = RefreshMode::none,
    RefreshMode denominator_refresh = RefreshMode::none);

} // namespace qwen::he
