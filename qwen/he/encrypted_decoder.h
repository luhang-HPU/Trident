#pragma once

#include "he/approximation.h"
#include "he/encrypted_attention.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "model/plain_decoder.h"
#include "model/qwen_config.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace qwen::he
{

struct EncryptedDecoderApproximationConfig
{
    ApproximationConfig input_inverse_sqrt;
    ApproximationConfig post_attention_inverse_sqrt;
    StableAttentionApproximationConfig attention;
    ApproximationConfig silu;
    RefreshMode attention_maximum_refresh = RefreshMode::none;
    RefreshMode post_attention_refresh = RefreshMode::none;
    RefreshMode input_norm_refresh = RefreshMode::none;
    RefreshMode qkv_refresh = RefreshMode::none;
    RefreshMode attention_denominator_refresh = RefreshMode::none;
    RefreshMode attention_output_refresh = RefreshMode::none;
    RefreshMode mlp_input_refresh = RefreshMode::none;
    RefreshMode output_refresh = RefreshMode::none;
    double input_norm_bootstrap_value_scale = 1.0;
    double post_attention_bootstrap_value_scale = 1.0;
    double mlp_input_bootstrap_value_scale = 1.0;
    double output_bootstrap_value_scale = 1.0;
    bool exact_silu_reference = false;
    std::map<std::size_t, ApproximationConfig>
        input_inverse_sqrt_overrides;
    std::map<std::size_t, ApproximationConfig>
        post_attention_inverse_sqrt_overrides;
    std::map<std::size_t, ApproximationConfig>
        silu_overrides;
    std::vector<ApproximationConfig> silu_feature_configs;
    std::map<std::size_t, std::vector<ApproximationConfig>>
        silu_feature_overrides;

    void validate() const;
};

void set_decoder_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    RefreshMode mode);

// Development profile: use a small number of real bootstrap boundaries so a
// small-ring CPU run can validate the complete decoder graph without hiding
// scale/schedule failures behind refreshes at every operator.
void set_decoder_boundary_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config);

// Bootstrap-mock validation schedule after the degree-15 RMSNorm and
// degree-31 SiLU depth reductions. All arithmetic remains encrypted; only
// the selected refresh boundaries decrypt and re-encrypt.
void set_decoder_reduced_mock_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    bool multi_token_attention);

// The calibrated Qwen2.5 RMSNorm and SiLU circuits fit between residual
// refreshes, so neither normalized activation needs its own refresh.
void remove_redundant_rmsnorm_refreshes(
    EncryptedDecoderApproximationConfig &config);

// A causal Attention row with one key returns V exactly and skips the
// maximum/exp/reciprocal circuit. Q/K/V and the returned V do not need to be
// refreshed before output projection, regardless of whether the remaining
// boundaries are mock or real bootstraps.
void remove_single_token_attention_refreshes(
    EncryptedDecoderApproximationConfig &config);

using EncryptedTraceCallback =
    std::function<void(const std::string &, const EncryptedTensor &)>;
using PlainTraceCallback =
    std::function<void(const std::string &, const Tensor &)>;

Tensor approximate_decoder_layer(
    const Tensor &input, const DecoderLayerWeights &weights,
    const QwenConfig &model_config,
    const EncryptedDecoderApproximationConfig &approximation,
    std::size_t position_offset,
    const PlainTraceCallback &trace = {},
    KVCache *cache = nullptr);

EncryptedTensor encrypted_decoder_layer(
    const EncryptedTensor &input, const DecoderLayerWeights &weights,
    const QwenConfig &model_config,
    const EncryptedDecoderApproximationConfig &approximation,
    std::size_t position_offset, HeRuntime &runtime,
    const EncryptedTraceCallback &trace = {},
    EncryptedKVCache *cache = nullptr);

} // namespace qwen::he
