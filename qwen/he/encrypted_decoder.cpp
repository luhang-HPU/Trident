#include "he/encrypted_decoder.h"

#include "ops/plain_ops.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace qwen::he
{

namespace
{

const Tensor *optional_bias(const Tensor &bias)
{
    return bias.empty() ? nullptr : &bias;
}

void trace_tensor(const EncryptedTraceCallback &trace,
                  const char *name, const EncryptedTensor &tensor)
{
    if (trace)
    {
        trace(name, tensor);
    }
}

void trace_plain(const PlainTraceCallback &trace, const char *name,
                 const Tensor &tensor)
{
    if (trace)
    {
        trace(name, tensor);
    }
}

EncryptedTensor apply_linear(const EncryptedTensor &input,
                             const Tensor &weight,
                             const Tensor *bias,
                             HeRuntime &runtime)
{
    const poseidon::Ciphertext *lowest = nullptr;
    std::size_t lowest_level =
        std::numeric_limits<std::size_t>::max();
    for (const poseidon::Ciphertext &cipher : input.ciphertexts())
    {
        const std::size_t level = runtime.chain_index(cipher);
        if (level < lowest_level)
        {
            lowest = &cipher;
            lowest_level = level;
        }
    }
    if (lowest == nullptr)
    {
        throw std::invalid_argument(
            "decoder Linear received an empty encrypted tensor");
    }
    std::vector<poseidon::Ciphertext> aligned_ciphers;
    aligned_ciphers.reserve(input.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : input.ciphertexts())
    {
        if (cipher.parms_id() == lowest->parms_id())
        {
            aligned_ciphers.push_back(cipher);
        }
        else
        {
            poseidon::Ciphertext aligned;
            runtime.evaluator->drop_modulus(
                cipher, aligned, lowest->parms_id());
            aligned_ciphers.push_back(std::move(aligned));
        }
    }
    const EncryptedTensor aligned(
        input.layout(), std::move(aligned_ciphers));
    const EncodedLinear encoded =
        encode_linear_at(weight, aligned.cipher(0, 0), runtime);
    return encrypted_linear(aligned, encoded, bias, runtime);
}

std::map<std::size_t, ApproximationConfig>
local_position_overrides(
    const std::map<std::size_t, ApproximationConfig> &absolute,
    std::size_t position_offset, std::size_t token_count)
{
    std::map<std::size_t, ApproximationConfig> local;
    for (const auto &[position, config] : absolute)
    {
        if (position >= position_offset &&
            position - position_offset < token_count)
        {
            local.emplace(position - position_offset, config);
        }
    }
    return local;
}

std::map<std::size_t, std::vector<ApproximationConfig>>
local_position_feature_overrides(
    const std::map<std::size_t, std::vector<ApproximationConfig>> &absolute,
    std::size_t position_offset, std::size_t token_count)
{
    std::map<std::size_t, std::vector<ApproximationConfig>> local;
    for (const auto &[position, configs] : absolute)
    {
        if (position >= position_offset &&
            position - position_offset < token_count)
        {
            local.emplace(position - position_offset, configs);
        }
    }
    return local;
}

void log_tensor_metadata(const EncryptedTensor &tensor,
                         HeRuntime &runtime)
{
    std::size_t minimum_level = std::numeric_limits<std::size_t>::max();
    std::size_t maximum_level = 0;
    for (const poseidon::Ciphertext &cipher : tensor.ciphertexts())
    {
        const std::size_t level = runtime.chain_index(cipher);
        minimum_level = std::min(minimum_level, level);
        maximum_level = std::max(maximum_level, level);
    }
    std::cout << " tokens=" << tensor.layout().tokens
              << " features=" << tensor.layout().features
              << " ciphers=" << tensor.ciphertexts().size();
    if (!tensor.ciphertexts().empty())
    {
        const std::size_t active_slots =
            tensor.layout().tokens * tensor.layout().features;
        const std::size_t available_slots =
            tensor.ciphertexts().size() * tensor.layout().slot_count;
        std::cout << " level_min=" << minimum_level
                  << " level_max=" << maximum_level
                  << " active_slots=" << active_slots
                  << " slot_utilization="
                  << static_cast<double>(active_slots) /
                         static_cast<double>(available_slots);
    }
}

template <typename Function>
EncryptedTensor logged_operation(const char *name,
                                 const EncryptedTensor &input,
                                 HeRuntime &runtime,
                                 Function &&function)
{
    if (!runtime.operation_logging())
    {
        return function();
    }
    const std::string operation =
        runtime.operation_context() + '.' + name;
    std::cout << "operation=" << operation << " event=start";
    log_tensor_metadata(input, runtime);
    std::cout << '\n';
    const auto start = std::chrono::steady_clock::now();
    try
    {
        EncryptedTensor output = function();
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start)
                .count();
        std::cout << "operation=" << operation
                  << " event=end duration_ms=" << elapsed;
        log_tensor_metadata(output, runtime);
        std::cout << '\n';
        return output;
    }
    catch (const std::exception &error)
    {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start)
                .count();
        std::cerr << "operation=" << operation
                  << " event=error duration_ms=" << elapsed
                  << " message=" << error.what() << '\n';
        throw;
    }
}

} // namespace

void EncryptedDecoderApproximationConfig::validate() const
{
    input_inverse_sqrt.validate();
    post_attention_inverse_sqrt.validate();
    attention.validate();
    silu.validate();
    const double scales[] = {
        input_norm_bootstrap_value_scale,
        query_key_bootstrap_value_scale,
        post_attention_bootstrap_value_scale,
        mlp_input_bootstrap_value_scale,
        output_bootstrap_value_scale};
    for (double scale : scales)
    {
        if (!std::isfinite(scale) || scale <= 0.0)
        {
            throw std::invalid_argument(
                "decoder bootstrap value scale must be finite and positive");
        }
    }
    for (const auto &[position, config] :
         input_inverse_sqrt_overrides)
    {
        static_cast<void>(position);
        config.validate();
    }
    for (const auto &[position, config] :
         post_attention_inverse_sqrt_overrides)
    {
        static_cast<void>(position);
        config.validate();
    }
    for (const auto &[position, config] : silu_overrides)
    {
        static_cast<void>(position);
        config.validate();
    }
    for (const ApproximationConfig &config : silu_feature_configs)
    {
        config.validate();
    }
    for (const auto &[position, configs] : silu_feature_overrides)
    {
        static_cast<void>(position);
        if (!silu_feature_configs.empty() &&
            configs.size() != silu_feature_configs.size())
        {
            throw std::invalid_argument(
                "position SiLU feature calibration has the wrong width");
        }
        for (const ApproximationConfig &config : configs)
        {
            config.validate();
        }
    }
}

void set_decoder_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    RefreshMode mode)
{
    if (mode != RefreshMode::debug_bootstrap &&
        mode != RefreshMode::bootstrap)
    {
        throw std::invalid_argument(
            "decoder bootstrap schedule requires a bootstrap refresh mode");
    }
    config.attention_maximum_refresh = mode;
    config.post_attention_refresh = mode;
    // Input RMSNorm leaves enough depth for Q/K/V projection and RoPE. A
    // refresh here only adds bootstrap latency and error; later Attention
    // boundaries are responsible for refreshing paths that need more depth.
    config.input_norm_refresh = RefreshMode::none;
    config.qkv_refresh = mode;
    config.attention_denominator_refresh = mode;
    config.attention_output_refresh = mode;
    config.mlp_input_refresh = mode;
    config.output_refresh = mode;
}

void set_decoder_boundary_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config)
{
    config.attention_maximum_refresh = RefreshMode::none;
    config.post_attention_refresh = RefreshMode::bootstrap;
    config.input_norm_refresh = RefreshMode::none;
    config.qkv_refresh = RefreshMode::none;
    config.attention_denominator_refresh = RefreshMode::none;
    config.attention_output_refresh = RefreshMode::none;
    config.mlp_input_refresh = RefreshMode::none;
    config.output_refresh = RefreshMode::bootstrap;
}

void set_decoder_dual_token_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    RefreshMode mode)
{
    set_decoder_multi_token_bootstrap_schedule(config, mode, 2);
}

void set_decoder_multi_token_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    RefreshMode mode, std::size_t maximum_tokens)
{
    if (mode != RefreshMode::debug_bootstrap &&
        mode != RefreshMode::bootstrap)
    {
        throw std::invalid_argument(
            "multi-token bootstrap schedule requires a bootstrap refresh mode");
    }
    if (maximum_tokens < 2)
    {
        throw std::invalid_argument(
            "multi-token bootstrap schedule requires at least two tokens");
    }
    // Form Attention scores before refreshing so bootstrap error is not
    // amplified by the Q/K dot product. Q/K/V and the Attention output retain
    // enough depth to reach their next nonlinear or residual boundary.
    config.input_norm_refresh = RefreshMode::none;
    config.qkv_refresh = RefreshMode::none;
    config.attention_maximum_refresh = mode;
    config.attention_denominator_refresh =
        maximum_tokens == 2 ? RefreshMode::none : mode;
    config.attention_output_refresh = RefreshMode::none;
    config.post_attention_refresh = mode;
    config.mlp_input_refresh = RefreshMode::none;
    config.output_refresh = mode;
}

void set_decoder_reduced_mock_bootstrap_schedule(
    EncryptedDecoderApproximationConfig &config,
    bool multi_token_attention)
{
    config.input_norm_refresh = RefreshMode::none;
    config.qkv_refresh = multi_token_attention
                             ? RefreshMode::debug_bootstrap
                             : RefreshMode::none;
    config.attention_maximum_refresh = multi_token_attention
                                           ? RefreshMode::debug_bootstrap
                                           : RefreshMode::none;
    config.attention_denominator_refresh = multi_token_attention
                                               ? RefreshMode::debug_bootstrap
                                               : RefreshMode::none;
    config.attention_output_refresh = RefreshMode::none;
    config.post_attention_refresh = RefreshMode::debug_bootstrap;
    config.mlp_input_refresh = RefreshMode::none;
    config.output_refresh = RefreshMode::debug_bootstrap;
}

void remove_redundant_rmsnorm_refreshes(
    EncryptedDecoderApproximationConfig &config)
{
    config.input_norm_refresh = RefreshMode::none;
    config.mlp_input_refresh = RefreshMode::none;
}

void remove_single_token_attention_refreshes(
    EncryptedDecoderApproximationConfig &config)
{
    config.qkv_refresh = RefreshMode::none;
    config.attention_maximum_refresh = RefreshMode::none;
    config.attention_denominator_refresh = RefreshMode::none;
    config.attention_output_refresh = RefreshMode::none;
}

Tensor approximate_decoder_layer(
    const Tensor &input, const DecoderLayerWeights &weights,
    const QwenConfig &model_config,
    const EncryptedDecoderApproximationConfig &approximation,
    std::size_t position_offset, const PlainTraceCallback &trace,
    KVCache *cache)
{
    model_config.validate();
    weights.validate(model_config);
    approximation.validate();
    if (input.rank() != 2 ||
        input.dim(1) != model_config.hidden_size)
    {
        throw std::invalid_argument(
            "approximate decoder input shape is invalid");
    }

    const auto input_overrides = local_position_overrides(
        approximation.input_inverse_sqrt_overrides,
        position_offset, input.dim(0));
    const auto post_overrides = local_position_overrides(
        approximation.post_attention_inverse_sqrt_overrides,
        position_offset, input.dim(0));
    const auto silu_overrides = local_position_overrides(
        approximation.silu_overrides,
        position_offset, input.dim(0));
    const auto silu_feature_overrides =
        local_position_feature_overrides(
            approximation.silu_feature_overrides,
            position_offset, input.dim(0));
    const Tensor normalized = approximate_rms_norm_plain(
        input, weights.input_norm, model_config.rms_norm_epsilon,
        approximation.input_inverse_sqrt,
        input_overrides);
    trace_plain(trace, "input_rmsnorm", normalized);
    if (approximation.input_norm_refresh != RefreshMode::none)
    {
        trace_plain(trace, "input_rmsnorm_refreshed", normalized);
    }
    const Tensor query_projection = linear(
        normalized, weights.query_weight,
        optional_bias(weights.query_bias));
    const Tensor key_projection = linear(
        normalized, weights.key_weight,
        optional_bias(weights.key_bias));
    const Tensor value_projection = linear(
        normalized, weights.value_weight,
        optional_bias(weights.value_bias));
    trace_plain(trace, "query_projection", query_projection);
    trace_plain(trace, "key_projection", key_projection);
    trace_plain(trace, "value_projection", value_projection);

    Tensor query = split_heads(
        query_projection, model_config.num_attention_heads,
        model_config.head_dim);
    Tensor key = split_heads(
        key_projection, model_config.num_key_value_heads,
        model_config.head_dim);
    const Tensor value = split_heads(
        value_projection, model_config.num_key_value_heads,
        model_config.head_dim);
    apply_rope(query, key, position_offset, model_config.rope_theta);
    trace_plain(trace, "query_rope",
                query.reshape(
                    {input.dim(0), model_config.hidden_size}));
    trace_plain(
        trace, "key_rope",
        key.reshape(
            {input.dim(0),
             model_config.num_key_value_heads *
                 model_config.head_dim}));
    if (approximation.qkv_refresh != RefreshMode::none)
    {
        trace_plain(
            trace, "query_rope_refreshed",
            query.reshape(
                {input.dim(0), model_config.hidden_size}));
        trace_plain(
            trace, "key_rope_refreshed",
            key.reshape(
                {input.dim(0),
                 model_config.num_key_value_heads *
                     model_config.head_dim}));
        trace_plain(trace, "value_refreshed", value_projection);
    }

    const Tensor attention = approximate_stable_causal_gqa_attention(
        query, key, value, model_config, approximation.attention,
        cache);
    trace_plain(trace, "attention",
                attention.reshape(
                    {input.dim(0), model_config.hidden_size}));
    if (approximation.attention_output_refresh != RefreshMode::none)
    {
        trace_plain(trace, "attention_refreshed",
                    attention.reshape(
                        {input.dim(0), model_config.hidden_size}));
    }
    const Tensor attention_output = linear(
        merge_heads(attention), weights.output_weight);
    trace_plain(trace, "attention_output", attention_output);
    const Tensor post_attention = add(input, attention_output);
    trace_plain(trace, "post_attention_residual", post_attention);
    trace_plain(trace, "post_attention_refreshed", post_attention);

    const Tensor mlp_input = approximate_rms_norm_plain(
        post_attention, weights.post_attention_norm,
        model_config.rms_norm_epsilon,
        approximation.post_attention_inverse_sqrt,
        post_overrides);
    trace_plain(trace, "post_attention_rmsnorm", mlp_input);
    if (approximation.mlp_input_refresh != RefreshMode::none)
    {
        trace_plain(trace, "post_attention_rmsnorm_refreshed",
                    mlp_input);
    }
    const Tensor gate = linear(mlp_input, weights.gate_weight);
    const Tensor up = linear(mlp_input, weights.up_weight);
    trace_plain(trace, "mlp_gate", gate);
    trace_plain(trace, "mlp_up", up);
    const Tensor activated_gate =
        approximation.exact_silu_reference
            ? silu(gate)
            : approximate_silu_plain(
                  gate, approximation.silu,
                  silu_overrides,
                  approximation.silu_feature_configs,
                  silu_feature_overrides);
    trace_plain(trace, "mlp_silu", activated_gate);
    const Tensor swiglu = multiply(activated_gate, up);
    trace_plain(trace, "mlp_swiglu", swiglu);
    const Tensor mlp_output = linear(swiglu, weights.down_weight);
    trace_plain(trace, "mlp_output", mlp_output);
    const Tensor output = add(post_attention, mlp_output);
    trace_plain(trace, "output", output);
    if (approximation.output_refresh != RefreshMode::none)
    {
        trace_plain(trace, "output_refreshed", output);
    }
    return output;
}

EncryptedTensor encrypted_decoder_layer(
    const EncryptedTensor &input, const DecoderLayerWeights &weights,
    const QwenConfig &model_config,
    const EncryptedDecoderApproximationConfig &approximation,
    std::size_t position_offset, HeRuntime &runtime,
    const EncryptedTraceCallback &trace,
    EncryptedKVCache *cache)
{
    model_config.validate();
    weights.validate(model_config);
    approximation.validate();
    if (input.layout().features != model_config.hidden_size)
    {
        throw std::invalid_argument(
            "encrypted decoder input width does not match the model");
    }

    const auto input_overrides = local_position_overrides(
        approximation.input_inverse_sqrt_overrides,
        position_offset, input.layout().tokens);
    const auto post_overrides = local_position_overrides(
        approximation.post_attention_inverse_sqrt_overrides,
        position_offset, input.layout().tokens);
    const auto silu_overrides = local_position_overrides(
        approximation.silu_overrides,
        position_offset, input.layout().tokens);
    const auto silu_feature_overrides =
        local_position_feature_overrides(
            approximation.silu_feature_overrides,
            position_offset, input.layout().tokens);
    EncryptedTensor normalized = logged_operation(
        "input_rmsnorm", input, runtime, [&] {
            return encrypted_rms_norm(
                input, weights.input_norm,
                model_config.rms_norm_epsilon,
                approximation.input_inverse_sqrt,
                input_overrides, runtime);
        });
    trace_tensor(trace, "input_rmsnorm", normalized);
    if (approximation.input_norm_refresh != RefreshMode::none)
    {
        normalized = logged_operation(
            "input_rmsnorm_refresh", normalized, runtime, [&] {
                return encrypted_refresh_at_scale(
                    normalized, approximation.input_norm_refresh,
                    approximation.input_norm_bootstrap_value_scale,
                    runtime);
            });
        trace_tensor(trace, "input_rmsnorm_refreshed", normalized);
    }

    const EncryptedTensor query = logged_operation(
        "query_projection", normalized, runtime, [&] {
            return apply_linear(
                normalized, weights.query_weight,
                optional_bias(weights.query_bias), runtime);
        });
    trace_tensor(trace, "query_projection", query);
    const EncryptedTensor key = logged_operation(
        "key_projection", normalized, runtime, [&] {
            return apply_linear(
                normalized, weights.key_weight,
                optional_bias(weights.key_bias), runtime);
        });
    trace_tensor(trace, "key_projection", key);
    EncryptedTensor value = logged_operation(
        "value_projection", normalized, runtime, [&] {
            return apply_linear(
                normalized, weights.value_weight,
                optional_bias(weights.value_bias), runtime);
        });
    trace_tensor(trace, "value_projection", value);

    EncryptedTensor query_rope = logged_operation(
        "query_rope", query, runtime, [&] {
            return encrypted_rope(
                query, model_config.num_attention_heads,
                model_config.head_dim, position_offset,
                model_config.rope_theta, runtime);
        });
    trace_tensor(trace, "query_rope", query_rope);
    EncryptedTensor key_rope = logged_operation(
        "key_rope", key, runtime, [&] {
            return encrypted_rope(
                key, model_config.num_key_value_heads,
                model_config.head_dim, position_offset,
                model_config.rope_theta, runtime);
        });
    trace_tensor(trace, "key_rope", key_rope);
    if (approximation.qkv_refresh != RefreshMode::none)
    {
        query_rope = logged_operation(
            "query_rope_refresh", query_rope, runtime, [&] {
                return encrypted_refresh_at_scale(
                    query_rope, approximation.qkv_refresh,
                    approximation.query_key_bootstrap_value_scale,
                    runtime);
            });
        key_rope = logged_operation(
            "key_rope_refresh", key_rope, runtime, [&] {
                return encrypted_refresh_at_scale(
                    key_rope, approximation.qkv_refresh,
                    approximation.query_key_bootstrap_value_scale,
                    runtime);
            });
        value = logged_operation(
            "value_refresh", value, runtime, [&] {
                return encrypted_refresh(
                    value, approximation.qkv_refresh, runtime);
            });
        trace_tensor(trace, "query_rope_refreshed", query_rope);
        trace_tensor(trace, "key_rope_refreshed", key_rope);
        trace_tensor(trace, "value_refreshed", value);
    }

    EncryptedTensor attention = logged_operation(
        cache == nullptr ? "attention" : "cached_attention",
        query_rope, runtime, [&] {
            return cache == nullptr
                       ? encrypted_stable_causal_gqa_attention(
                             query_rope, key_rope, value, model_config,
                             approximation.attention, runtime,
                             approximation.attention_maximum_refresh,
                             approximation.attention_denominator_refresh)
                       : encrypted_stable_cached_gqa_attention(
                             query_rope, key_rope, value, model_config,
                             approximation.attention, *cache, runtime,
                             approximation.attention_maximum_refresh,
                             approximation.attention_denominator_refresh);
        });
    trace_tensor(trace, "attention", attention);
    if (approximation.attention_output_refresh != RefreshMode::none)
    {
        attention = logged_operation(
            "attention_refresh", attention, runtime, [&] {
                return encrypted_refresh(
                    attention,
                    approximation.attention_output_refresh, runtime);
            });
        trace_tensor(trace, "attention_refreshed", attention);
    }
    const EncryptedTensor attention_output = logged_operation(
        "attention_output_projection", attention, runtime, [&] {
            return apply_linear(
                attention, weights.output_weight, nullptr, runtime);
        });
    trace_tensor(trace, "attention_output", attention_output);

    EncryptedTensor post_attention = logged_operation(
        "post_attention_residual", input, runtime, [&] {
            return encrypted_add(input, attention_output, runtime);
        });
    trace_tensor(trace, "post_attention_residual", post_attention);
    post_attention = logged_operation(
        "post_attention_refresh", post_attention, runtime, [&] {
            return encrypted_refresh_at_scale(
                post_attention,
                approximation.post_attention_refresh,
                approximation.post_attention_bootstrap_value_scale,
                runtime);
        });
    trace_tensor(trace, "post_attention_refreshed", post_attention);

    EncryptedTensor mlp_input = logged_operation(
        "post_attention_rmsnorm", post_attention, runtime, [&] {
            return encrypted_rms_norm(
                post_attention, weights.post_attention_norm,
                model_config.rms_norm_epsilon,
                approximation.post_attention_inverse_sqrt,
                post_overrides, runtime);
        });
    trace_tensor(trace, "post_attention_rmsnorm", mlp_input);
    if (approximation.mlp_input_refresh != RefreshMode::none)
    {
        mlp_input = logged_operation(
            "mlp_input_refresh", mlp_input, runtime, [&] {
                return encrypted_refresh_at_scale(
                    mlp_input, approximation.mlp_input_refresh,
                    approximation.mlp_input_bootstrap_value_scale,
                    runtime);
            });
        trace_tensor(trace, "post_attention_rmsnorm_refreshed",
                     mlp_input);
    }
    const EncryptedTensor gate = logged_operation(
        "mlp_gate_projection", mlp_input, runtime, [&] {
            return apply_linear(
                mlp_input, weights.gate_weight, nullptr, runtime);
        });
    trace_tensor(trace, "mlp_gate", gate);
    const EncryptedTensor up = logged_operation(
        "mlp_up_projection", mlp_input, runtime, [&] {
            return apply_linear(
                mlp_input, weights.up_weight, nullptr, runtime);
        });
    trace_tensor(trace, "mlp_up", up);
    const EncryptedTensor activated_gate = logged_operation(
        "mlp_silu", gate, runtime, [&] {
            return encrypted_silu(
                gate, approximation.silu,
                silu_overrides,
                approximation.silu_feature_configs,
                silu_feature_overrides, runtime);
        });
    trace_tensor(trace, "mlp_silu", activated_gate);
    const EncryptedTensor swiglu = logged_operation(
        "mlp_swiglu", activated_gate, runtime, [&] {
            return encrypted_multiply(activated_gate, up, runtime);
        });
    trace_tensor(trace, "mlp_swiglu", swiglu);
    const EncryptedTensor mlp_output = logged_operation(
        "mlp_down_projection", swiglu, runtime, [&] {
            return apply_linear(
                swiglu, weights.down_weight, nullptr, runtime);
        });
    trace_tensor(trace, "mlp_output", mlp_output);
    EncryptedTensor output = logged_operation(
        "output_residual", post_attention, runtime, [&] {
            return encrypted_add(post_attention, mlp_output, runtime);
        });
    trace_tensor(trace, "output", output);
    if (approximation.output_refresh != RefreshMode::none)
    {
        output = logged_operation(
            "output_refresh", output, runtime, [&] {
                return encrypted_refresh_at_scale(
                    output, approximation.output_refresh,
                    approximation.output_bootstrap_value_scale,
                    runtime);
            });
        trace_tensor(trace, "output_refreshed", output);
    }
    return output;
}

} // namespace qwen::he
