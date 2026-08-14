#include "he/encrypted_attention.h"

#include "he/encrypted_ops.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace qwen::he
{

namespace
{

void log_attention_tensor_metadata(const EncryptedTensor &tensor,
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
        std::cout << " level_min=" << minimum_level
                  << " level_max=" << maximum_level;
    }
}

template <typename Function>
EncryptedTensor logged_attention_tensor_operation(
    const std::string &name, const EncryptedTensor &input,
    HeRuntime &runtime, Function &&function)
{
    if (!runtime.operation_logging())
    {
        return function();
    }
    const std::string operation =
        runtime.operation_context() + ".attention." + name;
    std::cout << "operation=" << operation << " event=start";
    log_attention_tensor_metadata(input, runtime);
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
        log_attention_tensor_metadata(output, runtime);
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

Tensor flat_to_heads(const Tensor &flat, std::size_t heads,
                     std::size_t head_dim)
{
    if (flat.rank() != 2 || flat.dim(1) != heads * head_dim)
    {
        throw std::invalid_argument("mock attention tensor shape is invalid");
    }
    Tensor result({flat.dim(0), heads, head_dim});
    for (std::size_t token = 0; token < flat.dim(0); ++token)
    {
        for (std::size_t head = 0; head < heads; ++head)
        {
            for (std::size_t feature = 0; feature < head_dim; ++feature)
            {
                result.at(token, head, feature) =
                    flat.at(token, head * head_dim + feature);
            }
        }
    }
    return result;
}

Tensor heads_to_flat(const Tensor &heads, std::size_t head_count,
                     std::size_t head_dim)
{
    if (heads.rank() != 3 || heads.dim(1) != head_count ||
        heads.dim(2) != head_dim)
    {
        throw std::invalid_argument("mock attention output shape is invalid");
    }
    Tensor result({heads.dim(0), head_count * head_dim});
    for (std::size_t token = 0; token < heads.dim(0); ++token)
    {
        for (std::size_t head = 0; head < head_count; ++head)
        {
            for (std::size_t feature = 0; feature < head_dim; ++feature)
            {
                result.at(token, head * head_dim + feature) =
                    heads.at(token, head, feature);
            }
        }
    }
    return result;
}

void validate_plain_qkv(const Tensor &query, const Tensor &key,
                        const Tensor &value,
                        const QwenConfig &config)
{
    config.validate();
    if (query.rank() != 3 || key.rank() != 3 || value.rank() != 3 ||
        query.dim(0) != key.dim(0) || key.shape() != value.shape() ||
        query.dim(1) != config.num_attention_heads ||
        key.dim(1) != config.num_key_value_heads ||
        query.dim(2) != config.head_dim ||
        key.dim(2) != config.head_dim)
    {
        throw std::invalid_argument(
            "approximated attention Q/K/V shapes do not match Qwen config");
    }
}

void validate_encrypted_qkv(const EncryptedTensor &query,
                            const EncryptedTensor &key,
                            const EncryptedTensor &value,
                            const QwenConfig &config)
{
    config.validate();
    const std::size_t tokens = query.layout().tokens;
    const std::size_t query_features =
        config.num_attention_heads * config.head_dim;
    const std::size_t key_value_features =
        config.num_key_value_heads * config.head_dim;
    if (tokens == 0 || key.layout().tokens != tokens ||
        value.layout().tokens != tokens ||
        query.layout().features != query_features ||
        key.layout().features != key_value_features ||
        value.layout().features != key_value_features ||
        query.layout().feature_chunks() != 1 ||
        key.layout().feature_chunks() != 1 ||
        value.layout().feature_chunks() != 1 ||
        query.layout().token_stride != key.layout().token_stride ||
        query.layout().token_stride != value.layout().token_stride ||
        query.layout().slot_count != key.layout().slot_count ||
        query.layout().slot_count != value.layout().slot_count ||
        query.layout().token_capacity_limit !=
            key.layout().token_capacity_limit ||
        query.layout().token_capacity_limit !=
            value.layout().token_capacity_limit)
    {
        throw std::invalid_argument(
            "encrypted attention Q/K/V layouts do not match");
    }
}

Tensor make_repeat_kv_weight(const QwenConfig &config)
{
    const std::size_t query_features =
        config.num_attention_heads * config.head_dim;
    const std::size_t key_value_features =
        config.num_key_value_heads * config.head_dim;
    Tensor weight({query_features, key_value_features});
    const std::size_t group_size = config.query_group_size();
    for (std::size_t query_head = 0;
         query_head < config.num_attention_heads; ++query_head)
    {
        const std::size_t key_value_head = query_head / group_size;
        for (std::size_t feature = 0; feature < config.head_dim; ++feature)
        {
            weight.at(query_head * config.head_dim + feature,
                      key_value_head * config.head_dim + feature) = 1.0;
        }
    }
    return weight;
}

Tensor make_head_sum_weight(const QwenConfig &config)
{
    const std::size_t query_features =
        config.num_attention_heads * config.head_dim;
    const double scale =
        1.0 / std::sqrt(static_cast<double>(config.head_dim));
    Tensor weight({query_features, query_features});
    for (std::size_t head = 0; head < config.num_attention_heads; ++head)
    {
        const std::size_t begin = head * config.head_dim;
        for (std::size_t output = 0; output < config.head_dim; ++output)
        {
            for (std::size_t input = 0; input < config.head_dim; ++input)
            {
                weight.at(begin + output, begin + input) = scale;
            }
        }
    }
    return weight;
}

double last_modulus_scale(const poseidon::Ciphertext &cipher,
                          const HeRuntime &runtime)
{
    const auto context_data =
        runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error(
            "failed to locate encrypted attention ciphertext level");
    }
    return static_cast<double>(
        context_data->coeff_modulus().back().value());
}

poseidon::Ciphertext mask_first_token_block(
    const poseidon::Ciphertext &input, std::size_t token_stride,
    HeRuntime &runtime)
{
    std::vector<std::complex<double>> mask(
        runtime.config().slot_count(), {0.0, 0.0});
    std::fill(mask.begin(),
              mask.begin() + static_cast<std::ptrdiff_t>(token_stride),
              std::complex<double>{1.0, 0.0});
    poseidon::Plaintext encoded;
    runtime.encoder.encode(mask, input.parms_id(),
                           last_modulus_scale(input, runtime), encoded);
    poseidon::Ciphertext masked;
    runtime.evaluator->multiply_plain(input, encoded, masked);
    runtime.evaluator->rescale_dynamic(masked, masked, input.scale());
    return masked;
}

std::vector<EncryptedTensor> split_token_views(
    const EncryptedTensor &input, HeRuntime &runtime)
{
    std::vector<EncryptedTensor> tokens;
    tokens.reserve(input.layout().tokens);
    for (std::size_t token = 0; token < input.layout().tokens; ++token)
    {
        const std::size_t token_group =
            token / input.layout().token_capacity();
        const std::size_t local_token =
            token % input.layout().token_capacity();
        std::vector<poseidon::Ciphertext> ciphertexts;
        ciphertexts.reserve(input.layout().feature_chunks());
        for (std::size_t chunk = 0;
             chunk < input.layout().feature_chunks(); ++chunk)
        {
            const poseidon::Ciphertext &source =
                input.cipher(token_group, chunk);
            if (input.layout().token_capacity() == 1)
            {
                ciphertexts.push_back(source);
                continue;
            }
            const int rotation = static_cast<int>(
                local_token * input.layout().token_stride);
            const poseidon::Ciphertext shifted =
                rotation == 0
                    ? source
                    : rotate_slots(source, rotation, runtime);
            ciphertexts.push_back(mask_first_token_block(
                shifted, input.layout().token_stride, runtime));
        }
        EncryptedTensorLayout layout{
            1, input.layout().features, input.layout().token_stride,
            input.layout().slot_count,
            input.layout().token_capacity_limit};
        tokens.emplace_back(layout, std::move(ciphertexts));
    }
    return tokens;
}

EncryptedTensor token_view(const EncryptedTensor &input,
                           std::size_t token)
{
    EncryptedTensorLayout layout{
        1, input.layout().features, input.layout().token_stride,
        input.layout().slot_count,
        input.layout().token_capacity_limit};
    return EncryptedTensor(
        layout, {input.cipher(token, 0)});
}

EncryptedTensor stack_token_outputs(
    std::vector<EncryptedTensor> tokens, HeRuntime &runtime)
{
    if (tokens.empty())
    {
        throw std::invalid_argument(
            "cannot stack an empty encrypted token list");
    }
    const EncryptedTensorLayout first = tokens.front().layout();
    const poseidon::Ciphertext *lowest = nullptr;
    std::size_t lowest_level = std::numeric_limits<std::size_t>::max();
    for (const EncryptedTensor &token : tokens)
    {
        for (const poseidon::Ciphertext &cipher : token.ciphertexts())
        {
            const std::size_t level = runtime.chain_index(cipher);
            if (level < lowest_level)
            {
                lowest = &cipher;
                lowest_level = level;
            }
        }
    }
    if (lowest == nullptr)
    {
        throw std::logic_error(
            "encrypted attention produced no ciphertexts");
    }
    std::vector<poseidon::Ciphertext> aligned_tokens;
    aligned_tokens.reserve(tokens.size() * first.feature_chunks());
    for (EncryptedTensor &token : tokens)
    {
        if (token.layout().tokens != 1 ||
            token.layout().features != first.features ||
            token.layout().token_stride != first.token_stride ||
            token.layout().slot_count != first.slot_count ||
            token.layout().token_capacity_limit !=
                first.token_capacity_limit)
        {
            throw std::invalid_argument(
                "encrypted attention token outputs do not match");
        }
        for (const poseidon::Ciphertext &cipher : token.ciphertexts())
        {
            if (cipher.parms_id() == lowest->parms_id())
            {
                aligned_tokens.push_back(cipher);
            }
            else
            {
                poseidon::Ciphertext aligned;
                runtime.evaluator->drop_modulus(
                    cipher, aligned, lowest->parms_id());
                aligned_tokens.push_back(std::move(aligned));
            }
        }
    }
    if (first.token_capacity() == 1)
    {
        EncryptedTensorLayout layout{
            tokens.size(), first.features, first.token_stride,
            first.slot_count, first.token_capacity_limit};
        return EncryptedTensor(layout, std::move(aligned_tokens));
    }

    const std::size_t token_groups =
        (tokens.size() + first.token_capacity() - 1) /
        first.token_capacity();
    std::vector<poseidon::Ciphertext> ciphertexts(
        token_groups * first.feature_chunks());
    std::vector<bool> initialized(ciphertexts.size(), false);
    for (std::size_t token = 0; token < tokens.size(); ++token)
    {
        const std::size_t token_group = token / first.token_capacity();
        const std::size_t local_token = token % first.token_capacity();
        for (std::size_t chunk = 0; chunk < first.feature_chunks(); ++chunk)
        {
            poseidon::Ciphertext placed = mask_first_token_block(
                aligned_tokens[token * first.feature_chunks() + chunk],
                first.token_stride, runtime);
            const int rotation = -static_cast<int>(
                local_token * first.token_stride);
            if (rotation != 0)
            {
                placed = rotate_slots(placed, rotation, runtime);
            }
            const std::size_t index =
                token_group * first.feature_chunks() + chunk;
            if (!initialized[index])
            {
                ciphertexts[index] = std::move(placed);
                initialized[index] = true;
            }
            else
            {
                runtime.evaluator->add(
                    ciphertexts[index], placed, ciphertexts[index]);
            }
        }
    }
    EncryptedTensorLayout layout{
        tokens.size(), first.features, first.token_stride,
        first.slot_count, first.token_capacity_limit};
    return EncryptedTensor(layout, std::move(ciphertexts));
}

struct EncryptedAttentionScores
{
    std::vector<EncryptedTensor> repeated_values;
    std::vector<std::vector<EncryptedTensor>> rows;
};

EncryptedAttentionScores make_encrypted_attention_scores(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    std::size_t query_position_offset, HeRuntime &runtime)
{
    const std::vector<EncryptedTensor> query_tokens =
        split_token_views(query, runtime);
    const std::vector<EncryptedTensor> key_tokens =
        split_token_views(key, runtime);
    const std::vector<EncryptedTensor> value_tokens =
        split_token_views(value, runtime);
    const Tensor repeat_weight = make_repeat_kv_weight(model_config);
    const EncodedLinear encoded_repeat_key =
        encode_linear_at(repeat_weight,
                         key_tokens.front().cipher(0, 0), runtime);
    std::vector<EncryptedTensor> repeated_keys;
    repeated_keys.reserve(key_tokens.size());
    for (const EncryptedTensor &token : key_tokens)
    {
        repeated_keys.push_back(encrypted_linear(
            token, encoded_repeat_key, nullptr, runtime));
    }
    const EncodedLinear encoded_repeat_value =
        encode_linear_at(repeat_weight,
                         value_tokens.front().cipher(0, 0), runtime);
    std::vector<EncryptedTensor> repeated_values;
    repeated_values.reserve(value_tokens.size());
    for (const EncryptedTensor &token : value_tokens)
    {
        repeated_values.push_back(encrypted_linear(
            token, encoded_repeat_value, nullptr, runtime));
    }

    const Tensor head_sum_weight = make_head_sum_weight(model_config);
    std::vector<std::vector<EncryptedTensor>> scores(
        query.layout().tokens);
    std::optional<EncodedLinear> encoded_head_sum;
    for (std::size_t query_token = 0;
         query_token < query.layout().tokens; ++query_token)
    {
        const std::size_t visible_tokens =
            query_position_offset + query_token + 1;
        scores[query_token].reserve(visible_tokens);
        for (std::size_t key_token = 0;
             key_token < visible_tokens;
             ++key_token)
        {
            const EncryptedTensor product = encrypted_multiply(
                query_tokens[query_token], repeated_keys[key_token],
                runtime);
            if (!encoded_head_sum.has_value())
            {
                encoded_head_sum.emplace(encode_linear_at(
                    head_sum_weight, product.cipher(0, 0), runtime));
            }
            scores[query_token].push_back(encrypted_linear(
                product, *encoded_head_sum, nullptr, runtime));
        }
    }
    return {std::move(repeated_values), std::move(scores)};
}

double approximate_pairwise_maximum(double lhs, double rhs,
                                    const ComparisonConfig &config)
{
    const Tensor lhs_tensor({1, 1}, {lhs});
    const Tensor rhs_tensor({1, 1}, {rhs});
    return approximate_maximum_plain(
               lhs_tensor, rhs_tensor, config)
        .at(0, 0);
}

ApproximationConfig dual_token_sigmoid_config(
    const StableAttentionApproximationConfig &config)
{
    const double score_bound = std::max(
        std::abs(config.exponential.minimum),
        std::abs(config.exponential.maximum));
    return {-score_bound, score_bound,
            std::max(32, config.exponential.sample_count)};
}

ApproximationConfig online_softmax_config(
    const StableAttentionApproximationConfig &config)
{
    const double score_bound = std::max(
        std::abs(config.exponential.minimum),
        std::abs(config.exponential.maximum));
    const double accumulation_margin =
        std::log(std::max(1.0, config.reciprocal.maximum));
    const double bound = score_bound + accumulation_margin;
    return {-bound, bound, std::max(128, config.exponential.sample_count)};
}

EncryptedTensor mock_exact_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    HeRuntime &runtime, EncryptedKVCache *cache)
{
    const std::size_t head_dim = model_config.head_dim;
    Tensor plain_query = flat_to_heads(
        decrypt_tensor(query, runtime), model_config.num_attention_heads,
        head_dim);
    Tensor plain_key = flat_to_heads(
        decrypt_tensor(key, runtime), model_config.num_key_value_heads,
        head_dim);
    Tensor plain_value = flat_to_heads(
        decrypt_tensor(value, runtime), model_config.num_key_value_heads,
        head_dim);

    qwen::KVCache plain_cache;
    qwen::KVCache *plain_cache_ptr = nullptr;
    if (cache != nullptr)
    {
        if (!cache->empty())
        {
            plain_cache.append(
                flat_to_heads(decrypt_tensor(cache->key(), runtime),
                              model_config.num_key_value_heads, head_dim),
                flat_to_heads(decrypt_tensor(cache->value(), runtime),
                              model_config.num_key_value_heads, head_dim));
        }
        plain_cache_ptr = &plain_cache;
    }
    const Tensor plain_output = qwen::causal_gqa_attention(
        plain_query, plain_key, plain_value, model_config,
        plain_cache_ptr);
    if (cache != nullptr)
    {
        cache->append(key, value, runtime);
    }
    return encrypt_tensor(
        heads_to_flat(plain_output, model_config.num_attention_heads,
                      head_dim),
        runtime);
}

} // namespace

bool EncryptedKVCache::empty() const
{
    return key_.ciphertexts().empty();
}

std::size_t EncryptedKVCache::size() const
{
    return empty() ? 0 : key_.layout().tokens;
}

void EncryptedKVCache::clear()
{
    key_ = EncryptedTensor{};
    value_ = EncryptedTensor{};
}

void EncryptedKVCache::append(const EncryptedTensor &key,
                              const EncryptedTensor &value,
                              HeRuntime &runtime)
{
    if (key.layout().tokens == 0 ||
        key.layout().tokens != value.layout().tokens ||
        key.layout().features != value.layout().features ||
        key.layout().feature_chunks() != 1 ||
        value.layout().feature_chunks() != 1)
    {
        throw std::invalid_argument(
            "encrypted KV cache expects matching one-ciphertext tokens");
    }
    if (empty())
    {
        key_ = key;
        value_ = value;
        return;
    }
    if (key.layout().features != key_.layout().features ||
        key.layout().token_stride != key_.layout().token_stride ||
        key.layout().slot_count != key_.layout().slot_count ||
        key.layout().token_capacity_limit !=
            key_.layout().token_capacity_limit ||
        value.layout().features != value_.layout().features ||
        value.layout().token_stride != value_.layout().token_stride ||
        value.layout().slot_count != value_.layout().slot_count ||
        value.layout().token_capacity_limit !=
            value_.layout().token_capacity_limit)
    {
        throw std::invalid_argument(
            "encrypted KV cache append layout mismatch");
    }

    if (key.layout().token_capacity() > 1)
    {
        std::vector<EncryptedTensor> keys =
            split_token_views(key_, runtime);
        std::vector<EncryptedTensor> added_keys =
            split_token_views(key, runtime);
        keys.insert(keys.end(),
                    std::make_move_iterator(added_keys.begin()),
                    std::make_move_iterator(added_keys.end()));
        std::vector<EncryptedTensor> values =
            split_token_views(value_, runtime);
        std::vector<EncryptedTensor> added_values =
            split_token_views(value, runtime);
        values.insert(values.end(),
                      std::make_move_iterator(added_values.begin()),
                      std::make_move_iterator(added_values.end()));
        key_ = stack_token_outputs(std::move(keys), runtime);
        value_ = stack_token_outputs(std::move(values), runtime);
        return;
    }

    const poseidon::Ciphertext *lowest = nullptr;
    std::size_t lowest_level =
        std::numeric_limits<std::size_t>::max();
    const auto inspect = [&](const EncryptedTensor &tensor) {
        for (const poseidon::Ciphertext &cipher : tensor.ciphertexts())
        {
            const std::size_t level = runtime.chain_index(cipher);
            if (level < lowest_level)
            {
                lowest = &cipher;
                lowest_level = level;
            }
        }
    };
    inspect(key_);
    inspect(value_);
    inspect(key);
    inspect(value);
    if (lowest == nullptr)
    {
        throw std::logic_error(
            "encrypted KV cache contains no ciphertexts");
    }
    const auto lowest_parms_id = lowest->parms_id();

    const auto concatenate = [&](const EncryptedTensor &cached,
                                 const EncryptedTensor &added) {
        std::vector<poseidon::Ciphertext> ciphertexts;
        ciphertexts.reserve(cached.ciphertexts().size() +
                            added.ciphertexts().size());
        const auto append_aligned =
            [&](const EncryptedTensor &tensor) {
                for (const poseidon::Ciphertext &cipher :
                     tensor.ciphertexts())
                {
                    if (cipher.parms_id() == lowest_parms_id)
                    {
                        ciphertexts.push_back(cipher);
                    }
                    else
                    {
                        poseidon::Ciphertext aligned;
                        runtime.evaluator->drop_modulus(
                            cipher, aligned, lowest_parms_id);
                        ciphertexts.push_back(std::move(aligned));
                    }
                }
            };
        append_aligned(cached);
        append_aligned(added);
        EncryptedTensorLayout layout{
            cached.layout().tokens + added.layout().tokens,
            cached.layout().features,
            cached.layout().token_stride,
            cached.layout().slot_count,
            cached.layout().token_capacity_limit};
        return EncryptedTensor(layout, std::move(ciphertexts));
    };
    key_ = concatenate(key_, key);
    value_ = concatenate(value_, value);
}

const EncryptedTensor &EncryptedKVCache::key() const
{
    if (empty())
    {
        throw std::logic_error("encrypted KV cache is empty");
    }
    return key_;
}

const EncryptedTensor &EncryptedKVCache::value() const
{
    if (empty())
    {
        throw std::logic_error("encrypted KV cache is empty");
    }
    return value_;
}

void AttentionApproximationConfig::validate() const
{
    exponential.validate();
    reciprocal.validate();
    if (reciprocal.minimum <= 0.0)
    {
        throw std::invalid_argument(
            "attention reciprocal interval must be positive");
    }
}

void StableAttentionApproximationConfig::validate() const
{
    maximum.validate();
    exponential.validate();
    reciprocal.validate();
    if (reciprocal.minimum <= 0.0)
    {
        throw std::invalid_argument(
            "stable attention reciprocal interval must be positive");
    }
    if (!std::isfinite(maximum_bootstrap_value_scale) ||
        maximum_bootstrap_value_scale <= 0.0)
    {
        throw std::invalid_argument(
            "stable attention maximum bootstrap scale must be positive");
    }
    if (!std::isfinite(dual_token_bootstrap_value_scale) ||
        dual_token_bootstrap_value_scale <= 0.0)
    {
        throw std::invalid_argument(
            "stable attention dual-token bootstrap scale must be positive");
    }
}

Tensor approximate_causal_gqa_attention(
    const Tensor &query, const Tensor &key, const Tensor &value,
    const QwenConfig &model_config,
    const AttentionApproximationConfig &approximation)
{
    validate_plain_qkv(query, key, value, model_config);
    approximation.validate();
    const poseidon::Polynomial exponential =
        make_exp_polynomial(approximation.exponential);
    const poseidon::Polynomial reciprocal =
        make_reciprocal_polynomial(approximation.reciprocal);
    const std::size_t group_size = model_config.query_group_size();
    const double scale =
        1.0 / std::sqrt(static_cast<double>(model_config.head_dim));
    Tensor output(query.shape());

    for (std::size_t query_token = 0; query_token < query.dim(0);
         ++query_token)
    {
        for (std::size_t query_head = 0;
             query_head < model_config.num_attention_heads; ++query_head)
        {
            const std::size_t key_value_head = query_head / group_size;
            std::vector<double> exponentials(query_token + 1, 0.0);
            double denominator = 0.0;
            for (std::size_t key_token = 0;
                 key_token <= query_token; ++key_token)
            {
                double score = 0.0;
                for (std::size_t feature = 0;
                     feature < model_config.head_dim; ++feature)
                {
                    score += query.at(query_token, query_head, feature) *
                             key.at(key_token, key_value_head, feature);
                }
                score *= scale;
                if (score < approximation.exponential.minimum ||
                    score > approximation.exponential.maximum)
                {
                    throw std::out_of_range(
                        "attention score is outside the exponential interval");
                }
                exponentials[key_token] =
                    evaluate_chebyshev_plain(score, exponential);
                denominator += exponentials[key_token];
            }
            if (denominator < approximation.reciprocal.minimum ||
                denominator > approximation.reciprocal.maximum)
            {
                throw std::out_of_range(
                    "attention denominator is outside the reciprocal interval");
            }
            const double inverse =
                evaluate_chebyshev_plain(denominator, reciprocal);
            for (std::size_t key_token = 0;
                 key_token <= query_token; ++key_token)
            {
                const double probability =
                    exponentials[key_token] * inverse;
                for (std::size_t feature = 0;
                     feature < model_config.head_dim; ++feature)
                {
                    output.at(query_token, query_head, feature) +=
                        probability *
                        value.at(key_token, key_value_head, feature);
                }
            }
        }
    }
    return output;
}

EncryptedTensor encrypted_causal_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const AttentionApproximationConfig &approximation,
    HeRuntime &runtime)
{
    validate_encrypted_qkv(query, key, value, model_config);
    approximation.validate();

    EncryptedAttentionScores attention =
        make_encrypted_attention_scores(
            query, key, value, model_config, 0, runtime);

    std::vector<EncryptedTensor> output_tokens;
    output_tokens.reserve(query.layout().tokens);
    for (std::size_t query_token = 0;
         query_token < query.layout().tokens; ++query_token)
    {
        std::vector<EncryptedTensor> exponentials;
        exponentials.reserve(attention.rows[query_token].size());
        for (const EncryptedTensor &score :
             attention.rows[query_token])
        {
            exponentials.push_back(encrypted_exp(
                score, approximation.exponential, runtime));
        }
        EncryptedTensor denominator = exponentials.front();
        for (std::size_t key_token = 1;
             key_token < exponentials.size(); ++key_token)
        {
            denominator = encrypted_add(
                denominator, exponentials[key_token], runtime);
        }
        const EncryptedTensor inverse = encrypted_reciprocal(
            denominator, approximation.reciprocal, runtime);

        std::optional<EncryptedTensor> accumulated;
        for (std::size_t key_token = 0;
             key_token < exponentials.size(); ++key_token)
        {
            const EncryptedTensor probability = encrypted_multiply(
                exponentials[key_token], inverse, runtime);
            const EncryptedTensor weighted_value = encrypted_multiply(
                probability,
                attention.repeated_values[key_token],
                runtime);
            if (!accumulated.has_value())
            {
                accumulated.emplace(weighted_value);
            }
            else
            {
                accumulated = encrypted_add(
                    *accumulated, weighted_value, runtime);
            }
        }
        output_tokens.push_back(std::move(*accumulated));
    }
    return stack_token_outputs(std::move(output_tokens), runtime);
}

Tensor approximate_stable_causal_gqa_attention(
    const Tensor &query, const Tensor &key, const Tensor &value,
    const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    KVCache *cache)
{
    validate_plain_qkv(query, key, value, model_config);
    approximation.validate();
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
    const std::size_t group_size = model_config.query_group_size();
    const double scale =
        1.0 / std::sqrt(static_cast<double>(model_config.head_dim));
    Tensor output(query.shape());

    for (std::size_t query_token = 0; query_token < query.dim(0);
         ++query_token)
    {
        for (std::size_t query_head = 0;
             query_head < model_config.num_attention_heads; ++query_head)
        {
            const std::size_t key_value_head = query_head / group_size;
            const std::size_t visible_tokens =
                query_position_offset + query_token + 1;
            std::vector<double> scores(visible_tokens, 0.0);
            for (std::size_t key_token = 0;
                 key_token < visible_tokens; ++key_token)
            {
                for (std::size_t feature = 0;
                     feature < model_config.head_dim; ++feature)
                {
                    scores[key_token] +=
                        query.at(query_token, query_head, feature) *
                        all_key->at(
                            key_token, key_value_head, feature);
                }
                scores[key_token] *= scale;
            }

            if (scores.size() == 2)
            {
                const poseidon::Polynomial sigmoid =
                    make_sigmoid_polynomial(
                        dual_token_sigmoid_config(approximation));
                const double first_probability =
                    evaluate_chebyshev_plain(
                        scores[0] - scores[1], sigmoid);
                for (std::size_t feature = 0;
                     feature < model_config.head_dim; ++feature)
                {
                    const double first_value = all_value->at(
                        0, key_value_head, feature);
                    const double second_value = all_value->at(
                        1, key_value_head, feature);
                    output.at(query_token, query_head, feature) =
                        second_value + first_probability *
                                           (first_value - second_value);
                }
                continue;
            }

            const ApproximationConfig online_config =
                online_softmax_config(approximation);
            const poseidon::Polynomial sigmoid =
                make_sigmoid_polynomial(online_config);
            const poseidon::Polynomial softplus =
                make_softplus_polynomial(online_config);
            double log_normalizer = scores.front();
            std::vector<double> aggregate(model_config.head_dim, 0.0);
            for (std::size_t feature = 0;
                 feature < model_config.head_dim; ++feature)
            {
                aggregate[feature] =
                    all_value->at(0, key_value_head, feature);
            }
            for (std::size_t key_token = 1;
                 key_token < scores.size(); ++key_token)
            {
                const double delta = scores[key_token] - log_normalizer;
                if (delta < online_config.minimum ||
                    delta > online_config.maximum)
                {
                    throw std::out_of_range(
                        "online softmax delta is outside its calibrated interval");
                }
                const double new_probability =
                    evaluate_chebyshev_plain(delta, sigmoid);
                log_normalizer +=
                    evaluate_chebyshev_plain(delta, softplus);
                for (std::size_t feature = 0;
                     feature < model_config.head_dim; ++feature)
                {
                    const double next_value = all_value->at(
                        key_token, key_value_head, feature);
                    aggregate[feature] += new_probability *
                        (next_value - aggregate[feature]);
                }
            }
            for (std::size_t feature = 0;
                 feature < model_config.head_dim; ++feature)
            {
                output.at(query_token, query_head, feature) =
                    aggregate[feature];
            }
        }
    }
    return output;
}

EncryptedTensor encrypted_stable_attention_impl(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    std::size_t query_position_offset, HeRuntime &runtime,
    RefreshMode maximum_refresh,
    RefreshMode denominator_refresh)
{
    approximation.validate();
    EncryptedAttentionScores attention =
        make_encrypted_attention_scores(
            query, key, value, model_config,
            query_position_offset, runtime);

    std::vector<EncryptedTensor> output_tokens;
    output_tokens.reserve(query.layout().tokens);
    for (std::size_t query_token = 0;
         query_token < query.layout().tokens; ++query_token)
    {
        // A one-token causal row has softmax probability exactly one. Skip
        // the maximum/exp/reciprocal circuit; this both preserves the exact
        // semantics and avoids spending bootstrap depth on a degenerate row.
        if (attention.rows[query_token].size() == 1)
        {
            output_tokens.push_back(
                attention.repeated_values[query_token]);
            continue;
        }
        if (attention.rows[query_token].size() == 2)
        {
            EncryptedTensor difference = encrypted_subtract(
                attention.rows[query_token][0],
                attention.rows[query_token][1], runtime);
            const std::string prefix =
                "row_" + std::to_string(query_token) + ".step_1.";
            difference = logged_attention_tensor_operation(
                prefix + "delta_refresh", difference, runtime, [&] {
                    return encrypted_refresh_at_scale(
                        difference, maximum_refresh,
                        approximation.dual_token_bootstrap_value_scale,
                        runtime);
                });
            const EncryptedTensor first_probability =
                logged_attention_tensor_operation(
                    prefix + "sigmoid", difference, runtime, [&] {
                        return encrypted_sigmoid(
                            difference,
                            dual_token_sigmoid_config(approximation),
                            runtime);
                    });
            const EncryptedTensor value_difference = encrypted_subtract(
                attention.repeated_values[0],
                attention.repeated_values[1], runtime);
            const EncryptedTensor weighted_difference = encrypted_multiply(
                first_probability, value_difference, runtime);
            output_tokens.push_back(encrypted_add(
                attention.repeated_values[1], weighted_difference,
                runtime));
            continue;
        }
        const ApproximationConfig online_config =
            online_softmax_config(approximation);
        const double online_value_scale = std::max(
            approximation.dual_token_bootstrap_value_scale,
            std::max(std::abs(online_config.minimum),
                     std::abs(online_config.maximum)) /
                16.0);
        EncryptedTensor log_normalizer =
            attention.rows[query_token].front();
        EncryptedTensor aggregate = attention.repeated_values.front();
        for (std::size_t key_token = 1;
             key_token < attention.rows[query_token].size();
             ++key_token)
        {
            const std::string prefix =
                "row_" + std::to_string(query_token) + ".step_" +
                std::to_string(key_token) + '.';
            EncryptedTensor delta = encrypted_subtract(
                attention.rows[query_token][key_token],
                log_normalizer, runtime);
            delta = logged_attention_tensor_operation(
                prefix + "delta_refresh", delta, runtime, [&] {
                    return encrypted_refresh_at_scale(
                        delta, maximum_refresh, online_value_scale,
                        runtime);
                });
            const EncryptedTensor new_probability =
                logged_attention_tensor_operation(
                    prefix + "sigmoid", delta, runtime, [&] {
                        return encrypted_sigmoid(
                            delta, online_config, runtime);
                    });
            const EncryptedTensor log_correction =
                logged_attention_tensor_operation(
                    prefix + "softplus", delta, runtime, [&] {
                        return encrypted_softplus(
                            delta, online_config, runtime);
                    });
            log_normalizer = encrypted_add(
                log_normalizer, log_correction, runtime);

            if (runtime.chain_index(aggregate.cipher(0, 0)) <= 2 &&
                denominator_refresh != RefreshMode::none)
            {
                aggregate = logged_attention_tensor_operation(
                    prefix + "aggregate_refresh", aggregate, runtime,
                    [&] {
                        return encrypted_refresh(
                            aggregate, denominator_refresh, runtime);
                    });
            }
            const EncryptedTensor value_delta = encrypted_subtract(
                attention.repeated_values[key_token], aggregate, runtime);
            aggregate = logged_attention_tensor_operation(
                prefix + "aggregate_update", aggregate, runtime, [&] {
                    const EncryptedTensor weighted_delta =
                        encrypted_multiply(
                            new_probability, value_delta, runtime);
                    return encrypted_add(
                        aggregate, weighted_delta, runtime);
                });
        }
        output_tokens.push_back(std::move(aggregate));
    }
    EncryptedTensor output =
        stack_token_outputs(std::move(output_tokens), runtime);
    if (runtime.chain_index(output.cipher(0, 0)) <= 1 &&
        denominator_refresh != RefreshMode::none)
    {
        output = encrypted_refresh(
            output, denominator_refresh, runtime);
    }
    return output;
}

EncryptedTensor encrypted_stable_causal_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    HeRuntime &runtime, RefreshMode maximum_refresh,
    RefreshMode denominator_refresh)
{
    validate_encrypted_qkv(query, key, value, model_config);
    if (runtime.mock_attention())
    {
        return mock_exact_attention(
            query, key, value, model_config, runtime, nullptr);
    }
    return encrypted_stable_attention_impl(
        query, key, value, model_config, approximation, 0, runtime,
        maximum_refresh, denominator_refresh);
}

EncryptedTensor encrypted_stable_cached_gqa_attention(
    const EncryptedTensor &query, const EncryptedTensor &key,
    const EncryptedTensor &value, const QwenConfig &model_config,
    const StableAttentionApproximationConfig &approximation,
    EncryptedKVCache &cache, HeRuntime &runtime,
    RefreshMode maximum_refresh,
    RefreshMode denominator_refresh)
{
    validate_encrypted_qkv(query, key, value, model_config);
    if (runtime.mock_attention())
    {
        return mock_exact_attention(
            query, key, value, model_config, runtime, &cache);
    }
    const std::size_t query_position_offset = cache.size();
    cache.append(key, value, runtime);
    return encrypted_stable_attention_impl(
        query, cache.key(), cache.value(), model_config,
        approximation, query_position_offset, runtime,
        maximum_refresh, denominator_refresh);
}

} // namespace qwen::he
