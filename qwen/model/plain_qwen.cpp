#include "model/plain_qwen.h"

#include "io/safetensors.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>

namespace qwen
{
namespace
{

void require_shape(const Tensor &tensor, const std::vector<std::size_t> &shape,
                   const char *name)
{
    if (tensor.shape() != shape)
    {
        throw std::invalid_argument(std::string(name) + " has shape " + shape_string(tensor));
    }
}

Tensor load_optional(const SafeTensorStore &store, const std::string &name)
{
    return store.contains(name) ? store.load(name) : Tensor{};
}

DecoderLayerWeights load_decoder_layer(const SafeTensorStore &store, std::size_t layer)
{
    const std::string prefix = "model.layers." + std::to_string(layer) + ".";
    const std::string attention = prefix + "self_attn.";
    const std::string mlp = prefix + "mlp.";

    DecoderLayerWeights weights;
    weights.input_norm = store.load(prefix + "input_layernorm.weight");
    weights.query_weight = store.load(attention + "q_proj.weight");
    weights.query_bias = load_optional(store, attention + "q_proj.bias");
    weights.key_weight = store.load(attention + "k_proj.weight");
    weights.key_bias = load_optional(store, attention + "k_proj.bias");
    weights.value_weight = store.load(attention + "v_proj.weight");
    weights.value_bias = load_optional(store, attention + "v_proj.bias");
    weights.output_weight = store.load(attention + "o_proj.weight");
    weights.post_attention_norm =
        store.load(prefix + "post_attention_layernorm.weight");
    weights.gate_weight = store.load(mlp + "gate_proj.weight");
    weights.up_weight = store.load(mlp + "up_proj.weight");
    weights.down_weight = store.load(mlp + "down_proj.weight");
    return weights;
}

Tensor random_matrix(std::size_t rows, std::size_t columns, std::mt19937 &generator)
{
    const double bound = 0.25 / std::sqrt(static_cast<double>(columns));
    std::uniform_real_distribution<double> distribution(-bound, bound);
    Tensor result({rows, columns});
    for (double &value : result.data())
    {
        value = distribution(generator);
    }
    return result;
}

Tensor last_row(const Tensor &tensor)
{
    if (tensor.rank() != 2)
    {
        throw std::invalid_argument("last_row expects a rank-2 tensor");
    }
    Tensor result({1, tensor.dim(1)});
    const auto begin =
        tensor.data().begin() + static_cast<std::ptrdiff_t>((tensor.dim(0) - 1) * tensor.dim(1));
    std::copy(begin, begin + static_cast<std::ptrdiff_t>(tensor.dim(1)), result.data().begin());
    return result;
}

std::size_t argmax(const Tensor &logits)
{
    if (logits.rank() != 2 || logits.dim(0) != 1)
    {
        throw std::invalid_argument("argmax expects one row of logits");
    }
    return static_cast<std::size_t>(
        std::max_element(logits.data().begin(), logits.data().end()) - logits.data().begin());
}

} // namespace

void QwenModelWeights::validate(const QwenConfig &config) const
{
    config.validate_model();
    require_shape(token_embedding, {config.vocab_size, config.hidden_size}, "token_embedding");
    if (layers.size() != config.num_hidden_layers)
    {
        throw std::invalid_argument("Qwen layer weight count does not match config");
    }
    for (const DecoderLayerWeights &layer : layers)
    {
        layer.validate(config);
    }
    require_shape(final_norm, {config.hidden_size}, "final_norm");
    if (lm_head.empty())
    {
        if (!config.tie_word_embeddings)
        {
            throw std::invalid_argument("untied Qwen model is missing lm_head.weight");
        }
    }
    else
    {
        require_shape(lm_head, {config.vocab_size, config.hidden_size}, "lm_head");
    }
}

PlainQwenModel::PlainQwenModel(QwenConfig config, QwenModelWeights weights)
    : config_(std::move(config))
{
    weights.validate(config_);
    token_embedding_ = std::move(weights.token_embedding);
    final_norm_ = std::move(weights.final_norm);
    lm_head_ = std::move(weights.lm_head);

    layers_.reserve(weights.layers.size());
    for (DecoderLayerWeights &layer : weights.layers)
    {
        layers_.emplace_back(config_, std::move(layer));
    }
}

const QwenConfig &PlainQwenModel::config() const
{
    return config_;
}

Tensor PlainQwenModel::embed(const std::vector<std::size_t> &token_ids) const
{
    if (token_ids.empty())
    {
        throw std::invalid_argument("Qwen input token list must not be empty");
    }
    Tensor hidden({token_ids.size(), config_.hidden_size});
    for (std::size_t token = 0; token < token_ids.size(); ++token)
    {
        if (token_ids[token] >= config_.vocab_size)
        {
            throw std::out_of_range("Qwen token ID is outside the vocabulary");
        }
        const auto source =
            token_embedding_.data().begin() +
            static_cast<std::ptrdiff_t>(token_ids[token] * config_.hidden_size);
        std::copy(source, source + static_cast<std::ptrdiff_t>(config_.hidden_size),
                  hidden.data().begin() +
                      static_cast<std::ptrdiff_t>(token * config_.hidden_size));
    }
    return hidden;
}

Tensor PlainQwenModel::forward_hidden(const std::vector<std::size_t> &token_ids,
                                      std::vector<KVCache> *caches,
    ExecutionTrace *trace) const
{
    const std::size_t position_offset = validate_and_get_cache_offset(caches);
    if (position_offset > config_.max_position_embeddings ||
        token_ids.size() > config_.max_position_embeddings - position_offset)
    {
        throw std::out_of_range("Qwen input exceeds max_position_embeddings");
    }

    Tensor hidden = embed(token_ids);
    if (trace != nullptr)
    {
        trace->record("embedding", hidden);
    }
    for (std::size_t layer = 0; layer < layers_.size(); ++layer)
    {
        KVCache *cache = caches == nullptr ? nullptr : &caches->at(layer);
        hidden = layers_[layer].forward(
            hidden, cache, trace, "layer_" + std::to_string(layer) + ".");
    }
    hidden = rms_norm(hidden, final_norm_, config_.rms_norm_epsilon);
    if (trace != nullptr)
    {
        trace->record("final_rmsnorm", hidden);
    }
    return hidden;
}

Tensor PlainQwenModel::forward_logits(const std::vector<std::size_t> &token_ids,
                                      std::vector<KVCache> *caches,
                                      ExecutionTrace *trace) const
{
    const Tensor hidden = forward_hidden(token_ids, caches, trace);
    Tensor logits = linear(hidden, lm_head_weight());
    if (trace != nullptr)
    {
        trace->record("logits", logits);
    }
    return logits;
}

Tensor PlainQwenModel::last_token_logits(const std::vector<std::size_t> &token_ids,
                                         std::vector<KVCache> *caches,
                                         ExecutionTrace *trace) const
{
    const Tensor hidden = forward_hidden(token_ids, caches, trace);
    Tensor logits = linear(last_row(hidden), lm_head_weight());
    if (trace != nullptr)
    {
        trace->record("last_token_logits", logits);
    }
    return logits;
}

std::vector<std::size_t> PlainQwenModel::generate(
    const std::vector<std::size_t> &prompt, std::size_t max_new_tokens,
    ExecutionTrace *trace) const
{
    if (prompt.empty())
    {
        throw std::invalid_argument("generation prompt must not be empty");
    }
    std::vector<std::size_t> generated;
    generated.reserve(max_new_tokens);
    if (max_new_tokens == 0)
    {
        return generated;
    }

    std::vector<KVCache> caches;
    Tensor logits = last_token_logits(prompt, &caches, trace);
    for (std::size_t step = 0; step < max_new_tokens; ++step)
    {
        const std::size_t next_token = argmax(logits);
        generated.push_back(next_token);
        if (step + 1 < max_new_tokens)
        {
            logits = last_token_logits({next_token}, &caches, trace);
        }
    }
    return generated;
}

const Tensor &PlainQwenModel::lm_head_weight() const
{
    return lm_head_.empty() ? token_embedding_ : lm_head_;
}

std::size_t
PlainQwenModel::validate_and_get_cache_offset(std::vector<KVCache> *caches) const
{
    if (caches == nullptr)
    {
        return 0;
    }
    if (caches->empty())
    {
        caches->resize(layers_.size());
        return 0;
    }
    if (caches->size() != layers_.size())
    {
        throw std::invalid_argument("Qwen KV cache count does not match layer count");
    }
    const std::size_t offset = caches->front().size();
    for (const KVCache &cache : *caches)
    {
        if (cache.size() != offset)
        {
            throw std::invalid_argument("Qwen layer KV caches have inconsistent lengths");
        }
    }
    return offset;
}

PlainQwenModel load_plain_qwen_model(const std::filesystem::path &model_directory)
{
    QwenConfig config = load_qwen_config(model_directory / "config.json");
    return PlainQwenModel(
        std::move(config),
        load_qwen_model_weights(model_directory));
}

QwenModelWeights
load_qwen_model_weights(const std::filesystem::path &model_directory)
{
    const QwenConfig config =
        load_qwen_config(model_directory / "config.json");
    SafeTensorStore store(model_directory);
    QwenModelWeights weights;
    weights.token_embedding = store.load("model.embed_tokens.weight");
    weights.layers.reserve(config.num_hidden_layers);
    for (std::size_t layer = 0; layer < config.num_hidden_layers; ++layer)
    {
        weights.layers.push_back(load_decoder_layer(store, layer));
    }
    weights.final_norm = store.load("model.norm.weight");
    weights.lm_head = load_optional(store, "lm_head.weight");
    weights.validate(config);
    return weights;
}

QwenModelWeights make_demo_model_weights(const QwenConfig &config, unsigned int seed)
{
    config.validate_model();
    std::mt19937 generator(seed);
    QwenModelWeights weights;
    weights.token_embedding = random_matrix(config.vocab_size, config.hidden_size, generator);
    weights.layers.reserve(config.num_hidden_layers);
    for (std::size_t layer = 0; layer < config.num_hidden_layers; ++layer)
    {
        weights.layers.push_back(
            make_demo_layer_weights(config, seed + static_cast<unsigned int>(layer + 1)));
    }
    weights.final_norm = Tensor({config.hidden_size});
    std::fill(weights.final_norm.data().begin(), weights.final_norm.data().end(), 1.0);
    if (!config.tie_word_embeddings)
    {
        weights.lm_head = random_matrix(config.vocab_size, config.hidden_size, generator);
    }
    return weights;
}

std::vector<std::pair<std::size_t, double>> top_k_logits(const Tensor &logits,
                                                         std::size_t count)
{
    if (logits.rank() != 2 || logits.dim(0) != 1 || count == 0)
    {
        throw std::invalid_argument("top_k_logits expects one logits row and positive k");
    }
    count = std::min(count, logits.dim(1));
    std::vector<std::size_t> indices(logits.dim(1));
    std::iota(indices.begin(), indices.end(), std::size_t{0});
    std::partial_sort(indices.begin(), indices.begin() + static_cast<std::ptrdiff_t>(count),
                      indices.end(), [&logits](std::size_t lhs, std::size_t rhs) {
                          return logits.at(0, lhs) > logits.at(0, rhs);
                      });

    std::vector<std::pair<std::size_t, double>> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
    {
        result.emplace_back(indices[index], logits.at(0, indices[index]));
    }
    return result;
}

} // namespace qwen
