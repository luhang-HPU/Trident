#pragma once

#include "core/tensor.h"
#include "model/plain_attention.h"
#include "model/plain_decoder.h"
#include "model/qwen_config.h"

#include <cstddef>
#include <filesystem>
#include <utility>
#include <vector>

namespace qwen
{

struct QwenModelWeights
{
    Tensor token_embedding;
    std::vector<DecoderLayerWeights> layers;
    Tensor final_norm;
    // Empty means that token_embedding is reused as a tied LM head.
    Tensor lm_head;

    void validate(const QwenConfig &config) const;
};

class PlainQwenModel
{
public:
    PlainQwenModel(QwenConfig config, QwenModelWeights weights);

    const QwenConfig &config() const;
    Tensor embed(const std::vector<std::size_t> &token_ids) const;
    Tensor forward_hidden(const std::vector<std::size_t> &token_ids,
                          std::vector<KVCache> *caches = nullptr,
                          ExecutionTrace *trace = nullptr) const;
    Tensor forward_logits(const std::vector<std::size_t> &token_ids,
                          std::vector<KVCache> *caches = nullptr,
                          ExecutionTrace *trace = nullptr) const;
    Tensor last_token_logits(const std::vector<std::size_t> &token_ids,
                             std::vector<KVCache> *caches = nullptr,
                             ExecutionTrace *trace = nullptr) const;
    std::vector<std::size_t> generate(const std::vector<std::size_t> &prompt,
                                      std::size_t max_new_tokens,
                                      ExecutionTrace *trace = nullptr) const;

private:
    const Tensor &lm_head_weight() const;
    std::size_t validate_and_get_cache_offset(std::vector<KVCache> *caches) const;

    QwenConfig config_;
    Tensor token_embedding_;
    std::vector<PlainDecoderLayer> layers_;
    Tensor final_norm_;
    Tensor lm_head_;
};

PlainQwenModel load_plain_qwen_model(const std::filesystem::path &model_directory);
QwenModelWeights
load_qwen_model_weights(const std::filesystem::path &model_directory);
QwenModelWeights make_demo_model_weights(const QwenConfig &config, unsigned int seed = 11);
std::vector<std::pair<std::size_t, double>> top_k_logits(const Tensor &logits,
                                                         std::size_t count);

} // namespace qwen
