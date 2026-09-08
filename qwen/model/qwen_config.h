#pragma once

#include <cstddef>
#include <filesystem>

namespace qwen
{

struct QwenConfig
{
    std::size_t vocab_size = 0;
    std::size_t hidden_size = 0;
    std::size_t intermediate_size = 0;
    std::size_t num_hidden_layers = 0;
    std::size_t num_attention_heads = 0;
    std::size_t num_key_value_heads = 0;
    std::size_t head_dim = 0;
    std::size_t max_position_embeddings = 0;
    double rms_norm_epsilon = 1.0e-6;
    double rope_theta = 10000.0;
    bool tie_word_embeddings = false;

    void validate() const;
    void validate_model() const;
    std::size_t query_group_size() const;
};

QwenConfig load_qwen_config(const std::filesystem::path &path);
QwenConfig demo_config();

} // namespace qwen
