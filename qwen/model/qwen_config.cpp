#include "model/qwen_config.h"

#include "poseidon/util/json.h"

#include <fstream>
#include <stdexcept>
#include <string>

namespace qwen
{
namespace
{

using Json = nlohmann::json;

std::size_t required_size(const Json &json, const char *name)
{
    if (!json.contains(name) || !json.at(name).is_number_unsigned())
    {
        throw std::invalid_argument(std::string("missing or invalid Qwen config field: ") + name);
    }
    return json.at(name).get<std::size_t>();
}

std::size_t optional_size(const Json &json, const char *name, std::size_t default_value)
{
    if (!json.contains(name))
    {
        return default_value;
    }
    if (!json.at(name).is_number_unsigned())
    {
        throw std::invalid_argument(std::string("invalid Qwen config field: ") + name);
    }
    return json.at(name).get<std::size_t>();
}

double optional_double(const Json &json, const char *name, double default_value)
{
    if (!json.contains(name))
    {
        return default_value;
    }
    if (!json.at(name).is_number())
    {
        throw std::invalid_argument(std::string("invalid Qwen config field: ") + name);
    }
    return json.at(name).get<double>();
}

} // namespace

void QwenConfig::validate() const
{
    if (hidden_size == 0 || intermediate_size == 0 || num_attention_heads == 0 ||
        num_key_value_heads == 0 || head_dim == 0)
    {
        throw std::invalid_argument("Qwen dimensions must be positive");
    }
    if (hidden_size != num_attention_heads * head_dim)
    {
        throw std::invalid_argument("hidden_size must equal num_attention_heads * head_dim");
    }
    if (num_attention_heads % num_key_value_heads != 0)
    {
        throw std::invalid_argument("query head count must be divisible by KV head count");
    }
    if (head_dim % 2 != 0)
    {
        throw std::invalid_argument("RoPE requires an even head dimension");
    }
    if (rms_norm_epsilon <= 0.0 || rope_theta <= 0.0)
    {
        throw std::invalid_argument("normalization epsilon and RoPE theta must be positive");
    }
}

void QwenConfig::validate_model() const
{
    validate();
    if (vocab_size == 0 || num_hidden_layers == 0 || max_position_embeddings == 0)
    {
        throw std::invalid_argument("Qwen model dimensions must be positive");
    }
}

std::size_t QwenConfig::query_group_size() const
{
    validate();
    return num_attention_heads / num_key_value_heads;
}

QwenConfig load_qwen_config(const std::filesystem::path &path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open Qwen config: " + path.string());
    }

    Json json;
    try
    {
        input >> json;
    }
    catch (const std::exception &error)
    {
        throw std::runtime_error("failed to parse Qwen config " + path.string() + ": " +
                                 error.what());
    }

    QwenConfig config;
    config.vocab_size = required_size(json, "vocab_size");
    config.hidden_size = required_size(json, "hidden_size");
    config.intermediate_size = required_size(json, "intermediate_size");
    config.num_hidden_layers = required_size(json, "num_hidden_layers");
    config.num_attention_heads = required_size(json, "num_attention_heads");
    config.num_key_value_heads =
        optional_size(json, "num_key_value_heads", config.num_attention_heads);
    config.head_dim =
        optional_size(json, "head_dim", config.hidden_size / config.num_attention_heads);
    config.max_position_embeddings =
        optional_size(json, "max_position_embeddings", 32768);
    config.rms_norm_epsilon =
        optional_double(json, "rms_norm_eps", config.rms_norm_epsilon);
    config.rope_theta = optional_double(json, "rope_theta", config.rope_theta);
    if (json.contains("tie_word_embeddings"))
    {
        if (!json.at("tie_word_embeddings").is_boolean())
        {
            throw std::invalid_argument("invalid Qwen config field: tie_word_embeddings");
        }
        config.tie_word_embeddings = json.at("tie_word_embeddings").get<bool>();
    }
    config.validate_model();
    return config;
}

QwenConfig demo_config()
{
    QwenConfig config;
    config.vocab_size = 32;
    config.hidden_size = 8;
    config.intermediate_size = 16;
    config.num_hidden_layers = 1;
    config.num_attention_heads = 4;
    config.num_key_value_heads = 2;
    config.head_dim = 2;
    config.max_position_embeddings = 128;
    config.rms_norm_epsilon = 1.0e-6;
    config.rope_theta = 10000.0;
    config.tie_word_embeddings = false;
    return config;
}

} // namespace qwen
