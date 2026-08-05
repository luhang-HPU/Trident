#include "core/tensor.h"
#include "io/safetensors.h"
#include "model/plain_attention.h"
#include "model/plain_decoder.h"
#include "model/plain_qwen.h"
#include "model/qwen_config.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{

constexpr double kTolerance = 1.0e-10;

using NamedTensor = std::pair<std::string, const qwen::Tensor *>;

void expect_true(bool condition, const std::string &message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void expect_near(double actual, double expected, const std::string &message,
                 double tolerance = kTolerance)
{
    if (std::abs(actual - expected) > tolerance)
    {
        throw std::runtime_error(message + ": expected " + std::to_string(expected) +
                                 ", got " + std::to_string(actual));
    }
}

qwen::QwenConfig attention_test_config()
{
    qwen::QwenConfig config;
    config.hidden_size = 4;
    config.intermediate_size = 8;
    config.num_attention_heads = 2;
    config.num_key_value_heads = 1;
    config.head_dim = 2;
    config.rms_norm_epsilon = 1.0e-6;
    config.rope_theta = 10000.0;
    return config;
}

std::string tensor_shape_json(const qwen::Tensor &tensor)
{
    std::ostringstream output;
    output << '[';
    for (std::size_t axis = 0; axis < tensor.rank(); ++axis)
    {
        if (axis)
        {
            output << ',';
        }
        output << tensor.dim(axis);
    }
    output << ']';
    return output.str();
}

void write_little_endian_u64(std::ostream &output, std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
    {
        output.put(static_cast<char>((value >> (index * 8)) & 0xFFU));
    }
}

void write_f64_safetensors(const std::filesystem::path &path,
                           const std::vector<NamedTensor> &tensors)
{
    std::ostringstream header;
    header << '{';
    std::uint64_t offset = 0;
    for (std::size_t index = 0; index < tensors.size(); ++index)
    {
        if (index)
        {
            header << ',';
        }
        const auto &[name, tensor] = tensors[index];
        const std::uint64_t end =
            offset + static_cast<std::uint64_t>(tensor->numel() * sizeof(double));
        header << '"' << name << "\":{\"dtype\":\"F64\",\"shape\":"
               << tensor_shape_json(*tensor) << ",\"data_offsets\":[" << offset << ',' << end
               << "]}";
        offset = end;
    }
    header << '}';
    std::string header_text = header.str();
    while (header_text.size() % 8 != 0)
    {
        header_text.push_back(' ');
    }

    std::ofstream output(path, std::ios::binary);
    if (!output.is_open())
    {
        throw std::runtime_error("failed to create test safetensors file");
    }
    write_little_endian_u64(output, header_text.size());
    output.write(header_text.data(), static_cast<std::streamsize>(header_text.size()));
    for (const auto &[name, tensor] : tensors)
    {
        static_cast<void>(name);
        output.write(reinterpret_cast<const char *>(tensor->data().data()),
                     static_cast<std::streamsize>(tensor->numel() * sizeof(double)));
    }
}

void write_raw_safetensor(const std::filesystem::path &path, const std::string &name,
                          const std::string &dtype, const std::vector<std::size_t> &shape,
                          const std::vector<unsigned char> &bytes)
{
    std::ostringstream shape_json;
    shape_json << '[';
    for (std::size_t axis = 0; axis < shape.size(); ++axis)
    {
        if (axis)
        {
            shape_json << ',';
        }
        shape_json << shape[axis];
    }
    shape_json << ']';
    std::string header = "{\"" + name + "\":{\"dtype\":\"" + dtype +
                         "\",\"shape\":" + shape_json.str() +
                         ",\"data_offsets\":[0," + std::to_string(bytes.size()) + "]}}";
    while (header.size() % 8 != 0)
    {
        header.push_back(' ');
    }

    std::ofstream output(path, std::ios::binary);
    write_little_endian_u64(output, header.size());
    output.write(header.data(), static_cast<std::streamsize>(header.size()));
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
}

void write_config(const std::filesystem::path &path, const qwen::QwenConfig &config)
{
    std::ofstream output(path);
    output << "{\n"
           << "  \"vocab_size\": " << config.vocab_size << ",\n"
           << "  \"hidden_size\": " << config.hidden_size << ",\n"
           << "  \"intermediate_size\": " << config.intermediate_size << ",\n"
           << "  \"num_hidden_layers\": " << config.num_hidden_layers << ",\n"
           << "  \"num_attention_heads\": " << config.num_attention_heads << ",\n"
           << "  \"num_key_value_heads\": " << config.num_key_value_heads << ",\n"
           << "  \"head_dim\": " << config.head_dim << ",\n"
           << "  \"max_position_embeddings\": " << config.max_position_embeddings << ",\n"
           << "  \"rms_norm_eps\": " << config.rms_norm_epsilon << ",\n"
           << "  \"rope_theta\": " << config.rope_theta << ",\n"
           << "  \"tie_word_embeddings\": "
           << (config.tie_word_embeddings ? "true" : "false") << "\n"
           << "}\n";
}

void write_model_checkpoint(const std::filesystem::path &directory,
                            const qwen::QwenConfig &config,
                            const qwen::QwenModelWeights &weights)
{
    std::filesystem::create_directories(directory);
    write_config(directory / "config.json", config);
    std::vector<NamedTensor> tensors;
    tensors.emplace_back("model.embed_tokens.weight", &weights.token_embedding);
    for (std::size_t layer = 0; layer < weights.layers.size(); ++layer)
    {
        const std::string prefix = "model.layers." + std::to_string(layer) + ".";
        const std::string attention = prefix + "self_attn.";
        const std::string mlp = prefix + "mlp.";
        const qwen::DecoderLayerWeights &value = weights.layers[layer];
        tensors.emplace_back(prefix + "input_layernorm.weight", &value.input_norm);
        tensors.emplace_back(attention + "q_proj.weight", &value.query_weight);
        if (!value.query_bias.empty())
        {
            tensors.emplace_back(attention + "q_proj.bias", &value.query_bias);
        }
        tensors.emplace_back(attention + "k_proj.weight", &value.key_weight);
        if (!value.key_bias.empty())
        {
            tensors.emplace_back(attention + "k_proj.bias", &value.key_bias);
        }
        tensors.emplace_back(attention + "v_proj.weight", &value.value_weight);
        if (!value.value_bias.empty())
        {
            tensors.emplace_back(attention + "v_proj.bias", &value.value_bias);
        }
        tensors.emplace_back(attention + "o_proj.weight", &value.output_weight);
        tensors.emplace_back(prefix + "post_attention_layernorm.weight",
                             &value.post_attention_norm);
        tensors.emplace_back(mlp + "gate_proj.weight", &value.gate_weight);
        tensors.emplace_back(mlp + "up_proj.weight", &value.up_weight);
        tensors.emplace_back(mlp + "down_proj.weight", &value.down_weight);
    }
    tensors.emplace_back("model.norm.weight", &weights.final_norm);
    if (!weights.lm_head.empty())
    {
        tensors.emplace_back("lm_head.weight", &weights.lm_head);
    }
    write_f64_safetensors(directory / "model.safetensors", tensors);
}

void test_tensor_and_reshape()
{
    qwen::Tensor tensor({2, 3}, {0.0, 1.0, 2.0, 3.0, 4.0, 5.0});
    expect_near(tensor.at(1, 2), 5.0, "rank-2 indexing");
    const qwen::Tensor reshaped = tensor.reshape({1, 2, 3});
    expect_near(reshaped.at(0, 1, 2), 5.0, "rank-3 reshape indexing");
}

void test_linear()
{
    const qwen::Tensor input({2, 2}, {1.0, 2.0, 3.0, 4.0});
    const qwen::Tensor weight({2, 2}, {2.0, 0.0, 0.0, 3.0});
    const qwen::Tensor bias({2}, {1.0, -1.0});
    const qwen::Tensor output = qwen::linear(input, weight, &bias);
    const std::vector<double> expected{3.0, 5.0, 7.0, 11.0};
    expect_true(output.data() == expected, "linear output");
}

void test_rms_norm()
{
    const qwen::Tensor input({1, 2}, {3.0, 4.0});
    const qwen::Tensor weight({2}, {1.0, 2.0});
    constexpr double epsilon = 1.0e-12;
    const qwen::Tensor output = qwen::rms_norm(input, weight, epsilon);
    const double inverse_rms = 1.0 / std::sqrt(12.5 + epsilon);
    expect_near(output.at(0, 0), 3.0 * inverse_rms, "RMSNorm first feature");
    expect_near(output.at(0, 1), 8.0 * inverse_rms, "RMSNorm second feature");
}

void test_qwen_rope_pairing()
{
    qwen::Tensor query({2, 1, 2}, {1.0, 0.0, 1.0, 0.0});
    qwen::Tensor key = query;
    qwen::apply_rope(query, key, 0, 10000.0);
    expect_near(query.at(0, 0, 0), 1.0, "RoPE position zero real");
    expect_near(query.at(0, 0, 1), 0.0, "RoPE position zero imaginary");
    expect_near(query.at(1, 0, 0), std::cos(1.0), "RoPE position one real");
    expect_near(query.at(1, 0, 1), std::sin(1.0), "RoPE position one imaginary");
    expect_true(query.data() == key.data(), "RoPE applies equally to equal Q and K");
}

void test_causal_gqa_attention()
{
    const qwen::QwenConfig config = attention_test_config();
    const qwen::Tensor query({2, 2, 2});
    const qwen::Tensor key({2, 1, 2});
    const qwen::Tensor value({2, 1, 2}, {1.0, 2.0, 3.0, 4.0});
    const qwen::Tensor output =
        qwen::causal_gqa_attention(query, key, value, config);

    for (std::size_t head = 0; head < 2; ++head)
    {
        expect_near(output.at(0, head, 0), 1.0, "causal attention token zero");
        expect_near(output.at(0, head, 1), 2.0, "causal attention token zero");
        expect_near(output.at(1, head, 0), 2.0, "causal attention token one average");
        expect_near(output.at(1, head, 1), 3.0, "causal attention token one average");
    }
}

void test_kv_cache_decode()
{
    const qwen::QwenConfig config = attention_test_config();
    qwen::KVCache cache;
    const qwen::Tensor query({1, 2, 2});
    const qwen::Tensor key({1, 1, 2});
    const qwen::Tensor first_value({1, 1, 2}, {1.0, 2.0});
    const qwen::Tensor second_value({1, 1, 2}, {3.0, 4.0});

    const qwen::Tensor first =
        qwen::causal_gqa_attention(query, key, first_value, config, &cache);
    const qwen::Tensor second =
        qwen::causal_gqa_attention(query, key, second_value, config, &cache);
    expect_true(cache.size() == 2, "KV cache size after two decode steps");
    expect_near(first.at(0, 0, 0), 1.0, "first cached value");
    expect_near(second.at(0, 0, 0), 2.0, "cached value average");
    expect_near(second.at(0, 1, 1), 3.0, "cached value average for grouped head");
}

void zero_matrix(qwen::Tensor &tensor)
{
    std::fill(tensor.data().begin(), tensor.data().end(), 0.0);
}

void test_zero_weight_decoder_is_residual_identity()
{
    const qwen::QwenConfig config = qwen::demo_config();
    qwen::DecoderLayerWeights weights = qwen::make_demo_layer_weights(config);
    zero_matrix(weights.query_weight);
    zero_matrix(weights.query_bias);
    zero_matrix(weights.key_weight);
    zero_matrix(weights.key_bias);
    zero_matrix(weights.value_weight);
    zero_matrix(weights.value_bias);
    zero_matrix(weights.output_weight);
    zero_matrix(weights.gate_weight);
    zero_matrix(weights.up_weight);
    zero_matrix(weights.down_weight);

    const qwen::Tensor input = qwen::make_demo_hidden_states(3, config);
    const qwen::PlainDecoderLayer layer(config, weights);
    const qwen::Tensor output = layer.forward(input);
    expect_true(output.data() == input.data(), "zero-weight decoder preserves residual input");
}

void test_demo_decoder_is_finite_and_deterministic()
{
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::Tensor input = qwen::make_demo_hidden_states(5, config);
    const qwen::PlainDecoderLayer first(
        config, qwen::make_demo_layer_weights(config, 42));
    const qwen::PlainDecoderLayer second(
        config, qwen::make_demo_layer_weights(config, 42));
    const qwen::Tensor first_output = first.forward(input);
    const qwen::Tensor second_output = second.forward(input);
    expect_true(first_output.shape() == input.shape(), "decoder output shape");
    expect_true(qwen::tensor_stats(first_output).all_finite, "decoder output is finite");
    expect_true(first_output.data() == second_output.data(), "decoder output is deterministic");
}

void test_decoder_prefill_matches_token_decode()
{
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::DecoderLayerWeights weights =
        qwen::make_demo_layer_weights(config, 19);
    const qwen::PlainDecoderLayer layer(config, weights);
    const qwen::Tensor input = qwen::make_demo_hidden_states(4, config);
    const qwen::Tensor prefill_output = layer.forward(input);

    qwen::KVCache cache;
    qwen::Tensor decode_output({input.dim(0), input.dim(1)});
    for (std::size_t token = 0; token < input.dim(0); ++token)
    {
        qwen::Tensor token_input({1, input.dim(1)});
        std::copy(input.data().begin() +
                      static_cast<std::ptrdiff_t>(token * input.dim(1)),
                  input.data().begin() +
                      static_cast<std::ptrdiff_t>((token + 1) * input.dim(1)),
                  token_input.data().begin());
        const qwen::Tensor token_output = layer.forward(token_input, &cache);
        std::copy(token_output.data().begin(), token_output.data().end(),
                  decode_output.data().begin() +
                      static_cast<std::ptrdiff_t>(token * input.dim(1)));
    }

    expect_true(cache.size() == input.dim(0), "decoder KV cache contains every token");
    for (std::size_t index = 0; index < prefill_output.numel(); ++index)
    {
        expect_near(decode_output.data()[index], prefill_output.data()[index],
                    "prefill and token decode output", 1.0e-12);
    }
}

void test_qwen_config_json()
{
    const std::filesystem::path root = "/tmp/poseidon_qwen_config_test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    qwen::QwenConfig expected = qwen::demo_config();
    expected.num_hidden_layers = 3;
    expected.vocab_size = 41;
    write_config(root / "config.json", expected);

    const qwen::QwenConfig actual = qwen::load_qwen_config(root / "config.json");
    expect_true(actual.vocab_size == expected.vocab_size, "config vocab size");
    expect_true(actual.num_hidden_layers == expected.num_hidden_layers, "config layer count");
    expect_true(actual.num_key_value_heads == expected.num_key_value_heads,
                "config KV head count");
    expect_near(actual.rms_norm_epsilon, expected.rms_norm_epsilon,
                "config RMS epsilon");
}

void test_sharded_safetensors()
{
    const std::filesystem::path root = "/tmp/poseidon_qwen_sharded_test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const qwen::Tensor first({2}, {1.25, -2.5});
    const qwen::Tensor second({1, 2}, {3.75, 4.5});
    const std::string first_file = "model-00001-of-00002.safetensors";
    const std::string second_file = "model-00002-of-00002.safetensors";
    write_f64_safetensors(root / first_file, {{"first", &first}});
    write_f64_safetensors(root / second_file, {{"second", &second}});
    std::ofstream index(root / "model.safetensors.index.json");
    index << "{\"weight_map\":{\"first\":\"" << first_file
          << "\",\"second\":\"" << second_file << "\"}}\n";
    index.close();

    const qwen::SafeTensorStore store(root);
    expect_true(store.contains("first") && store.contains("second"),
                "sharded safetensors names");
    expect_true(store.load("first").data() == first.data(), "first sharded tensor values");
    expect_true(store.load("second").data() == second.data(), "second sharded tensor values");
}

void test_low_precision_safetensors()
{
    const std::filesystem::path root = "/tmp/poseidon_qwen_dtype_test";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const std::filesystem::path bf16_path = root / "bf16.safetensors";
    write_raw_safetensor(bf16_path, "weight", "BF16", {3},
                         {0x80, 0x3F, 0x20, 0xC0, 0x00, 0x3F});
    const qwen::Tensor bf16 = qwen::SafeTensorStore(bf16_path).load("weight");
    expect_near(bf16.at(0), 1.0, "BF16 one");
    expect_near(bf16.at(1), -2.5, "BF16 negative value");
    expect_near(bf16.at(2), 0.5, "BF16 half");

    const std::filesystem::path f16_path = root / "f16.safetensors";
    write_raw_safetensor(f16_path, "weight", "F16", {3},
                         {0x00, 0x3C, 0x00, 0xC0, 0x00, 0x38});
    const qwen::Tensor f16 = qwen::SafeTensorStore(f16_path).load("weight");
    expect_near(f16.at(0), 1.0, "F16 one");
    expect_near(f16.at(1), -2.0, "F16 negative value");
    expect_near(f16.at(2), 0.5, "F16 half");
}

void test_full_checkpoint_round_trip()
{
    const std::filesystem::path root = "/tmp/poseidon_qwen_model_test";
    std::filesystem::remove_all(root);
    qwen::QwenConfig config = qwen::demo_config();
    config.vocab_size = 17;
    config.num_hidden_layers = 2;
    config.max_position_embeddings = 32;
    qwen::QwenModelWeights weights = qwen::make_demo_model_weights(config, 73);
    write_model_checkpoint(root, config, weights);

    const qwen::PlainQwenModel expected(config, weights);
    const qwen::PlainQwenModel loaded = qwen::load_plain_qwen_model(root);
    const std::vector<std::size_t> input_ids{1, 4, 2, 8};
    const qwen::Tensor expected_logits = expected.last_token_logits(input_ids);
    const qwen::Tensor loaded_logits = loaded.last_token_logits(input_ids);
    expect_true(expected_logits.data() == loaded_logits.data(),
                "checkpoint round-trip logits");

    const std::vector<std::size_t> expected_tokens = expected.generate(input_ids, 3);
    const std::vector<std::size_t> loaded_tokens = loaded.generate(input_ids, 3);
    expect_true(expected_tokens == loaded_tokens, "checkpoint round-trip generation");
    expect_true(qwen::tensor_stats(loaded_logits).all_finite,
                "loaded model logits are finite");
}

} // namespace

int main()
{
    const std::vector<std::pair<std::string, std::function<void()>>> tests{
        {"tensor_and_reshape", test_tensor_and_reshape},
        {"linear", test_linear},
        {"rms_norm", test_rms_norm},
        {"qwen_rope_pairing", test_qwen_rope_pairing},
        {"causal_gqa_attention", test_causal_gqa_attention},
        {"kv_cache_decode", test_kv_cache_decode},
        {"zero_weight_decoder_is_residual_identity",
         test_zero_weight_decoder_is_residual_identity},
        {"demo_decoder_is_finite_and_deterministic",
         test_demo_decoder_is_finite_and_deterministic},
        {"decoder_prefill_matches_token_decode",
         test_decoder_prefill_matches_token_decode},
        {"qwen_config_json", test_qwen_config_json},
        {"sharded_safetensors", test_sharded_safetensors},
        {"low_precision_safetensors", test_low_precision_safetensors},
        {"full_checkpoint_round_trip", test_full_checkpoint_round_trip},
    };

    std::size_t passed = 0;
    for (const auto &[name, test] : tests)
    {
        try
        {
            test();
            std::cout << "[PASS] " << name << '\n';
            ++passed;
        }
        catch (const std::exception &error)
        {
            std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
        }
    }
    std::cout << passed << '/' << tests.size() << " tests passed\n";
    return passed == tests.size() ? 0 : 1;
}
