#include "core/tensor.h"
#include "he/encrypted_attention.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "io/safetensors.h"
#include "model/plain_attention.h"
#include "model/qwen_config.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

struct ErrorMetrics
{
    double max_abs = 0.0;
    double rmse = 0.0;
};

ErrorMetrics compare(const qwen::Tensor &actual, const qwen::Tensor &expected)
{
    if (actual.shape() != expected.shape())
    {
        throw std::invalid_argument(
            "Qwen HE attention comparison shape mismatch");
    }
    ErrorMetrics metrics;
    double square_sum = 0.0;
    for (std::size_t index = 0; index < actual.numel(); ++index)
    {
        const double difference =
            std::abs(actual.data()[index] - expected.data()[index]);
        metrics.max_abs = std::max(metrics.max_abs, difference);
        square_sum += difference * difference;
    }
    metrics.rmse =
        std::sqrt(square_sum / static_cast<double>(actual.numel()));
    return metrics;
}

std::vector<std::size_t> parse_token_ids(const std::string &text)
{
    std::vector<std::size_t> result;
    std::size_t begin = 0;
    while (begin < text.size())
    {
        const std::size_t end = text.find(',', begin);
        const std::string item =
            text.substr(begin, end == std::string::npos
                                   ? std::string::npos
                                   : end - begin);
        std::size_t parsed = 0;
        const unsigned long long value = std::stoull(item, &parsed);
        if (parsed != item.size())
        {
            throw std::invalid_argument("invalid token ID list");
        }
        result.push_back(static_cast<std::size_t>(value));
        if (end == std::string::npos)
        {
            break;
        }
        begin = end + 1;
    }
    if (result.size() != 2)
    {
        throw std::invalid_argument(
            "current stable attention validation requires two token IDs");
    }
    return result;
}

qwen::Tensor embedding_rows(
    const qwen::Tensor &embedding,
    const std::vector<std::size_t> &token_ids)
{
    qwen::Tensor result({token_ids.size(), embedding.dim(1)});
    for (std::size_t token = 0; token < token_ids.size(); ++token)
    {
        if (token_ids[token] >= embedding.dim(0))
        {
            throw std::out_of_range(
                "Qwen HE token ID is outside the embedding table");
        }
        const auto source =
            embedding.data().begin() +
            static_cast<std::ptrdiff_t>(
                token_ids[token] * embedding.dim(1));
        std::copy(
            source,
            source + static_cast<std::ptrdiff_t>(embedding.dim(1)),
            result.data().begin() +
                static_cast<std::ptrdiff_t>(token * embedding.dim(1)));
    }
    return result;
}

void print_metrics(const char *name, const ErrorMetrics &metrics)
{
    std::cout << name << " max_abs=" << metrics.max_abs
              << " rmse=" << metrics.rmse << '\n';
}

void print_usage(const char *program)
{
    std::cout << "Usage: " << program
              << " --model DIR [--input-ids N,N]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::filesystem::path model_directory;
        std::vector<std::size_t> token_ids{9707, 11};
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument(argv[index]);
            if (argument == "--help")
            {
                print_usage(argv[0]);
                return 0;
            }
            if (index + 1 >= argc)
            {
                throw std::invalid_argument(
                    "missing value for " + argument);
            }
            if (argument == "--model")
            {
                model_directory = argv[++index];
            }
            else if (argument == "--input-ids")
            {
                token_ids = parse_token_ids(argv[++index]);
            }
            else
            {
                throw std::invalid_argument(
                    "unknown option: " + argument);
            }
        }
        if (model_directory.empty())
        {
            throw std::invalid_argument("--model is required");
        }

        const qwen::QwenConfig config =
            qwen::load_qwen_config(model_directory / "config.json");
        qwen::SafeTensorStore weights(model_directory);
        qwen::Tensor embedding =
            weights.load("model.embed_tokens.weight");
        const qwen::Tensor hidden =
            embedding_rows(embedding, token_ids);
        embedding = qwen::Tensor{};
        const std::string layer = "model.layers.0.";
        const std::string attention = layer + "self_attn.";
        const qwen::Tensor normalized = qwen::rms_norm(
            hidden, weights.load(layer + "input_layernorm.weight"),
            config.rms_norm_epsilon);
        const qwen::Tensor query_bias =
            weights.load(attention + "q_proj.bias");
        const qwen::Tensor key_bias =
            weights.load(attention + "k_proj.bias");
        const qwen::Tensor value_bias =
            weights.load(attention + "v_proj.bias");
        qwen::Tensor query = qwen::split_heads(
            qwen::linear(
                normalized, weights.load(attention + "q_proj.weight"),
                &query_bias),
            config.num_attention_heads, config.head_dim);
        qwen::Tensor key = qwen::split_heads(
            qwen::linear(
                normalized, weights.load(attention + "k_proj.weight"),
                &key_bias),
            config.num_key_value_heads, config.head_dim);
        const qwen::Tensor value = qwen::split_heads(
            qwen::linear(
                normalized, weights.load(attention + "v_proj.weight"),
                &value_bias),
            config.num_key_value_heads, config.head_dim);
        qwen::apply_rope(query, key, 0, config.rope_theta);

        const qwen::Tensor exact_attention =
            qwen::causal_gqa_attention(query, key, value, config);
        const qwen::he::StableAttentionApproximationConfig approximation{
            {2048.0}, {-24.5, 0.25, 32}, {0.70, 2.50, 32}};
        const qwen::Tensor polynomial_attention =
            qwen::he::approximate_stable_causal_gqa_attention(
                query, key, value, config, approximation);
        const qwen::Tensor output_weight =
            weights.load(attention + "o_proj.weight");
        const qwen::Tensor exact_output = qwen::linear(
            qwen::merge_heads(exact_attention), output_weight);
        const qwen::Tensor polynomial_output = qwen::linear(
            qwen::merge_heads(polynomial_attention), output_weight);
        const qwen::Tensor exact_residual =
            qwen::add(hidden, exact_output);
        const qwen::Tensor polynomial_residual =
            qwen::add(hidden, polynomial_output);

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(
                qwen::he::deep_debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_query =
            qwen::he::encrypt_tensor(
                query.reshape({token_ids.size(), config.hidden_size}),
                runtime);
        const qwen::he::EncryptedTensor encrypted_key =
            qwen::he::encrypt_tensor(
                key.reshape(
                    {token_ids.size(),
                     config.num_key_value_heads * config.head_dim}),
                runtime);
        const qwen::he::EncryptedTensor encrypted_value =
            qwen::he::encrypt_tensor(
                value.reshape(
                    {token_ids.size(),
                     config.num_key_value_heads * config.head_dim}),
                runtime);

        const auto attention_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_attention =
            qwen::he::encrypted_stable_causal_gqa_attention(
                encrypted_query, encrypted_key, encrypted_value,
                config, approximation, runtime);
        const auto attention_stop = std::chrono::steady_clock::now();
        const auto output_start = std::chrono::steady_clock::now();
        const qwen::he::EncodedLinear encoded_output =
            qwen::he::encode_linear_at(
                output_weight, encrypted_attention.cipher(0, 0),
                runtime);
        const qwen::he::EncryptedTensor encrypted_output =
            qwen::he::encrypted_linear(
                encrypted_attention, encoded_output, nullptr, runtime);
        const qwen::he::EncryptedTensor encrypted_hidden =
            qwen::he::encrypt_tensor(hidden, runtime);
        const qwen::he::EncryptedTensor encrypted_residual =
            qwen::he::encrypted_add(
                encrypted_hidden, encrypted_output, runtime);
        const auto output_stop = std::chrono::steady_clock::now();

        const qwen::Tensor decrypted_attention =
            qwen::he::decrypt_tensor(encrypted_attention, runtime);
        const qwen::Tensor decrypted_output =
            qwen::he::decrypt_tensor(encrypted_output, runtime);
        const qwen::Tensor decrypted_residual =
            qwen::he::decrypt_tensor(encrypted_residual, runtime);
        const ErrorMetrics attention_approximation = compare(
            polynomial_attention, exact_attention);
        const ErrorMetrics attention_ckks = compare(
            decrypted_attention,
            polynomial_attention.reshape(
                {token_ids.size(), config.hidden_size}));
        const ErrorMetrics output_approximation =
            compare(polynomial_output, exact_output);
        const ErrorMetrics output_ckks =
            compare(decrypted_output, polynomial_output);
        const ErrorMetrics residual_ckks =
            compare(decrypted_residual, polynomial_residual);
        const ErrorMetrics residual_total =
            compare(decrypted_residual, exact_residual);

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };
        std::cout << "Qwen CKKS real-checkpoint stable attention validation\n"
                  << "stage=real_rope_qkv->private_max->stable_softmax->"
                     "o_proj->residual tokens=2\n";
        print_metrics(
            "attention_approx_vs_exact", attention_approximation);
        print_metrics(
            "attention_ckks_vs_polynomial", attention_ckks);
        print_metrics(
            "o_proj_approx_vs_exact", output_approximation);
        print_metrics("o_proj_ckks_vs_polynomial", output_ckks);
        print_metrics(
            "residual_ckks_vs_polynomial", residual_ckks);
        print_metrics("residual_total_vs_exact", residual_total);
        std::cout << "chain_qkv="
                  << runtime.chain_index(encrypted_query.cipher(0, 0))
                  << " chain_attention="
                  << runtime.chain_index(
                         encrypted_attention.cipher(0, 0))
                  << " chain_o_proj="
                  << runtime.chain_index(encrypted_output.cipher(0, 0))
                  << " chain_residual="
                  << runtime.chain_index(
                         encrypted_residual.cipher(0, 0))
                  << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " stable_attention_ms="
                  << milliseconds(attention_stop - attention_start)
                  << " o_proj_and_residual_ms="
                  << milliseconds(output_stop - output_start) << '\n'
                  << "security=deep-debug-not-production\n";

        if (attention_approximation.max_abs > 2.0e-4 ||
            attention_ckks.max_abs > 2.0e-3 ||
            output_ckks.max_abs > 2.0e-3 ||
            residual_ckks.max_abs > 2.0e-3)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_attention: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
