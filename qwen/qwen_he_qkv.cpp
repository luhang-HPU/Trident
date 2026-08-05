#include "core/tensor.h"
#include "he/approximation.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "io/safetensors.h"
#include "model/qwen_config.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <iostream>
#include <limits>
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
        throw std::invalid_argument("Qwen HE QKV comparison shape mismatch");
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
    if (result.empty())
    {
        throw std::invalid_argument("token ID list must not be empty");
    }
    return result;
}

qwen::Tensor embedding_rows(
    const qwen::Tensor &embedding,
    const std::vector<std::size_t> &token_ids)
{
    if (embedding.rank() != 2)
    {
        throw std::invalid_argument("embedding table must be rank 2");
    }
    qwen::Tensor result({token_ids.size(), embedding.dim(1)});
    for (std::size_t token = 0; token < token_ids.size(); ++token)
    {
        if (token_ids[token] >= embedding.dim(0))
        {
            throw std::out_of_range(
                "Qwen HE token ID is outside the embedding table");
        }
        const auto begin =
            embedding.data().begin() +
            static_cast<std::ptrdiff_t>(
                token_ids[token] * embedding.dim(1));
        std::copy(
            begin,
            begin + static_cast<std::ptrdiff_t>(embedding.dim(1)),
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
                throw std::invalid_argument("missing value for " + argument);
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
                throw std::invalid_argument("unknown option: " + argument);
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
        const std::string attention =
            "model.layers.0.self_attn.";
        const qwen::Tensor norm_weight =
            weights.load("model.layers.0.input_layernorm.weight");
        const qwen::Tensor query_weight =
            weights.load(attention + "q_proj.weight");
        const qwen::Tensor query_bias =
            weights.load(attention + "q_proj.bias");
        const qwen::Tensor key_weight =
            weights.load(attention + "k_proj.weight");
        const qwen::Tensor key_bias =
            weights.load(attention + "k_proj.bias");
        const qwen::Tensor value_weight =
            weights.load(attention + "v_proj.weight");
        const qwen::Tensor value_bias =
            weights.load(attention + "v_proj.bias");

        const qwen::he::ApproximationConfig inverse_sqrt_config =
            qwen::he::first_layer_inverse_sqrt_config();
        const qwen::Tensor exact_normalized =
            qwen::rms_norm(hidden, norm_weight, config.rms_norm_epsilon);
        const qwen::Tensor polynomial_normalized =
            qwen::he::approximate_rms_norm_plain(
                hidden, norm_weight, config.rms_norm_epsilon,
                inverse_sqrt_config);
        const qwen::Tensor polynomial_query =
            qwen::linear(
                polynomial_normalized, query_weight, &query_bias);
        const qwen::Tensor polynomial_key =
            qwen::linear(
                polynomial_normalized, key_weight, &key_bias);
        const qwen::Tensor polynomial_value =
            qwen::linear(
                polynomial_normalized, value_weight, &value_bias);
        const qwen::Tensor exact_query =
            qwen::linear(exact_normalized, query_weight, &query_bias);
        const qwen::Tensor exact_key =
            qwen::linear(exact_normalized, key_weight, &key_bias);

        qwen::Tensor polynomial_query_rope =
            polynomial_query.reshape(
                {token_ids.size(), config.num_attention_heads,
                 config.head_dim});
        qwen::Tensor polynomial_key_rope =
            polynomial_key.reshape(
                {token_ids.size(), config.num_key_value_heads,
                 config.head_dim});
        qwen::apply_rope(
            polynomial_query_rope, polynomial_key_rope, 0,
            config.rope_theta);
        qwen::Tensor exact_query_rope =
            exact_query.reshape(
                {token_ids.size(), config.num_attention_heads,
                 config.head_dim});
        qwen::Tensor exact_key_rope =
            exact_key.reshape(
                {token_ids.size(), config.num_key_value_heads,
                 config.head_dim});
        qwen::apply_rope(
            exact_query_rope, exact_key_rope, 0, config.rope_theta);

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(qwen::he::debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_hidden =
            qwen::he::encrypt_tensor(hidden, runtime);
        const auto norm_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_normalized =
            qwen::he::encrypted_rms_norm(
                encrypted_hidden, norm_weight, config.rms_norm_epsilon,
                inverse_sqrt_config, runtime);
        const auto norm_stop = std::chrono::steady_clock::now();

        const auto query_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_query = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    query_weight, encrypted_normalized.cipher(0, 0),
                    runtime);
            return qwen::he::encrypted_linear(
                encrypted_normalized, encoded, &query_bias, runtime);
        }();
        const auto query_stop = std::chrono::steady_clock::now();
        const auto key_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_key = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    key_weight, encrypted_normalized.cipher(0, 0),
                    runtime);
            return qwen::he::encrypted_linear(
                encrypted_normalized, encoded, &key_bias, runtime);
        }();
        const auto key_stop = std::chrono::steady_clock::now();
        const auto value_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_value = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    value_weight, encrypted_normalized.cipher(0, 0),
                    runtime);
            return qwen::he::encrypted_linear(
                encrypted_normalized, encoded, &value_bias, runtime);
        }();
        const auto value_stop = std::chrono::steady_clock::now();
        const auto rope_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_query_rope =
            qwen::he::encrypted_rope(
                encrypted_query, config.num_attention_heads,
                config.head_dim, 0, config.rope_theta, runtime);
        const qwen::he::EncryptedTensor encrypted_key_rope =
            qwen::he::encrypted_rope(
                encrypted_key, config.num_key_value_heads,
                config.head_dim, 0, config.rope_theta, runtime);
        const auto rope_stop = std::chrono::steady_clock::now();

        const ErrorMetrics norm_approximation =
            compare(polynomial_normalized, exact_normalized);
        const ErrorMetrics norm_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_normalized, runtime),
            polynomial_normalized);
        const ErrorMetrics query_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_query, runtime),
            polynomial_query);
        const ErrorMetrics key_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_key, runtime),
            polynomial_key);
        const ErrorMetrics value_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_value, runtime),
            polynomial_value);
        const ErrorMetrics query_rope_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_query_rope, runtime),
            polynomial_query_rope.reshape(
                {token_ids.size(), config.hidden_size}));
        const ErrorMetrics key_rope_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_key_rope, runtime),
            polynomial_key_rope.reshape(
                {token_ids.size(),
                 config.num_key_value_heads * config.head_dim}));

        double score_min = std::numeric_limits<double>::infinity();
        double score_max = -std::numeric_limits<double>::infinity();
        const double scale =
            1.0 / std::sqrt(static_cast<double>(config.head_dim));
        for (std::size_t query_token = 0;
             query_token < token_ids.size(); ++query_token)
        {
            for (std::size_t key_token = 0;
                 key_token <= query_token; ++key_token)
            {
                for (std::size_t query_head = 0;
                     query_head < config.num_attention_heads; ++query_head)
                {
                    const std::size_t key_head =
                        query_head / config.query_group_size();
                    double score = 0.0;
                    for (std::size_t feature = 0;
                         feature < config.head_dim; ++feature)
                    {
                        score += exact_query_rope.at(
                                     query_token, query_head, feature) *
                                 exact_key_rope.at(
                                     key_token, key_head, feature);
                    }
                    score *= scale;
                    score_min = std::min(score_min, score);
                    score_max = std::max(score_max, score);
                }
            }
        }

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };
        std::cout << "Qwen CKKS real-checkpoint multi-token QKV validation\n"
                  << "stage=embedding->input_rmsnorm->q/k/v_proj->rope"
                  << " tokens=" << token_ids.size() << '\n';
        print_metrics("rmsnorm_approx_vs_exact", norm_approximation);
        print_metrics("rmsnorm_ckks_vs_polynomial", norm_ckks);
        print_metrics("q_proj_ckks_vs_polynomial", query_ckks);
        print_metrics("k_proj_ckks_vs_polynomial", key_ckks);
        print_metrics("v_proj_ckks_vs_polynomial", value_ckks);
        print_metrics("q_rope_ckks_vs_polynomial", query_rope_ckks);
        print_metrics("k_rope_ckks_vs_polynomial", key_rope_ckks);
        std::cout << "exact_causal_score_range=[" << score_min << ','
                  << score_max << "]\n"
                  << "chain_in="
                  << runtime.chain_index(encrypted_hidden.cipher(0, 0))
                  << " chain_norm="
                  << runtime.chain_index(
                         encrypted_normalized.cipher(0, 0))
                  << " chain_qkv="
                  << runtime.chain_index(encrypted_query.cipher(0, 0))
                  << " chain_rope="
                  << runtime.chain_index(
                         encrypted_query_rope.cipher(0, 0))
                  << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " rmsnorm_ms="
                  << milliseconds(norm_stop - norm_start)
                  << " q_proj_ms="
                  << milliseconds(query_stop - query_start)
                  << " k_proj_ms="
                  << milliseconds(key_stop - key_start)
                  << " v_proj_ms="
                  << milliseconds(value_stop - value_start)
                  << " rope_ms="
                  << milliseconds(rope_stop - rope_start) << '\n'
                  << "softmax_status=blocked-on-stable-private-normalization\n"
                  << "security=debug-not-production\n";

        if (norm_approximation.max_abs > 1.0e-5 ||
            norm_ckks.max_abs > 2.0e-4 ||
            query_ckks.max_abs > 2.0e-4 ||
            key_ckks.max_abs > 2.0e-4 ||
            value_ckks.max_abs > 2.0e-4 ||
            query_rope_ckks.max_abs > 2.0e-4 ||
            key_rope_ckks.max_abs > 2.0e-4)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_qkv: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
