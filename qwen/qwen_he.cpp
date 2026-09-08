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
#include <stdexcept>
#include <string>

namespace
{

struct ErrorMetrics
{
    double max_abs = 0.0;
    double mean_abs = 0.0;
    double rmse = 0.0;
};

ErrorMetrics compare(const qwen::Tensor &actual, const qwen::Tensor &expected)
{
    if (actual.shape() != expected.shape())
    {
        throw std::invalid_argument("Qwen HE comparison shape mismatch");
    }
    ErrorMetrics metrics;
    double absolute_sum = 0.0;
    double square_sum = 0.0;
    for (std::size_t index = 0; index < actual.numel(); ++index)
    {
        const double difference =
            std::abs(actual.data()[index] - expected.data()[index]);
        metrics.max_abs = std::max(metrics.max_abs, difference);
        absolute_sum += difference;
        square_sum += difference * difference;
    }
    metrics.mean_abs = absolute_sum / static_cast<double>(actual.numel());
    metrics.rmse =
        std::sqrt(square_sum / static_cast<double>(actual.numel()));
    return metrics;
}

std::size_t parse_token_id(const char *text)
{
    std::size_t parsed = 0;
    const std::string value(text);
    const unsigned long long token = std::stoull(value, &parsed);
    if (parsed != value.size())
    {
        throw std::invalid_argument("invalid token ID");
    }
    return static_cast<std::size_t>(token);
}

qwen::Tensor embedding_row(const qwen::Tensor &embedding, std::size_t token)
{
    if (embedding.rank() != 2 || token >= embedding.dim(0))
    {
        throw std::out_of_range("Qwen HE token ID is outside the embedding table");
    }
    qwen::Tensor result({1, embedding.dim(1)});
    const auto begin = embedding.data().begin() +
                       static_cast<std::ptrdiff_t>(token * embedding.dim(1));
    std::copy(begin, begin + static_cast<std::ptrdiff_t>(embedding.dim(1)),
              result.data().begin());
    return result;
}

void print_usage(const char *program)
{
    std::cout << "Usage: " << program
              << " --model DIR [--token-id N]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::filesystem::path model_directory;
        std::size_t token_id = 9707;
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
            else if (argument == "--token-id")
            {
                token_id = parse_token_id(argv[++index]);
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

        const qwen::QwenConfig model_config =
            qwen::load_qwen_config(model_directory / "config.json");
        if (model_config.hidden_size != 896)
        {
            throw std::invalid_argument(
                "initial encrypted Qwen validation expects hidden_size=896");
        }
        qwen::SafeTensorStore weights(model_directory);
        qwen::Tensor embedding =
            weights.load("model.embed_tokens.weight");
        const qwen::Tensor hidden = embedding_row(embedding, token_id);
        embedding = qwen::Tensor{};
        const qwen::Tensor norm_weight =
            weights.load("model.layers.0.input_layernorm.weight");
        const qwen::Tensor exact_normalized =
            qwen::rms_norm(hidden, norm_weight,
                           model_config.rms_norm_epsilon);
        const qwen::he::ApproximationConfig inverse_sqrt_config =
            qwen::he::first_layer_inverse_sqrt_config();
        const qwen::Tensor polynomial_normalized =
            qwen::he::approximate_rms_norm_plain(
                hidden, norm_weight, model_config.rms_norm_epsilon,
                inverse_sqrt_config);
        const qwen::Tensor query_weight =
            weights.load("model.layers.0.self_attn.q_proj.weight");
        const qwen::Tensor query_bias =
            weights.load("model.layers.0.self_attn.q_proj.bias");
        const qwen::Tensor exact_query =
            qwen::linear(exact_normalized, query_weight, &query_bias);
        const qwen::Tensor polynomial_query =
            qwen::linear(polynomial_normalized, query_weight, &query_bias);

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(qwen::he::debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_hidden =
            qwen::he::encrypt_tensor(hidden, runtime);
        const auto norm_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_normalized =
            qwen::he::encrypted_rms_norm(
                encrypted_hidden, norm_weight, model_config.rms_norm_epsilon,
                inverse_sqrt_config, runtime);
        const auto norm_stop = std::chrono::steady_clock::now();
        const qwen::Tensor decrypted_normalized =
            qwen::he::decrypt_tensor(encrypted_normalized, runtime);

        const auto encode_start = std::chrono::steady_clock::now();
        const qwen::he::EncodedLinear encoded_query =
            qwen::he::encode_linear_at(
                query_weight, encrypted_normalized.cipher(0, 0), runtime);
        const auto encode_stop = std::chrono::steady_clock::now();

        const auto inference_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_query =
            qwen::he::encrypted_linear(encrypted_normalized, encoded_query,
                                       &query_bias, runtime);
        const auto inference_stop = std::chrono::steady_clock::now();
        const qwen::Tensor decrypted_query =
            qwen::he::decrypt_tensor(encrypted_query, runtime);
        const ErrorMetrics norm_approximation_metrics =
            compare(polynomial_normalized, exact_normalized);
        const ErrorMetrics norm_ckks_metrics =
            compare(decrypted_normalized, polynomial_normalized);
        const ErrorMetrics query_approximation_metrics =
            compare(polynomial_query, exact_query);
        const ErrorMetrics query_ckks_metrics =
            compare(decrypted_query, polynomial_query);
        const ErrorMetrics query_total_metrics =
            compare(decrypted_query, exact_query);

        qwen::Tensor rope_reference =
            polynomial_query.reshape({1, model_config.num_attention_heads,
                                      model_config.head_dim});
        qwen::Tensor unused_key = rope_reference;
        qwen::apply_rope(rope_reference, unused_key, 1,
                         model_config.rope_theta);
        const auto rope_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_query_rope =
            qwen::he::encrypted_rope(
                encrypted_query, model_config.num_attention_heads,
                model_config.head_dim, 1, model_config.rope_theta, runtime);
        const auto rope_stop = std::chrono::steady_clock::now();
        const ErrorMetrics rope_metrics =
            compare(qwen::he::decrypt_tensor(encrypted_query_rope, runtime),
                    rope_reference.reshape({1, model_config.hidden_size}));
        qwen::Tensor exact_rope_reference =
            exact_query.reshape({1, model_config.num_attention_heads,
                                 model_config.head_dim});
        unused_key = exact_rope_reference;
        qwen::apply_rope(exact_rope_reference, unused_key, 1,
                         model_config.rope_theta);
        const ErrorMetrics rope_total_metrics =
            compare(qwen::he::decrypt_tensor(encrypted_query_rope, runtime),
                    exact_rope_reference.reshape(
                        {1, model_config.hidden_size}));

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };
        std::cout << "Qwen CKKS real-checkpoint composed validation\n"
                  << "stage=embedding->layer_0.input_rmsnorm->q_proj->rope"
                  << " token_id=" << token_id
                  << " input_shape=" << qwen::shape_string(hidden)
                  << " output_shape=" << qwen::shape_string(polynomial_query)
                  << '\n'
                  << "rmsnorm_approx_vs_exact max_abs="
                  << norm_approximation_metrics.max_abs
                  << " rmse=" << norm_approximation_metrics.rmse << '\n'
                  << "rmsnorm_ckks_vs_polynomial max_abs="
                  << norm_ckks_metrics.max_abs
                  << " rmse=" << norm_ckks_metrics.rmse << '\n'
                  << "q_proj_approx_vs_exact max_abs="
                  << query_approximation_metrics.max_abs
                  << " rmse=" << query_approximation_metrics.rmse << '\n'
                  << "q_proj_ckks_vs_polynomial max_abs="
                  << query_ckks_metrics.max_abs
                  << " rmse=" << query_ckks_metrics.rmse << '\n'
                  << "q_proj_total_vs_exact max_abs="
                  << query_total_metrics.max_abs
                  << " rmse=" << query_total_metrics.rmse << '\n'
                  << "rope_ckks_vs_polynomial max_abs="
                  << rope_metrics.max_abs
                  << " rmse=" << rope_metrics.rmse << '\n'
                  << "rope_total_vs_exact max_abs="
                  << rope_total_metrics.max_abs
                  << " rmse=" << rope_total_metrics.rmse << '\n'
                  << "chain_in="
                  << runtime.chain_index(encrypted_hidden.cipher(0, 0))
                  << " chain_norm="
                  << runtime.chain_index(encrypted_normalized.cipher(0, 0))
                  << " chain_q="
                  << runtime.chain_index(encrypted_query.cipher(0, 0))
                  << " chain_rope="
                  << runtime.chain_index(encrypted_query_rope.cipher(0, 0))
                  << " scale_in=" << encrypted_hidden.cipher(0, 0).scale()
                  << " scale_out=" << encrypted_query.cipher(0, 0).scale()
                  << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " encrypted_rmsnorm_ms="
                  << milliseconds(norm_stop - norm_start)
                  << " weight_encode_ms="
                  << milliseconds(encode_stop - encode_start)
                  << " encrypted_linear_ms="
                  << milliseconds(inference_stop - inference_start)
                  << " encrypted_rope_ms="
                  << milliseconds(rope_stop - rope_start) << '\n'
                  << "security=debug-not-production\n";
        if (norm_approximation_metrics.max_abs > 1.0e-5 ||
            norm_ckks_metrics.max_abs > 2.0e-4 ||
            query_ckks_metrics.max_abs > 2.0e-4 ||
            rope_metrics.max_abs > 2.0e-4)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
