#include "core/tensor.h"
#include "he/approximation.h"
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
        throw std::invalid_argument("Qwen HE MLP comparison shape mismatch");
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

const qwen::Tensor *optional_bias(const qwen::Tensor &bias)
{
    return bias.empty() ? nullptr : &bias;
}

qwen::Tensor make_layer_zero_mlp_input(
    const qwen::Tensor &hidden, const qwen::QwenConfig &config,
    qwen::SafeTensorStore &weights)
{
    const std::string layer = "model.layers.0.";
    const std::string attention = layer + "self_attn.";
    const qwen::Tensor normalized = qwen::rms_norm(
        hidden, weights.load(layer + "input_layernorm.weight"),
        config.rms_norm_epsilon);

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

    qwen::Tensor query = qwen::split_heads(
        qwen::linear(normalized, query_weight, optional_bias(query_bias)),
        config.num_attention_heads, config.head_dim);
    qwen::Tensor key = qwen::split_heads(
        qwen::linear(normalized, key_weight, optional_bias(key_bias)),
        config.num_key_value_heads, config.head_dim);
    const qwen::Tensor value = qwen::split_heads(
        qwen::linear(normalized, value_weight, optional_bias(value_bias)),
        config.num_key_value_heads, config.head_dim);
    qwen::apply_rope(query, key, 0, config.rope_theta);
    const qwen::Tensor attention_output = qwen::linear(
        qwen::merge_heads(
            qwen::causal_gqa_attention(query, key, value, config)),
        weights.load(attention + "o_proj.weight"));
    const qwen::Tensor post_attention = qwen::add(hidden, attention_output);
    return qwen::rms_norm(
        post_attention,
        weights.load(layer + "post_attention_layernorm.weight"),
        config.rms_norm_epsilon);
}

void print_metrics(const char *name, const ErrorMetrics &metrics)
{
    std::cout << name << " max_abs=" << metrics.max_abs
              << " rmse=" << metrics.rmse << '\n';
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

        const qwen::QwenConfig config =
            qwen::load_qwen_config(model_directory / "config.json");
        qwen::SafeTensorStore weights(model_directory);
        qwen::Tensor embedding =
            weights.load("model.embed_tokens.weight");
        const qwen::Tensor hidden = embedding_row(embedding, token_id);
        embedding = qwen::Tensor{};
        const qwen::Tensor mlp_input =
            make_layer_zero_mlp_input(hidden, config, weights);

        const std::string mlp = "model.layers.0.mlp.";
        const qwen::Tensor gate_weight =
            weights.load(mlp + "gate_proj.weight");
        const qwen::Tensor up_weight =
            weights.load(mlp + "up_proj.weight");
        const qwen::Tensor down_weight =
            weights.load(mlp + "down_proj.weight");
        const qwen::Tensor exact_gate =
            qwen::linear(mlp_input, gate_weight);
        const qwen::Tensor exact_up =
            qwen::linear(mlp_input, up_weight);

        const qwen::he::ApproximationConfig silu_config =
            qwen::he::silu_config();
        const qwen::Tensor polynomial_silu =
            qwen::he::approximate_silu_plain(exact_gate, silu_config);
        const qwen::Tensor exact_swiglu =
            qwen::swiglu(exact_gate, exact_up);
        const qwen::Tensor polynomial_swiglu =
            qwen::multiply(polynomial_silu, exact_up);
        const qwen::Tensor exact_down =
            qwen::linear(exact_swiglu, down_weight);
        const qwen::Tensor polynomial_down =
            qwen::linear(polynomial_swiglu, down_weight);

        const qwen::TensorStats gate_stats = qwen::tensor_stats(exact_gate);
        if (gate_stats.min < silu_config.minimum ||
            gate_stats.max > silu_config.maximum)
        {
            throw std::runtime_error(
                "layer_0 gate activation is outside the calibrated SiLU interval");
        }

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(qwen::he::debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_input =
            qwen::he::encrypt_tensor(mlp_input, runtime);

        const auto gate_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_gate = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    gate_weight, encrypted_input.cipher(0, 0), runtime);
            return qwen::he::encrypted_linear(
                encrypted_input, encoded, nullptr, runtime);
        }();
        const auto gate_stop = std::chrono::steady_clock::now();

        const auto up_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_up = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    up_weight, encrypted_input.cipher(0, 0), runtime);
            return qwen::he::encrypted_linear(
                encrypted_input, encoded, nullptr, runtime);
        }();
        const auto up_stop = std::chrono::steady_clock::now();

        const auto activation_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_silu =
            qwen::he::encrypted_silu(
                encrypted_gate, silu_config, runtime);
        const qwen::he::EncryptedTensor encrypted_swiglu =
            qwen::he::encrypted_multiply(
                encrypted_silu, encrypted_up, runtime);
        const auto activation_stop = std::chrono::steady_clock::now();

        const auto down_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_down = [&] {
            const qwen::he::EncodedLinear encoded =
                qwen::he::encode_linear_at(
                    down_weight, encrypted_swiglu.cipher(0, 0), runtime);
            return qwen::he::encrypted_linear(
                encrypted_swiglu, encoded, nullptr, runtime);
        }();
        const auto down_stop = std::chrono::steady_clock::now();

        const ErrorMetrics gate_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_gate, runtime), exact_gate);
        const ErrorMetrics up_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_up, runtime), exact_up);
        const ErrorMetrics silu_approximation =
            compare(polynomial_silu, qwen::silu(exact_gate));
        const ErrorMetrics silu_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_silu, runtime),
            polynomial_silu);
        const ErrorMetrics swiglu_approximation =
            compare(polynomial_swiglu, exact_swiglu);
        const ErrorMetrics swiglu_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_swiglu, runtime),
            polynomial_swiglu);
        const qwen::Tensor decrypted_down =
            qwen::he::decrypt_tensor(encrypted_down, runtime);
        const ErrorMetrics down_ckks =
            compare(decrypted_down, polynomial_down);
        const ErrorMetrics down_total =
            compare(decrypted_down, exact_down);

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };
        std::cout << "Qwen CKKS real-checkpoint MLP validation\n"
                  << "stage=layer_0.post_attention_rmsnorm->gate/up->"
                     "polynomial_silu->swiglu->down token_id="
                  << token_id << '\n'
                  << "gate_range=[" << gate_stats.min << ','
                  << gate_stats.max << "] silu_interval=["
                  << silu_config.minimum << ',' << silu_config.maximum
                  << "]\n";
        print_metrics("gate_ckks_vs_exact", gate_ckks);
        print_metrics("up_ckks_vs_exact", up_ckks);
        print_metrics("silu_approx_vs_exact", silu_approximation);
        print_metrics("silu_ckks_vs_polynomial", silu_ckks);
        print_metrics("swiglu_approx_vs_exact", swiglu_approximation);
        print_metrics("swiglu_ckks_vs_polynomial", swiglu_ckks);
        print_metrics("down_ckks_vs_polynomial", down_ckks);
        print_metrics("down_total_vs_exact", down_total);
        std::cout << "chain_in="
                  << runtime.chain_index(encrypted_input.cipher(0, 0))
                  << " chain_gate="
                  << runtime.chain_index(encrypted_gate.cipher(0, 0))
                  << " chain_silu="
                  << runtime.chain_index(encrypted_silu.cipher(0, 0))
                  << " chain_swiglu="
                  << runtime.chain_index(encrypted_swiglu.cipher(0, 0))
                  << " chain_down="
                  << runtime.chain_index(encrypted_down.cipher(0, 0))
                  << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " gate_encode_and_linear_ms="
                  << milliseconds(gate_stop - gate_start)
                  << " up_encode_and_linear_ms="
                  << milliseconds(up_stop - up_start)
                  << " silu_and_swiglu_ms="
                  << milliseconds(activation_stop - activation_start)
                  << " down_encode_and_linear_ms="
                  << milliseconds(down_stop - down_start) << '\n'
                  << "security=debug-not-production\n";

        if (gate_ckks.max_abs > 2.0e-4 ||
            up_ckks.max_abs > 2.0e-4 ||
            silu_ckks.max_abs > 5.0e-4 ||
            swiglu_ckks.max_abs > 1.0e-3 ||
            down_ckks.max_abs > 2.0e-3)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_mlp: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
