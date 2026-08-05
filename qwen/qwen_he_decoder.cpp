#include "core/tensor.h"
#include "he/encrypted_decoder.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "io/safetensors.h"
#include "model/plain_decoder.h"
#include "model/qwen_config.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
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
            "Qwen HE decoder comparison shape mismatch");
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
            "current encrypted decoder validation requires two token IDs");
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

qwen::Tensor load_optional(
    const qwen::SafeTensorStore &store, const std::string &name)
{
    return store.contains(name) ? store.load(name) : qwen::Tensor{};
}

qwen::DecoderLayerWeights load_layer_zero(
    const qwen::SafeTensorStore &store)
{
    const std::string layer = "model.layers.0.";
    const std::string attention = layer + "self_attn.";
    const std::string mlp = layer + "mlp.";
    qwen::DecoderLayerWeights weights;
    weights.input_norm =
        store.load(layer + "input_layernorm.weight");
    weights.query_weight =
        store.load(attention + "q_proj.weight");
    weights.query_bias =
        load_optional(store, attention + "q_proj.bias");
    weights.key_weight =
        store.load(attention + "k_proj.weight");
    weights.key_bias =
        load_optional(store, attention + "k_proj.bias");
    weights.value_weight =
        store.load(attention + "v_proj.weight");
    weights.value_bias =
        load_optional(store, attention + "v_proj.bias");
    weights.output_weight =
        store.load(attention + "o_proj.weight");
    weights.post_attention_norm =
        store.load(layer + "post_attention_layernorm.weight");
    weights.gate_weight =
        store.load(mlp + "gate_proj.weight");
    weights.up_weight =
        store.load(mlp + "up_proj.weight");
    weights.down_weight =
        store.load(mlp + "down_proj.weight");
    return weights;
}

void print_usage(const char *program)
{
    std::cout << "Usage: " << program
              << " --model DIR [--input-ids N,N]"
                 " [--bootstrap-schedule]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        std::filesystem::path model_directory;
        std::vector<std::size_t> token_ids{9707, 11};
        bool bootstrap_schedule = false;
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument(argv[index]);
            if (argument == "--help")
            {
                print_usage(argv[0]);
                return 0;
            }
            if (argument == "--bootstrap-schedule")
            {
                bootstrap_schedule = true;
                continue;
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
        qwen::SafeTensorStore store(model_directory);
        qwen::Tensor embedding =
            store.load("model.embed_tokens.weight");
        const qwen::Tensor input =
            embedding_rows(embedding, token_ids);
        embedding = qwen::Tensor{};
        const qwen::DecoderLayerWeights weights =
            load_layer_zero(store);
        weights.validate(config);
        qwen::he::EncryptedDecoderApproximationConfig approximation{
            qwen::he::first_layer_inverse_sqrt_config(),
            qwen::he::first_layer_inverse_sqrt_config(),
            {{2048.0}, {-24.5, 0.25, 32}, {0.70, 2.50, 32}},
            qwen::he::silu_config(),
            qwen::he::RefreshMode::debug_reencrypt,
            qwen::he::RefreshMode::debug_reencrypt,
        };
        if (bootstrap_schedule)
        {
            qwen::he::set_decoder_bootstrap_schedule(
                approximation,
                qwen::he::RefreshMode::debug_bootstrap);
            qwen::he::remove_redundant_rmsnorm_refreshes(
                approximation);
        }

        std::map<std::string, qwen::Tensor> plain_trace;
        const auto plain_start = std::chrono::steady_clock::now();
        const qwen::Tensor polynomial_output =
            qwen::he::approximate_decoder_layer(
                input, weights, config, approximation, 0,
                [&](const std::string &name,
                    const qwen::Tensor &tensor) {
                    plain_trace[name] = tensor;
                });
        const auto plain_stop = std::chrono::steady_clock::now();
        const qwen::PlainDecoderLayer exact_layer(config, weights);
        const qwen::Tensor exact_output = exact_layer.forward(input);
        const ErrorMetrics approximation_total =
            compare(polynomial_output, exact_output);
        std::cout << "plain_reference=ready"
                  << " approximation_max_abs="
                  << approximation_total.max_abs << '\n';

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(
                qwen::he::deep_debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        std::cout << "he_runtime=ready\n";
        const qwen::he::EncryptedTensor encrypted_input =
            qwen::he::encrypt_tensor(input, runtime);
        std::map<std::string, ErrorMetrics> encrypted_metrics;
        const auto encrypted_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_output =
            qwen::he::encrypted_decoder_layer(
                encrypted_input, weights, config, approximation, 0,
                runtime,
                [&](const std::string &name,
                    const qwen::he::EncryptedTensor &tensor) {
                    const auto reference = plain_trace.find(name);
                    if (reference == plain_trace.end())
                    {
                        throw std::runtime_error(
                            "missing plaintext trace node " + name);
                    }
                    const ErrorMetrics metrics = compare(
                        qwen::he::decrypt_tensor(tensor, runtime),
                        reference->second);
                    encrypted_metrics[name] = metrics;
                    std::cout << "trace=" << name
                              << " chain="
                              << runtime.chain_index(tensor.cipher(0, 0))
                              << " max_abs=" << metrics.max_abs
                              << " rmse=" << metrics.rmse << '\n';
                });
        const auto encrypted_stop = std::chrono::steady_clock::now();
        const ErrorMetrics return_metrics = compare(
            qwen::he::decrypt_tensor(encrypted_output, runtime),
            polynomial_output);

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };
        std::cout << "Qwen CKKS real-checkpoint decoder layer validation\n"
                  << "stage=layer_0 tokens=2 trace_nodes="
                  << encrypted_metrics.size() << '\n'
                  << "node                              max_abs       rmse\n";
        double maximum_ckks_error = 0.0;
        for (const auto &[name, metrics] : encrypted_metrics)
        {
            std::cout << name;
            if (name.size() < 34)
            {
                std::cout << std::string(34 - name.size(), ' ');
            }
            std::cout << metrics.max_abs << "  " << metrics.rmse
                      << '\n';
            maximum_ckks_error =
                std::max(maximum_ckks_error, metrics.max_abs);
        }
        std::cout << "return_ckks_vs_polynomial max_abs="
                  << return_metrics.max_abs
                  << " rmse=" << return_metrics.rmse << '\n'
                  << "layer_approx_vs_exact max_abs="
                  << approximation_total.max_abs
                  << " rmse=" << approximation_total.rmse << '\n'
                  << "chain_in="
                  << runtime.chain_index(encrypted_input.cipher(0, 0))
                  << " chain_out="
                  << runtime.chain_index(encrypted_output.cipher(0, 0))
                  << '\n'
                  << "plain_polynomial_ms="
                  << milliseconds(plain_stop - plain_start)
                  << " runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " encrypted_layer_ms="
                  << milliseconds(encrypted_stop - encrypted_start)
                  << '\n'
                  << "refresh="
                  << (bootstrap_schedule
                          ? "debug-bootstrap-level-19"
                          : "debug-reencrypt")
                  << " security=deep-debug-not-production\n";

        if (encrypted_metrics.size() != plain_trace.size() ||
            maximum_ckks_error > 3.0e-3 ||
            return_metrics.max_abs > 3.0e-3 ||
            approximation_total.max_abs > 3.0e-3)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_decoder: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
