#include "core/tensor.h"
#include "he/encrypted_decoder.h"
#include "he/encrypted_model.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "he/qwen25_05b_config.h"
#include "model/plain_decoder.h"
#include "model/plain_qwen.h"
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

ErrorMetrics compare(const qwen::Tensor &actual,
                     const qwen::Tensor &expected)
{
    if (actual.shape() != expected.shape())
    {
        throw std::invalid_argument(
            "Qwen encrypted decode comparison shape mismatch");
    }
    ErrorMetrics result;
    double square_sum = 0.0;
    for (std::size_t index = 0; index < actual.numel(); ++index)
    {
        const double difference =
            std::abs(actual.data()[index] - expected.data()[index]);
        result.max_abs = std::max(result.max_abs, difference);
        square_sum += difference * difference;
    }
    result.rmse =
        std::sqrt(square_sum / static_cast<double>(actual.numel()));
    return result;
}

std::vector<std::size_t> parse_token_ids(const std::string &text)
{
    std::vector<std::size_t> result;
    std::size_t begin = 0;
    while (begin < text.size())
    {
        const std::size_t end = text.find(',', begin);
        const std::string item = text.substr(
            begin, end == std::string::npos
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
    if (result.size() < 2)
    {
        throw std::invalid_argument(
            "encrypted decode requires at least two token IDs");
    }
    return result;
}

qwen::Tensor embed(const qwen::Tensor &embedding,
                   const std::vector<std::size_t> &token_ids)
{
    qwen::Tensor result({token_ids.size(), embedding.dim(1)});
    for (std::size_t token = 0; token < token_ids.size(); ++token)
    {
        if (token_ids[token] >= embedding.dim(0))
        {
            throw std::out_of_range(
                "Qwen token ID is outside the embedding table");
        }
        const auto source =
            embedding.data().begin() +
            static_cast<std::ptrdiff_t>(
                token_ids[token] * embedding.dim(1));
        std::copy(
            source,
            source + static_cast<std::ptrdiff_t>(embedding.dim(1)),
            result.data().begin() +
                static_cast<std::ptrdiff_t>(
                    token * embedding.dim(1)));
    }
    return result;
}

qwen::Tensor last_token(const qwen::Tensor &input)
{
    if (input.rank() != 2 || input.dim(0) == 0)
    {
        throw std::invalid_argument(
            "last_token expects a nonempty rank-2 tensor");
    }
    const std::size_t width = input.dim(1);
    const auto first =
        input.data().end() - static_cast<std::ptrdiff_t>(width);
    return qwen::Tensor(
        {1, width}, std::vector<double>(first, input.data().end()));
}

void print_usage(const char *program)
{
    std::cout
        << "Usage: " << program
        << " --model DIR [--input-ids N,N,...,N]"
           " [--max-layers N]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        std::filesystem::path model_directory;
        std::vector<std::size_t> token_ids{9707, 11, 847};
        std::size_t maximum_layers = 1;
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
            else if (argument == "--max-layers")
            {
                maximum_layers = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
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

        const qwen::QwenConfig model_config =
            qwen::load_qwen_config(
                model_directory / "config.json");
        qwen::QwenModelWeights weights =
            qwen::load_qwen_model_weights(model_directory);
        maximum_layers = std::min(
            maximum_layers, model_config.num_hidden_layers);
        if (maximum_layers == 0)
        {
            throw std::invalid_argument(
                "--max-layers must be positive");
        }
        weights.layers.resize(maximum_layers);

        const std::vector<std::size_t> prompt_ids(
            token_ids.begin(), token_ids.end() - 1);
        const std::vector<std::size_t> decode_ids{
            token_ids.back()};
        const qwen::Tensor full_input =
            embed(weights.token_embedding, token_ids);
        const qwen::Tensor prompt_input =
            embed(weights.token_embedding, prompt_ids);
        const qwen::Tensor decode_input =
            embed(weights.token_embedding, decode_ids);
        weights.token_embedding = qwen::Tensor{};

        std::vector<qwen::he::EncryptedDecoderApproximationConfig>
            approximations;
        approximations.reserve(maximum_layers);
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            auto approximation =
                qwen::he::qwen25_05b_layer_approximation(
                    layer, token_ids.size());
            qwen::he::set_decoder_bootstrap_schedule(
                approximation,
                qwen::he::RefreshMode::debug_bootstrap);
            qwen::he::remove_redundant_rmsnorm_refreshes(
                approximation);
            approximations.push_back(std::move(approximation));
        }

        qwen::Tensor exact_full = full_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            exact_full = qwen::PlainDecoderLayer(
                model_config, weights.layers[layer])
                             .forward(exact_full);
        }

        std::vector<qwen::KVCache> exact_caches(maximum_layers);
        qwen::Tensor exact_prompt = prompt_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            exact_prompt = qwen::PlainDecoderLayer(
                model_config, weights.layers[layer])
                               .forward(
                                   exact_prompt,
                                   &exact_caches[layer]);
        }
        qwen::Tensor exact_decode = decode_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            exact_decode = qwen::PlainDecoderLayer(
                model_config, weights.layers[layer])
                               .forward(
                                   exact_decode,
                                   &exact_caches[layer]);
        }
        const ErrorMetrics exact_cache =
            compare(exact_decode, last_token(exact_full));

        qwen::Tensor polynomial_full = full_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            polynomial_full =
                qwen::he::approximate_decoder_layer(
                    polynomial_full, weights.layers[layer],
                    model_config, approximations[layer], 0);
        }

        std::vector<qwen::KVCache> polynomial_caches(
            maximum_layers);
        std::vector<std::map<std::string, qwen::Tensor>>
            prompt_traces(maximum_layers);
        std::vector<std::map<std::string, qwen::Tensor>>
            decode_traces(maximum_layers);
        qwen::Tensor polynomial_prompt = prompt_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            polynomial_prompt =
                qwen::he::approximate_decoder_layer(
                    polynomial_prompt, weights.layers[layer],
                    model_config, approximations[layer], 0,
                    [&](const std::string &name,
                        const qwen::Tensor &tensor) {
                        prompt_traces[layer][name] = tensor;
                    },
                    &polynomial_caches[layer]);
        }
        qwen::Tensor polynomial_decode = decode_input;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            polynomial_decode =
                qwen::he::approximate_decoder_layer(
                    polynomial_decode, weights.layers[layer],
                    model_config, approximations[layer],
                    prompt_ids.size(),
                    [&](const std::string &name,
                        const qwen::Tensor &tensor) {
                        decode_traces[layer][name] = tensor;
                    },
                    &polynomial_caches[layer]);
        }
        const ErrorMetrics polynomial_cache =
            compare(polynomial_decode, last_token(polynomial_full));
        const ErrorMetrics polynomial_exact =
            compare(polynomial_decode, exact_decode);

        std::cout
            << "Qwen encrypted KV-cache decode validation\n"
            << "tokens=" << token_ids.size()
            << " prompt_tokens=" << prompt_ids.size()
            << " layers=" << maximum_layers << '\n'
            << "exact_cached_vs_full max_abs="
            << exact_cache.max_abs
            << " rmse=" << exact_cache.rmse << '\n'
            << "polynomial_cached_vs_full max_abs="
            << polynomial_cache.max_abs
            << " rmse=" << polynomial_cache.rmse << '\n'
            << "polynomial_vs_exact max_abs="
            << polynomial_exact.max_abs
            << " rmse=" << polynomial_exact.rmse << '\n';

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(
                qwen::he::deep_debug_he_config());
        const auto runtime_stop = std::chrono::steady_clock::now();
        std::vector<qwen::he::EncryptedKVCache> encrypted_caches;
        double maximum_ckks_error = 0.0;
        const auto compare_trace =
            [&](const char *phase,
                const std::vector<
                    std::map<std::string, qwen::Tensor>> &references,
                std::size_t layer, const std::string &name,
                const qwen::he::EncryptedTensor &tensor) {
                const auto found = references[layer].find(name);
                if (found == references[layer].end())
                {
                    throw std::runtime_error(
                        "missing polynomial decode trace node");
                }
                const ErrorMetrics metrics = compare(
                    qwen::he::decrypt_tensor(tensor, runtime),
                    found->second);
                maximum_ckks_error = std::max(
                    maximum_ckks_error, metrics.max_abs);
                std::cout << "trace=" << phase << ".layer_"
                          << layer << '.' << name << " chain="
                          << runtime.chain_index(
                                 tensor.cipher(0, 0))
                          << " max_abs=" << metrics.max_abs
                          << " rmse=" << metrics.rmse << '\n';
            };

        const auto encrypted_start = std::chrono::steady_clock::now();
        const qwen::he::EncryptedTensor encrypted_prompt =
            qwen::he::encrypted_decoder_stack(
                qwen::he::encrypt_tensor(prompt_input, runtime),
                weights.layers, model_config, approximations, 0,
                runtime,
                [&](std::size_t layer, const std::string &name,
                    const qwen::he::EncryptedTensor &tensor) {
                    compare_trace(
                        "prefill", prompt_traces, layer, name,
                        tensor);
                },
                &encrypted_caches);
        const ErrorMetrics encrypted_prompt_metrics = compare(
            qwen::he::decrypt_tensor(encrypted_prompt, runtime),
            polynomial_prompt);
        const qwen::he::EncryptedTensor encrypted_decode =
            qwen::he::encrypted_decoder_stack(
                qwen::he::encrypt_tensor(decode_input, runtime),
                weights.layers, model_config, approximations,
                prompt_ids.size(), runtime,
                [&](std::size_t layer, const std::string &name,
                    const qwen::he::EncryptedTensor &tensor) {
                    compare_trace(
                        "decode", decode_traces, layer, name,
                        tensor);
                },
                &encrypted_caches);
        const auto encrypted_stop = std::chrono::steady_clock::now();
        const ErrorMetrics encrypted_decode_metrics = compare(
            qwen::he::decrypt_tensor(encrypted_decode, runtime),
            polynomial_decode);

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<
                       std::chrono::milliseconds>(duration)
                .count();
        };
        std::cout
            << "encrypted_prefill_vs_polynomial max_abs="
            << encrypted_prompt_metrics.max_abs
            << " rmse=" << encrypted_prompt_metrics.rmse << '\n'
            << "encrypted_decode_vs_polynomial max_abs="
            << encrypted_decode_metrics.max_abs
            << " rmse=" << encrypted_decode_metrics.rmse << '\n'
            << "cache_tokens="
            << encrypted_caches.front().size()
            << " output_level="
            << runtime.chain_index(
                   encrypted_decode.cipher(0, 0))
            << '\n'
            << "runtime_ms="
            << milliseconds(runtime_stop - runtime_start)
            << " encrypted_prefill_decode_ms="
            << milliseconds(encrypted_stop - encrypted_start)
            << '\n';

        if (exact_cache.max_abs > 1.0e-10 ||
            polynomial_cache.max_abs > 1.0e-10 ||
            polynomial_exact.max_abs > 1.0e-2 ||
            maximum_ckks_error > 1.0e-2 ||
            encrypted_prompt_metrics.max_abs > 1.0e-2 ||
            encrypted_decode_metrics.max_abs > 1.0e-2)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_decode: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
