#include "core/tensor.h"
#include "he/encrypted_decoder.h"
#include "he/qwen25_05b_config.h"
#include "model/plain_decoder.h"
#include "model/plain_qwen.h"
#include "model/qwen_config.h"
#include "ops/plain_ops.h"

#include <algorithm>
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

ErrorMetrics compare(const qwen::Tensor &actual,
                     const qwen::Tensor &expected)
{
    if (actual.shape() != expected.shape())
    {
        throw std::invalid_argument(
            "Qwen polynomial stack comparison shape mismatch");
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
    if (result.empty())
    {
        throw std::invalid_argument("token ID list is empty");
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
        << " --model DIR [--input-ids N,N,...] [--max-layers N]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::filesystem::path model_directory;
        std::vector<std::size_t> token_ids{9707, 11, 847};
        std::size_t maximum_layers = 24;
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
                maximum_layers =
                    static_cast<std::size_t>(
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
        qwen::Tensor exact = embed(weights.token_embedding, token_ids);
        qwen::Tensor polynomial = exact;

        std::cout << std::unitbuf
                  << "Qwen polynomial decoder stack validation\n"
                  << "tokens=" << token_ids.size()
                  << " layers=" << maximum_layers << '\n'
                  << "layer  max_abs       rmse          silu_max_abs  interval_outside  gate_range\n";
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            qwen::he::EncryptedDecoderApproximationConfig approximation =
                qwen::he::qwen25_05b_layer_approximation(
                    layer, token_ids.size());
            qwen::Tensor gate;
            qwen::Tensor approximated_silu;
            polynomial = qwen::he::approximate_decoder_layer(
                polynomial, weights.layers[layer], model_config,
                approximation, 0,
                [&](const std::string &name, const qwen::Tensor &value) {
                    if (name == "mlp_gate")
                    {
                        gate = value;
                    }
                    else if (name == "mlp_silu")
                    {
                        approximated_silu = value;
                    }
                });

            qwen::PlainDecoderLayer exact_layer(
                model_config, std::move(weights.layers[layer]));
            exact = exact_layer.forward(exact);
            const ErrorMetrics metrics = compare(polynomial, exact);
            const ErrorMetrics silu_metrics = compare(
                approximated_silu, qwen::silu(gate));
            const auto [gate_minimum, gate_maximum] =
                std::minmax_element(gate.data().begin(), gate.data().end());
            double interval_outside = 0.0;
            for (std::size_t token = 0; token < gate.dim(0); ++token)
            {
                const auto position_features =
                    approximation.silu_feature_overrides.find(token);
                const std::vector<qwen::he::ApproximationConfig> &configs =
                    position_features ==
                            approximation.silu_feature_overrides.end()
                        ? approximation.silu_feature_configs
                        : position_features->second;
                for (std::size_t feature = 0; feature < gate.dim(1);
                     ++feature)
                {
                    const double value = gate.at(token, feature);
                    interval_outside = std::max(
                        interval_outside,
                        std::max(configs[feature].minimum - value,
                                 value - configs[feature].maximum));
                }
            }
            interval_outside = std::max(0.0, interval_outside);
            std::cout << layer;
            if (layer < 10)
            {
                std::cout << ' ';
            }
            std::cout << "     " << metrics.max_abs
                      << "  " << metrics.rmse
                      << "  " << silu_metrics.max_abs
                      << "  " << interval_outside
                      << "  [" << *gate_minimum << ',' << *gate_maximum
                      << "]\n";
            if (!std::isfinite(metrics.max_abs) ||
                metrics.max_abs > 5.0e-1)
            {
                std::cerr << "result=FAIL layer=" << layer << '\n';
                return 1;
            }
        }
        const ErrorMetrics total = compare(polynomial, exact);
        if (maximum_layers == model_config.num_hidden_layers)
        {
            const qwen::Tensor exact_final = qwen::rms_norm(
                exact, weights.final_norm,
                model_config.rms_norm_epsilon);
            const qwen::Tensor polynomial_final =
                qwen::he::approximate_rms_norm_plain(
                    polynomial, weights.final_norm,
                    model_config.rms_norm_epsilon,
                    qwen::he::
                        qwen25_05b_final_inverse_sqrt_config());
            const ErrorMetrics final_norm =
                compare(polynomial_final, exact_final);
            const qwen::Tensor &lm_head =
                weights.lm_head.empty()
                    ? weights.token_embedding
                    : weights.lm_head;
            const qwen::Tensor exact_logits = qwen::linear(
                last_token(exact_final), lm_head);
            const qwen::Tensor polynomial_logits = qwen::linear(
                last_token(polynomial_final), lm_head);
            const ErrorMetrics logits =
                compare(polynomial_logits, exact_logits);
            const auto exact_argmax = static_cast<std::size_t>(
                std::max_element(
                    exact_logits.data().begin(),
                    exact_logits.data().end()) -
                exact_logits.data().begin());
            const auto polynomial_argmax =
                static_cast<std::size_t>(
                    std::max_element(
                        polynomial_logits.data().begin(),
                        polynomial_logits.data().end()) -
                    polynomial_logits.data().begin());
            std::cout
                << "final_rmsnorm_max_abs="
                << final_norm.max_abs
                << " final_rmsnorm_rmse="
                << final_norm.rmse << '\n'
                << "last_token_logits_max_abs="
                << logits.max_abs
                << " last_token_logits_rmse="
                << logits.rmse << '\n'
                << "exact_argmax=" << exact_argmax
                << " polynomial_argmax="
                << polynomial_argmax << '\n';
            if (final_norm.max_abs > 1.0e-2 ||
                logits.max_abs > 1.0e-1 ||
                exact_argmax != polynomial_argmax)
            {
                std::cerr << "result=FAIL final_output\n";
                return 1;
            }
        }
        std::cout << "final_max_abs=" << total.max_abs
                  << " final_rmse=" << total.rmse << '\n'
                  << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_poly_stack: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
