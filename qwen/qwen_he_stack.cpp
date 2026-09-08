#include "core/tensor.h"
#include "he/encrypted_decoder.h"
#include "he/encrypted_model.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "he/qwen25_05b_config.h"
#include "he/validation_log.h"
#include "model/plain_decoder.h"
#include "model/plain_qwen.h"
#include "model/qwen_config.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
#include <numeric>
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
            "Qwen encrypted stack comparison shape mismatch");
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

double tensor_max_abs(const qwen::Tensor &tensor)
{
    double maximum = 0.0;
    for (double value : tensor.data())
    {
        maximum = std::max(maximum, std::abs(value));
    }
    return maximum;
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
        << " --model DIR [--input-ids N,N,...] [--max-layers N]"
           " [--start-layer N]"
           " [--final-only] [--he-mode bootstrap-mock|debug|mock|silu-mock|bootstrap]"
           " [--bootstrap-layers N]"
           " [--profile target|prototype|prototype-fast|prototype-mid|prototype-high|prototype-high13]"
           " [--tokens-per-cipher N]"
           " [--log-file PATH]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        std::filesystem::path model_directory;
        std::vector<std::size_t> token_ids{9707, 11, 847};
        std::size_t maximum_layers = 2;
        std::size_t start_layer = 0;
        bool final_only = false;
        std::string he_mode = "bootstrap-mock";
        bool bootstrap_layers_set = false;
        std::size_t bootstrap_layers = 0;
        std::string profile = "target";
        bool tokens_per_cipher_set = false;
        std::size_t tokens_per_cipher = 0;
        std::filesystem::path log_file =
            "Trident/qwen/validation_output/qwen_he_stack.log";
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument(argv[index]);
            if (argument == "--help")
            {
                print_usage(argv[0]);
                return 0;
            }
            if (argument == "--final-only")
            {
                final_only = true;
                continue;
            }
            if (argument == "--bootstrap-layers")
            {
                if (index + 1 >= argc)
                {
                    throw std::invalid_argument(
                        "missing value for --bootstrap-layers");
                }
                bootstrap_layers = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
                bootstrap_layers_set = true;
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
            else if (argument == "--max-layers")
            {
                maximum_layers =
                    static_cast<std::size_t>(
                        std::stoull(argv[++index]));
            }
            else if (argument == "--start-layer")
            {
                start_layer = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
            }
            else if (argument == "--tokens-per-cipher")
            {
                tokens_per_cipher = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
                tokens_per_cipher_set = true;
            }
            else if (argument == "--he-mode")
            {
                he_mode = argv[++index];
                if (he_mode != "bootstrap-mock" &&
                    he_mode != "debug" && he_mode != "mock" &&
                    he_mode != "silu-mock" &&
                    he_mode != "bootstrap")
                {
                    throw std::invalid_argument(
                        "--he-mode must be bootstrap-mock, debug, mock, silu-mock, or bootstrap");
                }
            }
            else if (argument == "--log-file")
            {
                log_file = argv[++index];
            }
            else if (argument == "--profile")
            {
                profile = argv[++index];
                if (profile != "target" && profile != "prototype" &&
                    profile != "prototype-fast" && profile != "prototype-mid" &&
                    profile != "prototype-high" && profile != "prototype-high13")
                {
                    throw std::invalid_argument(
                        "--profile must be target, prototype, prototype-fast, prototype-mid, prototype-high, or prototype-high13");
                }
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
        if (bootstrap_layers_set && he_mode != "bootstrap")
        {
            throw std::invalid_argument(
                "--bootstrap-layers requires bootstrap mode");
        }
        if (bootstrap_layers_set && bootstrap_layers == 0)
        {
            throw std::invalid_argument(
                "--bootstrap-layers must be positive");
        }
        if (tokens_per_cipher_set && tokens_per_cipher == 0)
        {
            throw std::invalid_argument(
                "--tokens-per-cipher must be positive");
        }
        if (!log_file.parent_path().empty())
        {
            std::filesystem::create_directories(log_file.parent_path());
        }
        log_file = qwen::he::timestamped_log_path(log_file);
        qwen::he::ValidationLog validation_log(log_file.string());
        const qwen::he::RefreshMode refresh_mode =
            he_mode == "bootstrap"
                ? qwen::he::RefreshMode::bootstrap
                : qwen::he::RefreshMode::debug_bootstrap;

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
        if (start_layer >= maximum_layers)
        {
            throw std::invalid_argument(
                "--start-layer must be smaller than --max-layers");
        }
        const std::size_t effective_bootstrap_layers =
            bootstrap_layers_set
                ? std::min(bootstrap_layers, maximum_layers)
                : maximum_layers;
        if (final_only &&
            maximum_layers != model_config.num_hidden_layers)
        {
            throw std::invalid_argument(
                "--final-only requires all model layers");
        }
        if (final_only && start_layer != 0)
        {
            throw std::invalid_argument(
                "--final-only cannot be combined with --start-layer");
        }
        weights.layers.resize(maximum_layers);
        const qwen::Tensor input =
            embed(weights.token_embedding, token_ids);

        std::vector<qwen::he::EncryptedDecoderApproximationConfig>
            approximations;
        approximations.reserve(maximum_layers);
        std::vector<std::map<std::string, qwen::Tensor>>
            polynomial_traces(maximum_layers);
        std::vector<qwen::Tensor> exact_outputs;
        exact_outputs.reserve(maximum_layers);
        std::vector<qwen::Tensor> polynomial_outputs;
        polynomial_outputs.reserve(maximum_layers);

        qwen::Tensor exact = input;
        qwen::Tensor polynomial = input;
        std::cout << "Qwen encrypted decoder stack validation\n"
                  << "tokens=" << token_ids.size()
                  << " layers=" << maximum_layers
                  << " start_layer=" << start_layer
                  << " he_mode=" << he_mode
                  << " mock_bootstrap="
                  << (he_mode == "bootstrap" ? "no" : "yes")
                  << " mock_silu="
                  << (he_mode == "mock" || he_mode == "silu-mock"
                          ? "yes"
                          : "no")
                  << " mock_rmsnorm="
                  << (he_mode == "mock" ? "yes" : "no")
                  << " mock_attention="
                  << (he_mode == "mock" ? "yes" : "no")
                  << " bootstrap_layers="
                  << (he_mode == "bootstrap"
                          ? effective_bootstrap_layers
                          : 0)
                  << " profile=" << profile
                  << " log_file=" << log_file
                  << " mode="
                  << (final_only ? "final-boundary" : "full-stack")
                  << '\n';
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            const qwen::he::RefreshMode layer_refresh_mode =
                he_mode == "bootstrap" &&
                        layer < effective_bootstrap_layers
                    ? qwen::he::RefreshMode::bootstrap
                    : qwen::he::RefreshMode::debug_bootstrap;
            auto approximation =
                qwen::he::qwen25_05b_layer_approximation(
                    layer, token_ids.size());
            approximation.exact_silu_reference =
                he_mode == "mock" || he_mode == "silu-mock";
            qwen::he::set_decoder_bootstrap_schedule(
                approximation, layer_refresh_mode);
            if (he_mode == "bootstrap-mock")
            {
                qwen::he::set_decoder_reduced_mock_bootstrap_schedule(
                    approximation, token_ids.size() > 1);
            }
            if (token_ids.size() > 1)
            {
                qwen::he::set_decoder_multi_token_bootstrap_schedule(
                    approximation, layer_refresh_mode,
                    token_ids.size());
            }
            if (layer_refresh_mode == qwen::he::RefreshMode::bootstrap &&
                token_ids.size() == 1 &&
                (profile == "prototype" || profile == "prototype-fast" ||
                 profile == "prototype-mid" || profile == "prototype-high" ||
                 profile == "prototype-high13"))
            {
                qwen::he::set_decoder_boundary_bootstrap_schedule(
                    approximation);
            }
            if (token_ids.size() == 1)
            {
                qwen::he::remove_single_token_attention_refreshes(
                    approximation);
            }
            qwen::he::remove_redundant_rmsnorm_refreshes(
                approximation);
            if (layer_refresh_mode == qwen::he::RefreshMode::bootstrap &&
                (profile == "target" || profile == "prototype-high" ||
                 profile == "prototype-high13"))
            {
                qwen::he::set_qwen25_05b_calibrated_bootstrap_scales(
                    approximation, layer);
            }
            polynomial = qwen::he::approximate_decoder_layer(
                polynomial, weights.layers[layer], model_config,
                approximation, 0,
                [&](const std::string &name,
                    const qwen::Tensor &tensor) {
                    polynomial_traces[layer][name] = tensor;
                });
            qwen::PlainDecoderLayer exact_layer(
                model_config, weights.layers[layer]);
            exact = exact_layer.forward(exact);
            exact_outputs.push_back(exact);
            polynomial_outputs.push_back(polynomial);
            const ErrorMetrics metrics = compare(polynomial, exact);
            std::cout << "plain_layer=" << layer
                      << " max_abs=" << metrics.max_abs
                      << " rmse=" << metrics.rmse
                      << " polynomial_value_max_abs="
                      << tensor_max_abs(polynomial)
                      << " exact_value_max_abs="
                      << tensor_max_abs(exact) << '\n';
            approximations.push_back(std::move(approximation));
        }

        const auto runtime_start = std::chrono::steady_clock::now();
        qwen::he::HeConfig he_config =
            profile == "prototype"
                ? qwen::he::prototype_bootstrap_he_config()
                : profile == "prototype-fast"
                      ? qwen::he::prototype_fast_bootstrap_he_config()
                      : profile == "prototype-mid"
                            ? qwen::he::prototype_mid_bootstrap_he_config()
                            : profile == "prototype-high"
                                  ? qwen::he::prototype_high_bootstrap_he_config()
                                  : profile == "prototype-high13"
                                        ? qwen::he::prototype_high13_bootstrap_he_config()
                                        : qwen::he::target_he_config();
        if (tokens_per_cipher_set)
        {
            he_config.max_tokens_per_cipher = tokens_per_cipher;
            he_config.validate();
        }
        he_config.allow_insecure_mock_boundaries =
            he_mode != "bootstrap";
        const std::uint64_t q_modulus_bits = std::accumulate(
            he_config.log_q.begin(), he_config.log_q.end(),
            std::uint64_t{0});
        const std::uint64_t p_modulus_bits = std::accumulate(
            he_config.log_p.begin(), he_config.log_p.end(),
            std::uint64_t{0});
        std::cout << "he_parameters"
                  << " logN=" << he_config.log_n
                  << " slots=" << he_config.slot_count()
                  << " token_stride=" << he_config.token_stride
                  << " tokens_per_cipher="
                  << he_config.tokens_per_cipher()
                  << " log_scale=" << he_config.log_scale
                  << " q_primes=" << he_config.log_q.size()
                  << " q_bits=" << q_modulus_bits
                  << " p_primes=" << he_config.log_p.size()
                  << " p_bits=" << p_modulus_bits
                  << " parameter_security="
                  << (he_config.production_security ? "tc128" : "none")
                  << " insecure_mock_boundaries="
                  << (he_config.allow_insecure_mock_boundaries
                          ? "yes"
                          : "no")
                  << '\n';
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(he_config);
        runtime.set_mock_nonlinear(he_mode == "mock");
        runtime.set_mock_silu(
            he_mode == "mock" || he_mode == "silu-mock");
        if (he_mode == "bootstrap-mock" &&
            (runtime.mock_silu() || runtime.mock_rms_norm() ||
             runtime.mock_attention()))
        {
            throw std::logic_error(
                "bootstrap-mock must keep every nonlinear operator encrypted");
        }
        runtime.set_operation_logging(true);
        const auto runtime_stop = std::chrono::steady_clock::now();
        const qwen::Tensor &encrypted_reference_input =
            start_layer == 0
                ? input
                : polynomial_outputs[start_layer - 1];
        qwen::he::EncryptedTensor encrypted_input =
            qwen::he::encrypt_tensor(
                final_only ? polynomial : encrypted_reference_input,
                runtime);
        const auto input_drop_start =
            std::chrono::steady_clock::now();
        std::cout << "operation=input_modulus_drop event=start"
                  << " level="
                  << runtime.chain_index(
                         encrypted_input.cipher(0, 0))
                  << '\n';
        encrypted_input = qwen::he::encrypted_drop_to_level(
            encrypted_input,
            qwen::he::bootstrap_output_level, runtime);
        std::cout << "operation=input_modulus_drop event=end duration_ms="
                  << std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - input_drop_start)
                         .count()
                  << " level="
                  << runtime.chain_index(
                         encrypted_input.cipher(0, 0))
                  << '\n';
        if (final_only)
        {
            encrypted_input = qwen::he::encrypted_refresh(
                encrypted_input,
                refresh_mode,
                runtime);
        }
        double maximum_ckks_error = 0.0;
        double maximum_ckks_error_tolerance = 0.0;
        std::string maximum_ckks_error_node;
        bool intermediate_ckks_pass = true;
        const auto encrypted_start = std::chrono::steady_clock::now();
        qwen::he::EncryptedTensor encrypted_output = encrypted_input;
        if (!final_only)
        {
            for (std::size_t layer = start_layer;
                 layer < maximum_layers; ++layer)
            {
                runtime.set_operation_context(
                    "layer_" + std::to_string(layer));
                runtime.set_bootstrap_value_scale(
                    runtime.config().bootstrap_value_scale_for_layer(
                        layer));
                encrypted_output = qwen::he::encrypted_decoder_layer(
                    encrypted_output, weights.layers[layer],
                    model_config, approximations[layer], 0, runtime,
                    [&](const std::string &name,
                        const qwen::he::EncryptedTensor &tensor) {
                        const auto reference =
                            polynomial_traces[layer].find(name);
                        if (reference == polynomial_traces[layer].end())
                        {
                            throw std::runtime_error(
                                "missing polynomial trace node");
                        }
                        const ErrorMetrics metrics = compare(
                            qwen::he::decrypt_tensor(tensor, runtime),
                            reference->second);
                        const double tolerance =
                            2.0e-2 + 2.0e-5 *
                                           tensor_max_abs(
                                               reference->second);
                        intermediate_ckks_pass =
                            intermediate_ckks_pass &&
                            metrics.max_abs <= tolerance;
                        if (metrics.max_abs > maximum_ckks_error)
                        {
                            maximum_ckks_error = metrics.max_abs;
                            maximum_ckks_error_tolerance = tolerance;
                            maximum_ckks_error_node =
                                "layer_" + std::to_string(layer) +
                                '.' + name;
                        }
                        std::cout << "trace=layer_" << layer << '.'
                                  << name << " chain="
                                  << runtime.chain_index(
                                         tensor.cipher(0, 0))
                                  << " max_abs=" << metrics.max_abs
                                  << " rmse=" << metrics.rmse << '\n';
                    });
            }
        }
        const auto encrypted_stop = std::chrono::steady_clock::now();
        const ErrorMetrics final_ckks = compare(
            qwen::he::decrypt_tensor(encrypted_output, runtime),
            polynomial);
        const double final_ckks_tolerance =
            1.0e-2 + 2.0e-5 * tensor_max_abs(polynomial);
        ErrorMetrics final_norm_ckks;
        ErrorMetrics final_norm_approximation;
        double final_norm_ckks_tolerance = 0.0;
        double final_norm_approximation_tolerance = 0.0;
        ErrorMetrics logits_ckks;
        ErrorMetrics logits_approximation;
        std::size_t exact_argmax = 0;
        std::size_t polynomial_argmax = 0;
        std::size_t encrypted_argmax = 0;
        std::size_t final_output_level = 0;
        if (maximum_layers == model_config.num_hidden_layers)
        {
            const auto final_config =
                qwen::he::
                    qwen25_05b_final_inverse_sqrt_config();
            const qwen::Tensor exact_final = qwen::rms_norm(
                exact, weights.final_norm,
                model_config.rms_norm_epsilon);
            const qwen::Tensor polynomial_final =
                qwen::he::approximate_rms_norm_plain(
                    polynomial, weights.final_norm,
                    model_config.rms_norm_epsilon, final_config);
            final_norm_approximation =
                compare(polynomial_final, exact_final);
            final_norm_approximation_tolerance =
                1.0e-2 + 5.0e-4 * tensor_max_abs(exact_final);
            qwen::he::EncryptedTensor encrypted_final =
                qwen::he::encrypted_rms_norm(
                    encrypted_output, weights.final_norm,
                    model_config.rms_norm_epsilon,
                    final_config, runtime);
            encrypted_final = qwen::he::encrypted_refresh(
                encrypted_final,
                refresh_mode,
                runtime);
            const qwen::Tensor decrypted_final =
                qwen::he::decrypt_tensor(
                    encrypted_final, runtime);
            final_norm_ckks =
                compare(decrypted_final, polynomial_final);
            final_norm_ckks_tolerance =
                1.0e-2 + 5.0e-4 * tensor_max_abs(polynomial_final);
            final_output_level = runtime.chain_index(
                encrypted_final.cipher(0, 0));

            const qwen::Tensor &lm_head =
                weights.lm_head.empty()
                    ? weights.token_embedding
                    : weights.lm_head;
            const qwen::Tensor exact_logits = qwen::linear(
                last_token(exact_final), lm_head);
            const qwen::Tensor polynomial_logits = qwen::linear(
                last_token(polynomial_final), lm_head);
            const qwen::Tensor encrypted_logits = qwen::linear(
                last_token(decrypted_final), lm_head);
            logits_approximation =
                compare(polynomial_logits, exact_logits);
            logits_ckks =
                compare(encrypted_logits, polynomial_logits);
            const auto argmax = [](const qwen::Tensor &logits) {
                return static_cast<std::size_t>(
                    std::max_element(
                        logits.data().begin(),
                        logits.data().end()) -
                    logits.data().begin());
            };
            exact_argmax = argmax(exact_logits);
            polynomial_argmax = argmax(polynomial_logits);
            encrypted_argmax = argmax(encrypted_logits);
        }

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<
                       std::chrono::milliseconds>(duration)
                .count();
        };
        std::cout << "final_ckks_vs_polynomial max_abs="
                  << final_ckks.max_abs
                  << " rmse=" << final_ckks.rmse << '\n'
                  << "intermediate_ckks_peak node="
                  << maximum_ckks_error_node
                  << " max_abs=" << maximum_ckks_error
                  << " tolerance="
                  << maximum_ckks_error_tolerance << '\n'
                  << "final_ckks_tolerance="
                  << final_ckks_tolerance << '\n'
                  << "chain_in="
                  << runtime.chain_index(
                         encrypted_input.cipher(0, 0))
                  << " chain_out="
                  << runtime.chain_index(
                         encrypted_output.cipher(0, 0))
                  << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " encrypted_stack_ms="
                  << milliseconds(
                         encrypted_stop - encrypted_start)
                  << '\n';
        if (maximum_layers == model_config.num_hidden_layers)
        {
            std::cout
                << "final_rmsnorm_ckks_vs_polynomial max_abs="
                << final_norm_ckks.max_abs
                << " rmse=" << final_norm_ckks.rmse
                << " tolerance=" << final_norm_ckks_tolerance << '\n'
                << "final_rmsnorm_polynomial_vs_exact max_abs="
                << final_norm_approximation.max_abs
                << " rmse=" << final_norm_approximation.rmse
                << " tolerance="
                << final_norm_approximation_tolerance
                << '\n'
                << "client_logits_ckks_vs_polynomial max_abs="
                << logits_ckks.max_abs
                << " rmse=" << logits_ckks.rmse << '\n'
                << "client_logits_polynomial_vs_exact max_abs="
                << logits_approximation.max_abs
                << " rmse=" << logits_approximation.rmse
                << '\n'
                << "argmax exact=" << exact_argmax
                << " polynomial=" << polynomial_argmax
                << " encrypted=" << encrypted_argmax
                << " final_level=" << final_output_level << '\n';
        }
        if (!intermediate_ckks_pass ||
            final_ckks.max_abs > final_ckks_tolerance ||
            (maximum_layers == model_config.num_hidden_layers &&
             (final_norm_ckks.max_abs > final_norm_ckks_tolerance ||
              final_norm_approximation.max_abs >
                  final_norm_approximation_tolerance ||
              logits_ckks.max_abs > 1.0e-1 ||
              logits_approximation.max_abs > 1.0e-1 ||
              exact_argmax != polynomial_argmax ||
              exact_argmax != encrypted_argmax)))
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_stack: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
