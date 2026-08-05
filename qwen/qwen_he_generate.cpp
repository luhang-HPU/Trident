#include "core/tensor.h"
#include "he/encrypted_decoder.h"
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
#include <limits>
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
            "Qwen encrypted generation comparison shape mismatch");
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
        throw std::invalid_argument("generation prompt is empty");
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

std::size_t argmax(const qwen::Tensor &logits)
{
    return static_cast<std::size_t>(
        std::max_element(logits.data().begin(), logits.data().end()) -
        logits.data().begin());
}

qwen::he::ApproximationConfig partial_final_norm_config(
    const qwen::Tensor &hidden, double epsilon)
{
    if (hidden.rank() != 2 || hidden.dim(1) == 0 || epsilon <= 0.0)
    {
        throw std::invalid_argument(
            "partial final RMSNorm calibration received invalid input");
    }
    double minimum = std::numeric_limits<double>::infinity();
    double maximum = 0.0;
    for (std::size_t token = 0; token < hidden.dim(0); ++token)
    {
        double square_sum = 0.0;
        for (std::size_t feature = 0; feature < hidden.dim(1); ++feature)
        {
            const double value = hidden.at(token, feature);
            square_sum += value * value;
        }
        const double variance =
            square_sum / static_cast<double>(hidden.dim(1)) + epsilon;
        minimum = std::min(minimum, variance);
        maximum = std::max(maximum, variance);
    }
    const double lower = std::max(epsilon, minimum * 0.80);
    const double upper = std::max(lower * 1.05, maximum * 1.20);
    const double ratio = upper / lower;
    return {lower, upper, ratio > 20.0 ? 128 : (ratio > 5.0 ? 64 : 32)};
}

void print_usage(const char *program)
{
    std::cout
        << "Usage: " << program
        << " --model DIR [--input-ids N,N,...]"
           " [--max-new-tokens N] [--max-layers N]"
           " [--he-mode bootstrap-mock|debug|mock|silu-mock|bootstrap]"
           " [--bootstrap-layers N]"
           " [--profile target|prototype|prototype-fast|prototype-mid|prototype-high|prototype-high13] [--log-file PATH]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        std::filesystem::path model_directory;
        std::vector<std::size_t> prompt{9707, 11, 847};
        std::size_t maximum_new_tokens = 2;
        std::size_t maximum_layers = 24;
        std::string he_mode = "bootstrap-mock";
        bool bootstrap_layers_set = false;
        std::size_t bootstrap_layers = 0;
        std::string profile = "target";
        std::filesystem::path log_file =
            "Trident/qwen/validation_output/qwen_he_generate.log";
        for (int index = 1; index < argc; ++index)
        {
            const std::string argument(argv[index]);
            if (argument == "--help")
            {
                print_usage(argv[0]);
                return 0;
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
                prompt = parse_token_ids(argv[++index]);
            }
            else if (argument == "--max-new-tokens")
            {
                maximum_new_tokens = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
            }
            else if (argument == "--max-layers")
            {
                maximum_layers = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
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
        if (he_mode == "bootstrap" &&
            (profile == "prototype" || profile == "prototype-fast" ||
             profile == "prototype-mid" || profile == "prototype-high" ||
             profile == "prototype-high13") &&
            prompt.size() != 1)
        {
            throw std::invalid_argument(
                "prototype bootstrap currently requires one prompt token");
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
        std::cout << "Qwen encrypted greedy generation validation\n"
                  << "he_mode=" << he_mode
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
                          ? (bootstrap_layers_set
                                 ? std::to_string(bootstrap_layers)
                                 : "all")
                          : "0")
                  << " profile=" << profile
                  << " log_file=" << log_file << '\n';
        if (maximum_new_tokens == 0)
        {
            throw std::invalid_argument(
                "--max-new-tokens must be positive");
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
        const std::size_t effective_bootstrap_layers =
            bootstrap_layers_set
                ? std::min(bootstrap_layers, maximum_layers)
                : maximum_layers;

        std::vector<qwen::he::EncryptedDecoderApproximationConfig>
            approximations;
        approximations.reserve(maximum_layers);
        // The token produced by the final requested generation step is not
        // fed back through Attention. Only preceding generated tokens can
        // enlarge the cache seen by an executed decoder step.
        const std::size_t maximum_attention_tokens =
            prompt.size() + maximum_new_tokens - 1;
        for (std::size_t layer = 0; layer < maximum_layers; ++layer)
        {
            const qwen::he::RefreshMode layer_refresh_mode =
                he_mode == "bootstrap" &&
                        layer < effective_bootstrap_layers
                    ? qwen::he::RefreshMode::bootstrap
                    : qwen::he::RefreshMode::debug_bootstrap;
            auto approximation =
                qwen::he::qwen25_05b_layer_approximation(
                    layer, maximum_attention_tokens);
            approximation.exact_silu_reference =
                he_mode == "mock" || he_mode == "silu-mock";
            qwen::he::set_decoder_bootstrap_schedule(
                approximation, layer_refresh_mode);
            if (he_mode == "bootstrap-mock")
            {
                qwen::he::set_decoder_reduced_mock_bootstrap_schedule(
                    approximation, maximum_attention_tokens > 1);
            }
            if (layer_refresh_mode == qwen::he::RefreshMode::bootstrap &&
                (profile == "prototype" || profile == "prototype-fast" ||
                 profile == "prototype-mid" || profile == "prototype-high" ||
                 profile == "prototype-high13"))
            {
                qwen::he::set_decoder_boundary_bootstrap_schedule(
                    approximation);
                if (profile == "prototype-high" || profile == "prototype-high13")
                {
                    const double post_attention_scale =
                        layer < 3 ? 1.0 : 128.0;
                    const double output_scale =
                        layer < 2 ? 1.0 : (layer == 2 ? 32.0 : 1024.0);
                    const double mlp_input_scale =
                        layer < 3 ? 1.0 : (layer == 3 ? 128.0 : 4.0);
                    approximation.post_attention_bootstrap_value_scale =
                        post_attention_scale;
                    approximation.output_bootstrap_value_scale =
                        output_scale;
                    approximation.mlp_input_bootstrap_value_scale =
                        mlp_input_scale;
                }
            }
            if (maximum_attention_tokens == 1)
            {
                qwen::he::remove_single_token_attention_refreshes(
                    approximation);
            }
            qwen::he::remove_redundant_rmsnorm_refreshes(
                approximation);
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
        std::vector<qwen::KVCache> exact_caches(maximum_layers);
        std::vector<qwen::KVCache> polynomial_caches(maximum_layers);
        std::vector<qwen::he::EncryptedKVCache> encrypted_caches(
            maximum_layers);
        const qwen::Tensor &lm_head =
            weights.lm_head.empty()
                ? weights.token_embedding
                : weights.lm_head;

        std::vector<std::size_t> current_ids = prompt;
        std::vector<std::size_t> exact_generated;
        std::vector<std::size_t> polynomial_generated;
        std::vector<std::size_t> encrypted_generated;
        std::size_t position_offset = 0;
        double maximum_ckks_error = 0.0;
        const auto inference_start = std::chrono::steady_clock::now();
        for (std::size_t step = 0; step < maximum_new_tokens; ++step)
        {
            qwen::Tensor exact_hidden =
                embed(weights.token_embedding, current_ids);
            qwen::Tensor polynomial_hidden = exact_hidden;
            qwen::he::EncryptedTensor encrypted_hidden =
                qwen::he::encrypt_tensor(exact_hidden, runtime);
            const auto input_drop_start =
                std::chrono::steady_clock::now();
            std::cout << "operation=step_" << step
                      << ".input_modulus_drop event=start"
                      << " level="
                      << runtime.chain_index(
                             encrypted_hidden.cipher(0, 0))
                      << '\n';
            encrypted_hidden = qwen::he::encrypted_drop_to_level(
                encrypted_hidden,
                qwen::he::bootstrap_output_level, runtime);
            const auto input_drop_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - input_drop_start)
                    .count();
            std::cout << "operation=step_" << step
                      << ".input_modulus_drop event=end duration_ms="
                      << input_drop_ms << " level="
                      << runtime.chain_index(
                             encrypted_hidden.cipher(0, 0))
                      << '\n';

            for (std::size_t layer = 0;
                 layer < maximum_layers; ++layer)
            {
                runtime.set_operation_context(
                    "step_" + std::to_string(step) + ".layer_" +
                    std::to_string(layer));
                runtime.set_bootstrap_value_scale(
                    runtime.config().bootstrap_value_scale_for_layer(layer));
                exact_hidden = qwen::PlainDecoderLayer(
                    model_config, weights.layers[layer])
                                   .forward(
                                       exact_hidden,
                                       &exact_caches[layer]);
                polynomial_hidden =
                    qwen::he::approximate_decoder_layer(
                        polynomial_hidden, weights.layers[layer],
                        model_config, approximations[layer],
                        position_offset, {},
                        &polynomial_caches[layer]);
                encrypted_hidden =
                    qwen::he::encrypted_decoder_layer(
                        encrypted_hidden, weights.layers[layer],
                        model_config, approximations[layer],
                        position_offset, runtime, {},
                        &encrypted_caches[layer]);
                const ErrorMetrics layer_ckks = compare(
                    qwen::he::decrypt_tensor(
                        encrypted_hidden, runtime),
                    runtime.mock_nonlinear()
                        ? exact_hidden
                        : polynomial_hidden);
                const ErrorMetrics layer_approximation = compare(
                    polynomial_hidden, exact_hidden);
                maximum_ckks_error = std::max(
                    maximum_ckks_error, layer_ckks.max_abs);
                std::cout
                    << "step=" << step << " layer=" << layer
                    << " cache_tokens="
                    << encrypted_caches[layer].size()
                    << " cache_key_ciphers="
                    << encrypted_caches[layer].key().ciphertexts().size()
                    << " cache_value_ciphers="
                    << encrypted_caches[layer].value().ciphertexts().size()
                    << " cache_key_level="
                    << runtime.chain_index(
                           encrypted_caches[layer].key().cipher(0, 0))
                    << " cache_value_level="
                    << runtime.chain_index(
                           encrypted_caches[layer].value().cipher(0, 0))
                    << " ckks_max_abs=" << layer_ckks.max_abs
                    << " approximation_max_abs="
                    << layer_approximation.max_abs
                    << " level="
                    << runtime.chain_index(
                           encrypted_hidden.cipher(0, 0))
                    << '\n';
            }

            const qwen::he::ApproximationConfig final_config =
                maximum_layers == model_config.num_hidden_layers
                    ? qwen::he::qwen25_05b_final_inverse_sqrt_config()
                    : partial_final_norm_config(
                          polynomial_hidden,
                          model_config.rms_norm_epsilon);
            std::cout
                << "step=" << step
                << " final_norm_config_source="
                << (maximum_layers == model_config.num_hidden_layers
                        ? "qwen24_calibrated"
                        : "partial_validation_only")
                << " minimum=" << final_config.minimum
                << " maximum=" << final_config.maximum
                << " samples=" << final_config.sample_count << '\n';
            const qwen::Tensor exact_final = qwen::rms_norm(
                exact_hidden, weights.final_norm,
                model_config.rms_norm_epsilon);
            const qwen::Tensor polynomial_final =
                qwen::he::approximate_rms_norm_plain(
                    polynomial_hidden, weights.final_norm,
                    model_config.rms_norm_epsilon, final_config);
            qwen::he::EncryptedTensor encrypted_final =
                qwen::he::encrypted_rms_norm(
                    encrypted_hidden, weights.final_norm,
                    model_config.rms_norm_epsilon,
                    final_config, runtime);
            encrypted_final = qwen::he::encrypted_refresh(
                encrypted_final,
                refresh_mode,
                runtime);
            const qwen::Tensor decrypted_final =
                qwen::he::decrypt_tensor(encrypted_final, runtime);

            const qwen::Tensor exact_logits = qwen::linear(
                last_token(exact_final), lm_head);
            const qwen::Tensor polynomial_logits = qwen::linear(
                last_token(polynomial_final), lm_head);
            const qwen::Tensor encrypted_logits = qwen::linear(
                last_token(decrypted_final), lm_head);
            const std::size_t exact_token = argmax(exact_logits);
            const std::size_t polynomial_token =
                argmax(polynomial_logits);
            const std::size_t encrypted_token =
                argmax(encrypted_logits);
            exact_generated.push_back(exact_token);
            polynomial_generated.push_back(polynomial_token);
            encrypted_generated.push_back(encrypted_token);

            const ErrorMetrics final_ckks = compare(
                decrypted_final,
                runtime.mock_nonlinear() ? exact_final : polynomial_final);
            const ErrorMetrics logits_ckks = compare(
                encrypted_logits,
                runtime.mock_nonlinear() ? exact_logits : polynomial_logits);
            const ErrorMetrics logits_approximation = compare(
                polynomial_logits, exact_logits);
            maximum_ckks_error = std::max(
                maximum_ckks_error, final_ckks.max_abs);
            std::cout
                << "step=" << step
                << " final_ckks_max_abs=" << final_ckks.max_abs
                << " logits_ckks_max_abs=" << logits_ckks.max_abs
                << " logits_approximation_max_abs="
                << logits_approximation.max_abs
                << " token_exact=" << exact_token
                << " token_polynomial=" << polynomial_token
                << " token_encrypted=" << encrypted_token << '\n';
            if (exact_token != polynomial_token ||
                exact_token != encrypted_token)
            {
                throw std::runtime_error(
                    "encrypted greedy token does not match plaintext");
            }

            position_offset += current_ids.size();
            current_ids = {encrypted_token};
        }
        const auto inference_stop = std::chrono::steady_clock::now();

        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<
                       std::chrono::milliseconds>(duration)
                .count();
        };
        std::cout << "generated_exact:";
        for (const std::size_t token : exact_generated)
        {
            std::cout << ' ' << token;
        }
        std::cout << "\ngenerated_polynomial:";
        for (const std::size_t token : polynomial_generated)
        {
            std::cout << ' ' << token;
        }
        std::cout << "\ngenerated_encrypted:";
        for (const std::size_t token : encrypted_generated)
        {
            std::cout << ' ' << token;
        }
        std::cout
            << "\nmaximum_ckks_error=" << maximum_ckks_error
            << " runtime_ms="
            << milliseconds(runtime_stop - runtime_start)
            << " inference_ms="
            << milliseconds(inference_stop - inference_start)
            << '\n';
        if (maximum_ckks_error > 1.0e-2)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_generate: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
