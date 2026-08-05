#include "core/tensor.h"
#include "he/approximation.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "he/qwen25_05b_config.h"
#include "he/validation_log.h"
#include "io/safetensors.h"
#include "model/qwen_config.h"

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

ErrorMetrics compare(const qwen::Tensor &actual,
                     const qwen::Tensor &expected)
{
    if (actual.shape() != expected.shape())
    {
        throw std::invalid_argument(
            "Qwen bootstrap comparison shape mismatch");
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

qwen::Tensor embedding_row(const qwen::Tensor &embedding,
                           std::size_t token_id)
{
    if (embedding.rank() != 2 || token_id >= embedding.dim(0))
    {
        throw std::out_of_range(
            "Qwen bootstrap token ID is outside the embedding table");
    }
    qwen::Tensor result({1, embedding.dim(1)});
    const auto source =
        embedding.data().begin() +
        static_cast<std::ptrdiff_t>(token_id * embedding.dim(1));
    std::copy(source,
              source + static_cast<std::ptrdiff_t>(embedding.dim(1)),
              result.data().begin());
    return result;
}

qwen::he::EncryptedTensor encrypt_replicated_token(
    const qwen::Tensor &input, qwen::he::HeRuntime &runtime)
{
    if (input.rank() != 2 || input.dim(0) != 1 ||
        input.dim(1) > runtime.config().token_stride)
    {
        throw std::invalid_argument(
            "replicated target packing expects one feature vector");
    }
    std::vector<double> slots(runtime.config().slot_count(), 0.0);
    for (std::size_t block = 0;
         block < runtime.config().tokens_per_cipher(); ++block)
    {
        const std::size_t offset =
            block * runtime.config().token_stride;
        std::copy(input.data().begin(), input.data().end(),
                  slots.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    qwen::he::EncryptedTensorLayout layout{
        1, input.dim(1), runtime.config().token_stride,
        runtime.config().slot_count(), 1};
    std::vector<poseidon::Ciphertext> ciphertexts;
    ciphertexts.push_back(qwen::he::encrypt_slots(slots, runtime));
    return qwen::he::EncryptedTensor(
        layout, std::move(ciphertexts));
}

void print_usage(const char *program)
{
    std::cout << "Usage: " << program
              << " [--model DIR] [--token-id N]"
                 " [--profile target|prototype|prototype-fast|prototype-mid|prototype-high|prototype-high13]"
                 " [--log-file PATH]\n";
}

} // namespace

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        std::filesystem::path model_directory;
        std::size_t token_id = 9707;
        std::string profile = "target";
        std::filesystem::path log_file =
            "Trident/qwen/validation_output/qwen_he_bootstrap.log";
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
            else if (argument == "--token-id")
            {
                token_id = static_cast<std::size_t>(
                    std::stoull(argv[++index]));
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

        if (!log_file.parent_path().empty())
        {
            std::filesystem::create_directories(log_file.parent_path());
        }
        log_file = qwen::he::timestamped_log_path(log_file);
        qwen::he::ValidationLog validation_log(log_file.string());
        const auto milliseconds = [](auto duration) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       duration)
                .count();
        };

        std::cout << "Qwen real Bootstrap validation\n"
                  << "profile=" << profile
                  << " token_id=" << token_id
                  << " model="
                  << (model_directory.empty()
                          ? "synthetic"
                          : model_directory.string())
                  << " log_file=" << log_file << '\n';

        const auto input_start = std::chrono::steady_clock::now();
        std::cout << "operation=input_preparation event=start\n";
        qwen::Tensor input({1, 896});
        qwen::Tensor expected;
        qwen::Tensor norm_weight;
        qwen::he::EncryptedDecoderApproximationConfig approximation;
        double rms_epsilon = 0.0;
        const bool real_checkpoint = !model_directory.empty();
        if (real_checkpoint)
        {
            const qwen::QwenConfig model_config =
                qwen::load_qwen_config(
                    model_directory / "config.json");
            qwen::SafeTensorStore store(model_directory);
            qwen::Tensor embedding =
                store.load("model.embed_tokens.weight");
            input = embedding_row(embedding, token_id);
            embedding = qwen::Tensor{};
            norm_weight = store.load(
                "model.layers.0.input_layernorm.weight");
            approximation =
                qwen::he::qwen25_05b_layer_approximation(0, 1);
            rms_epsilon = model_config.rms_norm_epsilon;
            expected = qwen::he::approximate_rms_norm_plain(
                input, norm_weight, rms_epsilon,
                approximation.input_inverse_sqrt,
                approximation.input_inverse_sqrt_overrides);
        }
        else
        {
            for (std::size_t feature = 0;
                 feature < input.dim(1); ++feature)
            {
                input.at(0, feature) =
                    0.4 * std::sin(
                              static_cast<double>(feature) / 37.0) +
                    0.1 * std::cos(
                              static_cast<double>(feature) / 19.0);
            }
            expected = input;
        }
        const auto input_stop = std::chrono::steady_clock::now();
        std::cout << "operation=input_preparation event=end duration_ms="
                  << milliseconds(input_stop - input_start) << '\n';

        qwen::he::HeConfig config =
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
        std::cout << "he_parameters"
                  << " log_n=" << config.log_n
                  << " slots=" << config.slot_count()
                  << " bootstrap_slots="
                  << config.log_slots
                  << " q_primes=" << config.log_q.size()
                  << " scale_bits=" << config.log_scale
                  << " security="
                  << (config.production_security
                          ? "tc128"
                          : "development-only")
                  << '\n';
        const auto runtime_start = std::chrono::steady_clock::now();
        std::cout << "operation=runtime_initialization event=start\n";
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(config);
        const auto runtime_stop = std::chrono::steady_clock::now();
        std::cout << "operation=runtime_initialization event=end duration_ms="
                  << milliseconds(runtime_stop - runtime_start) << '\n';

        const auto encrypted_input_start =
            std::chrono::steady_clock::now();
        std::cout << "operation=encrypted_input_rmsnorm event=start\n";
        qwen::he::EncryptedTensor encrypted =
            real_checkpoint
                ? encrypt_replicated_token(input, runtime)
                : qwen::he::encrypt_tensor(input, runtime);
        std::cout << "operation=input_modulus_drop event=start"
                  << " level="
                  << runtime.chain_index(encrypted.cipher(0, 0))
                  << '\n';
        encrypted = qwen::he::encrypted_drop_to_level(
            encrypted, qwen::he::bootstrap_output_level, runtime);
        std::cout << "operation=input_modulus_drop event=end level="
                  << runtime.chain_index(encrypted.cipher(0, 0))
                  << '\n';
        if (real_checkpoint)
        {
            encrypted = qwen::he::encrypted_rms_norm(
                encrypted, norm_weight, rms_epsilon,
                approximation.input_inverse_sqrt,
                approximation.input_inverse_sqrt_overrides,
                runtime);
        }
        const auto encrypted_input_stop =
            std::chrono::steady_clock::now();
        const ErrorMetrics before_metrics = compare(
            qwen::he::decrypt_tensor(encrypted, runtime), expected);
        const std::size_t level_before =
            runtime.chain_index(encrypted.cipher(0, 0));
        std::cout << "operation=encrypted_input_rmsnorm event=end duration_ms="
                  << milliseconds(
                         encrypted_input_stop - encrypted_input_start)
                  << " level=" << level_before
                  << " scale=" << encrypted.cipher(0, 0).scale()
                  << '\n'
                  << "pre_bootstrap_level=" << level_before
                  << " pre_bootstrap_scale="
                  << encrypted.cipher(0, 0).scale() << '\n';
        const auto bootstrap_start = std::chrono::steady_clock::now();
        std::cout << "operation=poseidon_bootstrap event=start"
                  << " level=" << level_before
                  << " scale=" << encrypted.cipher(0, 0).scale()
                  << '\n';
        const qwen::he::EncryptedTensor refreshed =
            qwen::he::encrypted_refresh(
                encrypted, qwen::he::RefreshMode::bootstrap, runtime);
        const auto bootstrap_stop = std::chrono::steady_clock::now();
        std::cout << "operation=poseidon_bootstrap event=end duration_ms="
                  << milliseconds(bootstrap_stop - bootstrap_start)
                  << " level="
                  << runtime.chain_index(refreshed.cipher(0, 0))
                  << " scale=" << refreshed.cipher(0, 0).scale()
                  << '\n';
        const qwen::Tensor decrypted =
            qwen::he::decrypt_tensor(refreshed, runtime);

        const ErrorMetrics after_metrics =
            compare(decrypted, expected);
        std::cout << "Qwen CKKS target-parameter bootstrap validation\n"
                  << "stage="
                  << (real_checkpoint
                          ? "official_layer_0_input_rmsnorm"
                          : "synthetic_identity")
                  << '\n'
                  << "log_n=" << config.log_n
                  << " slots=" << config.slot_count()
                  << " bootstrap_slots="
                  << config.log_slots
                  << " token_stride=" << config.token_stride
                  << " tokens_per_cipher=" << config.tokens_per_cipher()
                  << " q_primes=" << config.log_q.size()
                  << " scale_bits=" << config.log_scale << '\n'
                  << "profile=" << profile << '\n'
                  << "level_before=" << level_before
                  << " level_after="
                  << runtime.chain_index(refreshed.cipher(0, 0))
                  << " scale_before=" << encrypted.cipher(0, 0).scale()
                  << " scale_after=" << refreshed.cipher(0, 0).scale()
                  << '\n'
                  << "before_bootstrap_max_abs="
                  << before_metrics.max_abs
                  << " before_bootstrap_rmse="
                  << before_metrics.rmse << '\n'
                  << "after_bootstrap_max_abs="
                  << after_metrics.max_abs
                  << " after_bootstrap_rmse="
                  << after_metrics.rmse << '\n'
                  << "runtime_ms="
                  << milliseconds(runtime_stop - runtime_start)
                  << " bootstrap_ms="
                  << milliseconds(bootstrap_stop - bootstrap_start)
                  << '\n'
                  << "security="
                  << (config.production_security ? "tc128" : "development-only")
                  << '\n';
        if (before_metrics.max_abs > 2.0e-4 ||
            after_metrics.max_abs > 5.0e-4 ||
            after_metrics.rmse > 2.0e-4)
        {
            std::cerr << "result=FAIL\n";
            return 1;
        }
        std::cout << "result=PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_bootstrap: " << error.what() << '\n';
        print_usage(argv[0]);
        return 1;
    }
}
