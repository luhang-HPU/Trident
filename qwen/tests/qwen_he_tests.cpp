#include "core/tensor.h"
#include "he/approximation.h"
#include "he/comparison.h"
#include "he/encrypted_attention.h"
#include "he/encrypted_decoder.h"
#include "he/encrypted_ops.h"
#include "he/encrypted_tensor.h"
#include "he/he_config.h"
#include "he/he_runtime.h"
#include "he/qwen25_05b_config.h"
#include "model/plain_attention.h"
#include "ops/plain_ops.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <exception>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void expect_true(bool condition, const std::string &message)
{
    if (!condition)
    {
        throw std::runtime_error(message);
    }
}

void expect_tensor_near(const qwen::Tensor &actual,
                        const qwen::Tensor &expected,
                        double tolerance, const std::string &message)
{
    expect_true(actual.shape() == expected.shape(),
                message + " shape mismatch");
    double maximum = 0.0;
    double square_sum = 0.0;
    for (std::size_t index = 0; index < actual.numel(); ++index)
    {
        const double difference =
            std::abs(actual.data()[index] - expected.data()[index]);
        maximum = std::max(maximum, difference);
        square_sum += difference * difference;
    }
    const double rmse =
        std::sqrt(square_sum / static_cast<double>(actual.numel()));
    std::cout << message << " max_abs=" << maximum << " rmse=" << rmse
              << " tolerance=" << tolerance << '\n';
    expect_true(maximum <= tolerance, message + " exceeds tolerance");
}

std::size_t count_occurrences(const std::string &text,
                              const std::string &pattern)
{
    std::size_t count = 0;
    std::size_t position = 0;
    while ((position = text.find(pattern, position)) != std::string::npos)
    {
        ++count;
        position += pattern.size();
    }
    return count;
}

qwen::Tensor token_range(const qwen::Tensor &input,
                         std::size_t begin, std::size_t count)
{
    if (input.rank() < 2 || count == 0 ||
        begin + count > input.dim(0))
    {
        throw std::invalid_argument("invalid tensor token range");
    }
    const std::size_t token_size = input.numel() / input.dim(0);
    const auto first =
        input.data().begin() +
        static_cast<std::ptrdiff_t>(begin * token_size);
    const auto last =
        first + static_cast<std::ptrdiff_t>(count * token_size);
    std::vector<std::size_t> shape = input.shape();
    shape[0] = count;
    return qwen::Tensor(
        std::move(shape),
        std::vector<double>(first, last));
}

void test_pack_round_trip()
{
    const qwen::Tensor input(
        {3, 5}, {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
                 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0});
    const qwen::he::EncryptedTensorLayout layout{3, 5, 8, 16};
    const auto packed = qwen::he::pack_tensor(input, layout);
    expect_true(packed.size() == 2, "packing token-group count");
    const qwen::Tensor output = qwen::he::unpack_tensor(packed, layout);
    expect_tensor_near(output, input, 0.0, "pack_round_trip");
}

void test_single_token_cipher_policy()
{
    const qwen::he::HeConfig config = qwen::he::target_he_config();
    expect_true(config.tokens_per_cipher() == 1,
                "target profile must use one token per ciphertext");
    const qwen::he::EncryptedTensorLayout layout{
        3, 8, config.token_stride, config.slot_count(),
        config.tokens_per_cipher()};
    expect_true(layout.token_capacity() == 1,
                "target layout logical token capacity");
    expect_true(layout.token_groups() == 3,
                "three target tokens must use three ciphertext groups");

    const qwen::Tensor input(
        {3, 8},
        {1, 2, 3, 4, 5, 6, 7, 8,
         11, 12, 13, 14, 15, 16, 17, 18,
         21, 22, 23, 24, 25, 26, 27, 28});
    const auto packed = qwen::he::pack_tensor(input, layout);
    expect_true(packed.size() == 3,
                "single-token policy ciphertext count");
    for (std::size_t token = 0; token < 3; ++token)
    {
        expect_true(
            packed[token][0] == input.at(token, 0) &&
                packed[token][config.token_stride] == 0.0,
            "each target token must start in its own ciphertext");
    }
    expect_tensor_near(
        qwen::he::unpack_tensor(packed, layout), input, 0.0,
        "single_token_cipher_pack_round_trip");
}

void test_qwen_wide_stride_cipher_counts()
{
    qwen::he::HeConfig config = qwen::he::target_he_config();
    config.token_stride = 8192;
    config.max_tokens_per_cipher = 4;
    config.validate();

    const qwen::he::EncryptedTensorLayout hidden{
        4, 896, config.token_stride, config.slot_count(),
        config.tokens_per_cipher()};
    const qwen::he::EncryptedTensorLayout intermediate{
        4, 4864, config.token_stride, config.slot_count(),
        config.tokens_per_cipher()};
    const qwen::he::EncryptedTensorLayout key_value{
        4, 128, config.token_stride, config.slot_count(),
        config.tokens_per_cipher()};
    expect_true(hidden.cipher_count() == 1,
                "wide-stride hidden ciphertext count");
    expect_true(intermediate.cipher_count() == 1,
                "wide-stride MLP ciphertext count");
    expect_true(key_value.cipher_count() == 1,
                "wide-stride KV ciphertext count");

    const qwen::he::EncryptedTensorLayout baseline_intermediate{
        4, 4864, 1024, config.slot_count(), 4};
    expect_true(baseline_intermediate.cipher_count() == 5,
                "baseline MLP ciphertext count");
}

void test_single_token_bootstrap_schedule()
{
    qwen::he::EncryptedDecoderApproximationConfig single;
    qwen::he::set_decoder_bootstrap_schedule(
        single, qwen::he::RefreshMode::bootstrap);
    qwen::he::remove_redundant_rmsnorm_refreshes(single);
    qwen::he::remove_single_token_attention_refreshes(single);
    expect_true(single.qkv_refresh == qwen::he::RefreshMode::none,
                "single-token QKV refresh must be disabled");
    expect_true(
        single.attention_maximum_refresh == qwen::he::RefreshMode::none,
        "single-token maximum refresh must be disabled");
    expect_true(
        single.attention_denominator_refresh == qwen::he::RefreshMode::none,
        "single-token denominator refresh must be disabled");
    expect_true(
        single.input_norm_refresh == qwen::he::RefreshMode::none &&
            single.attention_output_refresh == qwen::he::RefreshMode::none &&
            single.post_attention_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            single.mlp_input_refresh == qwen::he::RefreshMode::none &&
            single.output_refresh == qwen::he::RefreshMode::bootstrap,
        "single-token schedule must skip redundant RMSNorm refreshes");

    qwen::he::EncryptedDecoderApproximationConfig boundary;
    qwen::he::set_decoder_boundary_bootstrap_schedule(boundary);
    expect_true(
        boundary.post_attention_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            boundary.mlp_input_refresh == qwen::he::RefreshMode::none &&
            boundary.output_refresh == qwen::he::RefreshMode::bootstrap,
        "boundary schedule must contain only residual bootstraps");

    qwen::he::EncryptedDecoderApproximationConfig multi;
    qwen::he::set_decoder_reduced_mock_bootstrap_schedule(multi, true);
    expect_true(
        multi.qkv_refresh == qwen::he::RefreshMode::debug_bootstrap &&
            multi.attention_maximum_refresh ==
                qwen::he::RefreshMode::debug_bootstrap &&
        multi.attention_denominator_refresh ==
                qwen::he::RefreshMode::debug_bootstrap,
        "multi-token Attention refreshes must remain enabled");

    qwen::he::EncryptedDecoderApproximationConfig multi_real;
    qwen::he::set_decoder_bootstrap_schedule(
        multi_real, qwen::he::RefreshMode::bootstrap);
    qwen::he::remove_redundant_rmsnorm_refreshes(multi_real);
    expect_true(
        multi_real.qkv_refresh == qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_maximum_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_denominator_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_output_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.post_attention_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.output_refresh ==
                qwen::he::RefreshMode::bootstrap,
        "real multi-token schedule must retain Attention bootstraps");
    expect_true(
        multi_real.input_norm_refresh == qwen::he::RefreshMode::none &&
            multi_real.mlp_input_refresh == qwen::he::RefreshMode::none,
        "real multi-token schedule must skip redundant RMSNorm refreshes");

    qwen::he::set_decoder_dual_token_bootstrap_schedule(
        multi_real, qwen::he::RefreshMode::bootstrap);
    expect_true(
        multi_real.qkv_refresh == qwen::he::RefreshMode::none &&
            multi_real.attention_maximum_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_denominator_refresh ==
                qwen::he::RefreshMode::none &&
            multi_real.attention_output_refresh ==
                qwen::he::RefreshMode::none,
        "dual-token Attention must refresh only the score difference");
    expect_true(
        multi_real.post_attention_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.output_refresh ==
                qwen::he::RefreshMode::bootstrap,
        "dual-token schedule must retain both residual bootstraps");

    qwen::he::set_decoder_multi_token_bootstrap_schedule(
        multi_real, qwen::he::RefreshMode::bootstrap, 3);
    expect_true(
        multi_real.qkv_refresh == qwen::he::RefreshMode::none &&
            multi_real.attention_maximum_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_denominator_refresh ==
                qwen::he::RefreshMode::bootstrap &&
            multi_real.attention_output_refresh ==
                qwen::he::RefreshMode::none,
        "general multi-token Attention must refresh scores and denominator");

    qwen::he::set_qwen25_05b_calibrated_bootstrap_scales(
        multi_real, 2);
    expect_true(
        multi_real.post_attention_bootstrap_value_scale == 1.0 &&
            multi_real.output_bootstrap_value_scale == 32.0 &&
            multi_real.mlp_input_bootstrap_value_scale == 1.0 &&
            multi_real.mlp_input_refresh ==
                qwen::he::RefreshMode::bootstrap,
        "layer-2 calibrated bootstrap scales");
    qwen::he::set_qwen25_05b_calibrated_bootstrap_scales(
        multi_real, 3);
    expect_true(
        multi_real.post_attention_bootstrap_value_scale == 128.0 &&
            multi_real.output_bootstrap_value_scale == 128.0 &&
            multi_real.mlp_input_bootstrap_value_scale == 128.0 &&
            multi_real.mlp_input_refresh ==
                qwen::he::RefreshMode::bootstrap,
        "later-layer calibrated bootstrap scales");

    const auto short_attention =
        qwen::he::qwen25_05b_layer_approximation(3, 4);
    const auto medium_attention =
        qwen::he::qwen25_05b_layer_approximation(3, 8);
    const auto long_attention =
        qwen::he::qwen25_05b_layer_approximation(3, 16);
    expect_true(
        short_attention.attention.exponential.minimum == -23.8793227 &&
            medium_attention.attention.exponential.minimum == -35.3810452 &&
            long_attention.attention.exponential.minimum == -35.3810452,
        "token-count-aware Attention calibration intervals");
}

void test_single_token_periodic_linear()
{
    qwen::he::HeConfig config = qwen::he::debug_he_config();
    config.log_n = 12;
    config.log_slots = 11;
    config.max_tokens_per_cipher = 1;
    config.validate();
    qwen::he::HeRuntime runtime = qwen::he::make_he_runtime(config);

    const qwen::Tensor input(
        {2, 8},
        {0.5, -1.0, 2.0, 0.25, 1.5, -0.5, 0.75, 1.0,
         -0.25, 0.75, 1.0, -2.0, 0.5, 1.25, -1.5, 2.0});
    const qwen::Tensor weight(
        {6, 8},
        {1.0, 2.0, -1.0, 0.5, 0.25, -0.5, 1.5, 0.75,
         -0.25, 1.5, 0.75, -2.0, 1.0, 0.5, -1.0, 0.25,
         2.0, 0.0, 1.0, 1.0, -0.5, 0.75, 0.25, -1.25,
         0.5, -1.0, 0.25, 2.0, 1.5, -0.75, 0.0, 1.0,
         -1.0, 0.25, 1.25, -0.5, 0.75, 2.0, -1.5, 0.5,
         0.75, 1.0, -0.25, 0.5, -1.0, 1.5, 0.25, -2.0});
    const qwen::Tensor bias({6}, {0.1, -0.2, 0.3, 0.4, -0.5, 0.6});
    const qwen::Tensor reference = qwen::linear(input, weight, &bias);
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    expect_true(encrypted.ciphertexts().size() == 2,
                "periodic Linear must retain one ciphertext per token");
    const qwen::he::EncodedLinear encoded =
        qwen::he::encode_linear(weight, runtime);
    const qwen::he::EncryptedTensor result = qwen::he::encrypted_linear(
        encrypted, encoded, &bias, runtime);
    expect_true(result.ciphertexts().size() == 2,
                "periodic Linear output must retain one ciphertext per token");
    expect_tensor_near(qwen::he::decrypt_tensor(result, runtime), reference,
                       2.0e-4, "single_token_periodic_linear");
}

void test_wide_stride_operators()
{
    qwen::he::HeConfig config = qwen::he::deep_debug_he_config();
    config.token_stride = 16;
    config.max_tokens_per_cipher = 4;
    config.validate();
    qwen::he::HeRuntime runtime = qwen::he::make_he_runtime(config);

    qwen::Tensor input({4, 8});
    for (std::size_t index = 0; index < input.numel(); ++index)
    {
        input.data()[index] =
            0.4 * std::sin(0.23 * static_cast<double>(index + 1));
    }
    qwen::Tensor weight({12, 8});
    for (std::size_t index = 0; index < weight.numel(); ++index)
    {
        weight.data()[index] =
            0.15 * std::cos(0.17 * static_cast<double>(index + 2));
    }
    const qwen::Tensor linear_reference = qwen::linear(input, weight);
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    expect_true(encrypted.ciphertexts().size() == 1,
                "wide-stride input must use one ciphertext");
    const qwen::he::EncryptedTensor linear = qwen::he::encrypted_linear(
        encrypted, qwen::he::encode_linear(weight, runtime), nullptr,
        runtime);
    expect_true(linear.ciphertexts().size() == 1,
                "wide-stride expanded Linear must use one ciphertext");
    expect_tensor_near(qwen::he::decrypt_tensor(linear, runtime),
                       linear_reference, 2.0e-4,
                       "wide_stride_linear");

    const qwen::he::ApproximationConfig silu_config{-2.0, 2.0, 16};
    const qwen::Tensor silu_reference =
        qwen::he::approximate_silu_plain(
            linear_reference, silu_config);
    const qwen::he::EncryptedTensor silu = qwen::he::encrypted_silu(
        linear, silu_config, {}, runtime);
    expect_true(silu.ciphertexts().size() == 1,
                "wide-stride SiLU must preserve one ciphertext");
    expect_tensor_near(qwen::he::decrypt_tensor(silu, runtime),
                       silu_reference, 5.0e-4,
                       "wide_stride_silu");

    qwen::Tensor rope_reference = input.reshape({4, 2, 4});
    qwen::Tensor rope_key = rope_reference;
    qwen::apply_rope(rope_reference, rope_key, 2, 10000.0);
    const qwen::he::EncryptedTensor rope = qwen::he::encrypted_rope(
        encrypted, 2, 4, 2, 10000.0, runtime);
    expect_true(rope.ciphertexts().size() == 1,
                "wide-stride RoPE must preserve one ciphertext");
    expect_tensor_near(qwen::he::decrypt_tensor(rope, runtime),
                       rope_reference.reshape({4, 8}), 2.0e-4,
                       "wide_stride_rope");

    const qwen::Tensor rms_weight(
        {8}, {1.0, 0.9, 1.1, 0.8, 1.2, 0.75, 1.25, 0.95});
    const qwen::he::ApproximationConfig rms_config{0.01, 1.0, 16};
    const qwen::Tensor rms_reference =
        qwen::he::approximate_rms_norm_plain(
            input, rms_weight, 1.0e-5, rms_config);
    const qwen::he::EncryptedTensor rms = qwen::he::encrypted_rms_norm(
        encrypted, rms_weight, 1.0e-5, rms_config, runtime);
    expect_true(rms.ciphertexts().size() == 1,
                "wide-stride RMSNorm must preserve one ciphertext");
    expect_tensor_near(qwen::he::decrypt_tensor(rms, runtime),
                       rms_reference, 2.0e-3,
                       "wide_stride_rms_norm");

    const qwen::QwenConfig attention_config = qwen::demo_config();
    qwen::Tensor query({4, 4, 2});
    qwen::Tensor key({4, 2, 2});
    qwen::Tensor value({4, 2, 2});
    for (std::size_t index = 0; index < query.numel(); ++index)
    {
        query.data()[index] =
            0.35 * std::sin(0.31 * static_cast<double>(index + 1));
    }
    for (std::size_t index = 0; index < key.numel(); ++index)
    {
        key.data()[index] =
            0.40 * std::cos(0.27 * static_cast<double>(index + 2));
        value.data()[index] =
            0.65 * std::sin(0.19 * static_cast<double>(index + 3));
    }
    const qwen::he::StableAttentionApproximationConfig attention_approximation{
        {2.0}, {-2.0, 0.1, 32}, {0.75, 4.5, 32}};
    const qwen::Tensor attention_reference =
        qwen::he::approximate_stable_causal_gqa_attention(
            query, key, value, attention_config,
            attention_approximation);
    runtime.set_operation_context("wide_stride");
    runtime.set_operation_logging(true);
    std::ostringstream attention_log;
    std::streambuf *original_output =
        std::cout.rdbuf(attention_log.rdbuf());
    qwen::he::EncryptedTensor attention;
    try
    {
        attention = qwen::he::encrypted_stable_causal_gqa_attention(
            qwen::he::encrypt_tensor(query.reshape({4, 8}), runtime),
            qwen::he::encrypt_tensor(key.reshape({4, 4}), runtime),
            qwen::he::encrypt_tensor(value.reshape({4, 4}), runtime),
            attention_config, attention_approximation, runtime,
            qwen::he::RefreshMode::debug_bootstrap,
            qwen::he::RefreshMode::debug_bootstrap);
    }
    catch (...)
    {
        std::cout.rdbuf(original_output);
        throw;
    }
    std::cout.rdbuf(original_output);
    runtime.set_operation_logging(false);
    const std::size_t packed_delta_refreshes = count_occurrences(
        attention_log.str(), ".delta_refresh event=start");
    expect_true(packed_delta_refreshes == 3,
                "four-token Attention must use three packed delta refreshes");
    std::cout << "wide_stride_attention delta_refresh_batches="
              << packed_delta_refreshes << '\n';
    expect_true(attention.ciphertexts().size() == 1,
                "wide-stride Attention must preserve one ciphertext");
    expect_tensor_near(qwen::he::decrypt_tensor(attention, runtime),
                       attention_reference.reshape({4, 8}), 3.0e-3,
                       "wide_stride_attention");
}

void test_encrypt_round_trip(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input({1, 6}, {0.25, -0.5, 1.25, 2.0, -3.0, 0.125});
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::Tensor output = qwen::he::decrypt_tensor(encrypted, runtime);
    expect_tensor_near(output, input, 1.0e-6, "encrypt_round_trip");
}

void test_input_modulus_drop(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input(
        {1, 6}, {0.25, -0.5, 1.25, 2.0, -3.0, 0.125});
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const double scale = encrypted.cipher(0, 0).scale();
    const qwen::he::EncryptedTensor dropped =
        qwen::he::encrypted_drop_to_level(encrypted, 10, runtime);
    expect_true(runtime.chain_index(dropped.cipher(0, 0)) == 10,
                "input modulus drop target level");
    expect_true(std::abs(dropped.cipher(0, 0).scale() - scale) <=
                    scale * 1.0e-12,
                "input modulus drop must preserve scale");
    expect_tensor_near(qwen::he::decrypt_tensor(dropped, runtime), input,
                       1.0e-6, "input_modulus_drop");
}

void test_add_and_multiply_plain(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input({1, 4}, {1.0, -2.0, 3.0, -4.0});
    const qwen::Tensor other({1, 4}, {0.5, 1.5, -2.0, 4.0});
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncryptedTensor added =
        qwen::he::encrypted_add_plain(encrypted, other, runtime);
    const qwen::Tensor added_plain = qwen::add(input, other);
    expect_tensor_near(qwen::he::decrypt_tensor(added, runtime), added_plain,
                       1.0e-6, "encrypted_add_plain");

    const qwen::he::EncryptedTensor multiplied =
        qwen::he::encrypted_multiply_plain(encrypted, other, runtime);
    const qwen::Tensor multiplied_plain = qwen::multiply(input, other);
    expect_tensor_near(qwen::he::decrypt_tensor(multiplied, runtime),
                       multiplied_plain, 1.0e-5,
                       "encrypted_multiply_plain");

    const qwen::he::EncryptedTensor second =
        qwen::he::encrypt_tensor(other, runtime);
    const qwen::he::EncryptedTensor cipher_added =
        qwen::he::encrypted_add(encrypted, second, runtime);
    expect_tensor_near(qwen::he::decrypt_tensor(cipher_added, runtime),
                       added_plain, 1.0e-6, "encrypted_add");
}

void test_rotate_and_reduce(qwen::he::HeRuntime &runtime)
{
    const std::vector<double> values{1.0, 2.0, 3.0, 4.0};
    const poseidon::Ciphertext encrypted =
        qwen::he::encrypt_slots(values, runtime);
    const poseidon::Ciphertext rotated =
        qwen::he::rotate_slots(encrypted, 1, runtime);
    const auto rotated_values = qwen::he::decrypt_slots(rotated, runtime);
    expect_true(std::abs(rotated_values[0] - 2.0) <= 1.0e-6,
                "encrypted rotation");

    const poseidon::Ciphertext reduced =
        qwen::he::reduce_sum_slots(encrypted, 4, runtime);
    const auto reduced_values = qwen::he::decrypt_slots(reduced, runtime);
    std::cout << "reduce_sum_slots actual=" << reduced_values[0]
              << " expected=10\n";
    expect_true(std::abs(reduced_values[0] - 10.0) <= 1.0e-5,
                "encrypted reduction");
}

void test_packed_rotation_and_linear()
{
    qwen::he::HeRuntime runtime = qwen::he::make_he_runtime(
        qwen::he::packed_debug_he_config());
    const std::size_t stride = runtime.config().token_stride;
    std::vector<double> slots(runtime.config().slot_count(), 0.0);
    for (std::size_t token = 0; token < 3; ++token)
    {
        for (std::size_t index = 0; index < 8; ++index)
        {
            slots[token * stride + index] =
                100.0 * static_cast<double>(token) +
                static_cast<double>(index + 1);
        }
        slots[token * stride + stride - 1] =
            100.0 * static_cast<double>(token) + 99.0;
    }
    const poseidon::Ciphertext encrypted_slots =
        qwen::he::encrypt_slots(slots, runtime);
    const auto left = qwen::he::decrypt_slots(
        qwen::he::rotate_blocks(encrypted_slots, 1, stride, runtime),
        runtime);
    const auto right = qwen::he::decrypt_slots(
        qwen::he::rotate_blocks(encrypted_slots, -1, stride, runtime),
        runtime);
    for (std::size_t token = 0; token < 3; ++token)
    {
        const std::size_t base = token * stride;
        std::cout << "packed_rotate token=" << token
                  << " left_first=" << left[base]
                  << " left_last=" << left[base + stride - 1]
                  << " right_first=" << right[base]
                  << " right_second=" << right[base + 1] << '\n';
        expect_true(std::abs(left[base] - slots[base + 1]) <= 1.0e-5,
                    "packed block left rotation");
        expect_true(std::abs(left[base + stride - 1] - slots[base]) <=
                        1.0e-5,
                    "packed block left wrap");
        expect_true(std::abs(right[base] - slots[base + stride - 1]) <=
                        1.0e-5,
                    "packed block right wrap");
        expect_true(std::abs(right[base + 1] - slots[base]) <= 1.0e-5,
                    "packed block right rotation");
    }
    const auto reduced = qwen::he::decrypt_slots(
        qwen::he::reduce_sum_slots(encrypted_slots, 8, runtime), runtime);
    for (std::size_t token = 0; token < 3; ++token)
    {
        const double expected = 36.0 + 800.0 * static_cast<double>(token);
        expect_true(std::abs(reduced[token * stride] - expected) <= 1.0e-3,
                    "packed block reduction");
    }

    const qwen::Tensor input(
        {3, 8},
        {0.5, -1.0, 2.0, 0.25, 1.5, -0.5, 0.75, 1.0,
         -0.25, 0.75, 1.0, -2.0, 0.5, 1.25, -1.5, 2.0,
         1.0, 0.5, -0.75, 1.25, -2.0, 0.25, 1.5, -1.0});
    const qwen::Tensor weight(
        {6, 8},
        {1.0, 2.0, -1.0, 0.5, 0.25, -0.5, 1.5, 0.75,
         -0.25, 1.5, 0.75, -2.0, 1.0, 0.5, -1.0, 0.25,
         2.0, 0.0, 1.0, 1.0, -0.5, 0.75, 0.25, -1.25,
         0.5, -1.0, 0.25, 2.0, 1.5, -0.75, 0.0, 1.0,
         -1.0, 0.25, 1.25, -0.5, 0.75, 2.0, -1.5, 0.5,
         0.75, 1.0, -0.25, 0.5, -1.0, 1.5, 0.25, -2.0});
    const qwen::Tensor bias({6}, {0.1, -0.2, 0.3, 0.4, -0.5, 0.6});
    const qwen::Tensor reference = qwen::linear(input, weight, &bias);
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    expect_true(encrypted.layout().token_groups() == 1,
                "three tokens must share one packed ciphertext");
    const qwen::he::EncodedLinear encoded =
        qwen::he::encode_linear(weight, runtime);
    const qwen::he::EncryptedTensor result = qwen::he::encrypted_linear(
        encrypted, encoded, &bias, runtime);
    expect_true(result.ciphertexts().size() == 1,
                "packed Linear must preserve one ciphertext group");
    expect_tensor_near(qwen::he::decrypt_tensor(result, runtime), reference,
                       2.0e-4, "packed_encrypted_linear");

    qwen::Tensor rope_reference = input.reshape({3, 2, 4});
    qwen::Tensor rope_key = rope_reference;
    qwen::apply_rope(rope_reference, rope_key, 3, 10000.0);
    const qwen::he::EncryptedTensor rope = qwen::he::encrypted_rope(
        encrypted, 2, 4, 3, 10000.0, runtime);
    expect_true(rope.ciphertexts().size() == 1,
                "packed RoPE must preserve one ciphertext group");
    expect_tensor_near(qwen::he::decrypt_tensor(rope, runtime),
                       rope_reference.reshape({3, 8}), 2.0e-4,
                       "packed_encrypted_rope");

    const qwen::he::ApproximationConfig silu_config{-3.0, 3.0, 16};
    const std::map<std::size_t, qwen::he::ApproximationConfig>
        silu_overrides{{0, {-2.5, 2.5, 16}}};
    const qwen::Tensor silu_reference = qwen::he::approximate_silu_plain(
        input, silu_config, silu_overrides);
    const qwen::he::EncryptedTensor silu = qwen::he::encrypted_silu(
        encrypted, silu_config, silu_overrides, runtime);
    const qwen::Tensor silu_decrypted =
        qwen::he::decrypt_tensor(silu, runtime);
    std::cout << "packed_silu reference:";
    for (double value : silu_reference.data())
    {
        std::cout << ' ' << value;
    }
    std::cout << "\npacked_silu decrypted:";
    for (double value : silu_decrypted.data())
    {
        std::cout << ' ' << value;
    }
    std::cout << '\n';
    expect_tensor_near(silu_decrypted, silu_reference, 4.0e-4,
                       "packed_position_aware_silu");

    std::vector<qwen::he::ApproximationConfig> packed_feature_configs;
    packed_feature_configs.reserve(input.dim(1));
    for (std::size_t feature = 0; feature < input.dim(1); ++feature)
    {
        double minimum = input.at(0, feature);
        double maximum = input.at(0, feature);
        for (std::size_t token = 1; token < input.dim(0); ++token)
        {
            minimum = std::min(minimum, input.at(token, feature));
            maximum = std::max(maximum, input.at(token, feature));
        }
        packed_feature_configs.push_back({minimum - 2.0, maximum + 2.0,
                                          16});
    }
    std::map<std::size_t, std::vector<qwen::he::ApproximationConfig>>
        packed_feature_overrides;
    for (std::size_t token = 0; token < input.dim(0); ++token)
    {
        std::vector<qwen::he::ApproximationConfig> token_configs;
        token_configs.reserve(input.dim(1));
        for (std::size_t feature = 0; feature < input.dim(1);
             ++feature)
        {
            const double value = input.at(token, feature);
            token_configs.push_back({value - 1.0, value + 1.0, 16});
        }
        packed_feature_overrides.emplace(token, std::move(token_configs));
    }
    const qwen::Tensor packed_feature_reference =
        qwen::he::approximate_silu_plain(
            input, silu_config, {}, packed_feature_configs,
            packed_feature_overrides);
    const qwen::he::EncryptedTensor packed_feature_silu =
        qwen::he::encrypted_silu(
            encrypted, silu_config, {}, packed_feature_configs,
            packed_feature_overrides, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(packed_feature_silu, runtime),
        packed_feature_reference, 4.0e-4,
        "packed_feature_calibrated_silu");

    const qwen::Tensor rms_weight(
        {8}, {1.0, 0.9, 1.1, 0.8, 1.2, 0.75, 1.25, 0.95});
    const qwen::he::ApproximationConfig rms_config{0.1, 4.0, 16};
    const std::map<std::size_t, qwen::he::ApproximationConfig>
        rms_overrides{{0, {0.1, 3.0, 16}}};
    const qwen::Tensor rms_reference =
        qwen::he::approximate_rms_norm_plain(
            input, rms_weight, 1.0e-5, rms_config, rms_overrides);
    const qwen::he::EncryptedTensor rms = qwen::he::encrypted_rms_norm(
        encrypted, rms_weight, 1.0e-5, rms_config, rms_overrides,
        runtime);
    expect_tensor_near(qwen::he::decrypt_tensor(rms, runtime),
                       rms_reference, 1.0e-3,
                       "packed_position_aware_rms_norm");
    const std::size_t packed_rms_input_level =
        runtime.chain_index(encrypted.cipher(0, 0));
    const std::size_t packed_rms_output_level =
        runtime.chain_index(rms.cipher(0, 0));
    expect_true(packed_rms_input_level == packed_rms_output_level + 10,
                "packed reduced-depth RMSNorm must consume ten levels");
    std::cout << "packed_rmsnorm level_in="
              << packed_rms_input_level << " level_out="
              << packed_rms_output_level << '\n';

    const qwen::QwenConfig attention_config = qwen::demo_config();
    const qwen::Tensor query(
        {2, 4, 2},
        {0.20, -0.10, 0.15, 0.30, -0.25, 0.10, 0.35, -0.20,
         0.10, 0.25, -0.30, 0.15, 0.20, 0.05, -0.10, 0.40});
    const qwen::Tensor key(
        {2, 2, 2},
        {0.30, -0.20, 0.10, 0.25,
         -0.15, 0.35, 0.20, -0.10});
    const qwen::Tensor value(
        {2, 2, 2},
        {0.50, -0.25, 0.10, 0.75,
         -0.40, 0.20, 0.60, -0.30});
    const qwen::he::AttentionApproximationConfig attention_approximation{
        {-1.0, 1.0, 16}, {0.75, 6.0, 32}};
    const qwen::Tensor attention_reference =
        qwen::he::approximate_causal_gqa_attention(
            query, key, value, attention_config,
            attention_approximation);
    const qwen::he::EncryptedTensor attention =
        qwen::he::encrypted_causal_gqa_attention(
            qwen::he::encrypt_tensor(query.reshape({2, 8}), runtime),
            qwen::he::encrypt_tensor(key.reshape({2, 4}), runtime),
            qwen::he::encrypt_tensor(value.reshape({2, 4}), runtime),
            attention_config, attention_approximation, runtime);
    expect_true(attention.ciphertexts().size() == 1,
                "packed attention must return one ciphertext group");
    expect_tensor_near(qwen::he::decrypt_tensor(attention, runtime),
                       attention_reference.reshape({2, 8}), 2.0e-3,
                       "packed_encrypted_causal_attention");

    const qwen::Tensor cached_query(
        {3, 4, 2},
        {0.20, -0.10, 0.15, 0.30, -0.25, 0.10, 0.35, -0.20,
         0.10, 0.25, -0.30, 0.15, 0.20, 0.05, -0.10, 0.40,
         -0.15, 0.20, 0.25, -0.05, 0.10, 0.30, -0.20, 0.15});
    const qwen::Tensor cached_key(
        {3, 2, 2},
        {0.30, -0.20, 0.10, 0.25,
         -0.15, 0.35, 0.20, -0.10,
         0.05, 0.30, -0.25, 0.15});
    const qwen::Tensor cached_value(
        {3, 2, 2},
        {0.50, -0.25, 0.10, 0.75,
         -0.40, 0.20, 0.60, -0.30,
         0.25, 0.40, -0.10, 0.55});
    const qwen::he::StableAttentionApproximationConfig stable_config{
        {2.0}, {-2.0, 0.1, 16}, {0.75, 3.5, 16}};
    qwen::KVCache plain_cache;
    static_cast<void>(qwen::he::approximate_stable_causal_gqa_attention(
        token_range(cached_query, 0, 2),
        token_range(cached_key, 0, 2),
        token_range(cached_value, 0, 2), attention_config,
        stable_config, &plain_cache));
    const qwen::Tensor cached_reference =
        qwen::he::approximate_stable_causal_gqa_attention(
            token_range(cached_query, 2, 1),
            token_range(cached_key, 2, 1),
            token_range(cached_value, 2, 1), attention_config,
            stable_config, &plain_cache);

    qwen::he::EncryptedKVCache encrypted_cache;
    static_cast<void>(qwen::he::encrypted_stable_cached_gqa_attention(
        qwen::he::encrypt_tensor(
            token_range(cached_query, 0, 2).reshape({2, 8}), runtime),
        qwen::he::encrypt_tensor(
            token_range(cached_key, 0, 2).reshape({2, 4}), runtime),
        qwen::he::encrypt_tensor(
            token_range(cached_value, 0, 2).reshape({2, 4}), runtime),
        attention_config, stable_config, encrypted_cache, runtime,
        qwen::he::RefreshMode::debug_bootstrap,
        qwen::he::RefreshMode::debug_bootstrap));
    const std::size_t cached_key_level_before_append =
        runtime.chain_index(encrypted_cache.key().cipher(0, 0));
    const std::size_t cached_value_level_before_append =
        runtime.chain_index(encrypted_cache.value().cipher(0, 0));
    const qwen::he::EncryptedTensor cached_attention =
        qwen::he::encrypted_stable_cached_gqa_attention(
            qwen::he::encrypt_tensor(
                token_range(cached_query, 2, 1).reshape({1, 8}), runtime),
            qwen::he::encrypt_tensor(
                token_range(cached_key, 2, 1).reshape({1, 4}), runtime),
            qwen::he::encrypt_tensor(
                token_range(cached_value, 2, 1).reshape({1, 4}), runtime),
            attention_config, stable_config, encrypted_cache, runtime,
            qwen::he::RefreshMode::debug_bootstrap,
            qwen::he::RefreshMode::debug_bootstrap);
    expect_true(encrypted_cache.size() == 3,
                "packed encrypted KV cache size");
    expect_true(
        runtime.chain_index(encrypted_cache.key().cipher(0, 0)) ==
                cached_key_level_before_append &&
            runtime.chain_index(encrypted_cache.value().cipher(0, 0)) ==
                cached_value_level_before_append,
        "packed KV append must preserve cache levels");
    std::cout << "packed_kv_append level_key="
              << cached_key_level_before_append
              << " level_value="
              << cached_value_level_before_append << '\n';
    expect_tensor_near(qwen::he::decrypt_tensor(cached_attention, runtime),
                       cached_reference.reshape({1, 8}), 3.0e-3,
                       "packed_encrypted_cached_attention");

    const qwen::Tensor full_group_key(
        {4, 4},
        {0.10, 0.20, 0.30, 0.40,
         0.50, 0.60, 0.70, 0.80,
         0.90, 1.00, 1.10, 1.20,
         1.30, 1.40, 1.50, 1.60});
    const qwen::Tensor full_group_value(
        {4, 4},
        {-0.10, -0.20, -0.30, -0.40,
         -0.50, -0.60, -0.70, -0.80,
         -0.90, -1.00, -1.10, -1.20,
         -1.30, -1.40, -1.50, -1.60});
    const qwen::Tensor next_group_key(
        {1, 4}, {1.70, 1.80, 1.90, 2.00});
    const qwen::Tensor next_group_value(
        {1, 4}, {-1.70, -1.80, -1.90, -2.00});
    const qwen::Tensor expected_group_key(
        {5, 4},
        {0.10, 0.20, 0.30, 0.40,
         0.50, 0.60, 0.70, 0.80,
         0.90, 1.00, 1.10, 1.20,
         1.30, 1.40, 1.50, 1.60,
         1.70, 1.80, 1.90, 2.00});
    const qwen::Tensor expected_group_value(
        {5, 4},
        {-0.10, -0.20, -0.30, -0.40,
         -0.50, -0.60, -0.70, -0.80,
         -0.90, -1.00, -1.10, -1.20,
         -1.30, -1.40, -1.50, -1.60,
         -1.70, -1.80, -1.90, -2.00});
    qwen::he::EncryptedKVCache full_group_cache;
    full_group_cache.append(
        qwen::he::encrypt_tensor(full_group_key, runtime),
        qwen::he::encrypt_tensor(full_group_value, runtime), runtime);
    const std::size_t full_group_level = runtime.chain_index(
        full_group_cache.key().cipher(0, 0));
    full_group_cache.append(
        qwen::he::encrypt_tensor(next_group_key, runtime),
        qwen::he::encrypt_tensor(next_group_value, runtime), runtime);
    expect_true(full_group_cache.size() == 5,
                "packed KV full-group append size");
    expect_true(full_group_cache.key().ciphertexts().size() == 2 &&
                    full_group_cache.value().ciphertexts().size() == 2,
                "packed KV full-group append cipher count");
    expect_true(runtime.chain_index(
                    full_group_cache.key().cipher(1, 0)) ==
                    full_group_level,
                "packed KV full-group append must preserve level");
    expect_tensor_near(
        qwen::he::decrypt_tensor(full_group_cache.key(), runtime),
        expected_group_key, 2.0e-5,
        "packed_kv_full_group_key");
    expect_tensor_near(
        qwen::he::decrypt_tensor(full_group_cache.value(), runtime),
        expected_group_value, 2.0e-5,
        "packed_kv_full_group_value");

    const qwen::DecoderLayerWeights decoder_weights =
        qwen::make_demo_layer_weights(attention_config, 29);
    const qwen::Tensor decoder_input =
        qwen::make_demo_hidden_states(3, attention_config);
    qwen::he::EncryptedDecoderApproximationConfig decoder_approximation{
        {0.05, 0.25, 32},
        {0.05, 0.25, 32},
        {{2.0}, {-2.0, 0.1, 16}, {0.75, 3.25, 16}},
        {-2.0, 2.0, 16},
    };
    qwen::he::set_decoder_bootstrap_schedule(
        decoder_approximation,
        qwen::he::RefreshMode::debug_bootstrap);
    decoder_approximation.input_inverse_sqrt_overrides.emplace(
        0, qwen::he::ApproximationConfig{0.05, 0.25, 32});
    decoder_approximation.post_attention_inverse_sqrt_overrides.emplace(
        0, qwen::he::ApproximationConfig{0.05, 0.25, 32});
    decoder_approximation.silu_overrides.emplace(
        0, qwen::he::ApproximationConfig{-2.0, 2.0, 32});

    const qwen::Tensor decoder_prefix = token_range(decoder_input, 0, 2);
    const qwen::Tensor decoder_decode = token_range(decoder_input, 2, 1);
    qwen::KVCache decoder_plain_cache;
    const qwen::Tensor decoder_prefix_reference =
        qwen::he::approximate_decoder_layer(
            decoder_prefix, decoder_weights, attention_config,
            decoder_approximation, 0, {}, &decoder_plain_cache);
    const qwen::Tensor decoder_decode_reference =
        qwen::he::approximate_decoder_layer(
            decoder_decode, decoder_weights, attention_config,
            decoder_approximation, 2, {}, &decoder_plain_cache);

    qwen::he::EncryptedKVCache decoder_encrypted_cache;
    const qwen::he::EncryptedTensor decoder_prefix_encrypted =
        qwen::he::encrypted_decoder_layer(
            qwen::he::encrypt_tensor(decoder_prefix, runtime),
            decoder_weights, attention_config, decoder_approximation, 0,
            runtime, {}, &decoder_encrypted_cache);
    expect_tensor_near(
        qwen::he::decrypt_tensor(decoder_prefix_encrypted, runtime),
        decoder_prefix_reference, 4.0e-3,
        "packed_encrypted_decoder_prefill");
    const qwen::he::EncryptedTensor decoder_decode_encrypted =
        qwen::he::encrypted_decoder_layer(
            qwen::he::encrypt_tensor(decoder_decode, runtime),
            decoder_weights, attention_config, decoder_approximation, 2,
            runtime, {}, &decoder_encrypted_cache);
    expect_true(decoder_encrypted_cache.size() == 3,
                "packed decoder KV cache size");
    expect_tensor_near(
        qwen::he::decrypt_tensor(decoder_decode_encrypted, runtime),
        decoder_decode_reference, 4.0e-3,
        "packed_encrypted_decoder_decode");
}

void test_linear(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input({1, 4}, {0.5, -1.0, 2.0, 0.25});
    const qwen::Tensor weight(
        {3, 4}, {1.0, 2.0, -1.0, 0.5, -0.25, 1.5, 0.75, -2.0,
                 2.0, 0.0, 1.0, 1.0});
    const qwen::Tensor bias({3}, {0.1, -0.2, 0.3});
    const qwen::Tensor reference = qwen::linear(input, weight, &bias);

    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncodedLinear encoded =
        qwen::he::encode_linear(weight, runtime);
    std::cout << "encoded_linear diagonals="
              << encoded.diagonals(0, 0).size()
              << '\n';
    const auto first_context =
        runtime.context.crt_context()->first_context_data();
    std::cout << "encoded_linear modulus_bits:";
    for (const auto &modulus : first_context->coeff_modulus())
    {
        std::cout << ' ' << modulus.bit_count();
    }
    std::cout << '\n';
    const qwen::he::EncryptedTensor result =
        qwen::he::encrypted_linear(encrypted, encoded, &bias, runtime);
    const qwen::Tensor decrypted =
        qwen::he::decrypt_tensor(result, runtime);
    std::cout << "encrypted_linear reference:";
    for (double value : reference.data())
    {
        std::cout << ' ' << value;
    }
    std::cout << "\nencrypted_linear decrypted:";
    for (double value : decrypted.data())
    {
        std::cout << ' ' << value;
    }
    std::cout << '\n';
    std::cout << "encrypted_linear level_in="
              << runtime.chain_index(encrypted.cipher(0, 0))
              << " level_out=" << runtime.chain_index(result.cipher(0, 0))
              << " scale_in=" << encrypted.cipher(0, 0).scale()
              << " scale_out=" << result.cipher(0, 0).scale() << '\n';
    expect_tensor_near(decrypted, reference, 1.0e-4,
                       "encrypted_linear");

    const qwen::Tensor sequence_input(
        {2, 4}, {0.5, -1.0, 2.0, 0.25, -0.25, 0.75, 1.0, -2.0});
    const qwen::Tensor sequence_reference =
        qwen::linear(sequence_input, weight, &bias);
    const qwen::he::EncryptedTensor encrypted_sequence =
        qwen::he::encrypt_tensor(sequence_input, runtime);
    const qwen::he::EncryptedTensor sequence_result =
        qwen::he::encrypted_linear(
            encrypted_sequence, encoded, &bias, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(sequence_result, runtime),
        sequence_reference, 1.0e-4, "encrypted_sequence_linear");
}

void test_rope(qwen::he::HeRuntime &runtime)
{
    qwen::Tensor reference(
        {1, 2, 4}, {1.0, 2.0, 3.0, 4.0, -1.0, 0.5, 2.0, -3.0});
    qwen::Tensor key = reference;
    qwen::apply_rope(reference, key, 1, 10000.0);
    const qwen::Tensor input =
        qwen::Tensor({1, 8},
                     {1.0, 2.0, 3.0, 4.0, -1.0, 0.5, 2.0, -3.0});
    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncryptedTensor rope =
        qwen::he::encrypted_rope(encrypted, 2, 4, 1, 10000.0, runtime);
    const qwen::Tensor decrypted =
        qwen::he::decrypt_tensor(rope, runtime);
    expect_tensor_near(decrypted, reference.reshape({1, 8}), 1.0e-5,
                       "encrypted_rope");

    qwen::Tensor sequence_reference(
        {2, 2, 4},
        {1.0, 2.0, 3.0, 4.0, -1.0, 0.5, 2.0, -3.0,
         0.25, -0.75, 1.5, 2.5, 3.0, -2.0, 0.5, 1.0});
    qwen::Tensor sequence_key = sequence_reference;
    qwen::apply_rope(sequence_reference, sequence_key, 3, 10000.0);
    const qwen::Tensor sequence_input = qwen::Tensor(
        {2, 8},
        {1.0, 2.0, 3.0, 4.0, -1.0, 0.5, 2.0, -3.0,
         0.25, -0.75, 1.5, 2.5, 3.0, -2.0, 0.5, 1.0});
    const qwen::he::EncryptedTensor encrypted_sequence =
        qwen::he::encrypt_tensor(sequence_input, runtime);
    const qwen::he::EncryptedTensor sequence_rope =
        qwen::he::encrypted_rope(
            encrypted_sequence, 2, 4, 3, 10000.0, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(sequence_rope, runtime),
        sequence_reference.reshape({2, 8}), 1.0e-5,
        "encrypted_sequence_rope");
}

void test_chunked_linear(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input({1, 4}, {1.0, 2.0, -1.0, 0.5});
    qwen::Tensor expand_weight({1030, 4});
    expand_weight.at(0, 0) = 2.0;
    expand_weight.at(1, 1) = -1.0;
    expand_weight.at(1024, 2) = 3.0;
    expand_weight.at(1029, 3) = 4.0;
    const qwen::Tensor expanded_reference =
        qwen::linear(input, expand_weight);
    const auto encrypted_input = qwen::he::encrypt_tensor(input, runtime);
    const auto encoded_expand =
        qwen::he::encode_linear(expand_weight, runtime);
    const auto encrypted_expanded = qwen::he::encrypted_linear(
        encrypted_input, encoded_expand, nullptr, runtime);
    expect_true(encrypted_expanded.layout().feature_chunks() == 2,
                "expanded Linear feature chunks");
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_expanded, runtime),
        expanded_reference, 1.0e-5, "encrypted_chunked_linear_expand");

    qwen::Tensor reduce_weight({3, 1030});
    reduce_weight.at(0, 0) = 1.5;
    reduce_weight.at(0, 1024) = -0.5;
    reduce_weight.at(1, 1) = 2.0;
    reduce_weight.at(1, 1029) = 0.25;
    reduce_weight.at(2, 1024) = 1.0;
    reduce_weight.at(2, 1029) = -1.0;
    const qwen::Tensor reduced_reference =
        qwen::linear(expanded_reference, reduce_weight);
    const auto encoded_reduce = qwen::he::encode_linear_at(
        reduce_weight, encrypted_expanded.cipher(0, 0), runtime);
    const auto encrypted_reduced = qwen::he::encrypted_linear(
        encrypted_expanded, encoded_reduce, nullptr, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_reduced, runtime),
        reduced_reference, 1.0e-5, "encrypted_chunked_linear_reduce");
}

void test_silu(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input(
        {1, 8}, {-6.0, -2.0, -0.5, 0.0, 0.5, 2.0, 4.0, 6.0});
    const qwen::he::ApproximationConfig config = qwen::he::silu_config();
    const qwen::Tensor exact = qwen::silu(input);
    const qwen::Tensor polynomial =
        qwen::he::approximate_silu_plain(input, config);
    expect_tensor_near(polynomial, exact, 3.0e-5,
                       "polynomial_plain_silu");

    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_silu(encrypted, config, runtime);
    const qwen::Tensor decrypted =
        qwen::he::decrypt_tensor(encrypted_result, runtime);
    expect_tensor_near(decrypted, polynomial, 1.0e-4,
                       "encrypted_vs_polynomial_silu");
    const qwen::Tensor up(
        {1, 8}, {0.5, -1.0, 2.0, 0.25, -0.5, 1.5, 3.0, -2.0});
    const qwen::he::EncryptedTensor encrypted_up =
        qwen::he::encrypt_tensor(up, runtime);
    const qwen::he::EncryptedTensor encrypted_swiglu =
        qwen::he::encrypted_multiply(encrypted_result, encrypted_up,
                                    runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_swiglu, runtime),
        qwen::multiply(polynomial, up), 2.0e-4,
        "encrypted_mixed_level_swiglu");
    std::cout << "encrypted_silu level_in="
              << runtime.chain_index(encrypted.cipher(0, 0))
              << " level_out="
              << runtime.chain_index(encrypted_result.cipher(0, 0))
              << " swiglu_level_out="
              << runtime.chain_index(encrypted_swiglu.cipher(0, 0)) << '\n';
    expect_true(
        runtime.chain_index(encrypted.cipher(0, 0)) ==
            runtime.chain_index(encrypted_result.cipher(0, 0)) + 6,
        "reduced-depth degree-31 SiLU must consume six levels");

    std::vector<qwen::he::ApproximationConfig> feature_configs;
    feature_configs.reserve(input.dim(1));
    for (double value : input.data())
    {
        feature_configs.push_back({value - 1.5, value + 1.5, 32});
    }
    const std::map<
        std::size_t,
        std::vector<qwen::he::ApproximationConfig>>
        feature_overrides{{0, feature_configs}};
    const qwen::Tensor feature_polynomial =
        qwen::he::approximate_silu_plain(
            input, config, {}, feature_configs, feature_overrides);
    expect_tensor_near(
        feature_polynomial, exact, 1.0e-7,
        "feature_calibrated_plain_silu");
    const qwen::he::EncryptedTensor feature_encrypted =
        qwen::he::encrypted_silu(
            encrypted, config, {}, feature_configs,
            feature_overrides, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(feature_encrypted, runtime),
        feature_polynomial, 1.0e-4,
        "feature_calibrated_encrypted_silu");
    expect_true(
        runtime.chain_index(encrypted.cipher(0, 0)) ==
            runtime.chain_index(feature_encrypted.cipher(0, 0)) + 6,
        "feature-calibrated degree-31 SiLU must consume six levels");

    const qwen::Tensor mixed_input(
        {2, 8},
        {-20.0, -10.0, 0.0, 10.0, 20.0, 30.0, 40.0, 42.0,
         -6.0, -2.0, -0.5, 0.0, 0.5, 2.0, 4.0, 6.0});
    const std::map<std::size_t, qwen::he::ApproximationConfig>
        position_overrides{{0, {-24.0, 44.0, 64}}};
    const qwen::Tensor mixed_polynomial =
        qwen::he::approximate_silu_plain(
            mixed_input, config, position_overrides);
    expect_tensor_near(
        mixed_polynomial, qwen::silu(mixed_input), 2.0e-2,
        "position_aware_plain_silu");
    const qwen::he::EncryptedTensor encrypted_mixed =
        qwen::he::encrypt_tensor(mixed_input, runtime);
    const qwen::he::EncryptedTensor encrypted_mixed_result =
        qwen::he::encrypted_silu(
            encrypted_mixed, config, position_overrides, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(
            encrypted_mixed_result, runtime),
        mixed_polynomial, 1.0e-3,
        "position_aware_encrypted_silu");
}

void test_sigmoid(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor input(
        {1, 9}, {-8.0, -4.0, -2.0, -0.5, 0.0,
                 0.5, 2.0, 4.0, 8.0});
    const qwen::he::ApproximationConfig config{-8.0, 8.0, 32};
    qwen::Tensor exact(input.shape());
    for (std::size_t index = 0; index < input.numel(); ++index)
    {
        exact.data()[index] =
            1.0 / (1.0 + std::exp(-input.data()[index]));
    }
    const qwen::Tensor polynomial =
        qwen::he::approximate_sigmoid_plain(input, config);
    expect_tensor_near(polynomial, exact, 2.0e-4,
                       "polynomial_plain_sigmoid");

    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_sigmoid(encrypted, config, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_result, runtime),
        polynomial, 2.0e-4, "encrypted_vs_polynomial_sigmoid");
    const std::size_t input_level =
        runtime.chain_index(encrypted.cipher(0, 0));
    const std::size_t output_level =
        runtime.chain_index(encrypted_result.cipher(0, 0));
    expect_true(input_level == output_level + 6,
                "degree-31 sigmoid must consume six levels");
    std::cout << "encrypted_sigmoid level_in=" << input_level
              << " level_out=" << output_level << '\n';

    qwen::Tensor softplus_exact(input.shape());
    for (std::size_t index = 0; index < input.numel(); ++index)
    {
        const double value = input.data()[index];
        softplus_exact.data()[index] =
            value >= 0.0
                ? value + std::log1p(std::exp(-value))
                : std::log1p(std::exp(value));
    }
    const qwen::Tensor softplus_polynomial =
        qwen::he::approximate_softplus_plain(input, config);
    expect_tensor_near(softplus_polynomial, softplus_exact, 2.0e-4,
                       "polynomial_plain_softplus");
    const qwen::he::EncryptedTensor encrypted_softplus =
        qwen::he::encrypted_softplus(encrypted, config, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_softplus, runtime),
        softplus_polynomial, 2.0e-4,
        "encrypted_vs_polynomial_softplus");
    expect_true(
        input_level ==
            runtime.chain_index(encrypted_softplus.cipher(0, 0)) + 6,
        "degree-31 softplus must consume six levels");
}

void test_rms_norm(qwen::he::HeRuntime &runtime)
{
    qwen::Tensor input({1, 896});
    qwen::Tensor weight({896});
    for (std::size_t index = 0; index < 896; ++index)
    {
        input.at(0, index) =
            0.012 + 0.006 * std::sin(static_cast<double>(index) * 0.07);
        weight.at(index) =
            0.8 + 0.2 * std::cos(static_cast<double>(index) * 0.03);
    }
    constexpr double epsilon = 1.0e-6;
    const auto config = qwen::he::first_layer_inverse_sqrt_config();
    const qwen::Tensor exact = qwen::rms_norm(input, weight, epsilon);
    const qwen::Tensor polynomial =
        qwen::he::approximate_rms_norm_plain(input, weight, epsilon,
                                             config);
    expect_tensor_near(polynomial, exact, 1.0e-5,
                       "polynomial_plain_rms_norm");

    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypt_tensor(input, runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_rms_norm(encrypted, weight, epsilon, config,
                                     runtime);
    const qwen::Tensor decrypted =
        qwen::he::decrypt_tensor(encrypted_result, runtime);
    expect_tensor_near(decrypted, polynomial, 2.0e-4,
                       "encrypted_vs_polynomial_rms_norm");
    const std::size_t input_level =
        runtime.chain_index(encrypted.cipher(0, 0));
    const std::size_t output_level =
        runtime.chain_index(encrypted_result.cipher(0, 0));
    expect_true(input_level == output_level + 9,
                "reduced-depth RMSNorm must consume nine levels");
    std::cout << "encrypted_rms_norm level_in="
              << input_level
              << " level_out="
              << output_level << '\n';

    qwen::Tensor sequence_input({2, 896});
    for (std::size_t feature = 0; feature < 896; ++feature)
    {
        sequence_input.at(0, feature) = input.at(0, feature);
        sequence_input.at(1, feature) =
            0.014 + 0.005 * std::cos(
                              static_cast<double>(feature) * 0.05);
    }
    const qwen::Tensor sequence_polynomial =
        qwen::he::approximate_rms_norm_plain(
            sequence_input, weight, epsilon, config);
    const qwen::he::EncryptedTensor encrypted_sequence =
        qwen::he::encrypt_tensor(sequence_input, runtime);
    const qwen::he::EncryptedTensor encrypted_sequence_result =
        qwen::he::encrypted_rms_norm(
            encrypted_sequence, weight, epsilon, config, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_sequence_result, runtime),
        sequence_polynomial, 2.0e-4,
        "encrypted_sequence_rms_norm");

    qwen::Tensor mixed_scale_input({2, 896});
    for (std::size_t feature = 0; feature < 896; ++feature)
    {
        const double modulation =
            1.0 + 0.02 * std::sin(
                      static_cast<double>(feature) * 0.04);
        mixed_scale_input.at(0, feature) =
            std::sqrt(3000.0) * modulation;
        mixed_scale_input.at(1, feature) =
            std::sqrt(0.3) * modulation;
    }
    const qwen::he::ApproximationConfig low_scale{
        0.20, 0.40, 16};
    const std::map<std::size_t, qwen::he::ApproximationConfig>
        position_overrides{{0, {2500.0, 3500.0, 16}}};
    const qwen::Tensor mixed_polynomial =
        qwen::he::approximate_rms_norm_plain(
            mixed_scale_input, weight, epsilon, low_scale,
            position_overrides);
    expect_tensor_near(
        mixed_polynomial,
        qwen::rms_norm(mixed_scale_input, weight, epsilon),
        1.0e-5, "position_aware_plain_rms_norm");
    const qwen::he::EncryptedTensor encrypted_mixed =
        qwen::he::encrypt_tensor(mixed_scale_input, runtime);
    const qwen::he::EncryptedTensor encrypted_mixed_result =
        qwen::he::encrypted_rms_norm(
            encrypted_mixed, weight, epsilon, low_scale,
            position_overrides, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(
            encrypted_mixed_result, runtime),
        mixed_polynomial, 2.0e-4,
        "position_aware_encrypted_rms_norm");

    qwen::Tensor final_sequence({4, 896});
    const std::array<double, 4> final_variances{
        12.7, 6.2, 8.4, 50.0};
    for (std::size_t token = 0; token < 4; ++token)
    {
        for (std::size_t feature = 0; feature < 896; ++feature)
        {
            final_sequence.at(token, feature) =
                std::sqrt(final_variances[token]) *
                (1.0 + 0.04 * std::sin(
                            static_cast<double>(feature) * 0.03));
        }
    }
    const qwen::he::ApproximationConfig final_config{2.5, 55.0, 32};
    const qwen::Tensor final_polynomial =
        qwen::he::approximate_rms_norm_plain(
            final_sequence, weight, epsilon, final_config);
    const qwen::he::EncryptedTensor encrypted_final =
        qwen::he::encrypt_tensor(final_sequence, runtime);
    const qwen::he::EncryptedTensor encrypted_final_result =
        qwen::he::encrypted_rms_norm(
            encrypted_final, weight, epsilon, final_config, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_final_result, runtime),
        final_polynomial, 5.0e-4,
        "packed_four_token_final_rms_norm");
}

void test_causal_gqa_attention(qwen::he::HeRuntime &runtime)
{
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::Tensor query(
        {2, 4, 2},
        {0.20, -0.10, 0.15, 0.30, -0.25, 0.10, 0.35, -0.20,
         0.10, 0.25, -0.30, 0.15, 0.20, 0.05, -0.10, 0.40});
    const qwen::Tensor key(
        {2, 2, 2},
        {0.30, -0.20, 0.10, 0.25,
         -0.15, 0.35, 0.20, -0.10});
    const qwen::Tensor value(
        {2, 2, 2},
        {0.50, -0.25, 0.10, 0.75,
         -0.40, 0.20, 0.60, -0.30});
    const qwen::he::AttentionApproximationConfig approximation{
        {-1.0, 1.0, 16}, {0.75, 6.0, 32}};
    const qwen::Tensor exact =
        qwen::causal_gqa_attention(query, key, value, config);
    const qwen::Tensor polynomial =
        qwen::he::approximate_causal_gqa_attention(
            query, key, value, config, approximation);
    expect_tensor_near(polynomial, exact, 1.0e-5,
                       "polynomial_plain_causal_gqa_attention");

    const qwen::he::EncryptedTensor encrypted_query =
        qwen::he::encrypt_tensor(query.reshape({2, 8}), runtime);
    const qwen::he::EncryptedTensor encrypted_key =
        qwen::he::encrypt_tensor(key.reshape({2, 4}), runtime);
    const qwen::he::EncryptedTensor encrypted_value =
        qwen::he::encrypt_tensor(value.reshape({2, 4}), runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_causal_gqa_attention(
            encrypted_query, encrypted_key, encrypted_value, config,
            approximation, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_result, runtime),
        polynomial.reshape({2, 8}), 1.0e-3,
        "encrypted_vs_polynomial_causal_gqa_attention");
    std::cout << "encrypted_attention level_in="
              << runtime.chain_index(encrypted_query.cipher(0, 0))
              << " level_out_token0="
              << runtime.chain_index(encrypted_result.cipher(0, 0))
              << " level_out_token1="
              << runtime.chain_index(encrypted_result.cipher(1, 0))
              << '\n';
}

void test_private_maximum(qwen::he::HeRuntime &runtime)
{
    const qwen::Tensor lhs(
        {1, 9}, {-5.0, -2.0, -0.01, 0.0, 0.01,
                 2.0, 5.0, 4.0, -4.0});
    const qwen::Tensor rhs(
        {1, 9}, {5.0, 2.0, 0.0, 0.0, 0.0,
                 -2.0, -5.0, 3.0, -3.0});
    qwen::Tensor exact(lhs.shape());
    for (std::size_t index = 0; index < lhs.numel(); ++index)
    {
        exact.data()[index] =
            std::max(lhs.data()[index], rhs.data()[index]);
    }
    const qwen::he::ComparisonConfig config{10.0};
    const qwen::Tensor polynomial =
        qwen::he::approximate_maximum_plain(lhs, rhs, config);
    expect_tensor_near(polynomial, exact, 2.0e-2,
                       "polynomial_plain_private_maximum");

    const qwen::he::EncryptedTensor encrypted_lhs =
        qwen::he::encrypt_tensor(lhs, runtime);
    const qwen::he::EncryptedTensor encrypted_rhs =
        qwen::he::encrypt_tensor(rhs, runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_maximum(
            encrypted_lhs, encrypted_rhs, config, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_result, runtime),
        polynomial, 2.0e-3,
        "encrypted_vs_polynomial_private_maximum");
    std::cout << "encrypted_private_maximum level_in="
              << runtime.chain_index(encrypted_lhs.cipher(0, 0))
              << " level_out="
              << runtime.chain_index(encrypted_result.cipher(0, 0))
              << '\n';
}

void test_stable_causal_gqa_attention()
{
    qwen::he::HeRuntime runtime =
        qwen::he::make_he_runtime(
            qwen::he::deep_debug_he_config());
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::Tensor query(
        {2, 4, 2},
        {0.20, -0.10, 0.15, 0.30, -0.25, 0.10, 0.35, -0.20,
         0.10, 0.25, -0.30, 0.15, 0.20, 0.05, -0.10, 0.40});
    const qwen::Tensor key(
        {2, 2, 2},
        {0.30, -0.20, 0.10, 0.25,
         -0.15, 0.35, 0.20, -0.10});
    const qwen::Tensor value(
        {2, 2, 2},
        {0.50, -0.25, 0.10, 0.75,
         -0.40, 0.20, 0.60, -0.30});
    const qwen::he::StableAttentionApproximationConfig approximation{
        {2.0}, {-2.0, 0.1, 16}, {0.75, 2.25, 16}};
    const qwen::Tensor exact =
        qwen::causal_gqa_attention(query, key, value, config);
    const qwen::Tensor polynomial =
        qwen::he::approximate_stable_causal_gqa_attention(
            query, key, value, config, approximation);
    expect_tensor_near(
        polynomial, exact, 2.0e-4,
        "polynomial_plain_stable_causal_gqa_attention");

    const qwen::he::EncryptedTensor encrypted_query =
        qwen::he::encrypt_tensor(query.reshape({2, 8}), runtime);
    const qwen::he::EncryptedTensor encrypted_key =
        qwen::he::encrypt_tensor(key.reshape({2, 4}), runtime);
    const qwen::he::EncryptedTensor encrypted_value =
        qwen::he::encrypt_tensor(value.reshape({2, 4}), runtime);
    const qwen::he::EncryptedTensor encrypted_result =
        qwen::he::encrypted_stable_causal_gqa_attention(
            encrypted_query, encrypted_key, encrypted_value, config,
            approximation, runtime);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_result, runtime),
        polynomial.reshape({2, 8}), 2.0e-3,
        "encrypted_vs_polynomial_stable_causal_gqa_attention");
    std::cout << "encrypted_stable_attention level_in="
              << runtime.chain_index(encrypted_query.cipher(0, 0))
              << " level_out_token0="
              << runtime.chain_index(encrypted_result.cipher(0, 0))
              << " level_out_token1="
              << runtime.chain_index(encrypted_result.cipher(1, 0))
              << '\n';
}

void test_multi_token_stable_causal_gqa_attention()
{
    qwen::he::HeRuntime runtime =
        qwen::he::make_he_runtime(
            qwen::he::deep_debug_he_config());
    const qwen::QwenConfig config = qwen::demo_config();
    qwen::Tensor query({4, 4, 2});
    qwen::Tensor key({4, 2, 2});
    qwen::Tensor value({4, 2, 2});
    for (std::size_t index = 0; index < query.numel(); ++index)
    {
        query.data()[index] =
            0.35 * std::sin(0.31 * static_cast<double>(index + 1));
    }
    for (std::size_t index = 0; index < key.numel(); ++index)
    {
        key.data()[index] =
            0.40 * std::cos(0.27 * static_cast<double>(index + 2));
        value.data()[index] =
            0.65 * std::sin(0.19 * static_cast<double>(index + 3));
    }
    const qwen::he::StableAttentionApproximationConfig approximation{
        {2.0}, {-2.0, 0.1, 32}, {0.75, 4.5, 32}};
    const qwen::Tensor exact =
        qwen::causal_gqa_attention(query, key, value, config);
    const qwen::Tensor polynomial =
        qwen::he::approximate_stable_causal_gqa_attention(
            query, key, value, config, approximation);
    expect_tensor_near(
        polynomial, exact, 2.0e-4,
        "polynomial_plain_multi_token_stable_attention");

    const qwen::he::EncryptedTensor encrypted =
        qwen::he::encrypted_stable_causal_gqa_attention(
            qwen::he::encrypt_tensor(query.reshape({4, 8}), runtime),
            qwen::he::encrypt_tensor(key.reshape({4, 4}), runtime),
            qwen::he::encrypt_tensor(value.reshape({4, 4}), runtime),
            config, approximation, runtime,
            qwen::he::RefreshMode::debug_bootstrap,
            qwen::he::RefreshMode::debug_bootstrap);
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted, runtime),
        polynomial.reshape({4, 8}), 3.0e-3,
        "encrypted_vs_polynomial_multi_token_stable_attention");
    std::cout << "encrypted_multi_token_stable_attention tokens=4"
              << " level_out="
              << runtime.chain_index(encrypted.cipher(0, 0)) << '\n';
}

void test_encrypted_cached_stable_attention()
{
    qwen::he::HeRuntime runtime =
        qwen::he::make_he_runtime(
            qwen::he::deep_debug_he_config());
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::Tensor query(
        {3, 4, 2},
        {0.20, -0.10, 0.15, 0.30, -0.25, 0.10, 0.35, -0.20,
         0.10, 0.25, -0.30, 0.15, 0.20, 0.05, -0.10, 0.40,
         -0.05, 0.15, 0.22, -0.18, 0.12, 0.31, -0.27, 0.08});
    const qwen::Tensor key(
        {3, 2, 2},
        {0.30, -0.20, 0.10, 0.25,
         -0.15, 0.35, 0.20, -0.10,
         0.05, 0.40, -0.30, 0.15});
    const qwen::Tensor value(
        {3, 2, 2},
        {0.50, -0.25, 0.10, 0.75,
         -0.40, 0.20, 0.60, -0.30,
         0.20, 0.45, -0.10, 0.35});
    const qwen::he::StableAttentionApproximationConfig approximation{
        {2.0}, {-2.0, 0.1, 16}, {0.75, 3.25, 16}};

    const qwen::Tensor full_polynomial =
        qwen::he::approximate_stable_causal_gqa_attention(
            query, key, value, config, approximation);
    const qwen::Tensor query_prefix = token_range(query, 0, 2);
    const qwen::Tensor key_prefix = token_range(key, 0, 2);
    const qwen::Tensor value_prefix = token_range(value, 0, 2);
    const qwen::Tensor query_decode = token_range(query, 2, 1);
    const qwen::Tensor key_decode = token_range(key, 2, 1);
    const qwen::Tensor value_decode = token_range(value, 2, 1);

    qwen::KVCache plain_cache;
    static_cast<void>(
        qwen::he::approximate_stable_causal_gqa_attention(
            query_prefix, key_prefix, value_prefix, config,
            approximation, &plain_cache));
    expect_true(plain_cache.size() == 2,
                "plain polynomial KV prefill size");
    const qwen::Tensor cached_polynomial =
        qwen::he::approximate_stable_causal_gqa_attention(
            query_decode, key_decode, value_decode, config,
            approximation, &plain_cache);
    expect_true(plain_cache.size() == 3,
                "plain polynomial KV decode size");
    expect_tensor_near(
        cached_polynomial, token_range(full_polynomial, 2, 1),
        1.0e-12, "polynomial_cached_vs_full_attention");

    qwen::he::EncryptedKVCache encrypted_cache;
    const auto encrypt_flattened =
        [&](const qwen::Tensor &tensor) {
            return qwen::he::encrypt_tensor(
                tensor.reshape(
                    {tensor.dim(0), tensor.dim(1) * tensor.dim(2)}),
                runtime);
        };
    static_cast<void>(
        qwen::he::encrypted_stable_cached_gqa_attention(
            encrypt_flattened(query_prefix),
            encrypt_flattened(key_prefix),
            encrypt_flattened(value_prefix), config, approximation,
            encrypted_cache, runtime,
            qwen::he::RefreshMode::debug_bootstrap,
            qwen::he::RefreshMode::debug_bootstrap));
    expect_true(encrypted_cache.size() == 2,
                "encrypted KV prefill size");
    const qwen::he::EncryptedTensor encrypted_decode =
        qwen::he::encrypted_stable_cached_gqa_attention(
            encrypt_flattened(query_decode),
            encrypt_flattened(key_decode),
            encrypt_flattened(value_decode), config, approximation,
            encrypted_cache, runtime,
            qwen::he::RefreshMode::debug_bootstrap,
            qwen::he::RefreshMode::debug_bootstrap);
    expect_true(encrypted_cache.size() == 3,
                "encrypted KV decode size");
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_decode, runtime),
        cached_polynomial.reshape({1, 8}), 2.0e-3,
        "encrypted_cached_vs_polynomial_attention");
    std::cout << "encrypted_kv_cache tokens="
              << encrypted_cache.size() << " decode_level="
              << runtime.chain_index(
                     encrypted_decode.cipher(0, 0))
              << '\n';
}

void test_encrypted_decoder_layer()
{
    qwen::he::HeRuntime runtime =
        qwen::he::make_he_runtime(
            qwen::he::deep_debug_he_config());
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::DecoderLayerWeights weights =
        qwen::make_demo_layer_weights(config, 17);
    const qwen::Tensor input =
        qwen::make_demo_hidden_states(2, config);
    qwen::he::EncryptedDecoderApproximationConfig approximation{
        {0.05, 0.25, 32},
        {0.05, 0.25, 32},
        {{2.0}, {-2.0, 0.1, 16}, {0.75, 2.25, 16}},
        {-2.0, 2.0, 16},
    };
    qwen::he::set_decoder_bootstrap_schedule(
        approximation, qwen::he::RefreshMode::debug_bootstrap);
    approximation.silu_overrides.emplace(
        0, qwen::he::ApproximationConfig{-2.0, 2.0, 32});

    std::map<std::string, qwen::Tensor> reference;
    const qwen::Tensor polynomial_output =
        qwen::he::approximate_decoder_layer(
            input, weights, config, approximation, 0,
            [&](const std::string &name,
                const qwen::Tensor &tensor) {
                reference[name] = tensor;
            });

    const qwen::he::EncryptedTensor encrypted_input =
        qwen::he::encrypt_tensor(input, runtime);
    std::size_t traced_nodes = 0;
    const qwen::he::EncryptedTensor encrypted_output =
        qwen::he::encrypted_decoder_layer(
            encrypted_input, weights, config, approximation, 0, runtime,
            [&](const std::string &name,
                const qwen::he::EncryptedTensor &tensor) {
                const auto found = reference.find(name);
                expect_true(
                    found != reference.end(),
                    "unexpected encrypted decoder trace node " + name);
                expect_tensor_near(
                    qwen::he::decrypt_tensor(tensor, runtime),
                    found->second, 3.0e-3,
                    "encrypted_decoder." + name);
                ++traced_nodes;
            });
    expect_true(
        traced_nodes == reference.size(),
        "encrypted decoder trace node count");
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_output, runtime),
        polynomial_output, 3.0e-3,
        "encrypted_decoder.output_return");

    const qwen::PlainDecoderLayer exact_layer(config, weights);
    const qwen::Tensor exact_output = exact_layer.forward(input);
    expect_tensor_near(
        polynomial_output, exact_output, 2.0e-3,
        "polynomial_plain_decoder_vs_exact");
    std::cout << "encrypted_decoder level_in="
              << runtime.chain_index(encrypted_input.cipher(0, 0))
              << " level_out="
              << runtime.chain_index(encrypted_output.cipher(0, 0))
              << " traced_nodes=" << traced_nodes << '\n';
}

void test_encrypted_cached_decoder_layer()
{
    qwen::he::HeRuntime runtime =
        qwen::he::make_he_runtime(
            qwen::he::deep_debug_he_config());
    const qwen::QwenConfig config = qwen::demo_config();
    const qwen::DecoderLayerWeights weights =
        qwen::make_demo_layer_weights(config, 23);
    const qwen::Tensor input =
        qwen::make_demo_hidden_states(3, config);
    qwen::he::EncryptedDecoderApproximationConfig approximation{
        {0.05, 0.25, 32},
        {0.05, 0.25, 32},
        {{2.0}, {-2.0, 0.1, 16}, {0.75, 3.25, 16}},
        {-2.0, 2.0, 16},
    };
    qwen::he::set_decoder_bootstrap_schedule(
        approximation, qwen::he::RefreshMode::debug_bootstrap);
    approximation.input_inverse_sqrt_overrides.emplace(
        0, qwen::he::ApproximationConfig{0.05, 0.25, 32});
    approximation.post_attention_inverse_sqrt_overrides.emplace(
        0, qwen::he::ApproximationConfig{0.05, 0.25, 32});
    approximation.silu_overrides.emplace(
        0, qwen::he::ApproximationConfig{-2.0, 2.0, 32});

    const qwen::Tensor full_polynomial =
        qwen::he::approximate_decoder_layer(
            input, weights, config, approximation, 0);
    const qwen::Tensor prefix = token_range(input, 0, 2);
    const qwen::Tensor decode = token_range(input, 2, 1);

    qwen::KVCache plain_cache;
    static_cast<void>(qwen::he::approximate_decoder_layer(
        prefix, weights, config, approximation, 0, {},
        &plain_cache));
    expect_true(plain_cache.size() == 2,
                "plain decoder KV prefill size");
    const qwen::Tensor cached_polynomial =
        qwen::he::approximate_decoder_layer(
            decode, weights, config, approximation, 2, {},
            &plain_cache);
    expect_true(plain_cache.size() == 3,
                "plain decoder KV decode size");
    expect_tensor_near(
        cached_polynomial, token_range(full_polynomial, 2, 1),
        1.0e-12, "polynomial_cached_vs_full_decoder");

    qwen::he::EncryptedKVCache encrypted_cache;
    static_cast<void>(qwen::he::encrypted_decoder_layer(
        qwen::he::encrypt_tensor(prefix, runtime), weights, config,
        approximation, 0, runtime, {}, &encrypted_cache));
    expect_true(encrypted_cache.size() == 2,
                "encrypted decoder KV prefill size");
    const qwen::he::EncryptedTensor encrypted_decode =
        qwen::he::encrypted_decoder_layer(
            qwen::he::encrypt_tensor(decode, runtime), weights, config,
            approximation, 2, runtime, {}, &encrypted_cache);
    expect_true(encrypted_cache.size() == 3,
                "encrypted decoder KV decode size");
    expect_tensor_near(
        qwen::he::decrypt_tensor(encrypted_decode, runtime),
        cached_polynomial, 3.0e-3,
        "encrypted_cached_vs_polynomial_decoder");
    std::cout << "encrypted_decoder_kv_cache tokens="
              << encrypted_cache.size() << " output_level="
              << runtime.chain_index(
                     encrypted_decode.cipher(0, 0))
              << '\n';
}

} // namespace

int main()
{
    try
    {
        const auto run = [](const char *name, const auto &test) {
            std::cout << "running=" << name << std::endl;
            test();
        };
        run("pack_round_trip", test_pack_round_trip);
        run("single_token_cipher_policy", test_single_token_cipher_policy);
        run("qwen_wide_stride_cipher_counts",
            test_qwen_wide_stride_cipher_counts);
        run("single_token_bootstrap_schedule",
            test_single_token_bootstrap_schedule);
        run("single_token_periodic_linear",
            test_single_token_periodic_linear);
        run("wide_stride_operators", test_wide_stride_operators);
        // PoseidonFactory owns process-wide device/context state. Do not keep
        // the shared logN=11 runtime alive while this logN=13 test runs.
        run("packed_rotation_and_linear", test_packed_rotation_and_linear);
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(qwen::he::debug_he_config());
        run("encrypt_round_trip", [&] { test_encrypt_round_trip(runtime); });
        run("input_modulus_drop",
            [&] { test_input_modulus_drop(runtime); });
        run("add_and_multiply_plain", [&] { test_add_and_multiply_plain(runtime); });
        run("rotate_and_reduce", [&] { test_rotate_and_reduce(runtime); });
        run("linear", [&] { test_linear(runtime); });
        run("rope", [&] { test_rope(runtime); });
        run("chunked_linear", [&] { test_chunked_linear(runtime); });
        run("silu", [&] { test_silu(runtime); });
        run("sigmoid", [&] { test_sigmoid(runtime); });
        run("rms_norm", [&] { test_rms_norm(runtime); });
        run("causal_gqa_attention", [&] { test_causal_gqa_attention(runtime); });
        run("private_maximum", [&] { test_private_maximum(runtime); });
        run("stable_causal_gqa_attention", test_stable_causal_gqa_attention);
        run("multi_token_stable_causal_gqa_attention",
            test_multi_token_stable_causal_gqa_attention);
        run("encrypted_cached_stable_attention", test_encrypted_cached_stable_attention);
        run("encrypted_decoder_layer", test_encrypted_decoder_layer);
        run("encrypted_cached_decoder_layer", test_encrypted_cached_decoder_layer);
        std::cout << "qwen_he_tests: PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_he_tests: FAIL: " << error.what() << '\n';
        return 1;
    }
}
