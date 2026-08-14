#include "he/encrypted_ops.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace qwen::he
{

namespace
{

void require_same_layout(const EncryptedTensor &lhs,
                         const EncryptedTensor &rhs)
{
    const EncryptedTensorLayout &a = lhs.layout();
    const EncryptedTensorLayout &b = rhs.layout();
    if (a.tokens != b.tokens || a.features != b.features ||
        a.token_stride != b.token_stride || a.slot_count != b.slot_count ||
        a.token_capacity_limit != b.token_capacity_limit)
    {
        throw std::invalid_argument("encrypted add requires matching layouts");
    }
}

std::vector<std::vector<double>>
pack_plain_like(const Tensor &plain, const EncryptedTensor &encrypted)
{
    return pack_tensor(plain, encrypted.layout());
}

double rescale_plain_scale(const poseidon::Ciphertext &cipher,
                           const HeRuntime &runtime)
{
    const auto data =
        runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!data)
    {
        throw std::runtime_error("failed to find Qwen HE ciphertext level");
    }
    return static_cast<double>(data->coeff_modulus().back().value());
}

bool is_power_of_two(std::size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t linear_baby_step_width(std::size_t stride)
{
    if (!is_power_of_two(stride))
    {
        throw std::invalid_argument(
            "Qwen HE BSGS Linear requires a power-of-two stride");
    }
    std::size_t width = 1;
    while (width <= stride / 4 && width * width < stride)
    {
        width *= 2;
    }
    return width;
}

void rotate_plain_slots(std::vector<std::complex<double>> &values,
                        std::size_t steps)
{
    if (values.empty())
    {
        return;
    }
    steps %= values.size();
    if (steps == 0)
    {
        return;
    }
    std::rotate(values.begin(),
                values.begin() + static_cast<std::ptrdiff_t>(steps),
                values.end());
}

EncodedLinear encode_linear_at_parms(
    const Tensor &weight, const poseidon::parms_id_type &parms_id,
    HeRuntime &runtime)
{
    if (weight.rank() != 2)
    {
        throw std::invalid_argument("Qwen HE Linear weight must be rank 2");
    }
    const std::size_t output_features = weight.dim(0);
    const std::size_t input_features = weight.dim(1);
    const std::size_t stride = runtime.config().token_stride;
    const std::size_t slot_count = runtime.config().slot_count();
    if (slot_count % stride != 0)
    {
        throw std::invalid_argument(
            "Qwen HE Linear token stride must divide the slot count");
    }

    const std::size_t input_chunks =
        (input_features + stride - 1) / stride;
    const std::size_t output_chunks =
        (output_features + stride - 1) / stride;
    const bool single_token_cipher =
        runtime.config().tokens_per_cipher() == 1;
    const std::size_t baby_step = linear_baby_step_width(
        single_token_cipher ? stride : slot_count);
    const auto context_data =
        runtime.context.crt_context()->get_context_data(parms_id);
    if (!context_data)
    {
        throw std::invalid_argument(
            "Qwen HE Linear requested an unknown ciphertext level");
    }
    const double plain_scale =
        static_cast<double>(context_data->coeff_modulus().back().value());

    std::vector<std::map<int, poseidon::Plaintext>> encoded_matrices(
        input_chunks * output_chunks);
    bool any_nonzero = false;
    for (std::size_t output_chunk = 0; output_chunk < output_chunks;
         ++output_chunk)
    {
        const std::size_t output_offset = output_chunk * stride;
        const std::size_t local_outputs =
            std::min(stride, output_features - output_offset);
        for (std::size_t input_chunk = 0; input_chunk < input_chunks;
             ++input_chunk)
        {
            const std::size_t input_offset = input_chunk * stride;
            const std::size_t local_inputs =
                std::min(stride, input_features - input_offset);
            auto &encoded =
                encoded_matrices[output_chunk * input_chunks + input_chunk];
            // A single-token ciphertext is made stride-periodic immediately
            // before evaluation, so it needs only the stride local cyclic
            // diagonals. Packed ciphertexts retain the two global diagonal
            // ranges that prevent rotations from crossing token blocks.
            std::vector<std::size_t> rotations;
            rotations.reserve(
                single_token_cipher
                    ? stride
                    : std::min(slot_count, 2 * stride - 1));
            for (std::size_t diagonal = 0;
                 diagonal < std::min(stride, slot_count); ++diagonal)
            {
                rotations.push_back(diagonal);
            }
            if (!single_token_cipher && slot_count > stride)
            {
                for (std::size_t diagonal = slot_count - stride + 1;
                     diagonal < slot_count; ++diagonal)
                {
                    rotations.push_back(diagonal);
                }
            }
            for (const std::size_t diagonal : rotations)
            {
                std::vector<std::complex<double>> values(
                    slot_count, {0.0, 0.0});
                bool nonzero = false;
                const std::size_t encoded_blocks =
                    single_token_cipher ? 1 : slot_count / stride;
                for (std::size_t block = 0; block < encoded_blocks; ++block)
                {
                    const std::size_t block_offset = block * stride;
                    for (std::size_t output = 0;
                         output < local_outputs; ++output)
                    {
                        const std::size_t output_slot =
                            block_offset + output;
                        const std::size_t input_slot =
                            (output_slot + diagonal) % slot_count;
                        if (single_token_cipher ||
                            input_slot / stride == block)
                        {
                            const std::size_t input =
                                single_token_cipher
                                    ? (output + diagonal) % stride
                                    : input_slot % stride;
                            if (input < local_inputs)
                            {
                                const double value = weight.at(
                                    output_offset + output,
                                    input_offset + input);
                                values[output_slot] = {value, 0.0};
                                nonzero = nonzero || value != 0.0;
                            }
                        }
                    }
                }
                if (nonzero)
                {
                    // For k=j+i, encode R_{-j}(diag_k). The evaluator
                    // computes R_j(R_i(x) * R_{-j}(diag_k)).
                    const std::size_t giant_step =
                        (diagonal / baby_step) * baby_step;
                    rotate_plain_slots(
                        values, (slot_count - giant_step) % slot_count);
                    poseidon::Plaintext plain;
                    runtime.encoder.encode(values, parms_id, plain_scale,
                                           plain);
                    encoded.emplace(static_cast<int>(diagonal),
                                    std::move(plain));
                    any_nonzero = true;
                }
            }
        }
    }
    if (!any_nonzero)
    {
        throw std::invalid_argument("Qwen HE Linear weight is all zero");
    }
    return EncodedLinear(input_features, output_features, stride,
                         std::move(encoded_matrices));
}

} // namespace

EncryptedTensor encrypted_drop_to_level(const EncryptedTensor &input,
                                        std::size_t target_level,
                                        HeRuntime &runtime)
{
    const auto &parms_ids =
        runtime.context.crt_context()->parms_id_map();
    const auto target = parms_ids.find(target_level);
    if (target == parms_ids.end())
    {
        throw std::invalid_argument(
            "Qwen modulus drop requested an unavailable target level");
    }

    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : input.ciphertexts())
    {
        const std::size_t source_level = runtime.chain_index(cipher);
        if (source_level < target_level)
        {
            throw std::invalid_argument(
                "Qwen modulus drop cannot raise a ciphertext level");
        }
        if (source_level == target_level)
        {
            output.push_back(cipher);
            continue;
        }
        poseidon::Ciphertext dropped;
        runtime.evaluator->drop_modulus(
            cipher, dropped, target->second);
        output.push_back(std::move(dropped));
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor encrypted_add(const EncryptedTensor &lhs,
                              const EncryptedTensor &rhs,
                              HeRuntime &runtime)
{
    require_same_layout(lhs, rhs);
    std::vector<poseidon::Ciphertext> output(lhs.ciphertexts().size());
    for (std::size_t index = 0; index < output.size(); ++index)
    {
        runtime.evaluator->add_dynamic(lhs.ciphertexts()[index],
                                       rhs.ciphertexts()[index], output[index],
                                       runtime.encoder);
    }
    return EncryptedTensor(lhs.layout(), std::move(output));
}

EncryptedTensor encrypted_subtract(const EncryptedTensor &lhs,
                                   const EncryptedTensor &rhs,
                                   HeRuntime &runtime)
{
    require_same_layout(lhs, rhs);
    std::vector<poseidon::Ciphertext> output(lhs.ciphertexts().size());
    for (std::size_t index = 0; index < output.size(); ++index)
    {
        runtime.evaluator->sub_dynamic(
            lhs.ciphertexts()[index], rhs.ciphertexts()[index],
            output[index], runtime.encoder);
    }
    return EncryptedTensor(lhs.layout(), std::move(output));
}

EncryptedTensor encrypted_add_plain(const EncryptedTensor &input,
                                    const Tensor &plain,
                                    HeRuntime &runtime)
{
    const auto packed = pack_plain_like(plain, input);
    std::vector<poseidon::Ciphertext> output(input.ciphertexts().size());
    for (std::size_t index = 0; index < output.size(); ++index)
    {
        std::vector<std::complex<double>> values(packed[index].size());
        std::transform(packed[index].begin(), packed[index].end(),
                       values.begin(), [](double value) {
                           return std::complex<double>(value, 0.0);
                       });
        poseidon::Plaintext encoded;
        runtime.encoder.encode(values, input.ciphertexts()[index].parms_id(),
                               input.ciphertexts()[index].scale(), encoded);
        runtime.evaluator->add_plain(input.ciphertexts()[index], encoded,
                                     output[index]);
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor encrypted_multiply_plain(const EncryptedTensor &input,
                                         const Tensor &plain,
                                         HeRuntime &runtime)
{
    const auto packed = pack_plain_like(plain, input);
    std::vector<poseidon::Ciphertext> output(input.ciphertexts().size());
    for (std::size_t index = 0; index < output.size(); ++index)
    {
        std::vector<std::complex<double>> values(packed[index].size());
        std::transform(packed[index].begin(), packed[index].end(),
                       values.begin(), [](double value) {
                           return std::complex<double>(value, 0.0);
                       });
        poseidon::Plaintext encoded;
        runtime.encoder.encode(values, input.ciphertexts()[index].parms_id(),
                               rescale_plain_scale(input.ciphertexts()[index],
                                                   runtime),
                               encoded);
        runtime.evaluator->multiply_plain(input.ciphertexts()[index], encoded,
                                          output[index]);
        runtime.evaluator->rescale_dynamic(
            output[index], output[index], input.ciphertexts()[index].scale());
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor encrypted_multiply(const EncryptedTensor &lhs,
                                   const EncryptedTensor &rhs,
                                   HeRuntime &runtime)
{
    require_same_layout(lhs, rhs);
    std::vector<poseidon::Ciphertext> output(lhs.ciphertexts().size());
    for (std::size_t index = 0; index < output.size(); ++index)
    {
        output[index] = encrypted_multiply_ciphertexts(
            lhs.ciphertexts()[index], rhs.ciphertexts()[index],
            std::min(lhs.ciphertexts()[index].scale(),
                     rhs.ciphertexts()[index].scale()),
            runtime);
    }
    return EncryptedTensor(lhs.layout(), std::move(output));
}

poseidon::Ciphertext encrypted_multiply_ciphertexts(
    const poseidon::Ciphertext &lhs_input,
    const poseidon::Ciphertext &rhs_input, double target_scale,
    HeRuntime &runtime)
{
    poseidon::Ciphertext lhs = lhs_input;
    poseidon::Ciphertext rhs = rhs_input;
    const auto lhs_data = runtime.context.crt_context()->get_context_data(
        lhs.parms_id());
    const auto rhs_data = runtime.context.crt_context()->get_context_data(
        rhs.parms_id());
    if (!lhs_data || !rhs_data || !std::isfinite(target_scale) ||
        target_scale <= 0.0)
    {
        throw std::invalid_argument(
            "Qwen HE ciphertext product received invalid parameters");
    }
    if (lhs_data->chain_index() > rhs_data->chain_index())
    {
        runtime.evaluator->drop_modulus(lhs, lhs, rhs.parms_id());
    }
    else if (rhs_data->chain_index() > lhs_data->chain_index())
    {
        runtime.evaluator->drop_modulus(rhs, rhs, lhs.parms_id());
    }

    const double q_last = rescale_plain_scale(lhs, runtime);
    const double balancing_value =
        target_scale * q_last /
        (lhs.scale() * rhs.scale());
    if (!std::isfinite(balancing_value) || balancing_value <= 0.0)
    {
        throw std::runtime_error(
            "Qwen HE ciphertext product cannot balance its scale");
    }
    poseidon::Ciphertext balanced_rhs;
    runtime.evaluator->multiply_const(
        rhs, balancing_value, 1.0, balanced_rhs, runtime.encoder);

    poseidon::Ciphertext product;
    runtime.evaluator->multiply_relin_dynamic(
        lhs, balanced_rhs, product, runtime.relin_keys);
    runtime.evaluator->rescale(product, product);
    product.scale() = target_scale;
    return product;
}

EncryptedTensor encrypted_bootstrap(const EncryptedTensor &input,
                                    HeRuntime &runtime)
{
    const bool target_profile =
        runtime.config().production_security &&
        runtime.config().log_n == 16 && runtime.config().log_scale == 46;
    const bool prototype_profile =
        !runtime.config().production_security &&
        runtime.config().log_n == 13 && runtime.config().log_scale == 46;
    const bool prototype_fast_profile =
        !runtime.config().production_security &&
        runtime.config().log_n == 11 && runtime.config().log_scale == 46;
    const bool prototype_mid_profile =
        !runtime.config().production_security &&
        runtime.config().log_n == 12 && runtime.config().log_scale == 46;
    const bool prototype_high_profile =
        !runtime.config().production_security &&
        runtime.config().log_n == 12 && runtime.config().log_scale == 55;
    const bool prototype_high13_profile =
        !runtime.config().production_security &&
        runtime.config().log_n == 13 && runtime.config().log_scale == 55;
    if (!target_profile && !prototype_profile && !prototype_fast_profile &&
        !prototype_mid_profile && !prototype_high_profile &&
        !prototype_high13_profile)
    {
        throw std::invalid_argument(
            "Qwen bootstrap requires target or prototype HE configuration");
    }
    poseidon::BootstrapConfig config;
    config.boundary_k = runtime.config().bootstrap_boundary_k;
    config.scaling_log = runtime.config().bootstrap_scaling_log;
    // Keep the real projection for every validated profile. It removes the
    // unused conjugate component and materially improves long-stack noise.
    config.project_real = true;
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : input.ciphertexts())
    {
        poseidon::Ciphertext prepared = cipher;
        const double value_scale = runtime.config().bootstrap_value_scale;
        if (!poseidon::util::are_approximate<double>(value_scale, 1.0))
        {
            // Bootstrap's modular-reduction polynomial is calibrated for a
            // bounded message interval. Scale the CKKS message into that
            // interval; the inverse factor is applied after refresh.
            const double plain_scale =
                rescale_plain_scale(prepared, runtime);
            poseidon::Ciphertext scaled;
            runtime.evaluator->multiply_const(
                prepared, 1.0 / value_scale, plain_scale, scaled,
                runtime.encoder);
            runtime.evaluator->rescale_dynamic(
                scaled, scaled, prepared.scale());
            scaled.scale() = prepared.scale();
            prepared = std::move(scaled);
        }
        while (prepared.scale() > runtime.scale() &&
               !poseidon::util::are_approximate<double>(
                   prepared.scale(), runtime.scale()))
        {
            const auto context_data =
                runtime.context.crt_context()->get_context_data(
                    prepared.parms_id());
            if (!context_data ||
                context_data->coeff_modulus().size() <= 1)
            {
                throw std::runtime_error(
                    "Qwen bootstrap input has no scale-normalization level");
            }
            const double q_last = static_cast<double>(
                context_data->coeff_modulus().back().value());
            const double plain_scale =
                runtime.scale() * q_last / prepared.scale();
            if (!std::isfinite(plain_scale) || plain_scale <= 0.0)
            {
                throw std::runtime_error(
                    "Qwen bootstrap input scale cannot be normalized");
            }
            if (plain_scale < 1.0)
            {
                runtime.evaluator->rescale(prepared, prepared);
                continue;
            }
            poseidon::Ciphertext normalized;
            runtime.evaluator->multiply_const(
                prepared, 1.0, plain_scale, normalized,
                runtime.encoder);
            runtime.evaluator->rescale(normalized, normalized);
            normalized.scale() = runtime.scale();
            prepared = std::move(normalized);
        }
        poseidon::Ciphertext refreshed;
        runtime.evaluator->bootstrap(
            prepared, refreshed, runtime.relin_keys, runtime.galois_keys,
            runtime.encoder, config);
        if (!poseidon::util::are_approximate<double>(
                refreshed.scale(), runtime.scale()))
        {
            const auto context_data =
                runtime.context.crt_context()->get_context_data(
                    refreshed.parms_id());
            if (!context_data ||
                context_data->coeff_modulus().size() <= 1)
            {
                throw std::runtime_error(
                    "Qwen bootstrap output has no normalization level");
            }
            const double q_last = static_cast<double>(
                context_data->coeff_modulus().back().value());
            const double plain_scale =
                runtime.scale() * q_last / refreshed.scale();
            if (!std::isfinite(plain_scale) || plain_scale < 1.0)
            {
                throw std::runtime_error(
                    "Qwen bootstrap produced an invalid output scale");
            }
            poseidon::Ciphertext normalized;
            runtime.evaluator->multiply_const(
                refreshed, 1.0, plain_scale, normalized,
                runtime.encoder);
            runtime.evaluator->rescale(normalized, normalized);
            normalized.scale() = runtime.scale();
            refreshed = std::move(normalized);
        }
        if (!poseidon::util::are_approximate<double>(value_scale, 1.0))
        {
            poseidon::Ciphertext restored;
            const double rounded_scale = std::round(value_scale);
            if (poseidon::util::are_approximate<double>(
                    value_scale, rounded_scale) &&
                rounded_scale >=
                    static_cast<double>(std::numeric_limits<int>::min()) &&
                rounded_scale <=
                    static_cast<double>(std::numeric_limits<int>::max()))
            {
                // Calibrated Qwen boundary scales are small integers. A
                // unit-scale plaintext multiplication restores them exactly
                // without consuming the freshly bootstrapped level.
                runtime.evaluator->multiply_const_direct(
                    refreshed, static_cast<int>(rounded_scale), restored,
                    runtime.encoder);
            }
            else
            {
                const double plain_scale =
                    rescale_plain_scale(refreshed, runtime);
                runtime.evaluator->multiply_const(
                    refreshed, value_scale, plain_scale, restored,
                    runtime.encoder);
                runtime.evaluator->rescale_dynamic(
                    restored, restored, runtime.scale());
            }
            restored.scale() = runtime.scale();
            refreshed = std::move(restored);
        }
        output.push_back(std::move(refreshed));
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor encrypted_refresh(const EncryptedTensor &input,
                                  RefreshMode mode,
                                  HeRuntime &runtime)
{
    if (mode == RefreshMode::none)
    {
        return input;
    }
    if (mode == RefreshMode::bootstrap)
    {
        return encrypted_bootstrap(input, runtime);
    }
    if (runtime.config().production_security &&
        !runtime.config().allow_insecure_mock_boundaries)
    {
        throw std::invalid_argument(
            "debug re-encryption is forbidden for production HE parameters");
    }
    EncryptedTensor refreshed =
        encrypt_tensor(decrypt_tensor(input, runtime), runtime);
    if (mode == RefreshMode::debug_reencrypt)
    {
        return refreshed;
    }

    const auto &parms_ids =
        runtime.context.crt_context()->parms_id_map();
    const auto output_parms = parms_ids.find(bootstrap_output_level);
    if (output_parms == parms_ids.end())
    {
        throw std::invalid_argument(
            "debug bootstrap simulation requires chain level 19");
    }
    std::vector<poseidon::Ciphertext> output;
    output.reserve(refreshed.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : refreshed.ciphertexts())
    {
        poseidon::Ciphertext dropped;
        runtime.evaluator->drop_modulus(
            cipher, dropped, output_parms->second);
        output.push_back(std::move(dropped));
    }
    return EncryptedTensor(refreshed.layout(), std::move(output));
}

EncryptedTensor encrypted_refresh_at_scale(
    const EncryptedTensor &input, RefreshMode mode, double value_scale,
    HeRuntime &runtime)
{
    if (!std::isfinite(value_scale) || value_scale <= 0.0)
    {
        throw std::invalid_argument(
            "Qwen encrypted refresh value scale must be positive");
    }
    if (mode != RefreshMode::bootstrap ||
        poseidon::util::are_approximate<double>(value_scale, 1.0))
    {
        return encrypted_refresh(input, mode, runtime);
    }
    const double previous = runtime.config().bootstrap_value_scale;
    runtime.set_bootstrap_value_scale(value_scale);
    try
    {
        EncryptedTensor result = encrypted_refresh(input, mode, runtime);
        runtime.set_bootstrap_value_scale(previous);
        return result;
    }
    catch (...)
    {
        runtime.set_bootstrap_value_scale(previous);
        throw;
    }
}

poseidon::Ciphertext rotate_slots(const poseidon::Ciphertext &input, int steps,
                                  HeRuntime &runtime)
{
    poseidon::Ciphertext output;
    runtime.evaluator->rotate(input, output, steps, runtime.galois_keys);
    return output;
}

poseidon::Ciphertext rotate_blocks(const poseidon::Ciphertext &input,
                                   int steps, std::size_t block_width,
                                   HeRuntime &runtime)
{
    const std::size_t slot_count = runtime.config().slot_count();
    if (!is_power_of_two(block_width) || block_width > slot_count ||
        slot_count % block_width != 0)
    {
        throw std::invalid_argument(
            "Qwen HE block rotation width must divide the slot count");
    }

    const int width = static_cast<int>(block_width);
    int normalized = steps % width;
    if (normalized < 0)
    {
        normalized += width;
    }
    if (normalized == 0)
    {
        return input;
    }
    if (block_width == slot_count)
    {
        return rotate_slots(input, normalized, runtime);
    }

    poseidon::Ciphertext no_wrap =
        rotate_slots(input, normalized, runtime);
    poseidon::Ciphertext wrap =
        rotate_slots(input, normalized - width, runtime);
    std::vector<std::complex<double>> no_wrap_mask(
        slot_count, {0.0, 0.0});
    std::vector<std::complex<double>> wrap_mask(
        slot_count, {0.0, 0.0});
    const std::size_t split = block_width -
                              static_cast<std::size_t>(normalized);
    for (std::size_t slot = 0; slot < slot_count; ++slot)
    {
        if (slot % block_width < split)
        {
            no_wrap_mask[slot] = {1.0, 0.0};
        }
        else
        {
            wrap_mask[slot] = {1.0, 0.0};
        }
    }
    poseidon::Plaintext encoded_no_wrap;
    poseidon::Plaintext encoded_wrap;
    const double mask_scale = rescale_plain_scale(input, runtime);
    runtime.encoder.encode(no_wrap_mask, input.parms_id(), mask_scale,
                           encoded_no_wrap);
    runtime.encoder.encode(wrap_mask, input.parms_id(), mask_scale,
                           encoded_wrap);
    poseidon::Ciphertext masked_no_wrap;
    poseidon::Ciphertext masked_wrap;
    runtime.evaluator->multiply_plain(no_wrap, encoded_no_wrap,
                                      masked_no_wrap);
    runtime.evaluator->multiply_plain(wrap, encoded_wrap, masked_wrap);
    poseidon::Ciphertext combined;
    runtime.evaluator->add(masked_no_wrap, masked_wrap, combined);
    poseidon::Ciphertext output;
    runtime.evaluator->rescale_dynamic(combined, output, input.scale());
    return output;
}

poseidon::Ciphertext reduce_sum_slots(const poseidon::Ciphertext &input,
                                      std::size_t width,
                                      HeRuntime &runtime)
{
    const std::size_t slot_count = runtime.config().slot_count();
    if (!is_power_of_two(width) || width > slot_count ||
        slot_count % width != 0)
    {
        throw std::invalid_argument(
            "Qwen HE reduction width must be a supported power of two");
    }

    if (runtime.config().tokens_per_cipher() == 1)
    {
        // A target-profile ciphertext owns one logical token even though its
        // ring has several physical token-sized blocks. Replicating that same
        // encrypted block makes the value periodic, so the reduction can use
        // rotations and additions only instead of one plaintext mask (and one
        // level) at every step.
        poseidon::Ciphertext output = input;
        for (std::size_t distance = width; distance < slot_count;
             distance *= 2)
        {
            poseidon::Ciphertext rotated = rotate_slots(
                output, static_cast<int>(distance), runtime);
            runtime.evaluator->add(output, rotated, output);
        }
        for (std::size_t step = 1; step < width; step *= 2)
        {
            poseidon::Ciphertext rotated = rotate_slots(
                output, static_cast<int>(step), runtime);
            runtime.evaluator->add(output, rotated, output);
        }
        return output;
    }

    poseidon::Ciphertext output = input;
    for (std::size_t step = 1; step < width; step *= 2)
    {
        poseidon::Ciphertext rotated = rotate_blocks(
            output, static_cast<int>(step), width, runtime);
        if (output.parms_id() != rotated.parms_id())
        {
            poseidon::Ciphertext aligned;
            runtime.evaluator->drop_modulus(
                output, aligned, rotated.parms_id());
            output = std::move(aligned);
        }
        runtime.evaluator->add(output, rotated, output);
    }
    return output;
}

EncodedLinear::EncodedLinear(std::size_t input_features,
                             std::size_t output_features,
                             std::size_t token_stride,
                             std::vector<std::map<int, poseidon::Plaintext>>
                                 diagonals)
    : input_features_(input_features), output_features_(output_features),
      token_stride_(token_stride), diagonals_(std::move(diagonals))
{
}

std::size_t EncodedLinear::input_features() const
{
    return input_features_;
}

std::size_t EncodedLinear::output_features() const
{
    return output_features_;
}

std::size_t EncodedLinear::token_stride() const
{
    return token_stride_;
}

std::size_t EncodedLinear::input_chunks() const
{
    return (input_features_ + token_stride_ - 1) / token_stride_;
}

std::size_t EncodedLinear::output_chunks() const
{
    return (output_features_ + token_stride_ - 1) / token_stride_;
}

const std::map<int, poseidon::Plaintext> &
EncodedLinear::diagonals(std::size_t output_chunk,
                         std::size_t input_chunk) const
{
    return diagonals_.at(matrix_index(output_chunk, input_chunk));
}

std::size_t EncodedLinear::matrix_index(std::size_t output_chunk,
                                        std::size_t input_chunk) const
{
    if (output_chunk >= output_chunks() || input_chunk >= input_chunks())
    {
        throw std::out_of_range("Qwen HE Linear chunk index is out of range");
    }
    return output_chunk * input_chunks() + input_chunk;
}

EncodedLinear encode_linear(const Tensor &weight, HeRuntime &runtime)
{
    const auto context_data =
        runtime.context.crt_context()->first_context_data();
    return encode_linear_at_parms(weight, context_data->parms().parms_id(),
                                  runtime);
}

EncodedLinear encode_linear_at(const Tensor &weight,
                               const poseidon::Ciphertext &input_level,
                               HeRuntime &runtime)
{
    return encode_linear_at_parms(weight, input_level.parms_id(), runtime);
}

EncryptedTensor encrypted_linear(const EncryptedTensor &input,
                                 const EncodedLinear &linear,
                                 const Tensor *bias,
                                 HeRuntime &runtime)
{
    if (input.layout().features != linear.input_features() ||
        input.layout().feature_chunks() != linear.input_chunks() ||
        input.layout().token_stride != linear.token_stride())
    {
        throw std::invalid_argument(
            "Qwen HE Linear input layout does not match encoded weights");
    }
    if (bias != nullptr &&
        (bias->rank() != 1 || bias->dim(0) != linear.output_features()))
    {
        throw std::invalid_argument("Qwen HE Linear bias shape is invalid");
    }

    std::vector<poseidon::Ciphertext> outputs;
    outputs.reserve(input.layout().token_groups() *
                    linear.output_chunks());
    for (std::size_t token_group = 0;
         token_group < input.layout().token_groups(); ++token_group)
    {
        std::vector<poseidon::Ciphertext> accumulated(
            linear.output_chunks());
        std::vector<bool> initialized(linear.output_chunks(), false);
        for (std::size_t input_chunk = 0;
             input_chunk < linear.input_chunks(); ++input_chunk)
        {
            const bool single_token_cipher =
                runtime.config().tokens_per_cipher() == 1;
            const std::size_t baby_step = linear_baby_step_width(
                single_token_cipher
                    ? linear.token_stride()
                    : runtime.config().slot_count());
            std::set<int> baby_rotations;
            for (std::size_t output_chunk = 0;
                 output_chunk < linear.output_chunks(); ++output_chunk)
            {
                const auto &diagonals =
                    linear.diagonals(output_chunk, input_chunk);
                for (const auto &[rotation, unused] : diagonals)
                {
                    static_cast<void>(unused);
                    baby_rotations.insert(
                        rotation % static_cast<int>(baby_step));
                }
            }
            const poseidon::Ciphertext &logical_source =
                input.cipher(token_group, input_chunk);
            poseidon::Ciphertext periodic_source;
            const poseidon::Ciphertext *source = &logical_source;
            if (single_token_cipher &&
                runtime.config().slot_count() > linear.token_stride())
            {
                periodic_source = logical_source;
                for (std::size_t distance = linear.token_stride();
                     distance < runtime.config().slot_count();
                     distance *= 2)
                {
                    poseidon::Ciphertext rotated = rotate_slots(
                        periodic_source, static_cast<int>(distance),
                        runtime);
                    runtime.evaluator->add(
                        periodic_source, rotated, periodic_source);
                }
                source = &periodic_source;
            }
            std::map<int, poseidon::Ciphertext> rotated_babies;
            for (const int rotation : baby_rotations)
            {
                rotated_babies.emplace(
                    rotation,
                    rotation == 0
                        ? *source
                        : rotate_slots(*source, rotation, runtime));
            }

            for (std::size_t output_chunk = 0;
                 output_chunk < linear.output_chunks(); ++output_chunk)
            {
                // Baby rotations are shared by every output chunk. Each
                // giant-step partial sum needs only one additional rotation.
                std::map<int, poseidon::Ciphertext> giant_sums;
                for (const auto &[diagonal, plain] :
                     linear.diagonals(output_chunk, input_chunk))
                {
                    const int baby =
                        diagonal % static_cast<int>(baby_step);
                    const int giant = diagonal - baby;
                    poseidon::Ciphertext term;
                    runtime.evaluator->multiply_plain(
                        rotated_babies.at(baby), plain, term);
                    auto existing = giant_sums.find(giant);
                    if (existing == giant_sums.end())
                    {
                        giant_sums.emplace(giant, std::move(term));
                    }
                    else
                    {
                        runtime.evaluator->add(
                            existing->second, term, existing->second);
                    }
                }

                for (auto &[giant, inner_sum] : giant_sums)
                {
                    poseidon::Ciphertext term =
                        giant == 0
                            ? std::move(inner_sum)
                            : rotate_slots(inner_sum, giant, runtime);
                    if (!initialized[output_chunk])
                    {
                        accumulated[output_chunk] = std::move(term);
                        initialized[output_chunk] = true;
                    }
                    else
                    {
                        runtime.evaluator->add(
                            accumulated[output_chunk], term,
                            accumulated[output_chunk]);
                    }
                }
            }
        }

        for (std::size_t output_chunk = 0;
             output_chunk < linear.output_chunks(); ++output_chunk)
        {
            if (!initialized[output_chunk])
            {
                throw std::logic_error(
                    "Qwen HE Linear output chunk has no encoded diagonals");
            }
            poseidon::Ciphertext output;
            runtime.evaluator->rescale_dynamic(
                accumulated[output_chunk], output,
                input.cipher(token_group, 0).scale());
            if (bias != nullptr)
            {
                std::vector<std::complex<double>> values(
                    runtime.config().slot_count(), {0.0, 0.0});
                const std::size_t offset =
                    output_chunk * linear.token_stride();
                const std::size_t count = std::min(
                    linear.token_stride(),
                    linear.output_features() - offset);
                const std::size_t first_token =
                    token_group * input.layout().token_capacity();
                const std::size_t active_tokens = std::min(
                    input.layout().token_capacity(),
                    input.layout().tokens - first_token);
                for (std::size_t local_token = 0;
                     local_token < active_tokens; ++local_token)
                {
                    const std::size_t block_offset =
                        local_token * linear.token_stride();
                    for (std::size_t index = 0; index < count; ++index)
                    {
                        values[block_offset + index] =
                            {bias->at(offset + index), 0.0};
                    }
                }
                poseidon::Plaintext encoded_bias;
                runtime.encoder.encode(
                    values, output.parms_id(), output.scale(),
                    encoded_bias);
                runtime.evaluator->add_plain(
                    output, encoded_bias, output);
            }
            outputs.push_back(std::move(output));
        }
    }

    EncryptedTensorLayout layout{input.layout().tokens,
                                 linear.output_features(),
                                 linear.token_stride(),
                                 runtime.config().slot_count(),
                                 input.layout().token_capacity_limit};
    return EncryptedTensor(layout, std::move(outputs));
}

EncryptedTensor encrypted_rope(const EncryptedTensor &input,
                               std::size_t head_count,
                               std::size_t head_dim,
                               std::size_t position,
                               double theta,
                               HeRuntime &runtime)
{
    if (head_dim == 0 || head_dim % 2 != 0 || theta <= 0.0 ||
        input.layout().features != head_count * head_dim ||
        input.layout().feature_chunks() != 1)
    {
        throw std::invalid_argument("invalid Qwen HE RoPE input");
    }

    const std::size_t half = head_dim / 2;
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (std::size_t token_group = 0;
         token_group < input.layout().token_groups(); ++token_group)
    {
        const poseidon::Ciphertext &source =
            input.cipher(token_group, 0);
        std::vector<std::complex<double>> cosine_mask(
            input.layout().slot_count, {0.0, 0.0});
        std::vector<std::complex<double>> first_sine_mask(
            input.layout().slot_count, {0.0, 0.0});
        std::vector<std::complex<double>> second_sine_mask(
            input.layout().slot_count, {0.0, 0.0});
        const std::size_t first_token =
            token_group * input.layout().token_capacity();
        const std::size_t active_tokens = std::min(
            input.layout().token_capacity(),
            input.layout().tokens - first_token);
        for (std::size_t local_token = 0;
             local_token < active_tokens; ++local_token)
        {
            const std::size_t token = first_token + local_token;
            const std::size_t token_offset =
                local_token * input.layout().token_stride;
            for (std::size_t head = 0; head < head_count; ++head)
            {
                const std::size_t head_offset =
                    token_offset + head * head_dim;
                for (std::size_t index = 0; index < half; ++index)
                {
                    const double frequency = std::pow(
                        theta, -2.0 * static_cast<double>(index) /
                                   static_cast<double>(head_dim));
                    const double angle =
                        static_cast<double>(position + token) * frequency;
                    const double cosine = std::cos(angle);
                    const double sine = std::sin(angle);
                    const std::size_t first = head_offset + index;
                    const std::size_t second = first + half;
                    cosine_mask[first] = {cosine, 0.0};
                    cosine_mask[second] = {cosine, 0.0};
                    first_sine_mask[first] = {-sine, 0.0};
                    second_sine_mask[second] = {sine, 0.0};
                }
            }
        }

        const double plain_scale = rescale_plain_scale(source, runtime);
        poseidon::Plaintext encoded_cosine;
        poseidon::Plaintext encoded_first_sine;
        poseidon::Plaintext encoded_second_sine;
        runtime.encoder.encode(cosine_mask, source.parms_id(), plain_scale,
                               encoded_cosine);
        runtime.encoder.encode(first_sine_mask, source.parms_id(),
                               plain_scale, encoded_first_sine);
        runtime.encoder.encode(second_sine_mask, source.parms_id(),
                               plain_scale, encoded_second_sine);

        poseidon::Ciphertext cosine_term;
        poseidon::Ciphertext first_sine_term;
        poseidon::Ciphertext second_sine_term;
        runtime.evaluator->multiply_plain(source, encoded_cosine,
                                          cosine_term);
        const poseidon::Ciphertext rotated_left = rotate_slots(
            source, static_cast<int>(half), runtime);
        runtime.evaluator->multiply_plain(rotated_left,
                                          encoded_first_sine,
                                          first_sine_term);
        const poseidon::Ciphertext rotated_right = rotate_slots(
            source, -static_cast<int>(half), runtime);
        runtime.evaluator->multiply_plain(rotated_right,
                                          encoded_second_sine,
                                          second_sine_term);
        runtime.evaluator->add(cosine_term, first_sine_term, cosine_term);
        runtime.evaluator->add(cosine_term, second_sine_term, cosine_term);
        poseidon::Ciphertext result;
        runtime.evaluator->rescale_dynamic(cosine_term, result,
                                           source.scale());
        output.push_back(std::move(result));
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

} // namespace qwen::he
