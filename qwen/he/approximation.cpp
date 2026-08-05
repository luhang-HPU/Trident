#include "he/approximation.h"
#include "he/encrypted_ops.h"

#include "poseidon/advance/util/chebyshev_interpolation.h"
#include "poseidon/plaintext.h"
#include "relu_approx.h"

#include <cmath>
#include <complex>
#include <functional>
#include <numeric>
#include <stdexcept>
#include <utility>
#include <vector>

namespace qwen::he
{

namespace
{

double inverse_sqrt_function(double value)
{
    return 1.0 / std::sqrt(value);
}

double silu_function(double value)
{
    return value / (1.0 + std::exp(-value));
}

double exp_function(double value)
{
    return std::exp(value);
}

double reciprocal_function(double value)
{
    return 1.0 / value;
}

Tensor exact_rms_norm_plain(const Tensor &input, const Tensor &weight,
                            double epsilon)
{
    if (input.rank() != 2 || weight.rank() != 1 ||
        weight.dim(0) != input.dim(1) || epsilon <= 0.0)
    {
        throw std::invalid_argument("mock RMSNorm received invalid shapes");
    }
    Tensor output(input.shape());
    for (std::size_t token = 0; token < input.dim(0); ++token)
    {
        double sum = 0.0;
        for (std::size_t feature = 0; feature < input.dim(1); ++feature)
        {
            const double value = input.at(token, feature);
            sum += value * value;
        }
        const double inverse = 1.0 / std::sqrt(
            sum / static_cast<double>(input.dim(1)) + epsilon);
        for (std::size_t feature = 0; feature < input.dim(1); ++feature)
        {
            output.at(token, feature) =
                input.at(token, feature) * inverse * weight.at(feature);
        }
    }
    return output;
}

double last_modulus_scale(const poseidon::Ciphertext &cipher,
                          const HeRuntime &runtime)
{
    const auto context_data =
        runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error(
            "failed to locate ciphertext level for polynomial evaluation");
    }
    return static_cast<double>(
        context_data->coeff_modulus().back().value());
}

bool supports_reduced_depth_chebyshev(std::size_t degree)
{
    return degree > 0 && degree <= 31 &&
           ((degree + 1) & degree) == 0;
}

poseidon::Ciphertext affine_to_chebyshev_domain(
    const poseidon::Ciphertext &input, const ApproximationConfig &config,
    HeRuntime &runtime)
{
    const double multiplier =
        2.0 / (config.maximum - config.minimum);
    const double offset =
        -(config.maximum + config.minimum) /
        (config.maximum - config.minimum);
    poseidon::Ciphertext normalized;
    runtime.evaluator->multiply_const(
        input, multiplier, last_modulus_scale(input, runtime), normalized,
        runtime.encoder);
    runtime.evaluator->rescale_dynamic(normalized, normalized, input.scale());
    if (offset != 0.0)
    {
        runtime.evaluator->add_const(normalized, offset, normalized,
                                     runtime.encoder);
    }
    return normalized;
}

poseidon::Ciphertext evaluate_polynomial(
    const poseidon::Ciphertext &input,
    poseidon::Polynomial polynomial,
    const ApproximationConfig &config, HeRuntime &runtime)
{
    poseidon::Ciphertext normalized =
        affine_to_chebyshev_domain(input, config, runtime);
    polynomial.lead() = true;
    std::vector<int> all_slots(runtime.config().slot_count());
    std::iota(all_slots.begin(), all_slots.end(), 0);
    poseidon::PolynomialVector polynomials(
        {std::move(polynomial)}, {std::move(all_slots)});
    poseidon::Ciphertext output;
    if (supports_reduced_depth_chebyshev(
            polynomials.polys().front().degree()))
    {
        output = evaluate_chebyshev_baby(
            normalized, polynomials, runtime.encryptor,
            runtime.encoder, *runtime.evaluator,
            runtime.relin_keys, runtime.context);
    }
    else
    {
        runtime.evaluator->evaluate_poly_vector(
            normalized, output, polynomials, normalized.scale(),
            runtime.relin_keys, runtime.encoder);
    }
    return output;
}

EncryptedTensor evaluate_tensor_polynomial(
    const EncryptedTensor &input, const poseidon::Polynomial &polynomial,
    const ApproximationConfig &config, HeRuntime &runtime)
{
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : input.ciphertexts())
    {
        output.push_back(
            evaluate_polynomial(cipher, polynomial, config, runtime));
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor evaluate_position_polynomial(
    const EncryptedTensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::function<poseidon::Polynomial(const ApproximationConfig &)>
        &make_polynomial,
    HeRuntime &runtime)
{
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (std::size_t token_group = 0;
         token_group < input.layout().token_groups(); ++token_group)
    {
        const std::size_t first_token =
            token_group * input.layout().token_capacity();
        const std::size_t active_tokens = std::min(
            input.layout().token_capacity(),
            input.layout().tokens - first_token);
        for (std::size_t chunk = 0;
             chunk < input.layout().feature_chunks(); ++chunk)
        {
            const poseidon::Ciphertext &source =
                input.cipher(token_group, chunk);
            std::vector<std::complex<double>> multipliers(
                input.layout().slot_count, {0.0, 0.0});
            std::vector<std::complex<double>> offsets(
                input.layout().slot_count, {0.0, 0.0});
            std::vector<poseidon::Polynomial> polynomials;
            std::vector<std::vector<int>> polynomial_slots;
            std::size_t maximum_degree = 0;
            for (std::size_t local_token = 0;
                 local_token < active_tokens; ++local_token)
            {
                const std::size_t token = first_token + local_token;
                const auto override = position_overrides.find(token);
                const ApproximationConfig &token_config =
                    override == position_overrides.end()
                        ? config
                        : override->second;
                token_config.validate();
                const double multiplier =
                    2.0 / (token_config.maximum - token_config.minimum);
                const double offset =
                    -(token_config.maximum + token_config.minimum) /
                    (token_config.maximum - token_config.minimum);
                const std::size_t block_offset =
                    local_token * input.layout().token_stride;
                std::vector<int> slots;
                slots.reserve(input.layout().token_stride);
                for (std::size_t local_slot = 0;
                     local_slot < input.layout().token_stride; ++local_slot)
                {
                    const std::size_t slot = block_offset + local_slot;
                    multipliers[slot] = {multiplier, 0.0};
                    offsets[slot] = {offset, 0.0};
                    slots.push_back(static_cast<int>(slot));
                }
                poseidon::Polynomial polynomial =
                    make_polynomial(token_config);
                polynomial.lead() = true;
                maximum_degree =
                    std::max(maximum_degree, polynomial.degree());
                polynomials.push_back(std::move(polynomial));
                polynomial_slots.push_back(std::move(slots));
            }
            for (poseidon::Polynomial &polynomial : polynomials)
            {
                polynomial.data().resize(maximum_degree + 1,
                                         {0.0, 0.0});
                polynomial.max_degree() =
                    static_cast<int>(maximum_degree);
            }

            poseidon::Plaintext encoded_multipliers;
            runtime.encoder.encode(
                multipliers, source.parms_id(),
                last_modulus_scale(source, runtime),
                encoded_multipliers);
            poseidon::Ciphertext normalized;
            runtime.evaluator->multiply_plain(
                source, encoded_multipliers, normalized);
            runtime.evaluator->rescale_dynamic(
                normalized, normalized, source.scale());
            poseidon::Plaintext encoded_offsets;
            runtime.encoder.encode(offsets, normalized.parms_id(),
                                   normalized.scale(), encoded_offsets);
            runtime.evaluator->add_plain(
                normalized, encoded_offsets, normalized);

            poseidon::PolynomialVector polynomial_vector(
                polynomials, polynomial_slots);
            poseidon::Ciphertext result;
            if (supports_reduced_depth_chebyshev(maximum_degree))
            {
                result = evaluate_chebyshev_baby(
                    normalized, polynomial_vector, runtime.encryptor,
                    runtime.encoder, *runtime.evaluator,
                    runtime.relin_keys, runtime.context);
            }
            else
            {
                runtime.evaluator->evaluate_poly_vector(
                    normalized, result, polynomial_vector,
                    normalized.scale(), runtime.relin_keys,
                    runtime.encoder);
            }
            output.push_back(std::move(result));
        }
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor evaluate_feature_polynomial(
    const EncryptedTensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::vector<ApproximationConfig> &feature_configs,
    const std::map<std::size_t, std::vector<ApproximationConfig>>
        &position_feature_overrides,
    HeRuntime &runtime)
{
    if (!feature_configs.empty() &&
        feature_configs.size() != input.layout().features)
    {
        throw std::invalid_argument(
            "SiLU feature calibration does not match the tensor width");
    }
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (std::size_t token = 0; token < input.layout().tokens; ++token)
    {
        const auto token_override = position_overrides.find(token);
        const ApproximationConfig &token_config =
            token_override == position_overrides.end()
                ? config
                : token_override->second;
        const auto feature_override =
            position_feature_overrides.find(token);
        const std::vector<ApproximationConfig> *token_features =
            feature_override == position_feature_overrides.end()
                ? nullptr
                : &feature_override->second;
        if (token_features != nullptr &&
            token_features->size() != input.layout().features)
        {
            throw std::invalid_argument(
                "position SiLU feature calibration has the wrong width");
        }

        for (std::size_t chunk = 0;
             chunk < input.layout().feature_chunks(); ++chunk)
        {
            const poseidon::Ciphertext &source = input.cipher(token, chunk);
            std::vector<std::complex<double>> multipliers(
                runtime.config().slot_count(), {0.0, 0.0});
            std::vector<std::complex<double>> offsets(
                runtime.config().slot_count(), {0.0, 0.0});
            std::vector<poseidon::Polynomial> polynomials;
            std::vector<std::vector<int>> polynomial_slots;
            const std::size_t feature_begin =
                chunk * input.layout().token_stride;
            const std::size_t feature_end = std::min(
                feature_begin + input.layout().token_stride,
                input.layout().features);
            polynomials.reserve(feature_end - feature_begin);
            polynomial_slots.reserve(feature_end - feature_begin);
            std::size_t maximum_degree = 0;
            for (std::size_t feature = feature_begin;
                 feature < feature_end; ++feature)
            {
                const ApproximationConfig &feature_config =
                    token_features != nullptr
                        ? token_features->at(feature)
                        : (!feature_configs.empty()
                               ? feature_configs.at(feature)
                               : token_config);
                const std::size_t slot = feature - feature_begin;
                multipliers[slot] = {
                    2.0 / (feature_config.maximum -
                           feature_config.minimum),
                    0.0};
                offsets[slot] = {
                    -(feature_config.maximum +
                      feature_config.minimum) /
                        (feature_config.maximum -
                         feature_config.minimum),
                    0.0};
                poseidon::Polynomial polynomial =
                    make_silu_polynomial(feature_config);
                polynomial.lead() = true;
                maximum_degree =
                    std::max(maximum_degree, polynomial.degree());
                polynomials.push_back(std::move(polynomial));
                polynomial_slots.push_back(
                    {static_cast<int>(slot)});
            }
            for (poseidon::Polynomial &polynomial : polynomials)
            {
                polynomial.data().resize(maximum_degree + 1,
                                         {0.0, 0.0});
                polynomial.max_degree() =
                    static_cast<int>(maximum_degree);
            }

            poseidon::Plaintext encoded_multipliers;
            runtime.encoder.encode(
                multipliers, source.parms_id(),
                last_modulus_scale(source, runtime),
                encoded_multipliers);
            poseidon::Ciphertext normalized;
            runtime.evaluator->multiply_plain(
                source, encoded_multipliers, normalized);
            runtime.evaluator->rescale_dynamic(
                normalized, normalized, source.scale());
            poseidon::Plaintext encoded_offsets;
            runtime.encoder.encode(
                offsets, normalized.parms_id(), normalized.scale(),
                encoded_offsets);
            runtime.evaluator->add_plain(
                normalized, encoded_offsets, normalized);

            poseidon::PolynomialVector polynomial_vector(
                polynomials, polynomial_slots);
            output.push_back(evaluate_chebyshev_baby(
                normalized, polynomial_vector, runtime.encryptor,
                runtime.encoder, *runtime.evaluator,
                runtime.relin_keys, runtime.context));
        }
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

} // namespace

void ApproximationConfig::validate() const
{
    if (!std::isfinite(minimum) || !std::isfinite(maximum) ||
        minimum >= maximum || sample_count < 2)
    {
        throw std::invalid_argument("invalid Qwen polynomial approximation");
    }
}

ApproximationConfig first_layer_inverse_sqrt_config()
{
    return {1.0e-4, 5.0e-4, 16};
}

ApproximationConfig silu_config()
{
    return {-8.0, 8.0, 32};
}

poseidon::Polynomial
make_inverse_sqrt_polynomial(const ApproximationConfig &config)
{
    config.validate();
    if (config.minimum <= 0.0)
    {
        throw std::invalid_argument(
            "inverse square root interval must be positive");
    }
    return poseidon::util::approximate(
        inverse_sqrt_function, config.minimum, config.maximum,
        config.sample_count);
}

poseidon::Polynomial make_silu_polynomial(
    const ApproximationConfig &config)
{
    config.validate();
    return poseidon::util::approximate(
        silu_function, config.minimum, config.maximum,
        config.sample_count);
}

poseidon::Polynomial make_exp_polynomial(
    const ApproximationConfig &config)
{
    config.validate();
    return poseidon::util::approximate(
        exp_function, config.minimum, config.maximum,
        config.sample_count);
}

poseidon::Polynomial make_reciprocal_polynomial(
    const ApproximationConfig &config)
{
    config.validate();
    if (config.minimum <= 0.0)
    {
        throw std::invalid_argument(
            "reciprocal interval must be positive");
    }
    return poseidon::util::approximate(
        reciprocal_function, config.minimum, config.maximum,
        config.sample_count);
}

double evaluate_chebyshev_plain(
    double input, const poseidon::Polynomial &polynomial)
{
    if (polynomial.basis_type() != poseidon::Chebyshev ||
        polynomial.data().empty())
    {
        throw std::invalid_argument(
            "plain approximation expects a Chebyshev polynomial");
    }
    const double normalized =
        (2.0 * input - polynomial.a() - polynomial.b()) /
        (polynomial.b() - polynomial.a());
    double result = polynomial.data()[0].real();
    if (polynomial.data().size() == 1)
    {
        return result;
    }
    double previous = 1.0;
    double current = normalized;
    result += polynomial.data()[1].real() * current;
    for (std::size_t degree = 2; degree < polynomial.data().size();
         ++degree)
    {
        const double next = 2.0 * normalized * current - previous;
        result += polynomial.data()[degree].real() * next;
        previous = current;
        current = next;
    }
    return result;
}

Tensor approximate_silu_plain(const Tensor &input,
                              const ApproximationConfig &config)
{
    return approximate_silu_plain(input, config, {});
}

Tensor approximate_silu_plain(
    const Tensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides)
{
    return approximate_silu_plain(
        input, config, position_overrides, {}, {});
}

Tensor approximate_silu_plain(
    const Tensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::vector<ApproximationConfig> &feature_configs,
    const std::map<std::size_t, std::vector<ApproximationConfig>>
        &position_feature_overrides)
{
    if (input.rank() != 2)
    {
        throw std::invalid_argument(
            "position-aware SiLU expects a rank-2 tensor");
    }
    if (!feature_configs.empty() && feature_configs.size() != input.dim(1))
    {
        throw std::invalid_argument(
            "SiLU feature calibration does not match the tensor width");
    }
    Tensor output(input.shape());
    for (std::size_t token = 0; token < input.dim(0); ++token)
    {
        const auto override = position_overrides.find(token);
        const ApproximationConfig &token_config =
            override == position_overrides.end()
                ? config
                : override->second;
        const auto feature_override =
            position_feature_overrides.find(token);
        const std::vector<ApproximationConfig> *token_features =
            feature_override == position_feature_overrides.end()
                ? nullptr
                : &feature_override->second;
        if (token_features != nullptr &&
            token_features->size() != input.dim(1))
        {
            throw std::invalid_argument(
                "position SiLU feature calibration has the wrong width");
        }
        if (token_features == nullptr && feature_configs.empty())
        {
            const poseidon::Polynomial polynomial =
                make_silu_polynomial(token_config);
            for (std::size_t feature = 0; feature < input.dim(1);
                 ++feature)
            {
                output.at(token, feature) = evaluate_chebyshev_plain(
                    input.at(token, feature), polynomial);
            }
            continue;
        }
        for (std::size_t feature = 0; feature < input.dim(1);
             ++feature)
        {
            const ApproximationConfig &feature_config =
                token_features != nullptr
                    ? token_features->at(feature)
                    : (!feature_configs.empty()
                           ? feature_configs.at(feature)
                           : token_config);
            const poseidon::Polynomial polynomial =
                make_silu_polynomial(feature_config);
            output.at(token, feature) =
                evaluate_chebyshev_plain(
                    input.at(token, feature), polynomial);
        }
    }
    return output;
}

Tensor approximate_exp_plain(const Tensor &input,
                             const ApproximationConfig &config)
{
    const poseidon::Polynomial polynomial = make_exp_polynomial(config);
    Tensor output(input.shape());
    for (std::size_t index = 0; index < input.numel(); ++index)
    {
        output.data()[index] =
            evaluate_chebyshev_plain(input.data()[index], polynomial);
    }
    return output;
}

Tensor approximate_reciprocal_plain(
    const Tensor &input, const ApproximationConfig &config)
{
    const poseidon::Polynomial polynomial =
        make_reciprocal_polynomial(config);
    Tensor output(input.shape());
    for (std::size_t index = 0; index < input.numel(); ++index)
    {
        output.data()[index] =
            evaluate_chebyshev_plain(input.data()[index], polynomial);
    }
    return output;
}

Tensor approximate_rms_norm_plain(const Tensor &input, const Tensor &weight,
                                  double epsilon,
                                  const ApproximationConfig &config)
{
    return approximate_rms_norm_plain(
        input, weight, epsilon, config, {});
}

Tensor approximate_rms_norm_plain(
    const Tensor &input, const Tensor &weight, double epsilon,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides)
{
    if (input.rank() != 2 || weight.rank() != 1 ||
        input.dim(1) != weight.dim(0) || epsilon <= 0.0)
    {
        throw std::invalid_argument(
            "approximate RMSNorm received invalid shapes");
    }
    Tensor output(input.shape());
    for (std::size_t token = 0; token < input.dim(0); ++token)
    {
        const auto override = position_overrides.find(token);
        const ApproximationConfig &token_config =
            override == position_overrides.end()
                ? config
                : override->second;
        const poseidon::Polynomial polynomial =
            make_inverse_sqrt_polynomial(token_config);
        double square_sum = 0.0;
        for (std::size_t feature = 0; feature < input.dim(1); ++feature)
        {
            const double value = input.at(token, feature);
            square_sum += value * value;
        }
        const double variance =
            square_sum / static_cast<double>(input.dim(1)) + epsilon;
        const double inverse =
            evaluate_chebyshev_plain(variance, polynomial);
        for (std::size_t feature = 0; feature < input.dim(1); ++feature)
        {
            output.at(token, feature) =
                input.at(token, feature) * inverse * weight.at(feature);
        }
    }
    return output;
}

EncryptedTensor encrypted_silu(const EncryptedTensor &input,
                               const ApproximationConfig &config,
                               HeRuntime &runtime)
{
    return encrypted_silu(input, config, {}, runtime);
}

EncryptedTensor encrypted_silu(
    const EncryptedTensor &input,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides,
    HeRuntime &runtime)
{
    return encrypted_silu(
        input, config, position_overrides, {}, {}, runtime);
}

EncryptedTensor encrypted_silu(
    const EncryptedTensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::vector<ApproximationConfig> &feature_configs,
    const std::map<std::size_t, std::vector<ApproximationConfig>>
        &position_feature_overrides,
    HeRuntime &runtime)
{
    if (runtime.mock_silu())
    {
        Tensor plain = decrypt_tensor(input, runtime);
        for (double &value : plain.data())
        {
            value = silu_function(value);
        }
        return encrypt_tensor(plain, runtime);
    }
    if (!feature_configs.empty() || !position_feature_overrides.empty())
    {
        if (input.layout().tokens != input.layout().token_groups())
        {
            throw std::invalid_argument(
                "feature-calibrated SiLU requires one token per ciphertext");
        }
        return evaluate_feature_polynomial(
            input, config, position_overrides, feature_configs,
            position_feature_overrides, runtime);
    }
    if (input.layout().tokens != input.layout().token_groups())
    {
        return evaluate_position_polynomial(
            input, config, position_overrides, make_silu_polynomial,
            runtime);
    }
    std::vector<poseidon::Ciphertext> output;
    output.reserve(input.ciphertexts().size());
    for (std::size_t token = 0; token < input.layout().tokens;
         ++token)
    {
        const auto override = position_overrides.find(token);
        const ApproximationConfig &token_config =
            override == position_overrides.end()
                ? config
                : override->second;
        const poseidon::Polynomial polynomial =
            make_silu_polynomial(token_config);
        for (std::size_t chunk = 0;
             chunk < input.layout().feature_chunks(); ++chunk)
        {
            output.push_back(evaluate_polynomial(
                input.cipher(token, chunk), polynomial,
                token_config, runtime));
        }
    }
    return EncryptedTensor(input.layout(), std::move(output));
}

EncryptedTensor encrypted_exp(const EncryptedTensor &input,
                              const ApproximationConfig &config,
                              HeRuntime &runtime)
{
    if (runtime.mock_attention())
    {
        Tensor plain = decrypt_tensor(input, runtime);
        for (double &value : plain.data())
        {
            value = exp_function(value);
        }
        return encrypt_tensor(plain, runtime);
    }
    return evaluate_tensor_polynomial(
        input, make_exp_polynomial(config), config, runtime);
}

EncryptedTensor encrypted_reciprocal(
    const EncryptedTensor &input, const ApproximationConfig &config,
    HeRuntime &runtime)
{
    if (runtime.mock_attention())
    {
        Tensor plain = decrypt_tensor(input, runtime);
        for (double &value : plain.data())
        {
            value = reciprocal_function(value);
        }
        return encrypt_tensor(plain, runtime);
    }
    return evaluate_tensor_polynomial(
        input, make_reciprocal_polynomial(config), config, runtime);
}

EncryptedTensor encrypted_rms_norm(const EncryptedTensor &input,
                                   const Tensor &weight, double epsilon,
                                   const ApproximationConfig &config,
                                   HeRuntime &runtime)
{
    return encrypted_rms_norm(
        input, weight, epsilon, config, {}, runtime);
}

EncryptedTensor encrypted_rms_norm(
    const EncryptedTensor &input, const Tensor &weight, double epsilon,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides,
    HeRuntime &runtime)
{
    if (input.layout().feature_chunks() != 1 ||
        weight.rank() != 1 ||
        weight.dim(0) != input.layout().features || epsilon <= 0.0)
    {
        throw std::invalid_argument(
            "encrypted RMSNorm received invalid shapes");
    }

    if (runtime.mock_rms_norm())
    {
        return encrypt_tensor(
            exact_rms_norm_plain(decrypt_tensor(input, runtime), weight,
                                 epsilon),
            runtime);
    }

    // A packed ciphertext may contain fewer logical tokens than its slot
    // capacity (notably a one-token cached decode). Keep using the packed
    // reduction path in that case; the scalar path can otherwise consume the
    // final modulus before its first ciphertext square.
    if (input.layout().token_capacity() > 1)
    {
        const EncryptedTensor squared =
            encrypted_multiply(input, input, runtime);
        Tensor sum_weight(
            {input.layout().features, input.layout().features});
        std::fill(sum_weight.data().begin(), sum_weight.data().end(), 1.0);
        const EncodedLinear encoded_sum = encode_linear_at(
            sum_weight, squared.cipher(0, 0), runtime);
        const EncryptedTensor sums = encrypted_linear(
            squared, encoded_sum, nullptr, runtime);

        std::vector<poseidon::Ciphertext> variances;
        variances.reserve(sums.ciphertexts().size());
        for (const poseidon::Ciphertext &sum : sums.ciphertexts())
        {
            poseidon::Ciphertext variance;
            runtime.evaluator->multiply_const(
                sum, 1.0 / static_cast<double>(input.layout().features),
                last_modulus_scale(sum, runtime), variance,
                runtime.encoder);
            runtime.evaluator->rescale_dynamic(
                variance, variance, sum.scale());
            runtime.evaluator->add_const(
                variance, epsilon, variance, runtime.encoder);
            variances.push_back(std::move(variance));
        }
        const EncryptedTensor variance_tensor(
            input.layout(), std::move(variances));
        const EncryptedTensor inverse = evaluate_position_polynomial(
            variance_tensor, config, position_overrides,
            make_inverse_sqrt_polynomial, runtime);
        const EncryptedTensor normalized =
            encrypted_multiply(input, inverse, runtime);
        Tensor packed_weight(
            {input.layout().tokens, input.layout().features});
        for (std::size_t token = 0; token < input.layout().tokens; ++token)
        {
            for (std::size_t feature = 0;
                 feature < input.layout().features; ++feature)
            {
                packed_weight.at(token, feature) = weight.at(feature);
            }
        }
        return encrypted_multiply_plain(
            normalized, packed_weight, runtime);
    }

    std::vector<poseidon::Ciphertext> ciphertexts;
    ciphertexts.reserve(input.layout().tokens);
    for (std::size_t token = 0; token < input.layout().tokens; ++token)
    {
        const auto override = position_overrides.find(token);
        const ApproximationConfig &token_config =
            override == position_overrides.end()
                ? config
                : override->second;
        const poseidon::Polynomial inverse_sqrt =
            make_inverse_sqrt_polynomial(token_config);
        const poseidon::Ciphertext &source = input.cipher(token, 0);
        poseidon::Ciphertext squared = encrypted_multiply_ciphertexts(
            source, source, source.scale(), runtime);

        poseidon::Ciphertext sum =
            reduce_sum_slots(
                squared, input.layout().token_stride, runtime);
        poseidon::Ciphertext variance;
        runtime.evaluator->multiply_const(
            sum, 1.0 / static_cast<double>(input.layout().features),
            last_modulus_scale(sum, runtime), variance, runtime.encoder);
        runtime.evaluator->rescale_dynamic(
            variance, variance, sum.scale());
        runtime.evaluator->add_const(
            variance, epsilon, variance, runtime.encoder);

        poseidon::Ciphertext inverse = evaluate_polynomial(
            variance, inverse_sqrt, token_config, runtime);
        poseidon::Ciphertext normalized = encrypted_multiply_ciphertexts(
            source, inverse, inverse.scale(), runtime);

        std::vector<std::complex<double>> packed_weight(
            runtime.config().slot_count(), {0.0, 0.0});
        for (std::size_t index = 0; index < weight.dim(0); ++index)
        {
            packed_weight[index] = {weight.at(index), 0.0};
        }
        poseidon::Plaintext encoded_weight;
        runtime.encoder.encode(
            packed_weight, normalized.parms_id(),
            last_modulus_scale(normalized, runtime), encoded_weight);
        poseidon::Ciphertext output;
        runtime.evaluator->multiply_plain(
            normalized, encoded_weight, output);
        runtime.evaluator->rescale_dynamic(
            output, output, normalized.scale());
        ciphertexts.push_back(std::move(output));
    }
    return EncryptedTensor(input.layout(), std::move(ciphertexts));
}

} // namespace qwen::he
