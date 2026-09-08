#include "he/he_runtime.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/parameters_literal.h"

#include <stdexcept>
#include <cmath>
#include <utility>

namespace qwen::he
{

HeRuntime::HeRuntime(HeConfig config, poseidon::PoseidonContext context_value,
                     std::unique_ptr<poseidon::EvaluatorCkksBase> evaluator_value,
                     poseidon::PublicKey public_key_value,
                     poseidon::SecretKey secret_key_value,
                     poseidon::RelinKeys relin_keys_value,
                     poseidon::GaloisKeys galois_keys_value)
    : context(std::move(context_value)), evaluator(std::move(evaluator_value)),
      encoder(context), public_key(std::move(public_key_value)),
      secret_key(std::move(secret_key_value)),
      relin_keys(std::move(relin_keys_value)),
      galois_keys(std::move(galois_keys_value)),
      encryptor(context, public_key), decryptor(context, secret_key),
      config_(std::move(config))
{
}

const HeConfig &HeRuntime::config() const
{
    return config_;
}

double HeRuntime::scale() const
{
    return static_cast<double>(std::uint64_t{1} << config_.log_scale);
}

void HeRuntime::set_bootstrap_value_scale(double value)
{
    if (!std::isfinite(value) || value <= 0.0)
    {
        throw std::invalid_argument(
            "Qwen HE bootstrap value scale must be finite and positive");
    }
    config_.bootstrap_value_scale = value;
}

bool HeRuntime::mock_nonlinear() const
{
    return mock_silu_ && mock_rms_norm_ && mock_attention_;
}

void HeRuntime::set_mock_nonlinear(bool value)
{
    mock_silu_ = value;
    mock_rms_norm_ = value;
    mock_attention_ = value;
}

bool HeRuntime::mock_silu() const
{
    return mock_silu_;
}

void HeRuntime::set_mock_silu(bool value)
{
    mock_silu_ = value;
}

bool HeRuntime::mock_rms_norm() const
{
    return mock_rms_norm_;
}

void HeRuntime::set_mock_rms_norm(bool value)
{
    mock_rms_norm_ = value;
}

bool HeRuntime::mock_attention() const
{
    return mock_attention_;
}

void HeRuntime::set_mock_attention(bool value)
{
    mock_attention_ = value;
}

bool HeRuntime::operation_logging() const
{
    return operation_logging_;
}

void HeRuntime::set_operation_logging(bool value)
{
    operation_logging_ = value;
}

const std::string &HeRuntime::operation_context() const
{
    return operation_context_;
}

void HeRuntime::set_operation_context(std::string value)
{
    operation_context_ = std::move(value);
}

std::size_t HeRuntime::chain_index(const poseidon::Ciphertext &cipher) const
{
    const auto data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!data)
    {
        throw std::runtime_error("Qwen HE ciphertext has an unknown parms_id");
    }
    return data->chain_index();
}

HeRuntime make_he_runtime(const HeConfig &config)
{
    config.validate();
    poseidon::ParametersLiteral parameters{
        CKKS, config.log_n, config.log_slots, config.log_scale,
        config.hamming_weight, config.q0_level, 0, {}, {},
        config.production_security ? poseidon::sec_level_type::tc128
                                   : poseidon::sec_level_type::none};
    parameters.set_log_modulus(config.log_q, config.log_p);

    poseidon::PoseidonFactory::get_instance()->set_device_type(
        poseidon::DEVICE_SOFTWARE);
    auto context =
        poseidon::PoseidonFactory::get_instance()->create_poseidon_context(parameters);
    auto evaluator =
        poseidon::PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    poseidon::KeyGenerator key_generator(context);
    poseidon::PublicKey public_key;
    key_generator.create_public_key(public_key);
    poseidon::RelinKeys relin_keys;
    key_generator.create_relin_keys(relin_keys);
    poseidon::GaloisKeys galois_keys;
    key_generator.create_galois_keys(galois_keys);

    return HeRuntime(config, std::move(context), std::move(evaluator),
                     std::move(public_key), key_generator.secret_key(),
                     std::move(relin_keys), std::move(galois_keys));
}

} // namespace qwen::he
