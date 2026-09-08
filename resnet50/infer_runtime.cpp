#include "infer_runtime.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/parameters_literal.h"

#include <stdexcept>
#include <utility>

using namespace poseidon;

namespace
{

void validate_bootstrap_modulus_chain(const PoseidonInferPlan &plan)
{
    const std::size_t expected_size = 1 + kResNet50ComputePrimeCount +
                                      kResNet50BootstrapPrimeCount;
    if (plan.remaining_level != 16)
    {
        throw std::invalid_argument("ResNet50 application level budget must be 16");
    }
    if (plan.boot_level != static_cast<int>(kResNet50BootstrapPrimeCount))
    {
        throw std::invalid_argument("ResNet50 uses the 14-level bootstrap configuration");
    }
    if (plan.logq_chain.size() != expected_size)
    {
        throw std::invalid_argument(
            "ResNet50 modulus chain must contain q0, twenty compute primes, and fourteen bootstrap primes");
    }
    if (plan.logq_chain.front() != kResNet50BootstrapPrimeBits)
    {
        throw std::invalid_argument("ResNet50 bootstrap requires a 45-bit single-prime q0");
    }
    if (plan.log_scale != static_cast<int>(kResNet50ComputePrimeBits))
    {
        throw std::invalid_argument("ResNet50 CKKS scale must use 40 bits");
    }
    for (std::size_t i = 1; i <= kResNet50ComputePrimeCount; ++i)
    {
        if (plan.logq_chain.at(i) != kResNet50ComputePrimeBits)
        {
            throw std::invalid_argument("ResNet50 requires twenty 40-bit compute primes");
        }
    }
    for (std::size_t i = 1 + kResNet50ComputePrimeCount;
         i < plan.logq_chain.size(); ++i)
    {
        if (plan.logq_chain.at(i) != kResNet50BootstrapPrimeBits)
        {
            throw std::invalid_argument(
                "ResNet50 bootstrap requires fourteen 45-bit primes at the top of the chain");
        }
    }

    const auto p_chain = logp_chain(plan.logq_chain.size(), plan.dnum);
    const std::size_t actual_dnum =
        (plan.logq_chain.size() + p_chain.size() - 1) / p_chain.size();
    if (actual_dnum != plan.dnum)
    {
        throw std::invalid_argument("ResNet50 modulus chains do not produce the requested dnum");
    }
}

} // namespace

PoseidonRuntime::PoseidonRuntime(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva,
                                 PublicKey pk, SecretKey sk, RelinKeys rk, GaloisKeys gk,
                                 BootstrapConfig config, double scale_value)
    : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
      public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
      galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
      bootstrap_config(std::move(config)), scale(scale_value),
      slot_count(static_cast<int>(encoder.slot_count()))
{
}

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan, bool generate_evaluation_keys)
{
    validate_bootstrap_modulus_chain(plan);
    ParametersLiteral ckks_param_literal{
        CKKS, static_cast<std::uint32_t>(plan.logN), static_cast<std::uint32_t>(plan.logN - 1),
        static_cast<std::uint32_t>(plan.log_scale), 5, kResNet50BootstrapQ0Level, 0, {}, {}};
    ckks_param_literal.set_log_modulus(
        plan.logq_chain, logp_chain(plan.logq_chain.size(), plan.dnum));

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    if (generate_evaluation_keys)
    {
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(galois_keys);
    }

    BootstrapConfig bootstrap_config;
    bootstrap_config.boundary_k = 25;
    bootstrap_config.log_message_ratio = 5;
    bootstrap_config.double_angle = 2;
    bootstrap_config.scaling_log = kResNet50BootstrapPrimeBits;
    bootstrap_config.output_scaling_log = static_cast<std::uint32_t>(plan.log_scale);
    bootstrap_config.output_ratio = 32;
    bootstrap_config.project_real = true;

    return PoseidonRuntime(std::move(context), std::move(evaluator), std::move(public_key),
                           keygen.secret_key(), std::move(relin_keys), std::move(galois_keys),
                           std::move(bootstrap_config), ckks_param_literal.scale());
}

std::size_t cipher_chain_index(const PoseidonRuntime &runtime, const Ciphertext &cipher)
{
    auto context_data = runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}
