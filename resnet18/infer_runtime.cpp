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
    const std::size_t expected_size = 1 + kResNet18ComputePrimeCount +
                                      kResNet18BootstrapPrimeCount;
    if (plan.boot_level != static_cast<int>(kResNet18BootstrapPrimeCount))
    {
        throw std::invalid_argument("ResNet18 uses the 14-level bootstrap configuration");
    }
    if (plan.logq_chain.size() != expected_size)
    {
        throw std::invalid_argument(
            "ResNet18 modulus chain must contain q0, twenty compute primes, and fourteen bootstrap primes");
    }
    if (plan.logq_chain.front() != kResNet18BootstrapPrimeBits)
    {
        throw std::invalid_argument("ResNet18 bootstrap requires a 51-bit single-prime q0");
    }
    if (plan.log_scale != static_cast<int>(kResNet18ComputePrimeBits))
    {
        throw std::invalid_argument("ResNet18 CKKS scale must use 46 bits");
    }
    for (std::size_t i = 1; i <= kResNet18ComputePrimeCount; ++i)
    {
        if (plan.logq_chain.at(i) != kResNet18ComputePrimeBits)
        {
            throw std::invalid_argument("ResNet18 requires twenty 46-bit compute primes");
        }
    }
    for (std::size_t i = 1 + kResNet18ComputePrimeCount;
         i < plan.logq_chain.size(); ++i)
    {
        if (plan.logq_chain.at(i) != kResNet18BootstrapPrimeBits)
        {
            throw std::invalid_argument(
                "ResNet18 bootstrap requires fourteen trailing 51-bit primes");
        }
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
        static_cast<std::uint32_t>(plan.log_scale), 5, kResNet18BootstrapQ0Level, 0, {}, {}};
    ckks_param_literal.set_log_modulus(plan.logq_chain, logp_chain());

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
