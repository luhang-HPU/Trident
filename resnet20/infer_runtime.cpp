#include "infer_runtime.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/parameters_literal.h"

#include <stdexcept>
#include <utility>

using namespace poseidon;

PoseidonRuntime::PoseidonRuntime(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva,
                                 PublicKey pk, SecretKey sk, RelinKeys rk, GaloisKeys gk,
                                 BootstrapConfig bootstrap, double scale_value)
    : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
      public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
      galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
      bootstrap_config(std::move(bootstrap)), scale(scale_value),
      slot_count(static_cast<int>(encoder.slot_count()))
{
}

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan)
{
    if (plan.remaining_level != plan.convolution_levels + plan.relu_levels)
    {
        throw std::invalid_argument(
            "application level budget must equal convolution plus ReLU levels");
    }
    const std::size_t expected_q_count =
        static_cast<std::size_t>(plan.q0_level + 1 + plan.remaining_level +
                                 plan.boot_level);
    if (plan.logq_chain.size() != expected_q_count)
    {
        throw std::invalid_argument(
            "Q chain must contain q0, application, and bootstrap level budgets");
    }
    ParametersLiteral ckks_param_literal{
        CKKS, static_cast<std::uint32_t>(plan.logN), static_cast<std::uint32_t>(plan.logN - 1),
        static_cast<std::uint32_t>(plan.log_scale), 5,
        static_cast<std::uint32_t>(plan.q0_level), 0, {}, {}};
    ckks_param_literal.set_log_modulus(plan.logq_chain, {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    BootstrapConfig bootstrap_config;
    bootstrap_config.boundary_k = 25;
    bootstrap_config.log_message_ratio = 5;
    bootstrap_config.double_angle = 2;
    bootstrap_config.scaling_log = 45;
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
