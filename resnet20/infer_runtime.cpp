#include "infer_runtime.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/parameters_literal.h"

#include <stdexcept>
#include <utility>

using namespace poseidon;

PoseidonRuntime::PoseidonRuntime(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva,
                                 PublicKey pk, SecretKey sk, RelinKeys rk, GaloisKeys gk,
                                 std::unique_ptr<EvalModPoly> poly, double scale_value)
    : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
      public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
      galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
      bootstrap_poly(std::move(poly)), scale(scale_value),
      slot_count(static_cast<int>(encoder.slot_count()))
{
}

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan)
{
    ParametersLiteral ckks_param_literal{
        CKKS, static_cast<std::uint32_t>(plan.logN), static_cast<std::uint32_t>(plan.logN - 1),
        static_cast<std::uint32_t>(plan.log_scale), 5, 1, 0, {}, {}};
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

    auto bootstrap_poly = std::make_unique<EvalModPoly>(
        context, CosDiscrete, static_cast<std::uint64_t>(1) << 51, 1, 5, 2, 7, 0, 59);

    return PoseidonRuntime(std::move(context), std::move(evaluator), std::move(public_key),
                           keygen.secret_key(), std::move(relin_keys), std::move(galois_keys),
                           std::move(bootstrap_poly), ckks_param_literal.scale());
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
