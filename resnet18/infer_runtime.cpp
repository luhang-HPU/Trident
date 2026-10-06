#include "infer_runtime.h"
#include "parallel_utils.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/parameters_literal.h"
#include "poseidon/advance/homomorphic_dft.h"

#include <cmath>
#include <set>
#include <stdexcept>
#include <utility>

using namespace poseidon;

namespace
{

void validate_bootstrap_modulus_chain(const PoseidonInferPlan &plan)
{
    if (plan.use_single22_bootstrap &&
        plan.compute_prime_count != kResNet18ChebyshevComputePrimeCount)
        throw std::invalid_argument("single22 bootstrap requires the 31-prime Q chain");
    if (plan.compute_prime_count != kResNet18ComputePrimeCount &&
        plan.compute_prime_count != kResNet18ChebyshevComputePrimeCount)
        throw std::invalid_argument("ResNet18 requires 16 or 20 compute primes");
    const std::size_t expected_size = 1 + plan.compute_prime_count +
                                      kResNet18BootstrapPrimeCount;
    if (plan.boot_level != static_cast<int>(kResNet18BootstrapPrimeCount))
    {
        throw std::invalid_argument("ResNet18 uses the 14-level bootstrap configuration");
    }
    if (plan.logq_chain.size() != expected_size)
    {
        throw std::invalid_argument(
            "ResNet18 modulus chain does not match the configured compute and bootstrap prime counts");
    }
    if (plan.logq_chain.front() != kResNet18BootstrapPrimeBits)
    {
        throw std::invalid_argument("ResNet18 bootstrap requires a 45-bit single-prime q0");
    }
    if (plan.log_scale != static_cast<int>(kResNet18ComputePrimeBits))
    {
        throw std::invalid_argument("ResNet18 CKKS scale must use 40 bits");
    }
    for (std::size_t i = 1; i <= plan.compute_prime_count; ++i)
    {
        if (plan.logq_chain.at(i) != kResNet18ComputePrimeBits)
        {
            throw std::invalid_argument("ResNet18 requires 40-bit compute primes");
        }
    }
    for (std::size_t i = 1 + plan.compute_prime_count;
         i < plan.logq_chain.size(); ++i)
    {
        if (plan.logq_chain.at(i) != kResNet18BootstrapPrimeBits)
        {
            throw std::invalid_argument(
                "ResNet18 bootstrap requires fourteen trailing 45-bit primes");
        }
    }

    const auto p_chain = logp_chain(plan.logq_chain.size(), plan.dnum);
    const std::size_t actual_dnum =
        (plan.logq_chain.size() + p_chain.size() - 1) / p_chain.size();
    if (actual_dnum != plan.dnum)
    {
        throw std::invalid_argument("ResNet18 modulus chains do not produce the requested dnum");
    }
}

} // namespace

PoseidonRuntime::PoseidonRuntime(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva,
                                 PublicKey pk, SecretKey sk, RelinKeys rk, GaloisKeys gk,
                                 BootstrapConfig config, double scale_value,
                                 bool use_single22_bootstrap)
    : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
      public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
      galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
      bootstrap_config(std::move(config)), scale(scale_value),
      slot_count(static_cast<int>(encoder.slot_count()))
{
    if (use_single22_bootstrap)
    {
        single22_poly = std::make_unique<EvalModPoly>(
            context, CosDiscrete, std::ldexp(1.0, 45), 1, 5, 3, 12, 0, 22);
        single22_poly->enable_full_cosine_coefficients();
    }
}

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan, bool generate_evaluation_keys)
{
    validate_bootstrap_modulus_chain(plan);
    ParametersLiteral ckks_param_literal{
        CKKS, static_cast<std::uint32_t>(plan.logN), static_cast<std::uint32_t>(plan.logN - 1),
        static_cast<std::uint32_t>(plan.log_scale), 5, kResNet18BootstrapQ0Level, 0, {}, {}};
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
    bootstrap_config.scaling_log = kResNet18BootstrapPrimeBits;
    bootstrap_config.output_scaling_log = static_cast<std::uint32_t>(plan.log_scale);
    bootstrap_config.output_ratio = 32;
    bootstrap_config.project_real = true;
    if (plan.use_single22_bootstrap)
    {
        bootstrap_config.boundary_k = 12;
        bootstrap_config.double_angle = 3;
    }

    return PoseidonRuntime(std::move(context), std::move(evaluator), std::move(public_key),
                           keygen.secret_key(), std::move(relin_keys), std::move(galois_keys),
                           std::move(bootstrap_config), ckks_param_literal.scale(),
                           plan.use_single22_bootstrap);
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

void trim_bootstrap_relu_input(std::vector<Ciphertext> &packs,
                               PoseidonRuntime &runtime, std::size_t target_level)
{
    // parms_id_map() returns a map BY VALUE. Never retain an iterator into the
    // temporary returned by that call. Own the map and copy the ID for workers.
    const auto parms_ids = runtime.context.crt_context()->parms_id_map();
    const auto target = parms_ids.find(target_level);
    if (target == parms_ids.end())
        throw std::invalid_argument("post-bootstrap ReLU target level is missing from context");
    const auto target_id = target->second;
    const auto target_data = runtime.context.crt_context()->get_context_data(target_id);
    if (!target_data || target_data->chain_index() != target_level)
        throw std::runtime_error("post-bootstrap ReLU target context level mismatch");

    // Reject an invalid batch before mutating any pack. The library drop API
    // itself does not guard against accidentally passing a higher-level ID.
    for (const auto &cipher : packs)
    {
        if (!cipher.is_valid() || cipher_chain_index(runtime, cipher) < target_level)
            throw std::invalid_argument("bootstrap output is below the configured ReLU input level");
        if (!std::isfinite(cipher.scale()) || cipher.scale() <= 0.0)
            throw std::invalid_argument("post-bootstrap ReLU input scale is invalid");
    }
    resnet18_parallel_for(packs.size(), [&, target_id](std::size_t index) {
        auto &cipher = packs.at(index);
        const double original_scale = cipher.scale();
        if (cipher_chain_index(runtime, cipher) > target_level)
            runtime.evaluator->drop_modulus(cipher, cipher, target_id);
        if (cipher.parms_id() != target_id ||
            cipher_chain_index(runtime, cipher) != target_level ||
            cipher.level() != target_level ||
            cipher.coeff_modulus_size() != target_data->coeff_modulus().size() ||
            cipher.scale() != original_scale)
            throw std::runtime_error("post-bootstrap ReLU modulus drop failed its level/scale check");
    });
}

std::vector<int> single22_bootstrap_rotation_steps(long log_n)
{
    if (log_n < 4 || log_n > 20)
        throw std::invalid_argument("invalid single22 rotation logN");
    const int slots = 1 << (log_n - 1);
    std::set<int> steps{0}; // conjugation
    for (int type : {0, 1})
    {
        // Same factorization and BSGS ratio as bootstrap_core. Scaling and the
        // nonzero slot-0 weight do not change the diagonal rotation indices.
        HomomorphicDFTMatrixLiteral literal(type, log_n, log_n - 1, 30,
                                             {1, 1, 1}, true, 1.0, false, 1);
        for (const auto &matrix : literal.gen_matrices())
        {
            const int n1 = find_best_bsgs_ratio(matrix, slots, 1);
            const auto indices = bsgs_index(matrix, slots, n1);
            for (int step : std::get<1>(indices)) steps.insert(step);
            for (int step : std::get<2>(indices)) steps.insert(step);
        }
    }
    return {steps.begin(), steps.end()};
}
