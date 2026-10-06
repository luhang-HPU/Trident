#include "infer_config.h"
#include "chebyshev_relu.h"

#include <stdexcept>

namespace fs = std::filesystem;

fs::path resnet18_root()
{
    return fs::path(__FILE__).parent_path();
}

fs::path weights_root()
{
    return resnet18_root() / "pretrained_parameters";
}

fs::path data_root()
{
    return resnet18_root() / "testFile";
}

fs::path relu_param_root()
{
    return resnet18_root() / "relu_param";
}

fs::path result_dir()
{
    return resnet18_root() / "result";
}

std::vector<std::uint32_t> logq_chain(std::size_t compute_prime_count)
{
    if (compute_prime_count != kResNet18ComputePrimeCount &&
        compute_prime_count != kResNet18ChebyshevComputePrimeCount)
        throw std::invalid_argument("ResNet18 compute prime count must be 16 or 20");
    std::vector<std::uint32_t> chain;
    chain.reserve(1 + compute_prime_count + kResNet18BootstrapPrimeCount);
    chain.push_back(kResNet18BootstrapPrimeBits);
    chain.insert(chain.end(), compute_prime_count, kResNet18ComputePrimeBits);
    chain.insert(chain.end(), kResNet18BootstrapPrimeCount, kResNet18BootstrapPrimeBits);
    return chain;
}

std::vector<std::uint32_t> logp_chain(std::size_t q_count, std::size_t dnum)
{
    if (q_count == 0)
    {
        throw std::invalid_argument("ResNet18 Q modulus chain must not be empty");
    }
    if (dnum != 3 && dnum != 4)
    {
        throw std::invalid_argument("ResNet18 dnum must be 3 or 4");
    }

    // Poseidon's hybrid key switching uses dnum = ceil(|Q| / |P|).
    const std::size_t p_count = (q_count + dnum - 1) / dnum;
    return std::vector<std::uint32_t>(p_count, kResNet18SpecialPrimeBits);
}

PoseidonInferPlan default_poseidon_plan(std::size_t dnum, bool use_chebyshev,
                                      bool use_single22_bootstrap)
{
    if (use_single22_bootstrap && !use_chebyshev)
        throw std::invalid_argument("single22 bootstrap requires --relu=chebyshev471");
    PoseidonInferPlan plan;
    plan.use_single22_bootstrap = use_single22_bootstrap;
    plan.logN = 16;
    plan.log_slots = 15;
    plan.init_p = 8;
    plan.dnum = dnum;
    plan.compute_prime_count = use_chebyshev
        ? kResNet18ChebyshevComputePrimeCount : kResNet18ComputePrimeCount;
    plan.logq_chain = logq_chain(plan.compute_prime_count);
    // Validate dnum while building the plan, before the expensive runtime setup.
    (void)logp_chain(plan.logq_chain.size(), plan.dnum);
    return plan;
}

ReluConfig default_relu_config(const PoseidonInferPlan &plan, bool use_chebyshev)
{
    ReluConfig relu_config;
    relu_config.use_chebyshev = use_chebyshev;
    relu_config.use_single22_bootstrap = plan.use_single22_bootstrap;
    relu_config.scalingfactor = plan.log_scale;
    if (use_chebyshev)
    {
        // Prepare once before ciphertext timing; no external coefficient files.
        (void)chebyshev_relu_coefficients();
        return relu_config;
    }
    relu_config.comp_no = 3;
    relu_config.deg = {15, 15, 27};
    relu_config.alpha = 13;
    relu_config.scaled_val = 1.7;
    relu_config.tree.reserve(relu_config.deg.size());
    for (int degree : relu_config.deg)
    {
        Tree tr(EvalType::OddBaby);
        upgrade_oddbaby(degree, tr);
        relu_config.tree.emplace_back(std::move(tr));
    }
    return relu_config;
}

const char *relu_mode_name(const ReluConfig &config)
{
    return config.use_chebyshev ? "chebyshev471" : "composite";
}

double configured_relu_plain(double input, const ReluConfig &config)
{
    if (config.use_chebyshev)
        return chebyshev_relu_plain(input);
    return approximate_relu_plain(input, config.deg, config.alpha, config.tree, config.scaled_val);
}
