#include "infer_config.h"

#include <stdexcept>

namespace fs = std::filesystem;

fs::path resnet50_root()
{
    return fs::path(__FILE__).parent_path();
}

fs::path weights_root()
{
    return resnet50_root() / "pretrained_parameters";
}

fs::path data_root()
{
    return resnet50_root() / "testFile";
}

fs::path relu_param_root()
{
    const fs::path local = resnet50_root() / "relu_param";
    if (fs::exists(local))
    {
        return local;
    }
    return resnet50_root().parent_path() / "resnet18" / "relu_param";
}

fs::path result_dir()
{
    return resnet50_root() / "result";
}

std::vector<std::uint32_t> logq_chain()
{
    return {
        51,
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51,
    };
}

std::vector<std::uint32_t> logp_chain(std::size_t q_count, std::size_t dnum)
{
    if (dnum != 3 && dnum != 4)
    {
        throw std::invalid_argument("ResNet50 dnum must be 3 or 4");
    }
    if (q_count == 0)
    {
        throw std::invalid_argument("ResNet50 Q modulus chain must not be empty");
    }

    // Poseidon's hybrid key switching uses dnum = ceil(|Q| / |P|).
    const std::size_t p_count = (q_count + dnum - 1) / dnum;
    return std::vector<std::uint32_t>(p_count, kResNet50BootstrapPrimeBits);
}

PoseidonInferPlan default_poseidon_plan(std::size_t dnum)
{
    PoseidonInferPlan plan;
    plan.logN = 16;
    plan.log_slots = 15;
    plan.init_p = 8;
    plan.dnum = dnum;
    plan.logq_chain = logq_chain();
    (void)logp_chain(plan.logq_chain.size(), plan.dnum);
    return plan;
}

ReluConfig default_relu_config(const PoseidonInferPlan &plan)
{
    ReluConfig relu_config;
    relu_config.comp_no = 3;
    relu_config.deg = {15, 15, 27};
    relu_config.alpha = 13;
    relu_config.scaled_val = 1.7;
    relu_config.scalingfactor = plan.log_scale;
    relu_config.tree.reserve(relu_config.deg.size());
    for (int degree : relu_config.deg)
    {
        Tree tr(EvalType::OddBaby);
        upgrade_oddbaby(degree, tr);
        relu_config.tree.emplace_back(std::move(tr));
    }
    return relu_config;
}
