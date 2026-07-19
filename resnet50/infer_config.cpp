#include "infer_config.h"

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
    const fs::path local = resnet18_root() / "testFile";
    if (fs::exists(local))
    {
        return local;
    }
    return resnet18_root().parent_path() / "resnet18" / "testFile";
}

fs::path relu_param_root()
{
    const fs::path local = resnet18_root() / "relu_param";
    if (fs::exists(local))
    {
        return local;
    }
    return resnet18_root().parent_path() / "resnet18" / "relu_param";
}

fs::path result_dir()
{
    return resnet18_root() / "result";
}

std::vector<std::uint32_t> logq_chain()
{
    return {
        51,
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        46, 46, 46, 46, 46, 46, 46, 46, 
        51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51,
    };
}

std::vector<std::uint32_t> logp_chain()
{
    return {51};
}

PoseidonInferPlan default_poseidon_plan()
{
    PoseidonInferPlan plan;
    plan.logN = 16;
    plan.log_slots = 15;
    plan.init_p = 8;
    plan.logq_chain = logq_chain();
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
