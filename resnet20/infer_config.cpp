#include "infer_config.h"

namespace fs = std::filesystem;

fs::path resnet20_root()
{
    return fs::path(__FILE__).parent_path();
}

fs::path weights_root()
{
    return resnet20_root() / "pretrained_parameters";
}

fs::path data_root()
{
    return resnet20_root() / "testFile";
}

fs::path relu_param_root()
{
    return resnet20_root() / "relu_param";
}

fs::path result_dir()
{
    return resnet20_root() / "result";
}

std::vector<std::uint32_t> logq_chain()
{
    return {
        46, 46, 46, 46, 46, 46, 46, 46, 46,
        46, 46, 46, 46, 46, 46, 46, 46, 46, 51, 51, 51, 51, 51, 51, 51,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51};
}

PoseidonInferPlan default_poseidon_plan()
{
    PoseidonInferPlan plan;
    plan.logq_chain = logq_chain();
    plan.stages = {
        {"stage1", 16, 3, 1},
        {"stage2", 32, 3, 2},
        {"stage3", 64, 3, 2},
    };
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
