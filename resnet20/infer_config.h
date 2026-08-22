#pragma once

#include "relu_approx.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

constexpr std::size_t kResNet20LayerNum = 20;
constexpr int kResNet20EndNum = 2;
constexpr const char *kResNet20ParameterDir = "resnet20_new";
constexpr const char *kResNet20ResultPrefix = "resnet20_cifar10";
constexpr double kBatchNormEpsilon = 1.0e-5;
constexpr bool kEnableBootstrap = true;
constexpr bool kLogPlainIntermediate = false;

struct ReluConfig
{
    long comp_no = 0;
    std::vector<int> deg;
    long alpha = 0;
    std::vector<Tree> tree;
    double scaled_val = 0.0;
    long scalingfactor = 0;
};

struct PoseidonStagePlan
{
    const char *name = "";
    int out_channels = 0;
    int block_count = 0;
    int first_block_stride = 1;
};

struct PoseidonInferPlan
{
    double boundary = 40.0;
    long logN = 16;
    long log_slots = 15;
    long init_p = 8;
    int log_scale = 40;
    int q0_level = 0;
    int convolution_levels = 2;
    int relu_levels = 14;
    int remaining_level = 16;
    int boot_level = 14;
    std::vector<std::uint32_t> logq_chain;
    std::vector<PoseidonStagePlan> stages;
};

std::filesystem::path resnet20_root();
std::filesystem::path weights_root();
std::filesystem::path data_root();
std::filesystem::path relu_param_root();
std::filesystem::path result_dir();

std::vector<std::uint32_t> logq_chain();
PoseidonInferPlan default_poseidon_plan();
ReluConfig default_relu_config(const PoseidonInferPlan &plan);
