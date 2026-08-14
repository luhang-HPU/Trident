#pragma once

#include "relu_approx.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

constexpr std::size_t kResNet18LayerNum = 18;
constexpr int kResNet18BlocksPerStage = 2;
constexpr int kImageNetInputHeight = 224;
constexpr int kImageNetInputWidth = 224;
constexpr int kImageNetInputChannels = 3;
constexpr int kImageNetClassCount = 1000;
constexpr int kResNet18FinalChannels = 512;
constexpr const char *kResNet18ParameterDir = "resnet18_imagenet";
constexpr const char *kResNet18ResultPrefix = "resnet18_imagenet";
constexpr double kResNet18Boundary = 20.0;
constexpr double kBatchNormEpsilon = 1.0e-5;
constexpr bool kEnableHomomorphicRelu = true;
constexpr bool kBootstrapBeforeReluExceptFirst = true;
constexpr std::uint32_t kResNet18BootstrapQ0Level = 0;
constexpr std::uint32_t kResNet18BootstrapPrimeBits = 51;
constexpr std::uint32_t kResNet18ComputePrimeBits = 46;
constexpr std::size_t kResNet18ComputePrimeCount = 20;
constexpr std::size_t kResNet18BootstrapPrimeCount = 14;

struct ReluConfig
{
    long comp_no = 0;
    std::vector<int> deg;
    long alpha = 0;
    std::vector<Tree> tree;
    double scaled_val = 0.0;
    long scalingfactor = 0;
};

struct PoseidonInferPlan
{
    double boundary = kResNet18Boundary;
    long logN = 16;
    long log_slots = 15;
    long init_p = 8;
    int log_scale = static_cast<int>(kResNet18ComputePrimeBits);
    int boot_level = static_cast<int>(kResNet18BootstrapPrimeCount);
    std::size_t dnum = 3;
    std::vector<std::uint32_t> logq_chain;
};

std::filesystem::path resnet18_root();
std::filesystem::path weights_root();
std::filesystem::path data_root();
std::filesystem::path relu_param_root();
std::filesystem::path result_dir();

std::vector<std::uint32_t> logq_chain();
std::vector<std::uint32_t> logp_chain(std::size_t q_count, std::size_t dnum);
PoseidonInferPlan default_poseidon_plan(std::size_t dnum = 3);
ReluConfig default_relu_config(const PoseidonInferPlan &plan);
