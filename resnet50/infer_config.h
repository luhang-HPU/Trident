#pragma once

#include "relu_approx.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

constexpr std::size_t kResNet50LayerNum = 50;
constexpr int kResNet50StageCount = 4;
constexpr int kResNet50BlocksPerStage[kResNet50StageCount] = {3, 4, 6, 3};
constexpr int kImageNetInputHeight = 224;
constexpr int kImageNetInputWidth = 224;
constexpr int kImageNetInputChannels = 3;
constexpr int kImageNetClassCount = 1000;
constexpr int kResNet50FinalChannels = 2048;
constexpr const char *kResNet50ParameterDir = "resnet50_imagenet";
constexpr const char *kResNet50ResultPrefix = "resnet50_imagenet";
constexpr double kResNet50Boundary = 120.0;
constexpr double kResNet18Boundary = kResNet50Boundary;
constexpr double kBatchNormEpsilon = 1.0e-5;
constexpr bool kEnableHomomorphicRelu = true;
constexpr bool kBootstrapBeforeReluExceptFirst = true;
constexpr std::uint32_t kResNet50BootstrapQ0Level = 0;
constexpr std::uint32_t kResNet50BootstrapPrimeBits = 45;
constexpr std::uint32_t kResNet50ComputePrimeBits = 40;
constexpr std::uint32_t kResNet50SpecialPrimeBits = 51;
constexpr std::size_t kResNet50ComputePrimeCount = 20;
constexpr std::size_t kResNet50BootstrapPrimeCount = 14;

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
    double boundary = kResNet50Boundary;
    long logN = 16;
    long log_slots = 15;
    long init_p = 8;
    int log_scale = static_cast<int>(kResNet50ComputePrimeBits);
    int remaining_level = 16;
    int boot_level = static_cast<int>(kResNet50BootstrapPrimeCount);
    std::size_t dnum = 3;
    std::vector<std::uint32_t> logq_chain;
};

std::filesystem::path resnet50_root();
std::filesystem::path weights_root();
std::filesystem::path data_root();
std::filesystem::path relu_param_root();
std::filesystem::path result_dir();

std::vector<std::uint32_t> logq_chain();
std::vector<std::uint32_t> logp_chain(std::size_t q_count, std::size_t dnum);
PoseidonInferPlan default_poseidon_plan(std::size_t dnum = 3);
ReluConfig default_relu_config(const PoseidonInferPlan &plan);
