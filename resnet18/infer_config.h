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
constexpr double kBatchNormEpsilon = 1.0e-5;

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
    double boundary = 40.0;
    long logN = 16;
    long log_slots = 15;
    long init_p = 8;
    int log_scale = 46;
    int remaining_level = 16;
    int boot_level = 14;
    std::vector<std::uint32_t> logq_chain;
};

std::filesystem::path resnet18_root();
std::filesystem::path weights_root();
std::filesystem::path data_root();
std::filesystem::path relu_param_root();
std::filesystem::path result_dir();

std::vector<std::uint32_t> logq_chain();
PoseidonInferPlan default_poseidon_plan();
ReluConfig default_relu_config(const PoseidonInferPlan &plan);
