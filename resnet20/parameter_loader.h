#pragma once

#include <cstddef>
#include <filesystem>
#include <vector>

struct ModelWeights
{
    std::vector<double> linear_weight;
    std::vector<double> linear_bias;
    std::vector<std::vector<double>> conv_weight;
    std::vector<std::vector<double>> bn_bias;
    std::vector<std::vector<double>> bn_running_mean;
    std::vector<std::vector<double>> bn_running_var;
    std::vector<std::vector<double>> bn_weight;
};

std::vector<double> read_exact_values(const std::filesystem::path &path, std::size_t count);
std::vector<double> read_image_slots(std::size_t image_id, long log_slots, long init_p,
                                     double boundary);
int read_image_label(std::size_t image_id);

ModelWeights load_resnet20_parameters();

void import_resnet20_parameters(std::vector<double> &linear_weight,
                                std::vector<double> &linear_bias,
                                std::vector<std::vector<double>> &conv_weight,
                                std::vector<std::vector<double>> &bn_bias,
                                std::vector<std::vector<double>> &bn_running_mean,
                                std::vector<std::vector<double>> &bn_running_var,
                                std::vector<std::vector<double>> &bn_weight);
