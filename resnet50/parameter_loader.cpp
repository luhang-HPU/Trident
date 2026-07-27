#include "parameter_loader.h"

#include "infer_config.h"

#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <stdexcept>
#include <string>

using namespace std;

namespace
{

constexpr int kStagePlanes[kResNet50StageCount] = {64, 128, 256, 512};
constexpr int kStageOutputChannels[kResNet50StageCount] = {256, 512, 1024, 2048};
constexpr int kBottleneckExpansion = 4;

vector<double> read_first_existing_exact_values(initializer_list<filesystem::path> candidates,
                                                size_t count)
{
    for (const auto &path : candidates)
    {
        if (filesystem::exists(path))
        {
            return read_exact_values(path, count);
        }
    }
    throw runtime_error("failed to find any candidate parameter file");
}

int stage_input_channels(int stage, int block)
{
    if (stage == 1 && block == 0)
    {
        return 64;
    }
    if (block == 0)
    {
        return kStageOutputChannels[stage - 2];
    }
    return kStageOutputChannels[stage - 1];
}

} // namespace

vector<double> read_exact_values(const filesystem::path &path, size_t count)
{
    ifstream input(path);
    if (!input.is_open())
    {
        throw runtime_error("failed to open file: " + path.string());
    }

    vector<double> values;
    values.reserve(count);
    double value = 0.0;
    for (size_t i = 0; i < count; ++i)
    {
        if (!(input >> value))
        {
            throw runtime_error("failed to read expected number of values from: " + path.string());
        }
        values.emplace_back(value);
    }
    return values;
}

vector<double> read_plain_image_values(size_t image_id, double boundary)
{
    ifstream input(data_root() / "test_values.txt");
    if (!input.is_open())
    {
        throw runtime_error("failed to open ImageNet test values");
    }

    double value = 0.0;
    const size_t image_values =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth * kImageNetInputChannels);
    for (size_t i = 0; i < image_values * image_id; ++i)
    {
        if (!(input >> value))
        {
            throw runtime_error("failed to skip ImageNet input values");
        }
    }

    vector<double> image(image_values, 0.0);
    for (size_t i = 0; i < image_values; ++i)
    {
        if (!(input >> value))
        {
            throw runtime_error("failed to read ImageNet input values");
        }
        image[i] = value / boundary;
    }
    return image;
}

vector<double> read_image_slots(size_t image_id, long log_slots, long init_p, double boundary)
{
    ifstream input(data_root() / "test_values.txt");
    if (!input.is_open())
    {
        throw runtime_error("failed to open ImageNet test values");
    }

    const long total_slots = 1L << log_slots;
    vector<double> image(static_cast<size_t>(total_slots), 0.0);

    double value = 0.0;
    const size_t image_values =
        static_cast<size_t>(kImageNetInputHeight * kImageNetInputWidth * kImageNetInputChannels);
    if (image_values > image.size())
    {
        throw runtime_error(
            "ImageNet input does not fit in one ciphertext; multi-cipher packing is required");
    }
    for (size_t i = 0; i < image_values * image_id; ++i)
    {
        if (!(input >> value))
        {
            throw runtime_error("failed to skip ImageNet input values");
        }
    }
    for (size_t i = 0; i < image_values; ++i)
    {
        if (!(input >> value))
        {
            throw runtime_error("failed to read ImageNet input values");
        }
        image[i] = value;
    }

    const long base_slots = total_slots / init_p;
    for (long i = base_slots; i < total_slots; ++i)
    {
        image[static_cast<size_t>(i)] = image[static_cast<size_t>(i % base_slots)];
    }
    for (double &slot : image)
    {
        slot /= boundary;
    }
    return image;
}

int read_image_label(size_t image_id)
{
    ifstream input(data_root() / "test_label.txt");
    if (!input.is_open())
    {
        throw runtime_error("failed to open ImageNet test labels");
    }

    int label = -1;
    for (size_t i = 0; i <= image_id; ++i)
    {
        if (!(input >> label))
        {
            throw runtime_error("failed to read ImageNet test label");
        }
    }
    return label;
}

ModelWeights load_resnet50_parameters()
{
    const filesystem::path root = weights_root() / kResNet50ParameterDir;
    ModelWeights weights;

    constexpr int kConvCount = 1 + 3 * (3 + 4 + 6 + 3);
    weights.conv_weight.assign(kConvCount, {});
    weights.bn_bias.assign(kConvCount, {});
    weights.bn_running_mean.assign(kConvCount, {});
    weights.bn_running_var.assign(kConvCount, {});
    weights.bn_weight.assign(kConvCount, {});
    weights.downsample_weight.assign(kResNet50StageCount, {});
    weights.downsample_bn_bias.assign(kResNet50StageCount, {});
    weights.downsample_bn_running_mean.assign(kResNet50StageCount, {});
    weights.downsample_bn_running_var.assign(kResNet50StageCount, {});
    weights.downsample_bn_weight.assign(kResNet50StageCount, {});

    size_t conv_index = 0;
    size_t bn_index = 0;
    weights.conv_weight[conv_index++] =
        read_exact_values(root / "conv1_weight.txt", 7 * 7 * 3 * 64);
    weights.bn_bias[bn_index] = read_exact_values(root / "bn1_bias.txt", 64);
    weights.bn_running_mean[bn_index] = read_exact_values(root / "bn1_running_mean.txt", 64);
    weights.bn_running_var[bn_index] = read_exact_values(root / "bn1_running_var.txt", 64);
    weights.bn_weight[bn_index] = read_exact_values(root / "bn1_weight.txt", 64);
    ++bn_index;

    for (int stage = 1; stage <= kResNet50StageCount; ++stage)
    {
        const int planes = kStagePlanes[stage - 1];
        const int out_channels = planes * kBottleneckExpansion;
        for (int block = 0; block < kResNet50BlocksPerStage[stage - 1]; ++block)
        {
            const int in_channels = stage_input_channels(stage, block);
            const string prefix = "layer" + to_string(stage) + "_" + to_string(block);

            weights.conv_weight[conv_index++] =
                read_exact_values(root / (prefix + "_conv1_weight.txt"), in_channels * planes);
            weights.conv_weight[conv_index++] =
                read_exact_values(root / (prefix + "_conv2_weight.txt"), 3 * 3 * planes * planes);
            weights.conv_weight[conv_index++] = read_exact_values(
                root / (prefix + "_conv3_weight.txt"), planes * out_channels);

            for (int bn = 1; bn <= 3; ++bn)
            {
                const int channels = (bn == 3) ? out_channels : planes;
                const string bn_prefix = prefix + "_bn" + to_string(bn);
                weights.bn_bias[bn_index] =
                    read_exact_values(root / (bn_prefix + "_bias.txt"), channels);
                weights.bn_running_mean[bn_index] =
                    read_exact_values(root / (bn_prefix + "_running_mean.txt"), channels);
                weights.bn_running_var[bn_index] =
                    read_exact_values(root / (bn_prefix + "_running_var.txt"), channels);
                weights.bn_weight[bn_index] =
                    read_exact_values(root / (bn_prefix + "_weight.txt"), channels);
                ++bn_index;
            }
        }

        const string ds_prefix = "layer" + to_string(stage) + "_0_downsample";
        const int ds_in_channels = (stage == 1) ? 64 : kStageOutputChannels[stage - 2];
        const int ds_out_channels = kStageOutputChannels[stage - 1];
        const size_t ds_index = static_cast<size_t>(stage - 1);
        weights.downsample_weight[ds_index] =
            read_exact_values(root / (ds_prefix + "_0_weight.txt"),
                              ds_in_channels * ds_out_channels);
        weights.downsample_bn_bias[ds_index] =
            read_exact_values(root / (ds_prefix + "_1_bias.txt"), ds_out_channels);
        weights.downsample_bn_running_mean[ds_index] =
            read_exact_values(root / (ds_prefix + "_1_running_mean.txt"), ds_out_channels);
        weights.downsample_bn_running_var[ds_index] =
            read_exact_values(root / (ds_prefix + "_1_running_var.txt"), ds_out_channels);
        weights.downsample_bn_weight[ds_index] =
            read_exact_values(root / (ds_prefix + "_1_weight.txt"), ds_out_channels);
    }

    weights.linear_weight = read_first_existing_exact_values(
        {root / "fc_weight.txt", root / "linear_weight.txt"},
        kImageNetClassCount * kResNet50FinalChannels);
    weights.linear_bias = read_first_existing_exact_values(
        {root / "fc_bias.txt", root / "linear_bias.txt"}, kImageNetClassCount);
    return weights;
}

