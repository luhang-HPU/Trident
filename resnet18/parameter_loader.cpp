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

ModelWeights load_resnet18_parameters()
{
    ModelWeights weights;
    import_resnet18_parameters(weights.linear_weight, weights.linear_bias, weights.conv_weight,
                               weights.bn_bias, weights.bn_running_mean,
                               weights.bn_running_var, weights.bn_weight,
                               weights.downsample_weight, weights.downsample_bn_bias,
                               weights.downsample_bn_running_mean,
                               weights.downsample_bn_running_var,
                               weights.downsample_bn_weight);
    return weights;
}

void import_resnet18_parameters(vector<double> &linear_weight, vector<double> &linear_bias,
                                vector<vector<double>> &conv_weight,
                                vector<vector<double>> &bn_bias,
                                vector<vector<double>> &bn_running_mean,
                                vector<vector<double>> &bn_running_var,
                                vector<vector<double>> &bn_weight,
                                vector<vector<double>> &downsample_weight,
                                vector<vector<double>> &downsample_bn_bias,
                                vector<vector<double>> &downsample_bn_running_mean,
                                vector<vector<double>> &downsample_bn_running_var,
                                vector<vector<double>> &downsample_bn_weight)
{
    const filesystem::path root = weights_root() / kResNet18ParameterDir;
    const int stage_channels[] = {64, 128, 256, 512};

    size_t num_c = 0;
    size_t num_b = 0;
    size_t num_m = 0;
    size_t num_v = 0;
    size_t num_w = 0;
    size_t num_ds = 0;

    conv_weight.assign(1 + 4 * kResNet18BlocksPerStage * 2, {});
    bn_bias.assign(1 + 4 * kResNet18BlocksPerStage * 2, {});
    bn_running_mean.assign(1 + 4 * kResNet18BlocksPerStage * 2, {});
    bn_running_var.assign(1 + 4 * kResNet18BlocksPerStage * 2, {});
    bn_weight.assign(1 + 4 * kResNet18BlocksPerStage * 2, {});
    downsample_weight.assign(3, {});
    downsample_bn_bias.assign(3, {});
    downsample_bn_running_mean.assign(3, {});
    downsample_bn_running_var.assign(3, {});
    downsample_bn_weight.assign(3, {});

    conv_weight[num_c++] = read_exact_values(root / "conv1_weight.txt", 7 * 7 * 3 * 64);

    for (int stage = 1; stage <= 4; ++stage)
    {
        const int co = stage_channels[stage - 1];
        for (int block = 0; block < kResNet18BlocksPerStage; ++block)
        {
            const int conv1_ci = (block == 0 && stage > 1) ? stage_channels[stage - 2] : co;
            const string prefix = "layer" + to_string(stage) + "_" + to_string(block);
            conv_weight[num_c++] =
                read_exact_values(root / (prefix + "_conv1_weight.txt"), 3 * 3 * conv1_ci * co);
            conv_weight[num_c++] =
                read_exact_values(root / (prefix + "_conv2_weight.txt"), 3 * 3 * co * co);
        }
    }

    bn_bias[num_b++] = read_exact_values(root / "bn1_bias.txt", 64);
    bn_running_mean[num_m++] = read_exact_values(root / "bn1_running_mean.txt", 64);
    bn_running_var[num_v++] = read_exact_values(root / "bn1_running_var.txt", 64);
    bn_weight[num_w++] = read_exact_values(root / "bn1_weight.txt", 64);

    for (int stage = 1; stage <= 4; ++stage)
    {
        const int channels = stage_channels[stage - 1];
        for (int block = 0; block < kResNet18BlocksPerStage; ++block)
        {
            const string prefix = "layer" + to_string(stage) + "_" + to_string(block);
            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn1_bias.txt"), channels);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn1_running_mean.txt"), channels);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn1_running_var.txt"), channels);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn1_weight.txt"), channels);

            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn2_bias.txt"), channels);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn2_running_mean.txt"), channels);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn2_running_var.txt"), channels);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn2_weight.txt"), channels);
        }

        if (stage > 1)
        {
            const string prefix = "layer" + to_string(stage) + "_0_downsample";
            const int ds_ci = stage_channels[stage - 2];
            const int ds_co = stage_channels[stage - 1];
            downsample_weight[num_ds] =
                read_exact_values(root / (prefix + "_0_weight.txt"), ds_ci * ds_co);
            downsample_bn_bias[num_ds] =
                read_exact_values(root / (prefix + "_1_bias.txt"), ds_co);
            downsample_bn_running_mean[num_ds] =
                read_exact_values(root / (prefix + "_1_running_mean.txt"), ds_co);
            downsample_bn_running_var[num_ds] =
                read_exact_values(root / (prefix + "_1_running_var.txt"), ds_co);
            downsample_bn_weight[num_ds] =
                read_exact_values(root / (prefix + "_1_weight.txt"), ds_co);
            ++num_ds;
        }
    }

    linear_weight = read_first_existing_exact_values(
        {root / "fc_weight.txt", root / "linear_weight.txt"},
        kImageNetClassCount * kResNet18FinalChannels);
    linear_bias = read_first_existing_exact_values(
        {root / "fc_bias.txt", root / "linear_bias.txt"}, kImageNetClassCount);
}
