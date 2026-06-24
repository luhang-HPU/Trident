#include "parameter_loader.h"

#include "infer_config.h"

#include <fstream>
#include <stdexcept>
#include <string>

using namespace std;

std::vector<double> read_exact_values(const std::filesystem::path &path, std::size_t count)
{
    ifstream input(path);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open file: " + path.string());
    }

    vector<double> values;
    values.reserve(count);
    double value = 0.0;
    for (size_t i = 0; i < count; ++i)
    {
        if (!(input >> value))
        {
            throw std::runtime_error("failed to read expected number of values from: " + path.string());
        }
        values.emplace_back(value);
    }
    return values;
}

std::vector<double> read_image_slots(std::size_t image_id, long log_slots, long init_p,
                                     double boundary)
{
    ifstream input(data_root() / "test_values.txt");
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open CIFAR-10 test values");
    }

    const long total_slots = 1L << log_slots;
    vector<double> image(static_cast<size_t>(total_slots), 0.0);

    double value = 0.0;
    const size_t image_values = 32 * 32 * 3;
    for (size_t i = 0; i < image_values * image_id; ++i)
    {
        input >> value;
    }
    for (size_t i = 0; i < image_values; ++i)
    {
        input >> value;
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

int read_image_label(std::size_t image_id)
{
    ifstream input(data_root() / "test_label.txt");
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open CIFAR-10 test labels");
    }

    int label = -1;
    for (size_t i = 0; i <= image_id; ++i)
    {
        if (!(input >> label))
        {
            throw std::runtime_error("failed to read CIFAR-10 test label");
        }
    }
    return label;
}

ModelWeights load_resnet20_parameters()
{
    ModelWeights weights;
    import_resnet20_parameters(weights.linear_weight, weights.linear_bias, weights.conv_weight,
                               weights.bn_bias, weights.bn_running_mean,
                               weights.bn_running_var, weights.bn_weight);
    return weights;
}

void import_resnet20_parameters(vector<double> &linear_weight, vector<double> &linear_bias,
                                vector<vector<double>> &conv_weight,
                                vector<vector<double>> &bn_bias,
                                vector<vector<double>> &bn_running_mean,
                                vector<vector<double>> &bn_running_var,
                                vector<vector<double>> &bn_weight)
{
    const std::filesystem::path root = weights_root() / kResNet20ParameterDir;

    size_t num_c = 0;
    size_t num_b = 0;
    size_t num_m = 0;
    size_t num_v = 0;
    size_t num_w = 0;

    conv_weight.clear();
    conv_weight.resize(kResNet20LayerNum - 1);
    bn_bias.clear();
    bn_bias.resize(kResNet20LayerNum - 1);
    bn_running_mean.clear();
    bn_running_mean.resize(kResNet20LayerNum - 1);
    bn_running_var.clear();
    bn_running_var.resize(kResNet20LayerNum - 1);
    bn_weight.clear();
    bn_weight.resize(kResNet20LayerNum - 1);

    const int fh = 3;
    const int fw = 3;
    int ci = 3;
    int co = 16;

    conv_weight[num_c++] = read_exact_values(root / "conv1_weight.txt", fh * fw * ci * co);

    for (int stage = 1; stage <= 3; ++stage)
    {
        for (int block = 0; block <= kResNet20EndNum; ++block)
        {
            if (stage == 1)
            {
                co = 16;
            }
            else if (stage == 2)
            {
                co = 32;
            }
            else
            {
                co = 64;
            }

            if (stage == 1 || (stage == 2 && block == 0))
            {
                ci = 16;
            }
            else if ((stage == 2 && block != 0) || (stage == 3 && block == 0))
            {
                ci = 32;
            }
            else
            {
                ci = 64;
            }

            conv_weight[num_c++] = read_exact_values(
                root / ("layer" + to_string(stage) + "_" + to_string(block) + "_conv1_weight.txt"),
                fh * fw * ci * co);

            if (stage == 1)
            {
                ci = 16;
            }
            else if (stage == 2)
            {
                ci = 32;
            }
            else
            {
                ci = 64;
            }

            conv_weight[num_c++] = read_exact_values(
                root / ("layer" + to_string(stage) + "_" + to_string(block) + "_conv2_weight.txt"),
                fh * fw * ci * co);
        }
    }

    ci = 16;
    bn_bias[num_b++] = read_exact_values(root / "bn1_bias.txt", ci);
    bn_running_mean[num_m++] = read_exact_values(root / "bn1_running_mean.txt", ci);
    bn_running_var[num_v++] = read_exact_values(root / "bn1_running_var.txt", ci);
    bn_weight[num_w++] = read_exact_values(root / "bn1_weight.txt", ci);

    for (int stage = 1; stage <= 3; ++stage)
    {
        if (stage == 1)
        {
            ci = 16;
        }
        else if (stage == 2)
        {
            ci = 32;
        }
        else
        {
            ci = 64;
        }

        for (int block = 0; block <= kResNet20EndNum; ++block)
        {
            const string prefix = "layer" + to_string(stage) + "_" + to_string(block);
            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn1_bias.txt"), ci);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn1_running_mean.txt"), ci);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn1_running_var.txt"), ci);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn1_weight.txt"), ci);

            bn_bias[num_b++] = read_exact_values(root / (prefix + "_bn2_bias.txt"), ci);
            bn_running_mean[num_m++] =
                read_exact_values(root / (prefix + "_bn2_running_mean.txt"), ci);
            bn_running_var[num_v++] =
                read_exact_values(root / (prefix + "_bn2_running_var.txt"), ci);
            bn_weight[num_w++] = read_exact_values(root / (prefix + "_bn2_weight.txt"), ci);
        }
    }

    linear_weight = read_exact_values(root / "linear_weight.txt", 10 * 64);
    linear_bias = read_exact_values(root / "linear_bias.txt", 10);
}
