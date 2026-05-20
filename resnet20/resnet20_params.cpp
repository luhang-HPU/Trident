#include "resnet20_params.h"

#include "poseidon/util/json.h"

#include <cmath>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace ResNet20
{

namespace
{

using json = nlohmann::json;

double deterministic_weight(size_t index, double scale)
{
    const int bucket = static_cast<int>((index * 37 + 11) % 23) - 11;
    return static_cast<double>(bucket) * scale;
}

Conv2dWeights make_conv(size_t in_channels, size_t out_channels, size_t kernel,
                        size_t stride, size_t padding, size_t salt)
{
    Conv2dWeights conv;
    conv.in_channels = in_channels;
    conv.out_channels = out_channels;
    conv.kernel_h = kernel;
    conv.kernel_w = kernel;
    conv.stride = stride;
    conv.padding = padding;
    conv.weights.resize(out_channels * in_channels * kernel * kernel);
    conv.bias.resize(out_channels);

    const double scale = kernel == 1 ? 0.004 : 0.002;
    for (size_t i = 0; i < conv.weights.size(); ++i)
    {
        conv.weights[i] = deterministic_weight(i + salt, scale);
    }
    for (size_t i = 0; i < conv.bias.size(); ++i)
    {
        conv.bias[i] = deterministic_weight(i + salt * 3, 0.001);
    }
    return conv;
}

ResidualBlockWeights make_block(size_t in_channels, size_t out_channels, size_t stride,
                                size_t salt)
{
    ResidualBlockWeights block;
    block.conv1 = make_conv(in_channels, out_channels, 3, stride, 1, salt);
    block.conv2 = make_conv(out_channels, out_channels, 3, 1, 1, salt + 101);
    block.has_shortcut = in_channels != out_channels || stride != 1;
    if (block.has_shortcut)
    {
        block.shortcut = make_conv(in_channels, out_channels, 1, stride, 0, salt + 211);
    }
    return block;
}

std::vector<double> load_float32_as_double(const std::filesystem::path &filename,
                                           size_t expected_size)
{
    const auto raw = load_float32_file(filename.string());
    if (raw.size() != expected_size)
    {
        throw std::invalid_argument(
            "parameter size mismatch for " + filename.string() +
            ": expected " + std::to_string(expected_size) +
            ", got " + std::to_string(raw.size()));
    }

    std::vector<double> values(raw.size());
    for (size_t i = 0; i < raw.size(); ++i)
    {
        values[i] = static_cast<double>(raw[i]);
    }
    return values;
}

Conv2dWeights load_conv_from_files(const std::filesystem::path &parameters_dir,
                                   const std::string &prefix,
                                   size_t in_channels, size_t out_channels,
                                   size_t kernel, size_t stride, size_t padding)
{
    Conv2dWeights conv;
    conv.in_channels = in_channels;
    conv.out_channels = out_channels;
    conv.kernel_h = kernel;
    conv.kernel_w = kernel;
    conv.stride = stride;
    conv.padding = padding;
    conv.weights = load_float32_as_double(
        parameters_dir / (prefix + ".weight.f32"),
        out_channels * in_channels * kernel * kernel);
    conv.bias = load_float32_as_double(parameters_dir / (prefix + ".bias.f32"), out_channels);
    return conv;
}

ResidualBlockWeights load_block_from_files(const std::filesystem::path &parameters_dir,
                                           const std::string &prefix,
                                           size_t in_channels, size_t out_channels,
                                           size_t stride)
{
    ResidualBlockWeights block;
    block.conv1 = load_conv_from_files(parameters_dir, prefix + ".conv1",
                                       in_channels, out_channels, 3, stride, 1);
    block.conv2 = load_conv_from_files(parameters_dir, prefix + ".conv2",
                                       out_channels, out_channels, 3, 1, 1);
    block.has_shortcut = in_channels != out_channels || stride != 1;
    if (block.has_shortcut)
    {
        block.shortcut = load_conv_from_files(parameters_dir, prefix + ".shortcut",
                                             in_channels, out_channels, 1, stride, 0);
    }
    return block;
}

void validate_manifest(const std::filesystem::path &manifest_path)
{
    std::ifstream file(manifest_path);
    if (!file)
    {
        throw std::invalid_argument("failed to open parameter manifest: " +
                                    manifest_path.string());
    }

    json manifest;
    file >> manifest;
    const auto format = manifest.value("format", "");
    if (format != "poseidon_resnet20_weights_v1")
    {
        throw std::invalid_argument(
            "unsupported ResNet-20 parameter format in manifest: " + format);
    }

    const auto classes = manifest.value("num_classes", 10);
    if (classes != 10)
    {
        throw std::invalid_argument(
            "only CIFAR-10 ResNet-20 weights are supported; manifest num_classes is " +
            std::to_string(classes));
    }

    const auto activation = manifest.value("activation", "");
    if (activation != "relu_bn_folded" && activation != "square_bn_folded" &&
        activation != "square")
    {
        throw std::invalid_argument(
            "unsupported activation metadata in manifest: " + activation);
    }
}

} // namespace

std::vector<float> load_float32_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
    {
        throw std::invalid_argument("failed to open parameter file: " + filename);
    }

    const auto file_size = file.tellg();
    if (file_size < 0 || file_size % static_cast<std::streamoff>(sizeof(float)) != 0)
    {
        throw std::invalid_argument("parameter file is not float32 aligned: " + filename);
    }

    file.seekg(0, std::ios::beg);
    std::vector<float> values(static_cast<size_t>(file_size) / sizeof(float));
    file.read(reinterpret_cast<char *>(values.data()), file_size);
    return values;
}

bool has_external_parameters(const std::string &parameters_dir)
{
    if (parameters_dir.empty())
    {
        return false;
    }
    return std::filesystem::exists(std::filesystem::path(parameters_dir) / "manifest.json");
}

ResNet20Weights load_weights(const std::string &parameters_dir)
{
    if (!has_external_parameters(parameters_dir))
    {
        throw std::invalid_argument(
            "external ResNet-20 parameter directory must contain manifest.json: " +
            parameters_dir);
    }

    const std::filesystem::path dir(parameters_dir);
    validate_manifest(dir / "manifest.json");

    ResNet20Weights weights;
    weights.conv1 = load_conv_from_files(dir, "conv1", 3, 16, 3, 1, 1);

    weights.stage1.push_back(load_block_from_files(dir, "stage1.0", 16, 16, 1));
    weights.stage1.push_back(load_block_from_files(dir, "stage1.1", 16, 16, 1));
    weights.stage1.push_back(load_block_from_files(dir, "stage1.2", 16, 16, 1));

    weights.stage2.push_back(load_block_from_files(dir, "stage2.0", 16, 32, 2));
    weights.stage2.push_back(load_block_from_files(dir, "stage2.1", 32, 32, 1));
    weights.stage2.push_back(load_block_from_files(dir, "stage2.2", 32, 32, 1));

    weights.stage3.push_back(load_block_from_files(dir, "stage3.0", 32, 64, 2));
    weights.stage3.push_back(load_block_from_files(dir, "stage3.1", 64, 64, 1));
    weights.stage3.push_back(load_block_from_files(dir, "stage3.2", 64, 64, 1));

    weights.fc_in = 64;
    weights.fc_out = 10;
    weights.fc_weight = load_float32_as_double(dir / "fc.weight.f32",
                                               weights.fc_in * weights.fc_out);
    weights.fc_bias = load_float32_as_double(dir / "fc.bias.f32", weights.fc_out);
    return weights;
}

ResNet20Weights make_toy_weights()
{
    ResNet20Weights weights;
    weights.conv1 = make_conv(3, 16, 3, 1, 1, 1);

    for (size_t i = 0; i < 3; ++i)
    {
        weights.stage1.push_back(make_block(16, 16, 1, 1000 + i * 100));
    }
    weights.stage2.push_back(make_block(16, 32, 2, 2000));
    weights.stage2.push_back(make_block(32, 32, 1, 2100));
    weights.stage2.push_back(make_block(32, 32, 1, 2200));

    weights.stage3.push_back(make_block(32, 64, 2, 3000));
    weights.stage3.push_back(make_block(64, 64, 1, 3100));
    weights.stage3.push_back(make_block(64, 64, 1, 3200));

    weights.fc_in = 64;
    weights.fc_out = 10;
    weights.fc_weight.resize(weights.fc_in * weights.fc_out);
    weights.fc_bias.resize(weights.fc_out);
    for (size_t i = 0; i < weights.fc_weight.size(); ++i)
    {
        weights.fc_weight[i] = deterministic_weight(i + 4000, 0.003);
    }
    for (size_t i = 0; i < weights.fc_bias.size(); ++i)
    {
        weights.fc_bias[i] = deterministic_weight(i + 5000, 0.001);
    }
    return weights;
}

Tensor make_toy_input()
{
    Tensor input({3, 32, 32});
    for (size_t i = 0; i < input.values.size(); ++i)
    {
        input.values[i] = std::sin(static_cast<double>(i) * 0.013) * 0.25;
    }
    return input;
}

ResNet20Weights load_or_make_weights(const std::string &parameters_dir)
{
    if (has_external_parameters(parameters_dir))
    {
        return load_weights(parameters_dir);
    }
    return make_toy_weights();
}

} // namespace ResNet20
