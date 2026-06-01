#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/advance/homomorphic_linear_transform.h"
#include "poseidon/advance/util/chebyshev_interpolation.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/util/debug.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <ctime>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace poseidon;

namespace
{
constexpr int kImageSize = 32;
constexpr int kInputChannels = 3;
constexpr int kStemChannels = 16;
constexpr int kBlocksPerStage = 3;
constexpr int kClasses = 10;
constexpr double kBatchNormEpsilon = 1e-5;
constexpr double kFheMpCnnApproximationBoundary = 40.0;
constexpr int kFheMpCnnLogScale = 46;
constexpr double kFheMpCnnScale = static_cast<double>(1ULL << kFheMpCnnLogScale);

enum class InputLayout
{
    kHwc,
    kChw
};

enum class WeightLayout
{
    kOihw,
    kHwio
};

enum class RunMode
{
    kPlaintext,
    kHe
};

enum class HeActivation
{
    kFheMpCnnRelu
};

struct Options
{
    int start_image_id = -1;
    int end_image_id = -1;
    fs::path weights_root;
    fs::path data_root;
    InputLayout input_layout = InputLayout::kChw;
    WeightLayout weight_layout = WeightLayout::kOihw;
    RunMode mode = RunMode::kPlaintext;
    bool poseidon_roundtrip = false;
    int he_block_limit = 3;
    HeActivation he_activation = HeActivation::kFheMpCnnRelu;
    fs::path relu_coeffs_path;
};

struct Tensor3D
{
    int channels = 0;
    int height = 0;
    int width = 0;
    std::vector<double> values;

    Tensor3D() = default;

    Tensor3D(int c, int h, int w)
        : channels(c), height(h), width(w), values(static_cast<size_t>(c * h * w), 0.0)
    {
    }

    double &operator()(int c, int h, int w)
    {
        return values[static_cast<size_t>((c * height + h) * width + w)];
    }

    double operator()(int c, int h, int w) const
    {
        return values[static_cast<size_t>((c * height + h) * width + w)];
    }
};

struct BatchNormParams
{
    std::vector<double> bias;
    std::vector<double> running_mean;
    std::vector<double> running_var;
    std::vector<double> weight;
};

struct ConvBlockParams
{
    std::vector<double> conv1_weight;
    BatchNormParams bn1;
    std::vector<double> conv2_weight;
    BatchNormParams bn2;
    int conv1_in_channels = 0;
    int conv1_out_channels = 0;
    int conv2_in_channels = 0;
    int conv2_out_channels = 0;
};

struct ResNet20Weights
{
    std::vector<double> stem_conv_weight;
    BatchNormParams stem_bn;
    std::vector<std::vector<ConvBlockParams>> stages;
    std::vector<double> linear_weight;
    std::vector<double> linear_bias;
};

struct PlainForwardResult
{
    Tensor3D feature_map;
    std::vector<double> logits;
    bool has_logits = false;
    int completed_blocks = 0;
};

struct HeForwardResult
{
    Tensor3D decrypted_feature_map;
    std::vector<double> logits;
    bool has_logits = false;
    int completed_blocks = 0;
};

std::string to_string(InputLayout layout)
{
    return layout == InputLayout::kHwc ? "hwc" : "chw";
}

std::string to_string(WeightLayout layout)
{
    return layout == WeightLayout::kOihw ? "oihw" : "hwio";
}

std::string to_string(RunMode mode)
{
    return mode == RunMode::kPlaintext ? "plaintext" : "he";
}

std::string to_string(HeActivation activation)
{
    return activation == HeActivation::kFheMpCnnRelu ? "fhe_mp_cnn_relu" : "unknown";
}

[[noreturn]] void usage_and_exit(const char *argv0)
{
    std::cerr << "Usage: " << argv0 << " START_IMAGE END_IMAGE"
              << " [--weights-root PATH] [--data-root PATH]"
              << " [--input-layout hwc|chw] [--weight-layout oihw|hwio]"
              << " [--mode plaintext|he] [--he-block-limit N]"
              << " [--he-activation fhe_mp_cnn_relu|poly_relu]"
              << " [--relu-coeffs PATH]"
              << " [--poseidon-roundtrip]" << std::endl;
    std::exit(1);
}

fs::path default_weights_root()
{
    if (const char *env = std::getenv("TRIDENT_RESNET20_WEIGHTS_ROOT"))
    {
        return fs::path(env);
    }
    return "/home/guoshuai/github/FHE-MP-CNN/pretrained_parameters/resnet20_new";
}

fs::path default_data_root()
{
    if (const char *env = std::getenv("TRIDENT_RESNET20_DATA_ROOT"))
    {
        return fs::path(env);
    }
    return "/home/guoshuai/github/FHE-MP-CNN/testFile";
}

fs::path default_relu_coeffs_path()
{
    if (const char *env = std::getenv("TRIDENT_RESNET20_RELU_COEFFS"))
    {
        return fs::path(env);
    }
    return "/home/guoshuai/github/FHE-MP-CNN/cnn_ckks/result/d13.txt";
}

InputLayout parse_input_layout(const std::string &value)
{
    if (value == "hwc")
    {
        return InputLayout::kHwc;
    }
    if (value == "chw")
    {
        return InputLayout::kChw;
    }
    throw std::invalid_argument("unsupported --input-layout: " + value);
}

WeightLayout parse_weight_layout(const std::string &value)
{
    if (value == "oihw")
    {
        return WeightLayout::kOihw;
    }
    if (value == "hwio")
    {
        return WeightLayout::kHwio;
    }
    throw std::invalid_argument("unsupported --weight-layout: " + value);
}

RunMode parse_run_mode(const std::string &value)
{
    if (value == "plaintext")
    {
        return RunMode::kPlaintext;
    }
    if (value == "he")
    {
        return RunMode::kHe;
    }
    throw std::invalid_argument("unsupported --mode: " + value);
}

HeActivation parse_he_activation(const std::string &value)
{
    if (value == "fhe_mp_cnn_relu" || value == "poly_relu")
    {
        return HeActivation::kFheMpCnnRelu;
    }
    throw std::invalid_argument("unsupported --he-activation: " + value);
}

Options parse_options(int argc, char *argv[])
{
    if (argc < 3)
    {
        usage_and_exit(argv[0]);
    }

    Options options;
    options.relu_coeffs_path = default_relu_coeffs_path();
    options.start_image_id = std::stoi(argv[1]);
    options.end_image_id = std::stoi(argv[2]);
    options.weights_root = default_weights_root();
    options.data_root = default_data_root();

    for (int i = 3; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--weights-root" && i + 1 < argc)
        {
            options.weights_root = argv[++i];
        }
        else if (arg == "--data-root" && i + 1 < argc)
        {
            options.data_root = argv[++i];
        }
        else if (arg == "--input-layout" && i + 1 < argc)
        {
            options.input_layout = parse_input_layout(argv[++i]);
        }
        else if (arg == "--weight-layout" && i + 1 < argc)
        {
            options.weight_layout = parse_weight_layout(argv[++i]);
        }
        else if (arg == "--mode" && i + 1 < argc)
        {
            options.mode = parse_run_mode(argv[++i]);
        }
        else if (arg == "--he-block-limit" && i + 1 < argc)
        {
            options.he_block_limit = std::stoi(argv[++i]);
        }
        else if (arg == "--he-activation" && i + 1 < argc)
        {
            options.he_activation = parse_he_activation(argv[++i]);
        }
        else if (arg == "--relu-coeffs" && i + 1 < argc)
        {
            options.relu_coeffs_path = argv[++i];
        }
        else if (arg == "--poseidon-roundtrip")
        {
            options.poseidon_roundtrip = true;
        }
        else
        {
            usage_and_exit(argv[0]);
        }
    }

    if (options.start_image_id < 0 || options.end_image_id < options.start_image_id)
    {
        throw std::invalid_argument("invalid image range");
    }
    if (options.he_block_limit < -1)
    {
        throw std::invalid_argument("invalid --he-block-limit");
    }

    return options;
}

std::vector<double> read_vector_file(const fs::path &path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        throw std::runtime_error("cannot open file: " + path.string());
    }

    std::vector<double> values;
    double value = 0.0;
    while (input >> value)
    {
        values.push_back(value);
    }
    return values;
}

BatchNormParams load_batch_norm(const fs::path &root, const std::string &prefix)
{
    BatchNormParams params;
    params.bias = read_vector_file(root / (prefix + "_bias.txt"));
    params.running_mean = read_vector_file(root / (prefix + "_running_mean.txt"));
    params.running_var = read_vector_file(root / (prefix + "_running_var.txt"));
    params.weight = read_vector_file(root / (prefix + "_weight.txt"));
    return params;
}

ResNet20Weights load_resnet20_weights(const fs::path &weights_root)
{
    ResNet20Weights weights;
    weights.stem_conv_weight = read_vector_file(weights_root / "conv1_weight.txt");
    weights.stem_bn = load_batch_norm(weights_root, "bn1");
    weights.stages.resize(3);

    for (int stage = 1; stage <= 3; ++stage)
    {
        const int stage_out_channels = stage == 1 ? 16 : (stage == 2 ? 32 : 64);
        weights.stages[stage - 1].resize(kBlocksPerStage);
        for (int block = 0; block < kBlocksPerStage; ++block)
        {
            ConvBlockParams params;
            params.conv1_weight =
                read_vector_file(weights_root / ("layer" + std::to_string(stage) + "_" +
                                                 std::to_string(block) + "_conv1_weight.txt"));
            params.bn1 = load_batch_norm(weights_root, "layer" + std::to_string(stage) + "_" +
                                                           std::to_string(block) + "_bn1");
            params.conv2_weight =
                read_vector_file(weights_root / ("layer" + std::to_string(stage) + "_" +
                                                 std::to_string(block) + "_conv2_weight.txt"));
            params.bn2 = load_batch_norm(weights_root, "layer" + std::to_string(stage) + "_" +
                                                           std::to_string(block) + "_bn2");
            params.conv1_out_channels = stage_out_channels;
            params.conv2_in_channels = stage_out_channels;
            params.conv2_out_channels = stage_out_channels;

            if (stage == 1)
            {
                params.conv1_in_channels = 16;
            }
            else if (stage == 2 && block == 0)
            {
                params.conv1_in_channels = 16;
            }
            else if (stage == 2)
            {
                params.conv1_in_channels = 32;
            }
            else if (block == 0)
            {
                params.conv1_in_channels = 32;
            }
            else
            {
                params.conv1_in_channels = 64;
            }

            weights.stages[stage - 1][block] = std::move(params);
        }
    }

    weights.linear_weight = read_vector_file(weights_root / "linear_weight.txt");
    weights.linear_bias = read_vector_file(weights_root / "linear_bias.txt");
    return weights;
}

Tensor3D decode_image(const std::vector<double> &flat_values, InputLayout layout)
{
    if (flat_values.size() != static_cast<size_t>(kImageSize * kImageSize * kInputChannels))
    {
        throw std::invalid_argument("unexpected image size");
    }

    Tensor3D image(kInputChannels, kImageSize, kImageSize);
    if (layout == InputLayout::kHwc)
    {
        for (int h = 0; h < kImageSize; ++h)
        {
            for (int w = 0; w < kImageSize; ++w)
            {
                for (int c = 0; c < kInputChannels; ++c)
                {
                    const size_t index =
                        static_cast<size_t>((h * kImageSize + w) * kInputChannels + c);
                    image(c, h, w) = flat_values[index];
                }
            }
        }
    }
    else
    {
        const int plane = kImageSize * kImageSize;
        for (int c = 0; c < kInputChannels; ++c)
        {
            for (int h = 0; h < kImageSize; ++h)
            {
                for (int w = 0; w < kImageSize; ++w)
                {
                    const size_t index = static_cast<size_t>(c * plane + h * kImageSize + w);
                    image(c, h, w) = flat_values[index];
                }
            }
        }
    }
    return image;
}

std::vector<double> read_image_values(const fs::path &test_values_path, int image_id)
{
    std::ifstream input(test_values_path);
    if (!input.is_open())
    {
        throw std::runtime_error("cannot open file: " + test_values_path.string());
    }

    const int image_span = kImageSize * kImageSize * kInputChannels;
    const long long skip_count = static_cast<long long>(image_id) * image_span;
    double value = 0.0;
    for (long long i = 0; i < skip_count; ++i)
    {
        if (!(input >> value))
        {
            throw std::runtime_error("unexpected EOF while skipping test_values");
        }
    }

    std::vector<double> values(image_span, 0.0);
    for (int i = 0; i < image_span; ++i)
    {
        if (!(input >> values[i]))
        {
            throw std::runtime_error("unexpected EOF while reading image");
        }
    }
    return values;
}

int read_image_label(const fs::path &label_path, int image_id)
{
    std::ifstream input(label_path);
    if (!input.is_open())
    {
        throw std::runtime_error("cannot open file: " + label_path.string());
    }

    int label = -1;
    for (int i = 0; i <= image_id; ++i)
    {
        if (!(input >> label))
        {
            throw std::runtime_error("unexpected EOF while reading labels");
        }
    }
    return label;
}

double conv_weight_at(const std::vector<double> &weights, WeightLayout layout, int out_channel,
                      int in_channel, int kernel_h, int kernel_w, int in_channels,
                      int out_channels)
{
    if (layout == WeightLayout::kOihw)
    {
        const size_t index =
            static_cast<size_t>(((out_channel * in_channels + in_channel) * 3 + kernel_h) * 3 +
                                kernel_w);
        return weights[index];
    }

    const size_t index =
        static_cast<size_t>(((kernel_h * 3 + kernel_w) * in_channels + in_channel) * out_channels +
                            out_channel);
    return weights[index];
}

Tensor3D conv2d_same(const Tensor3D &input, const std::vector<double> &weights, int out_channels,
                     int stride, WeightLayout layout)
{
    const int out_height = input.height / stride;
    const int out_width = input.width / stride;
    Tensor3D output(out_channels, out_height, out_width);

    for (int oc = 0; oc < out_channels; ++oc)
    {
        for (int oh = 0; oh < out_height; ++oh)
        {
            for (int ow = 0; ow < out_width; ++ow)
            {
                double acc = 0.0;
                for (int ic = 0; ic < input.channels; ++ic)
                {
                    for (int kh = 0; kh < 3; ++kh)
                    {
                        const int ih = oh * stride + kh - 1;
                        if (ih < 0 || ih >= input.height)
                        {
                            continue;
                        }
                        for (int kw = 0; kw < 3; ++kw)
                        {
                            const int iw = ow * stride + kw - 1;
                            if (iw < 0 || iw >= input.width)
                            {
                                continue;
                            }
                            acc += input(ic, ih, iw) * conv_weight_at(weights, layout, oc, ic, kh,
                                                                     kw, input.channels,
                                                                     out_channels);
                        }
                    }
                }
                output(oc, oh, ow) = acc;
            }
        }
    }

    return output;
}

Tensor3D apply_batch_norm(const Tensor3D &input, const BatchNormParams &params)
{
    if (static_cast<int>(params.bias.size()) != input.channels)
    {
        throw std::invalid_argument("batch norm parameter size mismatch");
    }

    Tensor3D output(input.channels, input.height, input.width);
    for (int c = 0; c < input.channels; ++c)
    {
        const double inv = params.weight[c] / std::sqrt(params.running_var[c] + kBatchNormEpsilon);
        const double shift = params.bias[c] - params.running_mean[c] * inv;
        for (int h = 0; h < input.height; ++h)
        {
            for (int w = 0; w < input.width; ++w)
            {
                output(c, h, w) = input(c, h, w) * inv + shift;
            }
        }
    }
    return output;
}

double batch_norm_multiplier(const BatchNormParams &params, int channel)
{
    return params.weight[channel] /
           std::sqrt(params.running_var[channel] + kBatchNormEpsilon);
}

double batch_norm_shift(const BatchNormParams &params, int channel)
{
    const double multiplier = batch_norm_multiplier(params, channel);
    return params.bias[channel] - params.running_mean[channel] * multiplier;
}

Tensor3D relu(const Tensor3D &input)
{
    Tensor3D output = input;
    for (double &value : output.values)
    {
        value = std::max(value, 0.0);
    }
    return output;
}

Tensor3D add(const Tensor3D &lhs, const Tensor3D &rhs)
{
    if (lhs.channels != rhs.channels || lhs.height != rhs.height || lhs.width != rhs.width)
    {
        throw std::invalid_argument("tensor add shape mismatch");
    }

    Tensor3D output(lhs.channels, lhs.height, lhs.width);
    for (size_t i = 0; i < lhs.values.size(); ++i)
    {
        output.values[i] = lhs.values[i] + rhs.values[i];
    }
    return output;
}

Tensor3D shortcut_option_a(const Tensor3D &input, int out_channels)
{
    if (out_channels < input.channels || input.height % 2 != 0 || input.width % 2 != 0)
    {
        throw std::invalid_argument("invalid shortcut shape");
    }

    Tensor3D output(out_channels, input.height / 2, input.width / 2);
    const int pad = (out_channels - input.channels) / 2;
    for (int c = 0; c < input.channels; ++c)
    {
        for (int h = 0; h < output.height; ++h)
        {
            for (int w = 0; w < output.width; ++w)
            {
                output(c + pad, h, w) = input(c, h * 2, w * 2);
            }
        }
    }
    return output;
}

std::vector<double> global_average_pool(const Tensor3D &input)
{
    std::vector<double> pooled(static_cast<size_t>(input.channels), 0.0);
    const double denom = static_cast<double>(input.height * input.width);
    for (int c = 0; c < input.channels; ++c)
    {
        double sum = 0.0;
        for (int h = 0; h < input.height; ++h)
        {
            for (int w = 0; w < input.width; ++w)
            {
                sum += input(c, h, w);
            }
        }
        pooled[c] = sum / denom;
    }
    return pooled;
}

std::vector<double> linear(const std::vector<double> &input, const std::vector<double> &weights,
                           const std::vector<double> &bias)
{
    if (input.size() != 64 || weights.size() != 10 * 64 || bias.size() != 10)
    {
        throw std::invalid_argument("unexpected linear layer shape");
    }

    std::vector<double> logits(kClasses, 0.0);
    for (int out = 0; out < kClasses; ++out)
    {
        double value = bias[out];
        for (size_t in = 0; in < input.size(); ++in)
        {
            value += weights[static_cast<size_t>(out * 64 + in)] * input[in];
        }
        logits[out] = value;
    }
    return logits;
}

struct TensorStats
{
    double min = std::numeric_limits<double>::max();
    double max = std::numeric_limits<double>::lowest();
    double mean = 0.0;
};

TensorStats summarize(const Tensor3D &tensor)
{
    TensorStats stats;
    const double sum = std::accumulate(tensor.values.begin(), tensor.values.end(), 0.0);
    for (double value : tensor.values)
    {
        stats.min = std::min(stats.min, value);
        stats.max = std::max(stats.max, value);
    }
    stats.mean = sum / static_cast<double>(tensor.values.size());
    return stats;
}

std::string current_wallclock_timestamp()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &now_c);
#else
    localtime_r(&now_c, &local_tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

class TimestampedLogLine
{
public:
    explicit TimestampedLogLine(std::ostream &output)
        : output_(output)
    {
    }

    ~TimestampedLogLine()
    {
        output_ << "[" << current_wallclock_timestamp() << "] " << buffer_.str() << '\n';
    }

    template <typename T>
    TimestampedLogLine &operator<<(const T &value)
    {
        buffer_ << value;
        return *this;
    }

    TimestampedLogLine &operator<<(std::ostream &(*manip)(std::ostream &))
    {
        manip(buffer_);
        return *this;
    }

private:
    std::ostream &output_;
    std::ostringstream buffer_;
};

TimestampedLogLine timed_log(std::ostream &output)
{
    return TimestampedLogLine(output);
}

void log_decoded_vector_stats(std::ostream &log, std::string_view tag,
                              const std::vector<std::complex<double>> &decoded, int active_slots)
{
    if (active_slots <= 0 || active_slots > static_cast<int>(decoded.size()))
    {
        throw std::invalid_argument("active slot range is invalid for decoded vector stats");
    }

    double min_value = std::numeric_limits<double>::infinity();
    double max_value = -std::numeric_limits<double>::infinity();
    double sum = 0.0;
    for (int i = 0; i < active_slots; ++i)
    {
        const double value = decoded[static_cast<size_t>(i)].real();
        min_value = std::min(min_value, value);
        max_value = std::max(max_value, value);
        sum += value;
    }
    timed_log(log) << tag << ": active_slots=" << active_slots << ", min=" << min_value
                   << ", max=" << max_value << ", mean="
                   << (sum / static_cast<double>(active_slots));
}

void log_tensor_stats(std::ostream &output, std::string_view name, const Tensor3D &tensor)
{
    const TensorStats stats = summarize(tensor);
    timed_log(output) << name << ": shape=(" << tensor.channels << ", " << tensor.height << ", "
                      << tensor.width << "), min=" << stats.min << ", max=" << stats.max
                      << ", mean=" << stats.mean;
}

std::vector<std::complex<double>> poseidon_roundtrip_logits(const std::vector<double> &logits)
{
    ParametersLiteralDefault ckks_param_literal(CKKS, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    std::vector<std::complex<double>> input;
    input.reserve(logits.size());
    for (double value : logits)
    {
        input.emplace_back(value, 0.0);
    }

    Plaintext plain;
    encoder.encode(input, kFheMpCnnScale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);

    Plaintext decrypted;
    decryptor.decrypt(cipher, decrypted);
    std::vector<std::complex<double>> decoded;
    encoder.decode(decrypted, decoded);
    return decoded;
}

std::string format_logits(const std::vector<double> &logits)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6) << '(';
    for (size_t i = 0; i < logits.size(); ++i)
    {
        if (i != 0)
        {
            oss << ", ";
        }
        oss << logits[i];
    }
    oss << ')';
    return oss.str();
}

PlainForwardResult run_plaintext_forward(const Tensor3D &image, const ResNet20Weights &weights,
                                         WeightLayout weight_layout, int max_blocks,
                                         std::ostream &log)
{
    Tensor3D x = conv2d_same(image, weights.stem_conv_weight, 16, 1, weight_layout);
    x = apply_batch_norm(x, weights.stem_bn);
    x = relu(x);
    log_tensor_stats(log, "layer 0", x);

    int completed_blocks = 0;
    for (int stage = 0; stage < 3; ++stage)
    {
        for (int block = 0; block < kBlocksPerStage; ++block)
        {
            if (max_blocks != -1 && completed_blocks >= max_blocks)
            {
                PlainForwardResult result;
                result.feature_map = std::move(x);
                result.completed_blocks = completed_blocks;
                if (result.feature_map.channels == 64)
                {
                    result.logits =
                        linear(global_average_pool(result.feature_map), weights.linear_weight,
                               weights.linear_bias);
                    result.has_logits = true;
                }
                return result;
            }

            const ConvBlockParams &params = weights.stages[stage][block];
            const int stride = (stage > 0 && block == 0) ? 2 : 1;
            Tensor3D identity = x;

            Tensor3D y = conv2d_same(x, params.conv1_weight, params.conv1_out_channels, stride,
                                     weight_layout);
            y = apply_batch_norm(y, params.bn1);
            y = relu(y);

            y = conv2d_same(y, params.conv2_weight, params.conv2_out_channels, 1, weight_layout);
            y = apply_batch_norm(y, params.bn2);

            if (stride == 2)
            {
                identity = shortcut_option_a(identity, params.conv2_out_channels);
            }

            x = relu(add(y, identity));
            ++completed_blocks;
            log_tensor_stats(log, "block " + std::to_string(completed_blocks), x);
        }
    }

    PlainForwardResult result;
    result.feature_map = std::move(x);
    result.completed_blocks = completed_blocks;
    result.logits = linear(global_average_pool(result.feature_map), weights.linear_weight,
                           weights.linear_bias);
    result.has_logits = true;
    return result;
}

struct HeFeatureMap
{
    std::vector<Ciphertext> channels;
    int height = 0;
    int width = 0;
};

struct PackedTensorCipher
{
    Ciphertext cipher;
    int log_slots = 0;
    int k = 0;
    int h = 0;
    int w = 0;
    int c = 0;
    int t = 0;
    int p = 0;
};

struct ActivationComponentSpec
{
    int degree = 0;
    int depth = 0;
    int m = 0;
    int l = 0;
    std::vector<int> tree;
    std::vector<int> decomp_degrees;
    std::vector<int> leaf_start_indices;
    std::vector<double> raw_coeffs;
    std::vector<std::complex<double>> chebyshev_coeffs;
};

struct ActivationSpec
{
    std::vector<ActivationComponentSpec> components;
};

struct HeEnvironment
{
    struct ConvMaskKey
    {
        int height = 0;
        int width = 0;
        int row_offset = 0;
        int col_offset = 0;

        bool operator==(const ConvMaskKey &other) const
        {
            return height == other.height && width == other.width &&
                   row_offset == other.row_offset && col_offset == other.col_offset;
        }
    };

    struct ConvMaskKeyHash
    {
        size_t operator()(const ConvMaskKey &key) const
        {
            size_t seed = static_cast<size_t>(key.height);
            seed = seed * 1315423911u + static_cast<size_t>(key.width);
            seed = seed * 1315423911u + static_cast<size_t>(key.row_offset + 8);
            seed = seed * 1315423911u + static_cast<size_t>(key.col_offset + 8);
            return seed;
        }
    };

    struct DownsampleKey
    {
        int input_height = 0;
        int input_width = 0;
        uint32_t level = 0;
        int64_t scale_bucket = 0;

        bool operator==(const DownsampleKey &other) const
        {
            return input_height == other.input_height && input_width == other.input_width &&
                   level == other.level && scale_bucket == other.scale_bucket;
        }
    };

    struct DownsampleKeyHash
    {
        size_t operator()(const DownsampleKey &key) const
        {
            size_t seed = static_cast<size_t>(key.input_height);
            seed = seed * 1315423911u + static_cast<size_t>(key.input_width);
            seed = seed * 1315423911u + static_cast<size_t>(key.level);
            seed = seed * 1315423911u + static_cast<size_t>(key.scale_bucket);
            return seed;
        }
    };

    PoseidonContext context;
    std::unique_ptr<EvaluatorCkksBase> evaluator;
    CKKSEncoder encoder;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    Encryptor encryptor;
    Decryptor decryptor;
    ActivationSpec activation_spec;
    std::unique_ptr<EvalModPoly> bootstrap_poly;
    double scale = 0.0;
    int slot_count = 0;
    std::unordered_map<ConvMaskKey, std::vector<double>, ConvMaskKeyHash> conv_mask_cache;
    std::unordered_map<DownsampleKey, MatrixPlain, DownsampleKeyHash> downsample_matrix_cache;

    HeEnvironment(PoseidonContext ctx, std::unique_ptr<EvaluatorCkksBase> eva, PublicKey pk,
                  SecretKey sk, RelinKeys rk, GaloisKeys gk, ActivationSpec relu_spec,
                  std::unique_ptr<EvalModPoly> bootstrap, double scale_value)
        : context(std::move(ctx)), evaluator(std::move(eva)), encoder(context),
          public_key(std::move(pk)), secret_key(std::move(sk)), relin_keys(std::move(rk)),
          galois_keys(std::move(gk)), encryptor(context, public_key), decryptor(context, secret_key),
          activation_spec(std::move(relu_spec)), bootstrap_poly(std::move(bootstrap)),
          scale(scale_value),
          slot_count(static_cast<int>(encoder.slot_count()))
    {
    }
};

std::vector<double> read_all_scalars(const fs::path &path)
{
    std::ifstream input(path);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open activation coefficients: " + path.string());
    }

    std::vector<double> values;
    double value = 0.0;
    while (input >> value)
    {
        values.push_back(value);
    }
    if (values.empty())
    {
        throw std::runtime_error("activation coefficient file is empty: " + path.string());
    }
    return values;
}

ActivationComponentSpec make_activation_component(int degree, int depth, int m, int l,
                                                  std::vector<int> tree)
{
    ActivationComponentSpec component;
    component.degree = degree;
    component.depth = depth;
    component.m = m;
    component.l = l;
    component.tree = std::move(tree);
    return component;
}

std::vector<std::complex<double>> build_activation_component_chebyshev_coeffs(
    const ActivationComponentSpec &component, int tree_index);

std::vector<int> compute_leaf_degrees(const ActivationComponentSpec &component)
{
    std::vector<int> decomp_degree(component.tree.size(), -1);
    decomp_degree[1] = component.degree;
    for (int level = 1; level <= component.depth; ++level)
    {
        for (int index = 1 << level; index < (1 << (level + 1)); ++index)
        {
            if (component.tree[static_cast<size_t>(index / 2)] == -1)
            {
                continue;
            }

            if (index % 2 == 0)
            {
                decomp_degree[static_cast<size_t>(index)] =
                    component.tree[static_cast<size_t>(index / 2)] - 1;
            }
            else
            {
                decomp_degree[static_cast<size_t>(index)] =
                    decomp_degree[static_cast<size_t>(index / 2)] -
                    component.tree[static_cast<size_t>(index / 2)];
            }
        }
    }
    return decomp_degree;
}

std::vector<int> compute_leaf_start_indices(const ActivationComponentSpec &component)
{
    std::vector<int> start_indices(component.tree.size(), -1);
    int cursor = 1;
    for (int tree_index = 1; tree_index < static_cast<int>(component.tree.size()); ++tree_index)
    {
        if (component.tree[static_cast<size_t>(tree_index)] != 0)
        {
            continue;
        }
        start_indices[static_cast<size_t>(tree_index)] = cursor;
        cursor += component.decomp_degrees[static_cast<size_t>(tree_index)] + 1;
    }
    return start_indices;
}

ActivationSpec load_fhe_mp_cnn_activation_spec(const fs::path &coeffs_path)
{
    ActivationSpec spec;
    spec.components.push_back(
        make_activation_component(15, 3, 4, 2, {-1, 8, 4, 4, 0, 0, 0, 2, -1, -1, -1, -1, -1, -1, 0, 0}));
    spec.components.push_back(
        make_activation_component(15, 3, 4, 2, {-1, 8, 4, 4, 0, 0, 0, 2, -1, -1, -1, -1, -1, -1, 0, 0}));
    spec.components.push_back(make_activation_component(27, 2, 5, 3, {-1, 16, 8, 8, 0, 0, 0, 0}));

    const std::vector<double> coeffs = read_all_scalars(coeffs_path);
    size_t cursor = 0;

    for (size_t component_index = 0; component_index < spec.components.size(); ++component_index)
    {
        ActivationComponentSpec &component = spec.components[component_index];
        component.decomp_degrees = compute_leaf_degrees(component);
        size_t coeff_count = 0;
        for (int tree_index = 1; tree_index < static_cast<int>(component.tree.size()); ++tree_index)
        {
            if (component.tree[static_cast<size_t>(tree_index)] != 0)
            {
                continue;
            }

            coeff_count += static_cast<size_t>(
                component.decomp_degrees[static_cast<size_t>(tree_index)] + 1);
        }

        if (cursor + coeff_count > coeffs.size())
        {
            throw std::runtime_error("activation coefficient layout does not match FHE-MP-CNN");
        }

        component.raw_coeffs.resize(coeff_count);
        for (size_t i = 0; i < coeff_count; ++i)
        {
            double scaled_coeff = coeffs[cursor + i];
            if (component_index == 0)
            {
                scaled_coeff /= 2.0;
            }
            else if (component_index == 1)
            {
                scaled_coeff /= 1.7;
            }
            else
            {
                scaled_coeff *= 0.5;
            }
            component.raw_coeffs[i] = scaled_coeff;
        }
        cursor += coeff_count;
        component.leaf_start_indices = compute_leaf_start_indices(component);
        component.chebyshev_coeffs =
            build_activation_component_chebyshev_coeffs(component, 1);
    }

    if (cursor != coeffs.size())
    {
        throw std::runtime_error("activation coefficient file has unexpected extra values");
    }
    return spec;
}

std::vector<int> minimal_stem_rotation_steps()
{
    return {1,  2,   4,   8,    16,   32,   64,   128,
            256, 512, 1024, 2048, 4096, 8192, 16384};
}

std::vector<uint32_t> fhe_mp_cnn_resnet20_logq_chain()
{
    return {
        51,
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46,
        51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51};
}

std::unique_ptr<HeEnvironment> create_he_environment(const fs::path &relu_coeffs_path,
                                                     int max_blocks, std::ostream &log)
{
    util::Timestacs timer;
    const bool need_bootstrap = max_blocks != 0;
    (void)need_bootstrap;
    ParametersLiteral ckks_param_literal{CKKS, 16, 15, 46, 5, 0, 0, {}, {}};
    ckks_param_literal.set_log_modulus(fhe_mp_cnn_resnet20_logq_chain(), {51});

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    timer.start();
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    timer.end();
    timed_log(log) << "he setup context+evaluator time : " << timer.microseconds() / 1000
                   << " ms";

    timer.start();
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    timer.end();
    timed_log(log) << "he setup public key time : " << timer.microseconds() / 1000 << " ms";

    timer.start();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    timer.end();
    timed_log(log) << "he setup relin key time : " << timer.microseconds() / 1000 << " ms";

    timer.start();
    GaloisKeys galois_keys;
    if (need_bootstrap)
    {
        keygen.create_galois_keys(galois_keys);
    }
    else
    {
        keygen.create_galois_keys(minimal_stem_rotation_steps(), galois_keys);
    }
    timer.end();
    timed_log(log) << "he setup galois key time : " << timer.microseconds() / 1000 << " ms";

    timer.start();
    const ActivationSpec relu_spec = load_fhe_mp_cnn_activation_spec(relu_coeffs_path);
    std::unique_ptr<EvalModPoly> bootstrap_poly;
    if (need_bootstrap)
    {
        bootstrap_poly = std::make_unique<EvalModPoly>(
            context, CosDiscrete, kFheMpCnnScale, 1, 9, 3, 16, 0, 30);
    }
    timer.end();
    timed_log(log) << "he setup activation/bootstrap config time : "
                   << timer.microseconds() / 1000 << " ms";
    timed_log(log) << "he setup reference log_scale : " << kFheMpCnnLogScale;
    timed_log(log) << "he setup reference scale : " << kFheMpCnnScale;
    return std::make_unique<HeEnvironment>(
        std::move(context), std::move(evaluator), std::move(public_key), keygen.secret_key(),
        std::move(relin_keys), std::move(galois_keys), relu_spec, std::move(bootstrap_poly),
        kFheMpCnnScale);
}

Plaintext encode_with_consistent_level(const std::vector<double> &input, const Ciphertext &cipher,
                                       CKKSEncoder &encoder)
{
    Plaintext result;
    encoder.encode(input, cipher.parms_id(), cipher.scale(), result);
    return result;
}

Ciphertext encrypt_slots(const std::vector<double> &values, HeEnvironment &env)
{
    std::vector<std::complex<double>> slots(static_cast<size_t>(env.slot_count), {0.0, 0.0});
    for (size_t i = 0; i < values.size(); ++i)
    {
        slots[i] = {values[i], 0.0};
    }
    Plaintext plain;
    env.encoder.encode(slots, env.scale, plain);
    Ciphertext cipher;
    env.encryptor.encrypt(plain, cipher);
    return cipher;
}

int floor_power_of_two(int value)
{
    if (value <= 0)
    {
        return 0;
    }
    int result = 1;
    while ((result << 1) <= value)
    {
        result <<= 1;
    }
    return result;
}

int choose_compact_packing_factor(int slot_count, int k, int h, int w, int t)
{
    const int tile_size = k * k * h * w * t;
    if (tile_size <= 0 || tile_size > slot_count)
    {
        throw std::invalid_argument("tensor does not fit into current CKKS slot count");
    }
    return std::max(1, floor_power_of_two(slot_count / tile_size));
}

std::vector<double> flatten_image_chw_scaled(const Tensor3D &image, double scale_divisor)
{
    std::vector<double> flat(static_cast<size_t>(image.channels * image.height * image.width), 0.0);
    size_t cursor = 0;
    for (int c = 0; c < image.channels; ++c)
    {
        for (int h = 0; h < image.height; ++h)
        {
            for (int w = 0; w < image.width; ++w)
            {
                flat[cursor++] = image(c, h, w) / scale_divisor;
            }
        }
    }
    return flat;
}

std::vector<double> pack_compact_tensor_slots(const std::vector<double> &base_values, int slot_count,
                                              int packing_factor)
{
    if (packing_factor <= 0 || slot_count % packing_factor != 0)
    {
        throw std::invalid_argument("invalid compact packing factor");
    }

    const int chunk_size = slot_count / packing_factor;
    if (static_cast<int>(base_values.size()) > chunk_size)
    {
        throw std::invalid_argument("base tensor exceeds compact packing chunk size");
    }

    std::vector<double> packed(static_cast<size_t>(slot_count), 0.0);
    for (int copy_index = 0; copy_index < packing_factor; ++copy_index)
    {
        const size_t offset = static_cast<size_t>(copy_index * chunk_size);
        std::copy(base_values.begin(), base_values.end(), packed.begin() + offset);
    }
    return packed;
}

PackedTensorCipher encrypt_image_to_packed_tensor(const Tensor3D &image, HeEnvironment &env)
{
    PackedTensorCipher result;
    result.log_slots = static_cast<int>(std::llround(std::log2(env.slot_count)));
    result.k = 1;
    result.h = image.height;
    result.w = image.width;
    result.c = image.channels;
    result.t = image.channels;
    result.p = choose_compact_packing_factor(env.slot_count, result.k, result.h, result.w,
                                             result.t);

    const std::vector<double> base_values =
        flatten_image_chw_scaled(image, kFheMpCnnApproximationBoundary);
    const std::vector<double> packed_values =
        pack_compact_tensor_slots(base_values, env.slot_count, result.p);
    result.cipher = encrypt_slots(packed_values, env);
    return result;
}

Tensor3D decrypt_packed_input_tensor(const PackedTensorCipher &packed, HeEnvironment &env)
{
    if (packed.k != 1)
    {
        throw std::invalid_argument("only k=1 packed input tensors are supported");
    }

    Plaintext plain;
    env.decryptor.decrypt(packed.cipher, plain);
    std::vector<std::complex<double>> decoded;
    env.encoder.decode(plain, decoded);

    Tensor3D result(packed.c, packed.h, packed.w);
    size_t cursor = 0;
    for (int c = 0; c < packed.c; ++c)
    {
        for (int h = 0; h < packed.h; ++h)
        {
            for (int w = 0; w < packed.w; ++w)
            {
                result(c, h, w) = decoded[cursor++].real();
            }
        }
    }
    return result;
}

Tensor3D decrypt_packed_feature_map(const PackedTensorCipher &packed, HeEnvironment &env)
{
    if (packed.k != 1)
    {
        throw std::invalid_argument("packed feature map decrypt only supports k=1 tensors");
    }

    Plaintext plain;
    env.decryptor.decrypt(packed.cipher, plain);
    std::vector<std::complex<double>> decoded;
    env.encoder.decode(plain, decoded);

    Tensor3D result(packed.c, packed.h, packed.w);
    const int channel_stride = packed.h * packed.w;
    for (int channel = 0; channel < packed.c; ++channel)
    {
        const int channel_offset = channel * channel_stride;
        for (int row = 0; row < packed.h; ++row)
        {
            for (int col = 0; col < packed.w; ++col)
            {
                const int slot = channel_offset + row * packed.w + col;
                result(channel, row, col) = decoded[static_cast<size_t>(slot)].real();
            }
        }
    }
    return result;
}

void rotate_cipher_composed(const Ciphertext &source, int rotation, HeEnvironment &env,
                            Ciphertext &result);
void add_inplace_fast(Ciphertext &destination, Ciphertext term, HeEnvironment &env);
void log_cipher_metadata(std::ostream &log, std::string_view tag, const Ciphertext &cipher);

PackedTensorCipher pack_feature_map_to_tensor(const HeFeatureMap &feature_map, HeEnvironment &env)
{
    PackedTensorCipher result;
    result.log_slots = static_cast<int>(std::llround(std::log2(env.slot_count)));
    result.k = 1;
    result.h = feature_map.height;
    result.w = feature_map.width;
    result.c = static_cast<int>(feature_map.channels.size());
    result.t = result.c;
    result.p = choose_compact_packing_factor(env.slot_count, result.k, result.h, result.w,
                                             result.t);
    const int channel_stride = result.h * result.w;
    const int chunk_slots = env.slot_count / result.p;
    std::vector<double> source_mask(static_cast<size_t>(env.slot_count), 0.0);
    for (int index = 0; index < channel_stride; ++index)
    {
        source_mask[static_cast<size_t>(index)] = 1.0;
    }

    bool initialized = false;
    Ciphertext packed_sum;
    for (int channel = 0; channel < result.c; ++channel)
    {
        Plaintext source_plain = encode_with_consistent_level(
            source_mask, feature_map.channels[static_cast<size_t>(channel)], env.encoder);
        Ciphertext active = feature_map.channels[static_cast<size_t>(channel)];
        env.evaluator->multiply_plain(active, source_plain, active);
        env.evaluator->rescale(active, active);

        for (int copy_index = 0; copy_index < result.p; ++copy_index)
        {
            Ciphertext rotated = active;
            const int rotation = copy_index * chunk_slots + channel * channel_stride;
            if (rotation != 0)
            {
                rotate_cipher_composed(active, rotation, env, rotated);
            }

            if (!initialized)
            {
                packed_sum = std::move(rotated);
                initialized = true;
            }
            else
            {
                add_inplace_fast(packed_sum, std::move(rotated), env);
            }
        }
    }

    if (!initialized)
    {
        throw std::runtime_error("cannot pack empty encrypted feature map");
    }
    result.cipher = std::move(packed_sum);
    return result;
}

int packed_tensor_base_slots(const PackedTensorCipher &tensor)
{
    return tensor.k * tensor.k * tensor.h * tensor.w * tensor.t;
}

int packed_tensor_chunk_slots(const PackedTensorCipher &tensor, int slot_count)
{
    if (tensor.p <= 0 || slot_count % tensor.p != 0)
    {
        throw std::invalid_argument("packed tensor replication factor does not divide slot count");
    }
    return slot_count / tensor.p;
}

std::vector<double> batch_norm_channel_multipliers(const BatchNormParams &bn);
void add_inplace_fast(Ciphertext &destination, Ciphertext term, HeEnvironment &env);
HeFeatureMap encrypted_convolution_with_channel_multiplier(
    const HeFeatureMap &input, const std::vector<double> &weights,
    const std::vector<double> *channel_multiplier, int out_channels, int stride,
    WeightLayout weight_layout, HeEnvironment &env);
Ciphertext encrypted_fhe_mp_cnn_relu(const Ciphertext &cipher, HeEnvironment &env,
                                     std::ostream *log, std::string_view tag,
                                     size_t channel_index);
Ciphertext encrypted_bootstrap(const Ciphertext &cipher, HeEnvironment &env);
void match_levels(Ciphertext &lhs, Ciphertext &rhs, EvaluatorCkksBase &eva);
void match_scale(Ciphertext &lhs, Ciphertext &rhs, const CKKSEncoder &encoder,
                 EvaluatorCkksBase &eva, double scale);
void rotate_cipher_composed(const Ciphertext &source, int rotation, HeEnvironment &env,
                            Ciphertext &result);
HeFeatureMap encrypted_shortcut_option_a(const HeFeatureMap &input, int out_channels,
                                         HeEnvironment &env);
std::vector<Ciphertext> encrypted_linear_logits(const HeFeatureMap &feature_map,
                                                const ResNet20Weights &weights, HeEnvironment &env);
Ciphertext average_pool_cipher(const Ciphertext &cipher, int active_slots, HeEnvironment &env);
HeFeatureMap unpack_packed_output_channels(const PackedTensorCipher &packed, HeEnvironment &env);
PackedTensorCipher packed_convolution_stride1_poseidon(const PackedTensorCipher &input,
                                                       const std::vector<double> &weights,
                                                       const BatchNormParams &bn,
                                                       WeightLayout weight_layout,
                                                       int out_channels, HeEnvironment &env,
                                                       std::ostream *log);

std::vector<double> build_packed_weight_mask(const PackedTensorCipher &input,
                                             const std::vector<double> &weights,
                                             const std::vector<double> &channel_multipliers,
                                             int kernel_row, int kernel_col,
                                             int output_group, WeightLayout weight_layout,
                                             int out_channels, int slot_count)
{
    std::vector<double> mask(static_cast<size_t>(slot_count), 0.0);
    const int chunk_slots = packed_tensor_chunk_slots(input, slot_count);
    const int base_slots = packed_tensor_base_slots(input);
    for (int slot = 0; slot < slot_count; ++slot)
    {
        const int copy_index = slot / chunk_slots;
        const int out_channel = output_group * input.p + copy_index;
        if (out_channel >= out_channels)
        {
            continue;
        }

        const int local = slot % chunk_slots;
        if (local >= base_slots)
        {
            continue;
        }

        const int channel = local / (input.h * input.w);
        const int spatial = local % (input.h * input.w);
        const int row = spatial / input.w;
        const int col = spatial % input.w;
        const int source_row = row + kernel_row - 1;
        const int source_col = col + kernel_col - 1;
        if (source_row < 0 || source_row >= input.h || source_col < 0 || source_col >= input.w)
        {
            continue;
        }

        const double coeff = conv_weight_at(weights, weight_layout, out_channel, channel,
                                            kernel_row, kernel_col, input.c, out_channels) *
                             channel_multipliers[static_cast<size_t>(out_channel)];
        mask[static_cast<size_t>(slot)] = coeff;
    }
    return mask;
}

std::vector<double> build_packed_output_select_mask(int output_height, int output_width,
                                                    int out_channels, int out_channel,
                                                    int slot_count, int output_p)
{
    std::vector<double> mask(static_cast<size_t>(slot_count), 0.0);
    const int output_chunk = slot_count / output_p;
    const int channel_stride = output_height * output_width;
    const int channel_offset = out_channel * channel_stride;
    for (int index = 0; index < channel_stride; ++index)
    {
        mask[static_cast<size_t>(channel_offset + index)] = 1.0;
    }
    return mask;
}

PackedTensorCipher align_packed_tensor_to_reference_scale(const PackedTensorCipher &input,
                                                          HeEnvironment &env)
{
    PackedTensorCipher result = input;
    if (result.cipher.scale() > env.scale * 1.5)
    {
        env.evaluator->rescale_dynamic(result.cipher, result.cipher, env.scale);
    }
    result.cipher.scale() = env.scale;
    return result;
}

std::vector<double> build_packed_bn_shift_mask(const PackedTensorCipher &input,
                                               const BatchNormParams &bn, int slot_count)
{
    if (static_cast<int>(bn.bias.size()) != input.c)
    {
        throw std::invalid_argument("packed batch norm channel count mismatch");
    }

    std::vector<double> mask(static_cast<size_t>(slot_count), 0.0);
    const int chunk_slots = packed_tensor_chunk_slots(input, slot_count);
    const int channel_stride = input.h * input.w;
    for (int copy_index = 0; copy_index < input.p; ++copy_index)
    {
        const int base = copy_index * chunk_slots;
        for (int channel = 0; channel < input.c; ++channel)
        {
            const double shift =
                batch_norm_shift(bn, channel) / kFheMpCnnApproximationBoundary;
            for (int offset = 0; offset < channel_stride; ++offset)
            {
                mask[static_cast<size_t>(base + channel * channel_stride + offset)] = shift;
            }
        }
    }
    return mask;
}

PackedTensorCipher packed_batch_norm_poseidon(const PackedTensorCipher &input,
                                              const BatchNormParams &bn, HeEnvironment &env)
{
    PackedTensorCipher result = input;
    const std::vector<double> shift_mask =
        build_packed_bn_shift_mask(result, bn, env.slot_count);
    Plaintext plain = encode_with_consistent_level(shift_mask, result.cipher, env.encoder);
    env.evaluator->add_plain(result.cipher, plain, result.cipher);
    return result;
}

PackedTensorCipher packed_relu_poseidon(const PackedTensorCipher &input, HeEnvironment &env,
                                        std::ostream *log, std::string_view tag)
{
    PackedTensorCipher result = input;
    util::Timestacs timer;
    timer.start();
    result.cipher = encrypted_fhe_mp_cnn_relu(result.cipher, env, log, tag, 0);
    timer.end();
    if (log)
    {
        timed_log(*log) << tag << " packed relu time : " << timer.microseconds() / 1000
                        << " ms";
    }
    return result;
}

PackedTensorCipher packed_add_poseidon(const PackedTensorCipher &lhs, const PackedTensorCipher &rhs,
                                       HeEnvironment &env)
{
    if (lhs.k != rhs.k || lhs.h != rhs.h || lhs.w != rhs.w || lhs.c != rhs.c || lhs.t != rhs.t ||
        lhs.p != rhs.p)
    {
        throw std::invalid_argument("packed tensor add shape mismatch");
    }

    PackedTensorCipher result = lhs;
    Ciphertext other = rhs.cipher;
    match_levels(result.cipher, other, *env.evaluator);
    match_scale(result.cipher, other, env.encoder, *env.evaluator, env.scale);
    env.evaluator->add(result.cipher, other, result.cipher);
    return result;
}

std::vector<double> build_packed_single_slot_mask(int slot_count, int slot, double value)
{
    if (slot < 0 || slot >= slot_count)
    {
        throw std::out_of_range("packed slot index out of range");
    }
    std::vector<double> mask(static_cast<size_t>(slot_count), 0.0);
    mask[static_cast<size_t>(slot)] = value;
    return mask;
}

int packed_base_slot_index(const PackedTensorCipher &tensor, int channel, int row, int col)
{
    if (channel < 0 || channel >= tensor.c || row < 0 || row >= tensor.h || col < 0 || col >= tensor.w)
    {
        throw std::out_of_range("packed tensor coordinate out of range");
    }
    return channel * tensor.h * tensor.w + row * tensor.w + col;
}

Ciphertext replicate_packed_base_cipher(const Ciphertext &base, int output_p, HeEnvironment &env)
{
    if (output_p <= 0 || env.slot_count % output_p != 0)
    {
        throw std::invalid_argument("invalid packed replication factor");
    }

    Ciphertext replicated = base;
    const int chunk_slots = env.slot_count / output_p;
    for (int copy_index = 1; copy_index < output_p; ++copy_index)
    {
        Ciphertext rotated;
        rotate_cipher_composed(base, -copy_index * chunk_slots, env, rotated);
        add_inplace_fast(replicated, std::move(rotated), env);
    }
    return replicated;
}

PackedTensorCipher packed_spatial_downsample_poseidon(const PackedTensorCipher &input,
                                                      int out_channels, int channel_pad_left,
                                                      HeEnvironment &env)
{
    if (input.h % 2 != 0 || input.w % 2 != 0)
    {
        throw std::invalid_argument("packed spatial downsample expects even spatial dimensions");
    }
    if (channel_pad_left < 0 || channel_pad_left + input.c > out_channels)
    {
        throw std::invalid_argument("packed spatial downsample channel padding is invalid");
    }

    const int output_height = input.h / 2;
    const int output_width = input.w / 2;
    const int output_p =
        choose_compact_packing_factor(env.slot_count, 1, output_height, output_width, out_channels);

    bool initialized = false;
    Ciphertext output_base;
    for (int channel = 0; channel < input.c; ++channel)
    {
        const int output_channel = channel + channel_pad_left;
        for (int row = 0; row < output_height; ++row)
        {
            for (int col = 0; col < output_width; ++col)
            {
                const int source_slot = packed_base_slot_index(input, channel, row * 2, col * 2);
                const int output_slot =
                    output_channel * output_height * output_width + row * output_width + col;
                const int rotation = output_slot - source_slot;

                Ciphertext rotated = input.cipher;
                if (rotation != 0)
                {
                    rotate_cipher_composed(input.cipher, rotation, env, rotated);
                }

                Plaintext plain = encode_with_consistent_level(
                    build_packed_single_slot_mask(env.slot_count, output_slot, 1.0), rotated,
                    env.encoder);
                Ciphertext selected;
                env.evaluator->multiply_plain(rotated, plain, selected);
                env.evaluator->rescale(selected, selected);
                if (!initialized)
                {
                    output_base = std::move(selected);
                    initialized = true;
                }
                else
                {
                    add_inplace_fast(output_base, std::move(selected), env);
                }
            }
        }
    }

    if (!initialized)
    {
        throw std::runtime_error("packed spatial downsample produced no output");
    }

    return PackedTensorCipher{replicate_packed_base_cipher(output_base, output_p, env),
                              static_cast<int>(std::llround(std::log2(env.slot_count))), 1,
                              output_height, output_width, out_channels, out_channels, output_p};
}

PackedTensorCipher packed_shortcut_option_a_poseidon(const PackedTensorCipher &input,
                                                     int out_channels, HeEnvironment &env)
{
    const int pad = (out_channels - input.c) / 2;
    return packed_spatial_downsample_poseidon(input, out_channels, pad, env);
}

PackedTensorCipher packed_average_pool_poseidon(const PackedTensorCipher &input, HeEnvironment &env)
{
    bool initialized = false;
    Ciphertext pooled_base;
    const double coeff =
        kFheMpCnnApproximationBoundary / static_cast<double>(input.h * input.w);
    for (int channel = 0; channel < input.c; ++channel)
    {
        const int output_slot = channel;
        for (int row = 0; row < input.h; ++row)
        {
            for (int col = 0; col < input.w; ++col)
            {
                const int source_slot = packed_base_slot_index(input, channel, row, col);
                const int rotation = output_slot - source_slot;

                Ciphertext rotated = input.cipher;
                if (rotation != 0)
                {
                    rotate_cipher_composed(input.cipher, rotation, env, rotated);
                }

                Plaintext plain = encode_with_consistent_level(
                    build_packed_single_slot_mask(env.slot_count, output_slot, coeff), rotated,
                    env.encoder);
                Ciphertext term;
                env.evaluator->multiply_plain(rotated, plain, term);
                env.evaluator->rescale(term, term);
                if (!initialized)
                {
                    pooled_base = std::move(term);
                    initialized = true;
                }
                else
                {
                    add_inplace_fast(pooled_base, std::move(term), env);
                }
            }
        }
    }

    if (!initialized)
    {
        throw std::runtime_error("packed average pooling produced no output");
    }

    return PackedTensorCipher{std::move(pooled_base),
                              static_cast<int>(std::llround(std::log2(env.slot_count))), 1, 1, 1,
                              input.c, input.c, 1};
}

std::vector<Ciphertext> packed_fully_connected_poseidon(const PackedTensorCipher &input,
                                                        const ResNet20Weights &weights,
                                                        HeEnvironment &env)
{
    if (input.h != 1 || input.w != 1 || input.c != 64)
    {
        throw std::invalid_argument("packed fully connected expects pooled 1x1x64 tensor");
    }

    std::vector<Ciphertext> logits(static_cast<size_t>(kClasses));
    for (int out = 0; out < kClasses; ++out)
    {
        bool initialized = false;
        Ciphertext sum;
        for (int in = 0; in < 64; ++in)
        {
            Ciphertext rotated = input.cipher;
            if (in != 0)
            {
                rotate_cipher_composed(input.cipher, -in, env, rotated);
            }

            Plaintext plain = encode_with_consistent_level(
                build_packed_single_slot_mask(
                    env.slot_count, 0, weights.linear_weight[static_cast<size_t>(out * 64 + in)]),
                rotated, env.encoder);
            Ciphertext term;
            env.evaluator->multiply_plain(rotated, plain, term);
            env.evaluator->rescale(term, term);
            if (!initialized)
            {
                sum = std::move(term);
                initialized = true;
            }
            else
            {
                add_inplace_fast(sum, std::move(term), env);
            }
        }

        std::vector<double> bias_mask(static_cast<size_t>(env.slot_count), 0.0);
        bias_mask[0] = weights.linear_bias[static_cast<size_t>(out)];
        Plaintext bias_plain = encode_with_consistent_level(bias_mask, sum, env.encoder);
        env.evaluator->add_plain(sum, bias_plain, sum);
        logits[static_cast<size_t>(out)] = std::move(sum);
    }
    return logits;
}

bool can_pack_tensor_shape(int height, int width, int channels, const HeEnvironment &env)
{
    try
    {
        return choose_compact_packing_factor(env.slot_count, 1, height, width, channels) > 0;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

PackedTensorCipher packed_convolution_poseidon(const PackedTensorCipher &input,
                                               const std::vector<double> &weights,
                                               const BatchNormParams &bn, int out_channels,
                                               int stride, WeightLayout weight_layout,
                                               HeEnvironment &env, std::ostream *log,
                                               std::string_view tag)
{
    const int output_height = (stride == 1) ? input.h : (input.h / 2);
    const int output_width = (stride == 1) ? input.w : (input.w / 2);
    if (can_pack_tensor_shape(output_height, output_width, out_channels, env))
    {
        if (log)
        {
            *log << tag << " path : packed\n";
        }
        if (stride == 1)
        {
            return packed_convolution_stride1_poseidon(input, weights, bn, weight_layout,
                                                       out_channels, env, log);
        }

        PackedTensorCipher dense = packed_convolution_stride1_poseidon(
            input, weights, bn, weight_layout, out_channels, env, log);
        return packed_spatial_downsample_poseidon(dense, out_channels, 0, env);
    }

    throw std::runtime_error("packed convolution output shape does not fit into current CKKS slots");
}

PackedTensorCipher packed_bootstrap_poseidon(const PackedTensorCipher &input, HeEnvironment &env)
{
    PackedTensorCipher result = input;
    result.cipher = encrypted_bootstrap(result.cipher, env);
    return result;
}

void log_packed_tensor_stats(std::ostream &log, std::string_view tag,
                             const PackedTensorCipher &tensor, HeEnvironment &env)
{
    log_cipher_metadata(log, std::string(tag) + " metadata", tensor.cipher);
    try
    {
        Plaintext plain;
        env.decryptor.decrypt(tensor.cipher, plain);
        std::vector<std::complex<double>> decoded;
        env.encoder.decode(plain, decoded);
        log_decoded_vector_stats(log, tag, decoded, packed_tensor_base_slots(tensor));
    }
    catch (const std::exception &error)
    {
        timed_log(log) << tag << " decode failed: " << error.what();
    }
}

void rotate_cipher_composed(const Ciphertext &source, int rotation, HeEnvironment &env,
                            Ciphertext &result)
{
    const int slot_count = env.slot_count;
    int normalized = rotation % slot_count;
    if (normalized < 0)
    {
        normalized += slot_count;
    }
    if (normalized == 0)
    {
        result = source;
        return;
    }

    Ciphertext current = source;
    bool initialized = false;
    for (int bit = 0; (1 << bit) <= normalized; ++bit)
    {
        const int step = 1 << bit;
        if ((normalized & step) == 0)
        {
            continue;
        }
        Ciphertext rotated;
        env.evaluator->rotate(initialized ? current : source, rotated, step, env.galois_keys);
        current = std::move(rotated);
        initialized = true;
    }
    result = std::move(current);
}

PackedTensorCipher packed_convolution_stride1_poseidon(const PackedTensorCipher &input,
                                                       const std::vector<double> &weights,
                                                       const BatchNormParams &bn,
                                                       WeightLayout weight_layout,
                                                       int out_channels, HeEnvironment &env,
                                                       std::ostream *log)
{
    if (input.k != 1)
    {
        throw std::invalid_argument("packed stride-1 convolution expects k=1 contiguous packing");
    }

    const int slot_count = env.slot_count;
    const int output_p =
        choose_compact_packing_factor(slot_count, 1, input.h, input.w, out_channels);
    if (output_p <= 0)
    {
        throw std::runtime_error("current CKKS slot count cannot hold packed convolution output");
    }

    const std::vector<double> channel_multipliers = batch_norm_channel_multipliers(bn);
    const int chunk_slots = packed_tensor_chunk_slots(input, slot_count);
    const int copy_stride = input.h * input.w;
    const int q = (out_channels + input.p - 1) / input.p;

    std::array<std::array<Ciphertext, 3>, 3> rotated_inputs;
    util::Timestacs timer;
    for (int kh = 0; kh < 3; ++kh)
    {
        for (int kw = 0; kw < 3; ++kw)
        {
            rotated_inputs[static_cast<size_t>(kh)][static_cast<size_t>(kw)] = input.cipher;
            const int rotation = input.w * (kh - 1) + (kw - 1);
            if (rotation != 0)
            {
                rotate_cipher_composed(input.cipher, rotation, env,
                                       rotated_inputs[static_cast<size_t>(kh)][static_cast<size_t>(kw)]);
            }
        }
    }
    if (log)
    {
        timed_log(*log) << "he stem packed pre-rotation ready";
    }

    bool initialized_total = false;
    Ciphertext total_sum;
    for (int group = 0; group < q; ++group)
    {
        timer.start();
        bool initialized_group = false;
        Ciphertext group_sum;
        for (int kh = 0; kh < 3; ++kh)
        {
            for (int kw = 0; kw < 3; ++kw)
            {
                std::vector<double> mask = build_packed_weight_mask(
                    input, weights, channel_multipliers, kh, kw, group, weight_layout,
                    out_channels, slot_count);
                Plaintext plain = encode_with_consistent_level(
                    mask, rotated_inputs[static_cast<size_t>(kh)][static_cast<size_t>(kw)],
                    env.encoder);
                Ciphertext term;
                env.evaluator->multiply_plain(
                    rotated_inputs[static_cast<size_t>(kh)][static_cast<size_t>(kw)], plain, term);
                env.evaluator->rescale(term, term);
                if (!initialized_group)
                {
                    group_sum = std::move(term);
                    initialized_group = true;
                }
                else
                {
                    add_inplace_fast(group_sum, std::move(term), env);
                }
            }
        }

        if (!initialized_group)
        {
            continue;
        }

        const Ciphertext group_base = group_sum;
        Ciphertext reduced = group_sum;
        for (int channel = 1; channel < input.t; ++channel)
        {
            Ciphertext rotated;
            rotate_cipher_composed(group_base, channel * copy_stride, env, rotated);
            add_inplace_fast(reduced, std::move(rotated), env);
        }

        for (int within_group = 0; within_group < input.p; ++within_group)
        {
            const int out_channel = group * input.p + within_group;
            if (out_channel >= out_channels)
            {
                continue;
            }

            Ciphertext rotated = reduced;
            const int rotation = chunk_slots * within_group - out_channel * copy_stride;
            if (rotation != 0)
            {
                rotate_cipher_composed(reduced, rotation, env, rotated);
            }

            std::vector<double> select_mask = build_packed_output_select_mask(
                input.h, input.w, out_channels, out_channel, slot_count, output_p);
            Plaintext plain = encode_with_consistent_level(select_mask, rotated, env.encoder);
            Ciphertext selected;
            env.evaluator->multiply_plain(rotated, plain, selected);
            env.evaluator->rescale(selected, selected);
            if (!initialized_total)
            {
                total_sum = std::move(selected);
                initialized_total = true;
            }
            else
            {
                add_inplace_fast(total_sum, std::move(selected), env);
            }
        }
        timer.end();
        if (log)
        {
            timed_log(*log) << "he stem packed group " << group << " time : "
                            << timer.microseconds() / 1000 << " ms";
        }
    }

    if (!initialized_total)
    {
        throw std::runtime_error("packed stem convolution produced no ciphertext output");
    }

    const Ciphertext packed_base = total_sum;
    Ciphertext packed_output = total_sum;
    const int output_chunk = slot_count / output_p;
    for (int copy_index = 1; copy_index < output_p; ++copy_index)
    {
        Ciphertext rotated;
        rotate_cipher_composed(packed_base, -copy_index * output_chunk, env, rotated);
        add_inplace_fast(packed_output, std::move(rotated), env);
    }
    if (log)
    {
        timed_log(*log) << "he stem packed output replication done";
    }

    return PackedTensorCipher{std::move(packed_output),
                              static_cast<int>(std::llround(std::log2(slot_count))), 1,
                              input.h, input.w, out_channels, out_channels, output_p};
}

HeFeatureMap unpack_packed_output_channels(const PackedTensorCipher &packed, HeEnvironment &env)
{
    if (packed.k != 1)
    {
        throw std::invalid_argument("packed output unpack only supports k=1 tensors");
    }

    HeFeatureMap result;
    result.height = packed.h;
    result.width = packed.w;
    result.channels.reserve(static_cast<size_t>(packed.c));
    const int channel_stride = packed.h * packed.w;
    std::vector<double> channel_mask(static_cast<size_t>(env.slot_count), 0.0);
    for (int index = 0; index < channel_stride; ++index)
    {
        channel_mask[static_cast<size_t>(index)] = 1.0;
    }

    for (int channel = 0; channel < packed.c; ++channel)
    {
        Ciphertext rotated = packed.cipher;
        const int rotation = -channel * channel_stride;
        if (rotation != 0)
        {
            rotate_cipher_composed(packed.cipher, rotation, env, rotated);
        }
        Plaintext plain;
        env.encoder.encode(channel_mask, rotated.parms_id(), 1.0, plain);
        Ciphertext unpacked;
        env.evaluator->multiply_plain(rotated, plain, unpacked);
        unpacked.scale() = rotated.scale();
        result.channels.push_back(std::move(unpacked));
    }
    return result;
}

Ciphertext make_zero_like(const Ciphertext &cipher, HeEnvironment &env)
{
    std::vector<double> zero(static_cast<size_t>(env.slot_count), 0.0);
    Plaintext plain = encode_with_consistent_level(zero, cipher, env.encoder);
    Ciphertext zero_cipher;
    env.encryptor.encrypt(plain, zero_cipher);
    return zero_cipher;
}

void match_levels(Ciphertext &lhs, Ciphertext &rhs, EvaluatorCkksBase &eva)
{
    if (lhs.level() > rhs.level())
    {
        eva.drop_modulus(lhs, lhs, rhs.parms_id());
    }
    else if (lhs.level() < rhs.level())
    {
        eva.drop_modulus(rhs, rhs, lhs.parms_id());
    }
}

void match_scale(Ciphertext &lhs, Ciphertext &rhs, const CKKSEncoder &encoder, EvaluatorCkksBase &eva,
                 double scale)
{
    if (!util::are_approximate(lhs.scale(), rhs.scale()))
    {
        lhs.scale() = rhs.scale();
        std::vector<std::complex<double>> one(1, {1.0, 0.0});
        Plaintext plain;

        encoder.encode(one, rhs.parms_id(), scale * scale / rhs.scale(), plain);
        eva.multiply_plain(rhs, plain, rhs);
        eva.rescale(rhs, rhs);

        encoder.encode(one, lhs.parms_id(), scale * scale / lhs.scale(), plain);
        eva.multiply_plain(lhs, plain, lhs);
        eva.rescale(lhs, lhs);
    }
}

void add_inplace_dynamic(Ciphertext &destination, Ciphertext term, HeEnvironment &env)
{
    match_levels(destination, term, *env.evaluator);
    match_scale(destination, term, env.encoder, *env.evaluator, env.scale);
    env.evaluator->add(destination, term, destination);
}

void add_inplace_fast(Ciphertext &destination, Ciphertext term, HeEnvironment &env)
{
    add_inplace_dynamic(destination, std::move(term), env);
}

HeFeatureMap encrypt_image_to_feature_map(const Tensor3D &image, HeEnvironment &env)
{
    HeFeatureMap result;
    result.height = image.height;
    result.width = image.width;
    result.channels.resize(static_cast<size_t>(image.channels));
    for (int c = 0; c < image.channels; ++c)
    {
        std::vector<double> channel_values(static_cast<size_t>(image.height * image.width), 0.0);
        for (int h = 0; h < image.height; ++h)
        {
            for (int w = 0; w < image.width; ++w)
            {
                channel_values[static_cast<size_t>(h * image.width + w)] =
                    image(c, h, w) / kFheMpCnnApproximationBoundary;
            }
        }
        result.channels[static_cast<size_t>(c)] = encrypt_slots(channel_values, env);
    }
    return result;
}

Tensor3D decrypt_feature_map(const HeFeatureMap &feature_map, HeEnvironment &env)
{
    Tensor3D result(static_cast<int>(feature_map.channels.size()), feature_map.height,
                    feature_map.width);
    for (int c = 0; c < static_cast<int>(feature_map.channels.size()); ++c)
    {
        Plaintext plain;
        env.decryptor.decrypt(feature_map.channels[static_cast<size_t>(c)], plain);
        std::vector<std::complex<double>> decoded;
        env.encoder.decode(plain, decoded);
        for (int h = 0; h < feature_map.height; ++h)
        {
            for (int w = 0; w < feature_map.width; ++w)
            {
                result(c, h, w) = decoded[static_cast<size_t>(h * feature_map.width + w)].real();
            }
        }
    }
    return result;
}

std::vector<double> build_conv_mask(int height, int width, int row_offset, int col_offset,
                                    int slot_count, double coeff)
{
    std::vector<double> mask(static_cast<size_t>(slot_count), 0.0);
    for (int row = 0; row < height; ++row)
    {
        for (int col = 0; col < width; ++col)
        {
            const int source_row = row + row_offset;
            const int source_col = col + col_offset;
            if (source_row >= 0 && source_row < height && source_col >= 0 && source_col < width)
            {
                mask[static_cast<size_t>(row * width + col)] = coeff;
            }
        }
    }
    return mask;
}

const std::vector<double> &get_conv_mask_template(int height, int width, int row_offset,
                                                  int col_offset, HeEnvironment &env)
{
    const HeEnvironment::ConvMaskKey key{height, width, row_offset, col_offset};
    auto it = env.conv_mask_cache.find(key);
    if (it != env.conv_mask_cache.end())
    {
        return it->second;
    }

    auto [inserted_it, _] = env.conv_mask_cache.emplace(
        key, build_conv_mask(height, width, row_offset, col_offset, env.slot_count, 1.0));
    return inserted_it->second;
}

std::vector<std::vector<double>> build_downsample_matrix(int input_height, int input_width,
                                                         int output_height, int output_width,
                                                         int slot_count)
{
    std::vector<std::vector<double>> matrix(static_cast<size_t>(slot_count),
                                            std::vector<double>(static_cast<size_t>(slot_count), 0.0));
    for (int row = 0; row < output_height; ++row)
    {
        for (int col = 0; col < output_width; ++col)
        {
            const int target = row * output_width + col;
            const int source = (row * 2) * input_width + col * 2;
            matrix[static_cast<size_t>(target)][static_cast<size_t>(source)] = 1.0;
        }
    }
    return matrix;
}

Ciphertext apply_downsample_transform(const Ciphertext &cipher, int input_height, int input_width,
                                      HeEnvironment &env)
{
    const int output_height = input_height / 2;
    const int output_width = input_width / 2;
    const HeEnvironment::DownsampleKey key{
        input_height, input_width, static_cast<uint32_t>(cipher.level()),
        static_cast<int64_t>(std::llround(std::log2(cipher.scale())))};
    auto matrix_it = env.downsample_matrix_cache.find(key);
    if (matrix_it == env.downsample_matrix_cache.end())
    {
        std::vector<std::vector<double>> matrix = build_downsample_matrix(
            input_height, input_width, output_height, output_width, env.slot_count);
        MatrixPlain plain_matrix;
        std::vector<int> rotate_index;
        gen_matrix_form_bsgs(plain_matrix, rotate_index, env.encoder, matrix,
                             static_cast<uint32_t>(cipher.level()), cipher.scale(), 1,
                             env.context.parameters_literal()->log_slots());
        matrix_it = env.downsample_matrix_cache.emplace(key, std::move(plain_matrix)).first;
    }

    Ciphertext result;
    env.evaluator->multiply_by_diag_matrix_bsgs(cipher, matrix_it->second, result, env.galois_keys);
    return result;
}

Ciphertext encrypted_conv_term(const Ciphertext &cipher, int height, int width, int row_offset,
                               int col_offset, double coeff, HeEnvironment &env)
{
    Ciphertext rotated = cipher;
    const int rotation = row_offset * width + col_offset;
    if (rotation != 0)
    {
        env.evaluator->rotate(cipher, rotated, rotation, env.galois_keys);
    }
    const std::vector<double> &base_mask =
        get_conv_mask_template(height, width, row_offset, col_offset, env);
    std::vector<double> scaled_mask = base_mask;
    for (double &value : scaled_mask)
    {
        value *= coeff;
    }
    Plaintext plain = encode_with_consistent_level(scaled_mask, rotated, env.encoder);
    Ciphertext term;
    env.evaluator->multiply_plain(rotated, plain, term);
    env.evaluator->rescale(term, term);
    return term;
}

std::vector<std::vector<Ciphertext>> precompute_rotated_inputs(const HeFeatureMap &input,
                                                               HeEnvironment &env)
{
    std::vector<std::vector<Ciphertext>> rotated(input.channels.size());
    for (size_t ic = 0; ic < input.channels.size(); ++ic)
    {
        rotated[ic].reserve(9);
        for (int kh = 0; kh < 3; ++kh)
        {
            for (int kw = 0; kw < 3; ++kw)
            {
                const int row_offset = kh - 1;
                const int col_offset = kw - 1;
                const int rotation = row_offset * input.width + col_offset;
                Ciphertext rotated_cipher = input.channels[ic];
                if (rotation != 0)
                {
                    env.evaluator->rotate(input.channels[ic], rotated_cipher, rotation,
                                          env.galois_keys);
                }
                rotated[ic].push_back(std::move(rotated_cipher));
            }
        }
    }
    return rotated;
}

Ciphertext multiply_const_checked(const Ciphertext &cipher, double value, double scale,
                                  HeEnvironment &env, std::string_view tag);

std::vector<std::complex<double>> trim_trailing_near_zero(std::vector<std::complex<double>> coeffs)
{
    while (coeffs.size() > 1 && std::abs(coeffs.back()) < 1e-18)
    {
        coeffs.pop_back();
    }
    return coeffs;
}

std::vector<std::complex<double>> add_chebyshev_coeff_vectors(
    const std::vector<std::complex<double>> &lhs, const std::vector<std::complex<double>> &rhs)
{
    std::vector<std::complex<double>> result(std::max(lhs.size(), rhs.size()),
                                             std::complex<double>(0.0, 0.0));
    for (size_t i = 0; i < lhs.size(); ++i)
    {
        result[i] += lhs[i];
    }
    for (size_t i = 0; i < rhs.size(); ++i)
    {
        result[i] += rhs[i];
    }
    return trim_trailing_near_zero(std::move(result));
}

std::vector<std::complex<double>> multiply_chebyshev_by_basis(
    const std::vector<std::complex<double>> &coeffs, int basis_degree)
{
    if (basis_degree < 0)
    {
        throw std::invalid_argument("Chebyshev basis degree must be non-negative");
    }
    if (basis_degree == 0)
    {
        return coeffs;
    }

    std::vector<std::complex<double>> result(
        coeffs.size() + static_cast<size_t>(basis_degree), std::complex<double>(0.0, 0.0));
    for (size_t degree = 0; degree < coeffs.size(); ++degree)
    {
        const std::complex<double> coeff = coeffs[degree];
        if (std::abs(coeff) < 1e-18)
        {
            continue;
        }
        if (degree == 0)
        {
            result[static_cast<size_t>(basis_degree)] += coeff;
        }
        else
        {
            result[degree + static_cast<size_t>(basis_degree)] += coeff * 0.5;
            result[static_cast<size_t>(std::abs(static_cast<int>(degree) - basis_degree))] +=
                coeff * 0.5;
        }
    }
    return trim_trailing_near_zero(std::move(result));
}

std::vector<std::complex<double>> build_activation_component_chebyshev_coeffs(
    const ActivationComponentSpec &component, int tree_index)
{
    const int split_degree = component.tree[static_cast<size_t>(tree_index)];
    if (split_degree == 0)
    {
        const int degree = component.decomp_degrees[static_cast<size_t>(tree_index)];
        const int start_index = component.leaf_start_indices[static_cast<size_t>(tree_index)];
        if (degree < 0 || start_index < 0)
        {
            throw std::runtime_error("activation leaf metadata is invalid");
        }

        std::vector<std::complex<double>> coeffs(static_cast<size_t>(degree + 1),
                                                 std::complex<double>(0.0, 0.0));
        for (int odd_degree = 1; odd_degree <= degree; odd_degree += 2)
        {
            const size_t coeff_index = static_cast<size_t>(start_index + odd_degree - 1);
            if (coeff_index >= component.raw_coeffs.size())
            {
                throw std::runtime_error("activation leaf coefficient index is out of range");
            }
            coeffs[static_cast<size_t>(odd_degree)] =
                std::complex<double>(component.raw_coeffs[coeff_index], 0.0);
        }
        return trim_trailing_near_zero(std::move(coeffs));
    }

    const std::vector<std::complex<double>> remainder =
        build_activation_component_chebyshev_coeffs(component, tree_index * 2);
    const std::vector<std::complex<double>> quotient =
        build_activation_component_chebyshev_coeffs(component, tree_index * 2 + 1);
    return add_chebyshev_coeff_vectors(remainder,
                                       multiply_chebyshev_by_basis(quotient, split_degree));
}

PolynomialVector build_activation_component_polynomial_vector(
    const ActivationComponentSpec &component, int slot_count)
{
    std::vector<std::complex<double>> coeffs = component.chebyshev_coeffs;
    if (coeffs.empty())
    {
        coeffs.push_back(std::complex<double>(0.0, 0.0));
    }

    Polynomial poly(coeffs, 0, 0, component.degree, Chebyshev);
    poly.lead() = true;

    std::vector<std::vector<int>> slots_index(1, std::vector<int>(static_cast<size_t>(slot_count)));
    for (int slot = 0; slot < slot_count; ++slot)
    {
        slots_index[0][static_cast<size_t>(slot)] = slot;
    }
    return PolynomialVector(std::vector<Polynomial>{poly}, slots_index);
}

void ensure_scalar_encodable(double value, double scale, const Ciphertext &cipher,
                             const HeEnvironment &env, std::string_view tag)
{
    auto context_data = env.context.crt_context()->get_context_data(cipher.parms_id());
    const double scaled_value = std::abs(value) * scale;
    const double coeff_bits = scaled_value <= 0.0 ? 0.0 : (std::log2(scaled_value) + 2.0);
    const double total_bits = static_cast<double>(context_data->total_coeff_modulus_bit_count());
    if (!(coeff_bits < total_bits))
    {
        std::ostringstream oss;
        oss << tag << " scalar encode overflow: value=" << value << ", scale=" << scale
            << ", coeff_bits=" << coeff_bits << ", total_bits=" << total_bits
            << ", level=" << cipher.level();
        throw std::runtime_error(oss.str());
    }
}

Ciphertext multiply_const_checked(const Ciphertext &cipher, double value, double scale,
                                  HeEnvironment &env, std::string_view tag)
{
    ensure_scalar_encodable(value, scale, cipher, env, tag);
    Ciphertext result;
    env.evaluator->multiply_const(cipher, value, scale, result, env.encoder);
    return result;
}

void add_const_checked(Ciphertext &cipher, double value, HeEnvironment &env, std::string_view tag)
{
    ensure_scalar_encodable(value, cipher.scale(), cipher, env, tag);
    env.evaluator->add_const(cipher, value, cipher, env.encoder);
}

void log_cipher_metadata(std::ostream &log, std::string_view tag, const Ciphertext &cipher)
{
    timed_log(log) << tag << ": level=" << cipher.level() << ", scale=" << cipher.scale()
                   << ", log2_scale=" << std::log2(cipher.scale())
                   << ", coeff_modulus_size=" << cipher.coeff_modulus_size();
}

Ciphertext encrypted_fhe_mp_cnn_relu(const Ciphertext &cipher, HeEnvironment &env, std::ostream *log,
                                     std::string_view tag, size_t channel_index)
{
    Ciphertext original = cipher;
    Ciphertext sign_half = cipher;
    for (size_t component_index = 0; component_index < env.activation_spec.components.size();
         ++component_index)
    {
        const ActivationComponentSpec &component = env.activation_spec.components[component_index];
        const PolynomialVector polys =
            build_activation_component_polynomial_vector(component, env.slot_count);
        util::Timestacs component_timer;
        component_timer.start();
        env.evaluator->evaluate_poly_vector(sign_half, sign_half, polys, sign_half.scale(),
                                            env.relin_keys, env.encoder);
        component_timer.end();
        if (log)
        {
            timed_log(*log) << tag << " channel " << channel_index << " component "
                            << component_index << " time : "
                            << component_timer.microseconds() / 1000 << " ms";
            Plaintext component_plain;
            env.decryptor.decrypt(sign_half, component_plain);
            std::vector<std::complex<double>> component_decoded;
            env.encoder.decode(component_plain, component_decoded);
            log_decoded_vector_stats(*log,
                                     std::string(tag) + " channel " + std::to_string(channel_index) +
                                         " component " + std::to_string(component_index) + " stats",
                                     component_decoded, env.slot_count);
        }
    }
    if (log)
    {
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " sign_half before bias",
                            sign_half);
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " original before final multiply",
                            original);
    }
    add_const_checked(sign_half, 0.5, env, "activation_final_bias");
    if (log)
    {
        Plaintext biased_plain;
        env.decryptor.decrypt(sign_half, biased_plain);
        std::vector<std::complex<double>> biased_decoded;
        env.encoder.decode(biased_plain, biased_decoded);
        log_decoded_vector_stats(*log,
                                 std::string(tag) + " channel " +
                                     std::to_string(channel_index) + " biased gate stats",
                                 biased_decoded, env.slot_count);
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " sign_half after bias",
                            sign_half);
    }

    Ciphertext gate = sign_half;
    Ciphertext aligned_original = original;
    match_levels(gate, aligned_original, *env.evaluator);
    if (log)
    {
        Plaintext gate_plain;
        env.decryptor.decrypt(gate, gate_plain);
        std::vector<std::complex<double>> gate_decoded;
        env.encoder.decode(gate_plain, gate_decoded);
        log_decoded_vector_stats(*log,
                                 std::string(tag) + " channel " +
                                     std::to_string(channel_index) + " gate after level align stats",
                                 gate_decoded, env.slot_count);
        Plaintext original_plain;
        env.decryptor.decrypt(aligned_original, original_plain);
        std::vector<std::complex<double>> original_decoded;
        env.encoder.decode(original_plain, original_decoded);
        log_decoded_vector_stats(*log,
                                 std::string(tag) + " channel " +
                                     std::to_string(channel_index) +
                                     " original after level align stats",
                                 original_decoded, env.slot_count);
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " gate after align",
                            gate);
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " original after align",
                            aligned_original);
    }

    Ciphertext result;
    env.evaluator->multiply_relin_dynamic(gate, aligned_original, result, env.relin_keys);
    env.evaluator->rescale(result, result);
    if (log)
    {
        log_cipher_metadata(*log,
                            std::string(tag) + " channel " + std::to_string(channel_index) +
                                " relu result metadata",
                            result);
    }
    return result;
}

HeFeatureMap apply_encrypted_relu(const HeFeatureMap &input, HeEnvironment &env, std::ostream *log,
                                 std::string_view tag)
{
    HeFeatureMap result;
    result.height = input.height;
    result.width = input.width;
    result.channels.reserve(input.channels.size());
    util::Timestacs timer;
    for (size_t channel_index = 0; channel_index < input.channels.size(); ++channel_index)
    {
        timer.start();
        result.channels.push_back(
            encrypted_fhe_mp_cnn_relu(input.channels[channel_index], env, log, tag, channel_index));
        timer.end();
        if (log)
        {
            timed_log(*log) << tag << " channel " << channel_index << " relu time : "
                            << timer.microseconds() / 1000 << " ms";
        }
    }
    return result;
}

Ciphertext encrypted_bootstrap(const Ciphertext &cipher, HeEnvironment &env)
{
    if (!env.bootstrap_poly)
    {
        throw std::runtime_error("bootstrap configuration is not available in this HE environment");
    }
    Ciphertext result;
    env.evaluator->bootstrap(cipher, result, env.relin_keys, env.galois_keys, env.encoder,
                             *env.bootstrap_poly);
    env.evaluator->rescale_dynamic(result, result, env.scale);
    return result;
}

HeFeatureMap apply_encrypted_bootstrap(const HeFeatureMap &input, HeEnvironment &env)
{
    HeFeatureMap result;
    result.height = input.height;
    result.width = input.width;
    result.channels.reserve(input.channels.size());
    for (const Ciphertext &cipher : input.channels)
    {
        result.channels.push_back(encrypted_bootstrap(cipher, env));
    }
    return result;
}

HeFeatureMap encrypted_convolution(const HeFeatureMap &input, const std::vector<double> &weights,
                                   int out_channels, int stride, WeightLayout weight_layout,
                                   HeEnvironment &env)
{
    HeFeatureMap result;
    result.height = stride == 2 ? input.height / 2 : input.height;
    result.width = stride == 2 ? input.width / 2 : input.width;
    result.channels.reserve(static_cast<size_t>(out_channels));
    const std::vector<std::vector<Ciphertext>> rotated_inputs = precompute_rotated_inputs(input, env);

    for (int oc = 0; oc < out_channels; ++oc)
    {
        bool initialized = false;
        Ciphertext sum;

        for (int ic = 0; ic < static_cast<int>(input.channels.size()); ++ic)
        {
            for (int kh = 0; kh < 3; ++kh)
            {
                for (int kw = 0; kw < 3; ++kw)
                {
                    const int flat_index = kh * 3 + kw;
                    const double coeff =
                        conv_weight_at(weights, weight_layout, oc, ic, kh, kw,
                                       static_cast<int>(input.channels.size()), out_channels);
                    if (std::abs(coeff) < 1e-12)
                    {
                        continue;
                    }

                    const std::vector<double> &base_mask =
                        get_conv_mask_template(input.height, input.width, kh - 1, kw - 1, env);
                    std::vector<double> scaled_mask = base_mask;
                    for (double &value : scaled_mask)
                    {
                        value *= coeff;
                    }
                    Plaintext plain = encode_with_consistent_level(
                        scaled_mask, rotated_inputs[static_cast<size_t>(ic)][static_cast<size_t>(flat_index)],
                        env.encoder);
                    Ciphertext term;
                    env.evaluator->multiply_plain(
                        rotated_inputs[static_cast<size_t>(ic)][static_cast<size_t>(flat_index)],
                        plain, term);
                    env.evaluator->rescale(term, term);
                    if (!initialized)
                    {
                        sum = std::move(term);
                        initialized = true;
                    }
                    else
                    {
                        add_inplace_fast(sum, std::move(term), env);
                    }
                }
            }
        }

        if (!initialized)
        {
            sum = make_zero_like(input.channels.front(), env);
        }

        if (stride == 2)
        {
            sum = apply_downsample_transform(sum, input.height, input.width, env);
        }

        result.channels.push_back(std::move(sum));
    }

    return result;
}

HeFeatureMap align_feature_map_to_reference_scale(const HeFeatureMap &input, HeEnvironment &env)
{
    HeFeatureMap result = input;
    for (Ciphertext &cipher : result.channels)
    {
        if (cipher.scale() > env.scale * 1.5)
        {
            env.evaluator->rescale_dynamic(cipher, cipher, env.scale);
        }
        cipher.scale() = env.scale;
    }
    return result;
}

// This follows the same stage split as FHE-MP-CNN:
// convolution first applies the BN multiplicative factor, then batch norm
// subtracts the precomputed shift term in a separate pass.
HeFeatureMap encrypted_convolution_with_channel_multiplier(
    const HeFeatureMap &input, const std::vector<double> &weights,
    const std::vector<double> *channel_multiplier, int out_channels, int stride,
    WeightLayout weight_layout, HeEnvironment &env)
{
    HeFeatureMap result;
    result.height = stride == 2 ? input.height / 2 : input.height;
    result.width = stride == 2 ? input.width / 2 : input.width;
    result.channels.reserve(static_cast<size_t>(out_channels));
    const std::vector<std::vector<Ciphertext>> rotated_inputs = precompute_rotated_inputs(input, env);

    for (int oc = 0; oc < out_channels; ++oc)
    {
        const double output_multiplier =
            channel_multiplier ? (*channel_multiplier)[static_cast<size_t>(oc)] : 1.0;
        bool initialized = false;
        Ciphertext sum;

        for (int ic = 0; ic < static_cast<int>(input.channels.size()); ++ic)
        {
            for (int kh = 0; kh < 3; ++kh)
            {
                for (int kw = 0; kw < 3; ++kw)
                {
                    const int flat_index = kh * 3 + kw;
                    const double coeff =
                        conv_weight_at(weights, weight_layout, oc, ic, kh, kw,
                                       static_cast<int>(input.channels.size()), out_channels) *
                        output_multiplier;
                    if (std::abs(coeff) < 1e-12)
                    {
                        continue;
                    }

                    const std::vector<double> &base_mask =
                        get_conv_mask_template(input.height, input.width, kh - 1, kw - 1, env);
                    std::vector<double> scaled_mask = base_mask;
                    for (double &value : scaled_mask)
                    {
                        value *= coeff;
                    }
                    Plaintext plain = encode_with_consistent_level(
                        scaled_mask,
                        rotated_inputs[static_cast<size_t>(ic)][static_cast<size_t>(flat_index)],
                        env.encoder);
                    Ciphertext term;
                    env.evaluator->multiply_plain(
                        rotated_inputs[static_cast<size_t>(ic)][static_cast<size_t>(flat_index)],
                        plain, term);
                    env.evaluator->rescale(term, term);
                    if (!initialized)
                    {
                        sum = std::move(term);
                        initialized = true;
                    }
                    else
                    {
                        add_inplace_fast(sum, std::move(term), env);
                    }
                }
            }
        }

        if (!initialized)
        {
            sum = make_zero_like(input.channels.front(), env);
        }

        if (stride == 2)
        {
            sum = apply_downsample_transform(sum, input.height, input.width, env);
        }

        result.channels.push_back(std::move(sum));
    }

    return result;
}

HeFeatureMap encrypted_batch_norm(const HeFeatureMap &input, const BatchNormParams &bn,
                                  HeEnvironment &env)
{
    if (input.channels.size() != bn.bias.size())
    {
        throw std::invalid_argument("encrypted batch norm shape mismatch");
    }

    HeFeatureMap result;
    result.height = input.height;
    result.width = input.width;
    result.channels.reserve(input.channels.size());

    for (size_t channel_index = 0; channel_index < input.channels.size(); ++channel_index)
    {
        const double shift =
            batch_norm_shift(bn, static_cast<int>(channel_index)) / kFheMpCnnApproximationBoundary;
        Ciphertext channel = input.channels[channel_index];
        add_const_checked(channel, shift, env, "batch_norm_shift");
        result.channels.push_back(std::move(channel));
    }

    return result;
}

HeFeatureMap encrypted_shortcut_option_a(const HeFeatureMap &input, int out_channels,
                                         HeEnvironment &env);
HeFeatureMap add_feature_maps(const HeFeatureMap &lhs, const HeFeatureMap &rhs, HeEnvironment &env);
std::vector<Ciphertext> encrypted_linear_logits(const HeFeatureMap &feature_map,
                                                const ResNet20Weights &weights, HeEnvironment &env);

std::vector<double> batch_norm_channel_multipliers(const BatchNormParams &bn)
{
    std::vector<double> multipliers(bn.weight.size(), 1.0);
    for (size_t i = 0; i < multipliers.size(); ++i)
    {
        multipliers[i] = batch_norm_multiplier(bn, static_cast<int>(i));
    }
    return multipliers;
}

HeFeatureMap multiplexed_parallel_convolution_poseidon(const HeFeatureMap &input,
                                                       const std::vector<double> &weights,
                                                       const BatchNormParams &bn, int out_channels,
                                                       int stride, WeightLayout weight_layout,
                                                       HeEnvironment &env)
{
    const std::vector<double> multipliers = batch_norm_channel_multipliers(bn);
    return encrypted_convolution_with_channel_multiplier(input, weights, &multipliers,
                                                         out_channels, stride, weight_layout, env);
}

HeFeatureMap multiplexed_parallel_batch_norm_poseidon(const HeFeatureMap &input,
                                                      const BatchNormParams &bn, HeEnvironment &env)
{
    return encrypted_batch_norm(input, bn, env);
}

HeFeatureMap approx_relu_poseidon(const HeFeatureMap &input, HeEnvironment &env, std::ostream *log,
                                  std::string_view tag)
{
    return apply_encrypted_relu(input, env, log, tag);
}

HeFeatureMap bootstrap_poseidon(const HeFeatureMap &input, HeEnvironment &env)
{
    return apply_encrypted_bootstrap(input, env);
}

HeFeatureMap cipher_add_poseidon(const HeFeatureMap &lhs, const HeFeatureMap &rhs,
                                 HeEnvironment &env)
{
    return add_feature_maps(lhs, rhs, env);
}

HeFeatureMap multiplexed_parallel_downsampling_poseidon(const HeFeatureMap &input, int out_channels,
                                                        HeEnvironment &env)
{
    return encrypted_shortcut_option_a(input, out_channels, env);
}

std::vector<Ciphertext> fully_connected_poseidon(const HeFeatureMap &feature_map,
                                                 const ResNet20Weights &weights,
                                                 HeEnvironment &env)
{
    return encrypted_linear_logits(feature_map, weights, env);
}

HeFeatureMap encrypted_shortcut_option_a(const HeFeatureMap &input, int out_channels,
                                         HeEnvironment &env)
{
    HeFeatureMap result;
    result.height = input.height / 2;
    result.width = input.width / 2;
    result.channels.resize(static_cast<size_t>(out_channels));

    const int pad = (out_channels - static_cast<int>(input.channels.size())) / 2;
    Ciphertext zero = make_zero_like(input.channels.front(), env);
    for (int i = 0; i < out_channels; ++i)
    {
        result.channels[static_cast<size_t>(i)] = zero;
    }

    for (int c = 0; c < static_cast<int>(input.channels.size()); ++c)
    {
        result.channels[static_cast<size_t>(c + pad)] =
            apply_downsample_transform(input.channels[static_cast<size_t>(c)], input.height,
                                       input.width, env);
    }
    return result;
}

HeFeatureMap add_feature_maps(const HeFeatureMap &lhs, const HeFeatureMap &rhs, HeEnvironment &env)
{
    if (lhs.height != rhs.height || lhs.width != rhs.width || lhs.channels.size() != rhs.channels.size())
    {
        throw std::invalid_argument("encrypted feature map shape mismatch");
    }

    HeFeatureMap result;
    result.height = lhs.height;
    result.width = lhs.width;
    result.channels.resize(lhs.channels.size());

    for (size_t i = 0; i < lhs.channels.size(); ++i)
    {
        Ciphertext sum = lhs.channels[i];
        Ciphertext other = rhs.channels[i];
        add_inplace_fast(sum, std::move(other), env);
        result.channels[i] = std::move(sum);
    }
    return result;
}

Ciphertext average_pool_cipher(const Ciphertext &cipher, int active_slots, HeEnvironment &env)
{
    Ciphertext result = cipher;
    for (int step = 1; step < active_slots; step <<= 1)
    {
        Ciphertext rotated;
        env.evaluator->rotate(result, rotated, step, env.galois_keys);
        env.evaluator->add(result, rotated, result);
    }

    std::vector<double> mask(static_cast<size_t>(env.slot_count), 0.0);
    mask[0] = kFheMpCnnApproximationBoundary / static_cast<double>(active_slots);
    Plaintext plain = encode_with_consistent_level(mask, result, env.encoder);
    env.evaluator->multiply_plain(result, plain, result);
    env.evaluator->rescale(result, result);
    return result;
}

std::vector<double> decrypt_logits(const std::vector<Ciphertext> &logit_ciphers, HeEnvironment &env)
{
    std::vector<double> logits(logit_ciphers.size(), 0.0);
    for (size_t i = 0; i < logit_ciphers.size(); ++i)
    {
        Plaintext plain;
        env.decryptor.decrypt(logit_ciphers[i], plain);
        std::vector<std::complex<double>> decoded;
        env.encoder.decode(plain, decoded);
        logits[i] = decoded[0].real();
    }
    return logits;
}

std::vector<Ciphertext> encrypted_linear_logits(const HeFeatureMap &feature_map,
                                                const ResNet20Weights &weights, HeEnvironment &env)
{
    if (feature_map.height != 8 || feature_map.width != 8 || feature_map.channels.size() != 64)
    {
        throw std::invalid_argument("encrypted linear head expects a full 64x8x8 feature map");
    }

    std::vector<Ciphertext> pooled(64);
    for (int c = 0; c < 64; ++c)
    {
        pooled[static_cast<size_t>(c)] =
            average_pool_cipher(feature_map.channels[static_cast<size_t>(c)], 64, env);
    }

    std::vector<Ciphertext> logits(static_cast<size_t>(kClasses));
    for (int out = 0; out < kClasses; ++out)
    {
        bool initialized = false;
        Ciphertext sum;
        for (int in = 0; in < 64; ++in)
        {
            std::vector<double> coeff_mask(static_cast<size_t>(env.slot_count), 0.0);
            coeff_mask[0] = weights.linear_weight[static_cast<size_t>(out * 64 + in)];
            Plaintext plain = encode_with_consistent_level(coeff_mask, pooled[static_cast<size_t>(in)],
                                                           env.encoder);
            Ciphertext term;
            env.evaluator->multiply_plain(pooled[static_cast<size_t>(in)], plain, term);
            env.evaluator->rescale(term, term);
            if (!initialized)
            {
                sum = std::move(term);
                initialized = true;
            }
            else
            {
                add_inplace_fast(sum, std::move(term), env);
            }
        }

        std::vector<double> bias_mask(static_cast<size_t>(env.slot_count), 0.0);
        bias_mask[0] = weights.linear_bias[static_cast<size_t>(out)];
        Plaintext bias_plain = encode_with_consistent_level(bias_mask, sum, env.encoder);
        env.evaluator->add_plain(sum, bias_plain, sum);
        logits[static_cast<size_t>(out)] = std::move(sum);
    }
    return logits;
}

HeForwardResult run_he_forward(const Tensor3D &image, const ResNet20Weights &weights,
                               WeightLayout weight_layout, int max_blocks,
                               HeActivation activation, const fs::path &relu_coeffs_path,
                               std::ostream &log)
{
    (void)activation;
    auto env = create_he_environment(relu_coeffs_path, max_blocks, log);
    util::Timestacs timer;
    PackedTensorCipher packed_input = encrypt_image_to_packed_tensor(image, *env);
    timed_log(log) << "he packed input log_slots : " << packed_input.log_slots;
    timed_log(log) << "he packed input replication_p : " << packed_input.p;
    timed_log(log) << "he packed input base_slots : "
                   << (packed_input.k * packed_input.k * packed_input.h * packed_input.w *
                       packed_input.t);
    {
        const Tensor3D packed_roundtrip = decrypt_packed_input_tensor(packed_input, *env);
        double mse = 0.0;
        for (size_t i = 0; i < packed_roundtrip.values.size(); ++i)
        {
            const double plain_scaled =
                image.values[i] / kFheMpCnnApproximationBoundary;
            const double diff = plain_scaled - packed_roundtrip.values[i];
            mse += diff * diff;
        }
        mse /= static_cast<double>(packed_roundtrip.values.size());
        timed_log(log) << "he packed input roundtrip mse : " << mse;
    }
    HeFeatureMap x;
    PackedTensorCipher packed_x;
    bool use_packed_path = false;
    const bool packed_stem_supported =
        env->slot_count >= (kImageSize * kImageSize * kStemChannels);
    if (packed_stem_supported)
    {
        timed_log(log) << "he stem path : packed";
        timer.start();
        packed_x = packed_convolution_stride1_poseidon(
            packed_input, weights.stem_conv_weight, weights.stem_bn, weight_layout,
            kStemChannels, *env, &log);
        timer.end();
        timed_log(log) << "he stem packed conv time : " << timer.microseconds() / 1000 << " ms";
        timed_log(log) << "he stem packed output replication_p : " << packed_x.p;
        log_packed_tensor_stats(log, "he stem packed conv stats", packed_x, *env);
        timer.start();
        packed_x = align_packed_tensor_to_reference_scale(packed_x, *env);
        timer.end();
        timed_log(log) << "he stem packed scale-adjust time : "
                       << timer.microseconds() / 1000 << " ms";
        timer.start();
        packed_x = packed_batch_norm_poseidon(packed_x, weights.stem_bn, *env);
        timer.end();
        timed_log(log) << "he stem packed bn time : " << timer.microseconds() / 1000 << " ms";
        log_packed_tensor_stats(log, "he stem packed bn stats", packed_x, *env);
        timer.start();
        packed_x = packed_relu_poseidon(packed_x, *env, &log, "he stem packed");
        timer.end();
        timed_log(log) << "he stem packed relu total time : "
                       << timer.microseconds() / 1000 << " ms";
        log_packed_tensor_stats(log, "he stem packed relu stats", packed_x, *env);
        use_packed_path = true;
    }
    else
    {
        timed_log(log) << "he stem path : channelwise-fallback";
        x = encrypt_image_to_feature_map(image, *env);
        timer.start();
        x = multiplexed_parallel_convolution_poseidon(
            x, weights.stem_conv_weight, weights.stem_bn, 16, 1, weight_layout, *env);
        timer.end();
        timed_log(log) << "he stem conv time : " << timer.microseconds() / 1000 << " ms";
        timer.start();
        x = align_feature_map_to_reference_scale(x, *env);
        timer.end();
        timed_log(log) << "he stem scale-adjust time : " << timer.microseconds() / 1000 << " ms";
        timer.start();
        x = multiplexed_parallel_batch_norm_poseidon(x, weights.stem_bn, *env);
        timer.end();
        timed_log(log) << "he stem bn time : " << timer.microseconds() / 1000 << " ms";
        timer.start();
        x = approx_relu_poseidon(x, *env, &log, "he stem");
        timer.end();
        timed_log(log) << "he stem relu time : " << timer.microseconds() / 1000 << " ms";
    }
    if (use_packed_path)
    {
        timer.start();
        const Tensor3D packed_decrypted = decrypt_packed_feature_map(packed_x, *env);
        timer.end();
        timed_log(log) << "he stem unpack time : " << timer.microseconds() / 1000 << " ms";
        log_tensor_stats(log, "layer 0 (decrypted)", packed_decrypted);
    }
    else
    {
        log_tensor_stats(log, "layer 0 (decrypted)", decrypt_feature_map(x, *env));
    }

    int completed_blocks = 0;
    for (int stage = 0; stage < 3; ++stage)
    {
        for (int block = 0; block < kBlocksPerStage; ++block)
        {
            if (max_blocks != -1 && completed_blocks >= max_blocks)
            {
                HeForwardResult result;
                if (use_packed_path)
                {
                    result.decrypted_feature_map = decrypt_packed_feature_map(packed_x, *env);
                    if (packed_x.c == 64 && packed_x.h == 8 && packed_x.w == 8)
                    {
                        PackedTensorCipher packed_gap = packed_average_pool_poseidon(packed_x, *env);
                        result.logits =
                            decrypt_logits(packed_fully_connected_poseidon(packed_gap, weights, *env),
                                           *env);
                        result.has_logits = true;
                    }
                }
                else
                {
                    result.decrypted_feature_map = decrypt_feature_map(x, *env);
                    if (x.channels.size() == 64 && x.height == 8 && x.width == 8)
                    {
                        result.logits =
                            decrypt_logits(fully_connected_poseidon(x, weights, *env), *env);
                        result.has_logits = true;
                    }
                }
                result.completed_blocks = completed_blocks;
                return result;
            }

            if (use_packed_path)
            {
                const ConvBlockParams &params = weights.stages[stage][block];
                const int stride = (stage > 0 && block == 0) ? 2 : 1;
                PackedTensorCipher identity = packed_x;

                timer.start();
                PackedTensorCipher y = packed_convolution_poseidon(
                    packed_x, params.conv1_weight, params.bn1, params.conv1_out_channels, stride,
                    weight_layout, *env, &log, "he block " + std::to_string(completed_blocks + 1) +
                                                    " conv1");
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed conv1 time : " << timer.microseconds() / 1000
                               << " ms";
                y = align_packed_tensor_to_reference_scale(y, *env);
                timer.start();
                y = packed_batch_norm_poseidon(y, params.bn1, *env);
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed bn1 time : " << timer.microseconds() / 1000
                               << " ms";
                log_packed_tensor_stats(
                    log,
                    "he block " + std::to_string(completed_blocks + 1) + " packed bn1 stats", y,
                    *env);
                timer.start();
                y = packed_bootstrap_poseidon(y, *env);
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed bootstrap1 time : "
                               << timer.microseconds() / 1000 << " ms";
                log_packed_tensor_stats(
                    log,
                    "he block " + std::to_string(completed_blocks + 1) +
                        " packed bootstrap1 stats",
                    y, *env);
                timer.start();
                y = packed_relu_poseidon(
                    y, *env, &log,
                    "he block " + std::to_string(completed_blocks + 1) + " packed relu1");
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed relu1 time : " << timer.microseconds() / 1000
                               << " ms";

                timer.start();
                y = packed_convolution_poseidon(
                    y, params.conv2_weight, params.bn2, params.conv2_out_channels, 1, weight_layout,
                    *env, &log, "he block " + std::to_string(completed_blocks + 1) + " conv2");
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed conv2 time : " << timer.microseconds() / 1000
                               << " ms";
                y = align_packed_tensor_to_reference_scale(y, *env);
                timer.start();
                y = packed_batch_norm_poseidon(y, params.bn2, *env);
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed bn2 time : " << timer.microseconds() / 1000
                               << " ms";
                log_packed_tensor_stats(
                    log,
                    "he block " + std::to_string(completed_blocks + 1) + " packed bn2 stats", y,
                    *env);

                if (stride == 2)
                {
                    timer.start();
                    identity = packed_shortcut_option_a_poseidon(identity, params.conv2_out_channels,
                                                                *env);
                    timer.end();
                    timed_log(log) << "he block " << (completed_blocks + 1)
                                   << " packed shortcut time : " << timer.microseconds() / 1000
                                   << " ms";
                }

                timer.start();
                packed_x = packed_add_poseidon(y, identity, *env);
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed add time : " << timer.microseconds() / 1000
                               << " ms";
                log_packed_tensor_stats(
                    log,
                    "he block " + std::to_string(completed_blocks + 1) + " packed add stats",
                    packed_x, *env);
                timer.start();
                packed_x = packed_bootstrap_poseidon(packed_x, *env);
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed bootstrap2 time : "
                               << timer.microseconds() / 1000 << " ms";
                log_packed_tensor_stats(
                    log,
                    "he block " + std::to_string(completed_blocks + 1) +
                        " packed bootstrap2 stats",
                    packed_x, *env);
                timer.start();
                packed_x = packed_relu_poseidon(
                    packed_x, *env, &log,
                    "he block " + std::to_string(completed_blocks + 1) + " packed relu2");
                timer.end();
                timed_log(log) << "he block " << (completed_blocks + 1)
                               << " packed relu2 time : " << timer.microseconds() / 1000
                               << " ms";
                ++completed_blocks;
                HeFeatureMap unpacked = unpack_packed_output_channels(packed_x, *env);
                log_tensor_stats(log, "block " + std::to_string(completed_blocks) + " (decrypted)",
                                 decrypt_feature_map(unpacked, *env));
                continue;
            }

            const ConvBlockParams &params = weights.stages[stage][block];
            const int stride = (stage > 0 && block == 0) ? 2 : 1;
            HeFeatureMap identity = x;

            timer.start();
            HeFeatureMap y = multiplexed_parallel_convolution_poseidon(
                x, params.conv1_weight, params.bn1, params.conv1_out_channels, stride,
                weight_layout, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " conv1 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            y = multiplexed_parallel_batch_norm_poseidon(y, params.bn1, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " bn1 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            y = bootstrap_poseidon(y, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " bootstrap1 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            y = approx_relu_poseidon(
                y, *env, &log, "he block " + std::to_string(completed_blocks + 1) + " relu1");
            timer.end();
            log << "he block " << (completed_blocks + 1) << " relu1 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            y = multiplexed_parallel_convolution_poseidon(
                y, params.conv2_weight, params.bn2, params.conv2_out_channels, 1, weight_layout,
                *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " conv2 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            y = multiplexed_parallel_batch_norm_poseidon(y, params.bn2, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " bn2 time : "
                << timer.microseconds() / 1000 << " ms\n";

            if (stride == 2)
            {
                timer.start();
                identity = multiplexed_parallel_downsampling_poseidon(
                    identity, params.conv2_out_channels, *env);
                timer.end();
                log << "he block " << (completed_blocks + 1) << " shortcut time : "
                    << timer.microseconds() / 1000 << " ms\n";
            }

            timer.start();
            x = cipher_add_poseidon(y, identity, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " add time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            x = bootstrap_poseidon(x, *env);
            timer.end();
            log << "he block " << (completed_blocks + 1) << " bootstrap2 time : "
                << timer.microseconds() / 1000 << " ms\n";
            timer.start();
            x = approx_relu_poseidon(
                x, *env, &log, "he block " + std::to_string(completed_blocks + 1) + " relu2");
            timer.end();
            log << "he block " << (completed_blocks + 1) << " relu2 time : "
                << timer.microseconds() / 1000 << " ms\n";
            ++completed_blocks;
            log_tensor_stats(log, "block " + std::to_string(completed_blocks) + " (decrypted)",
                             decrypt_feature_map(x, *env));
        }
    }

    HeForwardResult result;
    if (use_packed_path)
    {
        result.decrypted_feature_map = decrypt_packed_feature_map(packed_x, *env);
        PackedTensorCipher packed_gap = packed_average_pool_poseidon(packed_x, *env);
        result.logits = decrypt_logits(packed_fully_connected_poseidon(packed_gap, weights, *env),
                                       *env);
    }
    else
    {
        result.decrypted_feature_map = decrypt_feature_map(x, *env);
        result.logits = decrypt_logits(fully_connected_poseidon(x, weights, *env), *env);
    }
    result.completed_blocks = completed_blocks;
    result.has_logits = true;
    return result;
}

} // namespace

int main(int argc, char *argv[])
{
    try
    {
        const Options options = parse_options(argc, argv);
        const fs::path current_dir = fs::path(__FILE__).parent_path();
        const fs::path result_dir = current_dir / "result";
        fs::create_directories(result_dir);

        if (!fs::exists(options.weights_root / "conv1_weight.txt"))
        {
            throw std::runtime_error("weights root does not look valid: " +
                                     options.weights_root.string());
        }
        if (!fs::exists(options.data_root / "test_values.txt"))
        {
            throw std::runtime_error("data root does not look valid: " +
                                     options.data_root.string());
        }

        const ResNet20Weights weights = load_resnet20_weights(options.weights_root);
        const fs::path summary_path = result_dir /
                                      ("resnet20_cifar10_label_" +
                                       std::to_string(options.start_image_id) + "_" +
                                       std::to_string(options.end_image_id));
        std::ofstream summary(summary_path, std::ios::app);
        if (!summary.is_open())
        {
            throw std::runtime_error("cannot open summary output: " + summary_path.string());
        }
        summary << std::unitbuf;
        timed_log(summary) << "==================== run_start ====================";
        timed_log(summary) << "session timestamp: " << current_wallclock_timestamp();

        std::cout << BANNER << std::endl;
        std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
        std::cout << "Weights root: " << options.weights_root << std::endl;
        std::cout << "Data root: " << options.data_root << std::endl;
        std::cout << "Input layout: " << to_string(options.input_layout) << std::endl;
        std::cout << "Weight layout: " << to_string(options.weight_layout) << std::endl;
        std::cout << "Mode: " << to_string(options.mode) << std::endl;
        if (options.mode == RunMode::kHe)
        {
            std::cout << "HE block limit: " << options.he_block_limit << std::endl;
            std::cout << "HE activation: " << to_string(options.he_activation) << std::endl;
            std::cout << "HE ReLU coeffs: " << options.relu_coeffs_path << std::endl;
        }

        const auto all_start = std::chrono::high_resolution_clock::now();
        for (int image_id = options.start_image_id; image_id <= options.end_image_id; ++image_id)
        {
            const auto image_start = std::chrono::high_resolution_clock::now();
            const std::vector<double> image_values =
                read_image_values(options.data_root / "test_values.txt", image_id);
            const int label = read_image_label(options.data_root / "test_label.txt", image_id);
            const Tensor3D image = decode_image(image_values, options.input_layout);

            const fs::path image_output_path =
                result_dir / ("resnet20_cifar10_image" + std::to_string(image_id) + ".txt");
            std::ofstream image_output(image_output_path, std::ios::app);
            if (!image_output.is_open())
            {
                throw std::runtime_error("cannot open image output: " + image_output_path.string());
            }
            image_output << std::unitbuf;

            timed_log(image_output) << "==================== run_start ====================";
            timed_log(image_output) << "session timestamp: " << current_wallclock_timestamp();
            timed_log(image_output) << "image_id: " << image_id;
            timed_log(image_output) << "weights_root: " << options.weights_root;
            timed_log(image_output) << "data_root: " << options.data_root;
            timed_log(image_output) << "input_layout: " << to_string(options.input_layout);
            timed_log(image_output) << "weight_layout: " << to_string(options.weight_layout);
            timed_log(image_output) << "mode: " << to_string(options.mode);
            if (options.mode == RunMode::kHe)
            {
                timed_log(image_output) << "he_block_limit: " << options.he_block_limit;
                timed_log(image_output) << "he_activation: " << to_string(options.he_activation);
                timed_log(image_output) << "relu_coeffs_path: " << options.relu_coeffs_path;
                timed_log(image_output) << "he_approximation_boundary: "
                                        << kFheMpCnnApproximationBoundary;
                timed_log(image_output) << "he_run_start";
            }

            const int plain_block_limit =
                options.mode == RunMode::kHe ? options.he_block_limit : -1;
            std::ostringstream plain_log;
            std::ostream &plain_log_stream =
                options.mode == RunMode::kHe ? static_cast<std::ostream &>(plain_log) : image_output;
            const PlainForwardResult plain_result = run_plaintext_forward(
                image, weights, options.weight_layout, plain_block_limit, plain_log_stream);

            int inferred_label = -1;
            if (options.mode == RunMode::kPlaintext)
            {
                image_output << "logits: " << format_logits(plain_result.logits) << '\n';
                inferred_label = static_cast<int>(std::distance(
                    plain_result.logits.begin(),
                    std::max_element(plain_result.logits.begin(), plain_result.logits.end())));

                if (options.poseidon_roundtrip)
                {
                    const std::vector<std::complex<double>> decoded =
                        poseidon_roundtrip_logits(plain_result.logits);
                    double max_error = 0.0;
                    image_output << "poseidon_roundtrip_logits: (";
                    for (size_t i = 0; i < plain_result.logits.size(); ++i)
                    {
                        if (i != 0)
                        {
                            image_output << ", ";
                        }
                        image_output << decoded[i].real();
                        max_error = std::max(max_error,
                                             std::abs(decoded[i].real() - plain_result.logits[i]));
                    }
                    image_output << ")\n";
                    image_output << "poseidon_roundtrip_max_error: " << max_error << '\n';
                }
            }
            else
            {
                timed_log(image_output) << "he_run_plaintext_reference_ready";
                const HeForwardResult he_result = run_he_forward(
                    image, weights, options.weight_layout, options.he_block_limit,
                    options.he_activation, options.relu_coeffs_path, image_output);
                timed_log(image_output) << "he_completed_blocks: " << he_result.completed_blocks;
                timed_log(image_output) << "plaintext_completed_blocks: "
                                        << plain_result.completed_blocks;
                timed_log(image_output) << "plaintext_reference_stats_begin";
                image_output << plain_log.str();
                timed_log(image_output) << "plaintext_reference_stats_end";

                Tensor3D plain_feature = plain_result.feature_map;
                Tensor3D he_feature = he_result.decrypted_feature_map;
                if (plain_feature.channels == he_feature.channels &&
                    plain_feature.height == he_feature.height &&
                    plain_feature.width == he_feature.width)
                {
                    double mse = 0.0;
                    for (size_t i = 0; i < plain_feature.values.size(); ++i)
                    {
                        const double he_reference =
                            plain_feature.values[i] / kFheMpCnnApproximationBoundary;
                        const double diff = he_reference - he_feature.values[i];
                        mse += diff * diff;
                    }
                    mse /= static_cast<double>(plain_feature.values.size());
                    timed_log(image_output) << "he_plaintext_feature_mse: " << mse;
                }

                if (he_result.has_logits)
                {
                    timed_log(image_output) << "he_logits: " << format_logits(he_result.logits);
                    inferred_label = static_cast<int>(std::distance(
                        he_result.logits.begin(),
                        std::max_element(he_result.logits.begin(), he_result.logits.end())));
                }
                else
                {
                    timed_log(image_output)
                        << "he_logits: unavailable (network stopped before final 64x8x8 feature "
                           "map)";
                }
            }

            timed_log(image_output) << "image label: " << label;
            timed_log(image_output) << "inferred label: " << inferred_label;

            const auto image_end = std::chrono::high_resolution_clock::now();
            const auto elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(image_end - image_start)
                    .count();
            timed_log(image_output) << "total time : " << elapsed_ms << " ms";

            std::cout << "image_id: " << image_id << ", image label: " << label
                      << ", inferred label: " << inferred_label << std::endl;
            timed_log(summary) << "image_id: " << image_id << ", image label: " << label
                               << ", inferred label: " << inferred_label;
        }

        const auto all_end = std::chrono::high_resolution_clock::now();
        const auto total_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(all_end - all_start).count();
        timed_log(summary) << "all threads time : " << total_ms << " ms";
        std::cout << "all threads time : " << total_ms << " ms" << std::endl;
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "resnet20 error: " << ex.what() << std::endl;
        return 1;
    }
}
