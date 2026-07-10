#include "infer_config.h"
#include "parameter_loader.h"
#include "plain_cnn.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;

namespace fs = std::filesystem;

namespace
{

enum class StemPoolMode
{
    AvgPool,
    MaxPool,
};

enum class PlainReluMode
{
    Relu,
    PolynomialRelu,
};

constexpr int kStagePlanes[kResNet50StageCount] = {64, 128, 256, 512};
constexpr int kStageOutputChannels[kResNet50StageCount] = {256, 512, 1024, 2048};

[[noreturn]] void usage_and_exit(const char *argv0)
{
    cerr << "Usage: " << argv0
         << " START_IMAGE_ID END_IMAGE_ID [avgpool|maxpool] [relu|polyrelu]" << endl;
    exit(1);
}

size_t parse_image_id(const char *value, const char *name)
{
    try
    {
        const string text(value);
        size_t parsed = 0;
        const unsigned long long result = stoull(text, &parsed, 10);
        if (parsed != text.size())
        {
            throw invalid_argument("trailing characters");
        }
        return static_cast<size_t>(result);
    }
    catch (const exception &)
    {
        throw invalid_argument(string("invalid ") + name + ": " + value);
    }
}

StemPoolMode parse_stem_pool_mode(const char *value)
{
    const string text(value);
    if (text == "avgpool")
    {
        return StemPoolMode::AvgPool;
    }
    if (text == "maxpool")
    {
        return StemPoolMode::MaxPool;
    }
    throw invalid_argument("invalid stem pool mode: " + text);
}

const char *stem_pool_mode_name(StemPoolMode mode)
{
    return mode == StemPoolMode::MaxPool ? "maxpool" : "avgpool";
}

PlainReluMode parse_plain_relu_mode(const char *value)
{
    const string text(value);
    if (text == "relu")
    {
        return PlainReluMode::Relu;
    }
    if (text == "polyrelu")
    {
        return PlainReluMode::PolynomialRelu;
    }
    throw invalid_argument("invalid plain relu mode: " + text);
}

const char *plain_relu_mode_name(PlainReluMode mode)
{
    return mode == PlainReluMode::PolynomialRelu ? "polyrelu" : "relu";
}

bool try_parse_optional_mode(const char *value, StemPoolMode &stem_pool_mode,
                             PlainReluMode &relu_mode)
{
    const string text(value);
    if (text == "avgpool" || text == "maxpool")
    {
        stem_pool_mode = parse_stem_pool_mode(value);
        return true;
    }
    if (text == "relu" || text == "polyrelu")
    {
        relu_mode = parse_plain_relu_mode(value);
        return true;
    }
    return false;
}

string make_run_timestamp()
{
    const auto now = chrono::system_clock::now();
    const auto time = chrono::system_clock::to_time_t(now);
    tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif

    ostringstream stamp;
    stamp << put_time(&local_tm, "%Y%m%d_%H%M%S");
    return stamp.str();
}

int argmax_index(const vector<double> &values)
{
    if (values.empty())
    {
        throw invalid_argument("argmax input should not be empty");
    }
    return static_cast<int>(max_element(values.begin(), values.end()) - values.begin());
}

void log_logits(const vector<double> &logits, ostream &output)
{
    output << "plain logits:";
    for (double value : logits)
    {
        output << ' ' << value;
    }
    output << '\n';
}

struct PlainInferenceState
{
    PlainTensor tensor;
    size_t conv_idx = 0;
    size_t bn_idx = 0;
};

PlainTensor apply_conv_bn(const PlainTensor &input, int out_channels, int stride, int fh, int fw,
                          const vector<double> &conv_weight, const vector<double> &bn_bias,
                          const vector<double> &bn_running_mean,
                          const vector<double> &bn_running_var, const vector<double> &bn_weight)
{
    PlainTensor conv =
        plain_convolution(input, out_channels, stride, fh, fw, conv_weight, bn_running_var,
                          bn_weight, kBatchNormEpsilon);
    return plain_batch_norm(conv, bn_bias, bn_running_mean, bn_running_var, bn_weight,
                            kBatchNormEpsilon, kResNet50Boundary);
}

PlainTensor apply_plain_relu(const PlainTensor &input, const ReluConfig &relu_config,
                             PlainReluMode relu_mode)
{
    if (relu_mode == PlainReluMode::PolynomialRelu)
    {
        return plain_polynomial_relu_reference(input, relu_config);
    }
    return plain_relu_reference(input);
}

void run_stem(PlainInferenceState &state, const ModelWeights &weights,
              const ReluConfig &relu_config, ostream &log, StemPoolMode stem_pool_mode,
              PlainReluMode relu_mode)
{
    log << "\n========== Stem ==========\n";
    PlainTensor stem = apply_conv_bn(state.tensor, 64, 2, 7, 7,
                                     weights.conv_weight.at(state.conv_idx),
                                     weights.bn_bias.at(state.bn_idx),
                                     weights.bn_running_mean.at(state.bn_idx),
                                     weights.bn_running_var.at(state.bn_idx),
                                     weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;

    stem = apply_plain_relu(stem, relu_config, relu_mode);
    if (stem_pool_mode == StemPoolMode::MaxPool)
    {
        stem = plain_max_pool2d(stem, 3, 2, 1);
    }
    else
    {
        stem = plain_average_pool2d(stem, 3, 2, 1);
    }

    log << "stem pool mode: " << stem_pool_mode_name(stem_pool_mode) << '\n';
    log_plain_tensor("plain stem output", stem, log);
    state.tensor = std::move(stem);
}

void run_bottleneck_block(PlainInferenceState &state, const ModelWeights &weights,
                          int stage_index, int block_index,
                          const ReluConfig &relu_config, ostream &log,
                          PlainReluMode relu_mode)
{
    const int planes = kStagePlanes[stage_index];
    const int out_channels = kStageOutputChannels[stage_index];
    const int stride = (stage_index > 0 && block_index == 0) ? 2 : 1;

    log << "\n========== layer" << (stage_index + 1) << " block " << block_index
        << " ==========\n";

    PlainTensor shortcut = state.tensor;

    PlainTensor branch = apply_conv_bn(state.tensor, planes, 1, 1, 1,
                                       weights.conv_weight.at(state.conv_idx),
                                       weights.bn_bias.at(state.bn_idx),
                                       weights.bn_running_mean.at(state.bn_idx),
                                       weights.bn_running_var.at(state.bn_idx),
                                       weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;
    branch = apply_plain_relu(branch, relu_config, relu_mode);

    branch = apply_conv_bn(branch, planes, stride, 3, 3, weights.conv_weight.at(state.conv_idx),
                           weights.bn_bias.at(state.bn_idx),
                           weights.bn_running_mean.at(state.bn_idx),
                           weights.bn_running_var.at(state.bn_idx),
                           weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;
    branch = apply_plain_relu(branch, relu_config, relu_mode);

    branch = apply_conv_bn(branch, out_channels, 1, 1, 1,
                           weights.conv_weight.at(state.conv_idx),
                           weights.bn_bias.at(state.bn_idx),
                           weights.bn_running_mean.at(state.bn_idx),
                           weights.bn_running_var.at(state.bn_idx),
                           weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;

    if (block_index == 0)
    {
        const size_t downsample_index = static_cast<size_t>(stage_index);
        shortcut = apply_conv_bn(shortcut, out_channels, stride, 1, 1,
                                 weights.downsample_weight.at(downsample_index),
                                 weights.downsample_bn_bias.at(downsample_index),
                                 weights.downsample_bn_running_mean.at(downsample_index),
                                 weights.downsample_bn_running_var.at(downsample_index),
                                 weights.downsample_bn_weight.at(downsample_index));
    }

    PlainTensor output = plain_add(branch, shortcut);
    output = apply_plain_relu(output, relu_config, relu_mode);
    log_plain_tensor("plain block output", output, log);
    state.tensor = std::move(output);
}

vector<double> run_plain_resnet50_for_image(size_t image_id, const ModelWeights &weights,
                                            ostream &log, StemPoolMode stem_pool_mode,
                                            PlainReluMode relu_mode)
{
    PlainInferenceState state;
    const ReluConfig relu_config = default_relu_config(default_poseidon_plan());
    state.tensor = PlainTensor(kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels,
                               read_plain_image_values(image_id, kResNet50Boundary));
    log_plain_tensor("plain input", state.tensor, log);

    run_stem(state, weights, relu_config, log, stem_pool_mode, relu_mode);
    for (int stage = 0; stage < kResNet50StageCount; ++stage)
    {
        for (int block = 0; block < kResNet50BlocksPerStage[stage]; ++block)
        {
            run_bottleneck_block(state, weights, stage, block, relu_config, log, relu_mode);
        }
    }

    PlainTensor pooled = plain_average_pool(state.tensor, kResNet50Boundary);
    log_plain_tensor("plain average pool output", pooled, log);
    return plain_fully_connected(pooled, weights.linear_weight, weights.linear_bias,
                                 kImageNetClassCount, kResNet50FinalChannels);
}

void run_plain_resnet50(size_t start_image_id, size_t end_image_id,
                        StemPoolMode stem_pool_mode, PlainReluMode relu_mode)
{
    fs::create_directories(result_dir());
    const string run_timestamp = make_run_timestamp();
    const fs::path summary_path =
        result_dir() / ("resnet50_plain_label_" + to_string(start_image_id) + "_" +
                        to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream summary(summary_path);
    if (!summary.is_open())
    {
        throw runtime_error("failed to open plain summary result file");
    }

    cout << "Loading ResNet50 ImageNet parameters" << endl;
    cout << "stem pool mode: " << stem_pool_mode_name(stem_pool_mode) << endl;
    cout << "plain relu mode: " << plain_relu_mode_name(relu_mode) << endl;
    ModelWeights weights = load_resnet50_parameters();

    size_t correct = 0;
    const auto all_start = chrono::high_resolution_clock::now();
    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const auto image_start = chrono::high_resolution_clock::now();
        const fs::path image_log_path =
            result_dir() / ("resnet50_plain_image" + to_string(image_id) + "_" + run_timestamp +
                            ".txt");
        ofstream image_log(image_log_path);
        if (!image_log.is_open())
        {
            throw runtime_error("failed to open plain per-image result file");
        }

        image_log << "image_id: " << image_id << '\n';
        image_log << "log_file: " << image_log_path << '\n';
        image_log << "plain_relu_reference: " << plain_relu_mode_name(relu_mode) << '\n';
        image_log << "stem_pool_mode: " << stem_pool_mode_name(stem_pool_mode) << '\n';
        const int image_label = read_image_label(image_id);
        vector<double> logits =
            run_plain_resnet50_for_image(image_id, weights, image_log, stem_pool_mode, relu_mode);
        const int predicted_label = argmax_index(logits);
        if (predicted_label == image_label)
        {
            ++correct;
        }

        const auto image_end = chrono::high_resolution_clock::now();
        const auto image_ms = chrono::duration_cast<chrono::milliseconds>(image_end - image_start);
        log_logits(logits, image_log);
        image_log << "image label: " << image_label << '\n';
        image_log << "plain predicted label: " << predicted_label << '\n';
        image_log << "image time : " << image_ms.count() << " ms\n";

        summary << "image_id: " << image_id << ", image label: " << image_label
                << ", plain predicted label: " << predicted_label
                << ", correct: " << (predicted_label == image_label ? 1 : 0)
                << ", image time : " << image_ms.count() << " ms\n";
        summary.flush();
        cout << "image_id: " << image_id << ", image label: " << image_label
             << ", plain predicted label: " << predicted_label
             << ", correct: " << (predicted_label == image_label ? 1 : 0)
             << ", image time : " << image_ms.count() << " ms" << endl;
    }

    const auto all_end = chrono::high_resolution_clock::now();
    const auto all_ms = chrono::duration_cast<chrono::milliseconds>(all_end - all_start);
    const size_t total = end_image_id - start_image_id + 1;
    const double accuracy = total == 0 ? 0.0 : static_cast<double>(correct) / total;
    cout << "plain total time : " << all_ms.count() << " ms" << endl;
    cout << "plain accuracy : " << correct << "/" << total << " = " << accuracy << endl;
    summary << "\nplain total time : " << all_ms.count() << " ms\n";
    summary << "plain accuracy : " << correct << "/" << total << " = " << accuracy << "\n";
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5)
    {
        usage_and_exit(argv[0]);
    }

    try
    {
        const size_t start_image_id = parse_image_id(argv[1], "start_image_id");
        const size_t end_image_id = parse_image_id(argv[2], "end_image_id");
        if (start_image_id > end_image_id)
        {
            throw invalid_argument("start_image_id must be <= end_image_id");
        }
        StemPoolMode stem_pool_mode = StemPoolMode::AvgPool;
        PlainReluMode relu_mode = PlainReluMode::Relu;
        for (int arg_index = 3; arg_index < argc; ++arg_index)
        {
            if (!try_parse_optional_mode(argv[arg_index], stem_pool_mode, relu_mode))
            {
                throw invalid_argument(string("invalid optional mode: ") + argv[arg_index]);
            }
        }

        run_plain_resnet50(start_image_id, end_image_id, stem_pool_mode, relu_mode);
        return 0;
    }
    catch (const exception &ex)
    {
        cerr << "resnet50_plain error: " << ex.what() << endl;
        return 1;
    }
}
