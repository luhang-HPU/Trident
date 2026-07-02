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

[[noreturn]] void usage_and_exit(const char *argv0)
{
    cerr << "Usage: " << argv0 << " START_IMAGE_ID END_IMAGE_ID [avgpool|maxpool]"
         << endl;
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
                            kBatchNormEpsilon, 40.0);
}

void run_stem(PlainInferenceState &state, const ModelWeights &weights, ostream &log,
              StemPoolMode stem_pool_mode)
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

    stem = plain_relu_reference(stem);
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

void run_block(PlainInferenceState &state, const ModelWeights &weights, int stage_index,
               int block_index, int out_channels, int first_stride, ostream &log)
{
    const int stride = (block_index == 0) ? first_stride : 1;
    log << "\n========== layer" << (stage_index + 1) << " block " << block_index
        << " ==========\n";

    PlainTensor shortcut = state.tensor;
    PlainTensor branch = apply_conv_bn(state.tensor, out_channels, stride, 3, 3,
                                       weights.conv_weight.at(state.conv_idx),
                                       weights.bn_bias.at(state.bn_idx),
                                       weights.bn_running_mean.at(state.bn_idx),
                                       weights.bn_running_var.at(state.bn_idx),
                                       weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;

    branch = plain_relu_reference(branch);

    branch = apply_conv_bn(branch, out_channels, 1, 3, 3, weights.conv_weight.at(state.conv_idx),
                           weights.bn_bias.at(state.bn_idx),
                           weights.bn_running_mean.at(state.bn_idx),
                           weights.bn_running_var.at(state.bn_idx),
                           weights.bn_weight.at(state.bn_idx));
    ++state.conv_idx;
    ++state.bn_idx;

    if (stage_index > 0 && block_index == 0)
    {
        const int downsample_index = stage_index - 1;
        shortcut = apply_conv_bn(shortcut, out_channels, 2, 1, 1,
                                 weights.downsample_weight.at(static_cast<size_t>(downsample_index)),
                                 weights.downsample_bn_bias.at(static_cast<size_t>(downsample_index)),
                                 weights.downsample_bn_running_mean.at(
                                     static_cast<size_t>(downsample_index)),
                                 weights.downsample_bn_running_var.at(
                                     static_cast<size_t>(downsample_index)),
                                 weights.downsample_bn_weight.at(
                                     static_cast<size_t>(downsample_index)));
    }

    PlainTensor output = plain_add(branch, shortcut);
    output = plain_relu_reference(output);
    log_plain_tensor("plain block output", output, log);
    state.tensor = std::move(output);
}

vector<double> run_plain_resnet18_for_image(size_t image_id, const ModelWeights &weights,
                                            ostream &log, StemPoolMode stem_pool_mode)
{
    PlainInferenceState state;
    state.tensor = PlainTensor(kImageNetInputHeight, kImageNetInputWidth, kImageNetInputChannels,
                               read_plain_image_values(image_id, 40.0));
    log_plain_tensor("plain input", state.tensor, log);

    run_stem(state, weights, log, stem_pool_mode);

    const int stage_channels[] = {64, 128, 256, 512};
    const int first_strides[] = {1, 2, 2, 2};
    for (int stage = 0; stage < 4; ++stage)
    {
        for (int block = 0; block < kResNet18BlocksPerStage; ++block)
        {
            run_block(state, weights, stage, block, stage_channels[stage], first_strides[stage],
                      log);
        }
    }

    PlainTensor pooled = plain_average_pool(state.tensor, 40.0);
    log_plain_tensor("plain average pool output", pooled, log);
    return plain_fully_connected(pooled, weights.linear_weight, weights.linear_bias,
                                 kImageNetClassCount, kResNet18FinalChannels);
}

void run_plain_resnet18(size_t start_image_id, size_t end_image_id,
                        StemPoolMode stem_pool_mode)
{
    fs::create_directories(result_dir());
    const string run_timestamp = make_run_timestamp();
    const fs::path summary_path =
        result_dir() / ("resnet18_plain_label_" + to_string(start_image_id) + "_" +
                        to_string(end_image_id) + "_" + run_timestamp + ".txt");
    ofstream summary(summary_path);
    if (!summary.is_open())
    {
        throw runtime_error("failed to open plain summary result file");
    }

    cout << "Loading ResNet18 ImageNet parameters" << endl;
    cout << "stem pool mode: " << stem_pool_mode_name(stem_pool_mode) << endl;
    ModelWeights weights = load_resnet18_parameters();

    size_t correct = 0;
    const auto all_start = chrono::high_resolution_clock::now();
    for (size_t image_id = start_image_id; image_id <= end_image_id; ++image_id)
    {
        const auto image_start = chrono::high_resolution_clock::now();
        const fs::path image_log_path =
            result_dir() / ("resnet18_plain_image" + to_string(image_id) + "_" + run_timestamp +
                            ".txt");
        ofstream image_log(image_log_path);
        if (!image_log.is_open())
        {
            throw runtime_error("failed to open plain per-image result file");
        }

        image_log << "image_id: " << image_id << '\n';
        image_log << "log_file: " << image_log_path << '\n';
        image_log << "stem_pool_mode: " << stem_pool_mode_name(stem_pool_mode) << '\n';
        const int image_label = read_image_label(image_id);
        vector<double> logits =
            run_plain_resnet18_for_image(image_id, weights, image_log, stem_pool_mode);
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
    if (argc != 3 && argc != 4)
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
        const StemPoolMode stem_pool_mode =
            argc == 4 ? parse_stem_pool_mode(argv[3]) : StemPoolMode::AvgPool;

        run_plain_resnet18(start_image_id, end_image_id, stem_pool_mode);
        return 0;
    }
    catch (const exception &ex)
    {
        cerr << "resnet18_plain error: " << ex.what() << endl;
        return 1;
    }
}
