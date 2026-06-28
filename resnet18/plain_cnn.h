#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

struct PlainTensor
{
    int h = 0;
    int w = 0;
    int c = 0;
    std::vector<double> values;

    PlainTensor() = default;
    PlainTensor(int height, int width, int channels);
    PlainTensor(int height, int width, int channels, std::vector<double> data);

    double &at(int channel, int row, int col);
    double at(int channel, int row, int col) const;
};

PlainTensor plain_input_tensor_from_image_slots(const std::vector<double> &image_slots);

PlainTensor plain_convolution(const PlainTensor &input, int out_channels, int stride, int fh, int fw,
                              const std::vector<double> &weights,
                              const std::vector<double> &running_var,
                              const std::vector<double> &constant_weight, double epsilon);

PlainTensor plain_batch_norm(const PlainTensor &input, const std::vector<double> &bias,
                             const std::vector<double> &running_mean,
                             const std::vector<double> &running_var,
                             const std::vector<double> &weight, double epsilon, double B);

PlainTensor plain_relu_reference(const PlainTensor &input);

PlainTensor plain_add(const PlainTensor &lhs, const PlainTensor &rhs);

PlainTensor plain_average_pool2d(const PlainTensor &input, int kernel, int stride, int padding);

PlainTensor plain_max_pool2d(const PlainTensor &input, int kernel, int stride, int padding);

PlainTensor plain_downsample_shortcut(const PlainTensor &input);

PlainTensor plain_average_pool(const PlainTensor &input, double B);

std::vector<double> plain_fully_connected(const PlainTensor &input,
                                          const std::vector<double> &matrix,
                                          const std::vector<double> &bias, int q, int r);

void log_plain_tensor(const std::string &label, const PlainTensor &tensor, std::ostream &output,
                      std::size_t preview_count = 32);
