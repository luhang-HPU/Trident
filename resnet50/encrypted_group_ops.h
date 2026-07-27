#pragma once

#include "infer_runtime.h"

#include <cstddef>
#include <vector>

struct Im2ColCipherGroup
{
    int input_h = 0;
    int input_w = 0;
    int input_c = 0;
    int out_h = 0;
    int out_w = 0;
    int fh = 0;
    int fw = 0;
    int stride = 0;
    std::size_t spatial_count = 0;
    std::size_t slot_count = 0;
    std::vector<poseidon::Ciphertext> patches;
};

struct ChannelCipherGroup
{
    int h = 0;
    int w = 0;
    int c = 0;
    std::size_t spatial_count = 0;
    std::size_t slot_count = 0;
    std::vector<poseidon::Ciphertext> channels;
};

Im2ColCipherGroup encrypt_conv2d_im2col_patches(
    const std::vector<double> &image_values, int input_h, int input_w, int input_c, int stride,
    int fh, int fw, PoseidonRuntime &runtime, int logp);

ChannelCipherGroup encrypted_conv2d_im2col_all_channels(
    const Im2ColCipherGroup &im2col, int out_channels, const std::vector<double> &weights,
    const std::vector<double> &running_var, const std::vector<double> &constant_weight,
    double epsilon, PoseidonRuntime &runtime);
