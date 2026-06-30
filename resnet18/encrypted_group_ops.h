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

std::vector<double> encrypted_conv2d_im2col_output_channel(
    const Im2ColCipherGroup &im2col, int output_channel, int out_channels,
    const std::vector<double> &weights, const std::vector<double> &running_var,
    const std::vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime);

poseidon::Ciphertext encrypted_conv2d_im2col_output_channel_cipher(
    const Im2ColCipherGroup &im2col, int output_channel, int out_channels,
    const std::vector<double> &weights, const std::vector<double> &running_var,
    const std::vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_conv2d_im2col_all_channels(
    const Im2ColCipherGroup &im2col, int out_channels, const std::vector<double> &weights,
    const std::vector<double> &running_var, const std::vector<double> &constant_weight,
    double epsilon, PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_channel_batch_norm(
    const ChannelCipherGroup &input, const std::vector<double> &bias,
    const std::vector<double> &running_mean, const std::vector<double> &running_var,
    const std::vector<double> &weight, double epsilon, double boundary,
    PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_channel_batch_norm_sparse_stride(
    const ChannelCipherGroup &input, const std::vector<double> &bias,
    const std::vector<double> &running_mean, const std::vector<double> &running_var,
    const std::vector<double> &weight, double epsilon, double boundary, int dense_h,
    int dense_w, int stride, PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_channel_add(const ChannelCipherGroup &lhs,
                                          const ChannelCipherGroup &rhs,
                                          PoseidonRuntime &runtime);

std::vector<int> maxpool_channel_preview_rotation_steps(int input_h, int input_w, int kernel,
                                                        int stride, int padding,
                                                        std::size_t preview_count);

poseidon::Ciphertext encrypted_maxpool_candidate_preview(
    const poseidon::Ciphertext &input, int input_h, int input_w, int kernel, int stride,
    int padding, int pick_row, int pick_col, std::size_t preview_count,
    PoseidonRuntime &runtime);

std::vector<int> maxpool_channel_sparse_rotation_steps(int input_w, int kernel, int padding);

poseidon::Ciphertext encrypted_maxpool_candidate_sparse(
    const poseidon::Ciphertext &input, int input_h, int input_w, int kernel, int stride,
    int padding, int pick_row, int pick_col, PoseidonRuntime &runtime);

std::vector<int> dense_conv2d_channel_rotation_steps(int input_w, int fh, int fw);

poseidon::Ciphertext encrypted_channel_conv2d_output_channel_cipher(
    const ChannelCipherGroup &input, int output_channel, int out_channels, int stride,
    int fh, int fw, const std::vector<double> &weights,
    const std::vector<double> &running_var, const std::vector<double> &constant_weight,
    double epsilon, PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_channel_conv2d_all_channels(
    const ChannelCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const std::vector<double> &weights, const std::vector<double> &running_var,
    const std::vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime);

ChannelCipherGroup encrypted_channel_conv2d_sparse_stride_all_channels(
    const ChannelCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const std::vector<double> &weights, const std::vector<double> &running_var,
    const std::vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime);

std::vector<double> decrypt_channel_cipher_group(const ChannelCipherGroup &group,
                                                 PoseidonRuntime &runtime);
