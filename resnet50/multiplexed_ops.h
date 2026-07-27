#pragma once

#include "encrypted_group_ops.h"
#include "infer_runtime.h"
#include "relu_approx.h"

#include <complex>
#include <cstddef>
#include <string>
#include <vector>

struct MultiplexedCipherGroup
{
    int h = 0;
    int w = 0;
    int c = 0;
    int k = 1;
    int pages_per_cipher = 2;
    std::size_t page_size = 0;
    std::size_t slot_count = 0;
    std::vector<poseidon::Ciphertext> packs;
};

struct MultiplexedMockOptions
{
    bool mock_relu = false;
    bool mock_bootstrap = false;
};

MultiplexedCipherGroup pack_channel_group_as_multiplexed_k1(
    const ChannelCipherGroup &input, PoseidonRuntime &runtime);

std::vector<std::complex<double>> decrypt_multiplexed_group_complex(
    const MultiplexedCipherGroup &group, PoseidonRuntime &runtime);

void log_multiplexed_group_cipher_state(const std::string &label,
                                        const MultiplexedCipherGroup &group,
                                        PoseidonRuntime &runtime);

MultiplexedCipherGroup multiplexed_channel_conv2d_all_channels(
    const MultiplexedCipherGroup &input, int out_channels, int stride, int fh, int fw,
    const std::vector<double> &weights, const std::vector<double> &running_var,
    const std::vector<double> &constant_weight, double epsilon, PoseidonRuntime &runtime);

MultiplexedCipherGroup multiplexed_channel_batch_norm(
    const MultiplexedCipherGroup &input, const std::vector<double> &bias,
    const std::vector<double> &running_mean, const std::vector<double> &running_var,
    const std::vector<double> &weight, double epsilon, double boundary,
    PoseidonRuntime &runtime);

MultiplexedCipherGroup multiplexed_channel_bootstrap_then_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const std::string &label, bool bootstrap_before_relu,
    const MultiplexedMockOptions &mock_options);

MultiplexedCipherGroup multiplexed_channel_bootstrap(
    const MultiplexedCipherGroup &input, long logn, PoseidonRuntime &runtime,
    const std::string &label, const MultiplexedMockOptions &mock_options);

MultiplexedCipherGroup multiplexed_channel_homomorphic_relu(
    const MultiplexedCipherGroup &input, long logn, const ReluConfig &relu_config,
    PoseidonRuntime &runtime, const std::string &label,
    const MultiplexedMockOptions &mock_options);

MultiplexedCipherGroup multiplexed_channel_add(const MultiplexedCipherGroup &lhs,
                                               const MultiplexedCipherGroup &rhs,
                                               PoseidonRuntime &runtime);

MultiplexedCipherGroup multiplexed_average_pool2d_stride2(
    const MultiplexedCipherGroup &input, int out_h, int out_w, int out_k,
    PoseidonRuntime &runtime);

poseidon::Ciphertext multiplexed_global_average_pool_packed(
    const MultiplexedCipherGroup &input, double boundary, PoseidonRuntime &runtime);

std::vector<poseidon::Ciphertext> multiplexed_fully_connected_packed(
    const poseidon::Ciphertext &features, int feature_count,
    const std::vector<double> &matrix, const std::vector<double> &bias,
    int class_count, PoseidonRuntime &runtime);
