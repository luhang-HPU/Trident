#ifndef POSEIDON_RESNET20_PLAIN_H
#define POSEIDON_RESNET20_PLAIN_H

#include "resnet20.h"

namespace ResNet20
{

size_t chw_index(const TensorShape &shape, size_t channel, size_t row, size_t col);
size_t conv_weight_index(const Conv2dWeights &weights, size_t out_channel, size_t in_channel,
                         size_t kernel_row, size_t kernel_col);

Tensor conv2d_plain(const Tensor &input, const Conv2dWeights &weights);
Tensor square_activation_plain(const Tensor &input);
Tensor apprelu_activation_plain(const Tensor &input, const ActivationOptions &activation);
Tensor activate_plain(const Tensor &input, const ActivationOptions &activation);
Tensor residual_block_plain(const Tensor &input, const ResidualBlockWeights &weights);
Tensor residual_block_plain(const Tensor &input, const ResidualBlockWeights &weights,
                            const ActivationOptions &activation);
Tensor global_average_pool_plain(const Tensor &input);
Tensor linear_plain(const Tensor &input, const ResNet20Weights &weights);

} // namespace ResNet20

#endif
