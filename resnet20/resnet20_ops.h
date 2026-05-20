#ifndef POSEIDON_RESNET20_OPS_H
#define POSEIDON_RESNET20_OPS_H

#include "resnet20.h"

#include "poseidon/key/galoiskeys.h"

namespace ResNet20
{

TensorShape conv2d_output_shape(const TensorShape &input_shape, const Conv2dWeights &weights);

std::vector<int> conv2d_rotation_steps(const TensorShape &input_shape,
                                       const Conv2dWeights &weights);

poseidon::Ciphertext conv2d_encrypted(const poseidon::Ciphertext &input,
                                      const TensorShape &input_shape,
                                      const Conv2dWeights &weights,
                                      const poseidon::CKKSEncoder &encoder,
                                      const poseidon::EvaluatorCkksBase &evaluator,
                                      const poseidon::GaloisKeys &galois_keys,
                                      double scale, size_t slot_count);

poseidon::Ciphertext residual_block_encrypted(const poseidon::Ciphertext &input,
                                              const TensorShape &input_shape,
                                              const ResidualBlockWeights &weights,
                                              const poseidon::CKKSEncoder &encoder,
                                              const poseidon::EvaluatorCkksBase &evaluator,
                                              const poseidon::GaloisKeys &galois_keys,
                                              const poseidon::RelinKeys &relin_keys,
                                              double scale, size_t slot_count);
poseidon::Ciphertext residual_block_encrypted(const poseidon::Ciphertext &input,
                                              const TensorShape &input_shape,
                                              const ResidualBlockWeights &weights,
                                              const poseidon::CKKSEncoder &encoder,
                                              const poseidon::EvaluatorCkksBase &evaluator,
                                              const poseidon::GaloisKeys &galois_keys,
                                              const poseidon::RelinKeys &relin_keys,
                                              double scale, size_t slot_count,
                                              const ActivationOptions &activation);

std::vector<int> sparse_downsample_block_rotation_steps(const TensorShape &input_shape,
                                                        const ResidualBlockWeights &weights,
                                                        size_t output_physical_height,
                                                        size_t output_physical_width,
                                                        size_t spacing);

poseidon::Ciphertext sparse_downsample_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t output_physical_height,
    size_t output_physical_width,
    size_t spacing);
poseidon::Ciphertext sparse_downsample_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t output_physical_height,
    size_t output_physical_width,
    size_t spacing,
    const ActivationOptions &activation);

std::vector<int> sparse_residual_block_rotation_steps(const TensorShape &input_physical_shape,
                                                      const ResidualBlockWeights &weights,
                                                      size_t spacing);

poseidon::Ciphertext sparse_residual_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t spacing);
poseidon::Ciphertext sparse_residual_block_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    const ResidualBlockWeights &weights,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    const poseidon::RelinKeys &relin_keys,
    double scale, size_t slot_count,
    size_t spacing,
    const ActivationOptions &activation);

std::vector<int> sparse_to_compact_rotation_steps(const TensorShape &input_physical_shape,
                                                  size_t spacing);

poseidon::Ciphertext sparse_to_compact_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    size_t spacing,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    double scale, size_t slot_count);

std::vector<int> sparse_global_average_pool_rotation_steps(
    const TensorShape &input_physical_shape, size_t spacing);

poseidon::Ciphertext sparse_global_average_pool_encrypted(
    const poseidon::Ciphertext &input,
    const TensorShape &input_physical_shape,
    size_t spacing,
    const poseidon::CKKSEncoder &encoder,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::GaloisKeys &galois_keys,
    double scale, size_t slot_count);

std::vector<int> linear_rotation_steps(size_t input_size, size_t output_size);

poseidon::Ciphertext linear_encrypted(const poseidon::Ciphertext &input,
                                      const std::vector<double> &weights,
                                      const std::vector<double> &bias,
                                      size_t input_size,
                                      size_t output_size,
                                      const poseidon::CKKSEncoder &encoder,
                                      const poseidon::EvaluatorCkksBase &evaluator,
                                      const poseidon::GaloisKeys &galois_keys,
                                      double scale, size_t slot_count);

void match_level_and_scale(poseidon::Ciphertext &lhs, poseidon::Ciphertext &rhs,
                           const poseidon::CKKSEncoder &encoder,
                           const poseidon::EvaluatorCkksBase &evaluator,
                           double scale);

} // namespace ResNet20

#endif
