#pragma once

#include "core/tensor.h"
#include "he/encrypted_tensor.h"

#include "poseidon/plaintext.h"

#include <cstddef>
#include <map>

namespace qwen::he
{

enum class RefreshMode
{
    none,
    debug_reencrypt,
    debug_bootstrap,
    bootstrap,
};

inline constexpr std::size_t bootstrap_output_level = 19;

EncryptedTensor encrypted_drop_to_level(const EncryptedTensor &input,
                                        std::size_t target_level,
                                        HeRuntime &runtime);

EncryptedTensor encrypted_add(const EncryptedTensor &lhs,
                              const EncryptedTensor &rhs,
                              HeRuntime &runtime);
EncryptedTensor encrypted_subtract(const EncryptedTensor &lhs,
                                   const EncryptedTensor &rhs,
                                   HeRuntime &runtime);
EncryptedTensor encrypted_add_plain(const EncryptedTensor &input,
                                    const Tensor &plain,
                                    HeRuntime &runtime);
EncryptedTensor encrypted_multiply_plain(const EncryptedTensor &input,
                                         const Tensor &plain,
                                         HeRuntime &runtime);
EncryptedTensor encrypted_multiply(const EncryptedTensor &lhs,
                                   const EncryptedTensor &rhs,
                                   HeRuntime &runtime);
poseidon::Ciphertext encrypted_multiply_ciphertexts(
    const poseidon::Ciphertext &lhs, const poseidon::Ciphertext &rhs,
    double target_scale, HeRuntime &runtime);
EncryptedTensor encrypted_bootstrap(const EncryptedTensor &input,
                                    HeRuntime &runtime);
EncryptedTensor encrypted_refresh(const EncryptedTensor &input,
                                  RefreshMode mode,
                                  HeRuntime &runtime);
EncryptedTensor encrypted_refresh_at_scale(
    const EncryptedTensor &input, RefreshMode mode, double value_scale,
    HeRuntime &runtime);

poseidon::Ciphertext rotate_slots(const poseidon::Ciphertext &input, int steps,
                                  HeRuntime &runtime);
poseidon::Ciphertext rotate_blocks(const poseidon::Ciphertext &input,
                                   int steps, std::size_t block_width,
                                   HeRuntime &runtime);
poseidon::Ciphertext reduce_sum_slots(const poseidon::Ciphertext &input,
                                      std::size_t width,
                                      HeRuntime &runtime);

class EncodedLinear
{
public:
    EncodedLinear(std::size_t input_features, std::size_t output_features,
                  std::size_t token_stride,
                  std::vector<std::map<int, poseidon::Plaintext>> diagonals);

    std::size_t input_features() const;
    std::size_t output_features() const;
    std::size_t token_stride() const;
    std::size_t input_chunks() const;
    std::size_t output_chunks() const;
    const std::map<int, poseidon::Plaintext> &
    diagonals(std::size_t output_chunk, std::size_t input_chunk) const;

private:
    std::size_t matrix_index(std::size_t output_chunk,
                             std::size_t input_chunk) const;

    std::size_t input_features_ = 0;
    std::size_t output_features_ = 0;
    std::size_t token_stride_ = 0;
    std::vector<std::map<int, poseidon::Plaintext>> diagonals_;
};

EncodedLinear encode_linear(const Tensor &weight, HeRuntime &runtime);
EncodedLinear encode_linear_at(const Tensor &weight,
                               const poseidon::Ciphertext &input_level,
                               HeRuntime &runtime);
EncryptedTensor encrypted_linear(const EncryptedTensor &input,
                                 const EncodedLinear &linear,
                                 const Tensor *bias,
                                 HeRuntime &runtime);
EncryptedTensor encrypted_rope(const EncryptedTensor &input,
                               std::size_t head_count,
                               std::size_t head_dim,
                               std::size_t position,
                               double theta,
                               HeRuntime &runtime);

} // namespace qwen::he
