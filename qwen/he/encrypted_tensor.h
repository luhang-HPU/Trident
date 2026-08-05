#pragma once

#include "core/tensor.h"
#include "he/he_runtime.h"

#include "poseidon/ciphertext.h"

#include <cstddef>
#include <vector>

namespace qwen::he
{

struct EncryptedTensorLayout
{
    std::size_t tokens = 0;
    std::size_t features = 0;
    std::size_t token_stride = 0;
    std::size_t slot_count = 0;
    std::size_t token_capacity_limit = 0;

    std::size_t token_capacity() const;
    std::size_t token_groups() const;
    std::size_t feature_chunks() const;
    std::size_t cipher_count() const;
    void validate() const;
};

class EncryptedTensor
{
public:
    EncryptedTensor() = default;
    EncryptedTensor(EncryptedTensorLayout layout,
                    std::vector<poseidon::Ciphertext> ciphertexts);

    const EncryptedTensorLayout &layout() const;
    const std::vector<poseidon::Ciphertext> &ciphertexts() const;
    std::vector<poseidon::Ciphertext> &ciphertexts();
    const poseidon::Ciphertext &cipher(std::size_t token_group,
                                      std::size_t feature_chunk) const;
    poseidon::Ciphertext &cipher(std::size_t token_group,
                                std::size_t feature_chunk);

private:
    std::size_t cipher_index(std::size_t token_group,
                             std::size_t feature_chunk) const;

    EncryptedTensorLayout layout_;
    std::vector<poseidon::Ciphertext> ciphertexts_;
};

std::vector<std::vector<double>>
pack_tensor(const Tensor &tensor, const EncryptedTensorLayout &layout);
Tensor unpack_tensor(const std::vector<std::vector<double>> &packed,
                     const EncryptedTensorLayout &layout);

EncryptedTensor encrypt_tensor(const Tensor &tensor, HeRuntime &runtime);
Tensor decrypt_tensor(const EncryptedTensor &tensor, HeRuntime &runtime);

poseidon::Ciphertext encrypt_slots(const std::vector<double> &values,
                                   HeRuntime &runtime);
std::vector<double> decrypt_slots(const poseidon::Ciphertext &cipher,
                                  HeRuntime &runtime);

} // namespace qwen::he
