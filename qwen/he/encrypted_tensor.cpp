#include "he/encrypted_tensor.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <stdexcept>
#include <utility>

namespace qwen::he
{

namespace
{

std::size_t divide_round_up(std::size_t value, std::size_t divisor)
{
    return (value + divisor - 1) / divisor;
}

} // namespace

std::size_t EncryptedTensorLayout::token_capacity() const
{
    const std::size_t physical_capacity = slot_count / token_stride;
    return token_capacity_limit == 0
               ? physical_capacity
               : std::min(token_capacity_limit, physical_capacity);
}

std::size_t EncryptedTensorLayout::token_groups() const
{
    return divide_round_up(tokens, token_capacity());
}

std::size_t EncryptedTensorLayout::feature_chunks() const
{
    return divide_round_up(features, token_stride);
}

std::size_t EncryptedTensorLayout::cipher_count() const
{
    return token_groups() * feature_chunks();
}

void EncryptedTensorLayout::validate() const
{
    if (tokens == 0 || features == 0 || token_stride == 0 ||
        slot_count == 0 || token_stride > slot_count ||
        slot_count % token_stride != 0)
    {
        throw std::invalid_argument("invalid Qwen encrypted tensor layout");
    }
    if (token_capacity_limit > slot_count / token_stride)
    {
        throw std::invalid_argument(
            "Qwen encrypted tensor token capacity exceeds physical slots");
    }
}

EncryptedTensor::EncryptedTensor(EncryptedTensorLayout layout,
                                 std::vector<poseidon::Ciphertext> ciphertexts)
    : layout_(std::move(layout)), ciphertexts_(std::move(ciphertexts))
{
    layout_.validate();
    if (ciphertexts_.size() != layout_.cipher_count())
    {
        throw std::invalid_argument(
            "Qwen encrypted tensor ciphertext count does not match layout");
    }
}

const EncryptedTensorLayout &EncryptedTensor::layout() const
{
    return layout_;
}

const std::vector<poseidon::Ciphertext> &EncryptedTensor::ciphertexts() const
{
    return ciphertexts_;
}

std::vector<poseidon::Ciphertext> &EncryptedTensor::ciphertexts()
{
    return ciphertexts_;
}

const poseidon::Ciphertext &
EncryptedTensor::cipher(std::size_t token_group,
                        std::size_t feature_chunk) const
{
    return ciphertexts_.at(cipher_index(token_group, feature_chunk));
}

poseidon::Ciphertext &EncryptedTensor::cipher(std::size_t token_group,
                                             std::size_t feature_chunk)
{
    return ciphertexts_.at(cipher_index(token_group, feature_chunk));
}

std::size_t EncryptedTensor::cipher_index(std::size_t token_group,
                                          std::size_t feature_chunk) const
{
    if (token_group >= layout_.token_groups() ||
        feature_chunk >= layout_.feature_chunks())
    {
        throw std::out_of_range("Qwen encrypted tensor chunk index is out of range");
    }
    return token_group * layout_.feature_chunks() + feature_chunk;
}

std::vector<std::vector<double>>
pack_tensor(const Tensor &tensor, const EncryptedTensorLayout &layout)
{
    layout.validate();
    if (tensor.rank() != 2 || tensor.dim(0) != layout.tokens ||
        tensor.dim(1) != layout.features)
    {
        throw std::invalid_argument("plaintext tensor shape does not match HE layout");
    }

    std::vector<std::vector<double>> packed(
        layout.cipher_count(), std::vector<double>(layout.slot_count, 0.0));
    const std::size_t token_capacity = layout.token_capacity();
    const std::size_t feature_chunks = layout.feature_chunks();
    for (std::size_t token = 0; token < layout.tokens; ++token)
    {
        const std::size_t token_group = token / token_capacity;
        const std::size_t local_token = token % token_capacity;
        for (std::size_t feature = 0; feature < layout.features; ++feature)
        {
            const std::size_t feature_chunk = feature / layout.token_stride;
            const std::size_t local_feature = feature % layout.token_stride;
            const std::size_t cipher_index =
                token_group * feature_chunks + feature_chunk;
            const std::size_t slot =
                local_token * layout.token_stride + local_feature;
            packed[cipher_index][slot] = tensor.at(token, feature);
        }
    }
    return packed;
}

Tensor unpack_tensor(const std::vector<std::vector<double>> &packed,
                     const EncryptedTensorLayout &layout)
{
    layout.validate();
    if (packed.size() != layout.cipher_count())
    {
        throw std::invalid_argument("packed ciphertext count does not match HE layout");
    }
    for (const std::vector<double> &slots : packed)
    {
        if (slots.size() != layout.slot_count)
        {
            throw std::invalid_argument("packed slot count does not match HE layout");
        }
    }

    Tensor tensor({layout.tokens, layout.features});
    const std::size_t token_capacity = layout.token_capacity();
    const std::size_t feature_chunks = layout.feature_chunks();
    for (std::size_t token = 0; token < layout.tokens; ++token)
    {
        const std::size_t token_group = token / token_capacity;
        const std::size_t local_token = token % token_capacity;
        for (std::size_t feature = 0; feature < layout.features; ++feature)
        {
            const std::size_t feature_chunk = feature / layout.token_stride;
            const std::size_t local_feature = feature % layout.token_stride;
            const std::size_t cipher_index =
                token_group * feature_chunks + feature_chunk;
            const std::size_t slot =
                local_token * layout.token_stride + local_feature;
            tensor.at(token, feature) = packed[cipher_index][slot];
        }
    }
    return tensor;
}

poseidon::Ciphertext encrypt_slots(const std::vector<double> &values,
                                   HeRuntime &runtime)
{
    if (values.size() > runtime.config().slot_count())
    {
        throw std::invalid_argument("Qwen HE input exceeds the CKKS slot count");
    }
    std::vector<std::complex<double>> slots(runtime.config().slot_count(),
                                            {0.0, 0.0});
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        slots[index] = {values[index], 0.0};
    }
    poseidon::Plaintext plain;
    runtime.encoder.encode(slots, runtime.scale(), plain);
    poseidon::Ciphertext cipher;
    runtime.encryptor.encrypt(plain, cipher);
    return cipher;
}

std::vector<double> decrypt_slots(const poseidon::Ciphertext &cipher,
                                  HeRuntime &runtime)
{
    poseidon::Plaintext plain;
    runtime.decryptor.decrypt(cipher, plain);
    std::vector<std::complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);
    std::vector<double> values(decoded.size(), 0.0);
    std::transform(decoded.begin(), decoded.end(), values.begin(),
                   [](const std::complex<double> &value) {
                       return value.real();
                   });
    return values;
}

EncryptedTensor encrypt_tensor(const Tensor &tensor, HeRuntime &runtime)
{
    if (tensor.rank() != 2)
    {
        throw std::invalid_argument("Qwen HE encrypt_tensor expects rank-2 input");
    }
    EncryptedTensorLayout layout{tensor.dim(0), tensor.dim(1),
                                 runtime.config().token_stride,
                                 runtime.config().slot_count(),
                                 runtime.config().tokens_per_cipher()};
    const std::vector<std::vector<double>> packed = pack_tensor(tensor, layout);
    std::vector<poseidon::Ciphertext> ciphertexts;
    ciphertexts.reserve(packed.size());
    for (const std::vector<double> &slots : packed)
    {
        ciphertexts.push_back(encrypt_slots(slots, runtime));
    }
    return EncryptedTensor(layout, std::move(ciphertexts));
}

Tensor decrypt_tensor(const EncryptedTensor &tensor, HeRuntime &runtime)
{
    std::vector<std::vector<double>> packed;
    packed.reserve(tensor.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : tensor.ciphertexts())
    {
        packed.push_back(decrypt_slots(cipher, runtime));
    }
    return unpack_tensor(packed, tensor.layout());
}

} // namespace qwen::he
