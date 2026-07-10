#pragma once

#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"

#include <cstddef>
#include <iosfwd>
#include <vector>

class TensorCipherGroup
{
private:
    struct ChunkLayout
    {
        std::size_t value_offset = 0;
        std::size_t value_count = 0;
    };

    int logn_ = 0;
    int h_ = 0;
    int w_ = 0;
    int c_ = 0;
    std::size_t value_count_ = 0;
    std::size_t slot_count_ = 0;
    std::vector<poseidon::Ciphertext> chunks_;
    std::vector<ChunkLayout> layouts_;

public:
    TensorCipherGroup() = default;
    TensorCipherGroup(int logn, int h, int w, int c, const std::vector<double> &values,
                      poseidon::Encryptor &encryptor, poseidon::CKKSEncoder &encoder,
                      int logp);

    int logn() const;
    int h() const;
    int w() const;
    int c() const;
    std::size_t value_count() const;
    std::size_t slot_count() const;
    std::size_t chunk_count() const;
    std::size_t chunk_index_for_value(std::size_t value_index) const;
    std::size_t slot_index_for_value(std::size_t value_index) const;

    const std::vector<poseidon::Ciphertext> &chunks() const;
    std::vector<poseidon::Ciphertext> &chunks();

    std::vector<double> decrypt_values(poseidon::Decryptor &decryptor,
                                       poseidon::CKKSEncoder &encoder) const;
    void print_summary(std::ostream &output) const;
};
