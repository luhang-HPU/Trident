#pragma once

#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/encryptor.h"

#include <iosfwd>
#include <vector>

class TensorCipher
{
private:
    int k_ = 0;
    int h_ = 0;
    int w_ = 0;
    int c_ = 0;
    int t_ = 0;
    int p_ = 0;
    int logn_ = 0;
    poseidon::Ciphertext cipher_;

public:
    TensorCipher() = default;
    TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                 const std::vector<double> &data, poseidon::Encryptor &encryptor,
                 poseidon::CKKSEncoder &encoder, int logp);
    TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                 const poseidon::Ciphertext &cipher);

    int k() const;
    int h() const;
    int w() const;
    int c() const;
    int t() const;
    int p() const;
    int logn() const;

    const poseidon::Ciphertext &cipher() const;
    poseidon::Ciphertext &cipher();
    void set_ciphertext(const poseidon::Ciphertext &cipher);
    void print_parms(std::ostream &output) const;
};
