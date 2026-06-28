#include "tensor_cipher_group.h"

#include "poseidon/plaintext.h"

#include <cmath>
#include <complex>
#include <ostream>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;

TensorCipherGroup::TensorCipherGroup(int logn, int h, int w, int c,
                                     const vector<double> &values, Encryptor &encryptor,
                                     CKKSEncoder &encoder, int logp)
    : logn_(logn), h_(h), w_(w), c_(c), value_count_(values.size()),
      slot_count_(encoder.slot_count())
{
    if (logn < 10 || logn > 16)
    {
        throw out_of_range("TensorCipherGroup supports logn in [10, 16]");
    }
    if (h <= 0 || w <= 0 || c <= 0)
    {
        throw invalid_argument("TensorCipherGroup shape is invalid");
    }
    if (values.size() != static_cast<size_t>(h * w * c))
    {
        throw invalid_argument("TensorCipherGroup values do not match shape");
    }
    if (slot_count_ == 0)
    {
        throw invalid_argument("CKKS encoder slot count is zero");
    }

    const size_t chunk_count = (values.size() + slot_count_ - 1) / slot_count_;
    chunks_.reserve(chunk_count);
    for (size_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index)
    {
        vector<complex<double>> slots(slot_count_, {0.0, 0.0});
        const size_t offset = chunk_index * slot_count_;
        const size_t copy_count = min(slot_count_, values.size() - offset);
        for (size_t i = 0; i < copy_count; ++i)
        {
            slots[i] = {values[offset + i], 0.0};
        }

        Plaintext plain;
        encoder.encode(slots, pow(2.0, logp), plain);
        Ciphertext cipher;
        encryptor.encrypt(plain, cipher);
        chunks_.emplace_back(std::move(cipher));
    }
}

int TensorCipherGroup::logn() const
{
    return logn_;
}

int TensorCipherGroup::h() const
{
    return h_;
}

int TensorCipherGroup::w() const
{
    return w_;
}

int TensorCipherGroup::c() const
{
    return c_;
}

size_t TensorCipherGroup::value_count() const
{
    return value_count_;
}

size_t TensorCipherGroup::slot_count() const
{
    return slot_count_;
}

size_t TensorCipherGroup::chunk_count() const
{
    return chunks_.size();
}

const vector<Ciphertext> &TensorCipherGroup::chunks() const
{
    return chunks_;
}

vector<Ciphertext> &TensorCipherGroup::chunks()
{
    return chunks_;
}

vector<double> TensorCipherGroup::decrypt_values(Decryptor &decryptor, CKKSEncoder &encoder) const
{
    vector<double> values;
    values.reserve(value_count_);
    for (const Ciphertext &cipher : chunks_)
    {
        Plaintext plain;
        decryptor.decrypt(cipher, plain);

        vector<complex<double>> decoded;
        encoder.decode(plain, decoded);
        const size_t remaining = value_count_ - values.size();
        const size_t copy_count = min(remaining, decoded.size());
        for (size_t i = 0; i < copy_count; ++i)
        {
            values.emplace_back(decoded[i].real());
        }
    }
    return values;
}

void TensorCipherGroup::print_summary(ostream &output) const
{
    output << "TensorCipherGroup(shape h=" << h_ << ", w=" << w_ << ", c=" << c_
           << ", values=" << value_count_ << ", slots_per_chunk=" << slot_count_
           << ", chunks=" << chunks_.size() << ")\n";
}
