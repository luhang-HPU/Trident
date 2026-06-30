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

    const size_t channel_values = static_cast<size_t>(h * w);
    if (values.size() <= slot_count_)
    {
        layouts_.push_back(ChunkLayout{0, values.size()});
    }
    else
    {
        const size_t chunks_per_channel = (channel_values + slot_count_ - 1) / slot_count_;
        layouts_.reserve(static_cast<size_t>(c) * chunks_per_channel);
        for (int channel = 0; channel < c; ++channel)
        {
            const size_t channel_base = static_cast<size_t>(channel) * channel_values;
            for (size_t channel_offset = 0; channel_offset < channel_values;
                 channel_offset += slot_count_)
            {
                const size_t copy_count = min(slot_count_, channel_values - channel_offset);
                layouts_.push_back(ChunkLayout{channel_base + channel_offset, copy_count});
            }
        }
    }

    chunks_.reserve(layouts_.size());
    for (const ChunkLayout &layout : layouts_)
    {
        vector<complex<double>> slots(slot_count_, {0.0, 0.0});
        for (size_t i = 0; i < layout.value_count; ++i)
        {
            slots[i] = {values[layout.value_offset + i], 0.0};
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

size_t TensorCipherGroup::chunk_index_for_value(size_t value_index) const
{
    if (value_index >= value_count_)
    {
        throw out_of_range("TensorCipherGroup value index is out of range");
    }
    for (size_t chunk_index = 0; chunk_index < layouts_.size(); ++chunk_index)
    {
        const ChunkLayout &layout = layouts_[chunk_index];
        if (value_index >= layout.value_offset &&
            value_index < layout.value_offset + layout.value_count)
        {
            return chunk_index;
        }
    }
    throw out_of_range("TensorCipherGroup value index is not covered by any chunk");
}

size_t TensorCipherGroup::slot_index_for_value(size_t value_index) const
{
    const size_t chunk_index = chunk_index_for_value(value_index);
    return value_index - layouts_.at(chunk_index).value_offset;
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
    vector<double> values(value_count_, 0.0);
    for (size_t chunk_index = 0; chunk_index < chunks_.size(); ++chunk_index)
    {
        Plaintext plain;
        decryptor.decrypt(chunks_.at(chunk_index), plain);

        vector<complex<double>> decoded;
        encoder.decode(plain, decoded);
        const ChunkLayout &layout = layouts_.at(chunk_index);
        const size_t copy_count = min(layout.value_count, decoded.size());
        for (size_t i = 0; i < copy_count; ++i)
        {
            values[layout.value_offset + i] = decoded[i].real();
        }
    }
    return values;
}

void TensorCipherGroup::print_summary(ostream &output) const
{
    output << "TensorCipherGroup(shape h=" << h_ << ", w=" << w_ << ", c=" << c_
           << ", values=" << value_count_ << ", slots_per_chunk=" << slot_count_
           << ", chunks=" << chunks_.size()
           << ", layout=channel_split)\n";
}
