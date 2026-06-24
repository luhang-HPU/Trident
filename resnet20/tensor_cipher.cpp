#include "tensor_cipher.h"

#include "poseidon/plaintext.h"

#include <cmath>
#include <complex>
#include <cstddef>
#include <ostream>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const vector<double> &data, Encryptor &encryptor,
                           CKKSEncoder &encoder, int logp)
{
    if (k != 1)
    {
        throw std::invalid_argument("supported k is only 1 right now");
    }
    if (logn < 1 || logn > 16)
    {
        throw std::out_of_range("the value of logn is out of range");
    }

    const size_t slot_count = encoder.slot_count();
    if (data.size() > slot_count)
    {
        throw std::out_of_range("the size of data is larger than slot count");
    }

    k_ = k;
    h_ = h;
    w_ = w;
    c_ = c;
    t_ = t;
    p_ = p;
    logn_ = logn;

    vector<complex<double>> slots(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < data.size(); ++i)
    {
        slots[i] = {data[i], 0.0};
    }

    Plaintext plain;
    encoder.encode(slots, pow(2.0, logp), plain);
    encryptor.encrypt(plain, cipher_);
}

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const Ciphertext &cipher)
    : k_(k), h_(h), w_(w), c_(c), t_(t), p_(p), logn_(logn), cipher_(cipher)
{
}

int TensorCipher::k() const
{
    return k_;
}

int TensorCipher::h() const
{
    return h_;
}

int TensorCipher::w() const
{
    return w_;
}

int TensorCipher::c() const
{
    return c_;
}

int TensorCipher::t() const
{
    return t_;
}

int TensorCipher::p() const
{
    return p_;
}

int TensorCipher::logn() const
{
    return logn_;
}

const Ciphertext &TensorCipher::cipher() const
{
    return cipher_;
}

Ciphertext &TensorCipher::cipher()
{
    return cipher_;
}

void TensorCipher::set_ciphertext(const Ciphertext &cipher)
{
    cipher_ = cipher;
}

void TensorCipher::print_parms(ostream &output) const
{
    output << "k: " << k_ << '\n';
    output << "h: " << h_ << '\n';
    output << "w: " << w_ << '\n';
    output << "c: " << c_ << '\n';
    output << "t: " << t_ << '\n';
    output << "p: " << p_ << '\n';
}
