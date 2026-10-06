#include "final_logits.h"

#include <chrono>
#include <cmath>
#include <stdexcept>

int final_logit_argmax(const std::vector<std::complex<double>> &logits)
{
    if (logits.size() < kImageNetClassCount)
        throw std::invalid_argument("final logits contain fewer than 1000 class slots");
    int predicted = 0;
    for (int i = 0; i < kImageNetClassCount; ++i)
    {
        if (!std::isfinite(logits[i].real()) || !std::isfinite(logits[i].imag()))
            throw std::runtime_error("final logits contain a non-finite value");
        if (logits[i].real() > logits[predicted].real()) predicted = i;
    }
    return predicted;
}

FinalLogitValidation validate_final_logits(const poseidon::Ciphertext &cipher,
                                           PoseidonRuntime &runtime, int true_label)
{
    if (true_label < 0 || true_label >= kImageNetClassCount)
        throw std::invalid_argument("final prediction true label is outside [0,999]");
    const auto start = std::chrono::steady_clock::now();
    poseidon::Plaintext plain;
    FinalLogitValidation result;
    runtime.decryptor.decrypt(cipher, plain);
    runtime.encoder.decode(plain, result.logits);
    result.predicted_label = final_logit_argmax(result.logits);
    result.correct = result.predicted_label == true_label;
    result.logits.resize(kImageNetClassCount);
    result.verification_time_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}
