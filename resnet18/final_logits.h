#pragma once

#include "infer_runtime.h"

#include <complex>
#include <vector>

struct FinalLogitValidation
{
    std::vector<std::complex<double>> logits;
    int predicted_label = -1;
    bool correct = false;
    double verification_time_ms = 0.0;
};

int final_logit_argmax(const std::vector<std::complex<double>> &logits);

// Mandatory in both modes. No plaintext reference and no encrypted-operation
// timer scope: decrypt/decode exactly once, then classify the first 1000 slots.
FinalLogitValidation validate_final_logits(const poseidon::Ciphertext &cipher,
                                           PoseidonRuntime &runtime, int true_label);
