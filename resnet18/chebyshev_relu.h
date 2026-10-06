#pragma once

#include "poseidon/ckks_encoder.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"

#include <vector>

constexpr int kChebyshevReluDegree = 471;
constexpr int kChebyshevReluLevels = 10;

// Direct interpolation of max(0, x) on [-1, 1], with c0 already halved.
const std::vector<double> &chebyshev_relu_coefficients();
double chebyshev_relu_plain(double input);

// Poseidon implementation; no OpenFHE ciphertexts or decryption are involved.
poseidon::Ciphertext chebyshev_relu(
    const poseidon::Ciphertext &input, poseidon::EvaluatorCkksBase &evaluator,
    poseidon::CKKSEncoder &encoder, const poseidon::RelinKeys &relin_keys,
    double output_scale);
