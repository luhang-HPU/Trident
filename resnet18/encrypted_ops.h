#pragma once

#include "relu_approx.h"
#include "tensor_cipher.h"

#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/poseidon_context.h"

#include <vector>

struct PoseidonBootstrapContext
{
    poseidon::PoseidonContext *context = nullptr;
    poseidon::EvaluatorCkksBase *evaluator = nullptr;
    poseidon::CKKSEncoder *encoder = nullptr;
    const poseidon::RelinKeys *relin_keys = nullptr;
    const poseidon::GaloisKeys *galois_keys = nullptr;
    const poseidon::BootstrapConfig *bootstrap_config = nullptr;
};

void relu(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
          const std::vector<int> &deg, long alpha, const std::vector<Tree> &tree,
          double scaled_val, poseidon::Encryptor &encryptor,
          poseidon::EvaluatorCkksBase &evaluator, poseidon::CKKSEncoder &encoder,
          poseidon::RelinKeys &relin_keys, double scale);

void bootstrap_tensor(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                      PoseidonBootstrapContext &bootstrapper);

void normalize_bootstrap_output_scale(poseidon::Ciphertext &cipher,
                                      PoseidonBootstrapContext &bootstrapper);

void matrix_multiplication(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                           std::vector<double> matrix, std::vector<double> bias, int q,
                           int r, poseidon::EvaluatorCkksBase &evaluator,
                           poseidon::GaloisKeys &gal_keys, poseidon::CKKSEncoder &encoder);
