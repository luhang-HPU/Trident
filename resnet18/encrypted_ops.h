#pragma once

#include "relu_approx.h"
#include "tensor_cipher.h"

#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/poseidon_context.h"

#include <cstddef>
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

struct FullyConnectedBsgsPlainDiagonal
{
    int baby_step = 0;
    poseidon::Plaintext plaintext;
};

struct FullyConnectedBsgsPlainGroup
{
    int giant_step = 0;
    std::vector<FullyConnectedBsgsPlainDiagonal> diagonals;
};

struct FullyConnectedBsgsPlainPlan
{
    int rows = 0;
    int columns = 0;
    int logn = 0;
    int baby_step = 0;
    double input_scale = 0.0;
    poseidon::parms_id_type input_parms_id{};
    poseidon::parms_id_type output_parms_id{};
    std::vector<FullyConnectedBsgsPlainGroup> groups;
    poseidon::Plaintext bias;
    std::size_t encoded_bytes = 0;
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
                           const FullyConnectedBsgsPlainPlan &plan,
                           poseidon::EvaluatorCkksBase &evaluator,
                           poseidon::GaloisKeys &gal_keys, poseidon::CKKSEncoder &encoder);

FullyConnectedBsgsPlainPlan prepare_fully_connected_bsgs_plain_plan(
    const std::vector<double> &matrix, const std::vector<double> &bias,
    int rows, int columns, int logn,
    poseidon::parms_id_type input_parms_id, double input_scale,
    poseidon::parms_id_type output_parms_id, poseidon::CKKSEncoder &encoder);

int fully_connected_bsgs_baby_step(int rows, int columns, std::size_t slot_count);

std::vector<int> fully_connected_bsgs_rotation_steps(
    int rows, int columns, std::size_t slot_count);
