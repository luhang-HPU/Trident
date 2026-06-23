#pragma once

#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/keygenerator.h"
#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"

#include <cstddef>
#include <iosfwd>
#include <map>
#include <vector>

enum class EvalType : int
{
    None = 0,
    OddBaby = 1,
    Baby = 2,
};

struct Tree
{
    int depth = 0;
    EvalType type = EvalType::None;
    std::vector<int> tree;
    int m = 0;
    int l = 0;
    int b = 0;

    Tree();
    explicit Tree(EvalType eval_type);

    void clear();
    void merge(const Tree &lhs, const Tree &rhs, int g);
};

void upgrade_oddbaby(long degree, Tree &tree);
void upgrade_baby(long degree, Tree &tree);

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

struct PoseidonBootstrapContext
{
    poseidon::PoseidonContext *context = nullptr;
    poseidon::EvaluatorCkksBase *evaluator = nullptr;
    poseidon::CKKSEncoder *encoder = nullptr;
    const poseidon::RelinKeys *relin_keys = nullptr;
    const poseidon::GaloisKeys *galois_keys = nullptr;
    poseidon::EvalModPoly *bootstrap_poly = nullptr;
};

void log_cipher_state(const TensorCipher &tensor, const poseidon::PoseidonContext &context,
                      std::ostream &output);

void multiplexed_parallel_convolution_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const std::vector<double> &data, std::vector<double> running_var,
    std::vector<double> constant_weight, double epsilon, poseidon::CKKSEncoder &encoder,
    poseidon::Encryptor &encryptor, poseidon::EvaluatorCkksBase &evaluator,
    poseidon::GaloisKeys &gal_keys, std::vector<poseidon::Ciphertext> &cipher_pool,
    std::ostream &output, poseidon::Decryptor &decryptor, poseidon::PoseidonContext &context,
    std::size_t stage, bool end = false);

void multiplexed_parallel_batch_norm_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, std::vector<double> bias,
    std::vector<double> running_mean, std::vector<double> running_var, std::vector<double> weight,
    double epsilon, poseidon::CKKSEncoder &encoder, poseidon::Encryptor &encryptor,
    poseidon::EvaluatorCkksBase &evaluator, double B, std::ostream &output,
    poseidon::Decryptor &decryptor, poseidon::PoseidonContext &context, std::size_t stage,
    bool end = false);

void approx_relu_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, std::vector<int> deg,
    long alpha, std::vector<Tree> &tree, double scaled_val,
    poseidon::Encryptor &encryptor, poseidon::EvaluatorCkksBase &evaluator,
    poseidon::Decryptor &decryptor, poseidon::CKKSEncoder &encoder,
    poseidon::RelinKeys &relin_keys, double target_scale, std::ostream &output,
    poseidon::PoseidonContext &context, std::size_t stage);

void bootstrap_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                     PoseidonBootstrapContext &bootstrapper, std::ostream &output,
                     poseidon::Decryptor &decryptor, poseidon::CKKSEncoder &encoder,
                     poseidon::PoseidonContext &context, std::size_t stage);

void cipher_add_stage_print(const TensorCipher &cnn1, const TensorCipher &cnn2,
                           TensorCipher &destination, poseidon::EvaluatorCkksBase &evaluator,
                           std::ostream &output, poseidon::Decryptor &decryptor,
                           poseidon::CKKSEncoder &encoder, poseidon::PoseidonContext &context);

void multiplexed_parallel_downsampling_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, poseidon::EvaluatorCkksBase &evaluator,
    poseidon::Decryptor &decryptor, poseidon::CKKSEncoder &encoder,
    poseidon::PoseidonContext &context, poseidon::GaloisKeys &gal_keys, std::ostream &output);

void averagepooling_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                     poseidon::EvaluatorCkksBase &evaluator,
                                     poseidon::GaloisKeys &gal_keys, double B,
                                     std::ostream &output, poseidon::Decryptor &decryptor,
                                     poseidon::CKKSEncoder &encoder,
                                     poseidon::PoseidonContext &context);

void fully_connected_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                std::vector<double> matrix, std::vector<double> bias, int q,
                                int r, poseidon::EvaluatorCkksBase &evaluator,
                                poseidon::GaloisKeys &gal_keys, std::ostream &output,
                                poseidon::Decryptor &decryptor, poseidon::CKKSEncoder &encoder,
                                poseidon::PoseidonContext &context);

void multiplexed_parallel_convolution(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const std::vector<double> &data, std::vector<double> running_var,
    std::vector<double> constant_weight, double epsilon, poseidon::CKKSEncoder &encoder,
    poseidon::Encryptor &encryptor, poseidon::EvaluatorCkksBase &evaluator,
    poseidon::GaloisKeys &gal_keys, std::vector<poseidon::Ciphertext> &cipher_pool,
    bool end = false);

void multiplexed_parallel_batch_norm(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, std::vector<double> bias,
    std::vector<double> running_mean, std::vector<double> running_var, std::vector<double> weight,
    double epsilon, poseidon::CKKSEncoder &encoder, poseidon::Encryptor &encryptor,
    poseidon::EvaluatorCkksBase &evaluator, double B, bool end = false);

void cnn_add(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination,
                  poseidon::EvaluatorCkksBase &evaluator, poseidon::CKKSEncoder &encoder);

void multiplexed_parallel_downsampling(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                            poseidon::EvaluatorCkksBase &evaluator,
                                            poseidon::GaloisKeys &gal_keys,
                                            poseidon::CKKSEncoder &encoder);

void averagepooling_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                               poseidon::EvaluatorCkksBase &evaluator,
                               poseidon::GaloisKeys &gal_keys, double B,
                               poseidon::CKKSEncoder &encoder, poseidon::Decryptor &decryptor,
                               std::ostream &output);

void matrix_multiplication(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                std::vector<double> matrix, std::vector<double> bias, int q,
                                int r, poseidon::EvaluatorCkksBase &evaluator,
                                poseidon::GaloisKeys &gal_keys, poseidon::CKKSEncoder &encoder);

void memory_save_rotate(const poseidon::Ciphertext &cipher_in, poseidon::Ciphertext &cipher_out,
                        int steps, poseidon::EvaluatorCkksBase &evaluator,
                        poseidon::GaloisKeys &gal_keys);

void cipher_add_print(const TensorCipher &lhs, const TensorCipher &rhs, TensorCipher &output,
                      poseidon::EvaluatorCkksBase &evaluator,
                      const poseidon::PoseidonContext &context, std::ostream &log);
