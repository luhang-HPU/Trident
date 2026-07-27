#pragma once

#include "poseidon/ckks_encoder.h"
#include "poseidon/ciphertext.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/keygenerator.h"

#include <iosfwd>
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

std::vector<std::vector<double>> load_relu_component_coeffs(
    long alpha, const std::vector<int> &deg, const std::vector<Tree> &trees, double scaled_val);

void log_relu_component_coeffs(const std::vector<std::vector<double>> &coeffs,
                               std::ostream &output);

void assign_scale_for_relu_reference(poseidon::Ciphertext &cipher, double scale);

poseidon::Ciphertext approximate_sign(const poseidon::Ciphertext &input,
                                      const std::vector<int> &deg, long alpha,
                                      const std::vector<Tree> &tree, double scaled_val,
                                      poseidon::Encryptor &encryptor,
                                      poseidon::CKKSEncoder &encoder,
                                      poseidon::EvaluatorCkksBase &evaluator,
                                      poseidon::RelinKeys &relin_keys);
