#ifndef POSEIDON_KNN_UTILS_H
#define POSEIDON_KNN_UTILS_H

#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/json.h"
#include "poseidon/util/precision.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/util/thread_pool.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;
using namespace poseidon;

namespace KNN
{
extern std::filesystem::path current_path;
extern int data_nums;
extern int dimension;
extern int N;
extern int NUM;
extern int num_threads;

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);

std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);

std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);

void read_jsonl_query(const std::string &file,
                      std::vector<std::vector<std::complex<double>>> &query);

void read_jsonl_data(const std::string &file,
                     std::vector<std::vector<std::complex<double>>> &matrix_data);

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);

std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);

std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);

void encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                        std::vector<std::complex<double>> &message, double scale, Ciphertext &ciph);

std::vector<Ciphertext>
encode_and_encrypt_mt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                      std::vector<std::vector<std::complex<double>>> &message, double scale);

void generate_glaios_mt(KeyGenerator &kgen, vector<vector<int>> step, GaloisKeys &rot_keys);

void sub_and_square(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
                    std::vector<Ciphertext> &ciph_data, const std::vector<Ciphertext> &ciph_query,
                    const poseidon::RelinKeys &relin_keys, const double scale);

void match_param_id(Ciphertext &ciph1, Ciphertext &ciph2, std::shared_ptr<EvaluatorCkksBase> eva);

void match_scale(Ciphertext &ciph1, Ciphertext &ciph2, const CKKSEncoder &encoder,
                 std::shared_ptr<EvaluatorCkksBase> eva, double scale);

// sign_1 第一次sign 近似拟合
Ciphertext sign_1(const Ciphertext &ciph, const PolynomialVector &polys_1,
                  const PolynomialVector &polys_2, const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva, const RelinKeys &relin_keys);

// sign_2 第二次拟合
Ciphertext sign_2(const Ciphertext &ciph, const PolynomialVector &polys, const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva, const RelinKeys &relin_keys);

void writePredictions(const std::vector<int> &data, std::string predictions_file);

Ciphertext accumulate_top_n_block(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                                  const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                                  const GaloisKeys rot_keys);

string get_current_path();

}

#endif  // POSEIDON_KNN_UTILS_H
