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

#include <cstdint>
#include <complex>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace KNN
{

using Complex = std::complex<double>;
using ComplexVec = std::vector<Complex>;
using ComplexMatrix = std::vector<ComplexVec>;

struct RuntimeOptions
{
    uint32_t log_degree = 15;
    std::string dataset_file;
    std::string predictions_file;
};

RuntimeOptions make_default_options();
RuntimeOptions parse_options(int argc, char *argv[]);
int run_knn(const RuntimeOptions &options);

poseidon::Ciphertext encode_and_encrypt(const poseidon::CKKSEncoder &encoder,
                                        const poseidon::Encryptor &encryptor,
                                        const ComplexVec &message, double scale);

std::vector<poseidon::Ciphertext> encode_and_encrypt(const poseidon::CKKSEncoder &encoder,
                                                     const poseidon::Encryptor &encryptor,
                                                     const ComplexMatrix &message,
                                                     double scale);

ComplexVec decrypt_and_decode(const poseidon::CKKSEncoder &encoder,
                              poseidon::Decryptor &decryptor,
                              const poseidon::Ciphertext &ciph);

void read_jsonl_query(const std::string &file, ComplexMatrix &query, size_t slot_count);
void read_jsonl_data(const std::string &file, ComplexMatrix &matrix_data);

void encode_and_encrypt(const poseidon::CKKSEncoder &encoder,
                        const poseidon::Encryptor &encryptor,
                        const ComplexVec &message, double scale,
                        poseidon::Ciphertext &ciph);

std::vector<poseidon::Ciphertext> encode_and_encrypt_mt(const poseidon::CKKSEncoder &encoder,
                                                        const poseidon::Encryptor &encryptor,
                                                        const ComplexMatrix &message,
                                                        double scale);

void sub_and_square(const std::shared_ptr<poseidon::EvaluatorCkksBase> &ckks_eva,
                    std::vector<poseidon::Ciphertext> &ciph_data,
                    const std::vector<poseidon::Ciphertext> &ciph_query,
                    const poseidon::RelinKeys &relin_keys, double scale);

void match_param_id(poseidon::Ciphertext &ciph1, poseidon::Ciphertext &ciph2,
                    std::shared_ptr<poseidon::EvaluatorCkksBase> eva);

void match_scale(poseidon::Ciphertext &ciph1, poseidon::Ciphertext &ciph2,
                 const poseidon::CKKSEncoder &encoder,
                 std::shared_ptr<poseidon::EvaluatorCkksBase> eva, double scale);

poseidon::Ciphertext sign_1(const poseidon::Ciphertext &ciph,
                            const poseidon::PolynomialVector &polys_1,
                            const poseidon::PolynomialVector &polys_2,
                            const poseidon::CKKSEncoder &encoder,
                            std::shared_ptr<poseidon::EvaluatorCkksBase> eva,
                            const poseidon::RelinKeys &relin_keys);

poseidon::Ciphertext sign_2(const poseidon::Ciphertext &ciph,
                            const poseidon::PolynomialVector &polys,
                            const poseidon::CKKSEncoder &encoder,
                            std::shared_ptr<poseidon::EvaluatorCkksBase> eva,
                            const poseidon::RelinKeys &relin_keys);

void writePredictions(const std::vector<int> &data, const std::string &predictions_file);

poseidon::Ciphertext accumulate_top_n_block(const poseidon::Ciphertext &ciph, int n,
                                            const poseidon::CKKSEncoder &encoder,
                                            const poseidon::Encryptor &enc,
                                            std::shared_ptr<poseidon::EvaluatorCkksBase> ckks_eva,
                                            const poseidon::GaloisKeys &rot_keys);

std::vector<int> decode_predictions(const ComplexVec &decoded);

} // namespace KNN

#endif
