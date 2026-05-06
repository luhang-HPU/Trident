#ifndef POSEIDON_CKKS_LRTRAIN_UTILS_H
#define POSEIDON_CKKS_LRTRAIN_UTILS_H

#include <fstream>
#include <filesystem>

#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/decryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"

using namespace poseidon;

const int EPOCHS = 50;
const double learning_rate = 0.95;
const int m = 780;      // row size of train set
const int n = 9;      // column size of train set

namespace check
{
template <typename T> void print_vector(const std::vector<T> &vec, const std::string &comment = "")
{
    ofstream of("output.txt", ios::app);
    of << comment << "  print vector: " << std::endl;
    for (auto value : vec)
    {
        of << value << std::endl;
    }
    of << std::endl;
}

template <typename T> void print_matrix(const std::vector<std::vector<T>> &matrix, const std::string& comment = "")
{
    ofstream of("output.txt", ios::app);
    of << comment << "  print matrix: " << std::endl;
    for (auto row : matrix)
    {
        for (auto value : row)
        {
            of << value << " ";
        }
        of << std::endl;
    }
}

long get_process_memory(int pid);

}  // namespace check

void read_file(std::vector<std::complex<double>> &matrix, const std::string& file);
void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string& file);

double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y);
double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder);

/*
 * calculate the transpose matrix @x_transpose and diagonal matrix @x_diag
 */
void preprocess(int block_size,
                int block_num,
                std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag);

/*
 * ciph.slot[0] = slot[0] + slot[1] + ... + slot[n-1]
 * ciph.slot[x] = 0 , x != 0
 */
Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys &rot_keys);

/*
 * return the sery expansion of (exp(x) / (1 + exp(x)))
 */
double sigmoid(double x);
Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys);

/*
 * get @ret = 2^x
 * where @min <= 2^x <= @max
 */
int get_size(int min, int max);

/*
 * accumulate all the slot into first block_size slot
 * [slot[0], ... , slot[block_size], slot[block_size+1], ... slot[block_size+block_size], ...]
 *  ==>
 * [(slot[0] + slot[block_size] + ...), (slot[1] + slot[block_size + 1] + ...), ..., (slot[block_size-1] + slot[block_size - 1 + block_size] + ...), ....]
 */
Ciphertext accumulate_block_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size);

Ciphertext accumulate_slot_matrix(const std::shared_ptr<EvaluatorCkksBase> eva, const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size, int block_num);

/*
 * batch the first @cnt items of @vec
 * into @return vector with block size @block_size
 */
std::vector<std::complex<double>> vector_to_block_message(const std::vector<std::complex<double>> &vec, int cnt, int block_size);

#endif  // POSEIDON_CKKS_LRTRAIN_UTILS_H
