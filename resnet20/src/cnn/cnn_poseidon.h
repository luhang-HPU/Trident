#pragma	once
#include <iostream>
#include <fstream>   
#include <cstdlib>
#include <vector>
#include <cmath>
#include <complex>
#include <math.h>
#include <gmpxx.h>

#include "poseidon/defines.h"
#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/advance/homomorphic_linear_transform.h"
#include "poseidon/seal/util/numth.h"
//#include "hardware/ConfigGen.h"

#include "poseidon/ciphertext.h"

#include "poseidon/util/matrix_operation.h"
#include "poseidon/CKKSEncoder.h"
//#include "BatchEncoder.h"
#include "poseidon/util/random_sample.h"

#include "poseidon/seal/randomgen.h"
//#include "random/Blake2xbPRNG.h"
#include "poseidon/seal/util/blake2.h"
#include "poseidon/seal/util/blake2-impl.h"
#include "poseidon/keygenerator.h"
#include "poseidon/encryptor.h"
#include "poseidon/decryptor.h"
#include "poseidon/ParametersLiteral.h"
#include "poseidon/seal/util/rlwe.h"
#include "poseidon/key/relinkeys.h"

#include "poseidon/Evaluator.h"
//#include "HardwareEvaluator.h"
#include "poseidon/advance/homomorphic_linear_transform.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/advance/util/chebyshev_interpolation.h"

#include "poseidon/scheme/ckks/CKKSEvaluatorBase.h"

using namespace std;
using namespace poseidon;

class TensorCipher
{
private:
	int k_;		// k: gap
	int h_;		// h: height
	int w_;		// w: width
	int c_;		// c: number of channels
	int t_;		// t: \lfloor c/k^2 \rfloor
	int p_;		// p: 2^log2(n/k^2hwt)
	int logn_;
	Ciphertext cipher_;

public:
	TensorCipher();
	TensorCipher(int logn, int k, int h, int w, int c, int t, int p, vector<double> data, Encryptor &encryptor, CKKSEncoder &encoder, PoseidonContext &context); 	// data vector contains hxwxc real numbers. 
	TensorCipher(int logn, int k, int h, int w, int c, int t, int p, Ciphertext cipher);
	int k() const;
    int h() const;
    int w() const;
	int c() const;
	int t() const;
	int p() const;
    int logn() const;
	Ciphertext cipher() const;
	void set_ciphertext(Ciphertext cipher);
	void print_parms();
};

double ReLU_func(double x);
void decrypt_and_print(ofstream &output, const Ciphertext &cipher, Decryptor &decryptor, CKKSEncoder &encoder, long sparse_slots, size_t front, size_t back);
long pow2(long n);
int floor_to_int(double x);
long log2_long(long n);

void multiplexed_parallel_convolution_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, ofstream &output, Decryptor &decryptor, PoseidonContext &context, size_t stage, bool end = false);
void multiplexed_parallel_batch_norm_poseidon_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias, vector<double> running_mean, vector<double> running_var, vector<double> weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, double B, ofstream &output, Decryptor &decryptor, PoseidonContext &context, size_t stage, bool end = false);
void approx_ReLU_poseidon_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, long scalingfactor, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, Decryptor &decryptor, CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key, RelinKeys &relin_keys, double B, ofstream &output, PoseidonContext &context, GaloisKeys &gal_keys, size_t stage);
void bootstrap_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, ofstream &output, std::shared_ptr<Evaluator> &evaluator, EvalModPoly &evalModPoly, LinearMatrixGroup &mat_group, LinearMatrixGroup &mat_group_dec, RelinKeys &relin_keys, GaloisKeys &gal_keys, Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context, size_t stage);
void cipher_add_poseidon_print(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination, std::shared_ptr<Evaluator> &evaluator, ofstream &output, Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context);
void multiplexed_parallel_downsampling_poseidon_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, std::shared_ptr<Evaluator> &evaluator, Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context, GaloisKeys &gal_keys, ofstream &output);
void averagepooling_poseidon_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, double B, ofstream &output, Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context);
void fully_connected_poseidon_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> matrix, vector<double> bias, int q, int r, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, ofstream &output, Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context);

void multiplexed_parallel_convolution_poseidon(const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw, const vector<double> &data, vector<double> running_var, vector<double> constant_weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, PoseidonContext &context, bool end = false);
void multiplexed_parallel_batch_norm_poseidon(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias, vector<double> running_mean, vector<double> running_var, vector<double> weight, double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, double B, PoseidonContext &context, bool end = false);
void ReLU_poseidon(const TensorCipher &cnn_in, TensorCipher &cnn_out, long scalingfactor, Encryptor &encryptor, std::shared_ptr<Evaluator> &evaluator, Decryptor &decryptor, CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key, RelinKeys &relin_keys, PoseidonContext &context, double scale = 1.0);
void cnn_add_poseidon(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination, std::shared_ptr<Evaluator> &evaluator, ofstream &output, Decryptor &decryptor, CKKSEncoder &encoder);
void multiplexed_parallel_downsampling_poseidon(const TensorCipher &cnn_in, TensorCipher &cnn_out, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, CKKSEncoder &encoder, PoseidonContext &context);
void averagepooling_poseidon_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, double B, CKKSEncoder &encoder, Decryptor &decryptor, ofstream &output, PoseidonContext &context);
void matrix_multiplication_poseidon(const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> matrix, vector<double> bias, int q, int r, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys, CKKSEncoder &encoder, PoseidonContext &context);
void memory_save_rotate(const Ciphertext &cipher_in, Ciphertext &cipher_out, int steps, std::shared_ptr<Evaluator> &evaluator, GaloisKeys &gal_keys);

