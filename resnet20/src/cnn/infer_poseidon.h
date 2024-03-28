#pragma	once
#include "cnn_poseidon.h"

#include <iostream>
#include <fstream>   
#include <cstdlib>
#include <vector>
#include <cmath>
#include <complex>
#include <math.h>
#include <gmpxx.h>
#include "omp.h"

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
#include "poseidon/util/precision.h"

using namespace std;
using namespace poseidon;

// import parameters
void import_parameters_cifar10(vector<double> &linear_weight, vector<double> &linear_bias, vector<vector<double>> &conv_weight, vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean, vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight, size_t layer_num, size_t end_num);
void import_parameters_cifar100(vector<double> &linear_weight, vector<double> &linear_bias, vector<vector<double>> &conv_weight, vector<vector<double>> &bn_bias, vector<vector<double>> &bn_running_mean, vector<vector<double>> &bn_running_var, vector<vector<double>> &bn_weight, vector<vector<double>> &shortcut_weight, vector<vector<double>> &shortcut_bn_bias, vector<vector<double>> &shortcut_bn_mean, vector<vector<double>> &shortcut_bn_var, vector<vector<double>> &shortcut_bn_weight, size_t layer_num, size_t end_num);

// cifar10, cifar100 integrated
void ResNet_cifar10_poseidon_sparse(size_t layer_num, size_t start_image_id, size_t end_image_id, size_t qdef);
// void ResNet_cifar100_poseidon_sparse(size_t layer_num, size_t start_image_id, size_t end_image_id);