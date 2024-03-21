
#include <bits/stdc++.h>


#include "poseidon/PoseidonContext.h"
#include "poseidon/CKKSEncoder.h"
#include "poseidon/plaintext.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/encryptor.h"
#include "poseidon/decryptor.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/precision.h"
#include "poseidon/Evaluator.h"
#include "poseidon/util/debug.h"
using namespace std;

using namespace poseidon;
using namespace poseidon::util;

int main() {

    cout << BANNER  << endl;
    cout << "POSEIDON SOFTWARE  VERSION:" <<POSEIDON_VERSION << endl;
    cout << "" << endl;

    ParametersLiteral ckks_param_literal{
            CKKS,
            13,
            12,
            40,
            5,
            0,
            0,
            {},
            {}
    };


    vector<uint32_t> logQTmp{31,31,31,31};//,31,31,31,31}; //
    vector<uint32_t> logPTmp{31,31,31,31};//,
    ckks_param_literal.set_log_modulus(logQTmp,logPTmp);
    PoseidonContext context(ckks_param_literal,sec_level_type::none);


    //=====================init random data ============================
    std::vector<std::complex<double>> vec;
    std::vector<std::complex<double>> vec_result,vec_result1;
    int mat_size = 1 << ckks_param_literal.LogSlots();
    std::vector<vector<std::complex<double>>> mat(mat_size,vector<complex<double>>(mat_size,0));
    std::vector<vector<std::complex<double>>> mat_T(mat_size);//(mat_size,vector<complex<double>>(mat_size));
    std::vector<vector<std::complex<double>>> mat_T1;
    //create message
    vector<complex<double>> message(mat_size,0);
    message[1] = 1;

    vector<complex<double>> message_tmp(mat_size);
    vector<complex<double>> message_sum(mat_size << 1,0.0);

    //=====================init  Plain & Ciph =========================
    Plaintext plainA,plainB,plainRes,plainRes1,plainT;
    Ciphertext cipherA,cipherB,cipherRes,cipherRes1,cipherRes2,cipherRes3;
    PublicKey public_key;
    RelinKeys relinKeys;
    GaloisKeys conjKeys;
    GaloisKeys rotKeys;
    vector<uint32_t> rot_elemt;
    CKKSEncoder ckks_encoder(context);
    //=====================GenMatrices  ========================
    MatrixPlain matrixPlain;

    for(int i = 0; i < mat_size; i++){
        sample_random_complex_vector2(mat[i],mat_size);
    }
    auto &modulus = context.crt_context()->first_context_data()->coeff_modulus();
    int level = modulus.size() - 1;
    matrix_operations::transpose_matrix(mat,mat_T1);
    for(int i = 0; i < mat.size(); i++){
        matrix_operations::diagonal(mat_T1, i,mat_T[i]);
    }


    GenMatrixformBSGS(matrixPlain,matrixPlain.rot_index, ckks_encoder, mat_T,
                      level , safe_cast<double>(modulus.back().value()) , 1, ckks_param_literal.LogSlots());


//=====================keys  =========================
    //
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);

    kgen.create_relin_keys(relinKeys);

    kgen.create_galois_keys(matrixPlain.rot_index,rotKeys);


    Encryptor enc(context,public_key,kgen.secret_key());
    Decryptor dec(context,kgen.secret_key());



    //gmp_printf("cc : %.Zd\n",two_pow_64_2.get_mpz_t());
    Plaintext plaintext,plaintext2;
    double scale = std::pow(2.0,51);
    ckks_encoder.encode(message, scale,plaintext);
    vector<complex<double>> message2;
    printf("scale : %.10lf\n",plaintext.scale());

    Ciphertext ct,ct2;
    enc.encrypt(plaintext,ct);
    auto ckks_eva = EvaluatorFactory::DefaultFactory()->create(context);
    Timestacs timestacs;
    timestacs.start();
    ckks_eva->multiplyByDiagMatrixBSGS(ct,matrixPlain,cipherRes,rotKeys);
    timestacs.end();
    timestacs.print_time("PIR TIME : ");
    ckks_eva->read(cipherRes);
    dec.decrypt(cipherRes,plaintext2);

    ckks_encoder.decode(plaintext2,message2);
    for(int i = 0; i < 8; i++){
        printf("result vec[%d] : %0.10f + %0.10f I \n",i,real(mat[1][i]), imag(mat[1][i]));
        printf("result vec[%d] : %0.10f + %0.10f I \n",i,real(message2[i]), imag(message2[i]));
    }



    return 0;
}
