#include <iostream>
#include <fstream>   //头文件包含
#include "poseidon/Release/define.h"
#include "poseidon/Release/homomorphic_DFT.h"
#include "kuku/kuku.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <gmpxx.h>

#include <cstdlib>
#include <vector>
#include <cmath>
#include <complex>
#define RNS_C 2


#include "poseidon/Release/util/number_theory.h"
#include "poseidon/Release/hardware/ConfigGen.h"

#include <gmpxx.h>
#include "poseidon/Release/Ciphertext.h"

#include "poseidon/Release/util/matrix_operation.h"
#include "poseidon/Release/CKKSEncoder.h"
#include "poseidon/Release/BatchEncoder.h"
#include "poseidon/Release/random/random_sample.h"

#include "poseidon/Release/random/RandomGen.h"
#include "poseidon/Release/random/Blake2xbPRNG.h"
#include "poseidon/Release/KeyGenerator.h"
#include "poseidon/Release/Encryptor.h"
#include "poseidon/Release/Decryptor.h"
#include "poseidon/Release/ParametersLiteral.h"
#include "poseidon/Release/rlwe.h"
#include "poseidon/Release/RelinKeys.h"

#include "poseidon/Release/Evaluator.h"
#include "poseidon/Release/HardwareEvaluator.h"

#include "poseidon/Release/bfv/MemoryPool2.h"
#include "poseidon/Release/linear_transform.h"
#include "poseidon/Release/util/matrix_operation.h"
#include "poseidon/Release/util/cosine_approx.h"
#include "oprf.cpp"
#include "item.h"
#include "ecpoint.h"
#include "gsl/span"

using namespace std;
using  namespace  poseidon;
using namespace kuku;
using namespace oprf;
using namespace poseidon::util;

vector<int> polynomialCoefficients(const vector<int>& roots) {
    vector<int> coefficients = {1}; // 初始化为只有一个系数1（即1）

    // 对于每个根，逐步更新系数
    for (int root : roots) {
        vector<int> newCoefficients(coefficients.size() + 1, 0);

        // 计算新的系数
        for (size_t i = 0; i < coefficients.size(); ++i) {
            newCoefficients[i + 1] += root * coefficients[i];
            newCoefficients[i] += coefficients[i];
        }

        coefficients = newCoefficients;
    }

    // 由于每次根的符号都是负的，因此最终每个系数需要乘以-1的i次幂
    for (size_t i = 0; i < coefficients.size(); i++) {
        if (i % 2 == 1) {
            coefficients[i] = -coefficients[i];
        }
    }

    if(roots.size()% 2 == 1){
        for(size_t i = 0; i < coefficients.size(); i++){
            coefficients[i] = -coefficients[i];
        }
    }
    
    return coefficients;
}

int main(){
    


    BFVParametersLiteralDefault ckks_param_literal(degree_16384);
    PoseidonContext context(ckks_param_literal);

    //===================== BFV ============================
    PublicKey public_key1;
    Ciphertext encrypted_result,scencrypted,encrypteddata;
    RelinKeys relinKeys;
    GaloisKeys rotKeys;
    uint32_t degree = 1 << ckks_param_literal.LogN;
    vector<uint32_t> data;
    vector<int> roots = {2, 3, 4};
    vector<int> coefficients = polynomialCoefficients(roots);
    
    
    vector<uint32_t> coeffs;
    
    for(int i=coefficients.size()-1;i>=0;i--){
        if(coefficients[i]>=0){
            coeffs.push_back(coefficients[i]);
        }
        else{
            coeffs.push_back(65537+coefficients[i]);
        }
    }
    
    for (int coeff : coeffs) {
        cout << coeff << " ";
    }
    cout << endl;
    
    default_random_engine e;
    
    

    Plaintext plain,scplain;
    

    
    vector<uint32_t> rot_elemt{degree*2-1,25};
    KeyGenerator kgen1(context);
    BatchEncoder bfv_encoder(context);
    
    
    kgen1.create_public_key(public_key1);
    kgen1.create_relin_keys(relinKeys);
    kgen1.create_galois_keys(rot_elemt,rotKeys);
    
    Encryptor enc1(context,public_key1,kgen1.secret_key());
    Decryptor dec1(context,kgen1.secret_key());
    uniform_int_distribution<unsigned >u(0, sqrt(ckks_param_literal.T));

    for(int i = 0; i < 1 << ckks_param_literal.LogSlots; i++){
        data.push_back(1);
    }

    




    BatchEncoder bfvenc(context);
    
    bfvenc.encode(data,plain);
    enc1.encrypt(plain, encrypteddata);
    
    

    
    auto eva = EvaluatorFactory::SoftFactory()->create(context,relinKeys);
    
    Ciphertext temp_result;
    Ciphertext powerx;
    int levelA,levelB,levelDiff;


    
    
    // 首先加密 Plaintext


    vector<uint32_t> sc;
    int count=0;
    for(int i = 0; i < 1 << ckks_param_literal.LogSlots; i++){
        sc.push_back(coeffs[count]);
    }
    count++;
    bfvenc.encode(sc,scplain);
    enc1.encrypt(scplain, scencrypted);
    encrypted_result=scencrypted;

    for (int j = 1; j < coeffs.size(); ++j) {
        // 计算x的下一个幂
        eva->compute_powers(encrypteddata, j, powerx, relinKeys);

        for(int i = 0; i < 1 << ckks_param_literal.LogSlots; i++){
            sc[i]=coeffs[count];
        }
        count++;
        bfvenc.encode(sc,scplain);
        enc1.encrypt(scplain, scencrypted);

        levelA = powerx.metaData()->getLevel();
        levelB = scencrypted.metaData()->getLevel();
        levelDiff = levelB - levelA;
        if(levelDiff != 0){
            while( levelDiff>0 ){
                eva->rescale(scencrypted);
                levelDiff--;
            }
         }

        eva->multiply(scencrypted, powerx, temp_result, relinKeys);

        levelA =encrypted_result.metaData()->getLevel();
        levelB = temp_result.metaData()->getLevel();
        if(levelA>levelB){
            int levelDiff = levelA - levelB;
            while( levelDiff > 0 ){
                eva->rescale(encrypted_result);
                levelDiff--;
            }
        }
        else if(levelB > levelA){
           int levelDiff = levelB - levelA;
            while( levelDiff > 0 ){
                eva->rescale(temp_result);
                levelDiff--;
            } 
        }
    

        eva->add(encrypted_result, temp_result, encrypted_result);

    }
    

        
    eva->read(encrypted_result);
        
        
    

    // 最终结果存储在 temp_result 中


    Plaintext decrypted_result;
    
    dec1.decrypt(encrypted_result, decrypted_result);

    vector<uint32_t> result_data;
     

    
    bfvenc.decode(decrypted_result,result_data);

    for(int i = 0; i < 5; i++){
        printf("result[%d] : %ld \n",i,result_data[i]);

    }


    
}



