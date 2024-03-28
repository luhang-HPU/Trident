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

using namespace std;
using  namespace  poseidon;
using namespace kuku;


void psi(){
    BFVParametersLiteralDefault ckks_param_literal(degree_8192);
    PoseidonContext context(ckks_param_literal);
    KukuTable cuckoo(5, // 哈希表大小
                0,      // 不使用stash
                2,      // 哈希函数数量
                { 0, 0 },    // 用硬编码的 { 0, 0 } 作为哈希函数的种子
                1,           // 定义 Cuckoo 哈希表插入操作的尝试次数
                { 0, 0 }); 

    //===================== BFV ============================
    PublicKey public_key1;
    Plaintext plainA,plainB,plainC,plainD;
    Ciphertext ciphA,ciphB,ciphC,ciphD,ciphRes1,ciphRes2,ciphRes;
    RelinKeys relinKeys;
    GaloisKeys rotKeys;
    uint32_t degree = 1 << ckks_param_literal.LogN;
    vector<uint32_t> rot_elemt{degree*2-1,25};
    KeyGenerator kgen1(context);


    kgen1.create_public_key(public_key1);
    kgen1.create_relin_keys(relinKeys);
    kgen1.create_galois_keys(rot_elemt,rotKeys);
    Encryptor enc1(context,public_key1,kgen1.secret_key());
    Decryptor dec1(context,kgen1.secret_key());


    default_random_engine e;
    vector<uint32_t> ccc,ddd;
    uniform_int_distribution<unsigned >u(0, sqrt(ckks_param_literal.T));
    for(int i = 0; i < 1 << ckks_param_literal.LogSlots; i++){
        ccc.push_back(i);
        //ccc.push_back(u(e));
    }
    BatchEncoder bfvenc(context);
    bfvenc.encode(ccc,plainA);
    bfvenc.encode(ccc,plainB);

    enc1.encrypt(plainA,ciphA);
    enc1.encrypt(plainB,ciphB);


    auto eva = EvaluatorFactory::SoftFactory()->create(context,relinKeys);
    auto start = chrono::high_resolution_clock::now();
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);

    //MULTIPLY
    print_example_banner("Example: MULTIPLY / MULTIPLY in BFV");
    start = chrono::high_resolution_clock::now();
    //eva->rotate_row(ciphA,1,rotKeys,ciphRes1);



    //eva->rescale(ciphRes);
    eva->read(ciphRes1);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "EXP TIME: " << duration.count() << " microseconds"<< endl;

    dec1.decrypt(ciphRes1,plainD);
    bfvenc.decode(plainD,ddd);
    for(int i = 0; i < 10; i++){
        //printf("source vec[%d] : %0.10f + %0.10f I \n",i,real(messageReal2[i].real()),imag(messageReal2[i].real()));
        printf("source vec[%d] : %d \n",i,ccc[i]);
        printf("result vec[%d] : %d \n",i,ddd[i]);
    }


}



