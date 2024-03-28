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
using namespace poseidon::util;


void compute_powers(Ciphertext &ciph,int exponent,Ciphertext &result,const RelinKeys &relinKeys){
    if(!ciph.isValid()){
        throw invalid_argument("compute_powers: ciph args miss!");
    }
    if(ciph.metaData()->isNTT() == false){
        throw invalid_argument("compute_powers: ciph is not NTT form!");
    }



    // 若指数为1，直接返回原始密文
    if (exponent == 1) {
        return;    
    } 

    int temp_result_set = 1;  // 标志，表示temp_result是否已设置
    
    if (exponent % 2 != 0) {
        result=ciph;
        temp_result_set = 0;
        exponent--;
    }
    else{
        eva->multiply(ciph,ciph,result,relinKeys);
        eva->rescale(result);
        exponent /= 2;
    }
    
    // 存储当前幂次的密文
    Ciphertext power;
    power=ciph;


    // 循环计算幂次，使用指数分解
    while (exponent > 1) {        

        // 如果指数是奇数，再乘以一个原始密文
        if (exponent % 2 != 0) {

            int levelA = result.metaData()->getLevel();
            int levelB = power.metaData()->getLevel();
            int levelDiff = levelA - levelB;
            if(levelDiff != 0){
                while( levelDiff>0 ){
                    eva->rescale(power);
                }
            }
            eva->multiply(result, power,result,relinKeys);
            eva->rescale(result);
            exponent--;
            }
        //偶数直接平方
        else
        {
            eva->multiply(result,result,result,relinKeys);
            eva->rescale(result);
            exponent /= 2;
            
          
        }
    }
    

    if (temp_result_set != 1)
    {

        int levelA = result.metaData()->getLevel();
        int levelB = power.metaData()->getLevel();
        int levelDiff = levelA - levelB;
        if(levelDiff != 0){
            while( levelDiff > 0 ){
                eva->rescale(power);
            }
        }

        eva->multiply(result,power,result,relinKeys); 
        eva->rescale(result);
        

    }
  

}



