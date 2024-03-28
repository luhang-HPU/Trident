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
#include "oprf.cpp"
#include "item.h"
#include "ecpoint.h"
#include "gsl/span"
#include "kuku/kuku.h"

using namespace std;
using  namespace  poseidon;
using namespace kuku;
using namespace oprf;

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

void create_eva(const vector<HashedItem> &items,const vector<HashedItem> &serms)
{
    IndexTranslationTable itt;
    itt.item_count_ = items.size();

    // 创建布谷鸟哈希表
    KukuTable cuckoo(
        10,      // 哈希表大小
        0,                                      // 不使用stash
        3, // 哈希函数数量
        { 0, 0 },                               // 用硬编码的 { 0, 0 } 作为哈希函数的种子
        500,           // 定义 Cuckoo 哈希表插入操作的尝试次数
        { 0, 0 });                              // 定义空元素的值


    {
       for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
            const auto &item = items[item_idx];
            if (!cuckoo.insert(item.get_as<kuku::item_type>().front())) {
                //Cuckoo 哈希表的过程中可能遇到的两种失败情况：
                //如果要插入的项已经在哈希表中，插入操作将不会进行，并且返回的 "leftover item"（剩余项）为空。
              if (cuckoo.is_empty_item(cuckoo.leftover_item())) {
                    throw invalid_argument("Skipping repeated insertion of items");
                }
            }
        }
    }
   print_table(cuckoo);
   
   
   for (const auto& test : serms) 
   QueryResult res = cuckoo.query(test.get_as<kuku::item_type>().front());
   if (res)
        {
            cout << "Location: " << res.location() << endl;

        }
   
   
    // 填充表格后，填充table_idx_to_item_idx映射
    for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
        auto item_loc = cuckoo.query(items[item_idx].get_as<kuku::item_type>().front());
    }
    printf("create query!!!");
}



int main(){
    int rec_size=2;
    vector<Item> rec_items;
    for (size_t i = 0; i < rec_size; i++) {
        rec_items.push_back({ i + 1, ~(i + 1) });
    }
    for (const auto& item : rec_items) {
    const auto& value = item.value(); // 获取 value 数组

        // 以十进制格式打印数组的每个字节
    for (unsigned char byte : value) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
    process_items(rec_items);
    OPRFKey oprf_key;
    //printf("good");

    auto queries_span = gsl::make_span(oprf_queries_);
    
    
    std::vector<unsigned char> oprf_responses = ProcessQueries(queries_span, oprf_key);
    
    vector<HashedItem> hashed_recv_items(2);

    
    process_responses(oprf_responses,hashed_recv_items);
    
    create_query(hashed_recv_items);
    
    int sender_size=5;
    vector<Item> sen_items;
    for (size_t i = 0; i < sender_size; i++) {
        sen_items.push_back({ i + 1, ~(i + 1) });
    }
    
    
    for (const auto& item : sen_items) {
    const auto& value = item.value(); // 获取 value 数组

        // 以十进制格式打印数组的每个字节
    for (unsigned char byte : value) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
        
    }
    std::vector<unsigned char> db_responses = process_db(sen_items,oprf_key);
    
    vector<HashedItem> hashed_sen_items(5); 
    process_dbresponses(db_responses,hashed_sen_items);
    
    create_eva(hashed_sen_items,hashed_recv_items);
    
    


}



