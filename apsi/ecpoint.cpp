// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.


//构造函数 ECPoint()：设置曲线点为中性元素。
//构造函数 ECPoint(input_span_const_type value)：接受一个输入值，并通过Blake2b哈希和HashToCurve函数转换为椭圆曲线点。
//static void MakeRandomNonzeroScalar(scalar_span_type out)：生成一个非零标量。
//static void InvertScalar(scalar_span_const_type in, scalar_span_type out)：计算给定标量的逆。
//bool scalar_multiply(scalar_span_const_type scalar, bool clear_cofactor)：使用给定的标量对ECPoint实例进行标量乘法，并根据clear_cofactor标志决定是否清除余因子。
//ECPoint &operator=(const ECPoint &assign)：赋值运算符重载。
//void save(ostream &stream) const：保存ECPoint到输出流。
//void load(istream &stream)：从输入流加载ECPoint。
//void save(point_save_span_type out) const：保存ECPoint到输出缓冲区。
//void load(point_save_span_const_type in)：从输入缓冲区加载ECPoint。
//void extract_hash(hash_span_type out) const：提取ECPoint的哈希。
//辅助函数：
//set_neutral_point：设置曲线点为中性元素。
//fourq_point_to_point_type 和 point_type_to_fourq_point：在FourQ库的点类型和ECPoint的点类型之间进行转换。
//random_scalar：生成一个随机标量。
//is_nonzero_scalar：检查标量是否非零。
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
#include "poseidon/Release/common.h"


// STD
#include <algorithm>
#include <functional>
#include "poseidon/Release/define.h"

// APSI
#include "ecpoint.h"


// FourQ
#include "fourq/FourQ.h"
#include "fourq/FourQ_api.h"
#include "fourq/FourQ_internal.h"
#include "fourq/random.h"


#include "poseidon/Release/random/blake2.h"

using namespace std;
using namespace poseidon;


namespace oprf {
    // Ensure our size constants are correct
    static_assert(ECPoint::save_size == sizeof(f2elm_t));
    static_assert(ECPoint::point_size == sizeof(point_t));
    static_assert(ECPoint::order_size == sizeof(digit_t) * NWORDS_ORDER);

    namespace {
        constexpr point_t neutral = { { { { 0 } }, { { 1 } } } }; // { {.x = { 0 }, .y = { 1 } }};

        void set_neutral_point(ECPoint::point_span_type pt) {
            copy_n(reinterpret_cast<const unsigned char *>(neutral), ECPoint::point_size, pt.data());
        }
        void fourq_point_to_point_type(const point_t fourq_pt, ECPoint::point_span_type pt) {
            copy_n(reinterpret_cast<const unsigned char *>(fourq_pt), ECPoint::point_size, pt.data());
        }
        void point_type_to_fourq_point(ECPoint::point_span_const_type pt, point_t fourq_pt) {
            copy_n(pt.data(), ECPoint::point_size, reinterpret_cast<unsigned char *>(fourq_pt));
        }
        void random_scalar(ECPoint::scalar_span_type value)
        {
            random_bytes(value.data(), static_cast<unsigned int>(value.size()));
            modulo_order(
                reinterpret_cast<digit_t *>(value.data()),
                reinterpret_cast<digit_t *>(value.data()));
        }
        digit_t is_nonzero_scalar(ECPoint::scalar_span_type value)
        {
            const digit_t *value_ptr = reinterpret_cast<digit_t *>(value.data());
            digit_t c = 0;
            for (size_t i = 0; i < NWORDS_ORDER; i++) {
                c |= value_ptr[i];
            }
            sdigit_t first_nz = -static_cast<sdigit_t>(c & 1);
            sdigit_t rest_nz = -static_cast<sdigit_t>(c >> 1);
            return static_cast<digit_t>((first_nz | rest_nz) >> (8 * sizeof(digit_t) - 1));
        }
    } // namespace
    ECPoint::ECPoint()
    {
        set_neutral_point(pt_);
    }
    ECPoint::ECPoint(input_span_const_type value)
    {
        if (!value.empty()) {
            f2elm_t r;
            // 调用APSI_blake2b函数以计算value的Blake2b哈希值，并将结果存储在r中
            blake2b(
                reinterpret_cast<unsigned char *>(r),
                sizeof(f2elm_t),
                value.data(),
                static_cast<size_t>(value.size()),
                nullptr,
                0);
            // Reduce r; note that this does not produce a perfectly uniform distribution modulo
            // 2^127-1, but it is good enough.
            mod1271(r[0]);
            mod1271(r[1]);
            //将哈希值映射到椭圆曲线上的一个点
            point_t pt;
            HashToCurve(r, pt);
            fourq_point_to_point_type(pt, pt_);
        }
    }
    void ECPoint::MakeRandomNonzeroScalar(scalar_span_type out)
    {
        // Loop until we find a non-zero element
        do {
            random_scalar(out);
        } while (!is_nonzero_scalar(out));
    }
    void ECPoint::InvertScalar(scalar_span_const_type in, scalar_span_type out)
    {
        to_Montgomery(
            const_cast<digit_t *>(reinterpret_cast<const digit_t *>(in.data())),
            reinterpret_cast<digit_t *>(out.data()));
        Montgomery_inversion_mod_order(
            reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
        from_Montgomery(
            reinterpret_cast<digit_t *>(out.data()), reinterpret_cast<digit_t *>(out.data()));
    }
    //对 ECPoint 实例（椭圆曲线上的点）执行标量乘法操作，并更新该 ECPoint 实例的值。
    bool ECPoint::scalar_multiply(scalar_span_const_type scalar, bool clear_cofactor)
    {
        // The ecc_mul functions returns false when the input point is not a valid curve point
        point_t pt_P, pt_Q;
        //将 pt_ 转换为 FourQ 库可以处理的点的类型，并将结果存储在 pt_P 中。FourQ 库是专用于高效椭圆曲线密码学运算的软件库
        point_type_to_fourq_point(pt_, pt_P);
         //调用 ecc_mul 函数执行标量乘法运算
        bool ret = ecc_mul(
            pt_P,
            const_cast<digit_t *>(reinterpret_cast<const digit_t *>(scalar.data())),
            pt_Q,
            clear_cofactor);
        //将 pt_Q 转换回 pt_ 的类型，并更新 pt_ 的值。
        fourq_point_to_point_type(pt_Q, pt_);
        return ret;
    }
    ECPoint &ECPoint::operator=(const ECPoint &assign)
    {
        if (&assign != this) {
            pt_[0] = assign.pt_[0];
        }
        return *this;
    }
    void ECPoint::save(ostream &stream) const
    {
        auto old_ex_mask = stream.exceptions();
        stream.exceptions(ios_base::failbit | ios_base::badbit);
        try {
            array<unsigned char, save_size> buf;
            point_t pt;
            point_type_to_fourq_point(pt_, pt);
            encode(pt, buf.data());
            stream.write(reinterpret_cast<const char *>(buf.data()), save_size);
        } catch (const ios_base::failure &) {
            stream.exceptions(old_ex_mask);
            throw;
        }
        stream.exceptions(old_ex_mask);
    }
    void ECPoint::load(istream &stream)
    {
        auto old_ex_mask = stream.exceptions();
        stream.exceptions(ios_base::failbit | ios_base::badbit);
        try {
            array<unsigned char, save_size> buf;
            stream.read(reinterpret_cast<char *>(buf.data()), save_size);
            point_t pt;
            if (decode(buf.data(), pt) != ECCRYPTO_SUCCESS) {
                stream.exceptions(old_ex_mask);
                throw logic_error("invalid point");
            }
            fourq_point_to_point_type(pt, pt_);
        } catch (const ios_base::failure &) {
            stream.exceptions(old_ex_mask);
            throw;
        }
        stream.exceptions(old_ex_mask);
    }
    void ECPoint::save(point_save_span_type out) const
    {
        point_t pt;
        point_type_to_fourq_point(pt_, pt);
        encode(pt, out.data());
    }
    void ECPoint::load(point_save_span_const_type in)
    {
        point_t pt;
        if (decode(in.data(), pt) != ECCRYPTO_SUCCESS) {
            throw logic_error("invalid point");
        }
        fourq_point_to_point_type(pt, pt_);
    }
    void ECPoint::extract_hash(hash_span_type out) const
    {
        // Compute a Blake2b hash of the value and expand to hash_size
        point_t pt;
        point_type_to_fourq_point(pt_, pt);
        blake2b(out.data(), out.size(), pt->y, sizeof(f2elm_t), nullptr, 0);
    }
} // namespace oprf

