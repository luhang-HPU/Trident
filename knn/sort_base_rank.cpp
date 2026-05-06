#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/precision.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/util/thread_pool.h"
#include "poseidon/util/log.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace poseidon;
using namespace poseidon::util;


Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale)
{
    Plaintext plain;
    Ciphertext ciph;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
    return ciph;
}

std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph)
{
    Plaintext plain;
    decryptor.decrypt(ciph, plain);
    std::vector<std::complex<double>> message;
    encoder.decode(plain, message);
    return message;
}

void mask(Ciphertext &ct, size_t slot_count, const CKKSEncoder &encoder,
          std::shared_ptr<EvaluatorCkksBase> &evaluator, const GaloisKeys &rot_keys, double scale)
{
    std::vector<std::complex<double>> mask_vec(slot_count, {1.0, 0.0});
    Plaintext mask_plain;
    encoder.encode(mask_vec, ct.parms_id(), scale, mask_plain);

    evaluator->multiply_plain(ct, mask_plain, ct);
    evaluator->rescale_dynamic(ct, ct, scale);
}

void match_param_id(Ciphertext &ciph1, Ciphertext &ciph2,
                    std::shared_ptr<EvaluatorCkksBase> evaluator)
{
    if (ciph1.level() > ciph2.level())
    {
        evaluator->drop_modulus(ciph1, ciph1, ciph2.parms_id());
    }
    else if (ciph1.level() < ciph2.level())
    {
        evaluator->drop_modulus(ciph2, ciph2, ciph1.parms_id());
    }
}

void match_scale(Ciphertext &ciph1, Ciphertext &ciph2,
                 const int slot_size,
                 const CKKSEncoder &encoder,
                 std::shared_ptr<EvaluatorCkksBase> evaluator,
                 double scale)
{
    if (!util::are_approximate(ciph1.scale(), ciph2.scale()))
    {
        ciph1.scale() = ciph2.scale();
        std::vector<std::complex<double>> vec_tmp(slot_size, {1.0, 0.0});
        Plaintext plt_tmp;

        // for ciph1
        encoder.encode(vec_tmp, ciph1.parms_id(), scale * scale / ciph1.scale(), plt_tmp);
        evaluator->multiply_plain(ciph1, plt_tmp, ciph1);
        evaluator->rescale(ciph1, ciph1);

        // for ciph2
        encoder.encode(vec_tmp, ciph2.parms_id(), scale * scale / ciph2.scale(), plt_tmp);
        evaluator->multiply_plain(ciph2, plt_tmp, ciph2);
        evaluator->rescale(ciph2, ciph2);
    }
}

// 行复制 v1 v2 v3 v1 v2 v3 v1 v2 v3
Ciphertext replRow(const Ciphertext &ct, const size_t slot_count,
                   std::shared_ptr<EvaluatorCkksBase> &evaluator, const GaloisKeys &rot_keys)
{
    auto ciph_tmp = ct;
    Ciphertext ciph_tmp_rotate;
    for (size_t i = 1; i <= std::log2(slot_count); i++)
    {
        int rotation_step = -(std::pow(2, i - 1) * slot_count);
        evaluator->rotate(ciph_tmp, ciph_tmp_rotate, rotation_step, rot_keys);
        evaluator->add(ciph_tmp, ciph_tmp_rotate, ciph_tmp);
    }
    return ciph_tmp;
}

// // 列复制 v1 v1 v1 v2 v2 v2 v3 v3 v3
// Ciphertext replCol(Ciphertext &ct, const size_t slot_count, const CKKSEncoder &encoder,
//                    std::shared_ptr<EvaluatorCkksBase> &evaluator, const GaloisKeys &rot_keys, double scale)
// {
//     auto ciph_tmp = ct;
//     Ciphertext ciph_tmp_rotate;
//     Ciphertext ciph_result = ct;
//     std::vector<std::complex<double>> mask_vec(slot_count, {0.0, 0.0});
//     mask_vec[0] = 1.0;
//     Plaintext mask_plain;
//     encoder.encode(mask_vec, scale, mask_plain);
//     evaluator->multiply_plain(ciph_result, mask_plain, ciph_result);
//     evaluator->rescale_dynamic(ciph_result, ciph_result, scale);
//     for (size_t i = 1; i < slot_count; i++)
//     {
//         // 将 v1 v2 v3 每个槽左旋到第一位
//         evaluator->rotate(ciph_tmp, ciph_tmp_rotate, i, rot_keys);
//         evaluator->multiply_plain(ciph_tmp_rotate, mask_plain, ciph_tmp_rotate);
//         evaluator->rescale_dynamic(ciph_tmp_rotate, ciph_tmp_rotate, scale);

//         // v1     v2     v3    将右旋到对应位置
//         int rotation_step = -(i * slot_count);
//         evaluator->rotate(ciph_tmp_rotate, ciph_tmp_rotate, rotation_step, rot_keys);
//         evaluator->add(ciph_result, ciph_tmp_rotate, ciph_result);
//     }
//     for (size_t i = 1; i <= std::log2(slot_count); i++)
//     {
//         int rotation_step = -(std::pow(2, i - 1) * slot_count);
//         evaluator->rotate(ciph_result, ciph_tmp_rotate, rotation_step, rot_keys);
//         evaluator->add(ciph_result, ciph_tmp_rotate, ciph_result);
//     }
//     return ciph_result;
// }

// 列复制 v1 v1 v1 v2 v2 v2 v3 v3 v3
Ciphertext replCol(const Ciphertext &ct,
                   const size_t slot_count,
                   const size_t slot_size,
                   const CKKSEncoder &encoder,
                   std::shared_ptr<EvaluatorCkksBase> &evaluator,
                   const GaloisKeys &rot_keys,
                   double scale)
{
    auto ciph_tmp = ct;
    Ciphertext ciph_tmp_rotate;
    Ciphertext ciph_result = ct;
    std::vector<std::complex<double>> mask_vec(slot_size, {0.0, 0.0});
    for (size_t i = 0; i < slot_count * slot_count; i += slot_count)
    {
        mask_vec[i] = 1.0;
    }
    Plaintext mask_plain;
    encoder.encode(mask_vec, scale, mask_plain);

    int rotation_step = -(slot_count - 1);
    for (size_t i = 1; i < slot_count; i++)
    {
        // v1     v2     v3    将右旋到对应位置
        evaluator->rotate(ciph_tmp, ciph_tmp, rotation_step, rot_keys);
        evaluator->add(ciph_result, ciph_tmp, ciph_result);
    }

    // 每一组首位与 1 相乘， 进行提取
    evaluator->multiply_plain(ciph_result, mask_plain, ciph_result);
    evaluator->rescale_dynamic(ciph_result, ciph_result, scale);

    // 列扩展
    for (size_t i = 0; i < std::log2(slot_count); i++)
    {
        rotation_step = -std::pow(2, i);
        evaluator->rotate(ciph_result, ciph_tmp_rotate, rotation_step, rot_keys);
        evaluator->add(ciph_result, ciph_tmp_rotate, ciph_result);
    }
    return ciph_result;
}

// 符号函数
Ciphertext sign(const Ciphertext &ciph,
                const int slot_size,
                const CKKSEncoder &encoder,
                std::shared_ptr<EvaluatorCkksBase> evaluator,
                const RelinKeys &relin_keys,
                const GaloisKeys &rot_keys,
                double scale)
{
    // 多项式创建
    vector<vector<int>> slots_index(1, vector<int>(slot_size, 0));
    vector<int> idxF(slot_size);
    for (int i = 0; i < slot_size; i++)
    {
        idxF[i] = i;
    }
    slots_index[0] = idxF;

    // 多项式 1
    vector<complex<double>> buffer = {0, 3.816912, 0, -9.226954, 0, 11.954844, 0, -5.516258};
    Polynomial approxF_1(buffer, 0, 0, 7, Monomial);
    approxF_1.lead() = true;
    vector<Polynomial> poly_1{approxF_1};
    PolynomialVector polys_1(poly_1, slots_index);

    // 多项式 2
    buffer = {
        0, 2.5390678487943066, 0, -15.36649590685934, 0, 72.05487340640471, 0, -229.83084441307128,
        0, 510.7603223522984, 0, -810.2812835443851, 0, 932.3382320828513, 0, -783.7465043857175,
        0, 480.4851545467111, 0, -212.16308093582333, 0, 65.63925462800184, 0, -13.490628831305791,
        0, 1.6532569365778251, 0, -0.091371472313767};
    Polynomial approxF_2(buffer, 0, 0, 27, Monomial);
    approxF_2.lead() = true;
    vector<Polynomial> poly_2{approxF_2};
    PolynomialVector polys_2(poly_2, slots_index);

    Ciphertext ciph_result = ciph;
    evaluator->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys, encoder);
    evaluator->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys, encoder);

    // 拟合结果为 [-0.5, 0.5], 需要 + 0.5
    evaluator->add_const(ciph_result, 0.5, ciph_result, encoder);
    return ciph_result;
}

Ciphertext cmp(const Ciphertext &ciph1,
               const Ciphertext &ciph2,
               const int slot_size,
               const CKKSEncoder &encoder,
               std::shared_ptr<EvaluatorCkksBase> evaluator,
               const RelinKeys &relin_keys,
               const GaloisKeys &rot_keys,
               double scale)
{
    Ciphertext ciph_result;
    evaluator->sub_dynamic(ciph1, ciph2, ciph_result, encoder);
    ciph_result = sign(ciph_result, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    return ciph_result;
}

Ciphertext ind(const Ciphertext &ciph,
               const int slot_size,
               const CKKSEncoder &encoder,
               std::shared_ptr<EvaluatorCkksBase> evaluator,
               const RelinKeys &relin_keys,
               const GaloisKeys &rot_keys,
               double scale)
{
    Ciphertext ciph_result;
    Ciphertext ciph_tmp = ciph;
    // 缩小10倍
    evaluator->multiply_const(ciph_tmp, -0.1, scale, ciph_tmp, encoder);
    evaluator->rescale_dynamic(ciph_tmp, ciph_tmp, scale);
    Ciphertext ciph_cmp = sign(ciph_tmp, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    // - cmp(x, a)
    evaluator->multiply_const(ciph_cmp, -1.0, scale, ciph_tmp, encoder);
    evaluator->rescale_dynamic(ciph_tmp, ciph_tmp, scale);

    // cmp(x,a)(1 - cmp(x, a))
    evaluator->add_const(ciph_tmp, 1.0, ciph_tmp, encoder);
    match_param_id(ciph_tmp, ciph_cmp, evaluator);
    match_scale(ciph_tmp, ciph_cmp, slot_size, encoder, evaluator, scale);
    evaluator->multiply_relin(ciph_cmp, ciph_tmp, ciph_result, relin_keys);
    evaluator->rescale_dynamic(ciph_result, ciph_result, scale);

    // 乘 4
    evaluator->multiply_const(ciph_result, 4.0, scale, ciph_result, encoder);
    evaluator->rescale_dynamic(ciph_result, ciph_result, scale);
    return ciph_result;
}

Ciphertext sum_row(const Ciphertext &ciph, const size_t slot_count, const CKKSEncoder &encoder,
                   const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                   const GaloisKeys rot_keys)
{
    int n = slot_count;
    if (n <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "n cannot be negative");
    }

    Ciphertext ciph_rotate_sum = ciph;

    std::vector<std::complex<double>> zero = {{0.0, 0.0}};
    Plaintext plain_zero;
    Ciphertext ciph_sum;
    encoder.encode(zero, ciph.parms_id(), ciph.scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_sum);

    int cnt = 0;
    int bottom_nth = 0;
    const int const_n = n;
    while (n > 1)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
            ckks_eva->rotate(ciph_rotate_sum, ciph_rotate_sum, slot_count, rot_keys);
            n--;
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, n * slot_count, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

Ciphertext sum_col(const Ciphertext &ciph, const size_t slot_count, const CKKSEncoder &encoder,
                   const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                   const GaloisKeys rot_keys)
{
    int n = slot_count;
    if (n <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "n cannot be negative");
    }

    Ciphertext ciph_rotate_sum = ciph;

    std::vector<std::complex<double>> zero = {{0.0, 0.0}};
    Plaintext plain_zero;
    Ciphertext ciph_sum;
    encoder.encode(zero, ciph.parms_id(), ciph.scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_sum);

    int cnt = 0;
    int bottom_nth = 0;
    const int const_n = n;
    while (n > 1)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
            ckks_eva->rotate(ciph_rotate_sum, ciph_rotate_sum, 1, rot_keys);
            n--;
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, n, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

Ciphertext trans_row(const Ciphertext &ct,
                     const size_t slot_count,
                     const size_t slot_size,
                     const CKKSEncoder &encoder,
                     std::shared_ptr<EvaluatorCkksBase> &evaluator,
                     const GaloisKeys &rot_keys,
                     double scale,
                    Decryptor &decryptor)
{
    auto ciph_tmp = ct;

    std::vector<std::complex<double>> mask_vec(slot_size, {0.0, 0.0});
    for (size_t i = 0; i < slot_count * slot_count; i += slot_count)
    {
        mask_vec[i] = 1.0;
    }
    Plaintext mask_plain;
    encoder.encode(mask_vec, ciph_tmp.parms_id(), scale, mask_plain);

    evaluator->multiply_plain(ciph_tmp, mask_plain, ciph_tmp);
    evaluator->rescale_dynamic(ciph_tmp, ciph_tmp, scale);

    Ciphertext ciph_tmp_rotate = ciph_tmp;
    int rotation_step = slot_count - 1;
    for (size_t i = 1; i < slot_count; i++)
    {
        evaluator->rotate(ciph_tmp_rotate, ciph_tmp_rotate, rotation_step, rot_keys);
        evaluator->add(ciph_tmp, ciph_tmp_rotate, ciph_tmp);
    }
    return ciph_tmp;
}

Ciphertext cal_rank(const Ciphertext &ciph,
                    Ciphertext &ciph_cmp,
                    const int slot_count,
                    const int slot_size,
                    const CKKSEncoder &encoder,
                    const Encryptor &encryptor,
                    std::shared_ptr<EvaluatorCkksBase> evaluator,
                    const RelinKeys &relin_keys,
                    const GaloisKeys &rot_keys,
                    double scale,
                    Decryptor &decryptor)
{
    // 行复制
    Ciphertext ciph_tmp_1 = replRow(ciph, slot_count, evaluator, rot_keys);
    // 列复制
    Ciphertext ciph_tmp_2 = replCol(ciph, slot_count, slot_size, encoder, evaluator, rot_keys, scale);

    // 比较大小
    Ciphertext ciph_rank = cmp(ciph_tmp_1, ciph_tmp_2, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    ciph_cmp = ciph_rank;
    // 旋转累加
    ciph_rank = sum_row(ciph_rank, slot_count, encoder, encryptor, evaluator, rot_keys);

    // + 0.5
    evaluator->add_const(ciph_rank, 0.5, ciph_rank, encoder);
    return ciph_rank;
}

Ciphertext sort_product_rank(const Ciphertext &ciph,
                             Ciphertext &ciph_rank,
                             Ciphertext &ciph_cmp,
                             const int slot_count,
                             const int slot_size,
                             const CKKSEncoder &encoder,
                             const Encryptor &encryptor,
                             std::shared_ptr<EvaluatorCkksBase> evaluator,
                             const RelinKeys &relin_keys,
                             const GaloisKeys &rot_keys,
                             double scale,
                             Decryptor &decryptor)
{
    mask(ciph_rank, slot_count, encoder, evaluator, rot_keys, scale);
    ciph_rank = replRow(ciph_rank, slot_count, evaluator, rot_keys);
    // 生成 constant 用于和 rank 做差
    std::vector<std::complex<double>> constant_vec(slot_size, {0.0, 0.0});
    for (size_t i = 0; i < slot_count; i++)
    {
        for (size_t j = 0; j < slot_count; j++)
        {
            constant_vec[j + slot_count * i] = i + 1;
        }
    }
    Ciphertext ciph_constant = encode_and_encrypt(encoder, encryptor, constant_vec, scale);

    // 排名与索引相减
    Ciphertext ciph_result;
    match_param_id(ciph_constant, ciph_rank, evaluator);
    match_scale(ciph_constant, ciph_rank, slot_size, encoder, evaluator, scale);
    evaluator->sub_dynamic(ciph_rank, ciph_constant, ciph_result, encoder);
    // ind(0)
    ciph_result = ind(ciph_result, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    // 原数组 行复制
    Ciphertext ciph_row_repl = replRow(ciph, slot_count, evaluator, rot_keys);

    // product
    match_param_id(ciph_result, ciph_row_repl, evaluator);
    match_scale(ciph_result, ciph_row_repl, slot_size, encoder, evaluator, scale);
    evaluator->multiply_relin(ciph_result, ciph_row_repl, ciph_result, relin_keys);
    evaluator->rescale_dynamic(ciph_result, ciph_result, scale);

    // 累加到每行首位
    ciph_result = sum_col(ciph_result, slot_count, encoder, encryptor, evaluator, rot_keys);
    ciph_result = trans_row(ciph_result, slot_count, slot_size, encoder, evaluator, rot_keys, scale, decryptor);

    return ciph_result;
}

int main(int argc, char *argv[])
{
    util::Timestacs timer;
    util::Timestacs timer_init;
    util::Timestacs timer_rank;
    util::Timestacs timer_sort;
    timer.start();
    timer_init.start();
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 16;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(33, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto slot_size = context.parameters_literal()->degree() >> 1;
    double scale = std::pow(2.0, q_def);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys conj_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // init keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    util::Timestacs timer_rot;
    timer_rot.start();
    // kgen.create_galois_keys(rot_keys);
    kgen.create_galois_keys_mt(rot_keys, 32);
    timer_rot.end();

    Encryptor encryptor(context, public_key, kgen.secret_key());
    Decryptor decryptor(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_evaluator =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    timer_init.end();
    // 密文中实际使用的槽位数量
    int slot_count = 8;

    // 待排序密文
    std::vector<std::complex<double>> message(slot_size, {0.0, 0.0});
    message = {{0.3, 0.0}, {0.2, 0.0}, {0.1, 0.0}, {0.4, 0.0}, {0.8, 0.0}, {0.9, 0.0}, {0.7, 0.0}, {0.6, 0.0}};
    Ciphertext ciph = encode_and_encrypt(ckks_encoder, encryptor, message, scale);

    // 先计算rank
    timer_rank.start();
    Ciphertext ciph_cmp;
    Ciphertext ciph_rank = cal_rank(ciph, ciph_cmp, slot_count, slot_size, ckks_encoder, encryptor, ckks_evaluator, relin_keys, rot_keys, scale, decryptor);
    timer_rank.end();

    timer_sort.start();
    // 对原数组排序
    Ciphertext ciph_res = sort_product_rank(ciph, ciph_rank, ciph_cmp, slot_count, slot_size, ckks_encoder, encryptor, ckks_evaluator, relin_keys, rot_keys, scale, decryptor);
    timer_sort.end();

    timer.end();


    return 0;
}
