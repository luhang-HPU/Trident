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

#include <fstream>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace poseidon;
using namespace poseidon::util;

#define DEBUG_LRTRAIN

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);
std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);

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
    evaluator->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys, encoder);

    // 拟合结果为 [-0.5, 0.5], 需要 + 0.5
    evaluator->add_const(ciph_result, 0.5, ciph_result, encoder);
    return ciph_result;
}

// 符号函数
Ciphertext sign_fake(const Ciphertext &ciph,
                     const int slot_size,
                     const CKKSEncoder &encoder,
                     std::shared_ptr<EvaluatorCkksBase> evaluator,
                     const RelinKeys &relin_keys,
                     const GaloisKeys &rot_keys,
                     double scale,
                     Encryptor &enc,
                     Decryptor &dec)
{
    // 多项式创建
    auto result = decrypt_and_decode(encoder, dec, ciph);

    for (size_t i = 0; i < slot_size; i++)
    {
        result[i].real((result[i].real() > 0) ? 1 : 0);
    }
    Ciphertext ciph_result = encode_and_encrypt(encoder, enc, result, scale);

    return ciph_result;
}

// 比较两个密文的大小，返回0，1
Ciphertext compare_two_ciph(const Ciphertext &ciph1, const Ciphertext &ciph2,
                            const int slot_count,
                            const int slot_size,
                            const CKKSEncoder &encoder,
                            std::shared_ptr<EvaluatorCkksBase> evaluator,
                            const RelinKeys &relin_keys,
                            const GaloisKeys &rot_keys,
                            double scale,
                            Encryptor &enc,
                            Decryptor &dec)
{
    Ciphertext ciph_tmp;
    evaluator->sub_dynamic(ciph2, ciph1, ciph_tmp, encoder);

    Ciphertext ciph_result = sign(ciph_tmp, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    // Ciphertext ciph_result = sign_fake(ciph_tmp, slot_size, encoder, evaluator, relin_keys, rot_keys, scale, enc, dec);

    return ciph_result;
}

// 复制密文
Ciphertext copy_ciph(const Ciphertext &ciph,
                     const int slot_count,
                     const int slot_size,
                     const CKKSEncoder &encoder,
                     std::shared_ptr<EvaluatorCkksBase> evaluator,
                     const RelinKeys &relin_keys,
                     const GaloisKeys &rot_keys,
                     double scale)
{
    Ciphertext ciph_result;

    vector<complex<double>> mask1(2 * slot_count, {0.0, 0.0});
    vector<complex<double>> mask2(2 * slot_count, {0.0, 0.0});

    for (int i = 0; i < slot_count; ++i)
    {
        mask1[i] = 1.0;
    }
    for (int i = slot_count; i < 2 * slot_count && i < slot_size; ++i)
    {
        mask2[i] = 1.0;
    }

    Plaintext plain;
    Ciphertext ciph_ct_mask1;
    Ciphertext ciph_ct_mask2;
    encoder.encode(mask1, ciph.parms_id(), ciph.scale(), plain);
    // ct * mask1
    evaluator->multiply_plain(ciph, plain, ciph_ct_mask1);
    evaluator->rescale_dynamic(ciph_ct_mask1, ciph_ct_mask1, scale);

    //  rotate(ct, -slot_count) * mask2
    evaluator->rotate(ciph, ciph_ct_mask2, -slot_count, rot_keys);
    encoder.encode(mask2, ciph_ct_mask2.parms_id(), ciph_ct_mask2.scale(), plain);
    evaluator->multiply_plain(ciph_ct_mask2, plain, ciph_ct_mask2);
    evaluator->rescale_dynamic(ciph_ct_mask2, ciph_ct_mask2, scale);

    evaluator->add(ciph_ct_mask1, ciph_ct_mask2, ciph_result);

    return ciph_result;
}

// 生成三对角密文
void MEncode(const Ciphertext &ciph,
             const int slot_count,
             const int slot_size,
             int s,
             int p,
             const CKKSEncoder &encoder,
             std::shared_ptr<EvaluatorCkksBase> evaluator,
             const RelinKeys &relin_keys,
             const GaloisKeys rot_keys,
             double scale,
             Ciphertext &ciph_sup_mask,
             Ciphertext &ciph_diag_mask,
             Ciphertext &ciph_sub_mask)
{

    Ciphertext ciph_tmp;
    vector<complex<double>> eli_vector(slot_size, {0.0, 0.0});
    int step = std::pow(2, s - p + 1);
    int half = std::pow(2, s - p);

    for (int i = 0; i < slot_count; i += step)
    {
        for (int j = i; j < i + half && j < slot_size; ++j)
        {
            eli_vector[j] = 1.0;
        }
        for (int j = i + half; j < i + step && j < slot_size; ++j)
        {
            eli_vector[j] = 0.0;
        }
    }

    evaluator->multiply_const(ciph, -1.0, ciph.scale(), ciph_tmp, encoder);
    evaluator->rescale_dynamic(ciph_tmp, ciph_tmp, scale);

    Plaintext eli_plain;
    encoder.encode(eli_vector, ciph_tmp.parms_id(), ciph_tmp.scale(), eli_plain);
    evaluator->add_plain(ciph_tmp, eli_plain, ciph_sub_mask);

    Ciphertext ciph_copy;
    ciph_copy = copy_ciph(ciph_sub_mask, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    evaluator->rotate(ciph_copy, ciph_sup_mask, slot_count - half, rot_keys);
    evaluator->rotate(ciph, ciph_tmp, -half, rot_keys);
    evaluator->add(ciph, ciph_tmp, ciph_diag_mask);
}

// 复制密文
Ciphertext HomOrdGen(const Ciphertext &ciph,
                     const int slot_count,
                     const int slot_size,
                     int s,
                     int p,
                     const CKKSEncoder &encoder,
                     std::shared_ptr<EvaluatorCkksBase> evaluator,
                     const RelinKeys &relin_keys,
                     const GaloisKeys rot_keys,
                     double scale,
                     Encryptor &enc,
                     Decryptor &dec)
{

    Ciphertext ciph_tmp;
    vector<complex<double>> mask_vector(slot_size, {0.0, 0.0});
    vector<complex<double>> eli_vector(slot_size, {0.0, 0.0});

    // 构造 mask_plain
    int block = std::pow(2, s + 2);
    int mid = std::pow(2, s + 1);

    for (int i = 0; i < slot_count; i += block)
    {
        for (int j = i; j < i + mid && j < slot_size; ++j)
            mask_vector[j] = 1.0;
        for (int j = i + mid; j < i + block && j < slot_size; ++j)
            mask_vector[j] = -1.0;
    }

    // 构造 eli_plain
    int step = pow(2, s - p + 1);
    int half = pow(2, s - p);
    for (int i = 0; i < slot_count; i += step)
    {
        for (int j = i; j < i + half && j < slot_size; ++j)
            eli_vector[j] = 1.0;
        for (int j = i + half; j < i + step && j < slot_size; ++j)
            eli_vector[j] = 0.0;
    }

    Plaintext mask_plain;
    encoder.encode(mask_vector, ciph.parms_id(), scale, mask_plain);

    Ciphertext ciph_ct_mask;
    evaluator->multiply_plain(ciph, mask_plain, ciph_ct_mask);
    evaluator->rescale_dynamic(ciph_ct_mask, ciph_ct_mask, scale);
    Ciphertext ciph_ct_mask_rotate;
    ciph_ct_mask = copy_ciph(ciph_ct_mask, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    evaluator->rotate(ciph_ct_mask, ciph_ct_mask_rotate, std::pow(2, s - p), rot_keys);

    auto ciph_cmp = compare_two_ciph(ciph_ct_mask, ciph_ct_mask_rotate, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale, enc, dec);

    Plaintext eli_plain;
    encoder.encode(eli_vector, ciph_cmp.parms_id(), ciph_cmp.scale(), eli_plain);
    evaluator->multiply_plain(ciph_cmp, eli_plain, ciph_cmp);
    evaluator->rescale_dynamic(ciph_cmp, ciph_cmp, scale);

    return ciph_cmp;
}

// 排序应用
Ciphertext HomOrdApp(const Ciphertext &ciph,
                     Ciphertext &ciph_index,
                     const int slot_count,
                     const int slot_size,
                     int s,
                     int p,
                     const CKKSEncoder &encoder,
                     std::shared_ptr<EvaluatorCkksBase> evaluator,
                     const RelinKeys &relin_keys,
                     const GaloisKeys rot_keys,
                     double scale,
                     Ciphertext &ciph_sup_mask,
                     Ciphertext &ciph_diag_mask,
                     Ciphertext &ciph_sub_mask)
{
    Ciphertext ciph_tmp;
    Ciphertext ciph_sup;
    Ciphertext ciph_sub;
    Ciphertext ciph_diag = ciph;

    Ciphertext ciph_sup_index;
    Ciphertext ciph_sub_index;
    Ciphertext ciph_diag_index = ciph_index;

    evaluator->drop_modulus(ciph_index, ciph_index, ciph.parms_id());
    ciph_tmp = copy_ciph(ciph, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    ciph_index = copy_ciph(ciph_index, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);

    int shift = std::pow(2, s - p);
    evaluator->rotate(ciph_tmp, ciph_sup, slot_size - shift, rot_keys);
    evaluator->rotate(ciph_tmp, ciph_sub, shift, rot_keys);

    evaluator->rotate(ciph_index, ciph_sup_index, slot_size - shift, rot_keys);
    evaluator->rotate(ciph_index, ciph_sub_index, shift, rot_keys);

    match_param_id(ciph_sup, ciph_sup_mask, evaluator);
    match_param_id(ciph_sup_index, ciph_sup_mask, evaluator);

    evaluator->multiply_relin(ciph_sup, ciph_sup_mask, ciph_sup, relin_keys);
    evaluator->rescale_dynamic(ciph_sup, ciph_sup, scale);

    evaluator->multiply_relin(ciph_sup_index, ciph_sup_mask, ciph_sup_index, relin_keys);
    evaluator->rescale_dynamic(ciph_sup_index, ciph_sup_index, scale);

    match_param_id(ciph_diag, ciph_diag_mask, evaluator);
    match_param_id(ciph_diag_index, ciph_diag_mask, evaluator);

    evaluator->multiply_relin(ciph_diag, ciph_diag_mask, ciph_diag, relin_keys);
    evaluator->rescale_dynamic(ciph_diag, ciph_diag, scale);

    evaluator->multiply_relin(ciph_diag_index, ciph_diag_mask, ciph_diag_index, relin_keys);
    evaluator->rescale_dynamic(ciph_diag_index, ciph_diag_index, scale);

    match_param_id(ciph_sub, ciph_sub_mask, evaluator);
    match_param_id(ciph_sub_index, ciph_sub_mask, evaluator);

    evaluator->multiply_relin(ciph_sub, ciph_sub_mask, ciph_sub, relin_keys);
    evaluator->rescale_dynamic(ciph_sub, ciph_sub, scale);

    evaluator->multiply_relin(ciph_sub_index, ciph_sub_mask, ciph_sub_index, relin_keys);
    evaluator->rescale_dynamic(ciph_sub_index, ciph_sub_index, scale);

    match_param_id(ciph_sup, ciph_diag, evaluator);
    match_scale(ciph_sup, ciph_diag, slot_size, encoder, evaluator, scale);
    evaluator->add(ciph_sup, ciph_diag, ciph_tmp);

    match_param_id(ciph_sub, ciph_tmp, evaluator);
    match_scale(ciph_sub, ciph_tmp, slot_size, encoder, evaluator, scale);
    evaluator->add(ciph_tmp, ciph_sub, ciph_tmp);

    match_param_id(ciph_sup_index, ciph_diag_index, evaluator);
    match_scale(ciph_sup_index, ciph_diag_index, slot_size, encoder, evaluator, scale);
    evaluator->add(ciph_sup_index, ciph_diag_index, ciph_index);
    match_param_id(ciph_sub_index, ciph_index, evaluator);
    match_scale(ciph_sub_index, ciph_index, slot_size, encoder, evaluator, scale);
    evaluator->add(ciph_sub_index, ciph_index, ciph_index);

    return ciph_tmp;
}

// 同态排序
Ciphertext HomSort(const Ciphertext &ciph,
                   Ciphertext &ciph_index,
                   const int slot_count,
                   const int slot_size,
                   const CKKSEncoder &encoder,
                   std::shared_ptr<EvaluatorCkksBase> evaluator,
                   const RelinKeys &relin_keys,
                   const GaloisKeys rot_keys,
                   double scale,
                   Ciphertext &ciph_sup_mask,
                   Ciphertext &ciph_diag_mask,
                   Ciphertext &ciph_sub_mask,
                   EvalModPoly &eval_mod_poly,
                   Encryptor &enc,
                   Decryptor &dec)
{
    auto ciph_result = copy_ciph(ciph, slot_count, slot_size, encoder, evaluator, relin_keys, rot_keys, scale);
    int log2_slot_count = static_cast<int>(round(log2(slot_count)));

    for (int s = 0; s < log2_slot_count; ++s)
    {
        for (int p = 0; p <= s; ++p)
        {
            auto ciph_cmp = HomOrdGen(ciph_result, slot_count, slot_size, s, p, encoder, evaluator, relin_keys, rot_keys, scale, enc, dec);

            MEncode(ciph_cmp, slot_count, slot_size, s, p, encoder, evaluator, relin_keys, rot_keys, scale, ciph_sup_mask, ciph_diag_mask, ciph_sub_mask);

            ciph_result = HomOrdApp(ciph_result, ciph_index, slot_count, slot_size, s, p, encoder, evaluator, relin_keys, rot_keys, scale, ciph_sup_mask, ciph_diag_mask, ciph_sub_mask);

            util::Timestacs timer_boot1;
            timer_boot1.start();
            evaluator->bootstrap(ciph_result, ciph_result, relin_keys, rot_keys, encoder, eval_mod_poly);
            timer_boot1.end();

            util::Timestacs timer_boot2;
            timer_boot2.start();
            evaluator->bootstrap(ciph_index, ciph_index, relin_keys, rot_keys, encoder, eval_mod_poly);
            timer_boot2.end();
        }
    }

    return ciph_result;
}

int main()
{

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 15;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(44, 32);
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

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_evaluator =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    int slot_count = 8;

    // 排序密文
    std::vector<std::complex<double>> message(slot_count, {0.0, 0.0});
    message = {{0.3, 0.0}, {0.2, 0.0}, {0.5, 0.0}, {0.4, 0.0}, {0.8, 0.0}, {0.9, 0.0}, {0.7, 0.0}, {0.6, 0.0}};
    Ciphertext ciph = encode_and_encrypt(ckks_encoder, enc, message, scale);

    // 索引密文
    std::vector<std::complex<double>> index(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < slot_count; i++)
    {
        index[i] = i;
    }
    Ciphertext ciph_index = encode_and_encrypt(ckks_encoder, enc, index, scale);

    Ciphertext ciph_sub_mask;
    Ciphertext ciph_diag_mask;
    Ciphertext ciph_sup_mask;

    EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 40, 1, 9, 3, 16, 0, 30);

    Ciphertext ciph_result;
    ciph_result = HomSort(ciph, ciph_index, slot_count, slot_size, ckks_encoder, ckks_evaluator, relin_keys, rot_keys, scale,
                          ciph_sup_mask, ciph_diag_mask, ciph_sub_mask, eval_mod_poly, enc, dec);

    return 0;
}

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