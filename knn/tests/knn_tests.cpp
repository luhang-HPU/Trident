#include <gtest/gtest.h>

#include "../knn_utils.h"

using namespace KNN;


namespace CKKS_LRTRAIN_TEST
{

int knn_test(uint32_t log_degree = 15)
{
    cout << BANNER << std::endl;
    cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "Trident Application: KNN start" << std::endl;
    cout << "" << std::endl;

    util::Timestacs timer;
    util::Timestacs timer_init;
    util::Timestacs timer_calculate;
    timer.start();
    timer_init.start();
    // 参数设置
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(21, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
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
    vector<int> step = {100, 200, 300, 600, 1200, 2500, 5000};
    kgen.create_galois_keys(step, rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // 多项式构建
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;
    }
    slots_index[0] = idxF;

    vector<complex<double>> buffer = {0, 3.816912, 0, -9.226954, 0, 11.954844, 0, -5.516258};
    Polynomial approxF(buffer, 0, 0, 7, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    PolynomialVector polys(poly_v, slots_index);

    buffer = {0, 2.5390678487943066,  0, -15.36649590685934, 0, 72.05487340640471,
              0, -229.83084441307128, 0, 510.7603223522984,  0, -810.2812835443851,
              0, 932.3382320828513,   0, -783.7465043857175, 0, 480.4851545467111,
              0, -212.16308093582333, 0, 65.63925462800184,  0, -13.490628831305791,
              0, 1.6532569365778251,  0, -0.091371472313767};
    Polynomial approxF_1(buffer, 0, 0, 27, Monomial);
    approxF_1.lead() = true;
    vector<Polynomial> poly_v_1{approxF_1};
    PolynomialVector polys_1(poly_v_1, slots_index);

    buffer = {0.5, 0.197, 0, -0.004};
    Polynomial approxF_2(buffer, 0, 0, 3, Monomial);
    approxF_2.lead() = true;
    vector<Polynomial> poly_v_2{approxF_2};
    PolynomialVector polys_2(poly_v_2, slots_index);

    vector<vector<complex<double>>> query(10, vector<complex<double>>(1 << (log_degree-1), {0.0, 0.0}));
    vector<vector<complex<double>>> data(20, vector<complex<double>>(1 << (log_degree-1), {0.0, 0.0}));

    std::string predictions_file = "./predictions.jsonl";
    std::string current_path = get_current_path();
    std::cout << "read query start" << std::endl;
    read_jsonl_query(current_path + "dataset/train.jsonl", query);
    std::cout << "read query end" << std::endl;
    std::cout << "read data start" << std::endl;
    read_jsonl_data(current_path + "dataset/train.jsonl", data);
    std::cout << "read data end" << std::endl;

    timer_init.end();
    timer_calculate.start();

    std::cout << "encode and encrypt start" << std::endl;
    vector<Ciphertext> ciph_query = encode_and_encrypt_mt(ckks_encoder, enc, query, scale);
    vector<Ciphertext> ciph_data = encode_and_encrypt_mt(ckks_encoder, enc, data, scale);
    std::cout << "encode and encrypt end" << std::endl;

    // 比较数组
    std::cout << "compare start" << std::endl;
    std::vector<std::complex<double>> cmp_top_k(1 << (log_degree-1), {0.0, 0.0});
    for (size_t i = 0; i < data_nums; i++)
    {
        cmp_top_k[i].real(11.5);
    }
    Ciphertext ciph_top_k = encode_and_encrypt(ckks_encoder, enc, cmp_top_k, scale);

    sub_and_square(ckks_eva, ciph_data, ciph_query, relin_keys, scale);
    Ciphertext ciph_distance_1 = ciph_data[0];
    Ciphertext ciph_distance_2 = ciph_data[dimension];
    for (size_t i = 1; i < dimension; i++)
    {
        ckks_eva->add(ciph_distance_1, ciph_data[i], ciph_distance_1);
        ckks_eva->add(ciph_distance_2, ciph_data[i + dimension], ciph_distance_2);
    }

    Ciphertext ciph_result;
    ckks_eva->sub_dynamic(ciph_distance_1, ciph_distance_2, ciph_result, ckks_encoder);

    Ciphertext ciph_tmp = sign_1(ciph_result, polys, polys_1, ckks_encoder, ckks_eva, relin_keys);
    ciph_result = accumulate_top_n_block(ciph_tmp, 100, ckks_encoder, enc, ckks_eva, rot_keys);

    match_param_id(ciph_result, ciph_top_k, ckks_eva);
    match_scale(ciph_result, ciph_top_k, ckks_encoder, ckks_eva, scale);

    ckks_eva->sub_dynamic(ciph_top_k, ciph_result, ciph_result, ckks_encoder);

    ckks_eva->multiply_const(ciph_result, 0.014, scale, ciph_result, ckks_encoder);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);

    ciph_result = sign_2(ciph_result, polys_2, ckks_encoder, ckks_eva, relin_keys);
    std::cout << "compare end" << std::endl;

    // 查询方
    auto result_index = decrypt_and_decode(ckks_encoder, dec, ciph_result);
    std::vector<int> result;
    for (size_t i = 0; i < 100; ++i)
    {
        if (std::round(result_index[i].real()) == 1)
        {
            result.push_back(i + 1);
        }
    }

    writePredictions(result, predictions_file);

    std::cout << std::endl;
    std::cout << "Trident Application: KNN end" << std::endl;
    std::cout << std::endl;

    timer_calculate.end();
    timer.end();
    timer_init.print_time_ms("Init time: ");
    timer_calculate.print_time_ms("Calculate time: ");
    timer.print_time_ms("All time: ");
    return 0;
}

    TEST(KNNTest, Degree8192)
    {
        knn_test(13);
    }

    TEST(KNNTest, Degree16384)
    {
        knn_test(14);
    }

    TEST(KNNTest, Degree32768)
    {
        knn_test(15);
    }


}