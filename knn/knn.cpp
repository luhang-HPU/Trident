
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
#include "poseidon/util/json.h"

#include <algorithm>
#include <chrono>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace std;

using namespace poseidon;
using namespace poseidon::util;

namespace
{
constexpr int kDataNums = 100;
constexpr int kDimension = 10;
constexpr int kScaleBits = 32;
constexpr int kNumThreads = 8;
constexpr int kPredictionCount = 10;
constexpr int kTopKThreshold = 100;
constexpr double kInputScaleDivisor = 40.0;
constexpr double kComparisonThreshold = 10.5;
constexpr double kFinalScaleFactor = 0.014;
constexpr double kMarginMaskMin = 0.95;
constexpr double kMarginMaskMax = 1.05;
const std::filesystem::path kCurrentPath(__FILE__);
const std::vector<int> kRotationSteps = {100, 200, 300, 600, 1200, 2500, 5000};

using Complex = std::complex<double>;
using ComplexVec = std::vector<Complex>;
using ComplexMatrix = std::vector<ComplexVec>;

struct RuntimeOptions
{
    uint32_t log_degree = 15;
    std::string dataset_file = (kCurrentPath.parent_path() / "dataset" / "train.jsonl").string();
    std::string predictions_file = (kCurrentPath.parent_path() / "predictions.jsonl").string();
};

RuntimeOptions parse_options(int argc, char *argv[])
{
    RuntimeOptions options;
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--log-degree" && i + 1 < argc)
        {
            options.log_degree = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--dataset" && i + 1 < argc)
        {
            options.dataset_file = argv[++i];
        }
        else if (arg == "--predictions" && i + 1 < argc)
        {
            options.predictions_file = argv[++i];
        }
        else
        {
            std::cerr << "Usage: " << argv[0]
                      << " [--log-degree 15|16] [--dataset path] [--predictions path]" << std::endl;
            throw std::invalid_argument("invalid command-line arguments");
        }
    }

    if (options.log_degree != 15 && options.log_degree != 16)
    {
        throw std::invalid_argument("Only --log-degree 15 (32768) and 16 (65536) are supported.");
    }

    return options;
}

PolynomialVector build_polynomial_vector(const ComplexVec &coeffs,
                                         std::vector<std::vector<int>> &slots_index,
                                         int degree)
{
    Polynomial poly(coeffs, 0, 0, degree, Monomial);
    poly.lead() = true;
    return PolynomialVector(std::vector<Polynomial>{poly}, slots_index);
}

Ciphertext sum_distance_columns(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
                                const std::vector<Ciphertext> &ciph_data,
                                size_t start_index)
{
    Ciphertext distance = ciph_data[start_index];
    for (size_t i = 1; i < kDimension; ++i)
    {
        ckks_eva->add(distance, ciph_data[start_index + i], distance);
    }
    return distance;
}

std::vector<int> decode_predictions(const ComplexVec &decoded)
{
    std::vector<int> result;
    result.reserve(kDataNums);
    for (int i = 0; i < kDataNums; ++i)
    {
        if (std::round(decoded[i].real()) == 1)
        {
            result.push_back(i + 1);
        }
    }
    return result;
}
} // namespace

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              const ComplexVec &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           const ComplexMatrix &message,
                                           double scale);
ComplexVec decrypt_and_decode(const CKKSEncoder &encoder, Decryptor &decryptor, const Ciphertext &ciph);

void read_jsonl_query(const std::string &file, ComplexMatrix &query, size_t slot_count)
{
    std::ifstream infile(file);
    if (!infile.is_open())
    {
        POSEIDON_THROW(config_error, "cannot open file ：" + file);
    }

    // 读取整个文件内容
    std::stringstream buffer;
    buffer << infile.rdbuf();
    json j_all = json::parse(buffer.str());
    infile.close();

    if (!j_all.contains("query") || !j_all["query"].is_array())
    {
        throw std::runtime_error("Invalid JSON: 'query' field missing or not an array");
    }

    const std::vector<double> real_vec = j_all["query"].get<std::vector<double>>();
    if (real_vec.size() != static_cast<size_t>(kDimension))
    {
        throw std::runtime_error("Invalid JSON: 'query' size does not match kDimension");
    }

    if (slot_count < static_cast<size_t>(kDataNums * kDataNums))
    {
        throw std::runtime_error("slot_count is smaller than the packed query size");
    }

    query.assign(kDimension, ComplexVec(slot_count, {0.0, 0.0}));
    for (int i = 0; i < kDimension; ++i)
    {
        const auto value = Complex(real_vec.at(i) / kInputScaleDivisor, 0.0);
        std::fill_n(query[i].begin(), kDataNums * kDataNums, value);
    }
}

void read_jsonl_data(const std::string &file, ComplexMatrix &matrix_data)
{
    std::ifstream infile(file);
    if (!infile.is_open())
    {
        throw std::runtime_error("cannot open file: " + file);
    }

    json j_all;
    infile >> j_all;

    // 读取二维数组
    if (!j_all.contains("data") || !j_all["data"].is_array())
    {
        throw std::runtime_error("Invalid JSON: 'data' field missing or not an array");
    }

    const auto &data_array = j_all["data"];
    const size_t num_rows = data_array.size();
    if (num_rows == 0)
    {
        return;
    }

    if (num_rows != static_cast<size_t>(kDataNums))
    {
        throw std::runtime_error("Invalid JSON: row count does not match kDataNums");
    }

    const size_t num_cols = data_array[0].size();
    if (num_cols != static_cast<size_t>(kDimension))
    {
        throw std::runtime_error("Invalid JSON: column count does not match kDimension");
    }

    if (matrix_data.size() < num_cols * 2)
    {
        throw std::runtime_error("matrix_data does not have enough columns for both layouts");
    }

    for (size_t row = 0; row < num_rows; ++row)
    {
        const auto &row_data = data_array[row];
        if (!row_data.is_array() || row_data.size() != num_cols)
        {
            throw std::runtime_error("Inconsistent row size in JSON data");
        }

        ComplexVec scaled_row(num_cols);
        for (size_t col = 0; col < num_cols; ++col)
        {
            scaled_row[col] = Complex(row_data[col].get<double>() / kInputScaleDivisor, 0.0);
        }

        for (int copy = 0; copy < kDataNums; ++copy)
        {
            const size_t interleaved_row = row + copy * kDataNums;
            const size_t blocked_row = row * kDataNums + copy;
            for (size_t col = 0; col < num_cols; ++col)
            {
                matrix_data[col][interleaved_row] = scaled_row[col];
                matrix_data[col + kDimension][blocked_row] = scaled_row[col];
            }
        }
    }
}

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              const ComplexVec &message, double scale)
{
    Plaintext plain;
    Ciphertext ciph;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
    return ciph;
}

std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           const ComplexMatrix &message,
                                           double scale)
{
    std::vector<Ciphertext> vec_ciph;
    vec_ciph.reserve(message.size());
    for (size_t i = 0; i < message.size(); ++i)
    {
        Plaintext plain;
        Ciphertext ciph;
        encoder.encode(message[i], scale, plain);
        encryptor.encrypt(plain, ciph);
        vec_ciph.push_back(ciph);
    }
    return vec_ciph;
}

ComplexVec decrypt_and_decode(const CKKSEncoder &encoder, Decryptor &decryptor, const Ciphertext &ciph)
{
    Plaintext plain;
    decryptor.decrypt(ciph, plain);
    ComplexVec message;
    encoder.decode(plain, message);
    return message;
}

void encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                        const ComplexVec &message, double scale, Ciphertext &ciph)
{
    Plaintext plain;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
}

std::vector<Ciphertext> encode_and_encrypt_mt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                              const ComplexMatrix &message,
                                              double scale)
{
    size_t num_messages = message.size();
    std::vector<Ciphertext> vec_ciph(num_messages);

    #pragma omp parallel for num_threads(kNumThreads)
    for (int i = 0; i < static_cast<int>(num_messages); ++i)
    {
        // 每个线程处理 message 的不同索引，不存在写冲突
        encode_and_encrypt(encoder, encryptor, message[i], scale, vec_ciph[i]);
    }

    return vec_ciph;
}


void sub_and_square(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
                    std::vector<Ciphertext> &ciph_data, const std::vector<Ciphertext> &ciph_query, const poseidon::RelinKeys &relin_keys, const double scale)
{
    const int query_size = static_cast<int>(ciph_query.size());
    #pragma omp parallel for num_threads(kNumThreads)
    for (int i = 0; i < query_size; ++i)
    {
        ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);
        ckks_eva->sub(ciph_data[i + kDimension], ciph_query[i], ciph_data[i + kDimension]);

        ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i], relin_keys);
        ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);

        ckks_eva->multiply_relin(ciph_data[i + kDimension], ciph_data[i + kDimension], ciph_data[i + kDimension], relin_keys);
        ckks_eva->rescale_dynamic(ciph_data[i + kDimension], ciph_data[i + kDimension], scale);
    }
}

void match_param_id(Ciphertext &ciph1, Ciphertext &ciph2,
                    std::shared_ptr<EvaluatorCkksBase> eva)
{
    if (ciph1.level() > ciph2.level())
    {
        eva->drop_modulus(ciph1, ciph1, ciph2.parms_id());
    }
    else if (ciph1.level() < ciph2.level())
    {
        eva->drop_modulus(ciph2, ciph2, ciph1.parms_id());
    }
}

void match_scale(Ciphertext &ciph1, Ciphertext &ciph2,
                 const CKKSEncoder &encoder,
                 std::shared_ptr<EvaluatorCkksBase> eva,
                 double scale)
{
    if (!util::are_approximate(ciph1.scale(), ciph2.scale()))
    {
        ciph1.scale() = ciph2.scale();
        ComplexVec vec_tmp(1, {1.0, 0.0});
        Plaintext plt_tmp;

        // for ciph_1
        {
            encoder.encode(vec_tmp, ciph2.parms_id(), scale * scale / ciph2.scale(), plt_tmp);
            eva->multiply_plain(ciph2, plt_tmp, ciph2);
            eva->rescale(ciph2, ciph2);
        }

        // for ciph_2
        {
            encoder.encode(vec_tmp, ciph1.parms_id(), scale * scale / ciph1.scale(), plt_tmp);
            eva->multiply_plain(ciph1, plt_tmp, ciph1);
            eva->rescale(ciph1, ciph1);
        }
    }
}

// sign_1 第一次sign 近似拟合
Ciphertext sign_1(const Ciphertext &ciph,
                  const PolynomialVector &polys_1,
                  const PolynomialVector &polys_2,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys, encoder);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys, encoder);
    eva->add_const(ciph_result, 0.5, ciph_result, encoder);
    return ciph_result;
}

// sign_2 第二次拟合
Ciphertext sign_2(const Ciphertext &ciph,
                  const PolynomialVector &polys,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys, ciph_result.scale(), relin_keys, encoder);
    return ciph_result;
}

void writePredictions(const std::vector<int> &data, std::string predictions_file)
{
    try
    {
        const auto parent = std::filesystem::path(predictions_file).parent_path();
        if (!parent.empty())
        {
            std::filesystem::create_directories(parent);
        }
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        std::cerr << "创建目录失败: " << e.what() << std::endl;
        return;
    }

    // 追加写入，便于保留不同参数下的结果做对比
    std::ofstream out_file(predictions_file, std::ios::app);
    if (!out_file.is_open())
    {
        std::cerr << "无法打开文件: " << predictions_file << std::endl;
        return;
    }

    // 写入JSON格式内容
    out_file << "{ \"answer\": [ ";
    for (size_t i = 0; i < kPredictionCount; ++i)
    {
        if (i < data.size())
        {
            out_file << data[i];
        }
        else
        {
            out_file << 100;
        }

        if (i + 1 != kPredictionCount)
        {
            out_file << ", ";
        }
    }
    out_file << " ] }" << std::endl;

    // 关闭文件
    out_file.close();
}

Ciphertext accumulate_top_n_block(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                                  const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                                  const GaloisKeys &rot_keys)
{
    if (n <= 0)
    {
        POSEIDON_THROW(invalid_argument_error, "n cannot be negative");
    }

    Ciphertext ciph_rotate_sum = ciph;

    ComplexVec zero = {{0.0, 0.0}};
    Plaintext plain_zero;
    Ciphertext ciph_sum;
    encoder.encode(zero, ciph.parms_id(), ciph.scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_sum);

    while (n > 1)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
            ckks_eva->rotate(ciph_rotate_sum, ciph_rotate_sum, kDataNums, rot_keys);
            n--;
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, n * kDataNums, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

std::vector<double> generateMarginMask(int n)
{
    std::vector<double> result;
    if (n <= 0)
    {
        return result;
    }

    result.reserve(n);
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::mt19937 generator(seed);

    // Keep the mask positive and close to 1.0 so the sign is harder to infer
    // from the raw margin while remaining much less likely to flip final labels.
    std::uniform_real_distribution<double> distribution(kMarginMaskMin, kMarginMaskMax);

    for (int i = 0; i < n; ++i)
    {
        result.push_back(distribution(generator));
    }

    return result;
}

int main(int argc, char *argv[])
{
    util::Timestacs timer;
    util::Timestacs timer_init;
    util::Timestacs timer_calculate;
    timer.start();
    timer_init.start();

    RuntimeOptions options;
    try
    {
        options = parse_options(argc, argv);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    // 参数设置
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = kScaleBits;

    ParametersLiteral ckks_param_literal{CKKS, options.log_degree, options.log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(18, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    double scale = std::pow(2.0, q_def);

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // init keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(kRotationSteps, rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    // 多项式构建
    const size_t slot_count = context.parameters_literal()->degree() >> 1;
    vector<vector<int>> slots_index(1, vector<int>(slot_count, 0));
    vector<int> idxF(slot_count);
    for (size_t i = 0; i < slot_count; ++i)
    {
        idxF[i] = static_cast<int>(i);
    }
    slots_index[0] = idxF;

    const PolynomialVector polys = build_polynomial_vector(
        {0, 3.816912, 0, -9.226954, 0, 11.954844, 0, -5.516258}, slots_index, 7);
    const PolynomialVector polys_1 = build_polynomial_vector(
        {0, 2.5390678487943066, 0, -15.36649590685934, 0, 72.05487340640471, 0, -229.83084441307128, 0, 510.7603223522984,
         0, -810.2812835443851, 0, 932.3382320828513, 0, -783.7465043857175, 0, 480.4851545467111, 0, -212.16308093582333,
         0, 65.63925462800184, 0, -13.490628831305791, 0, 1.6532569365778251, 0, -0.091371472313767},
        slots_index, 27);
    const PolynomialVector polys_2 = build_polynomial_vector({0.5, 0.197, 0, -0.004}, slots_index, 3);

    ComplexMatrix query(kDimension, ComplexVec(slot_count, {0.0, 0.0}));
    ComplexMatrix data(kDimension * 2, ComplexVec(slot_count, {0.0, 0.0}));

    read_jsonl_query(options.dataset_file, query, slot_count);
    read_jsonl_data(options.dataset_file, data);

    std::cout << "log_degree: " << options.log_degree << ", slot_count: " << slot_count << std::endl;

    timer_init.end();
    timer_calculate.start();

    vector<Ciphertext> ciph_query = encode_and_encrypt_mt(ckks_encoder, enc, query, scale);
    vector<Ciphertext> ciph_data = encode_and_encrypt_mt(ckks_encoder, enc, data, scale);

    // 比较数组
    ComplexVec cmp_top_k(slot_count, {0.0, 0.0});
    for (int i = 0; i < kDataNums; ++i)
    {
        cmp_top_k[i].real(kComparisonThreshold);
    }
    Ciphertext ciph_top_k = encode_and_encrypt(ckks_encoder, enc, cmp_top_k, scale);

    sub_and_square(ckks_eva, ciph_data, ciph_query, relin_keys, scale);
    Ciphertext ciph_distance_1 = sum_distance_columns(ckks_eva, ciph_data, 0);
    Ciphertext ciph_distance_2 = sum_distance_columns(ckks_eva, ciph_data, kDimension);

    Ciphertext ciph_result;
    ckks_eva->sub_dynamic(ciph_distance_1, ciph_distance_2, ciph_result, ckks_encoder);

    Ciphertext ciph_tmp = sign_1(ciph_result, polys, polys_1, ckks_encoder, ckks_eva, relin_keys);
    ciph_result = accumulate_top_n_block(ciph_tmp, kTopKThreshold, ckks_encoder, enc, ckks_eva, rot_keys);

    match_param_id(ciph_result, ciph_top_k, ckks_eva);
    match_scale(ciph_result, ciph_top_k, ckks_encoder, ckks_eva, scale);

    ckks_eva->sub_dynamic(ciph_top_k, ciph_result, ciph_result, ckks_encoder);

    ckks_eva->multiply_const(ciph_result, kFinalScaleFactor, scale, ciph_result, ckks_encoder);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);

    Plaintext pl_margin_mask;
    std::vector<double> margin_mask = generateMarginMask(kDataNums);
    ComplexVec vec_margin_mask(slot_count, {1.0, 0.0});
    for (int i = 0; i < kDataNums; ++i)
    {
        vec_margin_mask[i] = margin_mask[i];
    }
    ckks_encoder.encode(vec_margin_mask, ciph_result.parms_id(), scale, pl_margin_mask);
    ckks_eva->multiply_plain(ciph_result, pl_margin_mask, ciph_result);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);

    ciph_result = sign_2(ciph_result, polys_2, ckks_encoder, ckks_eva, relin_keys);

    std::cout << "ciph_result.coeff_modulus_size() - 1: " << ciph_result.coeff_modulus_size() - 1 << std::endl;

    // 查询方
    const auto result_index = decrypt_and_decode(ckks_encoder, dec, ciph_result);
    writePredictions(decode_predictions(result_index), options.predictions_file);

    timer_calculate.end();
    timer.end();
    timer_init.print_time_ms("Init time: ");
    timer_calculate.print_time_ms("Calculate time: ");
    timer.print_time_ms("All time: ");
    return 0;
}
