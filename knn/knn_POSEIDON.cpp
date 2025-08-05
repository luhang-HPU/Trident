#include "src/ckks_encoder.h"
#include "src/decryptor.h"
#include "src/encryptor.h"
#include "src/evaluator/evaluator_ckks_base.h"
#include "src/factory/poseidon_factory.h"
#include "src/keygenerator.h"
#include "src/plaintext.h"
#include "src/poseidon_context.h"
#include "src/util/debug.h"
#include "src/util/precision.h"
#include "src/util/random_sample.h"

#include <filesystem>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "../libs/nlohmann_json/json.hpp"

using json = nlohmann::json;
using namespace std;

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

#define DEBUG_LRTRAIN

std::filesystem::path current_path(__FILE__);
int data_nums = 100;
int dimension = 10;
int N = 16384;
int NUM = 128;

Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);
std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);

class Logger
{
private:
    std::ofstream logFile;
    std::string getCurrentTime()
    {
        time_t now = time(0);
        char *dt = ctime(&now);
        // 移除换行符
        std::string timeStr(dt);
        if (!timeStr.empty() && timeStr[timeStr.length() - 1] == '\n')
        {
            timeStr.erase(timeStr.length() - 1);
        }
        return timeStr;
    }

    // 内部使用的无时间戳输出函数
    template <typename T>
    Logger &rawOutput(const T &message)
    {
        std::cout << message;
        if (logFile.is_open())
        {
            logFile << message;
        }
        return *this;
    }

public:
    void info(const std::string &message)
    {
        std::cout << "[INFO] " << message << std::endl;
        logFile << "[INFO] " << " " << message;
    }

    class Timer
    {
    public:
        Timer(const std::string &label, Logger *logger = nullptr)
            : label_(label), logger_(logger), start_time_(std::chrono::high_resolution_clock::now())
        {
            if (logger_)
                logger_->info("开始计时: " + label_);
        }

        ~Timer()
        {
            auto end_time = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(end_time - start_time_).count();
            if (logger_)
            {
                logger_->info("结束计时: " + label_ + "，耗时: " + std::to_string(elapsed) + " 秒");
            }
            else
            {
                std::cout << "[Timer] " << label_ << " 耗时: " << elapsed << " 秒" << std::endl;
            }
        }

    private:
        std::string label_;
        Logger *logger_;
        std::chrono::high_resolution_clock::time_point start_time_;
    };

    // 提供创建 Timer 的方法
    Timer start_timer(const std::string &label)
    {
        return Timer(label, this);
    }
    Logger(const std::string &filename)
    {
        logFile.open(filename, std::ios::app);
        if (!logFile.is_open())
        {
            std::cerr << "Failed to open log file: " << filename << std::endl;
        }
    }

    ~Logger()
    {
        if (logFile.is_open())
        {
            logFile.close();
        }
    }

    // 主输出操作符，只在开始时添加时间戳
    template <typename T>
    Logger &operator<<(const T &message)
    {
        std::string timeStr = getCurrentTime();
        std::cout << timeStr << " " << message;
        if (logFile.is_open())
        {
            logFile << timeStr << " " << message;
        }
        return *this;
    }

    // 处理endl等操纵符
    Logger &operator<<(std::ostream &(*manipulator)(std::ostream &))
    {
        std::cout << manipulator;
        if (logFile.is_open())
        {
            logFile << manipulator;
        }
        return *this;
    }

    // 支持vector
    template <typename T>
    Logger &operator<<(const std::vector<T> &vec)
    {
        rawOutput("[");
        for (size_t i = 0; i < 300; ++i)
        {
            rawOutput(vec[i].real());
            if (i != NUM - 1)
            {
                rawOutput(", ");
            }
        }
        rawOutput("]");
        return *this;
    }

    // 新增：输出Ciphertext缩放信息
    Logger &print_scale(const std::string &content, const Ciphertext &ciph)
    {
        std::string timeStr = getCurrentTime();
        std::cout << timeStr << " " << content << std::endl;
        std::cout << timeStr << " " << "current scale: " << ciph.scale() << std::endl;
        std::cout << timeStr << " " << "current level: " << ciph.coeff_modulus_size() << std::endl;

        if (logFile.is_open())
        {
            logFile << timeStr << " " << content << "  ";
            logFile << "current scale: " << ciph.scale() << "  ";
            logFile << "current level: " << ciph.coeff_modulus_size() << std::endl;
        }

        return *this;
    }

    // 新增：输出Ciphertext缩放信息
    Logger &print_vector(const std::string &content, const Ciphertext &ciph, const CKKSEncoder &encoder, Decryptor &decryptor)
    {
        auto vec = decrypt_and_decode(encoder, decryptor, ciph);
        std::string timeStr = getCurrentTime();
        std::cout << timeStr << " " << content << std::endl;

        if (logFile.is_open())
        {
            logFile << timeStr << " " << content;
            rawOutput("[");
            for (size_t i = 0; i < 100; ++i)
            {
                // rawOutput(std::round(vec[i].real()));
                rawOutput(vec[i]);
                if (i != NUM - 1)
                {
                    rawOutput(", ");
                }
            }
            rawOutput("]");
            logFile << std::endl;
        }

        return *this;
    }

    // 新增：输出Ciphertext缩放信息
    Logger &print_vector_real(const std::string &content, const Ciphertext &ciph, const CKKSEncoder &encoder, Decryptor &decryptor)
    {
        auto vec = decrypt_and_decode(encoder, decryptor, ciph);
        std::string timeStr = getCurrentTime();
        std::cout << timeStr << " " << content << std::endl;

        if (logFile.is_open())
        {
            logFile << timeStr << " " << content;
            rawOutput("[");
            for (size_t i = 0; i < data_nums; ++i)
            {
                rawOutput(std::round(vec[i].real()));
                if (i != NUM - 1)
                {
                    rawOutput(", ");
                }
            }
            rawOutput("]");
            logFile << std::endl;
        }

        return *this;
    }

    // 新增：输出Ciphertext缩放信息
    Logger &print_time(Timestacs timer)
    {
        timer.print_time("bootstrap ciph_result time: ");
        std::string timeStr = getCurrentTime();
        if (logFile.is_open())
        {
            logFile << timeStr << " ";
            timer.print_time("bootstrap ciph_result time: ");
            logFile << std::endl;
        }

        return *this;
    }
};

Logger logger("knn.log");

void read_jsonl_query(const std::string &file, std::vector<std::vector<std::complex<double>>> &query)
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
    std::cout << "query size: " << j_all["query"].size() << std::endl;
    for (auto val : j_all["query"])
        std::cout << val << " ";
    std::cout << std::endl;
    infile.close();

    query.clear();
    // 获取 query 数组
    std::vector<double> real_vec = j_all["query"].get<std::vector<double>>();

    // 生成 10 行，每行复制对应实数 100 次，转为复数
    for (int i = 0; i < 10; ++i)
    {
        std::vector<std::complex<double>> row(10000, std::complex<double>(real_vec[i] / 40, 0.0));
        query.push_back(row);
    }
}

void read_jsonl_data(const std::string &file, std::vector<std::vector<std::complex<double>>> &matrix_data)
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
    size_t num_rows = data_array.size();
    if (num_rows == 0)
        return;

    std::cout << "data size: " << j_all["data"].size() << std::endl;
    for (auto val : j_all["data"])
        std::cout << val << " ";
    std::cout << std::endl;

    size_t num_cols = data_array[0].size();

    for (size_t row = 0; row < num_rows; ++row)
    {
        const auto &row_data = data_array[row];
        if (!row_data.is_array() || row_data.size() != num_cols)
        {
            throw std::runtime_error("Inconsistent row size in JSON data");
        }

        // 每行复制100次
        for (int copy = 0; copy < 100; ++copy)
        {
            // 计算复制后的目标行索引 = 原始行索引 * 100 + 复制次数
            size_t target_row = row + copy * 100;

            for (size_t col = 0; col < num_cols; ++col)
            {
                matrix_data[col][target_row] = std::complex<double>(row_data[col].get<double>() / 40, 0.0);
            }
        }
    }

    for (size_t row = 0; row < num_rows; ++row)
    {
        const auto &row_data = data_array[row];
        if (!row_data.is_array() || row_data.size() != num_cols)
        {
            throw std::runtime_error("Inconsistent row size in JSON data");
        }

        // 每行复制100次
        for (int copy = 0; copy < 100; ++copy)
        {
            // 计算复制后的目标行索引 = 原始行索引 * 100 + 复制次数
            size_t target_row = row * 100 + copy;

            for (size_t col = 0; col < num_cols; ++col)
            {
                matrix_data[col + 10][target_row] = std::complex<double>(row_data[col].get<double>() / 40, 0.0);
            }
        }
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
        std::vector<std::complex<double>> vec_tmp(NUM, {1.0, 0.0});
        Plaintext plt_tmp;

        // for ciph_gradient
        {
            encoder.encode(vec_tmp, ciph2.parms_id(), scale * scale / ciph2.scale(), plt_tmp);
            eva->multiply_plain(ciph2, plt_tmp, ciph2);
            eva->rescale(ciph2, ciph2);
        }

        // for ciph_weight
        {
            encoder.encode(vec_tmp, ciph1.parms_id(), scale * scale / ciph1.scale(), plt_tmp);
            eva->multiply_plain(ciph1, plt_tmp, ciph1);
            eva->rescale(ciph1, ciph1);
        }
    }
}

// sign_1 两次拟合
Ciphertext sign_1(const Ciphertext &ciph,
                  const PolynomialVector &polys,
                  const PolynomialVector &polys_1,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys,
                  Decryptor &dec,
                  const Encryptor &encryptor,
                  double scale,
                  const GaloisKeys rot_keys)
{
    logger << "sign start" << std::endl;
    auto ciph_result = ciph;

    util::Timestacs timer_1;
    timer_1.start();
    logger.print_scale("start sgn1 时 ciph_result 的level", ciph_result);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys, ciph_result.scale(), relin_keys, encoder);
    logger.print_scale("finish sgn1 时 ciph_result 的level", ciph_result);
    logger.print_vector("sgn1 解密结果: ", ciph_result, encoder, dec);

    eva->multiply_const(ciph_result, 2.2, scale, ciph_result, encoder);
    eva->rescale_dynamic(ciph_result, ciph_result, scale);
    logger.print_vector("sgn1 解密结果 * 2.2: ", ciph_result, encoder, dec);

    logger.print_scale("start sgn2 时 ciph_result 的level", ciph_result);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys, encoder);
    logger.print_scale("finish sgn2 时 ciph_result 的level", ciph_result);
    logger.print_vector("sgn2 解密结果: ", ciph_result, encoder, dec);

    // 加 0.5
    eva->add_const(ciph_result, 0.5, ciph_result, encoder);
    logger.print_vector("拟合后 + 0.5: ", ciph_result, encoder, dec);

    timer_1.end();
    logger << timer_1.get_time_s("sgn_1 time: ") << std::endl;
    return ciph_result;
}

// sign_2 一次拟合
Ciphertext sign_2(const Ciphertext &ciph,
                  const PolynomialVector &polys,
                  const PolynomialVector &polys_1,
                  const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva,
                  const RelinKeys &relin_keys,
                  Decryptor &dec,
                  const Encryptor &encryptor,
                  double scale,
                  const GaloisKeys rot_keys)
{
    logger << "sign start" << std::endl;
    auto ciph_result = ciph;

    util::Timestacs timer_2;
    timer_2.start();
    logger.print_scale("start sgn2 时 ciph_result 的level", ciph_result);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys, encoder);
    logger.print_scale("finish sgn2 时 ciph_result 的level", ciph_result);
    logger.print_vector("sgn2 解密结果: ", ciph_result, encoder, dec);

    // 加 0.5
    eva->add_const(ciph_result, 0.5, ciph_result, encoder);
    logger.print_vector("拟合后 + 0.5: ", ciph_result, encoder, dec);

    timer_2.end();
    logger << timer_2.get_time_s("sgn2 time: ") << std::endl;
    return ciph_result;
}

void writePredictions(const std::vector<int> &data, std::string predictions_file)
{
    try
    {
        std::filesystem::create_directories(std::filesystem::path(predictions_file).parent_path());
    }
    catch (const std::filesystem::filesystem_error &e)
    {
        std::cerr << "创建目录失败: " << e.what() << std::endl;
        return;
    }

    // 打开文件（使用trunc模式确保覆盖原有内容）
    std::ofstream out_file(predictions_file, std::ios::trunc);
    if (!out_file.is_open())
    {
        std::cerr << "无法打开文件: " << predictions_file << std::endl;
        return;
    }

    // 写入JSON格式内容
    out_file << "{ \"answer\": [ ";
    for (size_t i = 0; i < 10; ++i)
    {
        if (i < data.size())
        {
            out_file << data[i];
        }
        else
        {
            out_file << 100;
        }

        if (i != 9)
        {
            out_file << ", ";
        }
    }
    out_file << " ] }";

    // 关闭文件
    out_file.close();

    std::cout << "成功写入文件: " << predictions_file << std::endl;
}
Ciphertext accumulate_top_n_block(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                                  const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                                  const GaloisKeys rot_keys)
{
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
            ckks_eva->rotate(ciph_rotate_sum, ciph_rotate_sum, 100, rot_keys);
            n--;
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, n * 100, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

int main(int argc, char *argv[])
{
    util::Timestacs timer;
    timer.start();
    util::Timestacs timer_init;
    timer_init.start();

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 15;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(25, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    auto slot_size = 1 << ckks_param_literal.log_slots();
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
    logger << "create_galois_keys" << std::endl;
    vector<int> step = {100, 200, 300, 600, 1200, 2500, 5000};
    kgen.create_galois_keys(step, rot_keys);
    // kgen.create_galois_keys(rot_keys);
    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;
    }
    slots_index[0] = idxF;

    vector<complex<double>> buffer = {0, 1.73496, 0, -4.19407, 0, 5.43402, 0, -2.50739};

    Polynomial approxF(buffer, 0, 0, 7, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    PolynomialVector polys(poly_v, slots_index);

    buffer = {
        0, 2.5390678487943066, 0, -15.36649590685934,
        0, 72.05487340640471, 0, -229.83084441307128,
        0, 510.7603223522984, 0, -810.2812835443851,
        0, 932.3382320828513, 0, -783.7465043857175,
        0, 480.4851545467111, 0, -212.16308093582333,
        0, 65.63925462800184, 0, -13.490628831305791,
        0, 1.6532569365778251, 0, -0.091371472313767};

    Polynomial approxF_1(buffer, 0, 0, 15, Monomial);
    approxF_1.lead() = true;
    vector<Polynomial> poly_v_1{approxF_1};
    PolynomialVector polys_1(poly_v_1, slots_index);

    timer_init.end();
    logger << "read train.jsonl" << std::endl;
    vector<vector<complex<double>>> query(10, vector<complex<double>>(N, {0.0, 0.0}));
    vector<vector<complex<double>>> data(20, vector<complex<double>>(N, {0.0, 0.0}));

    util::Timestacs timer_real;
    timer_real.start();

    // 提交使用 参数解析,读入文件路径
    std::string dataset_file;
    std::string predictions_file;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--dataset") {
            dataset_file = argv[++i];
        } else if (std::string(argv[i]) == "--predictions") {
            predictions_file = argv[++i];
        }
    }
    read_jsonl_query(dataset_file, query);
    read_jsonl_data(dataset_file, data);

    // 本地测试用
    // std::string predictions_file = "/home/guoshuai/aproject/predictions.jsonl";
    // read_jsonl_query("/home/guoshuai/aproject/train.jsonl", query);
    // read_jsonl_data("/home/guoshuai/aproject/train.jsonl", data);

    // read_jsonl_query(current_path.parent_path().string() + "/" + "train.jsonl", query);
    // read_jsonl_data(current_path.parent_path().string() + "/" + "train.jsonl", data);

    vector<Ciphertext> ciph_query = encode_and_encrypt(ckks_encoder, enc, query, scale);
    vector<Ciphertext> ciph_data = encode_and_encrypt(ckks_encoder, enc, data, scale);

    Ciphertext ciph_tmp_1;
    Ciphertext ciph_tmp_2;
    Ciphertext ciph_distance_1;
    Ciphertext ciph_distance_2;

    util::Timestacs timer_sub;
    timer_sub.start();
    logger << "calculate distance: " << std::endl;
    for (size_t i = 0; i < dimension; i++)
    {
        ckks_eva->sub_dynamic(ciph_data[i], ciph_query[i], ciph_tmp_1, ckks_encoder);
        ckks_eva->sub_dynamic(ciph_data[i + 10], ciph_query[i], ciph_tmp_2, ckks_encoder);

        ckks_eva->multiply_relin(ciph_tmp_1, ciph_tmp_1, ciph_tmp_1, relin_keys);
        ckks_eva->rescale_dynamic(ciph_tmp_1, ciph_tmp_1, scale);

        ckks_eva->multiply_relin(ciph_tmp_2, ciph_tmp_2, ciph_tmp_2, relin_keys);
        ckks_eva->rescale_dynamic(ciph_tmp_2, ciph_tmp_2, scale);

        if (i == 0)
        {
            ciph_distance_1 = ciph_tmp_1;
        }
        else
        {
            ckks_eva->add(ciph_distance_1, ciph_tmp_1, ciph_distance_1);
        }

        if (i == 0)
        {
            ciph_distance_2 = ciph_tmp_2;
        }
        else
        {
            ckks_eva->add(ciph_distance_2, ciph_tmp_2, ciph_distance_2);
        }
    }
    // logger.print_vector("ciph_distance_1", ciph_distance_1, ckks_encoder, dec);
    // logger.print_vector("ciph_distance_2", ciph_distance_2, ckks_encoder, dec);

    Ciphertext ciph_result;
    ckks_eva->sub_dynamic(ciph_distance_1, ciph_distance_2, ciph_result, ckks_encoder);
    // logger.print_vector("ciph_distance_res", ciph_result, ckks_encoder, dec);
    timer_sub.end();

    Ciphertext ciph_tmp;
    Ciphertext ciph_tmp_rotate;
    ciph_tmp = sign_1(ciph_result, polys, polys_1, ckks_encoder, ckks_eva, relin_keys, dec, enc, scale, rot_keys);
    ciph_result = accumulate_top_n_block(ciph_tmp, 100, ckks_encoder, enc, ckks_eva, rot_keys);
    logger.print_vector("相对序列: ", ciph_result, ckks_encoder, dec);
    // logger.print_vector_real("相对序列取整：", ciph_result, ckks_encoder, dec);

    // 比较数组ckks_encoder
    std::vector<std::complex<double>> cmp_top_k(N, {0.0, 0.0});
    for (size_t i = 0; i < data_nums; i++)
    {
        cmp_top_k[i].real(11.5);
    }
    Ciphertext ciph_top_k = encode_and_encrypt(ckks_encoder, enc, cmp_top_k, scale);

    match_param_id(ciph_result, ciph_top_k, ckks_eva);
    match_scale(ciph_result, ciph_top_k, ckks_encoder, ckks_eva, scale);

    // logger.print_vector("ciph_top_k", ciph_top_k, ckks_encoder, dec);
    // logger.print_vector("ciph_result", ciph_result, ckks_encoder, dec);
    ckks_eva->sub_dynamic(ciph_top_k, ciph_result, ciph_result, ckks_encoder);

    logger.print_vector("序列相减：", ciph_result, ckks_encoder, dec);

    logger.print_scale("ciph_result  level", ciph_result);

    ckks_eva->multiply_const(ciph_result, 0.014, scale, ciph_result, ckks_encoder);
    ckks_eva->rescale_dynamic(ciph_result, ciph_result, scale);

    ciph_result = sign_2(ciph_result, polys, polys_1, ckks_encoder, ckks_eva, relin_keys, dec, enc, scale, rot_keys);

    // logger.print_scale("拟合后", ciph_result);
    logger.print_vector("索引标记: ", ciph_result, ckks_encoder, dec);

    

    // 查询方
    auto result_index = decrypt_and_decode(ckks_encoder, dec, ciph_result);
    std::vector<int> result;
    for (size_t i = 0; i < 100; ++i)
    {
        if (std::round(result_index[i].real()) == 1)
        {
            result.push_back(i + 1);
            logger << "索引: " << i + 1 << std::endl;
        }
    }

    writePredictions(result, predictions_file);
    logger << timer_init.get_time_s("init time: ") << std::endl;
    logger << timer_sub.get_time_s("sub time: ") << std::endl;
    timer_real.end();
    logger << timer_real.get_time_s("cal time: ") << std::endl;
    timer.end();
    logger << timer.get_time_s("All time: ") << std::endl;

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

std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale)
{
    std::vector<Ciphertext> vec_ciph;
    for (int i = 0; i < message.size(); ++i)
    {
        Plaintext plain;
        Ciphertext ciph;
        encoder.encode(message[i], scale, plain);
        encryptor.encrypt(plain, ciph);
        vec_ciph.push_back(ciph);
    }
    return vec_ciph;
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
