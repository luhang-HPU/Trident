#include "knn_utils.h"

using json = nlohmann::json;
using namespace poseidon::util;

namespace KNN
{

std::filesystem::path current_path(__FILE__);
int data_nums = 100;
int dimension = 10;
int N = 16384;
int NUM = 128;
int num_threads = 8;

void read_jsonl_query(const std::string &file,
                      std::vector<std::vector<std::complex<double>>> &query)
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

void read_jsonl_data(const std::string &file,
                     std::vector<std::vector<std::complex<double>>> &matrix_data)
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
                matrix_data[col][target_row] =
                    std::complex<double>(row_data[col].get<double>() / 40, 0.0);
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
                matrix_data[col + 10][target_row] =
                    std::complex<double>(row_data[col].get<double>() / 40, 0.0);
            }
        }
    }
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

void encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                        std::vector<std::complex<double>> &message, double scale, Ciphertext &ciph)
{
    Plaintext plain;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, ciph);
}

std::vector<Ciphertext>
encode_and_encrypt_mt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                      std::vector<std::vector<std::complex<double>>> &message, double scale)
{
    ThreadPool thread_pool(num_threads);
    std::vector<Ciphertext> vec_ciph;
    vec_ciph.resize(message.size());
    const int work_load = (message.size() + num_threads - 1) / num_threads;
    for (int w = 0; w < num_threads; ++w)
    {
        int start = w * work_load;
        int end = std::min<int>(start + work_load, message.size());

        if (end > start)
        {
            thread_pool.enqueue(
                [&](size_t s, size_t e)
                {
                    for (size_t i = s; i < e; ++i)
                    {
                        encode_and_encrypt(encoder, encryptor, message[i], scale, vec_ciph[i]);
                    }
                },
                start, end);
        }
    }
    return vec_ciph;
}

void generate_glaios_mt(KeyGenerator &kgen, vector<vector<int>> step, GaloisKeys &rot_keys)
{
    ThreadPool thread_pool(num_threads);
    const int work_load = (step.size() + num_threads - 1) / num_threads;
    for (int w = 0; w < num_threads; ++w)
    {
        int start = w * work_load;
        int end = std::min<int>(start + work_load, step.size());

        if (end > start)
        {
            thread_pool.enqueue(
                [&](size_t s, size_t e)
                {
                    for (size_t i = s; i < e; ++i)
                    {
                        kgen.create_galois_keys(step[i], rot_keys);
                    }
                },
                start, end);
        }
    }
}

void sub_and_square(const std::shared_ptr<EvaluatorCkksBase> &ckks_eva,
                    std::vector<Ciphertext> &ciph_data, const std::vector<Ciphertext> &ciph_query,
                    const poseidon::RelinKeys &relin_keys, const double scale)
{
    std::vector<Ciphertext> vec_ciph;
    vec_ciph.resize(ciph_data.size());

    ThreadPool thread_pool(num_threads);
    const int work_load = (ciph_query.size() + num_threads - 1) / num_threads;

    for (int w = 0; w < num_threads; ++w)
    {
        int start = w * work_load;
        int end = std::min<int>(start + work_load, ciph_query.size());

        if (end > start)
        {
            thread_pool.enqueue(
                [&](size_t s, size_t e)
                {
                    for (size_t i = s; i < e; ++i)
                    {
                        ckks_eva->sub(ciph_data[i], ciph_query[i], ciph_data[i]);
                        ckks_eva->sub(ciph_data[i + 10], ciph_query[i], ciph_data[i + 10]);

                        ckks_eva->multiply_relin(ciph_data[i], ciph_data[i], ciph_data[i],
                                                 relin_keys);
                        ckks_eva->rescale_dynamic(ciph_data[i], ciph_data[i], scale);

                        ckks_eva->multiply_relin(ciph_data[i + 10], ciph_data[i + 10],
                                                 ciph_data[i + 10], relin_keys);
                        ckks_eva->rescale_dynamic(ciph_data[i + 10], ciph_data[i + 10], scale);
                    }
                },
                start, end);
        }
    }
}

void match_param_id(Ciphertext &ciph1, Ciphertext &ciph2, std::shared_ptr<EvaluatorCkksBase> eva)
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

void match_scale(Ciphertext &ciph1, Ciphertext &ciph2, const CKKSEncoder &encoder,
                 std::shared_ptr<EvaluatorCkksBase> eva, double scale)
{
    if (!util::are_approximate(ciph1.scale(), ciph2.scale()))
    {
        ciph1.scale() = ciph2.scale();
        std::vector<std::complex<double>> vec_tmp(NUM, {1.0, 0.0});
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
Ciphertext sign_1(const Ciphertext &ciph, const PolynomialVector &polys_1,
                  const PolynomialVector &polys_2, const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva, const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_1, ciph_result.scale(), relin_keys,
                              encoder);
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys_2, ciph_result.scale(), relin_keys,
                              encoder);
    eva->add_const(ciph_result, 0.5, ciph_result, encoder);
    return ciph_result;
}

// sign_2 第二次拟合
Ciphertext sign_2(const Ciphertext &ciph, const PolynomialVector &polys, const CKKSEncoder &encoder,
                  std::shared_ptr<EvaluatorCkksBase> eva, const RelinKeys &relin_keys)
{
    auto ciph_result = ciph;
    eva->evaluate_poly_vector(ciph_result, ciph_result, polys, ciph_result.scale(), relin_keys,
                              encoder);
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

std::string get_current_path()
{
    char path_buffer[PATH_MAX] = {0};
    // 读取当前进程的可执行文件路径（/proc/self/exe 是 Linux 特有的符号链接）
    ssize_t len = readlink("/proc/self/exe", path_buffer, PATH_MAX - 1);
    std::string path = std::string(path_buffer, len);

    // 从完整路径中截取目录部分
    size_t pos = path.find_last_of("/");
    if (pos != std::string::npos)
    {
        path = path.substr(0, pos + 1);  // 保留路径分隔符
    }
    return path;
}

}

