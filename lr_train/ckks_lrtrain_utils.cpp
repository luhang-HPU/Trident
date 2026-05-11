#include "ckks_lrtrain_utils.h"

#include "poseidon/ckks_encoder.h"
#include "poseidon/encryptor.h"
#include "poseidon/plaintext.h"
#include "poseidon/poseidon_context.h"
#include "poseidon/util/random_sample.h"

using namespace poseidon;

namespace lr_train
{

int EPOCHS = 50;
double learning_rate = 0.95;
int m = 780;      // row size of train set
int n = 9;      // column size of train set

namespace check
{
long get_process_memory(int pid)
{
    std::string filename = "/proc/" + to_string(pid) + "/status";

    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "cannot open file: " << filename << std::endl;
        return -1;
    }

    std::string line;
    while (std::getline(file, line))
    {
        if (line.find("VmRSS:") != std::string::npos)
        {
            std::istringstream iss(line);
            std::string label;
            long rss;
            iss >> label >> rss;
            return rss;
        }
    }

    file.close();
    return -1;
}
}

double sigmoid(double x) { return (0.5 + 0.197 * x - 0.004 * x * x * x); }

Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys)
{
    Ciphertext ciph_result;
    eva->evaluate_poly_vector(ciph, ciph_result, polys, ciph.scale(), relin_keys, encoder);
    return ciph_result;
}

double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y)
{
    int cnt = 0;
    for (auto i = 0; i < m; ++i)
    {
        double sum = 0.0;
        for (auto j = 0; j < n; ++j)
        {
            sum += x[i][j].real() * weight[j].real();
        }
        if (abs(sigmoid(sum) - y[i].real()) < 0.5)
        {
            ++cnt;
        }
    }
    return (double)cnt / m;
}

double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder)
{
    Plaintext plain_weight;
    dec.decrypt(ciph_weight, plain_weight);
    std::vector<std::complex<double>> message;
    encoder.decode(plain_weight, message);
    return accuracy_of_plain(message, x, y);
}

void print_weight_and_bias(const std::vector<std::complex<double>> &weight)
{
    std::cout << "weight and bias: " << std::endl;
    for (auto i = 0; i < n; ++i)
    {
        std::cout << weight[i].real() << std::endl;
    }
    std::cout << std::endl;
}

void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string &file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file: " + file);
    }
    for (int i = 0; i < m; ++i)
    {
        for (auto j = 0; j < n; ++j)
        {
            if (!(in_file >> matrix[i][j]))
            {
                POSEIDON_THROW(config_error, "read file error: " + file);
            }
        }
    }
}

void read_file(std::vector<std::complex<double>> &matrix, const std::string &file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file: " + file);
    }
    for (int i = 0; i < n; ++i)
    {
        if (!(in_file >> matrix[i]))
        {
            POSEIDON_THROW(config_error, "read file error: " + file);
        }
    }
}

void preprocess(int block_size, int block_num, std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T)
{
    for (auto &vec : x)
    {
        vec.insert(vec.end(), block_size - vec.size(), {0.0, 0.0});
    }

    int row_added = block_size - (m % block_size);
    x.resize(x.size() + row_added);
    std::fill_n(x.end() - row_added, row_added,
                std::vector<std::complex<double>>(block_size, {0.0, 0.0}));

    for (auto i = 0; i < n; ++i)
    {
        for (auto j = 0; j < m; ++j)
        {
            x_transpose[i][j] = x[j][i];
        }
    }
    for (auto i = 0; i < block_num; ++i)
    {
        for (auto j = 0; j < block_size; ++j)
        {
            for (auto k = 0; k < block_size; ++k)
            {
                x_diag_T[i * block_size + j][k] = x[k + i * block_size][(j + k) % block_size];
            }
        }
    }
}

Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys &rot_keys)
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
    while (n)
    {
        Ciphertext ciph_tmp;
        if (n & 1 && n != 1)
        {
            bottom_nth += 1 << cnt;
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, const_n - bottom_nth, rot_keys);
            ckks_eva->add(ciph_sum, ciph_tmp, ciph_sum);
        }
        n = n >> 1;
        if (n)
        {
            ckks_eva->rotate(ciph_rotate_sum, ciph_tmp, 1 << cnt, rot_keys);
            ckks_eva->add(ciph_rotate_sum, ciph_tmp, ciph_rotate_sum);
        }
        ++cnt;
    }
    ckks_eva->add(ciph_sum, ciph_rotate_sum, ciph_sum);
    return ciph_sum;
}

int get_size(int min, int max)
{
    int num = 1;
    while (num < min)
    {
        num *= 2;
    }
    if (num > max)
    {
        POSEIDON_THROW(invalid_argument_error, "size not supported");
    }
    return num;
}

Ciphertext accumulate_block_matrix(const std::shared_ptr<EvaluatorCkksBase> eva,
                                   const GaloisKeys &rot_key, const Ciphertext &ciph,
                                   int block_size)
{
    Ciphertext ciph_sum = ciph;
    for (auto i = 1; i < block_size; i <<= 1)
    {
        Ciphertext ciph_rotate = ciph_sum;
        eva->rotate(ciph_rotate, ciph_rotate, i * block_size, rot_key);
        eva->add(ciph_sum, ciph_rotate, ciph_sum);
    }
    return ciph_sum;
}

Ciphertext accumulate_slot_matrix(const std::shared_ptr<EvaluatorCkksBase> eva,
                                  const GaloisKeys &rot_key, const Ciphertext &ciph, int block_size,
                                  int block_num)
{
    Ciphertext ciph_sum = ciph;
    for (auto i = 1; i < block_num; i <<= 1)
    {
        Ciphertext ciph_rotate = ciph_sum;
        eva->rotate(ciph_rotate, ciph_rotate, i * block_size * block_size, rot_key);
        eva->add(ciph_sum, ciph_rotate, ciph_sum);
    }
    return ciph_sum;
}

std::vector<std::complex<double>>
vector_to_block_message(const std::vector<std::complex<double>> &vec, int cnt, int block_size)
{
    std::vector<std::complex<double>> ans;
    for (auto i = 0; i < cnt; ++i)
    {
        ans.push_back(vec[i]);
        if ((i + 1) % block_size == 0)
        {
            ans.insert(ans.end(), (block_size - 1) * block_size, std::complex<double>(0.0, 0.0));
        }
    }
    return ans;
}

}