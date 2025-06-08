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

#include <fstream>
#include <filesystem>

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

// #define DEBUG_LRTRAIN

const int EPOCHS = 4;
const double learning_rate = 0.95;
int m = 780;      // row size of train set
int n = 9;      // column size of train set
int m_slot = 16384;

namespace check
{
template <typename T> void print_vector(const std::vector<T> &vec)
{
    ofstream of("output.txt", ios::app);
    of << "print vector: " << std::endl;
    for (auto value : vec)
    {
        of << value << std::endl;
    }
    of << std::endl;
}

template <typename T> void print_matrix(const std::vector<std::vector<T>> &matrix)
{
    ofstream of("output.txt", ios::app);
    of << "print matrix: " << std::endl;
    for (auto row : matrix)
    {
        for (auto value : row)
        {
            of << value << " ";
        }
        of << std::endl;
    }
}


}  // namespace check

void read_file(std::vector<std::complex<double>> &matrix, const std::string& file);
void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string& file);
void read_x_vecter(std::vector<std::complex<double>> &vec, const std::string& file);
Ciphertext encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                              std::vector<std::complex<double>> &message, double scale);
std::vector<Ciphertext> encode_and_encrypt(const CKKSEncoder &encoder, const Encryptor &encryptor,
                                           std::vector<std::vector<std::complex<double>>> &message,
                                           double scale);
std::vector<std::complex<double>> decrypt_and_decode(const CKKSEncoder &encoder,
                                                     Decryptor &decryptor, const Ciphertext &ciph);
double accuracy_of_plain(const std::vector<std::complex<double>> &weight,
                         const std::vector<std::vector<std::complex<double>>> &x,
                         const std::vector<std::complex<double>> &y);
double accuracy_of_ciph(const Ciphertext &ciph_weight,
                        const std::vector<std::vector<std::complex<double>>> &x,
                        const std::vector<std::complex<double>> &y, Decryptor &dec,
                        const CKKSEncoder &encoder);

void preprocess(const std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T,
                std::vector<std::vector<std::complex<double>>> &identity_matrix);
// ciph.slot[0] = slot[0] + slot[1] + ... + slot[n-1]
// ciph.slot[x] = 0 , x != 0
Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
                            const Encryptor &enc, std::shared_ptr<EvaluatorCkksBase> ckks_eva,
                            const GaloisKeys rot_keys);
double sigmoid(double x);
Ciphertext sigmoid_approx(const Ciphertext &ciph, const PolynomialVector &polys,
                          const CKKSEncoder &encoder, std::shared_ptr<EvaluatorCkksBase> eva,
                          const RelinKeys &relin_keys);

void update_weight(const std::vector<std::vector<std::complex<double>>> &x,
                   const std::vector<std::complex<double>> &y,
                   std::vector<std::complex<double>> &weight);
void update_weight_approx();

template<typename T>
bool writeVectorToFile(const std::vector<T>& data,
                       const std::string& filename,
                       const std::string& delimiter = " ",
                       size_t elementsPerLine = 9,
                       bool append = true,
                       bool addFinalNewline = true) {
    try {
        // 打开文件
        std::ofstream file(filename, append ? std::ios::app : std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("无法打开文件: " + filename);
        }

        // 写入数据
        for (size_t i = 0; i < data.size(); ++i) {
            // 对普通类型和复数类型进行不同处理
            if constexpr (std::is_same_v<T, std::complex<double>> ||
                          std::is_same_v<T, std::complex<float>>) {
                file << data[i].real();
            } else {
                file << data[i];
            }

            // 判断是否需要添加分隔符或换行
            if (i != data.size() - 1) {
                if ((i + 1) % elementsPerLine == 0) {
                    file << "\n";  // 换行
                } else {
                    file << delimiter;  // 分隔符
                }
            }

            // 检查写入是否成功
            if (!file.good()) {
                throw std::runtime_error("写入文件失败: " + filename);
            }
        }

        // 添加最终换行符（可选）
        if (addFinalNewline && !data.empty()) {
            file << "\n";
        }

        // 确保文件操作成功
        if (!file.good()) {
            throw std::runtime_error("写入文件失败: " + filename);
        }

        return true;
    } catch (const std::exception& e) {
        std::cerr << "写入文件失败: " << e.what() << std::endl;
        return false;
    }
}

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;

    ParametersLiteral ckks_param_literal{CKKS, 15, 15 - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> logQTmp(44, 32);
    vector<uint32_t> logPTmp(1, 60);
    ckks_param_literal.set_log_modulus(logQTmp, logPTmp);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    // input of trainning set
    vector<vector<complex<double>>> x(m, vector<complex<double>>(m, {0.0, 0.0}));
    // input of trainning set
    vector<complex<double>> vecter_x(m_slot, {0.0, 0.0});
    // output
    vector<complex<double>> vecter_y(m_slot, {0.0, 0.0});
    // weight
    vector<complex<double>> weight(m_slot, {0.0, 0.0});

    std::filesystem::path current_path(__FILE__);

    read_file(x, current_path.parent_path().string() + "/" + "x_train.txt");
    read_x_vecter(vecter_x, current_path.parent_path().string() + "/" + "x_train.txt");
    read_file(vecter_y, current_path.parent_path().string() + "/" + "y_train.txt");

    auto slot_size = 1 << ckks_param_literal.log_slots();
    double scale = std::pow(2.0, q_def);

    if ((m << 1) > slot_size)
    {
        POSEIDON_THROW(invalid_argument_error,
                       "size of matrix * 2 must be smaller than ciphertext slot!");
    }

    // init weight randomly
    srand(0);
    for (int i = 0; i < n; ++i)
    {
        weight[i].imag(0);
        double sum = 0;
        for (int j = 0; j < 200; ++j)
            sum += rand() / (RAND_MAX + 1.0);
        sum -= 100;
        sum /= sqrt(200.0 * n / 12);
        weight[i].real(sum);
    }
    auto _weight = weight;

    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys conj_keys;
    GaloisKeys rot_keys;
    CKKSEncoder ckks_encoder(context);

    // init keys
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);

    Encryptor enc(context, public_key, kgen.secret_key());
    Decryptor dec(context, kgen.secret_key());
    std::shared_ptr<EvaluatorCkksBase> ckks_eva =
        PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    Ciphertext ciph_x = encode_and_encrypt(ckks_encoder, enc, vecter_x, scale);
    Ciphertext ciph_y = encode_and_encrypt(ckks_encoder, enc, vecter_y, scale);
    Ciphertext ciph_weight = encode_and_encrypt(ckks_encoder, enc, weight, scale);

    vector<complex<double>> buffer(4, 0);
    buffer[0] = 0.5;
    buffer[1] = 0.197;
    buffer[3] = -0.004;

    Polynomial approxF(buffer, 0, 0, 4, Monomial);
    approxF.lead() = true;
    vector<Polynomial> poly_v{approxF};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);
    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;  // Index with all even slots
    }
    slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v, slots_index);

    util::Timestacs timer;
    timer.start();
    for (auto epoch = 0; epoch < EPOCHS; ++epoch)
    {
        util::Timestacs timer_epoch;
        timer_epoch.start();
        auto ciph_weight_expand = ciph_weight;
        auto ciph_weight_expand_tmp = ciph_weight;

        // 右旋到对应位置
        for (int i = 1; i <= 8; i++) {
            ckks_eva->rotate(ciph_weight_expand_tmp, ciph_weight_expand_tmp, -1023, rot_keys);
            ckks_eva->add(ciph_weight_expand, ciph_weight_expand_tmp, ciph_weight_expand);
        }
        // 通过掩码将每组槽位的第一位取出
        std::vector<std::complex<double>> vec_mask(m_slot, std::complex<double>(0.0, 0.0));
        for (size_t i = 0; i <= 8192; i += 1024) {
            vec_mask[i] = std::complex<double>(1.0, 0.0);
        }
        Plaintext plain_mask;
        ckks_encoder.encode(vec_mask, ciph_weight_expand.parms_id(), ciph_weight_expand.scale(), plain_mask);
        ckks_eva->multiply_plain(ciph_weight_expand, plain_mask, ciph_weight_expand);
        ckks_eva->rescale_dynamic(ciph_weight_expand, ciph_weight_expand, scale);

        Ciphertext ciph_weight_temp;
        for (int i = 0; i < 10; i++) {
            int rotation_step = -std::pow(2, i);
            ckks_eva->rotate(ciph_weight_expand, ciph_weight_temp, rotation_step, rot_keys);
            ckks_eva->add(ciph_weight_expand, ciph_weight_temp, ciph_weight_expand);
        }

        Ciphertext ciph_tmp;
        // calculate ciph_tmp = (theta * x1, theta * x2, ... , theta * xm, ...)
        auto ciph_x_x = ciph_x;
        ckks_eva->drop_modulus(ciph_x_x, ciph_x_x, ciph_weight_expand.parms_id());
        ckks_eva->multiply_relin(ciph_x_x, ciph_weight_expand, ciph_tmp, relin_keys);
        ckks_eva->rescale_dynamic(ciph_tmp, ciph_tmp, scale);

        auto ciph_temp_rotated = ciph_tmp;
        for (auto i = 1; i < n; ++i)
        {
            ckks_eva->rotate(ciph_temp_rotated, ciph_temp_rotated, 1024, rot_keys);
            ckks_eva->add(ciph_tmp, ciph_temp_rotated, ciph_tmp);
        }


#ifdef DEBUG_LRTRAIN
        // check theta^T * x
        std::vector<std::complex<double>> dot_product;
        {
            check::print_vector(vecter_x);
            // check::print_matrix(x_diag_T);
            check::print_vector(weight);
            std::vector<double> _dot_product;
            for (auto i = 0; i < m; ++i)
            {
                double _sum = 0.0;
                for (auto j = 0; j < m; ++j)
                {
                    _sum += x[i][j].real() * _weight[j].real();
                }
                _dot_product.push_back(_sum);
            }

            dot_product = decrypt_and_decode(ckks_encoder, dec, ciph_tmp);
            std::cout << "fhe value  |  perdict value" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << dot_product[i].real() << " " << _dot_product[i] << std::endl;
            }
        };
#endif

        if (0 == epoch)
        {
            ckks_eva->multiply_const(ciph_y, 1.0, scale, ciph_y, ckks_encoder);
            ckks_eva->rescale_dynamic(ciph_y, ciph_y, scale);
        }

        // calculate sigmoid(theta^T x)
        std::cout << "calculate sigmoid(theta^T x)" << std::endl;
        Ciphertext ciph_sigmoid =
            sigmoid_approx(ciph_tmp, polys, ckks_encoder, ckks_eva, relin_keys);

#ifdef DEBUG_LRTRAIN
        // check sigmoid
        std::vector<double> perdict_sigmoid(m, 0.0);
        {
            auto res = decrypt_and_decode(ckks_encoder, dec, ciph_sigmoid);
            for (auto i = 0; i < m; ++i)
            {
                perdict_sigmoid[i] = sigmoid(dot_product[i].real());
            }
            std::cout << "fhe sigmoid  |  perdict sigmoid" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << res[i] << " " << perdict_sigmoid[i] << std::endl;
            }
        }
#endif

        // calculate gradient
        ckks_eva->sub_dynamic(ciph_sigmoid, ciph_y, ciph_sigmoid, ckks_encoder);

        Ciphertext ciph_accumulate;
        Ciphertext ciph_gradient;
        auto ciph_x_temp = ciph_x;
        ckks_eva->drop_modulus(ciph_x_temp, ciph_x_temp, ciph_sigmoid.parms_id());

        for (auto j = 0; j < n; ++j)
        {
            if (j != 0) {
                ckks_eva->rotate(ciph_x_temp, ciph_x_temp, 1024, rot_keys);
            }
            ckks_eva->multiply_relin(ciph_sigmoid, ciph_x_temp, ciph_accumulate, relin_keys);
            ckks_eva->rescale_dynamic(ciph_accumulate, ciph_accumulate, scale);
            ciph_accumulate =
                accumulate_top_n(ciph_accumulate, m, ckks_encoder, enc, ckks_eva, rot_keys);
            // 通过掩码将第一位取出
            std::vector<std::complex<double>> vec_mask{1.0};
            Plaintext plain_mask;
            ckks_encoder.encode(vec_mask, ciph_accumulate.parms_id(), ciph_accumulate.scale(), plain_mask);
            ckks_eva->multiply_plain(ciph_accumulate, plain_mask, ciph_accumulate);
            if (j != 0){
                ckks_eva->rotate(ciph_accumulate, ciph_accumulate, -j, rot_keys);
            }
            if (j == 0){
                ciph_gradient = ciph_accumulate;
            }
            else{
                ckks_eva->add(ciph_accumulate, ciph_gradient, ciph_gradient);
            }
        }
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

        ckks_eva->multiply_const(ciph_gradient, learning_rate / m, ciph_gradient.scale(), ciph_gradient, ckks_encoder);
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

#ifdef DEBUG_LRTRAIN
        check gradient
        {
            std::vector<double> perdict_gradient(m, 0.0);
            for (auto j = 0; j < m; ++j)
            {
                auto sum = 0.0;
                for (auto i = 0; i < m; ++i)
                {
                    sum += (perdict_sigmoid[i] - y[i].real()) * x[i][j].real();
                }
                perdict_gradient[j] = sum / m;
            }
            auto res = decrypt_and_decode(ckks_encoder, dec, ciph_gradient);
            std::cout << "fhe gradient  |  perdict gradient" << std::endl;
            for (auto j = 0; j < m; ++j)
            {
                std::cout << res[j].real() << " " << perdict_gradient[j] << std::endl;
            }
        }
#endif

        // update ciph_weight
        ckks_eva->sub_dynamic(ciph_weight, ciph_gradient, ciph_weight, ckks_encoder);

        // check weight updated begin
        update_weight(x, vecter_y, _weight);
        std::cout << "fhe weight  |  perdict weight" << std::endl;
        auto res = decrypt_and_decode(ckks_encoder, dec, ciph_weight);
        for (auto i = 0; i < n; ++i)
        {
            std::cout << res[i].real() << " " << _weight[i].real() << std::endl;
        }

        timer.end();
        timer.print_time("lr train time one epoch: ");
    }

    timer.end();
    timer.print_time("lr train time: ");

    Plaintext plain_weight;
    dec.decrypt(ciph_weight, plain_weight);
    ckks_encoder.decode(plain_weight, weight);

    // std::cout << "accuracy of ciph: " << accuracy_of_plain(weight, x, y) << std::endl;

    return 0;
}

double sigmoid(double x)
{
    // return(exp(x) / (1 + exp(x)));
    return (0.5 + 0.197 * x - 0.004 * x * x * x);
}

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

void read_file(std::vector<std::vector<std::complex<double>>> &matrix, const std::string& file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file ：" + file);
    }
    for (int i = 0; i < m; ++i)
    {
        for (auto j = 0; j < n; ++j)
        {
            if (!(in_file >> matrix[i][j]))
            {
                POSEIDON_THROW(config_error, "read file error ：" + file);
            }
        }
    }
}

void read_x_vecter(std::vector<std::complex<double>> &vec, const std::string& file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file ：" + file);
    }
    for (int i = 0; i < m; ++i)
    {
        for (auto j = 0; j < n; ++j)
        {
            if (!(in_file >> vec[i + j * 1024]))
            {
                POSEIDON_THROW(config_error, "read file error ：" + file);
            }
        }
    }
}

void read_file(std::vector<std::complex<double>> &matrix, const std::string& file)
{
    std::ifstream in_file(file, ios::in);
    if (!in_file)
    {
        POSEIDON_THROW(config_error, "cannot open file ：" + file);
    }
    for (int i = 0; i < n; ++i)
    {
        if (!(in_file >> matrix[i]))
        {
            POSEIDON_THROW(config_error, "read file error ：" + file);
        }
    }
}

void preprocess(const std::vector<std::vector<std::complex<double>>> &x,
                std::vector<std::vector<std::complex<double>>> &x_transpose,
                std::vector<std::vector<std::complex<double>>> &x_diag_T,
                std::vector<std::vector<std::complex<double>>> &identity_matrix)
{
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < m; ++j)
        {
            x_transpose[i][j] = x[j][i];
        }
    }
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < m; ++j)
        {
            x_diag_T[i][j] = x[j][(i + j) % m];
        }
    }
    for (int i = 0; i < m; ++i)
    {
        identity_matrix[i][i] = 1.0;
    }
}

Ciphertext accumulate_top_n(const Ciphertext &ciph, int n, const CKKSEncoder &encoder,
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
    for (int i = 0; i < m; ++i)
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

void update_weight(const std::vector<std::vector<std::complex<double>>> &x,
                   const std::vector<std::complex<double>> &y,
                   std::vector<std::complex<double>> &weight)
{
    std::vector<std::complex<double>> sig(m);
    std::vector<std::complex<double>> grad(n);

    for (auto i = 0; i < m; ++i)
    {
        auto sum = 0.0;
        for (auto j = 0; j < n; ++j)
        {
            sum += x[i][j].real() * weight[j].real();
        }
        sig[i] = sigmoid(sum);
    }

    for (auto j = 0; j < n; ++j)
    {
        for (auto i = 0; i < m; ++i)
        {
            grad[j] += (sig[i] - y[i].real()) * x[i][j].real();
        }
        grad[j] /= m;
        weight[j] -= learning_rate * grad[j];
    }
}
