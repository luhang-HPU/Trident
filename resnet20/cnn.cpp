#include "cnn.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;
using namespace poseidon;

namespace
{

constexpr int kPreviewSlots = 8;
namespace fs = std::filesystem;

size_t slot_count_from_logn(int logn)
{
    if (logn < 1)
    {
        throw std::invalid_argument("logn should be positive");
    }
    return static_cast<size_t>(1) << (logn - 1);
}

int pow2(int exponent)
{
    if (exponent < 0)
    {
        throw std::invalid_argument("negative exponent is not supported");
    }
    return 1 << exponent;
}

int floor_to_int(double value)
{
    return static_cast<int>(floor(value));
}

int log2_long(long value)
{
    if (value <= 0 || (value & (value - 1)) != 0)
    {
        return -1;
    }
    int exponent = 0;
    while ((1L << exponent) != value)
    {
        ++exponent;
    }
    return exponent;
}

size_t chain_index_or_throw(const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

void decode_preview(const Ciphertext &cipher, Decryptor &decryptor, CKKSEncoder &encoder,
                    ostream &output)
{
    Plaintext plain;
    decryptor.decrypt(cipher, plain);

    vector<complex<double>> values;
    encoder.decode(plain, values);

    output << "preview:";
    const size_t preview = min(values.size(), static_cast<size_t>(kPreviewSlots));
    for (size_t i = 0; i < preview; ++i)
    {
        output << ' ' << values[i].real();
    }
    output << '\n';
}

double multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw std::runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    const int rescale_prime_bits = context_data->coeff_modulus().back().bit_count();
    return std::pow(2.0, static_cast<double>(rescale_prime_bits));
}

void multiply_by_vector(const Ciphertext &input, const vector<double> &weights, Ciphertext &output,
                        CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    encoder.encode(weights, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    evaluator.multiply_plain(input, plain, output);
    evaluator.rescale_dynamic(output, output, input.scale());
}

void multiply_by_vector_inplace(Ciphertext &input, const vector<double> &weights,
                                CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    Plaintext plain;
    const double original_scale = input.scale();
    encoder.encode(weights, input.parms_id(), multiply_plain_scale(input, encoder), plain);
    evaluator.multiply_plain_inplace(input, plain);
    evaluator.rescale_dynamic(input, input, original_scale);
}

void log_labeled_tensor_state(const string &label, const TensorCipher &tensor,
                              const PoseidonContext &context, ostream &output);

void log_labeled_cipher_state(const string &label, const Ciphertext &cipher,
                              const TensorCipher &meta_source, const PoseidonContext &context,
                              ostream &output);

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term, CKKSEncoder &encoder,
                        EvaluatorCkksBase &evaluator)
{
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

PolynomialVector build_polynomial_vector_from_coeffs(const vector<double> &coeffs, int slot_size,
                                                     int max_degree)
{
    vector<vector<int>> slots_index(1, vector<int>(slot_size, 0));
    for (int i = 0; i < slot_size; ++i)
    {
        slots_index[0][i] = i;
    }

    vector<complex<double>> complex_coeffs;
    complex_coeffs.reserve(coeffs.size());
    for (double coeff : coeffs)
    {
        complex_coeffs.emplace_back(coeff, 0.0);
    }
    Polynomial poly(complex_coeffs, 0, 0, max_degree, Monomial);
    poly.lead() = true;
    return PolynomialVector(vector<Polynomial>{poly}, slots_index);
}

vector<vector<double>> load_relu_component_coeffs(long alpha, const vector<int> &deg,
                                                  double scaled_val)
{
    const fs::path relu_file =
        fs::path(__FILE__).parent_path() / "relu_param" / ("d" + to_string(alpha) + ".txt");
    ifstream input(relu_file);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open relu parameter file: " + relu_file.string());
    }

    vector<vector<double>> coeffs;
    coeffs.reserve(deg.size());
    for (int degree : deg)
    {
        vector<double> component;
        component.reserve(static_cast<size_t>(degree + 1));
        for (int i = 0; i <= degree; ++i)
        {
            double coeff = 0.0;
            if (!(input >> coeff))
            {
                throw std::runtime_error("failed to read relu coefficients from: " +
                                         relu_file.string());
            }
            component.emplace_back(coeff);
        }
        coeffs.emplace_back(std::move(component));
    }

    if (coeffs.size() >= 3)
    {
        for (double &coeff : coeffs[0])
        {
            coeff /= 2.0;
        }
        for (double &coeff : coeffs[1])
        {
            coeff /= scaled_val;
        }
        for (double &coeff : coeffs[2])
        {
            coeff *= 0.5;
        }
    }

    return coeffs;
}

void log_relu_component_coeffs(const vector<vector<double>> &coeffs, ostream &output)
{
    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        output << "sign poly component " << (i + 1) << " coeff_count=" << coeffs[i].size()
               << '\n';
        output << "coeffs:";
        for (double coeff : coeffs[i])
        {
            output << ' ' << coeff;
        }
        output << '\n';
    }
}

Ciphertext approximate_sign01(const Ciphertext &input, const vector<int> &deg, long alpha,
                              double scaled_val, int slot_size, CKKSEncoder &encoder,
                              EvaluatorCkksBase &evaluator, RelinKeys &relin_keys,
                              const TensorCipher *meta_source = nullptr,
                              const PoseidonContext *context = nullptr,
                              ostream *output = nullptr)
{
    Ciphertext result = input;
    const vector<vector<double>> coeffs = load_relu_component_coeffs(alpha, deg, scaled_val);
    if (output)
    {
        log_relu_component_coeffs(coeffs, *output);
    }

    for (size_t i = 0; i < coeffs.size(); ++i)
    {
        const PolynomialVector polys =
            build_polynomial_vector_from_coeffs(coeffs[i], slot_size, deg.at(i));
        if (meta_source && context && output)
        {
            log_labeled_cipher_state("sign poly step " + to_string(i + 1) + " pre-eval state",
                                     result, *meta_source, *context, *output);
        }
        evaluator.evaluate_poly_vector(result, result, polys, result.scale(), relin_keys, encoder);
        if (meta_source && context && output)
        {
            log_labeled_cipher_state("sign poly step " + to_string(i + 1) + " post-eval state",
                                     result, *meta_source, *context, *output);
        }
    }

    evaluator.add_const(result, 0.5, result, encoder);
    if (meta_source && context && output)
    {
        log_labeled_cipher_state("sign poly add-const state", result, *meta_source, *context,
                                 *output);
    }

    return result;
}

void print_stage_banner(const string &title, ostream &output)
{
    cout << title << endl;
    output << title << endl;
}

void log_labeled_tensor_state(const string &label, const TensorCipher &tensor,
                              const PoseidonContext &context, ostream &output)
{
    output << label << '\n';
    log_cipher_state(tensor, context, output);
}

void log_labeled_cipher_state(const string &label, const Ciphertext &cipher,
                              const TensorCipher &meta_source, const PoseidonContext &context,
                              ostream &output)
{
    TensorCipher tensor(meta_source.logn(), meta_source.k(), meta_source.h(), meta_source.w(),
                        meta_source.c(), meta_source.t(), meta_source.p(), cipher);
    log_labeled_tensor_state(label, tensor, context, output);
}

void log_after_stage(const TensorCipher &tensor, Decryptor &decryptor, CKKSEncoder &encoder,
                     PoseidonContext &context, ostream &output)
{
    decode_preview(tensor.cipher(), decryptor, encoder, output);
    log_cipher_state(tensor, context, output);
    output << endl;
}

void relu_impl(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
               const vector<int> &deg, long alpha, double scaled_val,
               EvaluatorCkksBase &evaluator, CKKSEncoder &encoder, RelinKeys &relin_keys,
               double scale, ostream *output, const PoseidonContext *context)
{
    (void)comp_no;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    const int slot_size = static_cast<int>(slot_count_from_logn(logn));

    if (output && context)
    {
        log_labeled_tensor_state("relu input state", cnn_in, *context, *output);
    }

    Ciphertext mask;
    try
    {
        mask = approximate_sign01(cnn_in.cipher(), deg, alpha, scaled_val, slot_size, encoder,
                                  evaluator, relin_keys, &cnn_in, context, output);
        if (output && context)
        {
            log_labeled_cipher_state("relu sign-mask state", mask, cnn_in, *context, *output);
        }
    }
    catch (const std::exception &e)
    {
        if (output)
        {
            *output << "relu failure during sign polynomial: " << e.what() << '\n';
        }
        throw;
    }

    Ciphertext temp;
    try
    {
        evaluator.multiply_relin_dynamic(cnn_in.cipher(), mask, temp, relin_keys);
        if (output && context)
        {
            log_labeled_cipher_state("relu post-multiply state", temp, cnn_in, *context, *output);
        }
    }
    catch (const std::exception &e)
    {
        if (output)
        {
            *output << "relu failure during multiply_relin_dynamic: " << e.what() << '\n';
        }
        throw;
    }

    try
    {
        evaluator.rescale_dynamic(temp, temp, scale > 0.0 ? scale : cnn_in.cipher().scale());
        if (output && context)
        {
            log_labeled_cipher_state("relu post-rescale state", temp, cnn_in, *context, *output);
        }
    }
    catch (const std::exception &e)
    {
        if (output)
        {
            *output << "relu failure during rescale_dynamic: " << e.what() << '\n';
        }
        throw;
    }

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, temp);
}

} // namespace

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const vector<double> &data, Encryptor &encryptor,
                           CKKSEncoder &encoder, int logp)
{
    if (k != 1)
    {
        throw std::invalid_argument("supported k is only 1 right now");
    }
    if (logn < 1 || logn > 16)
    {
        throw std::out_of_range("the value of logn is out of range");
    }

    const size_t slot_count = encoder.slot_count();
    if (data.size() > slot_count)
    {
        throw std::out_of_range("the size of data is larger than slot count");
    }

    k_ = k;
    h_ = h;
    w_ = w;
    c_ = c;
    t_ = t;
    p_ = p;
    logn_ = logn;

    vector<complex<double>> slots(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < data.size(); ++i)
    {
        slots[i] = {data[i], 0.0};
    }

    Plaintext plain;
    encoder.encode(slots, pow(2.0, logp), plain);
    encryptor.encrypt(plain, cipher_);
}

TensorCipher::TensorCipher(int logn, int k, int h, int w, int c, int t, int p,
                           const Ciphertext &cipher)
    : k_(k), h_(h), w_(w), c_(c), t_(t), p_(p), logn_(logn), cipher_(cipher)
{
}

int TensorCipher::k() const
{
    return k_;
}

int TensorCipher::h() const
{
    return h_;
}

int TensorCipher::w() const
{
    return w_;
}

int TensorCipher::c() const
{
    return c_;
}

int TensorCipher::t() const
{
    return t_;
}

int TensorCipher::p() const
{
    return p_;
}

int TensorCipher::logn() const
{
    return logn_;
}

const Ciphertext &TensorCipher::cipher() const
{
    return cipher_;
}

Ciphertext &TensorCipher::cipher()
{
    return cipher_;
}

void TensorCipher::set_ciphertext(const Ciphertext &cipher)
{
    cipher_ = cipher;
}

void TensorCipher::print_parms(ostream &output) const
{
    output << "k: " << k_ << '\n';
    output << "h: " << h_ << '\n';
    output << "w: " << w_ << '\n';
    output << "c: " << c_ << '\n';
    output << "t: " << t_ << '\n';
    output << "p: " << p_ << '\n';
}

void log_cipher_state(const TensorCipher &tensor, const PoseidonContext &context, ostream &output)
{
    tensor.print_parms(output);
    output << "remaining level : " << chain_index_or_throw(context, tensor.cipher()) << '\n';
    output << "scale: " << tensor.cipher().scale() << '\n';
}

void multiplexed_parallel_convolution_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const vector<double> &data, vector<double> running_var, vector<double> constant_weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, ostream &output, Decryptor &decryptor,
    PoseidonContext &context, size_t stage, bool end)
{
    print_stage_banner("multiplexed parallel convolution...", output);
    log_labeled_tensor_state("convolution input state", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_convolution_seal(cnn_in, cnn_out, co, st, fh, fw, data,
                                          std::move(running_var), std::move(constant_weight),
                                          epsilon, encoder, encryptor, evaluator, gal_keys,
                                          cipher_pool, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    output << "convolution stage " << stage << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void multiplexed_parallel_batch_norm_seal_print(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, vector<double> bias,
    vector<double> running_mean, vector<double> running_var, vector<double> weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    double B, ostream &output, Decryptor &decryptor, PoseidonContext &context, size_t stage,
    bool end)
{
    print_stage_banner("multiplexed parallel batch normalization...", output);
    log_labeled_tensor_state("batchnorm input state", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_batch_norm_seal(cnn_in, cnn_out, std::move(bias), std::move(running_mean),
                                         std::move(running_var), std::move(weight), epsilon,
                                         encoder, encryptor, evaluator, B, end);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    output << "batch normalization stage " << stage << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void approx_ReLU_seal_print(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
                            vector<int> deg, long alpha, vector<Tree> &tree, double scaled_val,
                            long scalingfactor, Encryptor &encryptor,
                            EvaluatorCkksBase &evaluator, Decryptor &decryptor,
                            CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key,
                            RelinKeys &relin_keys, double B, ostream &output,
                            PoseidonContext &context, GaloisKeys &gal_keys, size_t stage)
{
    (void)comp_no;
    (void)deg;
    (void)alpha;
    (void)tree;
    (void)scaled_val;
    (void)scalingfactor;
    (void)encryptor;
    (void)public_key;
    (void)secret_key;
    (void)B;
    (void)gal_keys;

    print_stage_banner("approximate ReLU...", output);
    log_labeled_tensor_state("relu wrapper input state", cnn_in, context, output);
    const auto time_start = chrono::high_resolution_clock::now();
    relu_impl(cnn_in, cnn_out, comp_no, deg, alpha, scaled_val, evaluator, encoder, relin_keys,
              B, &output, &context);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    output << "ReLU stage " << stage << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void bootstrap_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                     PoseidonBootstrapContext &bootstrapper, ostream &output,
                     Decryptor &decryptor, CKKSEncoder &encoder, PoseidonContext &context,
                     size_t stage)
{
    if (!bootstrapper.evaluator || !bootstrapper.encoder || !bootstrapper.relin_keys ||
        !bootstrapper.galois_keys || !bootstrapper.bootstrap_poly)
    {
        throw std::invalid_argument("poseidon bootstrap context is incomplete");
    }

    print_stage_banner("bootstrapping...", output);
    log_labeled_tensor_state("bootstrap input state", cnn_in, context, output);
    Ciphertext result = cnn_in.cipher();
    const auto time_start = chrono::high_resolution_clock::now();
    bootstrapper.evaluator->bootstrap(result, result, *bootstrapper.relin_keys,
                                      *bootstrapper.galois_keys, *bootstrapper.encoder,
                                      *bootstrapper.bootstrap_poly);
    const auto time_end = chrono::high_resolution_clock::now();

    cnn_out = TensorCipher(cnn_in.logn(), cnn_in.k(), cnn_in.h(), cnn_in.w(), cnn_in.c(),
                           cnn_in.t(), cnn_in.p(), result);

    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    output << "bootstrapping " << stage << " finished" << '\n';
    log_labeled_tensor_state("bootstrap output state", cnn_out, context, output);
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void cipher_add_seal_print(const TensorCipher &cnn1, const TensorCipher &cnn2,
                           TensorCipher &destination, EvaluatorCkksBase &evaluator,
                           ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                           PoseidonContext &context)
{
    print_stage_banner("cipher add...", output);
    cnn_add_seal(cnn1, cnn2, destination, evaluator);
    log_after_stage(destination, decryptor, encoder, context, output);
}

void multiplexed_parallel_downsampling_seal_print(const TensorCipher &cnn_in,
                                                  TensorCipher &cnn_out,
                                                  EvaluatorCkksBase &evaluator,
                                                  Decryptor &decryptor, CKKSEncoder &encoder,
                                                  PoseidonContext &context,
                                                  GaloisKeys &gal_keys, ostream &output)
{
    print_stage_banner("multiplexed parallel downsampling...", output);
    const auto time_start = chrono::high_resolution_clock::now();
    multiplexed_parallel_downsampling_seal(cnn_in, cnn_out, evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void averagepooling_seal_scale_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                     EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys, double B,
                                     ostream &output, Decryptor &decryptor,
                                     CKKSEncoder &encoder, PoseidonContext &context)
{
    print_stage_banner("average pooling...", output);
    const auto time_start = chrono::high_resolution_clock::now();
    averagepooling_seal_scale(cnn_in, cnn_out, evaluator, gal_keys, B, encoder, decryptor,
                              output);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void fully_connected_seal_print(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                vector<double> matrix, vector<double> bias, int q, int r,
                                EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                ostream &output, Decryptor &decryptor, CKKSEncoder &encoder,
                                PoseidonContext &context)
{
    print_stage_banner("fully connected layer...", output);
    const auto time_start = chrono::high_resolution_clock::now();
    matrix_multiplication_seal(cnn_in, cnn_out, std::move(matrix), std::move(bias), q, r,
                               evaluator, gal_keys, encoder);
    const auto time_end = chrono::high_resolution_clock::now();
    output << "time : "
           << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
           << " ms" << '\n';
    log_after_stage(cnn_out, decryptor, encoder, context, output);
}

void multiplexed_parallel_convolution_seal(
    const TensorCipher &cnn_in, TensorCipher &cnn_out, int co, int st, int fh, int fw,
    const vector<double> &data, vector<double> running_var, vector<double> constant_weight,
    double epsilon, CKKSEncoder &encoder, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
    GaloisKeys &gal_keys, vector<Ciphertext> &cipher_pool, bool end)
{
    (void)encryptor;
    (void)cipher_pool;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();
    int ko = 0;
    int ho = 0;
    int wo = 0;

    if (st != 1 && st != 2)
    {
        throw std::invalid_argument("supported st is only 1 or 2");
    }
    if (static_cast<int>(data.size()) != fh * fw * ci * co)
    {
        throw std::invalid_argument("the size of data vector is not fh*fw*ci*co");
    }
    if (log2_long(ki) == -1)
    {
        throw std::invalid_argument("ki is not power of two");
    }
    if (static_cast<int>(running_var.size()) != co ||
        static_cast<int>(constant_weight.size()) != co)
    {
        throw std::invalid_argument("running_var or constant_weight has invalid size");
    }

    if (st == 1)
    {
        ho = hi;
        wo = wi;
        ko = ki;
    }
    else
    {
        if (hi % 2 != 0 || wi % 2 != 0)
        {
            throw std::invalid_argument("hi and wi should be even when st == 2");
        }
        ho = hi / 2;
        wo = wi / 2;
        ko = 2 * ki;
    }

    const long n = static_cast<long>(slot_count_from_logn(logn));
    const int to = (co + ko * ko - 1) / (ko * ko);
    const int po = pow2(floor_to_int(log(static_cast<double>(n) /
                                         static_cast<double>(ko * ko * ho * wo * to)) /
                                     log(2.0)));
    const int q = (co + pi - 1) / pi;

    if (n % pi != 0 || n % po != 0)
    {
        throw std::out_of_range("slot count is not divisible by tensor packing factor");
    }
    if (ki * ki * hi * wi * ti * pi > n)
    {
        throw std::out_of_range("input tensor packing exceeds slot capacity");
    }
    if (ko * ko * ho * wo * to * po > n)
    {
        throw std::out_of_range("output tensor packing exceeds slot capacity");
    }

    vector<vector<vector<vector<double>>>> weight(
        fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(ci, vector<double>(co, 0.0))));
    vector<vector<vector<vector<double>>>> compact_weight_vec(
        fh, vector<vector<vector<double>>>(fw, vector<vector<double>>(q, vector<double>(n, 0.0))));
    vector<vector<double>> select_one_vec(co, vector<double>(n, 0.0));

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            for (int j3 = 0; j3 < ci; ++j3)
            {
                for (int j4 = 0; j4 < co; ++j4)
                {
                    weight[i1][i2][j3][j4] =
                        data[fh * fw * ci * j4 + fh * fw * j3 + fw * i1 + i2];
                }
            }
        }
    }

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            for (int i9 = 0; i9 < q; ++i9)
            {
                for (long j8 = 0; j8 < n; ++j8)
                {
                    const int j5 = ((j8 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi);
                    const int j6 = (j8 % (n / pi)) % (ki * wi);
                    const int i7 = (j8 % (n / pi)) / (ki * ki * hi * wi);
                    const int i8 = j8 / (n / pi);

                    if (j8 % (n / pi) >= ki * ki * hi * wi * ti || i8 + pi * i9 >= co ||
                        ki * ki * i7 + ki * (j5 % ki) + j6 % ki >= ci ||
                        (j6 / ki) - (fw - 1) / 2 + i2 < 0 ||
                        (j6 / ki) - (fw - 1) / 2 + i2 > wi - 1 ||
                        (j5 / ki) - (fh - 1) / 2 + i1 < 0 ||
                        (j5 / ki) - (fh - 1) / 2 + i1 > hi - 1)
                    {
                        compact_weight_vec[i1][i2][i9][j8] = 0.0;
                    }
                    else
                    {
                        compact_weight_vec[i1][i2][i9][j8] =
                            weight[i1][i2][ki * ki * i7 + ki * (j5 % ki) + j6 % ki][i8 + pi * i9];
                    }
                }
            }
        }
    }

    for (int j4 = 0; j4 < co; ++j4)
    {
        for (int v1 = 0; v1 < ko * ho; ++v1)
        {
            for (int v2 = 0; v2 < ko * wo; ++v2)
            {
                for (int u3 = 0; u3 < to; ++u3)
                {
                    const size_t idx = static_cast<size_t>(ko * ko * ho * wo * u3 + ko * wo * v1 + v2);
                    if (ko * ko * u3 + ko * (v1 % ko) + v2 % ko == j4)
                    {
                        select_one_vec[j4][idx] =
                            constant_weight[j4] / sqrt(running_var[j4] + epsilon);
                    }
                }
            }
        }
    }

    Ciphertext ctxt_in = cnn_in.cipher();
    vector<vector<Ciphertext>> ctxt_rot(fh, vector<Ciphertext>(fw, ctxt_in));
    if (fh % 2 == 0 || fw % 2 == 0)
    {
        throw std::invalid_argument("fh and fw should be odd");
    }

    for (int i1 = 0; i1 < fh; ++i1)
    {
        for (int i2 = 0; i2 < fw; ++i2)
        {
            ctxt_rot[i1][i2] = ctxt_in;
            memory_save_rotate(ctxt_rot[i1][i2], ctxt_rot[i1][i2],
                               ki * ki * wi * (i1 - (fh - 1) / 2) + ki * (i2 - (fw - 1) / 2),
                               evaluator, gal_keys);
        }
    }

    Ciphertext total_sum;
    bool has_total_sum = false;
    for (int i9 = 0; i9 < q; ++i9)
    {
        Ciphertext sum;
        bool has_sum = false;
        for (int i1 = 0; i1 < fh; ++i1)
        {
            for (int i2 = 0; i2 < fw; ++i2)
            {
                Ciphertext temp;
                multiply_by_vector(ctxt_rot[i1][i2], compact_weight_vec[i1][i2][i9], temp, encoder,
                                   evaluator);
                if (!has_sum)
                {
                    sum = temp;
                    has_sum = true;
                }
                else
                {
                    add_assign_dynamic(sum, temp, encoder, evaluator);
                }
            }
        }

        Ciphertext var = sum;
        const int d = log2_long(ki);
        const int c = log2_long(ti);

        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x), evaluator, gal_keys);
            add_assign_dynamic(var, temp, encoder, evaluator);
        }
        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x) * ki * wi, evaluator, gal_keys);
            add_assign_dynamic(var, temp, encoder, evaluator);
        }

        if (c == -1)
        {
            Ciphertext grouped;
            bool has_grouped = false;
            for (int x = 0; x < ti; ++x)
            {
                Ciphertext temp = var;
                memory_save_rotate(temp, temp, ki * ki * hi * wi * x, evaluator, gal_keys);
                if (!has_grouped)
                {
                    grouped = temp;
                    has_grouped = true;
                }
                else
                {
                    add_assign_dynamic(grouped, temp, encoder, evaluator);
                }
            }
            var = grouped;
        }
        else
        {
            for (int x = 0; x < c; ++x)
            {
                Ciphertext temp = var;
                memory_save_rotate(temp, temp, pow2(x) * ki * ki * hi * wi, evaluator, gal_keys);
                add_assign_dynamic(var, temp, encoder, evaluator);
            }
        }

        for (int i8 = 0; i8 < pi && pi * i9 + i8 < co; ++i8)
        {
            const int j4 = pi * i9 + i8;
            Ciphertext temp = var;
            memory_save_rotate(temp, temp,
                               (n / pi) * (j4 % pi) - j4 % ko - (j4 / (ko * ko)) * ko * ko * ho * wo -
                                   ((j4 % (ko * ko)) / ko) * ko * wo,
                               evaluator, gal_keys);
            multiply_by_vector_inplace(temp, select_one_vec[j4], encoder, evaluator);
            if (!has_total_sum)
            {
                total_sum = temp;
                has_total_sum = true;
            }
            else
            {
                add_assign_dynamic(total_sum, temp, encoder, evaluator);
            }
        }
    }

    Ciphertext var = total_sum;
    if (!end)
    {
        Ciphertext sum = var;
        for (int u6 = 1; u6 < po; ++u6)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, -u6 * (n / po), evaluator, gal_keys);
            add_assign_dynamic(sum, temp, encoder, evaluator);
        }
        var = sum;
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, var);
}

void multiplexed_parallel_batch_norm_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                          vector<double> bias, vector<double> running_mean,
                                          vector<double> running_var, vector<double> weight,
                                          double epsilon, CKKSEncoder &encoder,
                                          Encryptor &encryptor, EvaluatorCkksBase &evaluator,
                                          double B, bool end)
{
    (void)encryptor;
    (void)end;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();
    const int ko = ki;
    const int ho = hi;
    const int wo = wi;
    const int co = ci;
    const int to = ti;
    const int po = pi;

    if (static_cast<int>(bias.size()) != ci || static_cast<int>(running_mean.size()) != ci ||
        static_cast<int>(running_var.size()) != ci || static_cast<int>(weight.size()) != ci)
    {
        throw std::invalid_argument("batch norm vectors have invalid size");
    }

    const long n = static_cast<long>(slot_count_from_logn(logn));
    vector<double> g(static_cast<size_t>(n), 0.0);

    if (n % pi != 0)
    {
        throw std::out_of_range("slot count is not divisible by pi");
    }

    for (int v4 = 0; v4 < n; ++v4)
    {
        const int v1 = ((v4 % (n / pi)) % (ki * ki * hi * wi)) / (ki * wi);
        const int v2 = (v4 % (n / pi)) % (ki * wi);
        const int u3 = (v4 % (n / pi)) / (ki * ki * hi * wi);
        if (ki * ki * u3 + ki * (v1 % ki) + v2 % ki >= ci || v4 % (n / pi) >= ki * ki * hi * wi * ti)
        {
            g[v4] = 0.0;
        }
        else
        {
            const int idx = ki * ki * u3 + ki * (v1 % ki) + v2 % ki;
            g[v4] = (bias[idx] -
                     running_mean[idx] * weight[idx] / sqrt(running_var[idx] + epsilon)) /
                    B;
        }
    }

    Plaintext plain;
    encoder.encode(g, cnn_in.cipher().parms_id(), cnn_in.cipher().scale(), plain);
    Ciphertext temp;
    evaluator.add_plain(cnn_in.cipher(), plain, temp);

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, temp);
}

void ReLU_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no, vector<int> deg,
               long alpha, vector<Tree> &tree, double scaled_val, long scalingfactor,
               Encryptor &encryptor, EvaluatorCkksBase &evaluator, Decryptor &decryptor,
               CKKSEncoder &encoder, PublicKey &public_key, SecretKey &secret_key,
               RelinKeys &relin_keys, double scale)
{
    (void)comp_no;
    (void)deg;
    (void)alpha;
    (void)tree;
    (void)scaled_val;
    (void)scalingfactor;
    (void)encryptor;
    (void)decryptor;
    (void)public_key;
    (void)secret_key;

    relu_impl(cnn_in, cnn_out, comp_no, deg, alpha, scaled_val, evaluator, encoder, relin_keys,
              scale, nullptr, nullptr);
}

void cnn_add_seal(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination,
                  EvaluatorCkksBase &evaluator)
{
    if (cnn1.k() != cnn2.k() || cnn1.h() != cnn2.h() || cnn1.w() != cnn2.w() ||
        cnn1.c() != cnn2.c() || cnn1.t() != cnn2.t() || cnn1.p() != cnn2.p() ||
        cnn1.logn() != cnn2.logn())
    {
        throw std::invalid_argument("the parameters of cnn1 and cnn2 are not the same");
    }

    Ciphertext temp;
    evaluator.add(cnn1.cipher(), cnn2.cipher(), temp);
    destination = TensorCipher(cnn1.logn(), cnn1.k(), cnn1.h(), cnn1.w(), cnn1.c(), cnn1.t(),
                               cnn1.p(), temp);
}

void multiplexed_parallel_downsampling_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                            EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                            CKKSEncoder &encoder)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int logn = cnn_in.logn();

    const long n = static_cast<long>(slot_count_from_logn(logn));
    const int ko = 2 * ki;
    const int ho = hi / 2;
    const int wo = wi / 2;
    const int to = ti / 2;
    const int co = 2 * ci;
    const int po =
        pow2(floor_to_int(log(static_cast<double>(n) / static_cast<double>(ko * ko * ho * wo * to)) /
                          log(2.0)));

    if (ti % 8 != 0 || hi % 2 != 0 || wi % 2 != 0)
    {
        throw std::invalid_argument("input tensor shape is not valid for packed downsampling");
    }
    if (n % po != 0)
    {
        throw std::out_of_range("slot count is not divisible by po");
    }

    vector<vector<vector<double>>> select_one_vec(
        ki, vector<vector<double>>(ti, vector<double>(n, 0.0)));
    for (int w1 = 0; w1 < ki; ++w1)
    {
        for (int w2 = 0; w2 < ti; ++w2)
        {
            for (int v4 = 0; v4 < n; ++v4)
            {
                const int j5 = (v4 % (ki * ki * hi * wi)) / (ki * wi);
                const int j6 = v4 % (ki * wi);
                const int i7 = v4 / (ki * ki * hi * wi);
                if (v4 < ki * ki * hi * wi * ti && (j5 / ki) % 2 == 0 && (j6 / ki) % 2 == 0 &&
                    (j5 % ki) == w1 && i7 == w2)
                {
                    select_one_vec[w1][w2][v4] = 1.0;
                }
            }
        }
    }

    Ciphertext ct = cnn_in.cipher();
    Ciphertext sum;
    bool has_sum = false;
    for (int w1 = 0; w1 < ki; ++w1)
    {
        for (int w2 = 0; w2 < ti; ++w2)
        {
            Ciphertext temp = ct;
            multiply_by_vector_inplace(temp, select_one_vec[w1][w2], encoder, evaluator);

            const int w3 = ((ki * w2 + w1) % (2 * ko)) / 2;
            const int w4 = (ki * w2 + w1) % 2;
            const int w5 = (ki * w2 + w1) / (2 * ko);
            memory_save_rotate(temp, temp,
                               ki * ki * hi * wi * w2 + ki * wi * w1 - ko * ko * ho * wo * w5 -
                                   ko * wo * w3 - ki * w4 - ko * ko * ho * wo * (ti / 8),
                               evaluator, gal_keys);

            if (!has_sum)
            {
                sum = temp;
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, temp, encoder, evaluator);
            }
        }
    }
    ct = sum;

    sum = ct;
    for (int u6 = 1; u6 < po; ++u6)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, -(n / po) * u6, evaluator, gal_keys);
        add_assign_dynamic(sum, temp, encoder, evaluator);
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, sum);
}

void averagepooling_seal_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                               EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys, double B,
                               CKKSEncoder &encoder, Decryptor &decryptor, ostream &output)
{
    (void)decryptor;
    (void)output;

    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int logn = cnn_in.logn();

    if (log2_long(hi) == -1 || log2_long(wi) == -1)
    {
        throw std::invalid_argument("hi and wi should be powers of two");
    }

    Ciphertext ct = cnn_in.cipher();
    for (int x = 0; x < log2_long(wi); ++x)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, pow2(x) * ki, evaluator, gal_keys);
        add_assign_dynamic(ct, temp, encoder, evaluator);
    }
    for (int x = 0; x < log2_long(hi); ++x)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, pow2(x) * ki * ki * wi, evaluator, gal_keys);
        add_assign_dynamic(ct, temp, encoder, evaluator);
    }

    const size_t n = slot_count_from_logn(logn);
    vector<double> select_one(n, 0.0);
    vector<double> zero(n, 0.0);
    Ciphertext sum;
    bool has_sum = false;

    for (int s = 0; s < ki; ++s)
    {
        for (int u = 0; u < ti; ++u)
        {
            const int p = ki * u + s;
            Ciphertext temp = ct;
            memory_save_rotate(temp, temp, -p * ki + ki * ki * hi * wi * u + ki * wi * s,
                               evaluator, gal_keys);
            select_one = zero;
            for (int i = 0; i < ki; ++i)
            {
                select_one[static_cast<size_t>((ki * u + s) * ki + i)] =
                    B / static_cast<double>(hi * wi);
            }

            multiply_by_vector_inplace(temp, select_one, encoder, evaluator);
            if (!has_sum)
            {
                sum = temp;
                has_sum = true;
            }
            else
            {
                add_assign_dynamic(sum, temp, encoder, evaluator);
            }
        }
    }

    cnn_out = TensorCipher(logn, 1, 1, 1, ci, ti, 1, sum);
}

void matrix_multiplication_seal(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                                vector<double> matrix, vector<double> bias, int q, int r,
                                EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys,
                                CKKSEncoder &encoder)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    if (static_cast<int>(matrix.size()) != q * r)
    {
        throw std::invalid_argument("the size of matrix is not q*r");
    }
    if (static_cast<int>(bias.size()) != q)
    {
        throw std::invalid_argument("the size of bias is not q");
    }

    const size_t n = slot_count_from_logn(logn);
    vector<vector<double>> W(q + r - 1, vector<double>(n, 0.0));
    vector<double> b(n, 0.0);

    for (int z = 0; z < q; ++z)
    {
        b[z] = bias[z];
    }
    for (int i = 0; i < q; ++i)
    {
        for (int j = 0; j < r; ++j)
        {
            W[i - j + r - 1][i] = matrix[i * r + j];
        }
    }

    Ciphertext ct = cnn_in.cipher();
    Ciphertext sum;
    bool has_sum = false;
    for (int s = 0; s < q + r - 1; ++s)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, r - 1 - s, evaluator, gal_keys);
        multiply_by_vector_inplace(temp, W[s], encoder, evaluator);
        if (!has_sum)
        {
            sum = temp;
            has_sum = true;
        }
        else
        {
            add_assign_dynamic(sum, temp, encoder, evaluator);
        }
    }

    Plaintext bias_plain;
    encoder.encode(b, sum.parms_id(), sum.scale(), bias_plain);
    evaluator.add_plain(sum, bias_plain, sum);

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, sum);
}

void memory_save_rotate(const Ciphertext &cipher_in, Ciphertext &cipher_out, int steps,
                        EvaluatorCkksBase &evaluator, GaloisKeys &gal_keys)
{
    const long n = static_cast<long>(cipher_in.poly_modulus_degree() / 2);
    Ciphertext temp = cipher_in;
    steps = (steps % n + n) % n;
    int first_step = 0;

    if (34 <= steps && steps <= 55)
    {
        first_step = 33;
    }
    else if (57 <= steps && steps <= 61)
    {
        first_step = 33;
    }

    if (steps == 0)
    {
        cipher_out = temp;
        return;
    }

    if (first_step == 0)
    {
        evaluator.rotate(temp, cipher_out, steps, gal_keys);
    }
    else
    {
        evaluator.rotate(temp, temp, first_step, gal_keys);
        evaluator.rotate(temp, cipher_out, steps - first_step, gal_keys);
    }
}

void cipher_add_print(const TensorCipher &lhs, const TensorCipher &rhs, TensorCipher &output,
                      EvaluatorCkksBase &evaluator, const PoseidonContext &context, ostream &log)
{
    cnn_add_seal(lhs, rhs, output, evaluator);
    log_cipher_state(output, context, log);
}
