#include "encrypted_ops.h"

#include "poseidon/plaintext.h"

#include <cmath>
#include <complex>
#include <stdexcept>
#include <vector>

using namespace std;
using namespace poseidon;

namespace
{

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

size_t ceil_to_int(double value)
{
    return static_cast<size_t>(ceil(value) + 0.5);
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

void add_lazy_cipher(Ciphertext &accumulator, const Ciphertext &term, EvaluatorCkksBase &evaluator,
                     CKKSEncoder &encoder)
{
    auto same_level_with_same_scale = [&](const Ciphertext &lhs, const Ciphertext &rhs) {
        return lhs.parms_id() == rhs.parms_id() &&
               poseidon::util::are_approximate<double>(lhs.scale(), rhs.scale());
    };

    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error add");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    if (accumulator.coeff_modulus_size() <= term.coeff_modulus_size())
    {
        Ciphertext rhs = (accumulator.coeff_modulus_size() == term.coeff_modulus_size())
                             ? preserve_value_scale_same_level(term, accumulator.scale())
                             : preserve_value_rescale_to(term, accumulator);
        if (!same_level_with_same_scale(accumulator, rhs))
        {
            evaluator.add_dynamic(accumulator, rhs, accumulator, encoder);
            return;
        }
        evaluator.add(accumulator, rhs, accumulator);
        return;
    }

    Ciphertext lhs = preserve_value_rescale_to(accumulator, term);
    if (!same_level_with_same_scale(lhs, term))
    {
        evaluator.add_dynamic(lhs, term, accumulator, encoder);
        return;
    }
    evaluator.add(lhs, term, accumulator);
}

void sub_lazy_cipher(const Ciphertext &lhs, const Ciphertext &rhs, Ciphertext &result,
                     EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    auto same_level_with_same_scale = [&](const Ciphertext &a, const Ciphertext &b) {
        return a.parms_id() == b.parms_id() &&
               poseidon::util::are_approximate<double>(a.scale(), b.scale());
    };

    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error sub");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    if (lhs.coeff_modulus_size() <= rhs.coeff_modulus_size())
    {
        Ciphertext rhs_aligned = (lhs.coeff_modulus_size() == rhs.coeff_modulus_size())
                                     ? preserve_value_scale_same_level(rhs, lhs.scale())
                                     : preserve_value_rescale_to(rhs, lhs);
        if (!same_level_with_same_scale(lhs, rhs_aligned))
        {
            evaluator.sub_dynamic(lhs, rhs_aligned, result, encoder);
            return;
        }
        evaluator.sub(lhs, rhs_aligned, result);
        return;
    }

    Ciphertext lhs_aligned = preserve_value_rescale_to(lhs, rhs);
    if (!same_level_with_same_scale(lhs_aligned, rhs))
    {
        evaluator.sub_dynamic(lhs_aligned, rhs, result, encoder);
        return;
    }
    evaluator.sub(lhs_aligned, rhs, result);
}

void multiply_reduced_cipher(const Ciphertext &lhs, const Ciphertext &rhs, Ciphertext &result,
                             EvaluatorCkksBase &evaluator, const RelinKeys &relin_keys,
                             CKKSEncoder &encoder)
{
    auto preserve_value_scale_same_level = [&](const Ciphertext &source, double target_scale) {
        if (poseidon::util::are_approximate<double>(source.scale(), target_scale))
        {
            return source;
        }
        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, target_scale / source.scale(), adjusted, encoder);
        return adjusted;
    };

    auto preserve_value_rescale_to = [&](const Ciphertext &source, const Ciphertext &target) {
        auto context_data = encoder.context().crt_context()->get_context_data(source.parms_id());
        if (!context_data)
        {
            throw runtime_error("failed to get source context data for reduced-error multiply");
        }
        const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
        const double plain_scale = target.scale() * q_last / source.scale();

        Ciphertext adjusted;
        evaluator.multiply_const(source, 1.0, plain_scale, adjusted, encoder);
        evaluator.rescale(adjusted, adjusted);
        if (adjusted.parms_id() != target.parms_id())
        {
            evaluator.drop_modulus(adjusted, adjusted, target.parms_id());
        }
        if (!poseidon::util::are_approximate<double>(adjusted.scale(), target.scale()))
        {
            adjusted = preserve_value_scale_same_level(adjusted, target.scale());
        }
        return adjusted;
    };

    Ciphertext lhs_aligned = lhs;
    Ciphertext rhs_aligned = rhs;

    if (lhs.coeff_modulus_size() < rhs.coeff_modulus_size())
    {
        rhs_aligned = preserve_value_rescale_to(rhs, lhs);
    }
    else if (lhs.coeff_modulus_size() > rhs.coeff_modulus_size())
    {
        lhs_aligned = preserve_value_rescale_to(lhs, rhs);
    }

    if (!poseidon::util::are_approximate<double>(lhs_aligned.scale(), rhs_aligned.scale()))
    {
        rhs_aligned = preserve_value_scale_same_level(rhs_aligned, lhs_aligned.scale());
    }

    evaluator.multiply_relin_dynamic(lhs_aligned, rhs_aligned, result, relin_keys);
}

Ciphertext zero_cipher_for_lazy_sum(size_t slot_count, double scale, Encryptor &encryptor,
                                    CKKSEncoder &encoder)
{
    vector<complex<double>> zeros(slot_count, complex<double>(0.0, 0.0));
    Plaintext plain;
    encoder.encode(zeros, scale * scale, plain);
    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    return cipher;
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

} // namespace

void relu(const TensorCipher &cnn_in, TensorCipher &cnn_out, long comp_no,
          const vector<int> &deg, long alpha, const vector<Tree> &tree, double scaled_val,
          Encryptor &encryptor, EvaluatorCkksBase &evaluator, CKKSEncoder &encoder,
          RelinKeys &relin_keys, double scale)
{
    const int ki = cnn_in.k();
    const int hi = cnn_in.h();
    const int wi = cnn_in.w();
    const int ci = cnn_in.c();
    const int ti = cnn_in.t();
    const int pi = cnn_in.p();
    const int logn = cnn_in.logn();

    if (comp_no != static_cast<long>(deg.size()) || deg.size() != tree.size())
    {
        throw invalid_argument("relu polynomial component count does not match degree/tree config");
    }

    Ciphertext mask = approximate_sign(cnn_in.cipher(), deg, alpha, tree, scaled_val, encryptor,
                                       encoder, evaluator, relin_keys);

    Ciphertext relu_cipher;
    evaluator.multiply_relin_dynamic(cnn_in.cipher(), mask, relu_cipher, relin_keys);

    evaluator.rescale(relu_cipher, relu_cipher);
    assign_scale_for_relu_reference(relu_cipher, scale);

    cnn_out = TensorCipher(logn, ki, hi, wi, ci, ti, pi, relu_cipher);
}

void bootstrap_tensor(const TensorCipher &cnn_in, TensorCipher &cnn_out,
                      PoseidonBootstrapContext &bootstrapper, CKKSEncoder &encoder)
{
    (void)encoder;
    if (!bootstrapper.evaluator || !bootstrapper.encoder || !bootstrapper.relin_keys ||
        !bootstrapper.galois_keys || !bootstrapper.config)
    {
        throw std::invalid_argument("poseidon bootstrap context is incomplete");
    }

    Ciphertext result;
    bootstrapper.evaluator->bootstrap(
        cnn_in.cipher(), result, *bootstrapper.relin_keys, *bootstrapper.galois_keys,
        *bootstrapper.encoder, *bootstrapper.config);

    cnn_out = TensorCipher(cnn_in.logn(), cnn_in.k(), cnn_in.h(), cnn_in.w(), cnn_in.c(),
                           cnn_in.t(), cnn_in.p(), result);
}

void multiplexed_convolution(
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

    Ciphertext total_sum_high_scale;
    for (int i9 = 0; i9 < q; ++i9)
    {
        // All kernel terms have the same parms_id and scale. Accumulate them
        // before rescaling so a q-group pays for one rescale instead of one
        // rescale per kernel position.
        Ciphertext kernel_sum_high_scale;
        for (int i1 = 0; i1 < fh; ++i1)
        {
            for (int i2 = 0; i2 < fw; ++i2)
            {
                Plaintext kernel_plain;
                encoder.encode(compact_weight_vec[i1][i2][i9],
                               ctxt_rot[i1][i2].parms_id(),
                               multiply_plain_scale(ctxt_rot[i1][i2], encoder),
                               kernel_plain);
                evaluator.multiply_plain_accumulate(
                    ctxt_rot[i1][i2], kernel_plain, kernel_sum_high_scale);
            }
        }
        if (!kernel_sum_high_scale.is_valid())
        {
            throw runtime_error("multiplexed convolution kernel accumulation produced no terms");
        }

        Ciphertext sum;
        evaluator.rescale_dynamic(kernel_sum_high_scale, sum, ctxt_in.scale());

        Ciphertext var = sum;
        const int d = log2_long(ki);
        const int c = log2_long(ti);

        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x), evaluator, gal_keys);
            evaluator.add(var, temp, var);
        }
        for (int x = 0; x < d; ++x)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, pow2(x) * ki * wi, evaluator, gal_keys);
            evaluator.add(var, temp, var);
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
                    evaluator.add(grouped, temp, grouped);
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
                evaluator.add(var, temp, var);
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
            Plaintext select_plain;
            encoder.encode(select_one_vec[j4], temp.parms_id(),
                           multiply_plain_scale(temp, encoder), select_plain);
            // Output placement and folded BN scaling are also linear. Keep
            // every output channel at high scale, then rescale the complete
            // output once instead of rescaling each channel independently.
            evaluator.multiply_plain_accumulate(
                temp, select_plain, total_sum_high_scale);
        }
    }

    if (!total_sum_high_scale.is_valid())
    {
        throw runtime_error("multiplexed convolution output accumulation produced no terms");
    }
    Ciphertext var;
    evaluator.rescale_dynamic(total_sum_high_scale, var, ctxt_in.scale());
    if (!end)
    {
        Ciphertext sum = var;
        for (int u6 = 1; u6 < po; ++u6)
        {
            Ciphertext temp = var;
            memory_save_rotate(temp, temp, -u6 * (n / po), evaluator, gal_keys);
            evaluator.add(sum, temp, sum);
        }
        var = sum;
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, var);
}

void multiplexed_batch_norm(const TensorCipher &cnn_in, TensorCipher &cnn_out,
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

void cnn_add(const TensorCipher &cnn1, const TensorCipher &cnn2, TensorCipher &destination,
                  EvaluatorCkksBase &evaluator, CKKSEncoder &encoder)
{
    if (cnn1.k() != cnn2.k() || cnn1.h() != cnn2.h() || cnn1.w() != cnn2.w() ||
        cnn1.c() != cnn2.c() || cnn1.t() != cnn2.t() || cnn1.p() != cnn2.p() ||
        cnn1.logn() != cnn2.logn())
    {
        throw std::invalid_argument("the parameters of cnn1 and cnn2 are not the same");
    }

    Ciphertext temp = cnn1.cipher();
    add_lazy_cipher(temp, cnn2.cipher(), evaluator, encoder);
    destination = TensorCipher(cnn1.logn(), cnn1.k(), cnn1.h(), cnn1.w(), cnn1.c(), cnn1.t(),
                               cnn1.p(), temp);
}

void multiplexed_downsampling(const TensorCipher &cnn_in, TensorCipher &cnn_out,
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
    Ciphertext sum_high_scale;
    bool has_sum = false;
    for (int w1 = 0; w1 < ki; ++w1)
    {
        for (int w2 = 0; w2 < ti; ++w2)
        {
            Plaintext select_plain;
            encoder.encode(select_one_vec[w1][w2], ct.parms_id(),
                           multiply_plain_scale(ct, encoder), select_plain);
            Ciphertext temp;
            evaluator.multiply_plain(ct, select_plain, temp);

            const int w3 = ((ki * w2 + w1) % (2 * ko)) / 2;
            const int w4 = (ki * w2 + w1) % 2;
            const int w5 = (ki * w2 + w1) / (2 * ko);
            memory_save_rotate(temp, temp,
                               ki * ki * hi * wi * w2 + ki * wi * w1 - ko * ko * ho * wo * w5 -
                                   ko * wo * w3 - ki * w4 - ko * ko * ho * wo * (ti / 8),
                               evaluator, gal_keys);

            if (!has_sum)
            {
                sum_high_scale = std::move(temp);
                has_sum = true;
            }
            else
            {
                evaluator.add(sum_high_scale, temp, sum_high_scale);
            }
        }
    }
    if (!has_sum)
    {
        throw runtime_error("multiplexed downsampling produced no encrypted terms");
    }
    evaluator.rescale_dynamic(sum_high_scale, ct, cnn_in.cipher().scale());

    Ciphertext sum = ct;
    for (int u6 = 1; u6 < po; ++u6)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, -(n / po) * u6, evaluator, gal_keys);
        evaluator.add(sum, temp, sum);
    }

    cnn_out = TensorCipher(logn, ko, ho, wo, co, to, po, sum);
}

void averagepooling_scale(const TensorCipher &cnn_in, TensorCipher &cnn_out,
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
        evaluator.add(ct, temp, ct);
    }
    for (int x = 0; x < log2_long(hi); ++x)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, pow2(x) * ki * ki * wi, evaluator, gal_keys);
        evaluator.add(ct, temp, ct);
    }

    const size_t n = slot_count_from_logn(logn);
    vector<double> select_one(n, 0.0);
    vector<double> zero(n, 0.0);
    Ciphertext sum_high_scale;

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

            Plaintext select_plain;
            encoder.encode(select_one, temp.parms_id(),
                           multiply_plain_scale(temp, encoder), select_plain);
            evaluator.multiply_plain_accumulate(temp, select_plain, sum_high_scale);
        }
    }

    if (!sum_high_scale.is_valid())
    {
        throw runtime_error("average pool produced no encrypted terms");
    }
    Ciphertext sum;
    evaluator.rescale_dynamic(sum_high_scale, sum, cnn_in.cipher().scale());

    cnn_out = TensorCipher(logn, 1, 1, 1, ci, ti, 1, sum);
}

void matrix_multiplication(const TensorCipher &cnn_in, TensorCipher &cnn_out,
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
    Ciphertext sum_high_scale;
    for (int s = 0; s < q + r - 1; ++s)
    {
        Ciphertext temp = ct;
        memory_save_rotate(temp, temp, r - 1 - s, evaluator, gal_keys);
        Plaintext diagonal_plain;
        encoder.encode(W[s], temp.parms_id(), multiply_plain_scale(temp, encoder),
                       diagonal_plain);
        evaluator.multiply_plain_accumulate(temp, diagonal_plain, sum_high_scale);
    }
    if (!sum_high_scale.is_valid())
    {
        throw runtime_error("fully connected layer produced no encrypted terms");
    }
    Ciphertext sum;
    evaluator.rescale_dynamic(sum_high_scale, sum, ct.scale());

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
