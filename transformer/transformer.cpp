#include <bits/stdc++.h>
#include <fstream>
#include <iostream>
#include "poseidon/src/ckks_encoder.h"
#include "poseidon/src/decryptor.h"
#include "poseidon/src/encryptor.h"
#include "poseidon/src/evaluator/software/evaluator_ckks_software.h"
#include "poseidon/src/factory/poseidon_factory.h"
#include "poseidon/src/keygenerator.h"
#include "poseidon/src/plaintext.h"
#include "poseidon/src/poseidon_context.h"
#include "poseidon/src/rns_poly.h"
#include "poseidon/src/util/debug.h"
#include "poseidon/src/util/precision.h"
#include "poseidon/src/util/random_sample.h"

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

const int m = 2, n = 3, k = 3;

void Exp(Ciphertext &input, Ciphertext &output, CKKSEncoder &ckks_encoder,
         shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    vector<complex<double>> buffer(8, 0);
    buffer[0] = 1.0;
    buffer[1] = 1.0;
    buffer[2] = 1.0 / 2;
    buffer[3] = 1.0 / 6;
    buffer[4] = 1.0 / 24;
    buffer[5] = 1.0 / 120;
    buffer[6] = 1.0 / 720;
    buffer[7] = 1.0 / 5040;

    Polynomial approxF(buffer, 0, 0, 8, Monomial);
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

    ckks_eva->evaluate_poly_vector(input, output, polys, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    return;
}

void P(Ciphertext &input, Ciphertext &output, CKKSEncoder &ckks_encoder,
       shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    vector<complex<double>> buffer(4, 0);
    buffer[0] = -0.5054031199708174;
    buffer[1] = -0.4222658115198386;
    buffer[2] = -0.1180761295118195;
    buffer[3] = -0.0110341340306157;

    Polynomial approxF(buffer, 0, 0, 4, Monomial);
    approxF.lead() = true;
    // auto approxG = util::Approximate(g, a, b, deg);
    vector<Polynomial> poly_v{approxF};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;  // Index with all even slots
    }

    slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v, slots_index);

    ckks_eva->evaluate_poly_vector(input, output, polys, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    return;
}

void Q(Ciphertext &input, Ciphertext &output, CKKSEncoder &ckks_encoder,
       shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    vector<complex<double>> buffer(8, 0);
    buffer[0] = 0.0085263215410380;
    buffer[1] = 0.5;
    buffer[2] = 0.3603292692789629;
    buffer[4] = -0.037688200365904;
    buffer[6] = 0.0018067462606141;

    Polynomial approxF(buffer, 0, 0, 8, Monomial);
    approxF.lead() = true;
    // auto approxG = util::Approximate(g, a, b, deg);
    vector<Polynomial> poly_v{approxF};
    vector<vector<int>> slots_index(1, vector<int>(context.parameters_literal()->degree() >> 1, 0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);

    for (int i = 0; i < context.parameters_literal()->degree() >> 1; i++)
    {
        idxF[i] = i;  // Index with all even slots
    }

    slots_index[0] = idxF;  // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v, slots_index);

    ckks_eva->evaluate_poly_vector(input, output, polys, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    return;
}

void Sgn1(Ciphertext &input, Ciphertext &output, PolynomialVector &polys1, PolynomialVector &polys2,
          PolynomialVector &polys3, CKKSEncoder &ckks_encoder, Encryptor &enc, Decryptor &dec,
          shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    Ciphertext tmp;
    ckks_eva->evaluate_poly_vector(input, tmp, polys1, input.scale(), relinKeys, ckks_encoder);
    Plaintext plain_ans;
    vector<complex<double>> ans(context.parameters_literal()->slot(), 0);
    dec.decrypt(tmp, plain_ans);
    ckks_encoder.decode(plain_ans, ans);
    cout << ans[0] << endl;
    cout << ans[1] << endl;
    ckks_eva->evaluate_poly_vector(tmp, tmp, polys2, tmp.scale(), relinKeys, ckks_encoder);

    dec.decrypt(tmp, plain_ans);
    ckks_encoder.decode(plain_ans, ans);
    cout << ans[0] << endl;
    cout << ans[1] << endl;

    ckks_eva->evaluate_poly_vector(tmp, output, polys3, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    return;
}

void Sgn(Ciphertext &input, Ciphertext &output, PolynomialVector &polys1, PolynomialVector &polys2,
         PolynomialVector &polys3, CKKSEncoder &ckks_encoder,
         shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    Ciphertext tmp;
    ckks_eva->evaluate_poly_vector(input, tmp, polys1, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    ckks_eva->evaluate_poly_vector(tmp, tmp, polys2, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    ckks_eva->evaluate_poly_vector(tmp, output, polys3, context.parameters_literal()->scale(),
                                   relinKeys, ckks_encoder);
    return;
}

void Gelu(Ciphertext &input, Ciphertext &output, PolynomialVector &polys1, PolynomialVector &polys2,
          PolynomialVector &polys3, CKKSEncoder &ckks_encoder,
          shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, PoseidonContext &context)
{
    Ciphertext s0, s1, s2;
    ckks_eva->add_const(input, 4.0, s0, ckks_encoder);
    Sgn(s0, s0, polys1, polys2, polys3, ckks_encoder, ckks_eva, relinKeys, context);
    ckks_eva->multiply_const(s0, 0.5, context.parameters_literal()->scale(), s0, ckks_encoder);
    ckks_eva->rescale_dynamic(s0, s0, context.parameters_literal()->scale());
    ckks_eva->add_const(input, 1.95, s1, ckks_encoder);
    Sgn(s1, s1, polys1, polys2, polys3, ckks_encoder, ckks_eva, relinKeys, context);
    ckks_eva->multiply_const(s1, 0.5, context.parameters_literal()->scale(), s1, ckks_encoder);
    ckks_eva->rescale_dynamic(s1, s1, context.parameters_literal()->scale());
    ckks_eva->add_const(input, -3.0, s2, ckks_encoder);
    Sgn(s2, s2, polys1, polys2, polys3, ckks_encoder, ckks_eva, relinKeys, context);
    ckks_eva->multiply_const(s2, 0.5, context.parameters_literal()->scale(), s2, ckks_encoder);
    ckks_eva->rescale_dynamic(s2, s2, context.parameters_literal()->scale());

    Ciphertext b1, b2, b3;
    ckks_eva->sub(s0, s1, b1);
    ckks_eva->sub(s1, s2, b2);
    ckks_eva->add_const(s2, 0.5, b3, ckks_encoder);

    Ciphertext tmp1, tmp2;
    ckks_eva->multiply_relin(b3, input, output, relinKeys);
    ckks_eva->rescale_dynamic(output, output, context.parameters_literal()->scale());
    P(input, tmp1, ckks_encoder, ckks_eva, relinKeys, context);
    ckks_eva->multiply_relin(b1, tmp1, tmp1, relinKeys);
    ckks_eva->rescale_dynamic(tmp1, tmp1, context.parameters_literal()->scale());
    ckks_eva->add(output, tmp1, output);
    Q(input, tmp2, ckks_encoder, ckks_eva, relinKeys, context);
    ckks_eva->multiply_relin(b2, tmp2, tmp2, relinKeys);
    ckks_eva->rescale_dynamic(tmp2, tmp2, context.parameters_literal()->scale());
    ckks_eva->add(output, tmp2, output);

    return;
}

void Quickmax(Ciphertext &input, Ciphertext &output, int n, PolynomialVector &polys1,
              PolynomialVector &polys2, PolynomialVector &polys3, CKKSEncoder &ckks_encoder,
              Encryptor &enc, Decryptor &dec, shared_ptr<EvaluatorCkksBase> &ckks_eva,
              RelinKeys &relinKeys, GaloisKeys &rotKeys, PoseidonContext &context,
              bool if_norm = true)
{
    Ciphertext tmp;
    ckks_eva->rotate(input, tmp, n, rotKeys);
    ckks_eva->add(tmp, input, output);
    for (int i = 0; i < floor(log2(n)); ++i)
    {
        Ciphertext s, a_minus_s, tmp;
        ckks_eva->rotate(output, s, -(1 << i), rotKeys);
        ckks_eva->sub(output, s, a_minus_s);

        Sgn1(a_minus_s, tmp, polys1, polys2, polys3, ckks_encoder, enc, dec, ckks_eva, relinKeys,
             context);
        ckks_eva->multiply_const(tmp, 0.5, context.parameters_literal()->scale(), tmp,
                                 ckks_encoder);
        ckks_eva->rescale_dynamic(tmp, tmp, context.parameters_literal()->scale());

        Plaintext plain_tmp;
        vector<complex<double>> vec_tmp(context.parameters_literal()->slot(), 0);
        dec.decrypt(tmp, plain_tmp);
        ckks_encoder.decode(plain_tmp, vec_tmp);
        ckks_encoder.encode(vec_tmp, context.parameters_literal()->scale(), plain_tmp);
        enc.encrypt(plain_tmp, tmp);

        ckks_eva->multiply_dynamic(tmp, a_minus_s, tmp);
        ckks_eva->rescale_dynamic(tmp, tmp, context.parameters_literal()->scale());
        ckks_eva->add(output, s, output);

        ckks_eva->multiply_const(output, 0.5, context.parameters_literal()->scale(), output,
                                 ckks_encoder);
        ckks_eva->rescale_dynamic(output, output, context.parameters_literal()->scale());

        // ckks_eva->add_dynamic(output, tmp, output, ckks_encoder);
        ckks_eva->add(output, tmp, output);

        dec.decrypt(output, plain_tmp);
        ckks_encoder.decode(plain_tmp, vec_tmp);
        ckks_encoder.encode(vec_tmp, context.parameters_literal()->scale(), plain_tmp);
        enc.encrypt(plain_tmp, output);
    }

    if (if_norm)
    {
        vector<complex<double>> one(context.parameters_literal()->slot(), 0);
        for (int i = 0; i < n; ++i)
            one[i] = 1;
        Plaintext plain_one;
        ckks_encoder.encode(one, output.scale(), plain_one);
        ckks_eva->multiply_plain(output, plain_one, output);
        ckks_eva->rescale_dynamic(output, output, context.parameters_literal()->scale());
    }
    return;
}

void Quicksum(Ciphertext &input, Ciphertext &output, int n, CKKSEncoder &ckks_encoder,
              shared_ptr<EvaluatorCkksBase> &ckks_eva, GaloisKeys &rotKeys,
              PoseidonContext &context, bool if_norm = false)
{
    Ciphertext tmp;
    ckks_eva->rotate(input, tmp, n, rotKeys);
    ckks_eva->add(tmp, input, output);
    for (int i = 0; i < floor(log2(n)); ++i)
    {
        Ciphertext tmp;
        ckks_eva->rotate(output, tmp, -(1 << i), rotKeys);
        ckks_eva->add(output, tmp, output);
    }
    if (if_norm)
    {
        vector<complex<double>> one(context.parameters_literal()->slot(), 0);
        for (int i = 0; i < n; ++i)
            one[i] = 1;
        Plaintext plain_one;
        ckks_encoder.encode(one, output.parms_id(), context.parameters_literal()->scale(),
                            plain_one);
        ckks_eva->multiply_plain(output, plain_one, output);
        ckks_eva->rescale_dynamic(output, output, context.parameters_literal()->scale());
    }
    return;
}

void Matmul_plain(vector<vector<Ciphertext>> &input, vector<Plaintext> &weight,
                  vector<Ciphertext> &output, int m, int n, int k,
                  shared_ptr<EvaluatorCkksBase> &ckks_eva, PoseidonContext &context)
{
    for (int i = 0; i < m; ++i)
    {
        ckks_eva->multiply_plain(input[i][0], weight[i], output[i]);
        Ciphertext tmp;
        for (int j = 1; j < n; ++j)
        {
            ckks_eva->multiply_plain(input[i][j], weight[i], tmp);
            ckks_eva->add(output[i], tmp, output[i]);
        }
        ckks_eva->rescale_dynamic(output[i], output[i], context.parameters_literal()->scale());
    }
    return;
}

void Matmul_plain2(vector<vector<Plaintext>> &weight, vector<Ciphertext> &input,
                   vector<Ciphertext> &output, int m, int n, int k,
                   shared_ptr<EvaluatorCkksBase> &ckks_eva, PoseidonContext &context)
{
    for (int i = 0; i < k; ++i)
    {
        ckks_eva->multiply_plain(input[i], weight[i][0], output[i]);
        Ciphertext tmp;
        for (int j = 1; j < n; ++j)
        {
            ckks_eva->multiply_plain(input[j], weight[i][j], tmp);
            ckks_eva->add(output[i], tmp, output[i]);
        }
        ckks_eva->rescale_dynamic(output[i], output[i], context.parameters_literal()->scale());
    }
    return;
}

void Matmul_plain3(vector<Ciphertext> &input, vector<Plaintext> &weight, vector<Plaintext> &bias,
                   vector<Ciphertext> &output, int m, int n, int k, CKKSEncoder &ckks_encoder,
                   shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys,
                   GaloisKeys &rotKeys, PoseidonContext &context)
{
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < k; ++j)
        {
            Ciphertext tmp;
            ckks_eva->multiply_plain(input[i], weight[j], tmp);
            ckks_eva->rescale_dynamic(tmp, tmp, context.parameters_literal()->scale());
            Quicksum(tmp, tmp, n, ckks_encoder, ckks_eva, rotKeys, context);
            vector<complex<double>> index(context.parameters_literal()->slot(), 0);
            index[j] = 1;
            Plaintext plain_index;
            ckks_encoder.encode(index, context.parameters_literal()->scale(), plain_index);
            ckks_eva->multiply_plain(tmp, plain_index, tmp);
            ckks_eva->add(output[i], tmp, output[i]);
        }
        ckks_eva->rescale_dynamic(output[i], output[i], context.parameters_literal()->scale());
        ckks_eva->add_plain(output[i], bias[i], output[i]);
    }
    return;
}

void Matmul_ciph(vector<Ciphertext> &input1, vector<Ciphertext> &input2, vector<Ciphertext> &output,
                 int m, int n, int k, CKKSEncoder &ckks_encoder,
                 shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, GaloisKeys &rotKeys,
                 PoseidonContext &context)
{
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < k; ++j)
        {
            Ciphertext tmp;
            ckks_eva->multiply_relin(input1[i], input2[j], tmp, relinKeys);
            ckks_eva->rescale_dynamic(tmp, tmp, context.parameters_literal()->scale());
            Quicksum(tmp, tmp, n, ckks_encoder, ckks_eva, rotKeys, context);
            vector<complex<double>> index(context.parameters_literal()->slot(), 0);
            index[j] = 1;
            Plaintext plain_index;
            ckks_encoder.encode(index, tmp.parms_id(), context.parameters_literal()->scale(),
                                plain_index);
            ckks_eva->multiply_plain(tmp, plain_index, tmp);
            if (0 == j)
                output[i] = tmp;
            else
                ckks_eva->add(output[i], tmp, output[i]);
        }
        ckks_eva->rescale_dynamic(output[i], output[i], context.parameters_literal()->scale());
    }
    return;
}

complex<double> get_initial_estimate(double value)
{
    if (value <= 1.0)
        return {1.0, 0.0};
    if (value >= 100.0)
        return {0.01, 0.0};

    std::vector<double> lookup_table_values = {1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0, 50.0, 100.0};
    std::vector<double> lookup_table_estimates = {1.0, 0.5,  0.333, 0.25, 0.2,
                                                  0.1, 0.05, 0.02,  0.01};

    for (size_t i = 1; i < lookup_table_values.size(); ++i)
    {
        if (value < lookup_table_values[i])
        {
            double t = (value - lookup_table_values[i - 1]) /
                       (lookup_table_values[i] - lookup_table_values[i - 1]);
            return lookup_table_estimates[i - 1] * (1 - t) + lookup_table_estimates[i] * t;
        }
    }
    return {1.0 / value, 0.0};  // Fallback, should not reach here
}

void GoldschmidtDivision(Ciphertext &tilde_A, Ciphertext &tilde_B, Ciphertext &result,
                         int num_iterations, CKKSEncoder &ckks_encoder, Encryptor &enc,
                         Decryptor &dec, shared_ptr<EvaluatorCkksBase> &ckks_eva,
                         RelinKeys &relinKeys, GaloisKeys &rotKeys, PoseidonContext &context)
{
    auto slot_num = context.parameters_literal()->slot();
    // Step 1: 初始估计
    double scale = std::pow(2.0, 40);
    Plaintext plain_b;
    dec.decrypt(tilde_B, plain_b);
    std::vector<double> decoded_b;
    ckks_encoder.decode(plain_b, decoded_b);
    complex<double> ie = get_initial_estimate(decoded_b[0]);
    cout << ie << endl;
    std::vector<std::complex<double>> initial_estimate(slot_num, ie);
    Plaintext plain_estimate;
    ckks_encoder.encode(initial_estimate, scale, plain_estimate);
    Ciphertext tilde_Y;
    enc.encrypt(plain_estimate, tilde_Y);

    // Step 2: 迭代优化
    Ciphertext tilde_X;

    for (int i = 0; i < num_iterations; ++i)
    {
        Ciphertext tilde_B_times_Y;
        ckks_eva->drop_modulus(tilde_B, tilde_B, tilde_Y.level());
        ckks_eva->multiply_relin(tilde_B, tilde_Y, tilde_B_times_Y, relinKeys);
        ckks_eva->rescale_dynamic(tilde_B_times_Y, tilde_B_times_Y,
                                  context.parameters_literal()->scale());

        vector<std::complex<double>> two(slot_num, std::complex<double>(2.0, 0.0));
        Plaintext plain_two;
        ckks_encoder.encode(two, tilde_B_times_Y.scale(), plain_two);
        Ciphertext tilde_two;
        enc.encrypt(plain_two, tilde_two);

        ckks_eva->drop_modulus(tilde_two, tilde_two, tilde_B_times_Y.level());

        ckks_eva->sub(tilde_two, tilde_B_times_Y, tilde_two);

        ckks_eva->drop_modulus(tilde_Y, tilde_Y, tilde_two.level());
        ckks_eva->multiply_relin(tilde_Y, tilde_two, tilde_Y, relinKeys);
        ckks_eva->rescale_dynamic(tilde_Y, tilde_Y, context.parameters_literal()->scale());
    }

    ckks_eva->drop_modulus(tilde_A, tilde_A, tilde_Y.level());
    ckks_eva->multiply_relin(tilde_Y, tilde_A, tilde_X, relinKeys);
    ckks_eva->rescale_dynamic(tilde_X, tilde_X, context.parameters_literal()->scale());

    result = tilde_X;
}
void Softmax(Ciphertext &input, Ciphertext &output, int m, PolynomialVector &polys1,
             PolynomialVector &polys2, PolynomialVector &polys3, CKKSEncoder &ckks_encoder,
             Encryptor &enc, Decryptor &dec, shared_ptr<EvaluatorCkksBase> &ckks_eva,
             RelinKeys &relinKeys, GaloisKeys &rotKeys, PoseidonContext &context)
{
    Ciphertext tmp, a_max, sum;
    Quickmax(input, a_max, m, polys1, polys2, polys3, ckks_encoder, enc, dec, ckks_eva, relinKeys,
             rotKeys, context);
    a_max.scale() = input.scale();
    ckks_eva->sub_dynamic(input, a_max, tmp, ckks_encoder);
    Exp(tmp, tmp, ckks_encoder, ckks_eva, relinKeys, context);

    Quicksum(tmp, sum, m, ckks_encoder, ckks_eva, rotKeys, context, true);
    GoldschmidtDivision(tmp, sum, output, 4, ckks_encoder, enc, dec, ckks_eva, relinKeys, rotKeys,
                        context);
    return;
}

void Attention(vector<vector<complex<double>>> &A, vector<vector<complex<double>>> &W_Q,
               vector<vector<complex<double>>> &W_K, vector<vector<complex<double>>> &W_V,
               vector<Ciphertext> &output, PolynomialVector &polys1, PolynomialVector &polys2,
               PolynomialVector &polys3, CKKSEncoder &ckks_encoder, Encryptor &enc, Decryptor &dec,
               shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, GaloisKeys &rotKeys,
               PoseidonContext &context)
{
    vector<complex<double>> vec_zero(context.parameters_literal()->slot(), 0);
    Plaintext plain_zero;
    Ciphertext ciph_zero;
    ckks_encoder.encode(vec_zero, context.parameters_literal()->scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_zero);

    vector<vector<Ciphertext>> ciph_A(m, vector<Ciphertext>(n, ciph_zero));
    for (int i = 0; i < m; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            Plaintext tmp;
            vector<complex<double>> vec_A(context.parameters_literal()->slot(), 0);
            for (int l = 0; l < k; ++l)
            {
                vec_A[l] = A[i][j];
            }
            ckks_encoder.encode(vec_A, context.parameters_literal()->scale(), tmp);
            enc.encrypt(tmp, ciph_A[i][j]);
        }
    }

    vector<Plaintext> plain_Q(n, plain_zero), plain_K(n, plain_zero);
    for (int i = 0; i < n; ++i)
    {
        vector<complex<double>> vec_Q(context.parameters_literal()->slot(), 0);
        vector<complex<double>> vec_K(context.parameters_literal()->slot(), 0);
        for (int j = 0; j < k; ++j)
        {
            vec_Q[j] = W_Q[i][j];
            vec_K[j] = W_K[i][j];
        }
        ckks_encoder.encode(vec_Q, context.parameters_literal()->scale(), plain_Q[i]);
        ckks_encoder.encode(vec_K, context.parameters_literal()->scale(), plain_K[i]);
    }
    vector<Ciphertext> Q(m, ciph_zero);
    vector<Ciphertext> K(m, ciph_zero);
    vector<Ciphertext> S(m, ciph_zero);
    Matmul_plain(ciph_A, plain_Q, Q, m, n, k, ckks_eva, context);
    Matmul_plain(ciph_A, plain_K, K, m, n, k, ckks_eva, context);
    Matmul_ciph(Q, K, S, m, n, m, ckks_encoder, ckks_eva, relinKeys, rotKeys, context);

    for (int i = 0; i < m; ++i)
    {
        ckks_eva->multiply_const(S[i], 1.0 / sqrt(k), context.parameters_literal()->scale(), S[i],
                                 ckks_encoder);
        ckks_eva->rescale_dynamic(S[i], S[i], context.parameters_literal()->scale());
        Softmax(S[i], S[i], m, polys1, polys2, polys3, ckks_encoder, enc, dec, ckks_eva, relinKeys,
                rotKeys, context);
    }

    vector<vector<Plaintext>> plain_V_T(k, vector<Plaintext>(n, plain_zero));
    for (int i = 0; i < k; ++i)
    {
        for (int j = 0; j < n; ++j)
        {
            vector<complex<double>> vec_V_T(context.parameters_literal()->slot(), 0);
            for (int l = 0; l < m; ++l)
            {
                vec_V_T[l] = W_V[j][i];
            }
            ckks_encoder.encode(vec_V_T, context.parameters_literal()->scale(), plain_V_T[i][j]);
        }
    }
    vector<Ciphertext> ciph_A_T(n, ciph_zero);
    for (int i = 0; i < n; ++i)
    {
        Plaintext tmp;
        vector<complex<double>> vec_A_T(context.parameters_literal()->slot(), 0);
        for (int j = 0; j < m; ++j)
        {
            vec_A_T[j] = A[j][i];
        }
        ckks_encoder.encode(vec_A_T, context.parameters_literal()->scale(), tmp);
        enc.encrypt(tmp, ciph_A_T[i]);
    }
    vector<Ciphertext> V(m, ciph_zero);
    Matmul_plain2(plain_V_T, ciph_A_T, V, m, n, k, ckks_eva, context);
    Matmul_ciph(S, V, output, m, m, k, ckks_encoder, ckks_eva, relinKeys, rotKeys, context);
    return;
}

void FeedForward(vector<Ciphertext> &X, vector<vector<complex<double>>> &W_1,
                 vector<vector<complex<double>>> &b_1, vector<vector<complex<double>>> &W_2,
                 vector<vector<complex<double>>> &b_2, vector<Ciphertext> &output,
                 PolynomialVector &polys1, PolynomialVector &polys2, PolynomialVector &polys3,
                 CKKSEncoder &ckks_encoder, Encryptor &enc, Decryptor &dec,
                 shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, GaloisKeys &rotKeys,
                 PoseidonContext &context)
{
    vector<complex<double>> vec_zero(context.parameters_literal()->slot(), 0);
    Plaintext plain_zero;
    Ciphertext ciph_zero;
    ckks_encoder.encode(vec_zero, context.parameters_literal()->scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_zero);

    vector<Plaintext> plain_W_1(k, plain_zero), plain_W_2(k, plain_zero), plain_b_1(m, plain_zero),
        plain_b_2(m, plain_zero);
    for (int i = 0; i < k; ++i)
    {
        vector<complex<double>> vec_W_1(context.parameters_literal()->slot(), 0);
        vector<complex<double>> vec_W_2(context.parameters_literal()->slot(), 0);
        for (int j = 0; j < n; ++j)
        {
            vec_W_1[j] = W_1[j][i];
            vec_W_2[j] = W_2[j][i];
        }
        ckks_encoder.encode(vec_W_1, context.parameters_literal()->scale(), plain_W_1[i]);
        ckks_encoder.encode(vec_W_2, context.parameters_literal()->scale(), plain_W_2[i]);
    }
    for (int i = 0; i < m; ++i)
    {
        vector<complex<double>> vec_b_1(context.parameters_literal()->slot(), 0);
        vector<complex<double>> vec_b_2(context.parameters_literal()->slot(), 0);
        for (int j = 0; j < n; ++j)
        {
            vec_b_1[j] = b_1[i][j];
            vec_b_2[j] = b_2[i][j];
        }
        ckks_encoder.encode(vec_b_1, context.parameters_literal()->scale(), plain_b_1[i]);
        ckks_encoder.encode(vec_b_2, context.parameters_literal()->scale(), plain_b_2[i]);
    }

    vector<Ciphertext> tmp;
    Matmul_plain3(X, plain_W_1, plain_b_1, tmp, m, n, k, ckks_encoder, ckks_eva, relinKeys, rotKeys,
                  context);
    for (int i = 0; i < m; ++i)
        Gelu(tmp[i], tmp[i], polys1, polys2, polys3, ckks_encoder, ckks_eva, relinKeys, context);
    Matmul_plain3(X, plain_W_2, plain_b_2, tmp, m, n, k, ckks_encoder, ckks_eva, relinKeys, rotKeys,
                  context);

    return;
}

void LayerNorm(vector<Ciphertext> &input, double gamma, double beta, vector<Ciphertext> &output,
               PolynomialVector &polys1, PolynomialVector &polys2, PolynomialVector &polys3,
               CKKSEncoder &ckks_encoder, Encryptor &enc, Decryptor &dec,
               shared_ptr<EvaluatorCkksBase> &ckks_eva, RelinKeys &relinKeys, GaloisKeys &rotKeys,
               PoseidonContext &context)
{
    vector<complex<double>> vec_zero(context.parameters_literal()->slot(), 0);
    Plaintext plain_zero;
    Ciphertext ciph_zero;
    ckks_encoder.encode(vec_zero, context.parameters_literal()->scale(), plain_zero);
    enc.encrypt(plain_zero, ciph_zero);

    for (int i = 0; i < m; ++i)
    {
        Ciphertext s, z, y;
        Quicksum(input[i], s, n, ckks_encoder, ckks_eva, rotKeys, context);
        ckks_eva->multiply_const(input[i], (double)n, context.parameters_literal()->scale(), z,
                                 ckks_encoder);
        ckks_eva->rescale_dynamic(z, z, context.parameters_literal()->scale());
        ckks_eva->sub(z, s, z);
        ckks_eva->multiply_relin(z, z, y, relinKeys);
        ckks_eva->rescale_dynamic(y, y, context.parameters_literal()->scale());
        Quicksum(y, y, n, ckks_encoder, ckks_eva, rotKeys, context);
        ckks_eva->multiply_relin(y, z, y, relinKeys);
        ckks_eva->rescale_dynamic(y, y, context.parameters_literal()->scale());
        ckks_eva->multiply_const(y, gamma * sqrt(n), context.parameters_literal()->scale(),
                                 output[i], ckks_encoder);
        ckks_eva->rescale_dynamic(output[i], output[i], context.parameters_literal()->scale());
        ckks_eva->add_const(output[i], beta, output[i], ckks_encoder);
    }
    return;
}
