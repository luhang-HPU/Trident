#include <bits/stdc++.h>
#include <iostream>
#include <fstream>

#include "poseidon/PoseidonContext.h"
#include "poseidon/CKKSEncoder.h"
#include "poseidon/plaintext.h"
#include "poseidon/util/random_sample.h"
#include "poseidon/encryptor.h"
#include "poseidon/decryptor.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/precision.h"
#include "poseidon/Evaluator.h"
#include "poseidon/RNSPoly.h"
#include "poseidon/util/debug.h"

using namespace std;
using namespace poseidon;
using namespace poseidon::util;

const int EPOCHS = 5;

double sigmoid(double x)
{
    // return(exp(x) / (1 + exp(x)));
    return(0.5 + 0.197 * x - 0.004 * x * x * x);
}

int main() {

    cout << BANNER  << endl;
    cout << "POSEIDON SOFTWARE  VERSION:" <<POSEIDON_VERSION << endl;
    cout << "" << endl;

    // uint32_t q0_bit = 63;
    uint32_t q_def = 31;

    ParametersLiteral ckks_param_literal{
            CKKS,
            13,
            12,
            q_def,
            5,
            1,
            0,
            {},
            {}
    };

    // vector<uint32_t> logQTmp{31,31,31,31,31,31,31,31,31,31, 31,31,31,31}; //,31,31,31,31,31,31,31,31,31,31
    // vector<uint32_t> logPTmp{31,31,31,31,31,31,31,31,31,31, 31,31,31,31};
    vector<uint32_t> logQTmp{31, 31, 31, 31, 31, 31, 31};//,31,31,31,31}; //
    vector<uint32_t> logPTmp{31, 31, 31, 31, 31, 31, 31};//,
    ckks_param_literal.set_log_modulus(logQTmp,logPTmp);
    PoseidonContext context(ckks_param_literal,sec_level_type::none,false);
    // PoseidonContext context(ckks_param_literal,sec_level_type::none);
    auto q0 = context.crt_context()->q0();


    //=====================init random data ============================
    int mat_size = 1 << ckks_param_literal.LogSlots();
    int m_count = 780;
    int n_features = 9;

    vector<vector<complex<double>>> x_train(mat_size,vector<complex<double>>(mat_size,0));
    vector<complex<double>> y_train(mat_size, 0);
    vector<complex<double>> weight(mat_size,0);
    vector<complex<double>> bias(mat_size,0);

    ifstream inFile_X("x_train.txt", ios::in);
    for (int i = 0; i < m_count; ++i)
        for (int j = 0; j < n_features; ++j)
            inFile_X >> x_train[i][j];
    inFile_X.close();

    ifstream inFile_Y("y_train.txt", ios::in);
    for (int i = 0; i < m_count; ++i)
        inFile_Y >> y_train[i];
    inFile_Y.close();

    ofstream outFile("result.txt", ios::out);

    // sample_random_complex_vector2(weight, mat_size);
    // srand(time(0));
    srand(0);
    for (int i = 0; i < n_features; ++i)
    {
        weight[i].imag(0);
        double sum = 0;
        for (int j = 0; j < 200; ++j)
            sum += rand() / (RAND_MAX + 1.0);
        sum -= 100;
        sum /= sqrt(200.0 * n_features / 12);
        weight[i].real(sum);
    }
    for (int i = n_features; i < mat_size; ++i)
        weight[i] = 0;

    vector<complex<double>> _weight(weight);
    vector<complex<double>> _bias(bias);

    vector<vector<complex<double>>> x_train_diag(mat_size,vector<complex<double>>(mat_size,0));
    vector<vector<complex<double>>> x_train_diag_T(mat_size,vector<complex<double>>(mat_size,0));
    vector<vector<complex<double>>> order(mat_size,vector<complex<double>>(mat_size,0));
    for (int i = 0; i < mat_size; ++i)
    {
        for (int j = 0; j < n_features; ++j)
        {
            x_train_diag[i][j] = x_train[(i + j) % mat_size][j];
        }
    }
    for (int i = 0; i < mat_size; ++i)
    {
        for (int j = 0; j < m_count; ++j)
        {
            x_train_diag_T[i][j] = x_train[j][(i + j) % mat_size];
        }
    }
    for (int i = 0; i < m_count; ++i)
    {
        order[i][i] = 1.0;
    }
    //=====================init  Plain & Ciph =========================
    PublicKey public_key;
    RelinKeys relinKeys;
    GaloisKeys conjKeys;
    GaloisKeys rotKeys;
    vector<uint32_t> rot_elemt;
    CKKSEncoder ckks_encoder(context);

    //=====================keys  =========================
    KeyGenerator kgen(context);
    kgen.create_public_key(public_key);

    kgen.create_relin_keys(relinKeys);

    vector<int> gal_steps_vector;
    gal_steps_vector.push_back(0);
    for (int i = 0; i < ckks_param_literal.LogSlots(); ++i)
    {
        gal_steps_vector.push_back(1 << i);
        gal_steps_vector.push_back(-(1 << i));
    }
    kgen.create_galois_keys(gal_steps_vector, rotKeys);


    Encryptor enc(context,public_key,kgen.secret_key());
    Decryptor dec(context,kgen.secret_key());
    auto ckks_eva = EvaluatorFactory::SoftFactory()->create(context);
    // auto ckks_eva = EvaluatorFactory::DefaultFactory()->create(context);

    double scale = std::pow(2.0, q_def);

    vector<Ciphertext> enc_x_train, enc_x_train_T, enc_order;
    for (int i = 0; i < mat_size; ++i)
    {
        Plaintext plaintext, plaintext_T, plaintext_order;
        Ciphertext ct, ct_T, ct_order;
        ckks_encoder.encode(x_train_diag[i], scale, plaintext);
        enc.encrypt(plaintext, ct);
        enc_x_train.emplace_back(ct);
        ckks_encoder.encode(x_train_diag_T[i], scale, plaintext_T);
        enc.encrypt(plaintext_T, ct_T);
        enc_x_train_T.emplace_back(ct_T);
        ckks_encoder.encode(order[i], scale, plaintext_order);
        enc.encrypt(plaintext_order, ct_order);
        enc_order.emplace_back(ct_order);
    }

    Plaintext plaintext, plain_mask, plain_first;
    Ciphertext enc_y_train, enc_weight, enc_bias, enc_mask, enc_first;
    ckks_encoder.encode(y_train, scale, plaintext);
    enc.encrypt(plaintext, enc_y_train);
    ckks_encoder.encode(weight, scale, plaintext);
    enc.encrypt(plaintext, enc_weight);
    ckks_encoder.encode(bias, scale, plaintext);
    enc.encrypt(plaintext, enc_bias);

    vector<complex<double>> mask(mat_size,0);
    vector<complex<double>> first(mat_size,0);
    for (int i = 0; i < m_count; ++i)
        mask[i] = 1;
    ckks_encoder.encode(mask, scale, plain_mask);
    enc.encrypt(plain_mask, enc_mask);
    first[0] = 1.0;
    ckks_encoder.encode(first, scale, plain_first);
    enc.encrypt(plain_first, enc_first);

    vector<complex<double>> buffer(4, 0);
    buffer[0] = 0.5;
    buffer[1] = 0.197;
    buffer[3] = -0.004;

    Polynomial approxF(buffer, 0, 0, 4, Monomial);
    approxF.lead() = true;
    //auto approxG = util::Approximate(g, a, b, deg);
    vector <Polynomial> poly_v{approxF};
    vector<vector<int>> slotsIndex(1,vector<int>(context.parameters_literal()->degree() >> 1,0));
    vector<int> idxF(context.parameters_literal()->degree() >> 1);

    for(int i = 0; i < context.parameters_literal()->degree() >> 1; i++){
        idxF[i] = i;   // Index with all even slots
    }

    slotsIndex[0] = idxF; // Assigns index of all even slots to poly[0] = f(x)

    PolynomialVector polys(poly_v,slotsIndex);

    if (1)
    {
        outFile << _bias[0] << " ";
        for (int i = 0; i < n_features; ++i)
            outFile << _weight[i] << " ";
        outFile << endl;

        int cnt = 0;
        for (int i = 0; i < m_count; ++i)
        {
            complex<double> sum = _bias[0];
            for (int j = 0; j < n_features; ++j)
            {
                sum += _weight[j] * x_train[i][j];
            }
            if (abs(sigmoid(sum.real()) - y_train[i].real()) < 0.5)
                ++cnt;
        }
        outFile << "Accuracy of Init:" << (double)cnt / (double)m_count << endl << endl;
    }

    for (int epoch = 1; epoch <= EPOCHS; ++epoch)
    {
        Ciphertext step, delta_weight, delta_bias;

        // ckks_eva->multiplyByDiagMatrixBSGS_ct(W^T, X^T, step, rot_key);
        ckks_eva->multiply_relin(enc_x_train[0], enc_weight, step, relinKeys);

        for (int i = 1; i < mat_size; ++i)
        {
            Ciphertext ct;
            ckks_eva->multiply_relin(enc_x_train[i], enc_weight, ct, relinKeys);
            // ckks_eva->rotate(ct, i, rotKeys, ct);
            int j = i;
            int cnt = 0;
            while (j)
            {
                if(j & 1)
                {
                    ckks_eva->rotate(ct, -(1 << cnt), rotKeys, ct);
                }
                j = j >> 1;
                ++cnt;
            }
            ckks_eva->add(step, ct, step);
        }
        ckks_eva->rescale_dynamic(step, step, scale); //step > $scale

        if (1 == epoch)
        {
            ckks_eva->multiply_const(enc_bias, 1.0, scale, enc_bias, ckks_encoder);
            ckks_eva->rescale_dynamic(enc_bias, enc_bias, scale); //enc_bias > $scale
            ckks_eva->multiply_const(enc_y_train, 1.0, scale, enc_y_train, ckks_encoder);
            ckks_eva->rescale_dynamic(enc_y_train, enc_y_train, scale); //enc_y_train > $scale
        }
        
        ckks_eva->add(step, enc_bias, step); // step = enc_bias

        ckks_eva->evaluatePolyVector(step,step,polys,step.scale(),relinKeys,ckks_encoder);

        ckks_eva->sub_dynamic(step, enc_y_train, step, ckks_encoder); //step = enc_y_train

        ckks_eva->multiply_const(step, 1.0 / m_count, scale, step, ckks_encoder);
        ckks_eva->rescale_dynamic(step, step, scale);

        vector<complex<double>> vec(mat_size,0);
        Plaintext plain_step1, plain_step2;
        ckks_eva->read(step);
        dec.decrypt(step, plain_step1);
        ckks_encoder.decode(plain_step1, vec);
        for (int i = m_count; i < mat_size; ++i)
            vec[i] = 0;
        ckks_encoder.encode(vec, scale, plain_step2);
        enc.encrypt(plain_step2, step);

        vector<complex<double>> _step(mat_size, 0);
        for (int i = 0; i < m_count; ++i)
        {
            for (int j = 0; j < mat_size; ++j)
            {
                _step[i] += x_train[i][j] * _weight[j];
            }
            _step[i] += _bias[i];
            _step[i] = (sigmoid(_step[i].real()) - y_train[i].real()) / m_count;            
        }
        for (int i = 0; i < m_count; ++i)
        {
            _weight[i] *= 0.95;
            for (int j = 0; j < mat_size; ++j)
            {
                _weight[i] -= _step[j] * x_train[j][i];
                _bias[i] -= _step[j];
            }
            // if (i >= m_count)
            //     _bias[i] = 0;
        }
        
        // ckks_eva->multiplyByDiagMatrixBSGS_ct(step, X, step, rot_key);
        ckks_eva->multiply_relin(enc_x_train_T[0], step, delta_weight, relinKeys);

        for (int i = 1; i < mat_size; ++i)
        {
            Ciphertext ct;
            ckks_eva->multiply_relin(enc_x_train_T[i], step, ct, relinKeys);
            // ckks_eva->rotate(ct, i, rotKeys, ct);
            int j = i;
            int cnt = 0;
            while (j)
            {
                if(j & 1)
                {
                    ckks_eva->rotate(ct, -(1 << cnt), rotKeys, ct);
                }
                j = j >> 1;
                ++cnt;
            }
            ckks_eva->add(delta_weight, ct, delta_weight);
        }
        ckks_eva->rescale_dynamic(delta_weight, delta_weight, scale); //delta_weight > $scale

        ckks_eva->multiply_const(enc_weight, 0.95, scale, enc_weight, ckks_encoder);
        ckks_eva->rescale_dynamic(enc_weight, enc_weight, scale);

        ckks_eva->sub_dynamic(enc_weight, delta_weight, enc_weight, ckks_encoder); //enc_weight = delta_weight = $scale

        ckks_eva->multiply_relin(enc_order[0], step, delta_bias, relinKeys);

        for (int i = 1; i < m_count; ++i)
        {
            Ciphertext ct;
            ckks_eva->multiply_relin(enc_order[i], step, ct, relinKeys);
            // ckks_eva->rotate(ct, i, rotKeys, ct);
            int j = i;
            int cnt = 0;
            while (j)
            {
                if(j & 1)
                {
                    ckks_eva->rotate(ct, (1 << cnt), rotKeys, ct);
                }
                j = j >> 1;
                ++cnt;
            }
            ckks_eva->add(delta_bias, ct, delta_bias);
        }
        ckks_eva->rescale_dynamic(delta_bias, delta_bias, scale); //delta_bias > $scale

        for (int i = 0; i < m_count; ++i)
        {
            ckks_eva->sub_dynamic(enc_bias, delta_bias, enc_bias, ckks_encoder);
            ckks_eva->rotate(delta_bias, -1, rotKeys, delta_bias);
        }
        
        Plaintext plain_weight1, plain_weight2;
        ckks_eva->read(enc_weight);
        dec.decrypt(enc_weight, plain_weight1);
        ckks_encoder.decode(plain_weight1, weight);
        ckks_encoder.encode(weight, scale, plain_weight2);
        enc.encrypt(plain_weight2, enc_weight);

        Plaintext plain_bias;
        ckks_eva->read(enc_bias);
        dec.decrypt(enc_bias, plain_bias);
        ckks_encoder.decode(plain_bias, bias);

        outFile << bias[0] << " ";
        for (int i = 0; i < n_features; ++i)
            outFile << weight[i] << " ";
        outFile << endl;
        
        outFile << _bias[0] << " ";
        for (int i = 0; i < n_features; ++i)
            outFile << _weight[i] << " ";
        outFile << endl;

        int cnt = 0, _cnt = 0;
        for (int i = 0; i < m_count; ++i)
        {
            complex<double> sum = bias[0], _sum = _bias[0];
            for (int j = 0; j < n_features; ++j)
            {
                sum += weight[j] * x_train[i][j];
                _sum += _weight[j] * x_train[i][j];
            }
            if (abs(sigmoid(sum.real()) - y_train[i].real()) < 0.5)
                ++cnt;
            if (abs(sigmoid(_sum.real()) - y_train[i].real()) < 0.5)
                ++_cnt;
        }
        outFile << "Accuracy at Epoch " << epoch << " is:" << (double)cnt / (double)m_count << endl;
        outFile << "Accuracy at Epoch " << epoch << " is:" << (double)_cnt / (double)m_count << endl << endl;
        
        util::GetPrecisionStats(_weight, weight);
    }

    ckks_eva->read(enc_weight);
    dec.decrypt(enc_weight, plaintext);
    ckks_encoder.decode(plaintext, weight);
    ckks_eva->read(enc_bias);
    dec.decrypt(enc_bias, plaintext);
    ckks_encoder.decode(plaintext, bias);
    cout << bias[0] << " ";
    for (int i = 0; i < n_features; ++i)
        cout << weight[i] << " ";
    cout << endl;
    int cnt = 0;
    for (int i = 0; i < m_count; ++i)
    {
        complex<double> sum = bias[0];
        for (int j = 0; j < n_features; ++j)
        {
            sum += weight[j] * x_train[i][j];
        }
        if (abs(sigmoid(sum.real()) - y_train[i]) < 0.5)
            ++cnt;
    }
    cout << "Accuracy:" << (double)cnt / (double)m_count << endl;

    outFile.close();

    return 0;
}