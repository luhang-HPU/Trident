#include "batch_handler.h"
#include "ckks_lrtrain_utils.h"

#include "poseidon/util/debug.h"
#include "poseidon/util/precision.h"

using namespace std;
using namespace poseidon;
using namespace poseidon::util;
using namespace lr_train;

int main()
{
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    uint32_t q_def = 32;
    uint32_t log_degree = 16;

    ParametersLiteral ckks_param_literal{CKKS, log_degree, log_degree - 1, q_def, 5, 1, 0, {}, {}};
    vector<uint32_t> log_q(50, 32);
    vector<uint32_t> log_p(1, 60);
    ckks_param_literal.set_log_modulus(log_q, log_p);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);

    auto slot_size = 1 << ckks_param_literal.log_slots();
    int block_size = get_size(n, slot_size);
    int block_num = (int)std::ceil((double)m / block_size);
    double scale = std::pow(2.0, q_def);

    std::cout << "matrix size: " << m << " * " << n << std::endl;
    std::cout << "block size: " << block_size << std::endl;
    std::cout << "block num: " << block_num << std::endl;

    // input of trainning set
    vector<vector<complex<double>>> x(m, vector<complex<double>>(n, {0.0, 0.0}));
    // output
    vector<complex<double>> y(m, {0.0, 0.0});
    // weight
    vector<complex<double>> weight(n, {0.0, 0.0});
    // transposed matrix of input
    vector<vector<complex<double>>> x_transpose(n, vector<complex<double>>(m, {0.0, 0.0}));
    // diagonal transposed matrix of input
    vector<vector<complex<double>>> x_diag(block_num * block_size, vector<complex<double>>(block_size, {0.0, 0.0}));

    std::filesystem::path current_path(__FILE__);
    read_file(x,current_path.parent_path().string() + "/dataset/x_train.txt");
    read_file(y,current_path.parent_path().string() + "/dataset/y_train.txt");

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
    auto expected_weight = weight;

    preprocess(block_size, block_num, x, x_transpose, x_diag);

    // batching x_diag
    std::vector<std::complex<double>> block_x_diag;
    for (const auto &vec : x_diag)
    {
        block_x_diag.insert(block_x_diag.end(), vec.begin(), vec.end());
    }
    // batching x_transpose
    std::vector<std::vector<std::complex<double>>> block_x_transpose;
    for (auto vec : x_transpose)
    {
        block_x_transpose.push_back(vector_to_block_message(vec, m, block_size));
    }
    // batching weight
    std::vector<std::complex<double>> block_weight;
    {
        /*
         * fulfill the weight vector to size @block_size with zero
         * weight_extend = [weight, 0, 0 ...]
         */
        auto weight_extend = weight;
        if (weight_extend.size() < block_size)
        {
            weight_extend.insert(weight_extend.end(), block_size - weight_extend.size(), {0.0, 0.0});
        }

        // concatenate the weight with the weight
        // weight_concat = [weight_extend, weight_extend]
        auto weight_concat = weight_extend;
        weight_concat.insert(weight_concat.end(), weight_concat.begin(), weight_concat.end());

        for (auto i = 0; i < block_size; ++i)
        {
            block_weight.insert(block_weight.end(), weight_concat.begin() + i, weight_concat.begin() + i + block_size);
        }

        while (block_weight.size() < slot_size)
        {
            block_weight.insert(block_weight.end(), block_weight.begin(), block_weight.end());
        }
    }
    // batching y
    std::vector<std::complex<double>> block_y = vector_to_block_message(y, m, block_size);

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

    BatchHandler batch_handler(slot_size, (int)log_degree, block_size, m, n);
    std::vector<Ciphertext> ciph_x_transpose;
    for (auto &vec : block_x_transpose)
    {
        ciph_x_transpose.emplace_back(batch_handler.encode_and_encrypt(ckks_encoder, enc, vec, scale));
    }
    Ciphertext ciph_x_diag = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_x_diag, scale);
    Ciphertext ciph_weight = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_weight, scale);
    Ciphertext ciph_y = batch_handler.encode_and_encrypt(ckks_encoder, enc, block_y, scale);

    for (auto &ciph : ciph_x_transpose)
    {
        auto message_x_transpose = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph);
        check::print_vector(message_x_transpose);
    }

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

    long long total_time_bootstrap = 0;
    long long total_time_lrtrain = 0;
    for (auto epoch = 0; epoch < EPOCHS; ++epoch)
    {
        util::Timestacs timer;
        timer.start();
        std::cout << "epoch " << epoch << " start..." << std::endl;

        Ciphertext ciph_product;
        Ciphertext ciph_x_diag_tmp = ciph_x_diag;
        if (ciph_x_diag_tmp.level() != ciph_weight.level())
        {
            ckks_eva->drop_modulus(ciph_x_diag_tmp, ciph_x_diag_tmp, ciph_weight.parms_id());
        }
        ckks_eva->multiply_relin(ciph_x_diag_tmp, ciph_weight, ciph_product, relin_keys);
        ckks_eva->rescale_dynamic(ciph_product, ciph_product, scale);
        ciph_product = accumulate_block_matrix(ckks_eva, rot_keys, ciph_product, block_size);

#ifdef DEBUG_LRTRAIN
        // check dot_product of theta^T and x
        std::vector<double> expected_dot_product;
        {
            for (auto i = 0; i < m; ++i)
            {
                double _sum = 0.0;
                for (auto j = 0; j < n; ++j)
                {
                    _sum += x[i][j].real() * expected_weight[j].real();
                }
                expected_dot_product.push_back(_sum);
            }

            auto fhe_dot_product = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_product);

            std::cout << "fhe value  |  expected value" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                std::cout << "dot product[" << i << "]: " << fhe_dot_product[i % block_size + i / block_size * block_size * block_size].real() << " " << expected_dot_product[i] << std::endl;
            }
        }
#endif

        // calculate sigmoid(theta^T x)
        Ciphertext ciph_sigmoid =
            sigmoid_approx(ciph_product, polys, ckks_encoder, ckks_eva, relin_keys);

#ifdef DEBUG_LRTRAIN
        // check sigmoid
        std::vector<double> expected_sigmoid(m, 0.0);
        {
            auto fhe_sigmoid = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_sigmoid);
            std::cout << "fhe sigmoid  |  expected sigmoid" << std::endl;
            for (auto i = 0; i < m; ++i)
            {
                expected_sigmoid[i] = sigmoid(expected_dot_product[i]);
                std::cout << "sigmoid[" << i << "]: " << fhe_sigmoid[i / block_size * block_size * block_size + (i % block_size)].real() << " " << expected_sigmoid[i] << std::endl;
            }
        }
#endif

        // calculate gradient
        auto ciph_y_tmp = ciph_y;
        if (ciph_y_tmp.level() != ciph_sigmoid.level())
        {
            ckks_eva->drop_modulus(ciph_y_tmp, ciph_y_tmp, ciph_sigmoid.parms_id());
        }

        if(!util::are_approximate(ciph_y_tmp.scale(), ciph_sigmoid.scale()))
        {
            std::vector<std::complex<double>> vec_tmp(slot_size, {1.0, 0.0});
            Plaintext plt_tmp;

            // for ciph_y_tmp
            {
                ckks_encoder.encode(vec_tmp, ciph_y_tmp.parms_id(), scale * scale / ciph_y_tmp.scale(), plt_tmp);
                ckks_eva->multiply_plain(ciph_y_tmp, plt_tmp, ciph_y_tmp);
                ckks_eva->rescale(ciph_y_tmp, ciph_y_tmp);
            }

            // for ciph_sigmoid
            {
                ckks_encoder.encode(vec_tmp, ciph_sigmoid.parms_id(), scale * scale / ciph_sigmoid.scale(), plt_tmp);
                ckks_eva->multiply_plain(ciph_sigmoid, plt_tmp, ciph_sigmoid);
                ckks_eva->rescale(ciph_sigmoid, ciph_sigmoid);
            }
        }

        ckks_eva->sub_dynamic(ciph_sigmoid, ciph_y_tmp, ciph_sigmoid, ckks_encoder);

        Ciphertext ciph_gradient;
        for (auto i = 0; i < n; ++i)
        {
            auto ciph = ciph_x_transpose[i];
            ckks_eva->drop_modulus(ciph, ciph, ciph_sigmoid.parms_id());
            ckks_eva->multiply_relin(ciph, ciph_sigmoid, ciph, relin_keys);
            ckks_eva->rescale_dynamic(ciph, ciph, scale);

            ciph = accumulate_slot_matrix(ckks_eva, rot_keys, ciph, block_size, block_num);
            ciph = accumulate_top_n(ciph, block_size, ckks_encoder, enc, ckks_eva, rot_keys);

            std::vector<std::complex<double>> vec_mask{1.0};
            Plaintext plain_mask;
            ckks_encoder.encode(vec_mask, ciph.parms_id(), ciph.scale(), plain_mask);
            ckks_eva->multiply_plain(ciph, plain_mask, ciph);

            ckks_eva->rotate(ciph, ciph, -i, rot_keys);
            if (i == 0)
            {
                ciph_gradient = ciph;
            }
            else
            {
                ckks_eva->add(ciph, ciph_gradient, ciph_gradient);
            }
        }
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

        ckks_eva->multiply_const(ciph_gradient, learning_rate / m , ciph_gradient.scale(), ciph_gradient, ckks_encoder);
        ckks_eva->rescale_dynamic(ciph_gradient, ciph_gradient, scale);

#ifdef DEBUG_LRTRAIN
        // check gradient
        std::vector<double> expected_gradient(n, 0.0);
        {
            for (auto i = 0; i < m; ++i)
            {
                for (auto j = 0; j < n; ++j)
                {
                    expected_gradient[j] += (expected_sigmoid[i] - y[i].real()) * x_transpose[j][i].real();
                }
            }

            auto res = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_gradient);
            std::cout << "fhe gradient  |  expected gradient" << std::endl;
            for (auto i = 0; i < n; ++i)
            {
                std::cout << "grad[" << i << "]: " << res[i].real() << " " << expected_gradient[i] * learning_rate / m << std::endl;
            }
        }
#endif

        // ciph_grad_concat = ciph_grad | ciph_grad
        Ciphertext ciph_grad_concat;
        {
            Ciphertext ciph_grad_rotated;
            ckks_eva->rotate(ciph_gradient, ciph_grad_rotated, -block_size, rot_keys);
            ckks_eva->add(ciph_gradient, ciph_grad_rotated, ciph_grad_concat);
        }

        // the gradient of block ciphertext
        Ciphertext ciph_grad_block;
        for (auto i = 0; i < block_size; ++i)
        {
            std::vector<std::complex<double>> mask(block_size * 2, {0.0, 0.0});
            std::fill_n(mask.begin() + i, block_size, std::complex<double>{1.0, 0.0});
            Plaintext plain_mask;
            ckks_encoder.encode(mask, ciph_grad_concat.parms_id(), ciph_grad_concat.scale(), plain_mask);

            Ciphertext ciph_grad_concat_rotated;
            ckks_eva->multiply_plain(ciph_grad_concat, plain_mask, ciph_grad_concat_rotated);
            ckks_eva->rescale(ciph_grad_concat_rotated, ciph_grad_concat_rotated);
            ckks_eva->rotate(ciph_grad_concat_rotated, ciph_grad_concat_rotated, -(i * block_size - i), rot_keys);

            if (i == 0)
            {
                ciph_grad_block = ciph_grad_concat_rotated;
            }
            else
            {
                ckks_eva->add_dynamic(ciph_grad_concat_rotated, ciph_grad_block, ciph_grad_block, ckks_encoder);
            }
        }

        // ciphertext for gradient updating
        Ciphertext ciph_for_grad_update = ciph_grad_block;
        for (auto i = block_size * block_size; i < slot_size; i *= 2)
        {
            Ciphertext ciph_tmp;
            ckks_eva->rotate(ciph_for_grad_update, ciph_tmp, -i, rot_keys);
            ckks_eva->add(ciph_for_grad_update, ciph_tmp, ciph_for_grad_update);
        }

        // update ciph_weight
        if (ciph_weight.level() > ciph_for_grad_update.level())
        {
            ckks_eva->drop_modulus(ciph_weight, ciph_weight, ciph_for_grad_update.parms_id());
        }

        if(!util::are_approximate(ciph_for_grad_update.scale(), ciph_weight.scale()))
        {
            std::vector<std::complex<double>> vec_tmp(slot_size, {1.0, 0.0});
            Plaintext plt_tmp;

            // for ciph_for_grad_update
            {
                ckks_encoder.encode(vec_tmp, ciph_for_grad_update.parms_id(), scale * scale / ciph_for_grad_update.scale(), plt_tmp);
                ckks_eva->multiply_plain(ciph_for_grad_update, plt_tmp, ciph_for_grad_update);
                ckks_eva->rescale(ciph_for_grad_update, ciph_for_grad_update);
            }

            // for ciph_weight
            {
                ckks_encoder.encode(vec_tmp, ciph_weight.parms_id(), scale * scale / ciph_weight.scale(), plt_tmp);
                ckks_eva->multiply_plain(ciph_weight, plt_tmp, ciph_weight);
                ckks_eva->rescale(ciph_weight, ciph_weight);
            }
        }

        ckks_eva->sub_dynamic(ciph_weight, ciph_for_grad_update, ciph_weight, ckks_encoder);


#ifdef DEBUG_LRTRAIN
        // check updated weight
        {
            for (auto i = 0; i < n; ++i)
            {
                expected_weight[i] -= learning_rate * expected_gradient[i] / m;
            }
            std::cout << "fhe weight  |  expected weight" << std::endl;
            auto res = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_weight);
            for (auto i = 0; i < n; ++i)
            {
                std::cout << "weight[" << i << "]: " << res[i].real() << " " << expected_weight[i].real() << std::endl;
            }
        }
#endif

        timer.end();
        std::cout << "epoch " << epoch << " end..." << std::endl;
        timer.print_time("lr train time: ");
        total_time_lrtrain += timer.microseconds();

        // bootstrap
        if(ciph_weight.level() < 12){
            auto start = chrono::high_resolution_clock::now();
            std::cout << "bootstraping start..." << std::endl;
            EvalModPoly eval_mod_poly(context, CosDiscrete, (uint64_t)1 << 40, 1,
                                      9, 3, 16, 0, 30);
            ckks_eva->bootstrap(ciph_weight, ciph_weight, relin_keys,rot_keys, ckks_encoder, eval_mod_poly);
            auto stop = chrono::high_resolution_clock::now();
            auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
            std::cout << "bootstraping TIME: " << duration.count() << " microseconds" << std::endl;
            total_time_bootstrap += duration.count();

#ifdef DEBUG_LRTRAIN
            // check the weight after bootstrap
            {
                auto wegiht_after_bootstrap = batch_handler.decrypt_and_decode(ckks_encoder, dec, ciph_weight);
                std::cout << "weight after bootstrap" << std::endl;
                for (auto i = 0; i < n; ++i)
                {
                    std::cout << "weight[" << i << "]: " << wegiht_after_bootstrap[i].real() << std::endl;
                }
            }
#endif
        }
    }

    std::cout << "total time of lr train: " << total_time_lrtrain << std::endl;
    std::cout << "total time of bootstrap: " << total_time_bootstrap << std::endl;
    std::cout << "total time: " << total_time_lrtrain + total_time_bootstrap << std::endl;
    std::cout << "fhe training accuracy : " << accuracy_of_ciph(ciph_weight, x, y, dec, ckks_encoder) << std::endl;
#ifdef DEBUG_LRTRAIN
    std::cout << "expected training accuracy : " << accuracy_of_plain(expected_weight, x, y) << std::endl;
#endif

    return 0;
}
