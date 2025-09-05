#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/util/debug.h"
#include "poseidon/util/random_sample.h"
#include <cmath>
#include <complex>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace poseidon;
using namespace poseidon::util;

std::vector<double> take_real(std::vector<complex<double>> &input)
{
    std::vector<double> result;
    result.reserve(input.size());
    for (int i = 0; i < input.size(); ++i)
    {
        result[i] = input[i].real();
    }
    return result;
}

std::vector<double> matrixVectorMultiply(const std::vector<std::vector<double>> &matrix, const std::vector<double> &vec)
{
    int rows = matrix.size();
    int cols = matrix[0].size();
    std::vector<double> result(cols, 0.0);
    for (int i = 0; i < cols; ++i)
    {
        for (int j = 0; j < rows; ++j)
        {
            result[i] += matrix[j][i] * vec[j];
        }
    }
    return result;
}

// Functions used in CNN
std::vector<double> softmax(std::vector<double> &logits)
{
    std::vector<double> result;
    result.reserve(logits.size());
    double max_val = *std::max_element(logits.begin(), logits.end());

    double sum = 0.0;
    for (double x : logits)
    {
        double exp_val = std::exp(x - max_val);
        result.push_back(exp_val);
        sum += exp_val;
    }
    for (double &val : result)
    {
        val /= sum;
    }
    return result;
}

std::vector<double> preprocess_image(const std::vector<std::vector<int>> &image, size_t ker_size, size_t stride)
{
    const int output = (image.size() - ker_size) / stride + 1;
    const int window_num = pow(output, 2);
    const int length = pow(ker_size, 2) * window_num;
    std::vector<double> result(length);
    for (int conv_row_idx = 0; conv_row_idx < output; ++conv_row_idx)
    {
        for (int conv_col_idx = 0; conv_col_idx < output; ++conv_col_idx)
        {
            int init_idx = (conv_row_idx * output + conv_col_idx) * pow(ker_size, 2);
            for (int input_row_idx = 0; input_row_idx < ker_size; ++input_row_idx)
            {
                for (int input_col_idx = 0; input_col_idx < ker_size; ++input_col_idx)
                {
                    result[init_idx + input_row_idx * ker_size + input_col_idx] =
                        static_cast<double>(image[conv_row_idx * stride + input_row_idx]
                                                 [conv_col_idx * stride + input_col_idx]) /
                        255.0;
                }
            }
        }
    }

    std::vector<std::vector<int>> middle(window_num, std::vector<int>(pow(ker_size, 2)));
    for (int i = 0; i < middle.size(); ++i)
    {
        for (int j = 0; j < middle[0].size(); ++j)
        {
            middle[i][j] = result[i * pow(ker_size, 2) + j];
        }
    }

    for (int j = 0; j < middle[0].size(); ++j)
    {
        for (int i = 0; i < middle.size(); ++i)
        {
            result[i + j * window_num] = middle[i][j];
        }
    }
    // result.resize(8192, 0);
    return result;
}

std::vector<float> load_binary_param(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    size_t num_elements = file_size / sizeof(float);
    std::vector<float> param_data(num_elements);
    file.read(reinterpret_cast<char *>(param_data.data()), file_size);
    return param_data;
}

std::vector<double> replicate(const std::vector<double> &kernel, int windows = 64)
{
    std::vector<double> result;
    for (int i = 0; i < kernel.size(); ++i)
    {
        for (int w = 0; w < windows; ++w)
        {
            result.push_back(kernel[i]);
        }
    }
    return result;
}

Plaintext encode_with_consistent_level(const std::vector<double> &input, const Ciphertext &cipher,
                                       CKKSEncoder &encoder)
{
    Plaintext result;
    encoder.encode(input, cipher.parms_id(), cipher.scale(), result);
    return result;
}

std::vector<std::vector<double>> padding_matrix(std::vector<std::vector<double>> &matrix)
{
    int rows = matrix.size();
    int cols = matrix[0].size();

    // row > col
    std::vector<std::vector<double>> result(8192, std::vector<double>(8192, 1e-10));
    for (int i = 0; i < rows; ++i)
    {
        for (int j = 0; j < cols; ++j)
        {
            result[i][j] = matrix[i][j];
        }
    }
    return result;
}

MatrixPlain gen_matrix(std::vector<std::vector<double>> &fc_weight, PoseidonContext context,
                       CKKSEncoder &encoder, ParametersLiteralDefault ckks_param_literal,
                       Ciphertext cipher)
{
    std::vector<std::vector<double>> square = padding_matrix(fc_weight);
    int length = square.size();
    std::vector<std::vector<complex<double>>> fc(length, std::vector<complex<double>>(length));
    std::vector<std::vector<complex<double>>> transpose_fc(length, std::vector<complex<double>>(length));
    for (int i = 0; i < length; ++i)
    {
        for (int j = 0; j < length; ++j)
        {
            fc[i][j] = complex<double>(square[i][j], 0.0);
        }
    }
    matrix_operations::transpose_matrix(fc, transpose_fc);
    std::vector<std::vector<complex<double>>> diagonal_fc(length, std::vector<complex<double>>(length));
    for (int i = 0; i < length; i++)
    {
        matrix_operations::diagonal(transpose_fc, i, diagonal_fc[i]);
    }
    MatrixPlain mplt_fc_weight;
    int level = cipher.level();
    gen_matrix_form_bsgs(mplt_fc_weight, mplt_fc_weight.rot_index, encoder, diagonal_fc, level,
                         cipher.scale(), 1, ckks_param_literal.log_slots());
    return mplt_fc_weight;
}

int main()
{
    // extract weights and bias from pre-trained model
    // conv_kernels_replicated from conv1.weight.bin
    // conv_bias_replicated from conv1.bias.bin
    // fc1_bias_vec from fc1.bias.bin
    // fc1_weights from fc1.weight.bin
    // fc2_bias_vec from fc2.bias.bin
    std::filesystem::path current_path(__FILE__);
    const std::string param_dir = current_path.parent_path().string() + "/parameters/";
    std::vector<float> conv1_weight = load_binary_param(param_dir + "conv1.weight.bin");
    std::vector<std::vector<double>> conv_kernels(4, std::vector<double>(49));
    for (int k = 0; k < 4; k++)
    {
        for (int i = 0; i < 7; i++)
        {
            for (int j = 0; j < 7; j++)
            {
                int idx = k * 49 + i * 7 + j;
                int kernel_idx = i * 7 + j;
                conv_kernels[k][kernel_idx] = static_cast<double>(conv1_weight[idx]);
            }
        }
    }

    std::vector<std::vector<double>> conv_kernels_replicated(4, std::vector<double>(49 * 64));
    for (int i = 0; i < 4; ++i)
    {
        conv_kernels_replicated[i] = replicate(conv_kernels[i]);
    }

    std::vector<float> conv1_bias = load_binary_param(param_dir + "conv1.bias.bin");
    std::vector<double> conv_bias_replicated(256, 0.0);
    for (int i = 0; i < 4; i++)
    {
        conv1_bias[i] = static_cast<double>(conv1_bias[i]);
        fill(conv_bias_replicated.begin() + i * 64, conv_bias_replicated.begin() + (i + 1) * 64,
             conv1_bias[i]);
    }

    std::vector<float> fc1_weight = load_binary_param(param_dir + "fc1.weight.bin");
    std::vector<std::vector<double>> fc1_weights(256, std::vector<double>(64));
    for (int out = 0; out < 64; out++)
    {
        for (int in = 0; in < 256; in++)
        {
            int idx = out * 256 + in;
            fc1_weights[in][out] = static_cast<double>(fc1_weight[idx]);
        }
    }

    std::vector<float> fc1_bias = load_binary_param(param_dir + "fc1.bias.bin");
    // bias dim: 64
    std::vector<double> fc1_bias_vec(64);
    for (int i = 0; i < 64; i++)
    {
        fc1_bias_vec[i] = static_cast<double>(fc1_bias[i]);
    }

    std::vector<float> fc2_weight = load_binary_param(param_dir + "fc2.weight.bin");
    // weight dim: 10*64
    std::vector<std::vector<double>> fc2_weights(64, std::vector<double>(10));

    for (int out = 0; out < 10; out++)
    {
        for (int in = 0; in < 64; in++)
        {
            int idx = out * 64 + in;
            fc2_weights[in][out] = static_cast<double>(fc2_weight[idx]);
        }
    }

    std::vector<float> fc2_bias = load_binary_param(param_dir + "fc2.bias.bin");
    // bias dim: 10
    std::vector<double> fc2_bias_vec(10);
    for (int i = 0; i < 10; i++)
    {
        fc2_bias_vec[i] = static_cast<double>(fc2_bias[i]);
    }

    std::cout << BANNER << std::endl;
    std::cout << "POSEIDON SOFTWARE VERSION:" << POSEIDON_VERSION << std::endl;
    std::cout << "" << std::endl;
    ParametersLiteralDefault ckks_param_literal(CKKS, 16384, poseidon::sec_level_type::tc128);
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    const double scale = std::pow(2.0, 48);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    std::vector<int> galois_steps;

    KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, keygen.secret_key());

    Timestacs timestacs;
    // Create Input Images
    std::vector<std::vector<int>> image(28, std::vector<int>(28, 0));
    for (int i = 5; i < 28; ++i)
    {
        for (int j = 13; j < 16; ++j)
        {
            image[i][j] = 255;
        }
    }
    for (int i = 5; i < 8; ++i)
    {
        for (int j = 0; j < 16; ++j)
        {
            image[i][j] = 255;
        }
    }

    std::vector<double> msg_image;
    msg_image = preprocess_image(image, 7, 3);

    Plaintext plt_image, plt_res_image;
    std::vector<complex<double>> msg_res_image;
    encoder.encode(msg_image, scale, plt_image);
    Ciphertext ct_image;
    encryptor.encrypt(plt_image, ct_image);
    std::vector<Ciphertext> ct_mult(4);
    std::vector<Ciphertext> ct_sum(4);
    std::vector<Plaintext> plain_conv_weight(4);
    timestacs.start();
    // Convolution Layer
    // Using Im2Col methods to rotate and add
    for (int i = 0; i < 4; ++i)
    {
        plain_conv_weight[i] =
            encode_with_consistent_level(conv_kernels_replicated[i], ct_image, encoder);
        ckks_eva->multiply_plain(ct_image, plain_conv_weight[i], ct_mult[i]);
        ckks_eva->rescale(ct_mult[i], ct_mult[i]);
        ct_sum[i] = ct_mult[i];
        for (int shift = 1; shift < 49; ++shift)
        {
            Ciphertext ct_rotated;
            ckks_eva->rotate(ct_mult[i], ct_rotated, shift * 64, galois_keys);
            ckks_eva->add(ct_sum[i], ct_rotated, ct_sum[i]);
        }
    }

    std::vector<double> mask_1(3136, 0.0);
    for (int i = 0; i < 3136; ++i)
    {
        if (i < 64)
        {
            mask_1[i] = 1.0;
        }
    }

    Plaintext plain_mask_1 = encode_with_consistent_level(mask_1, ct_sum[0], encoder);
    for (int i = 0; i < 4; ++i)
    {
        ckks_eva->multiply_plain(ct_sum[i], plain_mask_1, ct_sum[i]);
        ckks_eva->rescale(ct_sum[i], ct_sum[i]);
    }

    Ciphertext ct_conv_compressed = ct_sum[0];
    for (int i = 1; i < 4; ++i)
    {
        Ciphertext ct_shifted;
        ckks_eva->rotate(ct_sum[i], ct_shifted, -i * 64, galois_keys);
        ckks_eva->add(ct_shifted, ct_conv_compressed, ct_conv_compressed);
    }

    Plaintext plain_conv_bias =
        encode_with_consistent_level(conv_bias_replicated, ct_conv_compressed, encoder);
    // add bias
    ckks_eva->add_plain(ct_conv_compressed, plain_conv_bias, ct_conv_compressed);
    ckks_eva->multiply_relin(ct_conv_compressed, ct_conv_compressed, ct_conv_compressed,
                             relin_keys);
    ckks_eva->rescale(ct_conv_compressed, ct_conv_compressed);
    // finish convlution.

    Ciphertext ct_fc1;
    MatrixPlain mplt_fc1_weight =
        gen_matrix(fc1_weights, context, encoder, ckks_param_literal, ct_conv_compressed);
    ckks_eva->multiply_by_diag_matrix_bsgs(ct_conv_compressed, mplt_fc1_weight, ct_fc1,
                                           galois_keys);
    Plaintext plt_fc1_bias;
    plt_fc1_bias = encode_with_consistent_level(fc1_bias_vec, ct_fc1, encoder);
    ckks_eva->add_plain(ct_fc1, plt_fc1_bias, ct_fc1);
    ckks_eva->multiply_relin(ct_fc1, ct_fc1, ct_fc1, relin_keys);
    ckks_eva->rescale(ct_fc1, ct_fc1);

    Ciphertext ct_fc2;
    MatrixPlain mplt_fc2_weight =
        gen_matrix(fc2_weights, context, encoder, ckks_param_literal, ct_fc1);
    ckks_eva->multiply_by_diag_matrix_bsgs(ct_fc1, mplt_fc2_weight, ct_fc2, galois_keys);
    Plaintext plt_fc2_bias;
    plt_fc2_bias = encode_with_consistent_level(fc2_bias_vec, ct_fc2, encoder);
    ckks_eva->add_plain(ct_fc2, plt_fc2_bias, ct_fc2);
    timestacs.end();

    // Verification code
    // Convolution
    std::vector<std::vector<double>> verify_conv(4, std::vector<double>(3136));
    for (int j = 0; j < 4; ++j)
    {
        std::vector<double> mult(3136);
        std::vector<double> result(3136);
        for (int i = 0; i < msg_image.size(); ++i)
        {
            mult[i] = msg_image[i] * conv_kernels_replicated[j][i];
        }
        result = mult;
        for (int shift = 1; shift < 49; ++shift)
        {
            std::rotate(mult.begin(), mult.begin() + 64, mult.end());
            for (int i = 0; i < msg_image.size(); ++i)
            {
                result[i] = result[i] + mult[i];
            }
        }
        for (int i = 0; i < 3136; ++i)
        {
            if (i > 63)
            {
                result[i] = 0.0;
            }
        }
        verify_conv[j] = result;
    }

    std::vector<double> result;
    for (int j = 0; j < 4; ++j)
    {
        for (int i = 0; i < 64; ++i)
        {
            result.push_back(verify_conv[j][i]);
        }
    }

    for (int i = 0; i < 256; ++i)
    {
        result[i] = result[i] + conv_bias_replicated[i];
        result[i] = result[i] * result[i];
    }
    // fc layer
    result = matrixVectorMultiply(fc1_weights, result);
    for (int i = 0; i < 64; ++i)
    {
        result[i] = result[i] + fc1_bias_vec[i];
        result[i] = result[i] * result[i];
    }
    result = matrixVectorMultiply(fc2_weights, result);
    for (int i = 0; i < 10; ++i)
    {
        result[i] = result[i] + fc2_bias_vec[i];
    }

    std::vector<double> result_1(10, 0.0);
    for (int i = 0; i < 10; ++i)
    {
        result_1[i] = result[i];
    }
    result = softmax(result_1);

    decryptor.decrypt(ct_fc2, plt_res_image);
    encoder.decode(plt_res_image, msg_res_image);
    std::vector<double> msg_res = take_real(msg_res_image);
    std::vector<double> msg_res_1(10, 0.0);
    for (int i = 0; i < 10; ++i)
    {
        msg_res_1[i] = msg_res[i];
    }

    std::vector<double> msg_result;
    msg_result = softmax(msg_res_1);
    for (int i = 0; i < 10; ++i)
    {
        std::cout << i << " plaintext probability: " << result[i] << std::endl;
        std::cout << i << " encrypted probability: " << msg_result[i] << std::endl << std::endl;
    }

    timestacs.print_time("CNN TIME: ");
    return 0;
}
