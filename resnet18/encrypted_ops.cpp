#include "encrypted_ops.h"

#include "parallel_utils.h"
#include "progress_log.h"

#include "poseidon/plaintext.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

size_t slot_count_from_logn(int logn)
{
    if (logn < 1)
    {
        throw invalid_argument("logn should be positive");
    }
    return static_cast<size_t>(1) << (logn - 1);
}

double multiply_plain_scale(const Ciphertext &input, const CKKSEncoder &encoder)
{
    auto context_data = encoder.context().crt_context()->get_context_data(input.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id for plain scale selection");
    }
    return pow(2.0, static_cast<double>(context_data->coeff_modulus().back().bit_count()));
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

void add_assign_dynamic(Ciphertext &accumulator, const Ciphertext &term,
                        CKKSEncoder &encoder, EvaluatorCkksBase &evaluator)
{
    evaluator.add_dynamic(accumulator, term, accumulator, encoder);
}

void rotate_with_power_of_two_keys(const Ciphertext &input, Ciphertext &output, int steps,
                                   EvaluatorCkksBase &evaluator,
                                   const GaloisKeys &galois_keys)
{
    const long slot_count = static_cast<long>(input.poly_modulus_degree() / 2);
    steps = static_cast<int>((steps % slot_count + slot_count) % slot_count);

    if (steps == 0)
    {
        output = input;
        return;
    }

    Ciphertext current = input;
    int bit = 1;
    while (steps > 0)
    {
        if ((steps & bit) != 0)
        {
            Ciphertext rotated;
            evaluator.rotate(current, rotated, bit, galois_keys);
            current = std::move(rotated);
            steps -= bit;
        }
        bit <<= 1;
    }
    output = std::move(current);
}

} // namespace

void relu(const TensorCipher &input, TensorCipher &output, long component_count,
          const vector<int> &degrees, long alpha, const vector<Tree> &trees,
          double scaled_value, Encryptor &encryptor, EvaluatorCkksBase &evaluator,
          CKKSEncoder &encoder, RelinKeys &relin_keys, double scale)
{
    if (component_count != static_cast<long>(degrees.size()) || degrees.size() != trees.size())
    {
        throw invalid_argument("relu polynomial component count does not match degree/tree config");
    }

    Ciphertext mask = approximate_sign(input.cipher(), degrees, alpha, trees, scaled_value,
                                       encryptor, encoder, evaluator, relin_keys);

    Ciphertext relu_cipher;
    evaluator.multiply_relin_dynamic(input.cipher(), mask, relu_cipher, relin_keys);
    evaluator.rescale(relu_cipher, relu_cipher);
    assign_scale_for_relu_reference(relu_cipher, scale);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), relu_cipher);
}

void bootstrap_tensor(const TensorCipher &input, TensorCipher &output,
                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder ||
        !bootstrapper.relin_keys || !bootstrapper.galois_keys ||
        !bootstrapper.bootstrap_config)
    {
        throw invalid_argument("poseidon bootstrap context is incomplete");
    }

    Ciphertext result = input.cipher();
    bootstrapper.evaluator->bootstrap(
        result, result, *bootstrapper.relin_keys, *bootstrapper.galois_keys,
        *bootstrapper.encoder, *bootstrapper.bootstrap_config);
    normalize_bootstrap_output_scale(result, bootstrapper);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), result);
}

void normalize_bootstrap_output_scale(Ciphertext &cipher,
                                      PoseidonBootstrapContext &bootstrapper)
{
    if (!bootstrapper.context || !bootstrapper.evaluator || !bootstrapper.encoder)
    {
        throw invalid_argument("poseidon bootstrap scale context is incomplete");
    }

    const double target_scale = bootstrapper.context->parameters_literal()->scale();
    if (poseidon::util::are_approximate<double>(cipher.scale(), target_scale))
    {
        return;
    }

    auto context_data =
        bootstrapper.context->crt_context()->get_context_data(cipher.parms_id());
    if (!context_data || context_data->coeff_modulus().size() <= 1)
    {
        throw invalid_argument("bootstrap output has no level available for scale normalization");
    }

    const double current_scale = cipher.scale();
    const double q_last = static_cast<double>(context_data->coeff_modulus().back().value());
    const double plain_scale = target_scale * q_last / current_scale;
    if (!isfinite(plain_scale) || plain_scale < 1.0)
    {
        throw invalid_argument("invalid bootstrap output scale normalization factor");
    }

    Ciphertext normalized;
    bootstrapper.evaluator->multiply_const(cipher, 1.0, plain_scale, normalized,
                                           *bootstrapper.encoder);
    bootstrapper.evaluator->rescale(normalized, normalized);
    if (!poseidon::util::are_approximate<double>(normalized.scale(), target_scale))
    {
        throw runtime_error("failed to normalize bootstrap output scale");
    }
    normalized.scale() = target_scale;
    cipher = std::move(normalized);
}

void matrix_multiplication(const TensorCipher &input, TensorCipher &output,
                           const vector<double> &matrix, const vector<double> &bias,
                           int rows, int columns,
                           EvaluatorCkksBase &evaluator, GaloisKeys &galois_keys,
                           CKKSEncoder &encoder)
{
    if (static_cast<int>(matrix.size()) != rows * columns)
    {
        throw invalid_argument("the size of matrix is not rows*columns");
    }
    if (static_cast<int>(bias.size()) != rows)
    {
        throw invalid_argument("the size of bias is not rows");
    }

    const size_t slot_count = slot_count_from_logn(input.logn());
    vector<double> packed_bias(slot_count, 0.0);
    for (int row = 0; row < rows; ++row)
    {
        packed_bias[static_cast<size_t>(row)] = bias[static_cast<size_t>(row)];
    }

    auto make_diagonal = [&](int diagonal) {
        vector<double> weights(slot_count, 0.0);
        for (int row = 0; row < rows; ++row)
        {
            const int column = row + columns - 1 - diagonal;
            if (column >= 0 && column < columns)
            {
                weights[static_cast<size_t>(row)] =
                    matrix[static_cast<size_t>(row * columns + column)];
            }
        }
        return weights;
    };

    const size_t diagonal_count = static_cast<size_t>(rows + columns - 1);
    const size_t thread_count = resnet18_parallel_thread_count(diagonal_count);
    const size_t diagonals_per_thread =
        (diagonal_count + thread_count - 1) / thread_count;
    vector<Ciphertext> partial_sums(thread_count);
    vector<unsigned char> has_partial_sum(thread_count, 0);

    resnet18_progress_log() << "fully connected diagonal parallel threads: "
                            << thread_count << ", diagonals=" << diagonal_count
                            << endl;

    resnet18_parallel_for(thread_count, [&](size_t thread_index) {
        const size_t begin = thread_index * diagonals_per_thread;
        const size_t end = min(diagonal_count, begin + diagonals_per_thread);
        Ciphertext local_sum;
        bool has_local_sum = false;
        for (size_t diagonal = begin; diagonal < end; ++diagonal)
        {
            Ciphertext term;
            rotate_with_power_of_two_keys(
                input.cipher(), term,
                columns - 1 - static_cast<int>(diagonal), evaluator, galois_keys);
            multiply_by_vector_inplace(
                term, make_diagonal(static_cast<int>(diagonal)), encoder, evaluator);
            if (!has_local_sum)
            {
                local_sum = std::move(term);
                has_local_sum = true;
            }
            else
            {
                add_assign_dynamic(local_sum, term, encoder, evaluator);
            }
        }
        if (has_local_sum)
        {
            partial_sums.at(thread_index) = std::move(local_sum);
            has_partial_sum.at(thread_index) = 1;
        }
    });

    Ciphertext sum;
    bool has_sum = false;
    for (size_t thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        if (!has_partial_sum.at(thread_index))
        {
            continue;
        }
        if (!has_sum)
        {
            sum = std::move(partial_sums.at(thread_index));
            has_sum = true;
        }
        else
        {
            add_assign_dynamic(sum, partial_sums.at(thread_index), encoder, evaluator);
        }
    }
    if (!has_sum)
    {
        throw runtime_error("fully connected layer produced no encrypted terms");
    }

    Plaintext bias_plain;
    encoder.encode(packed_bias, sum.parms_id(), sum.scale(), bias_plain);
    evaluator.add_plain(sum, bias_plain, sum);

    output = TensorCipher(input.logn(), input.k(), input.h(), input.w(), input.c(), input.t(),
                          input.p(), sum);
}
