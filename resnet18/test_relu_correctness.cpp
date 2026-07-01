#include "encrypted_ops.h"
#include "infer_config.h"
#include "infer_runtime.h"
#include "tensor_cipher.h"

#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

constexpr size_t kPreviewCount = 16;

struct ErrorStats
{
    double max_abs_error = 0.0;
    double max_abs_error_far = 0.0;
    double mean_abs_error = 0.0;
    double max_negative_leak = 0.0;
    double max_positive_error = 0.0;
    size_t far_count = 0;
};

vector<double> decode_real_values(const TensorCipher &tensor, PoseidonRuntime &runtime,
                                  size_t count)
{
    Plaintext plain;
    runtime.decryptor.decrypt(tensor.cipher(), plain);

    vector<complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);

    vector<double> values(min(count, decoded.size()), 0.0);
    for (size_t i = 0; i < values.size(); ++i)
    {
        values[i] = decoded[i].real();
    }
    return values;
}

void drop_to_chain_index(TensorCipher &tensor, size_t target_chain, PoseidonRuntime &runtime)
{
    while (cipher_chain_index(runtime, tensor.cipher()) > target_chain)
    {
        Ciphertext dropped;
        runtime.evaluator->drop_modulus_to_next(tensor.cipher(), dropped);
        tensor.set_ciphertext(dropped);
    }
}

int next_rescale_prime_bits(const Ciphertext &cipher, PoseidonRuntime &runtime)
{
    auto context_data = runtime.context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id in relu test");
    }
    const auto &modulus = context_data->coeff_modulus();
    if (modulus.empty())
    {
        throw runtime_error("ciphertext has no coeff modulus in relu test");
    }
    return modulus.back().bit_count();
}

void drop_trailing_51_bit_primes(TensorCipher &tensor, PoseidonRuntime &runtime)
{
    size_t dropped = 0;
    while (next_rescale_prime_bits(tensor.cipher(), runtime) == 51)
    {
        Ciphertext next;
        runtime.evaluator->drop_modulus_to_next(tensor.cipher(), next);
        tensor.set_ciphertext(next);
        ++dropped;
    }
    cout << "dropped trailing 51-bit primes: " << dropped
         << ", chain_index=" << cipher_chain_index(runtime, tensor.cipher())
         << ", next_prime_bits=" << next_rescale_prime_bits(tensor.cipher(), runtime)
         << '\n';
}

vector<double> exact_relu(const vector<double> &values)
{
    vector<double> output = values;
    for (double &value : output)
    {
        value = max(0.0, value);
    }
    return output;
}

vector<double> exact_step(const vector<double> &values)
{
    vector<double> output = values;
    for (double &value : output)
    {
        value = value >= 0.0 ? 1.0 : 0.0;
    }
    return output;
}

ErrorStats compute_error_stats(const vector<double> &input, const vector<double> &actual,
                               double far_threshold)
{
    if (input.size() != actual.size())
    {
        throw invalid_argument("relu test input/output size mismatch");
    }

    ErrorStats stats;
    double sum_abs_error = 0.0;
    for (size_t i = 0; i < input.size(); ++i)
    {
        const double expected = max(0.0, input[i]);
        const double error = actual[i] - expected;
        const double abs_error = fabs(error);
        stats.max_abs_error = max(stats.max_abs_error, abs_error);
        sum_abs_error += abs_error;
        if (fabs(input[i]) >= far_threshold)
        {
            stats.max_abs_error_far = max(stats.max_abs_error_far, abs_error);
            ++stats.far_count;
        }
        if (input[i] < 0.0)
        {
            stats.max_negative_leak = max(stats.max_negative_leak, fabs(actual[i]));
        }
        else
        {
            stats.max_positive_error = max(stats.max_positive_error, abs_error);
        }
    }
    stats.mean_abs_error = input.empty() ? 0.0 : sum_abs_error / static_cast<double>(input.size());
    return stats;
}

void print_preview(const string &label, const vector<double> &values)
{
    cout << label;
    const size_t preview_count = min(kPreviewCount, values.size());
    for (size_t i = 0; i < preview_count; ++i)
    {
        cout << ' ' << values[i];
    }
    cout << '\n';
}

void run_relu_case(const string &label, const vector<double> &message, size_t target_chain,
                   bool drop_51_first, double far_threshold, PoseidonRuntime &runtime,
                   const ReluConfig &relu_config)
{
    cout << "\n=== " << label << " ===\n";
    TensorCipher input(static_cast<int>(default_poseidon_plan().logN), 1, 1, 1, 1, 1, 1,
                       message, runtime.encryptor, runtime.encoder,
                       default_poseidon_plan().log_scale);
    drop_to_chain_index(input, target_chain, runtime);
    if (drop_51_first)
    {
        drop_trailing_51_bit_primes(input, runtime);
    }

    cout << "input chain_index=" << cipher_chain_index(runtime, input.cipher())
         << ", coeff_modulus_size=" << input.cipher().coeff_modulus_size()
         << ", scale=" << input.cipher().scale()
         << ", next_prime_bits=" << next_rescale_prime_bits(input.cipher(), runtime)
         << '\n';

    Ciphertext mask = approximate_sign(input.cipher(), relu_config.deg, relu_config.alpha,
                                       relu_config.tree, relu_config.scaled_val,
                                       runtime.encryptor, runtime.encoder,
                                       *runtime.evaluator, runtime.relin_keys);
    TensorCipher mask_tensor(static_cast<int>(default_poseidon_plan().logN), 1, 1, 1, 1, 1, 1,
                             mask);
    vector<double> decoded_mask = decode_real_values(mask_tensor, runtime, message.size());
    vector<double> expected_step = exact_step(message);
    const ErrorStats mask_stats = compute_error_stats(expected_step, decoded_mask, 0.5);

    Ciphertext relu_cipher;
    runtime.evaluator->multiply_relin_dynamic(input.cipher(), mask, relu_cipher,
                                              runtime.relin_keys);
    runtime.evaluator->rescale(relu_cipher, relu_cipher);
    assign_scale_for_relu_reference(relu_cipher, runtime.scale);

    TensorCipher output(static_cast<int>(default_poseidon_plan().logN), 1, 1, 1, 1, 1, 1,
                        relu_cipher);

    cout << "output chain_index=" << cipher_chain_index(runtime, output.cipher())
         << ", coeff_modulus_size=" << output.cipher().coeff_modulus_size()
         << ", scale=" << output.cipher().scale() << '\n';

    vector<double> actual = decode_real_values(output, runtime, message.size());
    vector<double> expected = exact_relu(message);
    const ErrorStats stats = compute_error_stats(message, actual, far_threshold);

    print_preview("input preview:", message);
    print_preview("mask expected preview:", expected_step);
    print_preview("mask actual preview:", decoded_mask);
    print_preview("expected preview:", expected);
    print_preview("actual preview:", actual);
    cout << "mask max_abs_error=" << mask_stats.max_abs_error
         << ", mask mean_abs_error=" << mask_stats.mean_abs_error
         << ", mask max_positive_error=" << mask_stats.max_positive_error << '\n';
    cout << "max_abs_error=" << stats.max_abs_error
         << ", mean_abs_error=" << stats.mean_abs_error
         << ", far_threshold=" << far_threshold
         << ", far_count=" << stats.far_count
         << ", max_abs_error_far=" << stats.max_abs_error_far
         << ", max_negative_leak=" << stats.max_negative_leak
         << ", max_positive_error=" << stats.max_positive_error << '\n';
}

vector<double> make_symmetric_probe(size_t slot_count)
{
    vector<double> values(slot_count, 0.0);
    for (size_t i = 0; i < slot_count; ++i)
    {
        const double t = static_cast<double>(i % 257) / 256.0;
        values[i] = -0.4 + 0.8 * t;
    }
    return values;
}

vector<double> make_stem_like_probe(size_t slot_count)
{
    vector<double> values(slot_count, 0.0);
    for (size_t i = 0; i < slot_count; ++i)
    {
        const double a = sin(static_cast<double>(i) * 0.013);
        const double b = cos(static_cast<double>(i) * 0.007);
        values[i] = 0.06 * a + 0.025 * b - 0.01;
    }
    return values;
}

vector<double> make_far_from_zero_probe(size_t slot_count)
{
    vector<double> values(slot_count, 0.0);
    for (size_t i = 0; i < slot_count; ++i)
    {
        const double magnitude = 0.2 + 0.8 * static_cast<double>(i % 113) / 112.0;
        values[i] = (i % 2 == 0) ? magnitude : -magnitude;
    }
    return values;
}

vector<double> make_sparse_active_probe(size_t slot_count)
{
    vector<double> values(slot_count, 0.0);
    for (size_t i = 0; i < min<size_t>(25088, slot_count); ++i)
    {
        values[i] = 0.04 * sin(static_cast<double>(i) * 0.031) - 0.015;
    }
    return values;
}

} // namespace

int main(int argc, char **argv)
{
    cout << unitbuf << setprecision(10);

    size_t target_chain = 35;
    if (argc >= 2)
    {
        target_chain = static_cast<size_t>(stoul(argv[1]));
    }
    bool drop_51_first = true;
    if (argc >= 3)
    {
        const string mode = argv[2];
        drop_51_first = !(mode == "keep51" || mode == "0" || mode == "false");
    }

    const PoseidonInferPlan plan = default_poseidon_plan();
    ReluConfig relu_config = default_relu_config(plan);

    PoseidonRuntime runtime = make_poseidon_runtime(plan, false);
    KeyGenerator keygen(runtime.context, runtime.secret_key);
    keygen.create_relin_keys(runtime.relin_keys);

    const size_t slot_count = static_cast<size_t>(runtime.slot_count);
    cout << "resnet18 relu correctness test\n";
    cout << "slot_count=" << slot_count << ", target_chain=" << target_chain
         << ", scale=" << runtime.scale
         << ", drop_51_first=" << (drop_51_first ? "true" : "false") << '\n';
    cout << "relu config: comp_no=" << relu_config.comp_no
         << ", alpha=" << relu_config.alpha
         << ", scaled_val=" << relu_config.scaled_val << ", deg=";
    for (int degree : relu_config.deg)
    {
        cout << ' ' << degree;
    }
    cout << '\n';

    run_relu_case("symmetric [-0.4, 0.4]", make_symmetric_probe(slot_count), target_chain,
                  drop_51_first, 0.10, runtime, relu_config);
    run_relu_case("stem-like near zero", make_stem_like_probe(slot_count), target_chain,
                  drop_51_first, 0.05, runtime, relu_config);
    run_relu_case("far from zero alternating", make_far_from_zero_probe(slot_count),
                  target_chain, drop_51_first, 0.10, runtime, relu_config);
    run_relu_case("sparse active slots, zero inactive tail", make_sparse_active_probe(slot_count),
                  target_chain, drop_51_first, 0.05, runtime, relu_config);

    return 0;
}
