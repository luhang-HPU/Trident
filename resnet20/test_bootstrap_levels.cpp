#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/parameters_literal.h"

#include <chrono>
#include <complex>
#include <cstdlib>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace poseidon;
using namespace std;

namespace
{

vector<uint32_t> logq_chain()
{
    uint32_t prefix_46_count = 3;
    if (const char *value = std::getenv("BOOTSTRAP_PREFIX_46_COUNT"))
    {
        char *end = nullptr;
        const auto parsed = std::strtoul(value, &end, 10);
        if (end != value && *end == '\0')
        {
            prefix_46_count = static_cast<uint32_t>(parsed);
        }
    }

    constexpr uint32_t total_prime_count = 21;
    prefix_46_count = min(prefix_46_count, total_prime_count);
    vector<uint32_t> chain(total_prime_count, 51);
    for (uint32_t i = 0; i < prefix_46_count; ++i)
    {
        chain[i] = 46;
    }
    return chain;
}

uint32_t read_env_u32(const char *name, uint32_t fallback)
{
    const char *value = std::getenv(name);
    if (!value || *value == '\0')
    {
        return fallback;
    }
    char *end = nullptr;
    const auto parsed = std::strtoul(value, &end, 10);
    if (end == value || *end != '\0')
    {
        throw invalid_argument(string("invalid integer environment variable: ") + name);
    }
    return static_cast<uint32_t>(parsed);
}

bool read_env_bool(const char *name, bool fallback = false)
{
    const char *value = std::getenv(name);
    if (!value || *value == '\0')
    {
        return fallback;
    }
    return value[0] != '0';
}

double chebyshev_eval(const Polynomial &poly, complex<double> x)
{
    const auto &coeffs = poly.data();
    if (coeffs.empty())
    {
        return 0.0;
    }
    if (coeffs.size() == 1)
    {
        return (coeffs[0]).real();
    }

    complex<double> t_prev = 1.0;
    complex<double> t_curr = x;
    complex<double> value = coeffs[0] + coeffs[1] * t_curr;
    for (size_t i = 2; i < coeffs.size(); ++i)
    {
        complex<double> t_next = 2.0 * x * t_curr - t_prev;
        value += coeffs[i] * t_next;
        t_prev = t_curr;
        t_curr = t_next;
    }
    return value.real();
}

complex<double> eval_mod_plain(const EvalModPoly &poly, complex<double> x)
{
    if (poly.type() == CosDiscrete || poly.type() == CosContinuous)
    {
        x += -0.5 / (poly.sc_fac() * (poly.sine_poly_b() - poly.sine_poly_a()));
    }

    double y = chebyshev_eval(poly.sine_poly(), x);
    double sqrt2pi = poly.sqrt_2pi();
    for (uint32_t i = 0; i < poly.double_angle(); ++i)
    {
        sqrt2pi *= sqrt2pi;
        y = 2.0 * y * y - sqrt2pi;
    }
    return {y, 0.0};
}

size_t chain_index_or_throw(const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }
    return context_data->chain_index();
}

void print_cipher_state(const string &label, const PoseidonContext &context, const Ciphertext &cipher)
{
    auto context_data = context.crt_context()->get_context_data(cipher.parms_id());
    if (!context_data)
    {
        throw runtime_error("failed to locate ciphertext parms_id in Poseidon context");
    }

    cout << label << '\n';
    cout << "  remaining level : " << context_data->chain_index() << '\n';
    cout << "  coeff_modulus_size : " << cipher.coeff_modulus_size() << '\n';
    cout << "  scale : " << cipher.scale() << '\n';
}

void print_plain_preview(const string &label, const vector<complex<double>> &values)
{
    cout << label;
    const size_t preview_count = min<size_t>(8, values.size());
    for (size_t i = 0; i < preview_count; ++i)
    {
        cout << ' ' << values[i].real();
    }
    cout << '\n';
}

void print_value_stats(const string &label, const vector<complex<double>> &values,
                       const EvalModPoly *poly = nullptr)
{
    double min_real = numeric_limits<double>::infinity();
    double max_real = -numeric_limits<double>::infinity();
    double min_imag = numeric_limits<double>::infinity();
    double max_imag = -numeric_limits<double>::infinity();
    double max_abs = 0.0;
    double max_cheb_domain_abs = 0.0;
    size_t max_abs_index = 0;
    size_t max_domain_index = 0;

    for (size_t i = 0; i < values.size(); ++i)
    {
        const auto value = values[i];
        min_real = min(min_real, value.real());
        max_real = max(max_real, value.real());
        min_imag = min(min_imag, value.imag());
        max_imag = max(max_imag, value.imag());
        const double abs_value = abs(value);
        if (abs_value > max_abs)
        {
            max_abs = abs_value;
            max_abs_index = i;
        }

        if (poly)
        {
            const double cheb_domain_abs =
                abs(value.real() - 0.5 / (poly->sc_fac() *
                                           (poly->sine_poly_b() - poly->sine_poly_a())));
            if (cheb_domain_abs > max_cheb_domain_abs)
            {
                max_cheb_domain_abs = cheb_domain_abs;
                max_domain_index = i;
            }
        }
    }

    cout << label << '\n';
    cout << "  real range : [" << min_real << ", " << max_real << "]\n";
    cout << "  imag range : [" << min_imag << ", " << max_imag << "]\n";
    cout << "  max abs : " << max_abs << " at slot " << max_abs_index << '\n';
    if (poly)
    {
        cout << "  shifted Chebyshev input max abs : " << max_cheb_domain_abs
             << " at slot " << max_domain_index
             << " (expected <= 1 for ApproximateCos basis)\n";
    }
}

vector<complex<double>> decrypt_and_decode(const Ciphertext &cipher, Decryptor &decryptor,
                                           CKKSEncoder &encoder)
{
    Plaintext plain;
    vector<complex<double>> decoded;
    decryptor.decrypt(cipher, plain);
    encoder.decode(plain, decoded);
    return decoded;
}

Ciphertext reencrypt_like(const Ciphertext &source, Decryptor &decryptor, CKKSEncoder &encoder,
                          Encryptor &encryptor)
{
    Plaintext decoded_plain;
    vector<complex<double>> decoded;
    decryptor.decrypt(source, decoded_plain);
    encoder.decode(decoded_plain, decoded);

    Plaintext fresh_plain;
    encoder.encode(decoded, source.parms_id(), source.scale(), fresh_plain);

    Ciphertext fresh;
    encryptor.encrypt(fresh_plain, fresh);
    return fresh;
}

void print_error_stats(const string &label, const vector<complex<double>> &actual,
                       const vector<complex<double>> &expected)
{
    const size_t count = min(actual.size(), expected.size());
    double max_abs_error = 0.0;
    double abs_sum = 0.0;
    double l2_sum = 0.0;
    size_t max_index = 0;

    for (size_t i = 0; i < count; ++i)
    {
        const double err = abs(actual[i] - expected[i]);
        abs_sum += err;
        l2_sum += err * err;
        if (err > max_abs_error)
        {
            max_abs_error = err;
            max_index = i;
        }
    }

    const double rmse = count == 0 ? 0.0 : sqrt(l2_sum / static_cast<double>(count));
    const double mae = count == 0 ? 0.0 : abs_sum / static_cast<double>(count);
    cout << label << '\n';
    cout << "  max abs error : " << max_abs_error << " at slot " << max_index << '\n';
    cout << "  mean abs error : " << mae << '\n';
    cout << "  rmse : " << rmse << '\n';
}

vector<complex<double>> eval_mod_plain_vector(const vector<complex<double>> &input,
                                              const EvalModPoly &poly)
{
    vector<complex<double>> output(input.size());
    for (size_t i = 0; i < input.size(); ++i)
    {
        output[i] = eval_mod_plain(poly, input[i]);
    }
    return output;
}

void run_manual_bootstrap(Ciphertext bootstrap_input, const vector<complex<double>> &message,
                          const PoseidonContext &context, EvaluatorCkksBase &evaluator,
                          const RelinKeys &relin_keys, const GaloisKeys &rot_keys,
                          CKKSEncoder &encoder, Encryptor &encryptor, Decryptor &decryptor,
                          EvalModPoly &eval_mod_poly)
{
    const bool reencrypt_cts = read_env_bool("BOOTSTRAP_REENCRYPT_CTS");
    const bool reencrypt_evalmod = read_env_bool("BOOTSTRAP_REENCRYPT_EVALMOD");

    cout << "manual bootstrap options:"
         << " reencrypt_cts=" << reencrypt_cts
         << " reencrypt_evalmod=" << reencrypt_evalmod << '\n';

    auto result = bootstrap_input;
    const auto bootstrap_ratio = eval_mod_poly.message_ratio();
    auto input_context_data = context.crt_context()->get_context_data(result.parms_id());
    const auto q0_level = input_context_data->parms().q0_level();
    auto q0_over_message_ratio = context.crt_context()->q0();
    q0_over_message_ratio = exp2(round(log2(q0_over_message_ratio / static_cast<double>(bootstrap_ratio))));

    auto level = result.level();
    auto level_diff = level - q0_level;
    if (level_diff > 1)
    {
        auto parms_id = context.crt_context()->parms_id_map().at(q0_level + 1);
        evaluator.drop_modulus(result, result, parms_id);
    }

    auto scale = round(q0_over_message_ratio / result.scale());
    if (scale > 1)
    {
        evaluator.multiply_const_direct(result, static_cast<int>(scale), result, encoder);
        result.scale() *= scale;
    }

    auto parms_id = context.crt_context()->parms_id_map().at(q0_level);
    evaluator.drop_modulus(result, result, parms_id);

    Ciphertext ciph_raise;
    evaluator.read(result);
    evaluator.raise_modulus(result, ciph_raise);
    print_cipher_state("manual after raise_modulus", context, ciph_raise);

    auto scale_raise = eval_mod_poly.scaling_factor() / ciph_raise.scale();
    scale_raise /= eval_mod_poly.message_ratio();
    if (scale_raise > 1 && scale_raise < 0x7FFFFFFF)
    {
        evaluator.multiply_const_direct(ciph_raise, static_cast<int>(scale_raise), ciph_raise, encoder);
        ciph_raise.scale() *= scale_raise;
    }
    else if (scale_raise > 0x7FFFFFFF)
    {
        evaluator.multiply_const(ciph_raise, 1.0, scale_raise, ciph_raise, encoder);
    }

    auto coeffs_to_slots_scaling =
        eval_mod_poly.q_div() /
        (eval_mod_poly.k() * eval_mod_poly.sc_fac() * eval_mod_poly.q_diff());
    HomomorphicDFTMatrixLiteral coeff_to_slot_literal(
        0, context.parameters_literal()->log_n(), context.parameters_literal()->log_slots(),
        static_cast<uint32_t>(context.parameters_literal()->q().size() - 1),
        vector<uint32_t>(3, 1), true, coeffs_to_slots_scaling, false, 1);
    LinearMatrixGroup coeff_to_slot_matrix;
    coeff_to_slot_literal.create(coeff_to_slot_matrix, encoder, 2);

    Ciphertext ciph_real, ciph_imag;
    evaluator.coeff_to_slot(ciph_raise, coeff_to_slot_matrix, ciph_real, ciph_imag, rot_keys, encoder);
    print_cipher_state("manual after coeff_to_slot real", context, ciph_real);
    print_cipher_state("manual after coeff_to_slot imag", context, ciph_imag);
    auto cts_real_plain = decrypt_and_decode(ciph_real, decryptor, encoder);
    auto cts_imag_plain = decrypt_and_decode(ciph_imag, decryptor, encoder);
    print_plain_preview("manual coeff_to_slot real preview:", cts_real_plain);
    print_plain_preview("manual coeff_to_slot imag preview:", cts_imag_plain);
    print_value_stats("manual coeff_to_slot real stats:", cts_real_plain, &eval_mod_poly);
    print_value_stats("manual coeff_to_slot imag stats:", cts_imag_plain, &eval_mod_poly);

    if (reencrypt_cts)
    {
        ciph_real = reencrypt_like(ciph_real, decryptor, encoder, encryptor);
        ciph_imag = reencrypt_like(ciph_imag, decryptor, encoder, encryptor);
        print_cipher_state("manual after coeff_to_slot reencrypt real", context, ciph_real);
        print_cipher_state("manual after coeff_to_slot reencrypt imag", context, ciph_imag);
        cts_real_plain = decrypt_and_decode(ciph_real, decryptor, encoder);
        cts_imag_plain = decrypt_and_decode(ciph_imag, decryptor, encoder);
    }

    eval_mod_poly.set_level_start(static_cast<uint32_t>(
        context.crt_context()->get_context_data(ciph_real.parms_id())->level()));
    Ciphertext ciph_real_mod, ciph_imag_mod;
    evaluator.eval_mod(ciph_imag, ciph_imag_mod, eval_mod_poly, relin_keys, encoder);
    evaluator.eval_mod(ciph_real, ciph_real_mod, eval_mod_poly, relin_keys, encoder);
    print_cipher_state("manual after eval_mod imag", context, ciph_imag_mod);
    print_cipher_state("manual after eval_mod real", context, ciph_real_mod);
    auto evalmod_real_plain = decrypt_and_decode(ciph_real_mod, decryptor, encoder);
    auto evalmod_imag_plain = decrypt_and_decode(ciph_imag_mod, decryptor, encoder);
    const auto evalmod_real_expected = eval_mod_plain_vector(cts_real_plain, eval_mod_poly);
    const auto evalmod_imag_expected = eval_mod_plain_vector(cts_imag_plain, eval_mod_poly);
    print_plain_preview("manual eval_mod real decrypt preview:", evalmod_real_plain);
    print_plain_preview("manual eval_mod real plain-sim preview:", evalmod_real_expected);
    print_error_stats("manual eval_mod real error vs plain simulation:",
                      evalmod_real_plain, evalmod_real_expected);
    print_error_stats("manual eval_mod imag error vs plain simulation:",
                      evalmod_imag_plain, evalmod_imag_expected);

    ciph_imag_mod.scale() = context.parameters_literal()->scale();
    ciph_real_mod.scale() = context.parameters_literal()->scale();
    auto evalmod_real_after_scale_reset = decrypt_and_decode(ciph_real_mod, decryptor, encoder);
    auto evalmod_imag_after_scale_reset = decrypt_and_decode(ciph_imag_mod, decryptor, encoder);
    print_value_stats("manual eval_mod real stats after scale reset:", evalmod_real_after_scale_reset);
    print_value_stats("manual eval_mod imag stats after scale reset:", evalmod_imag_after_scale_reset);

    if (reencrypt_evalmod)
    {
        ciph_real_mod = reencrypt_like(ciph_real_mod, decryptor, encoder, encryptor);
        ciph_imag_mod = reencrypt_like(ciph_imag_mod, decryptor, encoder, encryptor);
        print_cipher_state("manual after eval_mod reencrypt real", context, ciph_real_mod);
        print_cipher_state("manual after eval_mod reencrypt imag", context, ciph_imag_mod);
    }

    auto slots_to_coeffs_scaling =
        context.parameters_literal()->scale() /
        (static_cast<double>(eval_mod_poly.scaling_factor()) /
         static_cast<double>(eval_mod_poly.message_ratio()));
    HomomorphicDFTMatrixLiteral slot_to_coeff_literal(
        1, context.parameters_literal()->log_n(), context.parameters_literal()->log_slots(),
        static_cast<uint32_t>(context.crt_context()->get_context_data(ciph_real_mod.parms_id())->level()),
        vector<uint32_t>(3, 1), true, slots_to_coeffs_scaling, false, 1);
    LinearMatrixGroup slot_to_coeff_matrix;
    slot_to_coeff_literal.create(slot_to_coeff_matrix, encoder, 1);

    Ciphertext manual_output;
    evaluator.slot_to_coeff(ciph_real_mod, ciph_imag_mod, slot_to_coeff_matrix, manual_output,
                            rot_keys, encoder);
    print_cipher_state("manual bootstrap output", context, manual_output);

    auto decoded = decrypt_and_decode(manual_output, decryptor, encoder);
    print_plain_preview("manual bootstrap output decrypt preview:", decoded);
    print_error_stats("manual bootstrap output error vs source:", decoded, message);
}

} // namespace

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    ParametersLiteral ckks_param_literal{CKKS, 16, 16 - 1, 46, 5, 1, 0, {}, {}};
    const auto q_chain = logq_chain();
    ckks_param_literal.set_log_modulus(q_chain, {51});
    size_t prefix_46_count = 0;
    while (prefix_46_count < q_chain.size() && q_chain[prefix_46_count] == 46)
    {
        ++prefix_46_count;
    }
    cout << "logq chain summary: total=" << q_chain.size()
         << " prefix_46_count=" << prefix_46_count << '\n';

    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    auto ckks_eva = PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    KeyGenerator kgen(context);
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys rot_keys;
    kgen.create_public_key(public_key);
    kgen.create_relin_keys(relin_keys);
    kgen.create_galois_keys(rot_keys);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key, kgen.secret_key());
    Decryptor decryptor(context, kgen.secret_key());

    const size_t slot_count = encoder.slot_count();
    vector<complex<double>> message(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < slot_count; ++i)
    {
        message[i] = {sin(static_cast<double>(i) / 32.0), 0.0};
    }
    print_plain_preview("plaintext source preview:", message);

    Plaintext plain;
    encoder.encode(message, ckks_param_literal.scale(), plain);

    Ciphertext cipher;
    encryptor.encrypt(plain, cipher);
    print_cipher_state("fresh ciphertext", context, cipher);

    while (chain_index_or_throw(context, cipher) > 1)
    {
        ckks_eva->drop_modulus_to_next(cipher, cipher);
    }
    print_cipher_state("after dropping to level 0", context, cipher);

    Ciphertext bootstrap_input = cipher;
    print_cipher_state("bootstrap input", context, bootstrap_input);
    auto before_bootstrap = decrypt_and_decode(bootstrap_input, decryptor, encoder);
    print_plain_preview("bootstrap input decrypt preview:", before_bootstrap);
    print_error_stats("bootstrap input error vs source:", before_bootstrap, message);

    const bool high_precision = read_env_bool("BOOTSTRAP_HIGH_PRECISION");
    const uint32_t log_message_ratio =
        read_env_u32("BOOTSTRAP_LOG_MESSAGE_RATIO", high_precision ? 10 : 16);
    const uint32_t double_angle = read_env_u32("BOOTSTRAP_DOUBLE_ANGLE", 3);
    const uint32_t k = read_env_u32("BOOTSTRAP_K", high_precision ? 25 : 16);
    const uint32_t arcsine_degree = read_env_u32("BOOTSTRAP_ARCSINE_DEGREE", 0);
    const uint32_t sine_degree = read_env_u32("BOOTSTRAP_SINE_DEGREE", 59);
    const uint32_t scaling_log = read_env_u32("BOOTSTRAP_SCALING_LOG", 51);
    cout << "bootstrap polynomial params:"
         << " high_precision=" << high_precision
         << " log_message_ratio=" << log_message_ratio
         << " double_angle=" << double_angle
         << " k=" << k
         << " arcsine_degree=" << arcsine_degree
         << " sine_degree=" << sine_degree
         << " scaling_log=" << scaling_log << '\n';

    EvalModPoly eval_mod_poly(context, CosDiscrete, ldexp(1.0, static_cast<int>(scaling_log)), 1,
                              log_message_ratio, double_angle, k, arcsine_degree, sine_degree);

    if (read_env_bool("BOOTSTRAP_MANUAL"))
    {
        const auto time_start = chrono::high_resolution_clock::now();
        run_manual_bootstrap(bootstrap_input, message, context, *ckks_eva, relin_keys, rot_keys,
                             encoder, encryptor, decryptor, eval_mod_poly);
        const auto time_end = chrono::high_resolution_clock::now();
        cout << "manual bootstrap time (ms) : "
             << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count()
             << '\n';
        return 0;
    }

    const size_t level_before = chain_index_or_throw(context, bootstrap_input);
    const auto time_start = chrono::high_resolution_clock::now();
    if (high_precision)
    {
        ckks_eva->bootstrap_high_precision(bootstrap_input, bootstrap_input, relin_keys,
                                           rot_keys, encoder, eval_mod_poly);
    }
    else
    {
        ckks_eva->bootstrap(bootstrap_input, bootstrap_input, relin_keys, rot_keys, encoder,
                            eval_mod_poly);
    }
    const auto time_end = chrono::high_resolution_clock::now();
    const size_t level_after = chain_index_or_throw(context, bootstrap_input);

    print_cipher_state("bootstrap output", context, bootstrap_input);
    cout << "bootstrap time (ms) : "
         << chrono::duration_cast<chrono::milliseconds>(time_end - time_start).count() << '\n';
    cout << "level delta : " << static_cast<long long>(level_after) - static_cast<long long>(level_before)
         << '\n';

    auto after_bootstrap = decrypt_and_decode(bootstrap_input, decryptor, encoder);
    print_plain_preview("bootstrap output decrypt preview:", after_bootstrap);
    print_error_stats("bootstrap output error vs source:", after_bootstrap, message);
    print_error_stats("bootstrap output delta vs input decrypt:", after_bootstrap, before_bootstrap);

    return 0;
}
