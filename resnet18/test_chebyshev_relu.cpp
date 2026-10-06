#include "chebyshev_relu.h"
#include "encrypted_ops.h"
#include "infer_runtime.h"

#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <stdexcept>

using namespace poseidon;

namespace
{
void require(bool condition, const char *message)
{
    if (!condition)
        throw std::runtime_error(message);
}
}

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        const int log_n = argc > 1 ? std::stoi(argv[1]) : 13;
        const bool single22 = argc > 2 && std::string(argv[2]) == "--single22";
        const bool test_bootstrap = single22 || (argc > 2 && std::string(argv[2]) == "--bootstrap");
        require(log_n >= 13 && log_n <= 16, "test logN must be in [13,16]");
        double max_plain_error = 0.0;
        for (int i = 0; i <= 20000; ++i)
        {
            const double x = -1.0 + 2.0 * i / 20000.0;
            const double y = chebyshev_relu_plain(x);
            require(std::isfinite(y), "non-finite plaintext approximation");
            max_plain_error = std::max(max_plain_error, std::abs(y - std::max(0.0, x)));
            require(std::abs(y - chebyshev_relu_plain(-x) - x) < 1e-12,
                    "ReLU odd-part symmetry failed");
        }
        // Interpolating polynomial must reproduce ReLU at its 472 nodes.
        for (int j = 0; j <= kChebyshevReluDegree; ++j)
        {
            const double x = std::cos(std::acos(-1.0) * (j + 0.5) /
                                      (kChebyshevReluDegree + 1));
            require(std::abs(chebyshev_relu_plain(x) - std::max(0.0, x)) < 1e-12,
                    "Chebyshev interpolation node mismatch");
        }
        require(max_plain_error < 0.002, "plaintext approximation error exceeded 0.002");
        std::cout << "plain_max_abs_error=" << max_plain_error << '\n';

        for (std::size_t dnum : {3, 4})
        {
            const auto old_plan = default_poseidon_plan(dnum);
            const auto new_plan = default_poseidon_plan(dnum, true);
            require(old_plan.compute_prime_count == 20 && old_plan.logq_chain.size() == 35,
                    "composite Q chain changed");
            require(new_plan.compute_prime_count == 16 && new_plan.logq_chain.size() == 31,
                    "Chebyshev Q chain was not shortened");
            const auto p = logp_chain(new_plan.logq_chain.size(), dnum);
            require(p.size() == (dnum == 4 ? 8 : 11), "unexpected shortened P chain");
            require((31 + p.size() - 1) / p.size() == dnum, "dnum mismatch");
        }
        // Use the same plan and runtime builder as production, not a duplicated chain.
        auto plan = default_poseidon_plan(4, true, single22);
        plan.logN = log_n;
        plan.log_slots = log_n - 1;
        auto runtime = make_poseidon_runtime(plan, false);
        require(static_cast<bool>(runtime.single22_poly) == single22, "wrong bootstrap backend");
        if (single22)
        {
            require(runtime.single22_poly->sine_poly().degree() == 22 &&
                    runtime.single22_poly->double_angle() == 3 &&
                    runtime.single22_poly->message_ratio() == 32,
                    "single22 parameter mismatch");
            bool invalid_plan_rejected = false;
            try { (void)default_poseidon_plan(4, false, true); }
            catch (const std::invalid_argument &) { invalid_plan_rejected = true; }
            require(invalid_plan_rejected, "single22 accepted composite ReLU");
        }
        auto &context = runtime.context;
        auto &evaluator = runtime.evaluator;
        auto &encoder = runtime.encoder;
        auto &encryptor = runtime.encryptor;
        auto &decryptor = runtime.decryptor;
        auto &rk = runtime.relin_keys;
        const auto &params = *context.parameters_literal();
        KeyGenerator keygen(context, runtime.secret_key);
        keygen.create_relin_keys(rk);
        require(params.q().size() == 31 && params.p().size() == 8,
                "runtime did not use the shortened Q/P chain");
        std::cout << "Q_primes=" << params.q().size() << ", P_primes=" << params.p().size() << '\n';
        std::vector<double> values(encoder.slot_count());
        for (std::size_t i = 0; i < values.size(); ++i)
            values[i] = -1.0 + 2.0 * i / (values.size() - 1);
        values[0] = 0.0;
        values[1] = -1.0;
        values[2] = 1.0;
        values[3] = -1e-6;
        values[4] = 1e-6;
        Plaintext plain;
        encoder.encode(values, params.scale(), plain);
        Ciphertext original;
        encryptor.encrypt(plain, original);

        // 12 -> 2 for internal activations, 16 -> 6 for the final head;
        // 16 is also the first ReLU's level after removing the bootstrap tail.
        for (int level : {single22 ? 14 : 12, 16})
        {
            std::vector<Ciphertext> trimmed{original};
            trim_bootstrap_relu_input(trimmed, runtime, level);
            const Ciphertext &input = trimmed.front();
            const auto start = std::chrono::steady_clock::now();
            const Ciphertext output = chebyshev_relu(input, *evaluator, encoder, rk, params.scale());
            require(output.level() == level - 10, "unexpected encrypted output level");
            require(std::abs(output.scale() / params.scale() - 1.0) < 1e-10,
                    "unexpected encrypted output scale");
            decryptor.decrypt(output, plain);
            std::vector<std::complex<double>> decoded;
            encoder.decode(plain, decoded);
            double max_he_error = 0.0, max_relu_error = 0.0, max_imag = 0.0;
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                require(std::isfinite(decoded[i].real()) && std::isfinite(decoded[i].imag()),
                        "non-finite encrypted approximation");
                max_he_error = std::max(max_he_error,
                    std::abs(decoded[i].real() - chebyshev_relu_plain(values[i])));
                max_relu_error = std::max(max_relu_error,
                    std::abs(decoded[i].real() - std::max(0.0, values[i])));
                max_imag = std::max(max_imag, std::abs(decoded[i].imag()));
            }
            std::cout << "logN=" << log_n << ", input_level=" << level
                      << ", output_level=" << output.level()
                      << ", he_vs_poly_max_abs_error=" << max_he_error
                      << ", he_vs_relu_max_abs_error=" << max_relu_error
                      << ", max_imag=" << max_imag
                      << ", time_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - start).count() << '\n';
            require(max_he_error < 1e-4 && max_imag < 1e-4,
                    "encrypted polynomial evaluation error exceeded tolerance");
            require(max_relu_error < 0.002, "encrypted ReLU approximation error exceeded tolerance");
        }
        Ciphertext too_low;
        evaluator->drop_modulus(original, too_low, context.crt_context()->parms_id_map().at(9));
        bool rejected = false;
        try { (void)chebyshev_relu(too_low, *evaluator, encoder, rk, params.scale()); }
        catch (const std::invalid_argument &) { rejected = true; }
        require(rejected, "insufficient level budget was not rejected");

        if (test_bootstrap)
        {
            std::cout << "Preparing bootstrap test keys\n";
            if (single22)
                keygen.create_galois_keys(single22_bootstrap_rotation_steps(log_n), runtime.galois_keys);
            else
                keygen.create_galois_keys(runtime.galois_keys);
            for (double &x : values)
                x *= 0.5;
            encoder.encode(values, params.scale(), plain);
            encryptor.encrypt(plain, original);
            evaluator->drop_modulus(original, original, context.crt_context()->parms_id_map().at(single22 ? 4 : 2));
            PoseidonBootstrapContext boot{&context, evaluator.get(), &encoder, &rk,
                                         &runtime.galois_keys, &runtime.bootstrap_config,
                                         runtime.single22_poly.get(), runtime.bootstrap_mutex.get()};
            if (single22)
            {
                // Exercise the real convolution scale drift and 4 -> 2 budget.
                for (int i = 0; i < 2; ++i)
                {
                    evaluator->multiply_const(original, 0.8, params.scale(), original, encoder);
                    evaluator->rescale(original, original);
                    for (double &x : values) x *= 0.8;
                }
                require(original.level() == 2 && original.scale() > params.scale(),
                        "scale-drift fixture did not exercise input alignment");
                std::cout << "single22_input_level=" << original.level()
                          << ", input_scale_ratio=" << original.scale() / params.scale() << '\n';
                for (int level : {0, 1})
                {
                    Ciphertext bad;
                    evaluator->drop_modulus(original, bad, context.crt_context()->parms_id_map().at(level));
                    TensorCipher bad_input(log_n, 1, 1, 1, 1, 1, 1, bad), unused;
                    bool rejected_input = false;
                    try { bootstrap_tensor(bad_input, unused, boot); }
                    catch (const std::invalid_argument &) { rejected_input = true; }
                    require(rejected_input, "single22 accepted insufficient alignment budget");
                }
            }
            TensorCipher input(log_n, 1, 1, 1, 1, 1, 1, original), refreshed;
            const auto start = std::chrono::steady_clock::now();
            bootstrap_tensor(input, refreshed, boot);
            require(refreshed.cipher().level() == 16, "short-chain bootstrap did not return level 16");
            require(std::abs(refreshed.cipher().scale() / params.scale() - 1.0) < 1e-5,
                    "short-chain bootstrap output scale mismatch");
            decryptor.decrypt(refreshed.cipher(), plain);
            std::vector<std::complex<double>> decoded;
            encoder.decode(plain, decoded);
            double bootstrap_error = 0.0;
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                require(std::isfinite(decoded[i].real()) && std::isfinite(decoded[i].imag()),
                        "non-finite bootstrap output");
                bootstrap_error = std::max(bootstrap_error, std::abs(decoded[i] - values[i]));
            }
            std::cout << "bootstrap_output_level=" << refreshed.cipher().level()
                      << ", bootstrap_max_abs_error=" << bootstrap_error
                      << ", bootstrap_time_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - start).count() << '\n';
            require(bootstrap_error < 1e-3, "short-chain bootstrap accuracy regression");
            // Exercise the SAME trimming routine used by the whole network,
            // both the internal activation and final-head target levels.
            std::vector<Ciphertext> internal{refreshed.cipher()};
            trim_bootstrap_relu_input(internal, runtime, single22 ? 14 : 12);
            require(internal.front().level() == (single22 ? 14 : 12),
                    "bootstrap internal ReLU trimming failed");
            std::vector<Ciphertext> final_input{refreshed.cipher()};
            trim_bootstrap_relu_input(final_input, runtime, 16);
            Ciphertext activated = chebyshev_relu(final_input.front(), *evaluator, encoder, rk, params.scale());
            require(activated.level() == 6, "final ReLU cannot feed the existing level-6 head");
            decryptor.decrypt(activated, plain);
            encoder.decode(plain, decoded);
            double activation_error = 0.0;
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                require(std::isfinite(decoded[i].real()) && std::isfinite(decoded[i].imag()),
                        "non-finite bootstrap + ReLU output");
                activation_error = std::max(activation_error,
                    std::abs(decoded[i] - chebyshev_relu_plain(values[i])));
            }
            std::cout << "bootstrap_then_relu_output_level=" << activated.level()
                      << ", max_abs_error_vs_polynomial=" << activation_error << '\n';
            require(activation_error < 1e-3, "bootstrap + ReLU accuracy regression");
            if (single22)
            {
                // Exact-scale level-1 is a valid API boundary, unlike the drifted
                // level-1 ciphertext above. Include a constant real message.
                std::vector<double> constant(values.size(), 0.25);
                encoder.encode(constant, params.scale(), plain);
                encryptor.encrypt(plain, original);
                evaluator->drop_modulus(original, original, context.crt_context()->parms_id_map().at(1));
                TensorCipher exact_input(log_n, 1, 1, 1, 1, 1, 1, original);
                bootstrap_tensor(exact_input, refreshed, boot);
                require(refreshed.cipher().level() == 16, "single22 exact-scale output level mismatch");
                decryptor.decrypt(refreshed.cipher(), plain);
                encoder.decode(plain, decoded);
                double constant_error = 0.0;
                for (const auto &v : decoded)
                {
                    require(std::isfinite(v.real()) && std::isfinite(v.imag()), "non-finite constant bootstrap");
                    constant_error = std::max(constant_error, std::abs(v - 0.25));
                }
                require(constant_error < 1e-3, "constant single22 error exceeded tolerance");
                std::cout << "single22_level1_constant_max_abs_error=" << constant_error << '\n';
            }
        }
        std::cout << "Chebyshev-471 ReLU tests passed\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Chebyshev ReLU test failed: " << error.what() << '\n';
        return 1;
    }
}
