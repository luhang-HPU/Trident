#include "infer_runtime.h"
#include "chebyshev_relu.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>

using namespace poseidon;

namespace
{
void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}

void verify_values(const Ciphertext &cipher, PoseidonRuntime &runtime)
{
    Plaintext plain;
    runtime.decryptor.decrypt(cipher, plain);
    std::vector<std::complex<double>> decoded;
    runtime.encoder.decode(plain, decoded);
    for (std::size_t i = 0; i < decoded.size(); ++i)
    {
        const double expected = (static_cast<int>(i % 9) - 4) / 16.0;
        require(std::isfinite(decoded[i].real()) && std::isfinite(decoded[i].imag()),
                "non-finite decrypted value after trim");
        require(std::abs(decoded[i] - expected) < 1e-5, "trim changed encrypted values");
    }
}
}

int main(int argc, char **argv)
{
    try
    {
        std::cout << std::unitbuf;
        const int log_n = argc > 1 ? std::stoi(argv[1]) : 13;
        require(log_n >= 13 && log_n <= 16, "test logN must be in [13,16]");
        for (bool short_chain : {false, true})
        {
            for (std::size_t dnum : {3, 4})
            {
                auto plan = default_poseidon_plan(dnum, short_chain);
                plan.logN = log_n;
                plan.log_slots = log_n - 1;
                auto runtime = make_poseidon_runtime(plan, false);
                std::vector<double> values(runtime.slot_count);
                for (std::size_t i = 0; i < values.size(); ++i)
                    values[i] = (static_cast<int>(i % 9) - 4) / 16.0;
                Plaintext plain;
                runtime.encoder.encode(values, runtime.scale, plain);
                Ciphertext original;
                runtime.encryptor.encrypt(plain, original);
                // A refreshed ciphertext would be at 20 (old Q) or 16 (short Q).
                const auto source_level = plan.compute_prime_count;
                runtime.evaluator->drop_modulus(original, original,
                    runtime.context.crt_context()->parms_id_map().at(source_level));
                for (std::size_t target_level : {12, 14, 16})
                {
                    // Multiple packs also exercise lifetime across worker threads.
                    std::vector<Ciphertext> packs(8, original);
                    trim_bootstrap_relu_input(packs, runtime, target_level);
                    trim_bootstrap_relu_input(packs, runtime, target_level); // no-op
                    for (const auto &cipher : packs)
                    {
                        require(cipher.level() == target_level &&
                                cipher_chain_index(runtime, cipher) == target_level,
                                "trim returned the wrong level");
                        require(cipher.coeff_modulus_size() == target_level + 1,
                                "trim returned the wrong prime count");
                        require(cipher.scale() == original.scale(), "trim changed scale");
                        verify_values(cipher, runtime);
                    }
                }

                // Invalid target and attempted modulus raising must not mutate
                // even the first pack of a batch whose last pack is too low.
                Ciphertext low = original;
                runtime.evaluator->drop_modulus(low, low,
                    runtime.context.crt_context()->parms_id_map().at(12));
                for (std::size_t target_level : {std::size_t{14}, plan.logq_chain.size()})
                {
                    std::vector<Ciphertext> packs{original, low};
                    bool rejected = false;
                    try { trim_bootstrap_relu_input(packs, runtime, target_level); }
                    catch (const std::invalid_argument &) { rejected = true; }
                    require(rejected, "invalid trim request was accepted");
                    require(packs[0].parms_id() == original.parms_id() &&
                            packs[1].parms_id() == low.parms_id(),
                            "invalid batch was partially modified");
                    verify_values(packs[0], runtime);
                    verify_values(packs[1], runtime);
                }

                // The old 35-prime run failed at FC because final trim to 16
                // did not happen. Test that actual trim -> ReLU yields level 6.
                if (dnum == 4)
                {
                    KeyGenerator keygen(runtime.context, runtime.secret_key);
                    keygen.create_relin_keys(runtime.relin_keys);
                    std::vector<Ciphertext> final_input{original};
                    trim_bootstrap_relu_input(final_input, runtime, 16);
                    const auto activated = chebyshev_relu(final_input.front(),
                        *runtime.evaluator, runtime.encoder, runtime.relin_keys, runtime.scale);
                    require(activated.level() == 6, "trim -> ReLU failed to reach head level 6");
                    runtime.decryptor.decrypt(activated, plain);
                    std::vector<std::complex<double>> decoded;
                    runtime.encoder.decode(plain, decoded);
                    for (std::size_t i = 0; i < values.size(); ++i)
                        require(std::isfinite(decoded[i].real()) &&
                                std::isfinite(decoded[i].imag()) &&
                                std::abs(decoded[i] - chebyshev_relu_plain(values[i])) < 1e-4,
                                "trim -> ReLU value mismatch");
                }
                std::cout << "PASS logN=" << log_n << ", Q=" << plan.logq_chain.size()
                          << ", dnum=" << dnum << ", trim=" << source_level
                          << "->{12,14,16}, invalid-batch guards, plaintext preservation\n";
            }
        }
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Bootstrap trim regression failed: " << error.what() << '\n';
        return 1;
    }
}
