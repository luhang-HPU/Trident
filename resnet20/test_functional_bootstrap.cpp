#include "functional_bootstrap.h"
#include "tensor_cipher.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"
#include "poseidon/encryptor.h"
#include "poseidon/decryptor.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <complex>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>

using namespace poseidon;
using namespace trident;

int main(int argc, char** argv) try {
    std::cout << std::unitbuf;
    const unsigned logn = argc > 1 ? std::stoul(argv[1]) : 10;
    const unsigned degree = argc > 2 ? std::stoul(argv[2]) : 15;
    const unsigned cycles = argc > 3 ? std::stoul(argv[3]) : 2;
    const unsigned depth = argc > 4 ? std::stoul(argv[4]) : 3;
    const double bound = argc > 5 ? std::stod(argv[5]) : 1.0;
    if (logn < 8 || logn > 16 || cycles < 1 || cycles > 20) throw std::invalid_argument("invalid test arguments");
    const auto root = std::filesystem::path(__FILE__).parent_path() / "functional_params";
    FunctionalBootstrapPlan plan;
    plan.harmonic_degree = degree;
    plan.transform_depth = depth;
    plan.bound = bound;
    ParametersLiteral params(CKKS, logn, logn-1, 40, 32, 0, 0, {}, {});
    params.set_log_modulus(plan.modulus_bits(), {51});
    PoseidonFactory::get_instance()->set_device_type(DEVICE_SOFTWARE);
    auto context = PoseidonFactory::get_instance()->create_poseidon_context(params);
    auto evaluator = PoseidonFactory::get_instance()->create_ckks_evaluator(context);
    CKKSEncoder encoder(context);
    PreparedFunctionalBootstrap prepared(context, encoder, plan,
        FrozenRelu::load(root / ("relu_d" + std::to_string(degree) + ".txt")), root / "carrier_k12_d31.txt");
    KeyGenerator generator(context);
    PublicKey pk; generator.create_public_key(pk);
    RelinKeys relin; generator.create_relin_keys(relin);
    GaloisKeys rotations;
    generator.create_galois_keys(prepared.rotations(), rotations);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, generator.secret_key());
    std::vector<double> reference(encoder.slot_count());
    for (size_t i=0; i<reference.size(); ++i) reference[i] = bound*(-1.0 + 2.0*i/(reference.size()-1));
    reference[reference.size()/2] = 0;
    reference[1] = -1e-8 * bound;
    reference[2] = 1e-8 * bound;
    std::mt19937 random(1339);
    std::shuffle(reference.begin(), reference.end(), random);
    Plaintext pt; encoder.encode(reference, std::exp2(40), pt);
    Ciphertext ct; encryptor.encrypt(pt, ct);
    evaluator->drop_modulus(ct, ct, plan.output_level());
    // The N=32768 input must not retain the old p=8 replication factor.
    // Test the same capacity check at every test ring size.
    bool rejected_layout = false;
    try { TensorCipher invalid_layout(logn, 1, 1, encoder.slot_count(), 1, 1, 2, ct); }
    catch (const std::invalid_argument&) { rejected_layout = true; }
    if (!rejected_layout) throw std::runtime_error("oversized tensor layout accepted");
    TensorCipher valid_layout(logn, 1, 1, encoder.slot_count(), 1, 1, 1, ct);
    if (logn == 15) {
        (void)TensorCipher(15, 1, 32, 32, 3, 3, 4, ct);
        (void)TensorCipher(15, 1, 32, 32, 16, 16, 1, ct);
        (void)TensorCipher(15, 2, 16, 16, 32, 8, 2, ct);
        (void)TensorCipher(15, 4, 8, 8, 64, 4, 4, ct);
        rejected_layout = false;
        try { (void)TensorCipher(15, 1, 32, 32, 3, 3, 8, ct); }
        catch (const std::invalid_argument&) { rejected_layout = true; }
        if (!rejected_layout) throw std::runtime_error("legacy p=8 accepted at N=32768");
    }
    const double tolerance = std::max(1e-6, bound * prepared.approximation().sampled_error * 0.1);
    // Fail fast on input-contract violations before running an expensive DFT.
    auto expect_invalid = [&](Ciphertext invalid) {
        Ciphertext result;
        try { prepared.evaluate(invalid, result, *evaluator, relin, rotations); }
        catch (const std::invalid_argument&) { return; }
        catch (const std::runtime_error&) { return; }
        throw std::runtime_error("invalid input unexpectedly accepted");
    };
    Ciphertext invalid = ct;
    evaluator->drop_modulus(invalid, invalid, depth - 1);
    expect_invalid(invalid);
    invalid = ct;
    invalid.scale() *= 2;
    expect_invalid(invalid);
    auto decode = [&](const Ciphertext& value) {
        Plaintext plain; decryptor.decrypt(value, plain);
        std::vector<std::complex<double>> slots; encoder.decode(plain, slots);
        for (const auto& slot : slots)
            if (!std::isfinite(slot.real()) || !std::isfinite(slot.imag()))
                throw std::runtime_error("nonfinite decoded slot");
        return slots;
    };
    for (unsigned cycle=0; cycle<cycles; ++cycle) {
        auto begin=std::chrono::steady_clock::now();
        auto observer=[&](const std::string& name, const Ciphertext& value) {
            auto slots=decode(value);
            double maxabs=0, maximag=0, modular_error=0;
            for (size_t i=0; i<slots.size(); ++i) {
                maxabs=std::max(maxabs,std::abs(slots[i]));
                maximag=std::max(maximag,std::abs(slots[i].imag()));
                if (name=="cts") {
                    double offset=slots[i].real()*plan.carrier_bound-prepared.approximation().phase*reference[i]/bound;
                    modular_error=std::max(modular_error,std::abs(offset-std::round(offset)));
                }
            }
            std::cout<<"stage="<<name<<" level="<<value.level()<<" logscale="<<std::log2(value.scale())
                <<" maxabs="<<maxabs<<" maximag="<<maximag<<" modular_error="<<modular_error<<'\n';
            if (name=="cts" && (maxabs>1 || modular_error>1e-5))
                throw std::runtime_error("CtS domain/phase recovery failed");
        };
        prepared.evaluate(ct, ct, *evaluator, relin, rotations, observer);
        auto actual=decode(ct);
        double error=0, target_error=0;
        for (size_t i=0; i<actual.size(); ++i) {
            const double expected=prepared.approximation().evaluate(reference[i], bound);
            error=std::max(error,std::abs(actual[i]-expected));
            target_error=std::max(target_error,std::abs(actual[i]-std::max(0.0,reference[i])));
            reference[i]=expected;
        }
        std::cout<<"cycle="<<cycle<<" logN="<<logn<<" degree="<<degree<<" bound="<<bound<<" Q="<<plan.modulus_bits().size()
            <<" output_level="<<ct.level()<<" max_error_vs_fit="<<error<<" max_error_vs_relu="<<target_error
            <<" tolerance="<<tolerance<<" seconds="
            <<std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count()<<'\n';
        if (!std::isfinite(error) || error>tolerance) throw std::runtime_error("functional bootstrap error exceeds tolerance");
    }
    std::cout<<"PASS\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr<<"FAIL: "<<error.what()<<'\n';
    return 1;
}
