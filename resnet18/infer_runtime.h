#pragma once

#include "infer_config.h"

#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/keygenerator.h"
#include "poseidon/poseidon_context.h"

#include <memory>
#include <mutex>

struct PoseidonRuntime
{
    poseidon::PoseidonContext context;
    std::unique_ptr<poseidon::EvaluatorCkksBase> evaluator;
    poseidon::CKKSEncoder encoder;
    poseidon::PublicKey public_key;
    poseidon::SecretKey secret_key;
    poseidon::RelinKeys relin_keys;
    poseidon::GaloisKeys galois_keys;
    poseidon::Encryptor encryptor;
    poseidon::Decryptor decryptor;
    poseidon::BootstrapConfig bootstrap_config;
    std::unique_ptr<poseidon::EvalModPoly> single22_poly;
    // EvalMod changes the evaluator's min_scale; serialize this new backend.
    std::shared_ptr<std::mutex> bootstrap_mutex = std::make_shared<std::mutex>();
    double scale = 0.0;
    int slot_count = 0;

    PoseidonRuntime(poseidon::PoseidonContext ctx,
                    std::unique_ptr<poseidon::EvaluatorCkksBase> eva,
                    poseidon::PublicKey pk, poseidon::SecretKey sk,
                    poseidon::RelinKeys rk, poseidon::GaloisKeys gk,
                    poseidon::BootstrapConfig config, double scale_value,
                    bool use_single22_bootstrap = false);
};

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan,
                                      bool generate_evaluation_keys = true);
std::size_t cipher_chain_index(const PoseidonRuntime &runtime,
                               const poseidon::Ciphertext &cipher);
std::vector<int> single22_bootstrap_rotation_steps(long log_n);

// Shared by inference and regression tests. Only drops levels; never raises Q.
void trim_bootstrap_relu_input(std::vector<poseidon::Ciphertext> &packs,
                               PoseidonRuntime &runtime, std::size_t target_level);
