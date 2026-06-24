#pragma once

#include "infer_config.h"

#include "poseidon/advance/homomorphic_mod.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/keygenerator.h"
#include "poseidon/poseidon_context.h"

#include <memory>

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
    std::unique_ptr<poseidon::EvalModPoly> bootstrap_poly;
    double scale = 0.0;
    int slot_count = 0;

    PoseidonRuntime(poseidon::PoseidonContext ctx,
                    std::unique_ptr<poseidon::EvaluatorCkksBase> eva,
                    poseidon::PublicKey pk, poseidon::SecretKey sk,
                    poseidon::RelinKeys rk, poseidon::GaloisKeys gk,
                    std::unique_ptr<poseidon::EvalModPoly> poly, double scale_value);
};

PoseidonRuntime make_poseidon_runtime(const PoseidonInferPlan &plan);
std::size_t cipher_chain_index(const PoseidonRuntime &runtime,
                               const poseidon::Ciphertext &cipher);
