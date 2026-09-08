#pragma once

#include "he/he_config.h"

#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/keygenerator.h"
#include "poseidon/poseidon_context.h"

#include <cstddef>
#include <memory>
#include <string>

namespace qwen::he
{

class HeRuntime
{
public:
    HeRuntime(HeConfig config, poseidon::PoseidonContext context,
              std::unique_ptr<poseidon::EvaluatorCkksBase> evaluator,
              poseidon::PublicKey public_key, poseidon::SecretKey secret_key,
              poseidon::RelinKeys relin_keys, poseidon::GaloisKeys galois_keys);

    const HeConfig &config() const;
    double scale() const;
    void set_bootstrap_value_scale(double value);
    bool mock_nonlinear() const;
    void set_mock_nonlinear(bool value);
    bool mock_silu() const;
    void set_mock_silu(bool value);
    bool mock_rms_norm() const;
    void set_mock_rms_norm(bool value);
    bool mock_attention() const;
    void set_mock_attention(bool value);
    bool operation_logging() const;
    void set_operation_logging(bool value);
    const std::string &operation_context() const;
    void set_operation_context(std::string value);
    std::size_t chain_index(const poseidon::Ciphertext &cipher) const;

    poseidon::PoseidonContext context;
    std::unique_ptr<poseidon::EvaluatorCkksBase> evaluator;
    poseidon::CKKSEncoder encoder;
    poseidon::PublicKey public_key;
    poseidon::SecretKey secret_key;
    poseidon::RelinKeys relin_keys;
    poseidon::GaloisKeys galois_keys;
    poseidon::Encryptor encryptor;
    poseidon::Decryptor decryptor;

private:
    HeConfig config_;
    bool mock_silu_ = false;
    bool mock_rms_norm_ = false;
    bool mock_attention_ = false;
    bool operation_logging_ = false;
    std::string operation_context_ = "decoder";
};

HeRuntime make_he_runtime(const HeConfig &config);

} // namespace qwen::he
