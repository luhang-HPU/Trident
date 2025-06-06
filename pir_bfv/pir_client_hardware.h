#pragma once

#include "pir.h"
#include "poseidon/src/batchencoder.h"
#include "poseidon/src/decryptor.h"
#include "poseidon/src/encryptor.h"
#include "poseidon/src/keygenerator.h"
#include <memory>
#include <vector>

namespace poseidon
{
namespace pir
{

class PIRClientHardware
{
public:
    PIRClientHardware(const ParametersLiteral &encparms, const PirParams &pirparams);

    PirQuery generate_query(std::uint64_t desiredIndex);
    // Serializes the query into the provided stream and returns number of bytes
    // written
    int generate_serialized_query(std::uint64_t desiredIndex, std::stringstream &stream);
    Plaintext decode_reply(PirReply &reply);

    std::vector<uint64_t> extract_coeffs(Plaintext pt);
    std::vector<uint64_t> extract_coeffs(Plaintext pt, std::uint64_t offset);
    std::vector<uint8_t> extract_bytes(Plaintext pt, std::uint64_t offset);

    std::vector<uint8_t> decode_reply(PirReply &reply, uint64_t offset);

    Plaintext decrypt(Ciphertext ct);

    GaloisKeys generate_galois_keys();

    // Index and offset of an element in an FV plaintext
    uint64_t get_fv_index(uint64_t element_index);
    uint64_t get_fv_offset(uint64_t element_index);

    // Only used for simple_query
    Ciphertext get_one();

    Plaintext replace_element(Plaintext pt, std::vector<std::uint64_t> new_element,
                              std::uint64_t offset);

    std::shared_ptr<PoseidonContext> get_context() const { return context_; }

private:
    ParametersLiteral enc_params_;
    PirParams pir_params_;

    std::unique_ptr<Encryptor> encryptor_;
    std::unique_ptr<Decryptor> decryptor_;
    std::unique_ptr<EvaluatorBfvBase> evaluator_;
    std::unique_ptr<KeyGenerator> keygen_;
    std::unique_ptr<BatchEncoder> encoder_;
    std::shared_ptr<PoseidonContext> context_;

    std::vector<uint64_t> indices_;  // the indices for retrieval.
    std::vector<uint64_t> inverse_scales_;

    friend class PIRServerHardware;
};

}  // namespace pir
}  // namespace poseidon
