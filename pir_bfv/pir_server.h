#pragma once

#include "pir.h"
#include <map>
#include <memory>
#include <vector>

namespace poseidon
{
namespace pir
{

class PIRServer
{
public:
#ifdef PIR_USE_HARDWARE
    PIRServer(const ParametersLiteral &enc_params,
              const PirParams &pir_params,
              std::shared_ptr<PoseidonContext> context);
#else
    PIRServer(const ParametersLiteral &enc_params, const PirParams &pir_params);
#endif

    // NOTE: server takes over ownership of db and frees it when it exits.
    // Caller cannot free db
    void set_database(std::unique_ptr<std::vector<Plaintext>> &&db);
    void set_database(const std::unique_ptr<const std::uint8_t[]> &bytes, std::uint64_t ele_num,
                      std::uint64_t ele_size);
    void preprocess_database();

    std::vector<Ciphertext> expand_query(const Ciphertext &encrypted, std::uint32_t m,
                                         std::uint32_t client_id);

    PirQuery deserialize_query(std::stringstream &stream);
    PirReply generate_reply(PirQuery &query, std::uint32_t client_id);
    // Serializes the reply into the provided stream and returns the number of
    // bytes written
    int serialize_reply(PirReply &reply, std::stringstream &stream);

    void set_galois_key(std::uint32_t client_id, GaloisKeys galkey);

    // Below simple operations are for interacting with the database WITHOUT
    // PIR. So they can be used to modify a particular element in the database
    // or to query a particular element (without privacy guarantees).
    void simple_set(std::uint64_t index, Plaintext pt);
    Ciphertext simple_query(std::uint64_t index);
    void set_one_ct(Ciphertext one);

private:
    ParametersLiteral enc_params_;  // SEAL parameters
    PirParams pir_params_;          // PIR parameters
    std::unique_ptr<Database> db_;
    bool is_db_preprocessed_;
    std::map<int, GaloisKeys> galoisKeys_;
    std::unique_ptr<EvaluatorBfvBase> evaluator_;
    std::unique_ptr<BatchEncoder> encoder_;
    std::shared_ptr<PoseidonContext> context_;

    // This is only used for simple_query
    Ciphertext one_;

    void multiply_power_of_X(const Ciphertext &encrypted, Ciphertext &destination,
                             std::uint32_t index);

#ifdef PIR_USE_HARDWARE
    bool is_using_ntt_form = false;
#else
    bool is_using_ntt_form = true;
#endif
};

}  // namespace pir
}  // namespace poseidon
