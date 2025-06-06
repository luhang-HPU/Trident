#pragma once

#include "base.h"
#include "poseidon/src/ciphertext.h"
#include "poseidon/src/ckks_encoder.h"
#include "poseidon/src/encryptor.h"
#include "poseidon/src/decryptor.h"
#include "poseidon/src/keygenerator.h"
#include "poseidon/src/factory/poseidon_factory.h"
#include "nlohmann_json/json.hpp"

namespace facial_recognition {

    class FrontendServer {
    public:
        static FrontendServer& getInstance();

        FrontendServer(const FrontendServer&) = delete;
        FrontendServer& operator=(const FrontendServer&) = delete;

        void run();

    private:
        FrontendServer();

        void init();
        void create_keys();
        poseidon::Plaintext encode(std::vector<double> feature_vector);
        poseidon::Ciphertext encrypt(const poseidon::Plaintext& ptxt);

        /*
         * handle network interface /getCiphertext
         * @param: json
         * json format { (array) float }
         * @return: json
         * json format { (binary) ciphertext }
         */
        nlohmann::json handler_feature_vector(nlohmann::json& json);
        /*
         * handle network interface /getGaloisKey
         * @param: json
         * json format {}
         * @return: json
         * json format { (binary) galois_key }
         */
        nlohmann::json handler_galois_key();
        /*
         * handle network interface /getId
         * @param: json
         * json format { (array) { (string) id, (binary) ciphertext } }
         * @return: json
         * json format { (string) id }
         */
        nlohmann::json handler_get_id(nlohmann::json& json);

        nlohmann::json handler_test_ciphertext(nlohmann::json& json);

    private:
        poseidon::ParametersLiteralDefault parm_;
        poseidon::PoseidonContext context_;
        double scale_;
        // similarity threshold;
        double threshold_;

        poseidon::KeyGenerator keygen_;
        poseidon::PublicKey public_key_;
        poseidon::RelinKeys relin_key_;
        poseidon::GaloisKeys galois_key_;

        poseidon::CKKSEncoder encoder_;
        std::unique_ptr<poseidon::Encryptor> ptr_encryptor_;
        std::unique_ptr<poseidon::Decryptor> ptr_decryptor_;

        nlohmann::json galois_key_json_;

        std::vector<std::string> id_vec_;
    };

}
