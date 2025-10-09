#pragma once

#include "../base.h"
#include "../monitor_server/monitor_helper.h"
#include "cinatra/cinatra.hpp"
#include "nlohmann_json/json.hpp"
#include "poseidon/ciphertext.h"
#include "poseidon/ckks_encoder.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/factory/poseidon_factory.h"

#ifdef USE_MYSQL
struct MYSQL;
#endif

namespace facial_recognition {

    class BackendServer {
        friend class Test;

    public:
        static BackendServer& getInstance();
        BackendServer(const BackendServer&) = delete;
        BackendServer& operator=(const BackendServer&) = delete;

        void run();

    private:
        explicit BackendServer(const poseidon::sec_level_type& sec_level = poseidon::sec_level_type::none);
        ~BackendServer();

        void register_handler(cinatra::http_server &server);

        /*
         * handle network interface /setGaloisKey
         * @param: json
         * json format { (binary) galois_key }
         * @return: json
         * json format {}
         */
        nlohmann::json handler_set_galois_key(nlohmann::json& json);

        /* handle network interface /getIdCihertext
         * @param: json
         * json format { (binary) ciphertext }
         * @return: json
         * json format { {key: (string)id, value: (binary)ciphertext}, ... }
         */
        nlohmann::json handler_get_similarity_ciphertext(nlohmann::json& json);

#ifdef USE_MYSQL
        nlohmann::json handler_database(nlohmann::json& json);
#endif

        // for test
        nlohmann::json handler_test_ciphertext(nlohmann::json& json);
        // for test
        nlohmann::json handler_set_public_key(nlohmann::json& json);

        // compute the inner product of received ciphertext and the database plaintext
        std::map<std::string, poseidon::Ciphertext> compute_similarity(const poseidon::Ciphertext &ctxt);

        nlohmann::json serialize(const std::map<std::string, poseidon::Ciphertext> &ctxt_vec);

        void test_read_database();

    private:
        poseidon::ParametersLiteralDefault parm_;
        poseidon::PoseidonContext context_;
        poseidon::CKKSEncoder encoder_;
        std::unique_ptr<poseidon::EvaluatorCkksBase> evaluator_;
        double scale_;
        poseidon::GaloisKeys galois_key_;

        FEATURE_DATABASE database_;

        std::string file_path_;
        int face_id_size_;
#ifdef USE_MYSQL
        const std::string host = "127.0.0.1";
        const std::string user = "root";
        const std::string passwd = "123456";
        const std::string db = "FacePoseidon";
        const unsigned int port = 3306;
        MYSQL* conn_;
#endif

        poseidon::PublicKey pk_;
        poseidon::Ciphertext ctxt_;
    };

}
