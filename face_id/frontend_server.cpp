#include "cinatra/include/cinatra.hpp"
#include "frontend_server.h"
#include "config.h"
#include "json_helper.h"

namespace facial_recognition {
    FrontendServer& FrontendServer::getInstance() {
        static FrontendServer instance;
        return instance;
    }

    FrontendServer::FrontendServer()
        : parm_(CKKS, 4096, poseidon::sec_level_type::none),
          context_(poseidon::PoseidonFactory::get_instance()->create_poseidon_context(
              parm_)),
          scale_(std::pow(2.0, 32)), threshold_(0.6), encoder_(context_), keygen_(context_)
    {
        init();
        ptr_encryptor_ = std::make_unique<poseidon::Encryptor>(context_, public_key_);
        ptr_decryptor_ = std::make_unique<poseidon::Decryptor>(context_, keygen_.secret_key());
    }

    void FrontendServer::init() {
        create_keys();

        std::stringstream ss(std::ios_base::binary | std::ios_base::in | std::ios_base::out);
        galois_key_.save(ss);
        galois_key_json_ = stream_to_json(ss);

        // set id vector
        for (auto i = 1; i <= 3; ++i) {
            id_vec_.emplace_back(std::to_string(i));
        }
    }

    void FrontendServer::create_keys() {
        keygen_.create_public_key(public_key_);
        keygen_.create_relin_keys(relin_key_);
        keygen_.create_galois_keys(std::vector<int>{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}, galois_key_);
    }

    void FrontendServer::run() {
        int max_thread_num = 4;
        cinatra::http_server server(max_thread_num);
        server.listen("0.0.0.0", port_frontend_default);
        std::cout << "frontend server start" << std::endl;

        // test
        server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>("/", [&](cinatra::request& req, cinatra::response& res) {
            std::cout << "response to / start" << std::endl;
            res.set_status_and_content(cinatra::status_type::ok, generate_json(1, "", get_timestamp(), nlohmann::json{"frontend server alive"}).dump());
            std::cout << "response to / end" << std::endl;
        });
        // get encrypted feature vector
        server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>("/getCiphertext", [&](cinatra::request& req, cinatra::response& res) {
            std::cout << "response to /getCiphertext start" << std::endl;
            auto data = req.body();
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok, handler_feature_vector(json).dump());
            std::cout << "response to /getCiphertext end" << std::endl;
        });
        // get galois key
        server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>("/getGaloisKey", [&](cinatra::request& req, cinatra::response& res) {
            std::cout << "response to /getGaloisKey start" << std::endl;
            auto data = req.body();
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok, handler_galois_key().dump());
            std::cout << "response to /getGaloisKey end" << std::endl;
        });
        // get face id
        server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>("/getId", [&](cinatra::request& req, cinatra::response& res) {
            std::cout << "response to /getId start" << std::endl;
            auto data = req.body();
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok, handler_get_id(json).dump());
            std::cout << "response to /getId end" << std::endl;
        });

        server.set_http_handler<cinatra::http_method::GET, cinatra::http_method::POST>("/testCiphertext", [&](cinatra::request& req, cinatra::response& res) {
            std::cout << "response to /testCiphertext start" << std::endl;
            auto data = req.body();
            auto json = nlohmann::json::parse(data);
            res.set_status_and_content(cinatra::status_type::ok, handler_test_ciphertext(json).dump());
            std::cout << "response to /testCiphertext end" << std::endl;
        });

        server.run();
    }

    poseidon::Plaintext FrontendServer::encode(std::vector<double> feature_vector) {
        poseidon::Plaintext feat_vec_ptxt;
        encoder_.encode(feature_vector, scale_, feat_vec_ptxt);
        return feat_vec_ptxt;
    }

    poseidon::Ciphertext FrontendServer::encrypt(const poseidon::Plaintext &ptxt) {
        poseidon::Ciphertext ctxt;
        ptr_encryptor_->encrypt(ptxt, ctxt);
        return ctxt;
    }

    nlohmann::json FrontendServer::handler_feature_vector(nlohmann::json& json) {
        int code = 0;
        std::string error_message;

        if (!json.is_array()) {
            error_message = "parse json data array fail";
            return generate_json(-1, std::move(error_message), get_timestamp(), nlohmann::json{});
        }

        std::vector<double> feature_vector(1024);
        for (auto i = 0; i < json.size(); ++i) {
            feature_vector[i] = json[i];
        }

        // encode the feature vector message
        poseidon::Plaintext ptxt = encode(feature_vector);
        // encrypt the feature vector plaintext
        poseidon::Ciphertext ctxt = encrypt(ptxt);
        // serialize the feature vector ciphertext
        // pack into json and return
        std::stringstream ss;
        ctxt.save(ss);

        return stream_to_json(ss);
    }

    nlohmann::json FrontendServer::handler_galois_key() {
        int code = 0;
        std::string error_message = "";

        if (!galois_key_json_.is_binary()) {
            code = -1;
            error_message = "get galois_key failed";
        }

        return galois_key_json_;
    }

    nlohmann::json FrontendServer::handler_get_id(nlohmann::json& json) {
        if (!json.is_object()) {
            return generate_json(-1, "json format error", get_timestamp(), nlohmann::json{});
        }

        std::string max_id = "null";
        std::stringstream ss_message;
        double max_value = 0.0;

        for (auto &item : json.items()) {
            std::string id;
            id = item.key();

            std::stringstream ss = json_to_stream(item.value()["bytes"]);

            poseidon::Ciphertext ctxt;
            poseidon::Plaintext ptxt;
            ctxt.load(context_, ss);
            ptr_decryptor_->decrypt(ctxt, ptxt);

            std::vector<double> ans;
            encoder_.decode(ptxt, ans);
            ss_message << "result of id[" << id << "] : " << ans[0] << std::endl;

            if ((ans[0] > max_value) && (ans[0] > threshold_)) {
                max_id = id;
            }
        }

        nlohmann::json result;
        result["id"] = max_id;
        return generate_json(0, ss_message.str(), get_timestamp(), std::move(result));
    }

    nlohmann::json FrontendServer::handler_test_ciphertext(nlohmann::json &json) {
        auto cstream = json["bytes"];
        std::stringstream ss = json_to_stream(cstream);
        poseidon::Ciphertext ctxt;
        ctxt.load(context_, ss);

        poseidon::Plaintext ptxt;
        ptr_decryptor_->decrypt(ctxt, ptxt);

        std::vector<double> vec;
        encoder_.decode(ptxt, vec);
        for (auto elem : vec) {
            std::cout << elem << " ";
        }
        std::cout << std::endl;
        return nlohmann::json();
    }
}
