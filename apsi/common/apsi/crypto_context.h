#pragma once

#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include "apsi/psi_params.h"
#include "poseidon/src/batchencoder.h"
#include "poseidon/src/decryptor.h"
#include "poseidon/src/encryptor.h"
#include "poseidon/src/evaluator/evaluator_base.h"
#include "poseidon/src/key/publickey.h"
#include "poseidon/src/key/relinkeys.h"
#include "poseidon/src/key/secretkey.h"
#include "poseidon/src/keygenerator.h"
#include "poseidon/src/poseidon_context.h"
#include "src/factory/poseidon_factory.h"

using namespace poseidon;

namespace apsi {
    class CryptoContext {
    public:
        CryptoContext() = default;

        CryptoContext(const PSIParams &parms)
            : poseidon_context_(std::make_shared<poseidon::PoseidonContext>(
                  PoseidonFactory::get_instance()->create_poseidon_context(
                      parms.poseidon_params()))),
              evaluator_(
                  PoseidonFactory::get_instance()->create_bfv_evaluator(*poseidon_context_.get()))
        {
                encoder_ = std::make_shared<poseidon::BatchEncoder>(*poseidon_context_);
        }

        void set_evaluator()
        {
            relin_keys_.reset();
        }

        void set_evaluator(poseidon::RelinKeys relin_keys)
        {
            relin_keys_ = std::make_shared<poseidon::RelinKeys>(std::move(relin_keys));
        }

        void set_secret(poseidon::SecretKey secret_key)
        {
            secret_key_ = std::make_shared<poseidon::SecretKey>(secret_key);
            encryptor_ = std::make_shared<poseidon::Encryptor>(*poseidon_context_, *secret_key_);
            decryptor_ = std::make_shared<poseidon::Decryptor>(*poseidon_context_, *secret_key_);
        }

        void clear_secret()
        {
            secret_key_.reset();
            encryptor_.reset();
            decryptor_.reset();
        }

        void clear_evaluator()
        {
            relin_keys_.reset();
            evaluator_.reset();
        }

        std::shared_ptr<poseidon::PoseidonContext> poseidon_context() const
        {
            return poseidon_context_;
        }

        std::shared_ptr<poseidon::RelinKeys> relin_keys() const
        {
            return relin_keys_;
        }

        std::shared_ptr<poseidon::BatchEncoder> encoder() const
        {
            return encoder_;
        }

        std::shared_ptr<poseidon::SecretKey> secret_key() const
        {
            return secret_key_;
        }

        std::shared_ptr<poseidon::Encryptor> encryptor() const
        {
            return encryptor_;
        }

        std::shared_ptr<poseidon::Decryptor> decryptor() const
        {
            return decryptor_;
        }

        std::shared_ptr<poseidon::EvaluatorBfvBase> evaluator() const
        {
            return evaluator_;
        }

        explicit operator bool() const noexcept
        {
            return !!poseidon_context_;
        }

    private:
        std::shared_ptr<poseidon::PoseidonContext> poseidon_context_ = nullptr;

        std::shared_ptr<poseidon::RelinKeys> relin_keys_ = nullptr;

        std::shared_ptr<poseidon::SecretKey> secret_key_ = nullptr;

        std::shared_ptr<poseidon::Encryptor> encryptor_ = nullptr;

        std::shared_ptr<poseidon::Decryptor> decryptor_ = nullptr;

        std::shared_ptr<poseidon::EvaluatorBfvBase> evaluator_ = nullptr;

        std::shared_ptr<poseidon::BatchEncoder> encoder_ = nullptr;
    };
} // namespace apsi
