
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>
#include "apsi/network/sender_operation.h"
#include "apsi/powers.h"
#include "apsi/requests.h"
#include "apsi/sender_db.h"
#include "poseidon/src/ciphertext.h"
#include "poseidon/src/key/relinkeys.h"

namespace apsi {
    namespace sender {
        class Query {
        public:
            Query() = default;

            Query(QueryRequest query_request, std::shared_ptr<sender::SenderDB> sender_db);

            Query deep_copy() const;

            Query(const Query &source) = delete;

            Query(Query &&source) = default;

            Query &operator=(const Query &source) = delete;

            Query &operator=(Query &&source) = default;

            bool is_valid() const noexcept
            {
                return valid_;
            }

            explicit operator bool() const noexcept
            {
                return is_valid();
            }

            const poseidon::RelinKeys &relin_keys() const noexcept
            {
                return relin_keys_;
            }

            auto &data() const noexcept
            {
                return data_;
            }

            const PowersDag &pd() const noexcept
            {
                return pd_;
            }

            std::shared_ptr<sender::SenderDB> sender_db() const noexcept
            {
                return sender_db_;
            }

            poseidon::compr_mode_type compr_mode() const noexcept
            {
                return compr_mode_;
            }

        private:
            poseidon::RelinKeys relin_keys_;

            std::unordered_map<std::uint32_t, std::vector<poseidon::Ciphertext>> data_;

            PowersDag pd_;

            std::shared_ptr<sender::SenderDB> sender_db_;

            bool valid_ = false;

            poseidon::compr_mode_type compr_mode_;
        };
    } // namespace sender
} // namespace apsi
