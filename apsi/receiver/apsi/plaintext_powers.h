#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>
#include "apsi/crypto_context.h"
#include "apsi/powers.h"
#include "apsi/psi_params.h"
#include "apsi/poseidon_object.h"
#include "poseidon/src/ciphertext.h"
#include "poseidon/src/basics/modulus.h"
#include "gsl/span"

namespace apsi {
    namespace receiver {
        class PlaintextPowers {
        public:
            PlaintextPowers(
                std::vector<std::uint64_t> values, const PSIParams &params, const PowersDag &pd);

            std::unordered_map<std::uint32_t, PoseidonObject<poseidon::Ciphertext>> encrypt(
                const CryptoContext &crypto_context);

        private:
            poseidon::Modulus mod_;

            std::unordered_map<std::uint32_t, std::vector<std::uint64_t>> powers_;

            void square_array(gsl::span<std::uint64_t> in) const;

            void multiply_array(
                gsl::span<std::uint64_t> in1,
                gsl::span<std::uint64_t> in2,
                gsl::span<std::uint64_t> out) const;

            std::vector<std::uint64_t> exponentiate_array(
                std::vector<std::uint64_t> values, std::uint32_t exponent);

            void compute_powers(std::vector<std::uint64_t> values, const PowersDag &pd);
        };
    } // namespace receiver
} // namespace apsi
