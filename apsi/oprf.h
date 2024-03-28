#pragma once

// STD
#include <cstddef>
#include <stdexcept>
#include <unordered_set>
#include <vector>
#include <array>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <utility>

// GSL
#include "gsl/span"

#include "oprf_common.h"

namespace oprf {

    class FactorData {
    public:
        static constexpr std::size_t factor_size = ECPoint::order_size;

        explicit FactorData(std::size_t item_count = 2)
        {
            resize(item_count);
        }

        ~FactorData() = default;
        FactorData(const FactorData &) = delete;
        FactorData(FactorData &&) = default;
        FactorData &operator=(const FactorData &) = delete;
        FactorData &operator=(FactorData &&) = default;



        auto get_factor(std::size_t index) -> ECPoint::scalar_span_type
        {
            if (index >= item_count_) {
                throw std::invalid_argument("index out of bounds");
            }
            return ECPoint::scalar_span_type(
                factor_data_.data() + index * factor_size,
                factor_size);
        }

        auto get_factor(std::size_t index) const -> ECPoint::scalar_span_const_type
        {
            if (index >= item_count_) {
                throw std::invalid_argument("index out of bounds");
            }
            return ECPoint::scalar_span_const_type(
                factor_data_.data() + index * factor_size,
                factor_size);
        }

    private:

        void resize(std::size_t item_count)
        {
            item_count_ = item_count;
            factor_data_.resize(item_count * factor_size);
        }

        std::vector<unsigned char> factor_data_;
        std::size_t item_count_ = 0;
    };

    
    std::array<unsigned char, 2*oprf_item_size> oprf_queries_;
    FactorData inv_factor_data_;

    bool compare_bytes(const void *first, const void *second, std::size_t count);

    class OPRFKey {
    public:
        OPRFKey()
        {
            create();
        }
        OPRFKey &operator=(const OPRFKey &copy)
        {
            oprf_key_ = copy.oprf_key_;
            return *this;
        }
        OPRFKey &operator=(OPRFKey &&source) = default;
        OPRFKey(const OPRFKey &copy)
        {
            operator=(copy);
        }
        OPRFKey(OPRFKey &&source) = default;
        bool operator==(const OPRFKey &compare) const;
        bool operator!=(const OPRFKey &compare) const
        {
            return !operator==(compare);
        }
        void create()
        {
            // Create a random key
            ECPoint::MakeRandomNonzeroScalar(
                oprf_key_span_type{ oprf_key_.begin(), oprf_key_size });
        }
        void save(std::ostream &stream) const;
        void load(std::istream &stream);
        void save(oprf_key_span_type oprf_key) const;
        void load(oprf_key_span_const_type oprf_key);

        oprf_key_span_const_type key_span() const noexcept
        {
            return oprf_key_span_const_type{ oprf_key_.cbegin(), oprf_key_size };
        }
    private:
        std::array<unsigned char, oprf_key_size> oprf_key_;

    };
}

