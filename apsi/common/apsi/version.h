#pragma once

#include <cstdint>

namespace apsi {
    extern const std::uint32_t apsi_version;

    extern const std::uint32_t apsi_serialization_version;

    bool same_serialization_version(std::uint32_t sv);
} // namespace apsi
