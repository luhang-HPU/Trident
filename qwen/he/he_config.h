#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace qwen::he
{

struct HeConfig
{
    std::uint32_t log_n = 11;
    std::uint32_t log_slots = 10;
    std::uint32_t log_scale = 40;
    std::uint32_t hamming_weight = 5;
    std::uint32_t q0_level = 0;
    std::uint32_t bootstrap_boundary_k = 25;
    std::uint32_t bootstrap_scaling_log = 51;
    double bootstrap_value_scale = 1.0;
    std::vector<double> bootstrap_value_scale_schedule;
    std::size_t token_stride = 1024;
    std::vector<std::uint32_t> log_q;
    std::vector<std::uint32_t> log_p;
    // Zero uses every physical token block. One keeps each logical token in
    // a separate ciphertext without changing the CKKS ring or slot count.
    std::size_t max_tokens_per_cipher = 0;
    bool production_security = false;
    // Keeps the tc128 parameter context intact while allowing explicitly
    // requested decrypt/re-encrypt validation boundaries. Such a run uses
    // production-shaped parameters but is not a secure inference protocol.
    bool allow_insecure_mock_boundaries = false;

    std::size_t slot_count() const;
    std::size_t tokens_per_cipher() const;
    double bootstrap_value_scale_for_layer(std::size_t layer) const;
    void validate() const;
};

// Fast CPU configuration for operator development. It is intentionally not a
// production security parameter set.
HeConfig debug_he_config();

// Non-secure small-ring configuration with four 1024-slot token blocks per
// ciphertext. This keeps packed-operator tests practical on a CPU.
HeConfig packed_debug_he_config();

// Non-secure small-ring configuration used only to exercise deep composed
// operators without paying the cost of a production bootstrap.
HeConfig deep_debug_he_config();

// CPU reference parameters matching the 2^16 CKKS ring and 14-level
// bootstrap shape used by AEGIS. This configuration enforces 128-bit
// parameter validation and keeps each Qwen token in its own ciphertext.
HeConfig target_he_config();

// Small-ring bootstrap profile for end-to-end CPU validation. This executes
// the same encrypted operators and bootstrap schedule as the target profile,
// but intentionally does not claim tc128 security.
HeConfig prototype_bootstrap_he_config();

// Minimal one-token CPU profile. The CKKS ring has exactly 1024 active slots
// and is intended only to make a full-model encrypted run practical.
HeConfig prototype_fast_bootstrap_he_config();

// Intermediate CPU profile (logN=12) used to trade runtime for long-stack
// CKKS precision during development.
HeConfig prototype_mid_bootstrap_he_config();

// High-precision reduced-ring profile for long-stack range-calibrated runs.
HeConfig prototype_high_bootstrap_he_config();

// Larger-ring high-precision development profile. This is still
// development-only, but provides more CKKS headroom for long Qwen stacks.
HeConfig prototype_high13_bootstrap_he_config();

} // namespace qwen::he
