#include "he/he_config.h"

#include <algorithm>
#include <stdexcept>
#include <cmath>

namespace qwen::he
{

std::size_t HeConfig::slot_count() const
{
    return std::size_t{1} << log_slots;
}

std::size_t HeConfig::tokens_per_cipher() const
{
    const std::size_t physical_capacity = slot_count() / token_stride;
    return max_tokens_per_cipher == 0
               ? physical_capacity
               : std::min(max_tokens_per_cipher, physical_capacity);
}

double HeConfig::bootstrap_value_scale_for_layer(std::size_t layer) const
{
    if (bootstrap_value_scale_schedule.empty())
    {
        return bootstrap_value_scale;
    }
    return bootstrap_value_scale_schedule[
        std::min(layer, bootstrap_value_scale_schedule.size() - 1)];
}

void HeConfig::validate() const
{
    if (log_n < 2 || log_slots >= log_n)
    {
        throw std::invalid_argument("Qwen HE requires log_slots < log_n");
    }
    if (log_scale == 0 || log_q.size() < 2 || log_p.empty())
    {
        throw std::invalid_argument("Qwen HE modulus configuration is incomplete");
    }
    if (bootstrap_boundary_k == 0)
    {
        throw std::invalid_argument(
            "Qwen HE bootstrap boundary must be positive");
    }
    if (!std::isfinite(bootstrap_value_scale) ||
        bootstrap_value_scale <= 0.0)
    {
        throw std::invalid_argument(
            "Qwen HE bootstrap value scale must be finite and positive");
    }
    for (double value : bootstrap_value_scale_schedule)
    {
        if (!std::isfinite(value) || value <= 0.0)
        {
            throw std::invalid_argument(
                "Qwen HE bootstrap value scale schedule is invalid");
        }
    }
    if (token_stride == 0 ||
        (token_stride & (token_stride - 1)) != 0 ||
        token_stride > slot_count() ||
        slot_count() % token_stride != 0)
    {
        throw std::invalid_argument(
            "Qwen HE token_stride must be a power of two that divides the slot count");
    }
    if (max_tokens_per_cipher > slot_count() / token_stride)
    {
        throw std::invalid_argument(
            "Qwen HE logical token capacity exceeds physical slots");
    }
}

HeConfig debug_he_config()
{
    HeConfig config;
    config.log_n = 11;
    config.log_slots = 10;
    config.log_scale = 40;
    config.token_stride = 1024;
    config.log_q = {
        50, 40, 40, 40, 40, 40, 40, 40, 40, 40,
        40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    };
    config.log_p = {50};
    config.production_security = false;
    config.validate();
    return config;
}

HeConfig packed_debug_he_config()
{
    HeConfig config = debug_he_config();
    config.log_n = 13;
    config.log_slots = 12;
    config.log_q.assign(24, 40);
    config.log_q.front() = 51;
    config.validate();
    return config;
}

HeConfig deep_debug_he_config()
{
    HeConfig config = debug_he_config();
    config.log_q.assign(40, 40);
    config.log_q.front() = 50;
    config.validate();
    return config;
}

HeConfig target_he_config()
{
    HeConfig config;
    config.log_n = 16;
    config.log_slots = 15;
    config.log_scale = 46;
    config.token_stride = 1024;
    config.log_q = {51, 46};
    config.log_q.insert(config.log_q.end(), 19, 46);
    config.log_q.insert(config.log_q.end(), 14, 51);
    config.log_p = {51};
    config.max_tokens_per_cipher = 1;
    config.production_security = true;
    config.validate();
    return config;
}

HeConfig prototype_bootstrap_he_config()
{
    // Keep the larger development ring but use only one logical token block
    // per ciphertext. The extra chain levels are needed by the bootstrap
    // schedule; security validation is intentionally disabled here.
    HeConfig config = packed_debug_he_config();
    config.log_scale = 46;
    config.log_q = {51, 46};
    config.log_q.insert(config.log_q.end(), 19, 46);
    config.log_q.insert(config.log_q.end(), 14, 51);
    config.log_p = {51};
    config.max_tokens_per_cipher = 1;
    config.production_security = false;
    config.validate();
    return config;
}

HeConfig prototype_fast_bootstrap_he_config()
{
    HeConfig config;
    config.log_n = 11;
    config.log_slots = 10;
    config.log_scale = 46;
    config.token_stride = 1024;
    config.log_q = {51, 46};
    config.log_q.insert(config.log_q.end(), 19, 46);
    config.log_q.insert(config.log_q.end(), 14, 51);
    config.log_p = {51};
    config.max_tokens_per_cipher = 1;
    config.production_security = false;
    config.validate();
    return config;
}

HeConfig prototype_mid_bootstrap_he_config()
{
    HeConfig config = prototype_fast_bootstrap_he_config();
    config.log_n = 12;
    config.log_slots = 11;
    config.validate();
    return config;
}

HeConfig prototype_high_bootstrap_he_config()
{
    HeConfig config = prototype_mid_bootstrap_he_config();
    // Development-only high-precision profile.  The smaller ring keeps CPU
    // bootstrap practical while the 55-bit working scale gives the later
    // Qwen layers enough headroom after their range normalization.
    config.log_scale = 55;
    config.log_q = {60, 55};
    config.log_q.insert(config.log_q.end(), 19, 55);
    config.log_q.insert(config.log_q.end(), 14, 60);
    config.log_p = {60};
    config.bootstrap_scaling_log = 60;
    config.bootstrap_boundary_k = 25;
    config.validate();
    return config;
}

HeConfig prototype_high13_bootstrap_he_config()
{
    HeConfig config = prototype_bootstrap_he_config();
    config.log_scale = 55;
    config.log_q = {60, 55};
    config.log_q.insert(config.log_q.end(), 19, 55);
    config.log_q.insert(config.log_q.end(), 14, 60);
    config.log_p = {60};
    config.bootstrap_scaling_log = 60;
    config.validate();
    return config;
}

} // namespace qwen::he
