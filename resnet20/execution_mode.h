#pragma once

#include <atomic>

namespace resnet20_execution
{
inline std::atomic<bool> inference_only_enabled{false};

inline void set_inference_only(bool enabled)
{
    inference_only_enabled.store(enabled, std::memory_order_relaxed);
}

inline bool inference_only()
{
    return inference_only_enabled.load(std::memory_order_relaxed);
}
} // namespace resnet20_execution
