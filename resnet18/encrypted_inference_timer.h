#pragma once

#include <chrono>
#include <cstddef>

namespace resnet18_timing
{
namespace detail
{
struct EncryptedInferenceAccumulator
{
    std::chrono::steady_clock::duration elapsed{};
    std::size_t operation_count = 0;
};

inline thread_local EncryptedInferenceAccumulator *current_accumulator = nullptr;
inline thread_local std::size_t operation_depth = 0;
} // namespace detail

class EncryptedInferenceTimerSession
{
public:
    EncryptedInferenceTimerSession()
        : previous_accumulator_(detail::current_accumulator),
          previous_depth_(detail::operation_depth)
    {
        detail::current_accumulator = &accumulator_;
        detail::operation_depth = 0;
    }

    ~EncryptedInferenceTimerSession()
    {
        detail::current_accumulator = previous_accumulator_;
        detail::operation_depth = previous_depth_;
    }

    EncryptedInferenceTimerSession(const EncryptedInferenceTimerSession &) = delete;
    EncryptedInferenceTimerSession &operator=(
        const EncryptedInferenceTimerSession &) = delete;

    long long elapsed_milliseconds() const
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   accumulator_.elapsed)
            .count();
    }

    std::size_t operation_count() const
    {
        return accumulator_.operation_count;
    }

private:
    detail::EncryptedInferenceAccumulator accumulator_;
    detail::EncryptedInferenceAccumulator *previous_accumulator_ = nullptr;
    std::size_t previous_depth_ = 0;
};

class ScopedEncryptedInferenceOperation
{
public:
    ScopedEncryptedInferenceOperation()
        : accumulator_(detail::current_accumulator)
    {
        if (accumulator_ != nullptr)
        {
            outermost_ = detail::operation_depth++ == 0;
            if (outermost_)
            {
                start_ = std::chrono::steady_clock::now();
            }
        }
    }

    ~ScopedEncryptedInferenceOperation()
    {
        if (accumulator_ == nullptr)
        {
            return;
        }
        --detail::operation_depth;
        if (outermost_)
        {
            accumulator_->elapsed += std::chrono::steady_clock::now() - start_;
            ++accumulator_->operation_count;
        }
    }

    ScopedEncryptedInferenceOperation(const ScopedEncryptedInferenceOperation &) = delete;
    ScopedEncryptedInferenceOperation &operator=(
        const ScopedEncryptedInferenceOperation &) = delete;

private:
    detail::EncryptedInferenceAccumulator *accumulator_ = nullptr;
    bool outermost_ = false;
    std::chrono::steady_clock::time_point start_{};
};
} // namespace resnet18_timing
