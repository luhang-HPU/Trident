#pragma once

#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>

std::ostream &resnet18_progress_log();

struct ProcessMemorySnapshot
{
    bool available = false;
    std::uint64_t rss_kb = 0;
    std::uint64_t peak_rss_kb = 0;
    std::uint64_t virtual_kb = 0;
};

ProcessMemorySnapshot capture_process_memory();
void log_process_memory_snapshot(const std::string &label,
                                 const ProcessMemorySnapshot &snapshot);
void log_process_memory_change(const std::string &label,
                               const ProcessMemorySnapshot &before,
                               const ProcessMemorySnapshot &after);

class ScopedOperationMetrics
{
public:
    explicit ScopedOperationMetrics(std::string label);
    ~ScopedOperationMetrics();

    ScopedOperationMetrics(const ScopedOperationMetrics &) = delete;
    ScopedOperationMetrics &operator=(const ScopedOperationMetrics &) = delete;

private:
    std::string label_;
    std::chrono::steady_clock::time_point start_;
    ProcessMemorySnapshot memory_before_;
};

class ScopedProgressLogTarget
{
public:
    explicit ScopedProgressLogTarget(std::ostream &target);
    ~ScopedProgressLogTarget();

    ScopedProgressLogTarget(const ScopedProgressLogTarget &) = delete;
    ScopedProgressLogTarget &operator=(const ScopedProgressLogTarget &) = delete;

private:
    std::ostream *previous_;
    std::unique_ptr<std::streambuf> timestamp_buffer_;
    std::unique_ptr<std::ostream> timestamp_stream_;
};
