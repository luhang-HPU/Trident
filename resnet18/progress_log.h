#pragma once

#include <iosfwd>
#include <memory>

std::ostream &resnet18_progress_log();

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
