#pragma once

#include <iosfwd>

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
};

