#include "progress_log.h"

#include <iostream>

namespace
{

std::ostream *g_progress_log = &std::cout;

} // namespace

std::ostream &resnet18_progress_log()
{
    return *g_progress_log;
}

ScopedProgressLogTarget::ScopedProgressLogTarget(std::ostream &target)
    : previous_(g_progress_log)
{
    g_progress_log = &target;
}

ScopedProgressLogTarget::~ScopedProgressLogTarget()
{
    g_progress_log = previous_;
}

