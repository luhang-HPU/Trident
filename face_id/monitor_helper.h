#pragma once

#include "monitor/memory_and_cpu.h"
#include <chrono>

class MonitorForCompute
{
public:
    std::chrono::time_point<std::chrono::system_clock> compute_start_;
    std::chrono::time_point<std::chrono::system_clock> compute_end_;

    MonitorForCompute() : compute_start_(std::chrono::high_resolution_clock::now()), compute_end_(compute_start_){};
};

struct MonitorForCpuMemory
{
    MemOccupy mem_stat;
    CpuUsage cpu_usage;
};
