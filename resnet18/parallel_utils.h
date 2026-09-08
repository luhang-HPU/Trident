#pragma once

#include <algorithm>
#include <cstdlib>
#include <future>
#include <string>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

inline std::size_t resnet18_parallel_thread_count(std::size_t work_items)
{
    if (work_items <= 1)
    {
        return 1;
    }

    std::size_t requested = 0;
    if (const char *env = std::getenv("RESNET18_THREADS"))
    {
        try
        {
            requested = static_cast<std::size_t>(std::stoull(env));
        }
        catch (const std::exception &)
        {
            requested = 0;
        }
    }

    if (requested == 0)
    {
        requested = std::thread::hardware_concurrency();
        if (requested == 0)
        {
            requested = 1;
        }
        requested = std::min<std::size_t>(requested, 8);
    }

    return std::max<std::size_t>(1, std::min(requested, work_items));
}

template <class Fn>
void resnet18_parallel_for_with_thread_count(std::size_t work_items,
                                             std::size_t requested_threads,
                                             Fn fn)
{
    const std::size_t thread_count = std::max<std::size_t>(
        1, std::min(requested_threads, work_items == 0 ? 1 : work_items));
    if (thread_count <= 1)
    {
        for (std::size_t i = 0; i < work_items; ++i)
        {
            fn(i);
        }
        return;
    }

    const std::size_t chunk = (work_items + thread_count - 1) / thread_count;
    std::vector<std::future<void>> futures;
    futures.reserve(thread_count);
    for (std::size_t thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        const std::size_t begin = thread_index * chunk;
        if (begin >= work_items)
        {
            break;
        }
        const std::size_t end = std::min(work_items, begin + chunk);
        futures.emplace_back(std::async(std::launch::async, [begin, end, &fn]() {
            for (std::size_t i = begin; i < end; ++i)
            {
                fn(i);
            }
        }));
    }

    for (auto &future : futures)
    {
        future.get();
    }
}

template <class Fn>
void resnet18_parallel_for(std::size_t work_items, Fn fn)
{
    resnet18_parallel_for_with_thread_count(
        work_items, resnet18_parallel_thread_count(work_items), std::move(fn));
}
