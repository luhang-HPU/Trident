#include "progress_log.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <mutex>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>

namespace
{

std::ostream *g_progress_log = &std::cout;

std::string timestamp_prefix()
{
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &time);
#else
    localtime_r(&time, &local_tm);
#endif

    std::ostringstream out;
    out << '[' << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S") << '.'
        << std::setw(3) << std::setfill('0') << millis << "] ";
    return out.str();
}

class TimestampPrefixBuf : public std::streambuf
{
public:
    explicit TimestampPrefixBuf(std::ostream &target)
        : target_(target)
    {
    }

protected:
    int overflow(int ch) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return write_char(ch);
    }

    std::streamsize xsputn(const char *s, std::streamsize count) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (std::streamsize i = 0; i < count; ++i)
        {
            write_char(static_cast<unsigned char>(s[i]));
        }
        return count;
    }

    int sync() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        target_.flush();
        return 0;
    }

private:
    int write_char(int ch)
    {
        if (ch == traits_type::eof())
        {
            return traits_type::not_eof(ch);
        }

        if (at_line_start_)
        {
            const std::string prefix = timestamp_prefix();
            target_.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
            at_line_start_ = false;
        }

        target_.put(static_cast<char>(ch));
        if (ch == '\n')
        {
            target_.flush();
            at_line_start_ = true;
        }
        return ch;
    }
    std::ostream &target_;
    bool at_line_start_ = true;
    std::mutex mutex_;
};

} // namespace

std::ostream &resnet18_progress_log()
{
    return *g_progress_log;
}

ProcessMemorySnapshot capture_process_memory()
{
    ProcessMemorySnapshot snapshot;
    std::ifstream status("/proc/self/status");
    if (!status.is_open())
    {
        return snapshot;
    }

    std::string line;
    while (std::getline(status, line))
    {
        std::istringstream fields(line);
        std::string key;
        std::uint64_t value = 0;
        fields >> key >> value;
        if (key == "VmRSS:")
        {
            snapshot.rss_kb = value;
        }
        else if (key == "VmHWM:")
        {
            snapshot.peak_rss_kb = value;
        }
        else if (key == "VmSize:")
        {
            snapshot.virtual_kb = value;
        }
    }
    snapshot.available = snapshot.rss_kb != 0 || snapshot.peak_rss_kb != 0 ||
                         snapshot.virtual_kb != 0;
    return snapshot;
}

void log_process_memory_snapshot(const std::string &label,
                                 const ProcessMemorySnapshot &snapshot)
{
    if (!snapshot.available)
    {
        resnet18_progress_log() << "[memory] " << label << ": unavailable" << std::endl;
        return;
    }
    resnet18_progress_log() << "[memory] " << label << ": rss_kb=" << snapshot.rss_kb
                            << ", peak_rss_kb=" << snapshot.peak_rss_kb
                            << ", virtual_kb=" << snapshot.virtual_kb << std::endl;
}

void log_process_memory_change(const std::string &label,
                               const ProcessMemorySnapshot &before,
                               const ProcessMemorySnapshot &after)
{
    if (!before.available || !after.available)
    {
        resnet18_progress_log() << "[memory] " << label << ": unavailable" << std::endl;
        return;
    }
    const auto rss_delta = static_cast<std::int64_t>(after.rss_kb) -
                           static_cast<std::int64_t>(before.rss_kb);
    const auto peak_delta = static_cast<std::int64_t>(after.peak_rss_kb) -
                            static_cast<std::int64_t>(before.peak_rss_kb);
    const auto virtual_delta = static_cast<std::int64_t>(after.virtual_kb) -
                               static_cast<std::int64_t>(before.virtual_kb);
    resnet18_progress_log()
        << "[memory] " << label << ": rss_before_kb=" << before.rss_kb
        << ", rss_after_kb=" << after.rss_kb << ", rss_delta_kb=" << rss_delta
        << ", peak_rss_before_kb=" << before.peak_rss_kb
        << ", peak_rss_after_kb=" << after.peak_rss_kb
        << ", peak_rss_delta_kb=" << peak_delta
        << ", virtual_before_kb=" << before.virtual_kb
        << ", virtual_after_kb=" << after.virtual_kb
        << ", virtual_delta_kb=" << virtual_delta << std::endl;
}

ScopedOperationMetrics::ScopedOperationMetrics(std::string label)
    : label_(std::move(label)), start_(std::chrono::steady_clock::now()),
      memory_before_(capture_process_memory())
{
    resnet18_progress_log() << "[operation-start] " << label_ << std::endl;
    log_process_memory_snapshot(label_ + " start", memory_before_);
}

ScopedOperationMetrics::~ScopedOperationMetrics()
{
    try
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - start_)
                                 .count();
        const ProcessMemorySnapshot memory_after = capture_process_memory();
        resnet18_progress_log() << "[duration] " << label_ << ": " << elapsed << " ms"
                                << std::endl;
        log_process_memory_change(label_, memory_before_, memory_after);
    }
    catch (...)
    {
    }
}

ScopedProgressLogTarget::ScopedProgressLogTarget(std::ostream &target)
    : previous_(g_progress_log)
{
    timestamp_buffer_ = std::make_unique<TimestampPrefixBuf>(target);
    timestamp_stream_ = std::make_unique<std::ostream>(timestamp_buffer_.get());
    g_progress_log = timestamp_stream_.get();
}

ScopedProgressLogTarget::~ScopedProgressLogTarget()
{
    if (timestamp_stream_)
    {
        timestamp_stream_->flush();
    }
    g_progress_log = previous_;
}
