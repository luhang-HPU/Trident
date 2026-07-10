#include "progress_log.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <sstream>
#include <streambuf>

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

    std::streamsize xsputn(const char *s, std::streamsize count) override
    {
        for (std::streamsize i = 0; i < count; ++i)
        {
            overflow(static_cast<unsigned char>(s[i]));
        }
        return count;
    }

    int sync() override
    {
        target_.flush();
        return 0;
    }

private:
    std::ostream &target_;
    bool at_line_start_ = true;
};

} // namespace

std::ostream &resnet18_progress_log()
{
    return *g_progress_log;
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
