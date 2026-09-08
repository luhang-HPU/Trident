#include "he/validation_log.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <stdexcept>

namespace qwen::he
{

std::filesystem::path timestamped_log_path(
    const std::filesystem::path &path)
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t now_time =
        std::chrono::system_clock::to_time_t(now);
    std::tm local_time{};
    localtime_r(&now_time, &local_time);
    const auto milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) %
        std::chrono::seconds(1);

    std::ostringstream suffix;
    suffix << '_' << std::put_time(&local_time, "%Y%m%d_%H%M%S")
           << '_' << std::setfill('0') << std::setw(3)
           << milliseconds.count();
    const std::string filename =
        path.stem().string() + suffix.str() + path.extension().string();
    return path.parent_path() / filename;
}

class ValidationLog::TeeBuffer final : public std::streambuf
{
public:
    TeeBuffer(std::streambuf *console, std::streambuf *file,
              std::mutex &file_mutex,
              std::chrono::steady_clock::time_point start,
              std::string channel)
        : console_(console), file_(file), file_mutex_(file_mutex),
          start_(start), channel_(std::move(channel))
    {
    }

protected:
    int_type overflow(int_type value) override
    {
        if (traits_type::eq_int_type(value, traits_type::eof()))
        {
            return sync() == 0 ? traits_type::not_eof(value)
                               : traits_type::eof();
        }
        const char character = traits_type::to_char_type(value);
        std::lock_guard<std::mutex> lock(file_mutex_);
        if (!write_character(character))
        {
            return traits_type::eof();
        }
        return value;
    }

    std::streamsize xsputn(const char *data,
                           std::streamsize count) override
    {
        std::lock_guard<std::mutex> lock(file_mutex_);
        std::streamsize written = 0;
        for (; written < count; ++written)
        {
            if (!write_character(data[written]))
            {
                break;
            }
        }
        return written;
    }

    int sync() override
    {
        const int console_result = console_->pubsync();
        std::lock_guard<std::mutex> lock(file_mutex_);
        const int file_result = file_->pubsync();
        return console_result == 0 && file_result == 0 ? 0 : -1;
    }

private:
    std::string prefix() const
    {
        const auto now_system = std::chrono::system_clock::now();
        const auto now_time = std::chrono::system_clock::to_time_t(now_system);
        std::tm local_time{};
        localtime_r(&now_time, &local_time);
        const auto milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now_system.time_since_epoch()) %
            std::chrono::seconds(1);
        const double elapsed =
            std::chrono::duration<double>(
                std::chrono::steady_clock::now() - start_)
                .count();
        std::ostringstream output;
        output << '[' << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S")
               << '.' << std::setfill('0') << std::setw(3)
               << milliseconds.count() << "]"
               << "[+" << std::fixed << std::setprecision(3)
               << elapsed << "s]"
               << '[' << channel_ << "] ";
        return output.str();
    }

    bool write_character(char character)
    {
        if (line_start_)
        {
            const std::string line_prefix = prefix();
            const auto prefix_size =
                static_cast<std::streamsize>(line_prefix.size());
            if (console_->sputn(line_prefix.data(), prefix_size) !=
                    prefix_size ||
                file_->sputn(line_prefix.data(), prefix_size) != prefix_size)
            {
                return false;
            }
            line_start_ = false;
        }
        if (traits_type::eq_int_type(console_->sputc(character),
                                     traits_type::eof()) ||
            traits_type::eq_int_type(file_->sputc(character),
                                     traits_type::eof()))
        {
            return false;
        }
        if (character == '\n')
        {
            line_start_ = true;
        }
        return true;
    }

    std::streambuf *console_;
    std::streambuf *file_;
    std::mutex &file_mutex_;
    std::chrono::steady_clock::time_point start_;
    std::string channel_;
    bool line_start_ = true;
};

ValidationLog::ValidationLog(const std::string &path) : file_(path)
{
    if (!file_)
    {
        throw std::runtime_error("cannot open validation log: " + path);
    }
    const auto start = std::chrono::steady_clock::now();
    file_ << "# Qwen encrypted inference validation log\n"
          << "# Each runtime line contains local wall time, elapsed time, and stream\n";
    file_.flush();
    old_stdout_ = std::cout.rdbuf();
    old_stderr_ = std::cerr.rdbuf();
    stdout_buffer_ = std::make_unique<TeeBuffer>(
        old_stdout_, file_.rdbuf(), file_mutex_, start, "out");
    stderr_buffer_ = std::make_unique<TeeBuffer>(
        old_stderr_, file_.rdbuf(), file_mutex_, start, "err");
    std::cout.rdbuf(stdout_buffer_.get());
    std::cerr.rdbuf(stderr_buffer_.get());
}

ValidationLog::~ValidationLog()
{
    std::cout.flush();
    std::cerr.flush();
    if (old_stdout_ != nullptr)
    {
        std::cout.rdbuf(old_stdout_);
    }
    if (old_stderr_ != nullptr)
    {
        std::cerr.rdbuf(old_stderr_);
    }
}

} // namespace qwen::he
