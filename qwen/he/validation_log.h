#pragma once

#include <fstream>
#include <filesystem>
#include <iosfwd>
#include <memory>
#include <mutex>
#include <string>

namespace qwen::he
{

std::filesystem::path timestamped_log_path(
    const std::filesystem::path &path);

// Duplicates stdout/stderr into a file so long-running validation runs leave
// a complete, human-readable record without changing the existing CLI output.
class ValidationLog
{
public:
    explicit ValidationLog(const std::string &path);
    ~ValidationLog();

    ValidationLog(const ValidationLog &) = delete;
    ValidationLog &operator=(const ValidationLog &) = delete;

private:
    class TeeBuffer;
    std::ofstream file_;
    std::mutex file_mutex_;
    std::unique_ptr<TeeBuffer> stdout_buffer_;
    std::unique_ptr<TeeBuffer> stderr_buffer_;
    std::streambuf *old_stdout_ = nullptr;
    std::streambuf *old_stderr_ = nullptr;
};

} // namespace qwen::he
