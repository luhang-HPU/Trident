#pragma once

#include "core/tensor.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace qwen
{

class SafeTensorStore
{
public:
    explicit SafeTensorStore(const std::filesystem::path &model_path);

    bool contains(const std::string &name) const;
    Tensor load(const std::string &name) const;
    std::vector<std::string> names() const;

private:
    struct TensorDescriptor
    {
        std::filesystem::path file;
        std::string dtype;
        std::vector<std::size_t> shape;
        std::uint64_t byte_begin = 0;
        std::uint64_t byte_end = 0;
    };

    void load_tensor_file(const std::filesystem::path &path);
    void load_model_directory(const std::filesystem::path &path);

    std::unordered_map<std::string, TensorDescriptor> tensors_;
};

} // namespace qwen
