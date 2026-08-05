#include "io/safetensors.h"

#include "poseidon/util/json.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <stdexcept>

namespace qwen
{
namespace
{

using Json = nlohmann::json;

constexpr std::uint64_t kMaximumHeaderSize = 100ULL * 1024ULL * 1024ULL;

std::uint64_t read_little_endian_u64(std::istream &input)
{
    std::array<unsigned char, 8> bytes{};
    input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input)
    {
        throw std::runtime_error("failed to read safetensors header length");
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index)
    {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
    }
    return value;
}

std::size_t dtype_size(const std::string &dtype)
{
    if (dtype == "F64")
    {
        return 8;
    }
    if (dtype == "F32")
    {
        return 4;
    }
    if (dtype == "F16" || dtype == "BF16")
    {
        return 2;
    }
    throw std::invalid_argument("unsupported safetensors dtype: " + dtype);
}

std::size_t checked_element_count(const std::vector<std::size_t> &shape)
{
    if (shape.empty())
    {
        throw std::invalid_argument("scalar safetensors are not supported");
    }
    std::size_t count = 1;
    for (std::size_t extent : shape)
    {
        if (extent == 0 || count > std::numeric_limits<std::size_t>::max() / extent)
        {
            throw std::invalid_argument("invalid safetensors shape");
        }
        count *= extent;
    }
    return count;
}

float half_to_float(std::uint16_t bits)
{
    const bool negative = (bits & 0x8000U) != 0;
    const std::uint16_t exponent = static_cast<std::uint16_t>((bits >> 10) & 0x1FU);
    const std::uint16_t fraction = static_cast<std::uint16_t>(bits & 0x03FFU);

    double value = 0.0;
    if (exponent == 0)
    {
        value = std::ldexp(static_cast<double>(fraction), -24);
    }
    else if (exponent == 0x1FU)
    {
        value = fraction == 0 ? std::numeric_limits<double>::infinity()
                              : std::numeric_limits<double>::quiet_NaN();
    }
    else
    {
        value = std::ldexp(1.0 + static_cast<double>(fraction) / 1024.0,
                           static_cast<int>(exponent) - 15);
    }
    return static_cast<float>(negative ? -value : value);
}

template <typename T> T read_native(const unsigned char *data)
{
    T value{};
    std::memcpy(&value, data, sizeof(T));
    return value;
}

double decode_value(const unsigned char *data, const std::string &dtype)
{
    if constexpr (std::endian::native != std::endian::little)
    {
        throw std::runtime_error("safetensors loading currently requires a little-endian CPU");
    }
    if (dtype == "F64")
    {
        return read_native<double>(data);
    }
    if (dtype == "F32")
    {
        return static_cast<double>(read_native<float>(data));
    }
    if (dtype == "F16")
    {
        return static_cast<double>(half_to_float(read_native<std::uint16_t>(data)));
    }
    if (dtype == "BF16")
    {
        const std::uint32_t float_bits =
            static_cast<std::uint32_t>(read_native<std::uint16_t>(data)) << 16;
        float value = 0.0F;
        std::memcpy(&value, &float_bits, sizeof(value));
        return static_cast<double>(value);
    }
    throw std::invalid_argument("unsupported safetensors dtype: " + dtype);
}

std::set<std::string> files_from_index(const std::filesystem::path &index_path)
{
    std::ifstream input(index_path);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open safetensors index: " + index_path.string());
    }
    Json index;
    input >> index;
    if (!index.contains("weight_map") || !index.at("weight_map").is_object())
    {
        throw std::invalid_argument("safetensors index does not contain weight_map");
    }

    std::set<std::string> files;
    for (const auto &[name, file] : index.at("weight_map").items())
    {
        static_cast<void>(name);
        if (!file.is_string())
        {
            throw std::invalid_argument("invalid file entry in safetensors weight_map");
        }
        files.insert(file.get<std::string>());
    }
    return files;
}

} // namespace

SafeTensorStore::SafeTensorStore(const std::filesystem::path &model_path)
{
    if (std::filesystem::is_directory(model_path))
    {
        load_model_directory(model_path);
    }
    else
    {
        load_tensor_file(model_path);
    }
    if (tensors_.empty())
    {
        throw std::runtime_error("no tensors found at: " + model_path.string());
    }
}

bool SafeTensorStore::contains(const std::string &name) const
{
    return tensors_.find(name) != tensors_.end();
}

Tensor SafeTensorStore::load(const std::string &name) const
{
    const auto iterator = tensors_.find(name);
    if (iterator == tensors_.end())
    {
        throw std::runtime_error("tensor is missing from checkpoint: " + name);
    }
    const TensorDescriptor &descriptor = iterator->second;
    const std::uint64_t byte_count = descriptor.byte_end - descriptor.byte_begin;
    if (byte_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        throw std::runtime_error("tensor is too large to load: " + name);
    }

    std::ifstream input(descriptor.file, std::ios::binary);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open tensor file: " + descriptor.file.string());
    }
    input.seekg(static_cast<std::streamoff>(descriptor.byte_begin));
    std::vector<unsigned char> bytes(static_cast<std::size_t>(byte_count));
    input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input)
    {
        throw std::runtime_error("failed to read tensor data: " + name);
    }

    const std::size_t element_size = dtype_size(descriptor.dtype);
    const std::size_t count = checked_element_count(descriptor.shape);
    Tensor tensor(descriptor.shape);
    for (std::size_t index = 0; index < count; ++index)
    {
        tensor.data()[index] =
            decode_value(bytes.data() + index * element_size, descriptor.dtype);
    }
    return tensor;
}

std::vector<std::string> SafeTensorStore::names() const
{
    std::vector<std::string> result;
    result.reserve(tensors_.size());
    for (const auto &[name, descriptor] : tensors_)
    {
        static_cast<void>(descriptor);
        result.push_back(name);
    }
    std::sort(result.begin(), result.end());
    return result;
}

void SafeTensorStore::load_tensor_file(const std::filesystem::path &path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open())
    {
        throw std::runtime_error("failed to open safetensors file: " + path.string());
    }
    const std::uint64_t file_size = std::filesystem::file_size(path);
    const std::uint64_t header_size = read_little_endian_u64(input);
    if (header_size == 0 || header_size > kMaximumHeaderSize || header_size + 8 > file_size)
    {
        throw std::invalid_argument("invalid safetensors header size in: " + path.string());
    }

    std::string header(static_cast<std::size_t>(header_size), '\0');
    input.read(header.data(), static_cast<std::streamsize>(header.size()));
    if (!input)
    {
        throw std::runtime_error("failed to read safetensors header: " + path.string());
    }

    Json metadata;
    try
    {
        metadata = Json::parse(header);
    }
    catch (const std::exception &error)
    {
        throw std::invalid_argument("invalid safetensors JSON in " + path.string() + ": " +
                                    error.what());
    }
    if (!metadata.is_object())
    {
        throw std::invalid_argument("safetensors header must be an object");
    }

    const std::uint64_t data_start = 8 + header_size;
    for (const auto &[name, value] : metadata.items())
    {
        if (name == "__metadata__")
        {
            continue;
        }
        if (!value.is_object() || !value.contains("dtype") || !value.contains("shape") ||
            !value.contains("data_offsets"))
        {
            throw std::invalid_argument("invalid safetensors descriptor: " + name);
        }

        TensorDescriptor descriptor;
        descriptor.file = path;
        descriptor.dtype = value.at("dtype").get<std::string>();
        descriptor.shape = value.at("shape").get<std::vector<std::size_t>>();
        const std::vector<std::uint64_t> offsets =
            value.at("data_offsets").get<std::vector<std::uint64_t>>();
        if (offsets.size() != 2 || offsets[1] < offsets[0])
        {
            throw std::invalid_argument("invalid safetensors data offsets: " + name);
        }
        descriptor.byte_begin = data_start + offsets[0];
        descriptor.byte_end = data_start + offsets[1];

        const std::size_t count = checked_element_count(descriptor.shape);
        const std::size_t element_size = dtype_size(descriptor.dtype);
        if (count > std::numeric_limits<std::size_t>::max() / element_size ||
            offsets[1] - offsets[0] != count * element_size ||
            descriptor.byte_end > file_size)
        {
            throw std::invalid_argument("safetensors byte size does not match shape: " + name);
        }
        if (!tensors_.emplace(name, std::move(descriptor)).second)
        {
            throw std::invalid_argument("duplicate tensor name in checkpoint: " + name);
        }
    }
}

void SafeTensorStore::load_model_directory(const std::filesystem::path &path)
{
    const std::filesystem::path index = path / "model.safetensors.index.json";
    if (std::filesystem::exists(index))
    {
        for (const std::string &file : files_from_index(index))
        {
            load_tensor_file(path / file);
        }
        return;
    }

    const std::filesystem::path single_file = path / "model.safetensors";
    if (std::filesystem::exists(single_file))
    {
        load_tensor_file(single_file);
        return;
    }
    throw std::runtime_error("model directory has no safetensors checkpoint: " + path.string());
}

} // namespace qwen
