#include "core/tensor.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace qwen
{
namespace
{

std::size_t element_count(const std::vector<std::size_t> &shape)
{
    if (shape.empty())
    {
        return 0;
    }
    return std::accumulate(shape.begin(), shape.end(), std::size_t{1},
                           [](std::size_t lhs, std::size_t rhs) {
                               if (rhs == 0 || lhs > std::numeric_limits<std::size_t>::max() / rhs)
                               {
                                   throw std::invalid_argument("tensor shape is empty or too large");
                               }
                               return lhs * rhs;
                           });
}

} // namespace

Tensor::Tensor(std::vector<std::size_t> shape)
    : shape_(std::move(shape)), data_(element_count(shape_), 0.0)
{
    validate_shape();
}

Tensor::Tensor(std::vector<std::size_t> shape, std::vector<double> data)
    : shape_(std::move(shape)), data_(std::move(data))
{
    validate_shape();
    if (data_.size() != element_count(shape_))
    {
        throw std::invalid_argument("tensor data size does not match shape");
    }
}

bool Tensor::empty() const
{
    return data_.empty();
}

std::size_t Tensor::rank() const
{
    return shape_.size();
}

std::size_t Tensor::dim(std::size_t axis) const
{
    if (axis >= shape_.size())
    {
        throw std::out_of_range("tensor axis is out of range");
    }
    return shape_[axis];
}

std::size_t Tensor::numel() const
{
    return data_.size();
}

const std::vector<std::size_t> &Tensor::shape() const
{
    return shape_;
}

const std::vector<double> &Tensor::data() const
{
    return data_;
}

std::vector<double> &Tensor::data()
{
    return data_;
}

double &Tensor::at(std::size_t i)
{
    if (rank() != 1 || i >= dim(0))
    {
        throw std::out_of_range("invalid rank-1 tensor index");
    }
    return data_[i];
}

double Tensor::at(std::size_t i) const
{
    if (rank() != 1 || i >= dim(0))
    {
        throw std::out_of_range("invalid rank-1 tensor index");
    }
    return data_[i];
}

double &Tensor::at(std::size_t i, std::size_t j)
{
    return data_[offset2(i, j)];
}

double Tensor::at(std::size_t i, std::size_t j) const
{
    return data_[offset2(i, j)];
}

double &Tensor::at(std::size_t i, std::size_t j, std::size_t k)
{
    return data_[offset3(i, j, k)];
}

double Tensor::at(std::size_t i, std::size_t j, std::size_t k) const
{
    return data_[offset3(i, j, k)];
}

Tensor Tensor::reshape(std::vector<std::size_t> shape) const
{
    if (element_count(shape) != numel())
    {
        throw std::invalid_argument("reshape changes tensor element count");
    }
    return Tensor(std::move(shape), data_);
}

std::size_t Tensor::offset2(std::size_t i, std::size_t j) const
{
    if (rank() != 2 || i >= dim(0) || j >= dim(1))
    {
        throw std::out_of_range("invalid rank-2 tensor index");
    }
    return i * dim(1) + j;
}

std::size_t Tensor::offset3(std::size_t i, std::size_t j, std::size_t k) const
{
    if (rank() != 3 || i >= dim(0) || j >= dim(1) || k >= dim(2))
    {
        throw std::out_of_range("invalid rank-3 tensor index");
    }
    return (i * dim(1) + j) * dim(2) + k;
}

void Tensor::validate_shape() const
{
    if (shape_.empty() && !data_.empty())
    {
        throw std::invalid_argument("a non-empty tensor must have a shape");
    }
    for (std::size_t extent : shape_)
    {
        if (extent == 0)
        {
            throw std::invalid_argument("tensor dimensions must be positive");
        }
    }
}

TensorStats tensor_stats(const Tensor &tensor)
{
    TensorStats stats;
    stats.count = tensor.numel();
    if (tensor.empty())
    {
        return stats;
    }

    stats.min = std::numeric_limits<double>::infinity();
    stats.max = -std::numeric_limits<double>::infinity();
    double sum = 0.0;
    for (double value : tensor.data())
    {
        if (!std::isfinite(value))
        {
            stats.all_finite = false;
            continue;
        }
        stats.min = std::min(stats.min, value);
        stats.max = std::max(stats.max, value);
        stats.max_abs = std::max(stats.max_abs, std::abs(value));
        sum += value;
    }
    stats.mean = sum / static_cast<double>(stats.count);
    return stats;
}

std::string shape_string(const Tensor &tensor)
{
    std::ostringstream output;
    output << '[';
    for (std::size_t axis = 0; axis < tensor.rank(); ++axis)
    {
        if (axis)
        {
            output << ',';
        }
        output << tensor.dim(axis);
    }
    output << ']';
    return output.str();
}

void print_tensor_summary(const std::string &name, const Tensor &tensor, std::ostream &output,
                          std::size_t preview_count)
{
    const TensorStats stats = tensor_stats(tensor);
    output << name << " shape=" << shape_string(tensor) << " min=" << stats.min
           << " max=" << stats.max << " mean=" << stats.mean
           << " max_abs=" << stats.max_abs
           << " finite=" << (stats.all_finite ? "yes" : "no") << '\n';
    output << "  preview:";
    const std::size_t count = std::min(preview_count, tensor.numel());
    for (std::size_t i = 0; i < count; ++i)
    {
        output << ' ' << tensor.data()[i];
    }
    output << '\n';
}

} // namespace qwen
