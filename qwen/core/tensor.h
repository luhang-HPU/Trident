#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

namespace qwen
{

class Tensor
{
public:
    Tensor() = default;
    explicit Tensor(std::vector<std::size_t> shape);
    Tensor(std::vector<std::size_t> shape, std::vector<double> data);

    bool empty() const;
    std::size_t rank() const;
    std::size_t dim(std::size_t axis) const;
    std::size_t numel() const;
    const std::vector<std::size_t> &shape() const;

    const std::vector<double> &data() const;
    std::vector<double> &data();

    double &at(std::size_t i);
    double at(std::size_t i) const;
    double &at(std::size_t i, std::size_t j);
    double at(std::size_t i, std::size_t j) const;
    double &at(std::size_t i, std::size_t j, std::size_t k);
    double at(std::size_t i, std::size_t j, std::size_t k) const;

    Tensor reshape(std::vector<std::size_t> shape) const;

private:
    std::size_t offset2(std::size_t i, std::size_t j) const;
    std::size_t offset3(std::size_t i, std::size_t j, std::size_t k) const;
    void validate_shape() const;

    std::vector<std::size_t> shape_;
    std::vector<double> data_;
};

struct TensorStats
{
    std::size_t count = 0;
    double min = 0.0;
    double max = 0.0;
    double mean = 0.0;
    double max_abs = 0.0;
    bool all_finite = true;
};

TensorStats tensor_stats(const Tensor &tensor);
std::string shape_string(const Tensor &tensor);
void print_tensor_summary(const std::string &name, const Tensor &tensor, std::ostream &output,
                          std::size_t preview_count = 8);

} // namespace qwen
