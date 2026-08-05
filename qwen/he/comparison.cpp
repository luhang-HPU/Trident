#include "he/comparison.h"

#include "he/encrypted_ops.h"
#include "ops/plain_ops.h"
#include "relu_approx.h"

#include <cmath>
#include <stdexcept>
#include <vector>

namespace qwen::he
{

namespace
{

constexpr long kSignAlpha = 13;
constexpr double kSignScaledValue = 1.7;

std::vector<int> sign_degrees()
{
    return {15, 15, 27};
}

std::vector<Tree> sign_trees()
{
    const std::vector<int> degrees = sign_degrees();
    std::vector<Tree> trees;
    trees.reserve(degrees.size());
    for (const int degree : degrees)
    {
        Tree tree(EvalType::OddBaby);
        upgrade_oddbaby(degree, tree);
        trees.push_back(std::move(tree));
    }
    return trees;
}

void require_same_plain_shape(const Tensor &lhs, const Tensor &rhs)
{
    if (lhs.shape() != rhs.shape())
    {
        throw std::invalid_argument(
            "approximate maximum requires matching tensor shapes");
    }
}

} // namespace

void ComparisonConfig::validate() const
{
    if (!std::isfinite(difference_bound) ||
        difference_bound <= 0.0)
    {
        throw std::invalid_argument(
            "comparison difference bound must be positive");
    }
}

Tensor approximate_maximum_plain(const Tensor &lhs, const Tensor &rhs,
                                 const ComparisonConfig &config)
{
    require_same_plain_shape(lhs, rhs);
    config.validate();
    const std::vector<int> degrees = sign_degrees();
    const std::vector<Tree> trees = sign_trees();
    Tensor output(lhs.shape());
    for (std::size_t index = 0; index < lhs.numel(); ++index)
    {
        const double difference =
            lhs.data()[index] - rhs.data()[index];
        const double normalized =
            difference / config.difference_bound;
        if (std::abs(normalized) > 1.0 + 1.0e-12)
        {
            throw std::out_of_range(
                "comparison input exceeds its difference bound");
        }
        const double step = approximate_step_plain(
            normalized, degrees, kSignAlpha, trees,
            kSignScaledValue);
        output.data()[index] =
            rhs.data()[index] + difference * step;
    }
    return output;
}

EncryptedTensor encrypted_maximum(const EncryptedTensor &lhs,
                                  const EncryptedTensor &rhs,
                                  const ComparisonConfig &config,
                                  HeRuntime &runtime)
{
    config.validate();
    const EncryptedTensor difference =
        encrypted_subtract(lhs, rhs, runtime);
    Tensor inverse_bound(
        {lhs.layout().tokens, lhs.layout().features});
    std::fill(inverse_bound.data().begin(), inverse_bound.data().end(),
              1.0 / config.difference_bound);
    const EncryptedTensor normalized =
        encrypted_multiply_plain(difference, inverse_bound, runtime);

    const std::vector<int> degrees = sign_degrees();
    const std::vector<Tree> trees = sign_trees();
    std::vector<poseidon::Ciphertext> step_ciphers;
    step_ciphers.reserve(normalized.ciphertexts().size());
    for (const poseidon::Ciphertext &cipher : normalized.ciphertexts())
    {
        step_ciphers.push_back(approximate_sign(
            cipher, degrees, kSignAlpha, trees, kSignScaledValue,
            runtime.encryptor, runtime.encoder, *runtime.evaluator,
            runtime.relin_keys));
    }
    const EncryptedTensor step(
        normalized.layout(), std::move(step_ciphers));
    const EncryptedTensor selected_difference =
        encrypted_multiply(difference, step, runtime);
    return encrypted_add(rhs, selected_difference, runtime);
}

} // namespace qwen::he
