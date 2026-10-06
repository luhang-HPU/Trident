#include "chebyshev_relu.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <stdexcept>

using namespace poseidon;

const std::vector<double> &chebyshev_relu_coefficients()
{
    static const std::vector<double> coefficients = [] {
        // DCT at the roots of T_(degree+1), as in OpenFHE's
        // EvalChebyshevCoefficients. Poseidon/plain evaluation uses c0, not c0/2.
        constexpr int count = kChebyshevReluDegree + 1;
        const long double pi = std::acos(-1.0L);
        std::vector<double> result(count, 0.0);
        for (int k = 0; k < count; ++k)
        {
            long double sum = 0.0L;
            for (int j = 0; j < count; ++j)
            {
                const long double theta = pi * (j + 0.5L) / count;
                sum += std::max(0.0L, std::cos(theta)) * std::cos(k * theta);
            }
            result[k] = static_cast<double>(sum * (k == 0 ? 1.0L : 2.0L) / count);
        }
        // ReLU = (x + |x|)/2: all odd terms except T1 vanish exactly.
        result[1] = 0.5;
        for (int k = 3; k < count; k += 2)
            result[k] = 0.0;
        return result;
    }();
    return coefficients;
}

double chebyshev_relu_plain(double input)
{
    const auto &coefficients = chebyshev_relu_coefficients();
    double next = 0.0, next_next = 0.0;
    for (int k = kChebyshevReluDegree; k >= 1; --k)
    {
        const double value = 2.0 * input * next - next_next + coefficients[k];
        next_next = next;
        next = value;
    }
    return input * next - next_next + coefficients[0];
}

namespace
{

// Split p = T_s * q + r using 2*T_s*T_j = T_(s+j) + T_(s-j).
// A full 512-coefficient tree has 32 degree-15 leaves and five merges.
// Basis generation: 4 levels; coefficient multiplication: 1; merges: 5.
class ChebyshevReluEvaluator
{
public:
    ChebyshevReluEvaluator(const Ciphertext &input, EvaluatorCkksBase &evaluator,
                          CKKSEncoder &encoder, const RelinKeys &relin_keys)
        : evaluator_(evaluator), encoder_(encoder), relin_keys_(relin_keys),
          input_level_(input.level())
    {
        basis_.emplace(1, input);
    }

    Ciphertext run(double output_scale)
    {
        std::vector<double> coefficients = chebyshev_relu_coefficients();
        coefficients.resize(512, 0.0);
        return evaluate(coefficients, output_scale);
    }

private:
    double prime(int level) const
    {
        return static_cast<double>(encoder_.context().parameters_literal()->q().at(level).value());
    }

    Ciphertext at_level(const Ciphertext &input, int level)
    {
        if (input.level() < level)
            throw std::logic_error("Chebyshev ReLU attempted to raise a ciphertext level");
        Ciphertext result = input;
        if (input.level() > level)
            evaluator_.drop_modulus(input, result,
                encoder_.context().crt_context()->parms_id_map().at(level));
        return result;
    }

    const Ciphertext &basis(int degree)
    {
        auto found = basis_.find(degree);
        if (found != basis_.end())
            return found->second;
        const int a = (degree + 1) / 2;
        const int b = degree / 2;
        const Ciphertext &lhs = basis(a);
        const Ciphertext &rhs = basis(b);
        Ciphertext product;
        evaluator_.multiply_relin_dynamic(lhs, rhs, product, relin_keys_);
        evaluator_.add(product, product, product);
        if (a == b)
        {
            evaluator_.add_const(product, -1.0, product, encoder_);
        }
        else
        {
            // Align the correction at the high product scale BEFORE rescale.
            // Encoding 1 at a ~2^40 ratio preserves the value without resetting
            // scale metadata or paying for another level.
            Ciphertext correction = at_level(basis(a - b), product.level());
            evaluator_.multiply_const(correction, 1.0,
                product.scale() / correction.scale(), correction, encoder_);
            evaluator_.sub(product, correction, product);
        }
        evaluator_.rescale(product, product);
        return basis_.emplace(degree, std::move(product)).first->second;
    }

    Ciphertext evaluate(const std::vector<double> &coefficients, double output_scale)
    {
        if (coefficients.size() == 16)
        {
            const int level = input_level_ - 4;
            const double high_scale = output_scale * prime(level);
            Ciphertext sum;
            for (int k = 1; k < 16; ++k)
            {
                if (coefficients[k] == 0.0)
                    continue;
                Ciphertext term = at_level(basis(k), level);
                evaluator_.multiply_const(term, coefficients[k],
                    high_scale / term.scale(), term, encoder_);
                if (!sum.is_valid())
                    sum = std::move(term);
                else
                    evaluator_.add(sum, term, sum);
            }
            if (!sum.is_valid())
            {
                sum = at_level(basis(1), level);
                Plaintext zero;
                encoder_.encode(0.0, sum.parms_id(), high_scale / sum.scale(), zero);
                evaluator_.multiply_plain(sum, zero, sum);
            }
            if (coefficients[0] != 0.0)
                evaluator_.add_const(sum, coefficients[0], sum, encoder_);
            evaluator_.rescale(sum, sum);
            return sum;
        }

        const int split = static_cast<int>(coefficients.size() / 2);
        std::vector<double> q(split, 0.0);
        std::vector<double> r(coefficients.begin(), coefficients.begin() + split);
        q[0] = coefficients[split];
        for (int j = 1; j < split; ++j)
        {
            q[j] = 2.0 * coefficients[split + j];
            r[split - j] -= coefficients[split + j];
        }
        int depth = 0;
        for (std::size_t size = coefficients.size(); size > 1; size >>= 1)
            ++depth;
        const int multiply_level = input_level_ - depth;
        const Ciphertext &t = basis(split);
        const double high_scale = output_scale * prime(multiply_level);
        const double child_scale = high_scale / t.scale();
        Ciphertext high = evaluate(q, child_scale);
        Ciphertext low = evaluate(r, child_scale);
        Ciphertext result;
        evaluator_.multiply_relin_dynamic(high, t, result, relin_keys_);
        evaluator_.multiply_const(low, 1.0, result.scale() / low.scale(), low, encoder_);
        evaluator_.add(result, low, result);
        evaluator_.rescale(result, result);
        return result;
    }

    EvaluatorCkksBase &evaluator_;
    CKKSEncoder &encoder_;
    const RelinKeys &relin_keys_;
    int input_level_;
    std::map<int, Ciphertext> basis_;
};

} // namespace

Ciphertext chebyshev_relu(const Ciphertext &input, EvaluatorCkksBase &evaluator,
                         CKKSEncoder &encoder, const RelinKeys &relin_keys,
                         double output_scale)
{
    if (!input.is_valid() || input.level() < kChebyshevReluLevels)
        throw std::invalid_argument("Chebyshev-471 ReLU requires at least 10 levels");
    if (!std::isfinite(output_scale) || output_scale <= 0.0)
        throw std::invalid_argument("Chebyshev ReLU output scale must be positive and finite");
    ChebyshevReluEvaluator evaluator_impl(input, evaluator, encoder, relin_keys);
    Ciphertext result = evaluator_impl.run(output_scale);
    if (input.level() - result.level() != kChebyshevReluLevels)
        throw std::runtime_error("Chebyshev-471 ReLU did not consume exactly 10 levels");
    return result;
}
