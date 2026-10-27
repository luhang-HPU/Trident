#pragma once

#include "poseidon/advance/homomorphic_dft.h"
#include "poseidon/advance/polynomial_evaluation.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace trident {

// Independent, frozen fixed-phase fit. sampled_error is not a certificate.
struct FrozenRelu {
    double phase = 0;
    double sampled_error = 0;
    double constant = 0;
    std::vector<double> cosine, sine;
    static FrozenRelu load(const std::filesystem::path& path);
    double evaluate(double input, double bound = 1) const;
};

struct FunctionalBootstrapPlan {
    unsigned transform_depth = 3;
    unsigned harmonic_degree = 15;
    unsigned carrier_degree = 31;
    unsigned doublings = 3;
    unsigned carrier_bound = 12;
    double bound = 1;
    double application_scale = 1099511627776.0; // 2^40
    unsigned output_level() const { return 2 + transform_depth; }
    unsigned nonlinear_depth() const;
    unsigned max_level() const { return output_level() + transform_depth + nonlinear_depth(); }
    std::vector<std::uint32_t> modulus_bits() const;
    void validate() const;
};

// Optional observer receives ciphertext only; production never decrypts here.
using FunctionalObserver = std::function<void(const std::string&, const poseidon::Ciphertext&)>;

class PreparedFunctionalBootstrap {
public:
    PreparedFunctionalBootstrap(const poseidon::PoseidonContext& context,
        poseidon::CKKSEncoder& encoder, const FunctionalBootstrapPlan& plan,
        FrozenRelu approximation, const std::filesystem::path& carrier_file);
    void evaluate(const poseidon::Ciphertext& input, poseidon::Ciphertext& output,
        poseidon::EvaluatorCkksBase& evaluator, const poseidon::RelinKeys& relin,
        const poseidon::GaloisKeys& rotations,
        const FunctionalObserver& observer = {}) const;
    const FunctionalBootstrapPlan& plan() const { return plan_; }
    const FrozenRelu& approximation() const { return approximation_; }
    std::vector<int> rotations() const;
private:
    const poseidon::PoseidonContext& context_;
    poseidon::CKKSEncoder& encoder_;
    FunctionalBootstrapPlan plan_;
    FrozenRelu approximation_;
    poseidon::LinearMatrixGroup stc_, cts_;
    poseidon::Polynomial carrier_, harmonic_;
};

} // namespace trident
