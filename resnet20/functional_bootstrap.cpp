#include "functional_bootstrap.h"
#include "poseidon/advance/bootstrapper.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <set>
#include <stdexcept>
#include <utility>

namespace trident {
using namespace poseidon;
namespace {
unsigned polynomial_depth(unsigned degree) {
    unsigned depth = 0;
    for (; degree; degree >>= 1) ++depth;
    return depth;
}
void require(bool ok, const char* message) {
    if (!ok) throw std::invalid_argument(message);
}
void check_level(const Ciphertext& value, unsigned level, double scale, const char* stage) {
    if (value.level() != level || !std::isfinite(value.scale()) ||
        std::abs(value.scale() / scale - 1) > 1e-4)
        throw std::runtime_error(std::string(stage) + ": unexpected level/scale: level=" +
            std::to_string(value.level()) + " log_scale=" + std::to_string(std::log2(value.scale())));
}
void run_polynomial(const Polynomial& polynomial, const Ciphertext& input, Ciphertext& output,
    double target_scale, EvaluatorCkksBase& evaluator, const RelinKeys& relin,
    CKKSEncoder& encoder) {
    evaluator.evaluate_frozen_polynomial(polynomial, input, output, target_scale, relin, encoder);
}
}

FrozenRelu FrozenRelu::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    std::string magic;
    unsigned degree = 0;
    FrozenRelu fit;
    require(bool(file >> magic) && magic == "RELU_TRIG_V1", "invalid ReLU coefficient header");
    require(bool(file >> fit.phase >> degree >> fit.sampled_error >> fit.constant),
        "incomplete ReLU coefficient header");
    require((degree == 15 || degree == 31) && fit.phase > 0 && fit.phase < 0.5 &&
        std::isfinite(fit.constant) && std::isfinite(fit.sampled_error) && fit.sampled_error > 0,
        "invalid ReLU fit parameters");
    fit.cosine.resize(degree);
    fit.sine.resize(degree);
    for (unsigned k = 0; k < degree; ++k)
        require(bool(file >> fit.cosine[k] >> fit.sine[k]) &&
            std::isfinite(fit.cosine[k]) && std::isfinite(fit.sine[k]), "invalid ReLU coefficient");
    std::string extra;
    require(!(file >> extra), "unexpected trailing ReLU coefficients");
    return fit;
}

double FrozenRelu::evaluate(double input, double bound) const {
    require(std::isfinite(input) && std::isfinite(bound) && bound > 0, "invalid ReLU input/bound");
    const double angle = 2 * std::acos(-1.0) * phase * input / bound;
    double value = constant;
    for (std::size_t k = 0; k < cosine.size(); ++k)
        value += cosine[k] * std::cos((k + 1) * angle) + sine[k] * std::sin((k + 1) * angle);
    return bound * value;
}

unsigned FunctionalBootstrapPlan::nonlinear_depth() const {
    return polynomial_depth(carrier_degree) + doublings + polynomial_depth(harmonic_degree);
}
void FunctionalBootstrapPlan::validate() const {
    require(transform_depth >= 2 && transform_depth <= 3, "supported DFT depths are 2 and 3");
    require(harmonic_degree == 15 || harmonic_degree == 31, "unsupported harmonic degree");
    require(carrier_degree == 31 && doublings == 3 && carrier_bound == 12,
        "carrier requires degree31, K12 and three squarings");
    require(std::isfinite(bound) && bound > 0 && application_scale == std::exp2(40),
        "invalid bound or unsupported application scale");
}
std::vector<std::uint32_t> FunctionalBootstrapPlan::modulus_bits() const {
    validate();
    std::vector<std::uint32_t> bits(1, 45);
    bits.insert(bits.end(), output_level(), 40);
    bits.insert(bits.end(), transform_depth + nonlinear_depth(), 45);
    return bits;
}

PreparedFunctionalBootstrap::PreparedFunctionalBootstrap(const PoseidonContext& context,
    CKKSEncoder& encoder, const FunctionalBootstrapPlan& plan, FrozenRelu approximation,
    const std::filesystem::path& carrier_file)
    : context_(context), encoder_(encoder), plan_(plan), approximation_(std::move(approximation)) {
    plan_.validate();
    const auto& params = *context_.parameters_literal();
    require(params.q0_level() == 0 && params.log_slots() == params.log_n() - 1,
        "functional bootstrap requires full slots and a single q0");
    require(params.q().size() == plan_.max_level() + 1 &&
        approximation_.cosine.size() == plan_.harmonic_degree &&
        approximation_.sine.size() == plan_.harmonic_degree, "plan/context/fit mismatch");
    require(params.hamming_weight() == 32, "K12 profile requires secret H=32");
    const auto expected_bits = plan_.modulus_bits();
    for (std::size_t i = 0; i < expected_bits.size(); ++i)
        require(params.q()[i].bit_count() == expected_bits[i], "plan/context Q bit-width mismatch");
    require(std::isfinite(approximation_.phase) && approximation_.phase > 0 &&
        approximation_.phase < 0.5 && std::isfinite(approximation_.constant), "invalid frozen fit");
    for (std::size_t k = 0; k < approximation_.cosine.size(); ++k)
        require(std::isfinite(approximation_.cosine[k]) && std::isfinite(approximation_.sine[k]),
            "nonfinite frozen fit coefficient");
    const double q0 = static_cast<double>(params.q().front().value());

    // decode=StC makes the original real slots into the first coefficient half.
    // Only the FINAL existing StC matrix receives the gain. At scale Delta the
    // raw message coefficients then equal q0 * phase * z/b. After lifting,
    // interpreting at q0 gives I + phase*z/b. This is a deliberate change of unit.
    HomomorphicDFTMatrixLiteral stc_literal(decode, params.log_n(), params.log_slots(),
        plan_.transform_depth, std::vector<uint32_t>(plan_.transform_depth, 1), true, 1.0, false, 1);
    auto matrices = stc_literal.gen_matrices();
    const double gain = q0 / plan_.application_scale * approximation_.phase / plan_.bound;
    for (auto& [rotation, diagonal] : matrices.back())
        for (auto& entry : diagonal) entry *= gain;
    stc_.data().resize(matrices.size());
    stc_.set_step(1);
    for (unsigned j = 0; j < matrices.size(); ++j) {
        const auto level = plan_.transform_depth - j;
        gen_linear_transform_bsgs(stc_.data()[j], stc_.rot_index(), encoder_, matrices[j],
            level, static_cast<double>(params.q()[level].value()), 1, params.log_slots());
    }
    // CtS has its 1/2 extraction factor; conjugate-add below recovers the real
    // coefficient half without mixing in the independent imaginary-half offsets.
    HomomorphicDFTMatrixLiteral cts_literal(encode, params.log_n(), params.log_slots(),
        plan_.max_level(), std::vector<uint32_t>(plan_.transform_depth, 1), true,
        1.0 / plan_.carrier_bound, false, 1);
    cts_literal.create(cts_, encoder_, 1);

    std::ifstream file(carrier_file);
    std::string magic;
    unsigned K = 0, doubles = 0, degree = 0;
    require(bool(file >> magic >> K >> doubles >> degree) && magic == "COMPLEX_CARRIER_V1" &&
        K == plan_.carrier_bound && doubles == plan_.doublings && degree == plan_.carrier_degree,
        "invalid carrier file or plan mismatch");
    carrier_.data().resize(degree + 1);
    for (auto& c : carrier_.data()) {
        double re, im;
        require(bool(file >> re >> im) && std::isfinite(re) && std::isfinite(im), "invalid carrier coefficient");
        c = {re, im};
    }
    std::string extra;
    require(!(file >> extra), "unexpected trailing carrier coefficients");
    carrier_.basis_type() = Chebyshev;
    carrier_.max_degree() = degree;
    carrier_.lead() = true;
    carrier_.is_even() = carrier_.is_odd() = true;
    harmonic_.basis_type() = Monomial;
    harmonic_.max_degree() = plan_.harmonic_degree;
    harmonic_.lead() = true;
    harmonic_.is_even() = harmonic_.is_odd() = true;
    harmonic_.data().resize(plan_.harmonic_degree + 1);
    harmonic_[0] = approximation_.constant * plan_.bound / 2;
    for (unsigned k = 1; k <= plan_.harmonic_degree; ++k)
        harmonic_[k] = std::complex<double>(approximation_.cosine[k-1], -approximation_.sine[k-1]) *
            (plan_.bound / 2);
}

std::vector<int> PreparedFunctionalBootstrap::rotations() const {
    std::set<int> steps{0}; // conjugation
    steps.insert(stc_.rot_index().begin(), stc_.rot_index().end());
    steps.insert(cts_.rot_index().begin(), cts_.rot_index().end());
    return {steps.begin(), steps.end()};
}

void PreparedFunctionalBootstrap::evaluate(const Ciphertext& input, Ciphertext& output,
    EvaluatorCkksBase& evaluator, const RelinKeys& relin, const GaloisKeys& rotations,
    const FunctionalObserver& observer) const {
    require(input.size() == 2 && input.is_ntt_form() && input.level() >= plan_.transform_depth,
        "invalid functional bootstrap input");
    const auto input_context = context_.crt_context()->get_context_data(input.parms_id());
    require(bool(input_context), "input belongs to a different context");
    auto observe = [&](const char* stage, const Ciphertext& ct) { if (observer) observer(stage, ct); };
    Ciphertext value = input;
    evaluator.drop_modulus(value, value, plan_.transform_depth);
    check_level(value, plan_.transform_depth, plan_.application_scale, "input");
    evaluator.dft(value, stc_, value, rotations);
    check_level(value, 0, plan_.application_scale, "StC");
    observe("stc", value);
    const double q0 = static_cast<double>(context_.parameters_literal()->q().front().value());
    Bootstrapper raiser(context_, evaluator, encoder_, context_.parameters_literal()->log_slots(),
        plan_.carrier_bound, plan_.application_scale, plan_.application_scale);
    Ciphertext raised;
    raiser.mod_raise(value, raised);
    raised.scale() = q0; // raw coefficients/q0 = I + phase*z/b
    observe("modraise", raised);
    evaluator.dft(raised, cts_, value, rotations);
    Ciphertext conjugated;
    evaluator.conjugate(value, rotations, conjugated);
    evaluator.add(value, conjugated, value);
    const auto cts_level = plan_.max_level() - plan_.transform_depth;
    check_level(value, cts_level, q0, "CtS");
    observe("cts", value);
    run_polynomial(carrier_, value, value, q0, evaluator, relin, encoder_);
    check_level(value, cts_level - polynomial_depth(plan_.carrier_degree), q0, "carrier");
    observe("carrier", value);
    for (unsigned j = 0; j < plan_.doublings; ++j) {
        evaluator.multiply_relin_dynamic(value, value, value, relin);
        evaluator.rescale_dynamic(value, value, q0);
    }
    observe("periodic", value);
    run_polynomial(harmonic_, value, value, plan_.application_scale, evaluator, relin, encoder_);
    evaluator.conjugate(value, rotations, conjugated);
    evaluator.add(value, conjugated, value);
    check_level(value, plan_.output_level(), plan_.application_scale, "output");
    observe("output", value);
    output = std::move(value);
}
} // namespace trident
