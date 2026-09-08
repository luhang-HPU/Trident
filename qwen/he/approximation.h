#pragma once

#include "core/tensor.h"
#include "he/encrypted_tensor.h"

#include "poseidon/advance/polynomial_evaluation.h"

#include <cstddef>
#include <map>
#include <vector>

namespace qwen::he
{

struct ApproximationConfig
{
    double minimum = 0.0;
    double maximum = 0.0;
    int sample_count = 0;

    void validate() const;
};

ApproximationConfig first_layer_inverse_sqrt_config();
ApproximationConfig silu_config();

poseidon::Polynomial
make_inverse_sqrt_polynomial(const ApproximationConfig &config);
poseidon::Polynomial make_silu_polynomial(const ApproximationConfig &config);
poseidon::Polynomial make_sigmoid_polynomial(
    const ApproximationConfig &config);
poseidon::Polynomial make_softplus_polynomial(
    const ApproximationConfig &config);
poseidon::Polynomial make_exp_polynomial(const ApproximationConfig &config);
poseidon::Polynomial
make_reciprocal_polynomial(const ApproximationConfig &config);

double evaluate_chebyshev_plain(double input,
                                const poseidon::Polynomial &polynomial);
Tensor approximate_silu_plain(const Tensor &input,
                              const ApproximationConfig &config);
Tensor approximate_sigmoid_plain(const Tensor &input,
                                 const ApproximationConfig &config);
Tensor approximate_softplus_plain(const Tensor &input,
                                  const ApproximationConfig &config);
Tensor approximate_silu_plain(
    const Tensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides);
Tensor approximate_silu_plain(
    const Tensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::vector<ApproximationConfig> &feature_configs,
    const std::map<std::size_t, std::vector<ApproximationConfig>>
        &position_feature_overrides);
Tensor approximate_exp_plain(const Tensor &input,
                             const ApproximationConfig &config);
Tensor approximate_reciprocal_plain(const Tensor &input,
                                    const ApproximationConfig &config);
Tensor approximate_rms_norm_plain(const Tensor &input, const Tensor &weight,
                                  double epsilon,
                                  const ApproximationConfig &config);
Tensor approximate_rms_norm_plain(
    const Tensor &input, const Tensor &weight, double epsilon,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides);

EncryptedTensor encrypted_silu(const EncryptedTensor &input,
                               const ApproximationConfig &config,
                               HeRuntime &runtime);
EncryptedTensor encrypted_sigmoid(const EncryptedTensor &input,
                                  const ApproximationConfig &config,
                                  HeRuntime &runtime);
EncryptedTensor encrypted_softplus(const EncryptedTensor &input,
                                   const ApproximationConfig &config,
                                   HeRuntime &runtime);
EncryptedTensor encrypted_silu(
    const EncryptedTensor &input,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides,
    HeRuntime &runtime);
EncryptedTensor encrypted_silu(
    const EncryptedTensor &input, const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig> &position_overrides,
    const std::vector<ApproximationConfig> &feature_configs,
    const std::map<std::size_t, std::vector<ApproximationConfig>>
        &position_feature_overrides,
    HeRuntime &runtime);
EncryptedTensor encrypted_exp(const EncryptedTensor &input,
                              const ApproximationConfig &config,
                              HeRuntime &runtime);
EncryptedTensor encrypted_reciprocal(const EncryptedTensor &input,
                                     const ApproximationConfig &config,
                                     HeRuntime &runtime);
EncryptedTensor encrypted_rms_norm(const EncryptedTensor &input,
                                   const Tensor &weight, double epsilon,
                                   const ApproximationConfig &config,
                                   HeRuntime &runtime);
EncryptedTensor encrypted_rms_norm(
    const EncryptedTensor &input, const Tensor &weight, double epsilon,
    const ApproximationConfig &config,
    const std::map<std::size_t, ApproximationConfig>
        &position_overrides,
    HeRuntime &runtime);

} // namespace qwen::he
