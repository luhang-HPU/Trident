#ifndef POSEIDON_RESNET20_H
#define POSEIDON_RESNET20_H

#include "poseidon/ckks_encoder.h"
#include "poseidon/decryptor.h"
#include "poseidon/encryptor.h"
#include "poseidon/evaluator/evaluator_ckks_base.h"
#include "poseidon/key/relinkeys.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ResNet20
{

enum class ActivationKind
{
    Square,
    AppReLU
};

struct ActivationOptions
{
    ActivationKind kind = ActivationKind::Square;
    double apprelu_bound = 6.0;
    size_t apprelu_rounds = 2;
};

struct RuntimeOptions
{
    uint32_t log_degree = 15;
    bool run_full_plain = true;
    bool run_stage1_block0 = false;
    bool run_stage1 = false;
    bool run_stage2_block0 = false;
    bool run_stage2 = false;
    bool run_stage3_block0 = false;
    bool run_stage3 = false;
    bool run_stage2_stage3_bridge = false;
    bool run_stage2_stage3_block0 = false;
    bool run_stage2_stage3 = false;
    bool run_full_he = false;
    bool run_stage3_tail = false;
    bool plain_only = false;
    bool profile = false;
    bool enable_bootstrap = false;
    bool bootstrap_after_stage1 = true;
    bool bootstrap_after_stage2_block0 = false;
    bool bootstrap_after_stage2_block1 = false;
    bool bootstrap_after_stage2 = true;
    bool bootstrap_after_stage3_block1 = true;
    uint32_t scale_bits = 32;
    size_t full_he_q_count = 42;
    size_t stage2_direct_rotation_keys = 0;
    ActivationOptions activation;
    std::string parameters_dir;
};

struct TensorShape
{
    size_t channels = 0;
    size_t height = 0;
    size_t width = 0;

    size_t size() const;
};

struct Tensor
{
    TensorShape shape;
    std::vector<double> values;

    Tensor() = default;
    explicit Tensor(TensorShape tensor_shape);
};

struct Conv2dWeights
{
    size_t out_channels = 0;
    size_t in_channels = 0;
    size_t kernel_h = 0;
    size_t kernel_w = 0;
    size_t stride = 1;
    size_t padding = 0;
    std::vector<double> weights;
    std::vector<double> bias;
};

struct ResidualBlockWeights
{
    Conv2dWeights conv1;
    Conv2dWeights conv2;
    Conv2dWeights shortcut;
    bool has_shortcut = false;
};

struct ResNet20Weights
{
    Conv2dWeights conv1;
    std::vector<ResidualBlockWeights> stage1;
    std::vector<ResidualBlockWeights> stage2;
    std::vector<ResidualBlockWeights> stage3;
    std::vector<double> fc_weight;
    std::vector<double> fc_bias;
    size_t fc_in = 64;
    size_t fc_out = 10;
};

RuntimeOptions make_default_options();
RuntimeOptions parse_options(int argc, char *argv[]);
int run_resnet20(const RuntimeOptions &options);

ResNet20Weights make_toy_weights();
Tensor make_toy_input();
Tensor forward_plain(const Tensor &input, const ResNet20Weights &weights);
Tensor forward_plain(const Tensor &input, const ResNet20Weights &weights,
                     const ActivationOptions &activation);

poseidon::Ciphertext encrypt_vector(const poseidon::CKKSEncoder &encoder,
                                    const poseidon::Encryptor &encryptor,
                                    const std::vector<double> &values, double scale,
                                    size_t slot_count);

std::vector<double> decrypt_vector(const poseidon::CKKSEncoder &encoder,
                                   poseidon::Decryptor &decryptor,
                                   const poseidon::Ciphertext &cipher);

void square_activation_inplace(
    poseidon::Ciphertext &cipher,
    const poseidon::EvaluatorCkksBase &evaluator,
    const poseidon::RelinKeys &relin_keys, double scale);

void activation_inplace(poseidon::Ciphertext &cipher,
                        const poseidon::EvaluatorCkksBase &evaluator,
                        const poseidon::RelinKeys &relin_keys,
                        const poseidon::CKKSEncoder &encoder,
                        double scale,
                        const ActivationOptions &activation);

} // namespace ResNet20

#endif
