#include "resnet20.h"

#include "resnet20_ops.h"
#include "resnet20_params.h"
#include "resnet20_plain.h"
#include "poseidon/factory/poseidon_factory.h"
#include "poseidon/keygenerator.h"

#include <algorithm>
#include <cstdlib>
#include <chrono>
#include <cmath>
#include <complex>
#include <iostream>
#include <set>
#include <stdexcept>
#include <utility>
#ifdef _OPENMP
#include <omp.h>
#endif

namespace ResNet20
{

namespace
{

using Clock = std::chrono::steady_clock;

double elapsed_seconds(Clock::time_point start, Clock::time_point end)
{
    return std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
}

void print_profile_step(bool enabled, const std::string &label,
                        Clock::time_point &last, Clock::time_point total_start)
{
    if (!enabled)
    {
        return;
    }

    const auto now = Clock::now();
    std::cout << "[profile] " << label
              << ": step=" << elapsed_seconds(last, now)
              << "s total=" << elapsed_seconds(total_start, now) << "s" << std::endl;
    last = now;
}

void print_usage(const char *program)
{
    std::cout << "Usage: " << program
              << " [--log-degree 15|16] [--parameters path] [--no-full-plain]"
              << " [--run-block0] [--run-stage1] [--run-stage2-block0] [--run-stage2]"
              << " [--run-stage3-block0] [--run-stage3]"
              << " [--run-stage2-stage3-bridge] [--run-stage2-stage3-block0]"
              << " [--run-stage2-stage3]"
              << " [--run-full-he] [--run-stage3-tail] [--plain-only]"
              << " [--profile]"
              << " [--activation square|apprelu] [--apprelu-bound value]"
              << " [--apprelu-rounds count]"
              << " [--scale-bits bits]"
              << " [--full-he-q-count count]"
              << " [--stage2-direct-keys count]"
              << std::endl;
}

std::vector<int> merge_rotation_steps(const std::vector<std::vector<int>> &groups)
{
    std::set<int> merged;
    for (const auto &group : groups)
    {
        merged.insert(group.begin(), group.end());
    }
    return {merged.begin(), merged.end()};
}

int naf_weight(int step)
{
    int n = std::abs(step);
    int weight = 0;
    while (n > 0)
    {
        if (n & 1)
        {
            const int u = 2 - (n & 3);
            n -= u;
            ++weight;
        }
        n >>= 1;
    }
    return weight;
}

std::vector<int> make_hybrid_rotation_key_steps(const std::vector<int> &rotation_steps,
                                                uint32_t log_slots,
                                                size_t direct_rotation_key_count)
{
    // 稀疏卷积会产生很多逻辑旋转。如果给每个旋转都生成 key，时间和内存都很重。
    // 这里默认保留 +/- 2 的幂次旋转，并可选加入少量代价高的直接旋转。
    // 没有直接 key 的旋转仍然可以由 key-switch 层组合出来。
    std::set<int> selected;
    const int max_power = 1 << (log_slots - 1);
    for (int step = 1; step <= max_power; step <<= 1)
    {
        selected.insert(step);
        selected.insert(-step);
    }

    std::vector<std::pair<int, int>> scored;
    scored.reserve(rotation_steps.size());
    for (int step : rotation_steps)
    {
        if (step != 0)
        {
            scored.push_back({naf_weight(step), step});
        }
    }
    std::sort(scored.begin(), scored.end(),
              [](const auto &lhs, const auto &rhs)
              {
                  if (lhs.first != rhs.first)
                  {
                      return lhs.first > rhs.first;
                  }
                  return std::abs(lhs.second) > std::abs(rhs.second);
              });

    const size_t direct_count = std::min(direct_rotation_key_count, scored.size());
    for (size_t i = 0; i < direct_count; ++i)
    {
        selected.insert(scored[i].second);
    }
    return {selected.begin(), selected.end()};
}

double max_abs_error(const std::vector<double> &actual, const std::vector<double> &expected)
{
    if (actual.size() < expected.size())
    {
        throw std::invalid_argument("max_abs_error: actual vector is shorter than expected");
    }

    double result = 0.0;
    for (size_t i = 0; i < expected.size(); ++i)
    {
        result = std::max(result, std::abs(actual[i] - expected[i]));
    }
    return result;
}

void add_residual_block_rotation_steps(std::vector<std::vector<int>> &groups,
                                       const TensorShape &input_shape,
                                       const ResidualBlockWeights &block)
{
    groups.push_back(conv2d_rotation_steps(input_shape, block.conv1));
    const TensorShape middle_shape = conv2d_output_shape(input_shape, block.conv1);
    groups.push_back(conv2d_rotation_steps(middle_shape, block.conv2));
    if (block.has_shortcut)
    {
        groups.push_back(conv2d_rotation_steps(input_shape, block.shortcut));
    }
}

Tensor forward_stage_plain(Tensor input, const std::vector<ResidualBlockWeights> &stage)
{
    for (const auto &block : stage)
    {
        input = residual_block_plain(input, block);
    }
    return input;
}

Tensor embed_sparse_plain(const Tensor &compact, size_t physical_height, size_t physical_width,
                          size_t spacing)
{
    // 稀疏 HE 布局的明文参考实现：逻辑值按 `spacing` 间隔放在高/宽方向上，
    // 中间空出来的位置用于表达下采样后的稀疏物理布局。
    Tensor sparse({compact.shape.channels, physical_height, physical_width});
    for (size_t c = 0; c < compact.shape.channels; ++c)
    {
        for (size_t h = 0; h < compact.shape.height; ++h)
        {
            for (size_t w = 0; w < compact.shape.width; ++w)
            {
                const size_t compact_index =
                    c * compact.shape.height * compact.shape.width + h * compact.shape.width + w;
                const size_t sparse_index =
                    c * physical_height * physical_width + h * spacing * physical_width +
                    w * spacing;
                sparse.values[sparse_index] = compact.values[compact_index];
            }
        }
    }
    return sparse;
}

Tensor compact_sparse_plain(const Tensor &sparse, size_t spacing)
{
    // embed_sparse_plain 的逆操作，用来对照密文 sparse_to_compact bridge 的结果。
    if (spacing == 0 || sparse.shape.height % spacing != 0 ||
        sparse.shape.width % spacing != 0)
    {
        throw std::invalid_argument("compact_sparse_plain: invalid sparse spacing");
    }

    Tensor compact({sparse.shape.channels, sparse.shape.height / spacing,
                    sparse.shape.width / spacing});
    for (size_t c = 0; c < compact.shape.channels; ++c)
    {
        for (size_t h = 0; h < compact.shape.height; ++h)
        {
            for (size_t w = 0; w < compact.shape.width; ++w)
            {
                const size_t sparse_index =
                    c * sparse.shape.height * sparse.shape.width +
                    h * spacing * sparse.shape.width + w * spacing;
                const size_t compact_index =
                    c * compact.shape.height * compact.shape.width + h * compact.shape.width + w;
                compact.values[compact_index] = sparse.values[sparse_index];
            }
        }
    }
    return compact;
}

Tensor make_operator_test_tensor(const TensorShape &shape)
{
    Tensor tensor(shape);
    for (size_t i = 0; i < tensor.values.size(); ++i)
    {
        const int centered = static_cast<int>((i * 17 + 5) % 29) - 14;
        tensor.values[i] = static_cast<double>(centered) / 10.0;
    }
    return tensor;
}

} // namespace

RuntimeOptions make_default_options()
{
    return RuntimeOptions{};
}

RuntimeOptions parse_options(int argc, char *argv[])
{
    RuntimeOptions options = make_default_options();
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--log-degree" && i + 1 < argc)
        {
            options.log_degree = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--parameters" && i + 1 < argc)
        {
            options.parameters_dir = argv[++i];
        }
        else if (arg == "--no-full-plain")
        {
            options.run_full_plain = false;
        }
        else if (arg == "--run-block0")
        {
            options.run_stage1_block0 = true;
        }
        else if (arg == "--run-stage1")
        {
            options.run_stage1 = true;
        }
        else if (arg == "--run-stage2-block0")
        {
            options.run_stage2_block0 = true;
        }
        else if (arg == "--run-stage2")
        {
            options.run_stage2 = true;
        }
        else if (arg == "--run-stage3-block0")
        {
            options.run_stage3_block0 = true;
        }
        else if (arg == "--run-stage3")
        {
            options.run_stage3 = true;
        }
        else if (arg == "--run-stage2-stage3-bridge")
        {
            options.run_stage2_stage3_bridge = true;
        }
        else if (arg == "--run-stage2-stage3-block0")
        {
            options.run_stage2_stage3_block0 = true;
        }
        else if (arg == "--run-stage2-stage3")
        {
            options.run_stage2_stage3 = true;
        }
        else if (arg == "--run-full-he")
        {
            options.run_full_he = true;
        }
        else if (arg == "--run-stage3-tail")
        {
            options.run_stage3_tail = true;
        }
        else if (arg == "--plain-only")
        {
            options.plain_only = true;
        }
        else if (arg == "--profile")
        {
            options.profile = true;
        }
        else if (arg == "--activation" && i + 1 < argc)
        {
            const std::string value = argv[++i];
            if (value == "square")
            {
                options.activation.kind = ActivationKind::Square;
            }
            else if (value == "apprelu")
            {
                options.activation.kind = ActivationKind::AppReLU;
            }
            else
            {
                throw std::invalid_argument("unknown activation: " + value);
            }
        }
        else if (arg == "--apprelu-bound" && i + 1 < argc)
        {
            options.activation.apprelu_bound = std::stod(argv[++i]);
        }
        else if (arg == "--apprelu-rounds" && i + 1 < argc)
        {
            options.activation.apprelu_rounds = static_cast<size_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--scale-bits" && i + 1 < argc)
        {
            options.scale_bits = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--full-he-q-count" && i + 1 < argc)
        {
            options.full_he_q_count = static_cast<size_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--stage2-direct-keys" && i + 1 < argc)
        {
            options.stage2_direct_rotation_keys = static_cast<size_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--help" || arg == "-h")
        {
            print_usage(argv[0]);
            std::exit(0);
        }
        else
        {
            throw std::invalid_argument("unknown ResNet-20 option: " + arg);
        }
    }
    return options;
}

poseidon::Ciphertext encrypt_vector(const poseidon::CKKSEncoder &encoder,
                                    const poseidon::Encryptor &encryptor,
                                    const std::vector<double> &values, double scale,
                                    size_t slot_count)
{
    if (values.size() > slot_count)
    {
        throw std::invalid_argument("encrypt_vector: input does not fit in CKKS slots");
    }

    std::vector<std::complex<double>> message(slot_count, {0.0, 0.0});
    for (size_t i = 0; i < values.size(); ++i)
    {
        message[i] = {values[i], 0.0};
    }

    poseidon::Plaintext plain;
    poseidon::Ciphertext cipher;
    encoder.encode(message, scale, plain);
    encryptor.encrypt(plain, cipher);
    return cipher;
}

std::vector<double> decrypt_vector(const poseidon::CKKSEncoder &encoder,
                                   poseidon::Decryptor &decryptor,
                                   const poseidon::Ciphertext &cipher)
{
    poseidon::Plaintext plain;
    decryptor.decrypt(cipher, plain);

    std::vector<std::complex<double>> decoded;
    encoder.decode(plain, decoded);

    std::vector<double> result(decoded.size());
    std::transform(decoded.begin(), decoded.end(), result.begin(),
                   [](const std::complex<double> &value) { return value.real(); });
    return result;
}

int run_resnet20(const RuntimeOptions &options)
{
    if (options.plain_only)
    {
        // 激活函数/权重实验的快速路径：跳过 CKKS context、旋转 key 生成和全部密文算子。
        const auto weights = load_or_make_weights(options.parameters_dir);
        const auto input = make_toy_input();
        const Tensor logits = forward_plain(input, weights, options.activation);
        std::cout << "Plain HE-friendly ResNet-20 logits:";
        for (size_t i = 0; i < logits.values.size(); ++i)
        {
            std::cout << (i == 0 ? " " : ", ") << logits.values[i];
        }
        std::cout << std::endl;
        return 0;
    }

    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);

    const bool run_connected_stage2_stage3 =
        !options.run_full_he && (options.run_stage2_stage3 || options.run_stage2_stage3_block0);
    const bool run_sparse_stage2 =
        !options.run_full_he && !run_connected_stage2_stage3 &&
        (options.run_stage2 || options.run_stage2_block0);
    const bool run_sparse_stage3 =
        !options.run_full_he && !run_connected_stage2_stage3 &&
        (options.run_stage3 || options.run_stage3_block0);
    const bool needs_stage2_sparse_slots =
        options.run_full_he || run_sparse_stage2 || run_connected_stage2_stage3 ||
        options.run_stage2_stage3_bridge;
    // stage2 稀疏布局需要 32 channels x 32 x 32 个物理槽位，也就是 32768 个 CKKS slots。
    // 如果用户给的 log-degree 太小，这里自动升到能容纳该布局的参数。
    const uint32_t log_degree =
        needs_stage2_sparse_slots && options.log_degree < 16
            ? 16
            : options.log_degree;
    if (log_degree != options.log_degree)
    {
        std::cout << "Stage2 sparse layout needs 32768 slots; using log-degree " << log_degree
                  << std::endl;
    }

    poseidon::ParametersLiteral ckks_param_literal{CKKS, log_degree,
                                                  log_degree - 1, options.scale_bits, 5,
                                                  1, 0, {}, {}};
    const bool uses_apprelu = options.activation.kind == ActivationKind::AppReLU;
    // q_count 是 modulus chain 的长度。AppReLU 和完整 ResNet 会比 square smoke test
    // 消耗更多层级，因为每次激活都包含额外乘法。
    const size_t q_count =
        options.run_full_he ? options.full_he_q_count :
        options.run_stage2_stage3 ? 28 :
        options.run_stage2_stage3_block0 ? 22 :
        uses_apprelu ? 24 :
        (options.run_stage1 || options.run_stage2 || options.run_stage3) ? 18 : 10;
    std::vector<uint32_t> log_q(q_count, options.scale_bits);
    std::vector<uint32_t> log_p(1, 60);
    ckks_param_literal.set_log_modulus(log_q, log_p);

    auto context =
        poseidon::PoseidonFactory::get_instance()->create_poseidon_context(ckks_param_literal);
    const double scale = std::pow(2.0, options.scale_bits);
    const size_t slot_count = context.parameters_literal()->degree() >> 1;

    poseidon::PublicKey public_key;
    poseidon::RelinKeys relin_keys;
    poseidon::GaloisKeys galois_keys;
    poseidon::KeyGenerator keygen(context);
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);

    poseidon::CKKSEncoder encoder(context);
    poseidon::Encryptor encryptor(context, public_key, keygen.secret_key());
    poseidon::Decryptor decryptor(context, keygen.secret_key());
    auto evaluator = poseidon::PoseidonFactory::get_instance()->create_ckks_evaluator(context);

    const auto weights = load_or_make_weights(options.parameters_dir);
    const auto input = make_toy_input();
    if (input.values.size() > slot_count)
    {
        throw std::invalid_argument("ResNet-20 input does not fit in one ciphertext");
    }
    const Tensor conv1_plain = conv2d_plain(input, weights.conv1);
    if (conv1_plain.values.size() > slot_count)
    {
        throw std::invalid_argument("ResNet-20 conv1 output does not fit in one ciphertext");
    }
    const Tensor conv1_activation_plain = activate_plain(conv1_plain, options.activation);
    const Tensor stage2_operator_input =
        (run_sparse_stage2 || run_connected_stage2_stage3)
            ? make_operator_test_tensor({16, 32, 32})
            : Tensor{};
    const Tensor stage3_operator_input =
        run_sparse_stage3 ? make_operator_test_tensor({32, 16, 16}) : Tensor{};
    const Tensor bridge_operator_input =
        options.run_stage2_stage3_bridge ? make_operator_test_tensor({32, 16, 16}) : Tensor{};
    const Tensor stage3_tail_input =
        options.run_stage3_tail ? make_operator_test_tensor({64, 8, 8}) : Tensor{};

    std::vector<std::vector<int>> rotation_step_groups;
    if (options.run_full_he)
    {
        // 完整密文路径：
        // compact conv1/stage1 -> sparse stage2 -> sparse-to-compact bridge ->
        // sparse stage3 -> sparse GAP -> FC。
        if (weights.stage1.empty() || weights.stage2.empty() || weights.stage3.empty())
        {
            throw std::invalid_argument("ResNet-20 full HE requires all residual stages");
        }

        rotation_step_groups.push_back(conv2d_rotation_steps(input.shape, weights.conv1));
        TensorShape stage1_input_shape = conv1_activation_plain.shape;
        for (const auto &block : weights.stage1)
        {
            add_residual_block_rotation_steps(rotation_step_groups, stage1_input_shape, block);
            stage1_input_shape =
                conv2d_output_shape(conv2d_output_shape(stage1_input_shape, block.conv1),
                                    block.conv2);
        }

        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            stage1_input_shape, weights.stage2.front(), stage1_input_shape.height,
            stage1_input_shape.width, 2));
        TensorShape sparse_stage2_shape{weights.stage2.front().conv2.out_channels,
                                        stage1_input_shape.height, stage1_input_shape.width};
        for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
        {
            rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                sparse_stage2_shape, weights.stage2[block_index], 2));
        }

        rotation_step_groups.push_back(sparse_to_compact_rotation_steps(sparse_stage2_shape, 2));
        // stage2 输出逻辑上的 32x16x16，但实际存储在物理 32x32x32 稀疏布局中。
        // stage3 需要 compact 的 32x16x16 输入，因此这里需要 bridge 把稀疏结果压紧。
        TensorShape compact_stage2_shape{weights.stage2.front().conv2.out_channels,
                                         stage1_input_shape.height / 2,
                                         stage1_input_shape.width / 2};
        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            compact_stage2_shape, weights.stage3.front(), compact_stage2_shape.height,
            compact_stage2_shape.width, 2));
        TensorShape sparse_stage3_shape{weights.stage3.front().conv2.out_channels,
                                        compact_stage2_shape.height,
                                        compact_stage2_shape.width};
        for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
        {
            rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                sparse_stage3_shape, weights.stage3[block_index], 2));
        }
        rotation_step_groups.push_back(
            sparse_global_average_pool_rotation_steps(sparse_stage3_shape, 2));
        rotation_step_groups.push_back(linear_rotation_steps(weights.fc_in, weights.fc_out));
    }
    else if (run_connected_stage2_stage3)
    {
        // bridge 开发时使用的诊断路径：从合成的 stage2 输入开始，
        // 只验证 stage2 -> bridge -> stage3，不跑 conv1/stage1。
        if (weights.stage2.empty() || weights.stage3.empty())
        {
            throw std::invalid_argument("ResNet-20 connected stage requires stage2 and stage3");
        }

        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            stage2_operator_input.shape, weights.stage2.front(),
            stage2_operator_input.shape.height, stage2_operator_input.shape.width, 2));

        TensorShape sparse_stage2_shape{weights.stage2.front().conv2.out_channels,
                                        stage2_operator_input.shape.height,
                                        stage2_operator_input.shape.width};
        for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
        {
            rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                sparse_stage2_shape, weights.stage2[block_index], 2));
        }

        rotation_step_groups.push_back(sparse_to_compact_rotation_steps(sparse_stage2_shape, 2));
        TensorShape compact_stage2_shape{weights.stage2.front().conv2.out_channels,
                                         stage2_operator_input.shape.height / 2,
                                         stage2_operator_input.shape.width / 2};
        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            compact_stage2_shape, weights.stage3.front(), compact_stage2_shape.height,
            compact_stage2_shape.width, 2));
        if (options.run_stage2_stage3)
        {
            TensorShape sparse_stage3_shape{weights.stage3.front().conv2.out_channels,
                                            compact_stage2_shape.height,
                                            compact_stage2_shape.width};
            for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
            {
                rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                    sparse_stage3_shape, weights.stage3[block_index], 2));
            }
        }
    }
    else if (options.run_stage2_stage3_bridge)
    {
        // 单独测试 bridge：先把 compact 数据嵌入稀疏物理槽位，
        // 再运行密文 bridge，并和 compact_sparse_plain 对比。
        const Tensor bridge_sparse_input =
            embed_sparse_plain(bridge_operator_input, 32, 32, 2);
        rotation_step_groups.push_back(
            sparse_to_compact_rotation_steps(bridge_sparse_input.shape, 2));
    }
    else if (options.run_stage3_tail)
    {
        const Tensor stage3_tail_sparse_input = embed_sparse_plain(stage3_tail_input, 16, 16, 2);
        rotation_step_groups.push_back(sparse_global_average_pool_rotation_steps(
            stage3_tail_sparse_input.shape, 2));
        rotation_step_groups.push_back(linear_rotation_steps(weights.fc_in, weights.fc_out));
    }
    else if (run_sparse_stage2)
    {
        if (weights.stage2.empty())
        {
            throw std::invalid_argument("ResNet-20 stage2 has no residual blocks");
        }

        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            stage2_operator_input.shape, weights.stage2.front(),
            stage2_operator_input.shape.height, stage2_operator_input.shape.width, 2));
        if (options.run_stage2)
        {
            TensorShape sparse_stage2_shape{weights.stage2.front().conv2.out_channels,
                                            stage2_operator_input.shape.height,
                                            stage2_operator_input.shape.width};
            for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
            {
                rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                    sparse_stage2_shape, weights.stage2[block_index], 2));
            }
        }
    }
    else if (run_sparse_stage3)
    {
        if (weights.stage3.empty())
        {
            throw std::invalid_argument("ResNet-20 stage3 has no residual blocks");
        }

        rotation_step_groups.push_back(sparse_downsample_block_rotation_steps(
            stage3_operator_input.shape, weights.stage3.front(),
            stage3_operator_input.shape.height, stage3_operator_input.shape.width, 2));
        if (options.run_stage3)
        {
            TensorShape sparse_stage3_shape{weights.stage3.front().conv2.out_channels,
                                            stage3_operator_input.shape.height,
                                            stage3_operator_input.shape.width};
            for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
            {
                rotation_step_groups.push_back(sparse_residual_block_rotation_steps(
                    sparse_stage3_shape, weights.stage3[block_index], 2));
            }
        }
    }
    else
    {
        rotation_step_groups.push_back(conv2d_rotation_steps(input.shape, weights.conv1));
    }

    if (!run_sparse_stage2 && !run_sparse_stage3 &&
        (options.run_stage1_block0 || options.run_stage1))
    {
        if (weights.stage1.empty())
        {
            throw std::invalid_argument("ResNet-20 stage1 has no residual blocks");
        }
        for (const auto &block : weights.stage1)
        {
            add_residual_block_rotation_steps(rotation_step_groups, conv1_activation_plain.shape,
                                              block);
        }
    }

    const auto rotation_steps = merge_rotation_steps(rotation_step_groups);
    std::cout << "Rotation steps: " << rotation_steps.size() << std::endl;
#ifdef _OPENMP
    const int previous_max_threads = omp_get_max_threads();
    omp_set_num_threads(1);
#endif
    // 观察到 OpenMP 多线程生成 key 时容易给 Poseidon memory pool 带来压力。
    // 这里生成旋转 key 时临时切成单线程，优先保证稳定性。
    const auto keygen_start = Clock::now();
    if (options.run_full_he || run_sparse_stage2 || run_sparse_stage3 ||
        run_connected_stage2_stage3 || options.run_stage2_stage3_bridge ||
        options.run_stage3_tail)
    {
        const auto hybrid_steps =
            make_hybrid_rotation_key_steps(rotation_steps, log_degree - 1,
                                           options.stage2_direct_rotation_keys);
        std::cout << "Generating hybrid rotation keys: " << hybrid_steps.size()
                  << " keys for sparse stage";
        if (options.stage2_direct_rotation_keys > 0)
        {
            std::cout << " (" << options.stage2_direct_rotation_keys << " direct requested)";
        }
        std::cout << std::endl;
        keygen.create_galois_keys(hybrid_steps, galois_keys);
    }
    else
    {
        keygen.create_galois_keys(rotation_steps, galois_keys);
    }
#ifdef _OPENMP
    omp_set_num_threads(previous_max_threads);
#endif
    const auto keygen_end = Clock::now();
    std::cout << "Rotation keys generated in " << elapsed_seconds(keygen_start, keygen_end)
              << " seconds" << std::endl;

    if (options.run_full_plain)
    {
        const Tensor logits = forward_plain(input, weights, options.activation);
        std::cout << "Plain HE-friendly ResNet-20 logits:";
        for (size_t i = 0; i < logits.values.size(); ++i)
        {
            std::cout << (i == 0 ? " " : ", ") << logits.values[i];
        }
        std::cout << std::endl;
    }

    if (options.run_full_he)
    {
        // `plain` 张量同步跑同一条明文网络，便于完整密文推理结束后报告 logits 误差。
        const auto compute_start = Clock::now();
        auto profile_last = compute_start;
        poseidon::Ciphertext cipher =
            encrypt_vector(encoder, encryptor, input.values, scale, slot_count);
        print_profile_step(options.profile, "encrypt input", profile_last, compute_start);

        cipher = conv2d_encrypted(cipher, input.shape, weights.conv1, encoder, *evaluator,
                                  galois_keys, scale, slot_count);
        print_profile_step(options.profile, "conv1 convolution", profile_last, compute_start);
        activation_inplace(cipher, *evaluator, relin_keys, encoder, scale, options.activation);
        print_profile_step(options.profile, "conv1 activation", profile_last, compute_start);
        Tensor plain = conv1_activation_plain;
        std::cout << "Encrypted full HE conv1 complete" << std::endl;

        for (size_t block_index = 0; block_index < weights.stage1.size(); ++block_index)
        {
            cipher = residual_block_encrypted(cipher, plain.shape, weights.stage1[block_index],
                                              encoder, *evaluator, galois_keys, relin_keys,
                                              scale, slot_count, options.activation);
            print_profile_step(options.profile,
                               "stage1 block" + std::to_string(block_index),
                               profile_last, compute_start);
            plain = residual_block_plain(plain, weights.stage1[block_index], options.activation);
            std::cout << "Encrypted full HE stage1 block" << block_index
                      << " complete" << std::endl;
        }

        cipher = sparse_downsample_block_encrypted(
            cipher, plain.shape, weights.stage2.front(), encoder, *evaluator, galois_keys,
            relin_keys, scale, slot_count, plain.shape.height, plain.shape.width, 2,
            options.activation);
        print_profile_step(options.profile, "stage2 block0 sparse", profile_last,
                           compute_start);
        plain = residual_block_plain(plain, weights.stage2.front(), options.activation);
        std::cout << "Encrypted full HE stage2 block0 sparse complete" << std::endl;

        // 第一个 stage2 block 之后，逻辑 32x16x16 数据存放在物理 32x32x32 槽位中，
        // spacing=2。后续 stage2 block 都保持这个稀疏布局。
        TensorShape sparse_stage2_shape{plain.shape.channels, plain.shape.height * 2,
                                        plain.shape.width * 2};
        for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
        {
            cipher = sparse_residual_block_encrypted(
                cipher, sparse_stage2_shape, weights.stage2[block_index], encoder, *evaluator,
                galois_keys, relin_keys, scale, slot_count, 2, options.activation);
            print_profile_step(options.profile,
                               "stage2 block" + std::to_string(block_index) + " sparse",
                               profile_last, compute_start);
            plain = residual_block_plain(plain, weights.stage2[block_index], options.activation);
            std::cout << "Encrypted full HE stage2 block" << block_index
                      << " sparse complete" << std::endl;
        }

        cipher = sparse_to_compact_encrypted(cipher, sparse_stage2_shape, 2, encoder,
                                             *evaluator, galois_keys, scale, slot_count);
        print_profile_step(options.profile, "stage2->stage3 bridge", profile_last,
                           compute_start);
        std::cout << "Encrypted full HE stage2->stage3 bridge complete" << std::endl;

        // stage3 在 stride-2 下采样后也使用稀疏布局：
        // 逻辑 64x8x8 数据存放在物理 64x16x16 槽位中，spacing=2。
        cipher = sparse_downsample_block_encrypted(
            cipher, plain.shape, weights.stage3.front(), encoder, *evaluator, galois_keys,
            relin_keys, scale, slot_count, plain.shape.height, plain.shape.width, 2,
            options.activation);
        print_profile_step(options.profile, "stage3 block0 sparse", profile_last,
                           compute_start);
        plain = residual_block_plain(plain, weights.stage3.front(), options.activation);
        std::cout << "Encrypted full HE stage3 block0 sparse complete" << std::endl;

        TensorShape sparse_stage3_shape{plain.shape.channels, plain.shape.height * 2,
                                        plain.shape.width * 2};
        for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
        {
            cipher = sparse_residual_block_encrypted(
                cipher, sparse_stage3_shape, weights.stage3[block_index], encoder, *evaluator,
                galois_keys, relin_keys, scale, slot_count, 2, options.activation);
            print_profile_step(options.profile,
                               "stage3 block" + std::to_string(block_index) + " sparse",
                               profile_last, compute_start);
            plain = residual_block_plain(plain, weights.stage3[block_index], options.activation);
            std::cout << "Encrypted full HE stage3 block" << block_index
                      << " sparse complete" << std::endl;
        }

        cipher = sparse_global_average_pool_encrypted(cipher, sparse_stage3_shape, 2, encoder,
                                                      *evaluator, galois_keys, scale,
                                                      slot_count);
        print_profile_step(options.profile, "stage3 sparse global average pool",
                           profile_last, compute_start);
        cipher = linear_encrypted(cipher, weights.fc_weight, weights.fc_bias, weights.fc_in,
                                  weights.fc_out, encoder, *evaluator, galois_keys, scale,
                                  slot_count);
        print_profile_step(options.profile, "fc linear", profile_last, compute_start);

        const Tensor expected_logits = linear_plain(global_average_pool_plain(plain), weights);
        const auto decoded_logits = decrypt_vector(encoder, decryptor, cipher);
        print_profile_step(options.profile, "decrypt logits", profile_last, compute_start);
        const auto compute_end = Clock::now();
        const double logits_max_error = max_abs_error(decoded_logits, expected_logits.values);

        std::cout << "Encrypted full HE ResNet-20 logits:";
        for (size_t i = 0; i < expected_logits.values.size(); ++i)
        {
            std::cout << (i == 0 ? " " : ", ") << decoded_logits[i];
        }
        std::cout << std::endl;
        std::cout << "Encrypted full HE ResNet-20 logits max error: "
                  << logits_max_error << std::endl;
        std::cout << "Full HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return logits_max_error < 1e-2 ? 0 : 2;
    }

    if (options.run_stage3_tail)
    {
        const auto compute_start = Clock::now();
        const Tensor stage3_tail_sparse_input = embed_sparse_plain(stage3_tail_input, 16, 16, 2);
        poseidon::Ciphertext cipher =
            encrypt_vector(encoder, encryptor, stage3_tail_sparse_input.values, scale, slot_count);
        cipher = sparse_global_average_pool_encrypted(cipher, stage3_tail_sparse_input.shape, 2,
                                                      encoder, *evaluator, galois_keys, scale,
                                                      slot_count);
        cipher = linear_encrypted(cipher, weights.fc_weight, weights.fc_bias, weights.fc_in,
                                  weights.fc_out, encoder, *evaluator, galois_keys, scale,
                                  slot_count);

        const Tensor expected_logits =
            linear_plain(global_average_pool_plain(stage3_tail_input), weights);
        const auto decoded_logits = decrypt_vector(encoder, decryptor, cipher);
        const auto compute_end = Clock::now();
        const double logits_max_error = max_abs_error(decoded_logits, expected_logits.values);
        std::cout << "Encrypted stage3 tail smoke-test logits max error: "
                  << logits_max_error << std::endl;
        std::cout << "Stage3 tail HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return logits_max_error < 1e-3 ? 0 : 2;
    }

    if (options.run_stage2_stage3_bridge)
    {
        const auto compute_start = Clock::now();
        const Tensor bridge_sparse_input = embed_sparse_plain(bridge_operator_input, 32, 32, 2);
        poseidon::Ciphertext cipher_sparse =
            encrypt_vector(encoder, encryptor, bridge_sparse_input.values, scale, slot_count);
        poseidon::Ciphertext cipher_compact =
            sparse_to_compact_encrypted(cipher_sparse, bridge_sparse_input.shape, 2, encoder,
                                        *evaluator, galois_keys, scale, slot_count);
        const auto decoded_compact = decrypt_vector(encoder, decryptor, cipher_compact);
        const Tensor expected_compact = compact_sparse_plain(bridge_sparse_input, 2);
        const auto compute_end = Clock::now();
        const double bridge_max_error =
            max_abs_error(decoded_compact, expected_compact.values);
        std::cout << "Encrypted stage2->stage3 sparse-to-compact bridge max error: "
                  << bridge_max_error << std::endl;
        std::cout << "Bridge HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return bridge_max_error < 1e-3 ? 0 : 2;
    }

    if (run_connected_stage2_stage3)
    {
        const auto compute_start = Clock::now();
        poseidon::Ciphertext cipher_stage2_input =
            encrypt_vector(encoder, encryptor, stage2_operator_input.values, scale, slot_count);
        poseidon::Ciphertext cipher_stage2 =
            sparse_downsample_block_encrypted(cipher_stage2_input, stage2_operator_input.shape,
                                              weights.stage2.front(), encoder, *evaluator,
                                              galois_keys, relin_keys, scale, slot_count,
                                              stage2_operator_input.shape.height,
                                              stage2_operator_input.shape.width, 2,
                                              options.activation);
        Tensor stage2_plain = residual_block_plain(stage2_operator_input, weights.stage2.front(),
                                                   options.activation);
        std::cout << "Encrypted connected stage2 block0 sparse complete" << std::endl;

        TensorShape sparse_stage2_shape{stage2_plain.shape.channels,
                                        stage2_operator_input.shape.height,
                                        stage2_operator_input.shape.width};
        for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
        {
            cipher_stage2 = sparse_residual_block_encrypted(
                cipher_stage2, sparse_stage2_shape, weights.stage2[block_index], encoder,
                *evaluator, galois_keys, relin_keys, scale, slot_count, 2, options.activation);
            stage2_plain = residual_block_plain(stage2_plain, weights.stage2[block_index],
                                                options.activation);
            std::cout << "Encrypted connected stage2 block" << block_index
                      << " sparse complete" << std::endl;
        }

        poseidon::Ciphertext cipher_stage3_input =
            sparse_to_compact_encrypted(cipher_stage2, sparse_stage2_shape, 2, encoder,
                                        *evaluator, galois_keys, scale, slot_count);
        const auto decoded_bridge = decrypt_vector(encoder, decryptor, cipher_stage3_input);
        const double bridge_max_error = max_abs_error(decoded_bridge, stage2_plain.values);
        std::cout << "Encrypted connected stage2->stage3 bridge max error: "
                  << bridge_max_error << std::endl;

        poseidon::Ciphertext cipher_stage3 =
            sparse_downsample_block_encrypted(cipher_stage3_input, stage2_plain.shape,
                                              weights.stage3.front(), encoder, *evaluator,
                                              galois_keys, relin_keys, scale, slot_count,
                                              stage2_plain.shape.height, stage2_plain.shape.width,
                                              2, options.activation);
        Tensor stage3_plain = residual_block_plain(stage2_plain, weights.stage3.front(),
                                                   options.activation);
        std::cout << "Encrypted connected stage3 block0 sparse complete" << std::endl;

        if (options.run_stage2_stage3)
        {
            TensorShape sparse_stage3_shape{stage3_plain.shape.channels, stage2_plain.shape.height,
                                            stage2_plain.shape.width};
            for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
            {
                cipher_stage3 = sparse_residual_block_encrypted(
                    cipher_stage3, sparse_stage3_shape, weights.stage3[block_index], encoder,
                    *evaluator, galois_keys, relin_keys, scale, slot_count, 2,
                    options.activation);
                stage3_plain = residual_block_plain(stage3_plain, weights.stage3[block_index],
                                                    options.activation);
                std::cout << "Encrypted connected stage3 block" << block_index
                          << " sparse complete" << std::endl;
            }
        }

        const Tensor stage3_sparse_plain =
            embed_sparse_plain(stage3_plain, stage2_plain.shape.height, stage2_plain.shape.width,
                               2);
        const auto decoded_stage3 = decrypt_vector(encoder, decryptor, cipher_stage3);
        const auto compute_end = Clock::now();
        const double stage3_max_error = max_abs_error(decoded_stage3, stage3_sparse_plain.values);
        std::cout << "Encrypted connected "
                  << (options.run_stage2_stage3 ? "stage2->stage3" : "stage2->stage3 block0")
                  << " sparse smoke-test max error: " << stage3_max_error << std::endl;
        std::cout << "Connected stage2->stage3 HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return stage3_max_error < 1e-2 && bridge_max_error < 1e-2 ? 0 : 2;
    }

    if (run_sparse_stage2)
    {
        const auto compute_start = Clock::now();
        poseidon::Ciphertext cipher_stage2_input =
            encrypt_vector(encoder, encryptor, stage2_operator_input.values, scale, slot_count);
        poseidon::Ciphertext cipher_stage2 =
            sparse_downsample_block_encrypted(cipher_stage2_input, stage2_operator_input.shape,
                                              weights.stage2.front(), encoder, *evaluator,
                                              galois_keys, relin_keys, scale, slot_count,
                                              stage2_operator_input.shape.height,
                                              stage2_operator_input.shape.width, 2,
                                              options.activation);
        std::cout << "Encrypted isolated stage2 block0 sparse complete" << std::endl;
        Tensor stage2_plain = residual_block_plain(stage2_operator_input, weights.stage2.front(),
                                                   options.activation);

        if (options.run_stage2)
        {
            TensorShape sparse_stage2_shape{stage2_plain.shape.channels,
                                            stage2_operator_input.shape.height,
                                            stage2_operator_input.shape.width};
            for (size_t block_index = 1; block_index < weights.stage2.size(); ++block_index)
            {
                cipher_stage2 = sparse_residual_block_encrypted(
                    cipher_stage2, sparse_stage2_shape, weights.stage2[block_index], encoder,
                    *evaluator, galois_keys, relin_keys, scale, slot_count, 2,
                    options.activation);
                stage2_plain = residual_block_plain(stage2_plain, weights.stage2[block_index],
                                                    options.activation);
                std::cout << "Encrypted isolated stage2 block" << block_index
                          << " sparse complete" << std::endl;
            }
        }

        const Tensor stage2_sparse_plain =
            embed_sparse_plain(stage2_plain, stage2_operator_input.shape.height,
                               stage2_operator_input.shape.width, 2);
        const auto decoded_stage2 = decrypt_vector(encoder, decryptor, cipher_stage2);
        const auto compute_end = Clock::now();
        const double stage2_max_error = max_abs_error(decoded_stage2, stage2_sparse_plain.values);
        std::cout << "Encrypted isolated "
                  << (options.run_stage2 ? "stage2" : "stage2 block0")
                  << " sparse smoke-test max error: " << stage2_max_error << std::endl;
        std::cout << "Stage2 HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return stage2_max_error < 1e-2 ? 0 : 2;
    }

    if (run_sparse_stage3)
    {
        const auto compute_start = Clock::now();
        poseidon::Ciphertext cipher_stage3_input =
            encrypt_vector(encoder, encryptor, stage3_operator_input.values, scale, slot_count);
        poseidon::Ciphertext cipher_stage3 =
            sparse_downsample_block_encrypted(cipher_stage3_input, stage3_operator_input.shape,
                                              weights.stage3.front(), encoder, *evaluator,
                                              galois_keys, relin_keys, scale, slot_count,
                                              stage3_operator_input.shape.height,
                                              stage3_operator_input.shape.width, 2,
                                              options.activation);
        std::cout << "Encrypted isolated stage3 block0 sparse complete" << std::endl;
        Tensor stage3_plain = residual_block_plain(stage3_operator_input, weights.stage3.front(),
                                                   options.activation);

        if (options.run_stage3)
        {
            TensorShape sparse_stage3_shape{stage3_plain.shape.channels,
                                            stage3_operator_input.shape.height,
                                            stage3_operator_input.shape.width};
            for (size_t block_index = 1; block_index < weights.stage3.size(); ++block_index)
            {
                cipher_stage3 = sparse_residual_block_encrypted(
                    cipher_stage3, sparse_stage3_shape, weights.stage3[block_index], encoder,
                    *evaluator, galois_keys, relin_keys, scale, slot_count, 2,
                    options.activation);
                stage3_plain = residual_block_plain(stage3_plain, weights.stage3[block_index],
                                                    options.activation);
                std::cout << "Encrypted isolated stage3 block" << block_index
                          << " sparse complete" << std::endl;
            }
        }

        const Tensor stage3_sparse_plain =
            embed_sparse_plain(stage3_plain, stage3_operator_input.shape.height,
                               stage3_operator_input.shape.width, 2);
        const auto decoded_stage3 = decrypt_vector(encoder, decryptor, cipher_stage3);
        const auto compute_end = Clock::now();
        const double stage3_max_error = max_abs_error(decoded_stage3, stage3_sparse_plain.values);
        std::cout << "Encrypted isolated "
                  << (options.run_stage3 ? "stage3" : "stage3 block0")
                  << " sparse smoke-test max error: " << stage3_max_error << std::endl;
        std::cout << "Stage3 HE compute time: "
                  << elapsed_seconds(compute_start, compute_end) << " seconds" << std::endl;
        return stage3_max_error < 1e-2 ? 0 : 2;
    }

    poseidon::Ciphertext cipher_input =
        encrypt_vector(encoder, encryptor, input.values, scale, slot_count);
    poseidon::Ciphertext cipher_conv1 =
        conv2d_encrypted(cipher_input, input.shape, weights.conv1, encoder, *evaluator,
                         galois_keys, scale, slot_count);
    activation_inplace(cipher_conv1, *evaluator, relin_keys, encoder, scale, options.activation);

    if (options.run_stage1)
    {
        poseidon::Ciphertext cipher_stage1 = cipher_conv1;
        Tensor stage1_plain = conv1_activation_plain;
        for (size_t block_index = 0; block_index < weights.stage1.size(); ++block_index)
        {
            cipher_stage1 =
                residual_block_encrypted(cipher_stage1, stage1_plain.shape,
                                         weights.stage1[block_index], encoder, *evaluator,
                                         galois_keys, relin_keys, scale, slot_count,
                                         options.activation);
            stage1_plain = residual_block_plain(stage1_plain, weights.stage1[block_index],
                                                options.activation);
            std::cout << "Encrypted stage1 block" << block_index << " complete" << std::endl;
        }

        const auto decoded_stage1 = decrypt_vector(encoder, decryptor, cipher_stage1);
        const double stage1_max_error = max_abs_error(decoded_stage1, stage1_plain.values);
        std::cout << "Encrypted stage1 smoke-test max error: " << stage1_max_error << std::endl;
        return stage1_max_error < 1e-2 ? 0 : 2;
    }

    if (options.run_stage1_block0)
    {
        poseidon::Ciphertext cipher_block0 =
            residual_block_encrypted(cipher_conv1, conv1_activation_plain.shape,
                                     weights.stage1.front(), encoder, *evaluator, galois_keys,
                                     relin_keys, scale, slot_count, options.activation);
        const auto decoded_block0 = decrypt_vector(encoder, decryptor, cipher_block0);
        const Tensor block0_plain =
            residual_block_plain(conv1_activation_plain, weights.stage1.front(),
                                 options.activation);
        const double block0_max_error = max_abs_error(decoded_block0, block0_plain.values);

        std::cout << "Encrypted stage1 block0 smoke-test max error: " << block0_max_error
                  << std::endl;
        return block0_max_error < 1e-3 ? 0 : 2;
    }

    const auto decoded_conv1 = decrypt_vector(encoder, decryptor, cipher_conv1);
    const double conv1_max_error = max_abs_error(decoded_conv1, conv1_activation_plain.values);
    std::cout << "Encrypted conv1 + activation smoke-test max error: " << conv1_max_error
              << std::endl;
    return conv1_max_error < 1e-3 ? 0 : 2;
}

} // namespace ResNet20
