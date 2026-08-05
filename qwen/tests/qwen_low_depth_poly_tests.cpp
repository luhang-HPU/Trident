#include "core/tensor.h"
#include "he/approximation.h"
#include "he/encrypted_ops.h"
#include "he/he_config.h"
#include "he/he_runtime.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <iostream>
#include <stdexcept>

namespace
{

double maximum_absolute_error(const qwen::Tensor &lhs,
                              const qwen::Tensor &rhs)
{
    if (lhs.shape() != rhs.shape())
    {
        throw std::invalid_argument("tensor shape mismatch");
    }
    double maximum = 0.0;
    for (std::size_t row = 0; row < lhs.dim(0); ++row)
    {
        for (std::size_t column = 0; column < lhs.dim(1); ++column)
        {
            maximum = std::max(
                maximum,
                std::abs(lhs.at(row, column) - rhs.at(row, column)));
        }
    }
    return maximum;
}

} // namespace

int main()
{
    try
    {
        qwen::he::HeRuntime runtime =
            qwen::he::make_he_runtime(qwen::he::debug_he_config());
        qwen::Tensor input({1, 896});
        qwen::Tensor weight({896});
        for (std::size_t index = 0; index < 896; ++index)
        {
            input.at(0, index) =
                0.012 + 0.006 * std::sin(static_cast<double>(index) * 0.07);
            weight.at(index) =
                0.8 + 0.2 * std::cos(static_cast<double>(index) * 0.03);
        }

        constexpr double epsilon = 1.0e-6;
        const qwen::he::ApproximationConfig config =
            qwen::he::first_layer_inverse_sqrt_config();
        const qwen::Tensor polynomial =
            qwen::he::approximate_rms_norm_plain(
                input, weight, epsilon, config);
        const qwen::he::EncryptedTensor encrypted =
            qwen::he::encrypt_tensor(input, runtime);
        const qwen::he::EncryptedTensor result =
            qwen::he::encrypted_rms_norm(
                encrypted, weight, epsilon, config, runtime);
        const qwen::Tensor decrypted =
            qwen::he::decrypt_tensor(result, runtime);

        const std::size_t input_level =
            runtime.chain_index(encrypted.cipher(0, 0));
        const std::size_t output_level =
            runtime.chain_index(result.cipher(0, 0));
        const std::size_t rmsnorm_levels = input_level - output_level;
        // Square, mean, x*inverse, and gamma account for four levels.
        const std::size_t polynomial_wrapper_levels = rmsnorm_levels - 4;
        const double error =
            maximum_absolute_error(decrypted, polynomial);
        std::cout << "degree=15 polynomial_wrapper_levels="
                  << polynomial_wrapper_levels
                  << " rmsnorm_level_in=" << input_level
                  << " rmsnorm_level_out=" << output_level
                  << " rmsnorm_levels=" << rmsnorm_levels
                  << " max_abs=" << error << '\n';

        if (rmsnorm_levels != 9 || polynomial_wrapper_levels != 5)
        {
            throw std::runtime_error(
                "reduced-depth RMSNorm did not consume nine levels");
        }
        if (error > 2.0e-4)
        {
            throw std::runtime_error(
                "reduced-depth RMSNorm exceeded CKKS error tolerance");
        }
        std::cout << "qwen_low_depth_poly_tests: PASS\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "qwen_low_depth_poly_tests: FAIL: "
                  << error.what() << '\n';
        return 1;
    }
}
