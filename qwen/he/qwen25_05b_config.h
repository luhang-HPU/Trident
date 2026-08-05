#pragma once

#include "he/encrypted_decoder.h"

#include <cstddef>

namespace qwen::he
{

EncryptedDecoderApproximationConfig
qwen25_05b_layer_approximation(std::size_t layer,
                               std::size_t maximum_tokens);

ApproximationConfig qwen25_05b_final_inverse_sqrt_config();

} // namespace qwen::he
