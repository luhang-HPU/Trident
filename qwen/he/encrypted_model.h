#pragma once

#include "he/encrypted_decoder.h"

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

namespace qwen::he
{

using EncryptedStackTraceCallback = std::function<void(
    std::size_t, const std::string &, const EncryptedTensor &)>;

EncryptedTensor encrypted_decoder_stack(
    const EncryptedTensor &input,
    const std::vector<DecoderLayerWeights> &weights,
    const QwenConfig &model_config,
    const std::vector<EncryptedDecoderApproximationConfig>
        &approximations,
    std::size_t position_offset, HeRuntime &runtime,
    const EncryptedStackTraceCallback &trace = {},
    std::vector<EncryptedKVCache> *caches = nullptr);

} // namespace qwen::he
