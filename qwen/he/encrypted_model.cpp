#include "he/encrypted_model.h"

#include <stdexcept>
#include <string>

namespace qwen::he
{

EncryptedTensor encrypted_decoder_stack(
    const EncryptedTensor &input,
    const std::vector<DecoderLayerWeights> &weights,
    const QwenConfig &model_config,
    const std::vector<EncryptedDecoderApproximationConfig>
        &approximations,
    std::size_t position_offset, HeRuntime &runtime,
    const EncryptedStackTraceCallback &trace,
    std::vector<EncryptedKVCache> *caches)
{
    if (weights.empty() || weights.size() != approximations.size())
    {
        throw std::invalid_argument(
            "encrypted decoder stack weights/config count mismatch");
    }
    if (caches != nullptr)
    {
        if (caches->empty())
        {
            caches->resize(weights.size());
        }
        if (caches->size() != weights.size())
        {
            throw std::invalid_argument(
                "encrypted decoder stack KV cache count mismatch");
        }
        for (const EncryptedKVCache &cache : *caches)
        {
            if (cache.size() != position_offset)
            {
                throw std::invalid_argument(
                    "encrypted decoder stack KV cache offset mismatch");
            }
        }
    }
    EncryptedTensor hidden = input;
    for (std::size_t layer = 0; layer < weights.size(); ++layer)
    {
        runtime.set_operation_context(
            "layer_" + std::to_string(layer));
        runtime.set_bootstrap_value_scale(
            runtime.config().bootstrap_value_scale_for_layer(layer));
        EncryptedKVCache *cache =
            caches == nullptr ? nullptr : &caches->at(layer);
        hidden = encrypted_decoder_layer(
            hidden, weights[layer], model_config,
            approximations[layer], position_offset, runtime,
            [&](const std::string &name,
                const EncryptedTensor &tensor) {
                if (trace)
                {
                    trace(layer, name, tensor);
                }
            },
            cache);
    }
    return hidden;
}

} // namespace qwen::he
