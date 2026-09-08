#pragma once

#include "core/tensor.h"
#include "he/encrypted_tensor.h"

namespace qwen::he
{

struct ComparisonConfig
{
    double difference_bound = 1.0;

    void validate() const;
};

Tensor approximate_maximum_plain(const Tensor &lhs, const Tensor &rhs,
                                 const ComparisonConfig &config);

EncryptedTensor encrypted_maximum(const EncryptedTensor &lhs,
                                  const EncryptedTensor &rhs,
                                  const ComparisonConfig &config,
                                  HeRuntime &runtime);

} // namespace qwen::he
