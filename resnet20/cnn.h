#pragma once

#include "encrypted_ops.h"

#include "poseidon/poseidon_context.h"

#include <iosfwd>

void log_cipher_state(const TensorCipher &tensor, const poseidon::PoseidonContext &context,
                      std::ostream &output);
