#pragma once

#include <cstddef>
#include "apsi/item.h"

namespace apsi {
    namespace util {
        EncryptedLabel encrypt_label(
            const Label &label,
            const LabelKey &key,
            std::size_t label_byte_count,
            std::size_t nonce_byte_count);

        Label decrypt_label(
            const EncryptedLabel &encrypted_label,
            const LabelKey &key,
            std::size_t nonce_byte_count);
    } // namespace util
} // namespace apsi
