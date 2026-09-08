#pragma once

#include <cstddef>

struct ResNet18RunOptions
{
    std::size_t dnum = 3;
    bool inference_only = false;
    std::size_t conv_plaintext_cache_mb = 2048;
};

void ResNet_imagenet_sparse(size_t start_image_id, size_t end_image_id,
                            const ResNet18RunOptions &options = {});
