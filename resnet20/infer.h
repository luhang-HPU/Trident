#pragma once

#include <cstddef>

struct ResNet20RunOptions
{
    bool inference_only = false;
};

void ResNet_cifar10_sparse(size_t start_image_id, size_t end_image_id,
                           const ResNet20RunOptions &options = {});
