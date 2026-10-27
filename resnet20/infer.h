#pragma once

#include <cstddef>

struct ResNet20RunOptions
{
    bool inference_only = false;
    bool functional_relu = false;
    unsigned functional_degree = 15;
    unsigned functional_log_n = 15;
    unsigned functional_dft_depth = 2;
    double functional_bound = 1.0;
};

void ResNet_cifar10_sparse(size_t start_image_id, size_t end_image_id,
                           const ResNet20RunOptions &options = {});
