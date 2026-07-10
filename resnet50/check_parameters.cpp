#include "infer_config.h"
#include "parameter_loader.h"

#include <iostream>
#include <stdexcept>

int main()
{
    try
    {
        const ModelWeights weights = load_resnet50_parameters();
        std::cout << "conv_weight=" << weights.conv_weight.size() << '\n';
        std::cout << "bn_bias=" << weights.bn_bias.size() << '\n';
        std::cout << "downsample_weight=" << weights.downsample_weight.size() << '\n';
        std::cout << "fc_weight=" << weights.linear_weight.size() << '\n';
        std::cout << "fc_bias=" << weights.linear_bias.size() << '\n';

        if (weights.conv_weight.size() != 49 || weights.bn_bias.size() != 49 ||
            weights.downsample_weight.size() != 4 ||
            weights.linear_weight.size() !=
                static_cast<std::size_t>(kImageNetClassCount * kResNet50FinalChannels) ||
            weights.linear_bias.size() != static_cast<std::size_t>(kImageNetClassCount))
        {
            throw std::runtime_error("unexpected ResNet50 parameter vector sizes");
        }
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "resnet50 parameter check failed: " << ex.what() << '\n';
        return 1;
    }
}

