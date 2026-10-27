#include "infer.h"

#include <cstdlib>
#include <cmath>
#include <exception>
#include <iostream>
#include <string>

namespace
{

[[noreturn]] void usage_and_exit(const char *argv0)
{
    std::cerr << "Usage: " << argv0
              << " START_IMAGE_ID END_IMAGE_ID [--inference-only] [--functional-relu]"
                 " [--functional-degree 15|31] [--log-n 15|16] [--dft-depth 2|3]"
                 " [--functional-bound B]" << std::endl;
    std::exit(1);
}

size_t parse_image_id(const char *value, const char *name)
{
    try
    {
        const std::string text(value);
        size_t parsed = 0;
        const unsigned long long result = std::stoull(text, &parsed, 10);
        if (text.empty() || text.front() == '-' || parsed != text.size())
        {
            throw std::invalid_argument("trailing characters");
        }
        return static_cast<size_t>(result);
    }
    catch (const std::exception &)
    {
        throw std::invalid_argument(std::string("invalid ") + name + ": " + value);
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage_and_exit(argv[0]);
    }

    try
    {
        const size_t start_image_id = parse_image_id(argv[1], "start_image_id");
        const size_t end_image_id = parse_image_id(argv[2], "end_image_id");
        if (start_image_id > end_image_id)
        {
            throw std::invalid_argument("start_image_id must be <= end_image_id");
        }

        ResNet20RunOptions options;
        for (int i = 3; i < argc; ++i)
        {
            const std::string option(argv[i]);
            if (option == "--inference-only") options.inference_only = true;
            else if (option == "--functional-relu") options.functional_relu = true;
            else if (option == "--functional-degree" || option == "--log-n" ||
                     option == "--dft-depth" || option == "--functional-bound")
            {
                if (++i == argc) usage_and_exit(argv[0]);
                options.functional_relu = true;
                if (option == "--functional-bound")
                {
                    std::size_t consumed = 0;
                    options.functional_bound = std::stod(argv[i], &consumed);
                    if (consumed != std::string(argv[i]).size()) usage_and_exit(argv[0]);
                }
                else
                {
                    const auto value = parse_image_id(argv[i], option.c_str());
                    if (option == "--functional-degree")
                    {
                        if (value != 15 && value != 31) usage_and_exit(argv[0]);
                        options.functional_degree = value;
                    }
                    else if (option == "--log-n")
                    {
                        if (value != 15 && value != 16) usage_and_exit(argv[0]);
                        options.functional_log_n = value;
                    }
                    else
                    {
                        if (value != 2 && value != 3) usage_and_exit(argv[0]);
                        options.functional_dft_depth = value;
                    }
                }
            }
            else usage_and_exit(argv[0]);
        }
        if (!std::isfinite(options.functional_bound) || options.functional_bound <= 0)
            throw std::invalid_argument("functional bound must be finite and positive");

        ResNet_cifar10_sparse(start_image_id, end_image_id, options);
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "resnet20 error: " << ex.what() << std::endl;
        return 1;
    }
}
