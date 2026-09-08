#include "infer.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

namespace
{

[[noreturn]] void usage_and_exit(const char *argv0)
{
    std::cerr << "Usage: " << argv0
              << " START_IMAGE_ID END_IMAGE_ID [--inference-only]" << std::endl;
    std::exit(1);
}

size_t parse_image_id(const char *value, const char *name)
{
    try
    {
        const std::string text(value);
        size_t parsed = 0;
        const unsigned long long result = std::stoull(text, &parsed, 10);
        if (parsed != text.size())
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
    if (argc != 3 && argc != 4)
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
        if (argc == 4)
        {
            if (std::string(argv[3]) != "--inference-only")
            {
                usage_and_exit(argv[0]);
            }
            options.inference_only = true;
        }

        ResNet_cifar10_sparse(start_image_id, end_image_id, options);
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "resnet20 error: " << ex.what() << std::endl;
        return 1;
    }
}
