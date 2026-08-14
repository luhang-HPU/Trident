#include "infer.h"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

namespace
{

[[noreturn]] void usage_and_exit(const char *argv0)
{
    std::cerr << "Usage: " << argv0 << " START_IMAGE_ID END_IMAGE_ID [DNUM=3|4]"
              << std::endl;
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

size_t parse_dnum(const char *value)
{
    const size_t dnum = parse_image_id(value, "dnum");
    if (dnum != 3 && dnum != 4)
    {
        throw std::invalid_argument("dnum must be 3 or 4");
    }
    return dnum;
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
        const size_t dnum = argc == 4 ? parse_dnum(argv[3]) : 3;
        if (start_image_id > end_image_id)
        {
            throw std::invalid_argument("start_image_id must be <= end_image_id");
        }

        ResNet_imagenet_sparse(start_image_id, end_image_id, dnum);
        return 0;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "resnet18 error: " << ex.what() << std::endl;
        return 1;
    }
}
