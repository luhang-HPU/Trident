#include "resnet20.h"

#include <exception>
#include <iostream>

int main(int argc, char *argv[])
{
    try
    {
        const auto options = ResNet20::parse_options(argc, argv);
        return ResNet20::run_resnet20(options);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
