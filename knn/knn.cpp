#include "knn_utils.h"

#include <exception>
#include <iostream>

int main(int argc, char *argv[])
{
    try
    {
        const auto options = KNN::parse_options(argc, argv);
        return KNN::run_knn(options);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
