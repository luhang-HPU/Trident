// Google Test
#include "src/factory/poseidon_factory.h"
#include "gtest/gtest.h"

/**
Main entry point for Google Test unit tests.
*/
int main(int argc, char **argv)
{
    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);
    testing::InitGoogleTest(&argc, argv);
    if (argc == 2) {
        testing::FLAGS_gtest_filter = argv[1];
    }
    return RUN_ALL_TESTS();
}
