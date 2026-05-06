#include "poseidon/factory/poseidon_factory.h"
#include "gtest/gtest.h"

/**
Main entry point for Google Test unit tests.
*/
int main(int argc, char **argv)
{
#ifdef PIR_USE_HARDWARE
    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_HARDWARE);
#else
    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);
#endif
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}