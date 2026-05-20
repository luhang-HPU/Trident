#include "poseidon/factory/poseidon_factory.h"
#include "gtest/gtest.h"

int main(int argc, char **argv)
{
    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
