#include "backend_server/backend_server.h"

#include "local_test/test.h"

int main(int argc, char** argv) {
#ifdef POSEIDON_USE_ZLIB
    std::cerr << "zlib not support" << std::endl;
    return -1;
    std::cout << "macro POSEIDON_USE_ZLIB: on" << std::endl;
#endif
#ifdef POSEIDON_USE_ZSTD
    std::cerr << "zstd not support" << std::endl;
    return -1;
    std::cout << "macro POSEIDON_USE_ZSTD: on" << std::endl;
#endif


    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_HARDWARE);

    facial_recognition::BackendServer::getInstance().run();

    return 0;
}




