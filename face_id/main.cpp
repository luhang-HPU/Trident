#include "backend_server/backend_server.h"

#include "local_test/test.h"

int main(int argc, char** argv) {
#ifdef POSEIDON_USE_ZLIB
    std::cout << "macro POSEIDON_USE_ZLIB: on" << std::endl;
#endif
#ifdef POSEIDON_USE_ZSTD
    std::cout << "macro POSEIDON_USE_ZSTD: on" << std::endl;
#endif

    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);

    facial_recognition::BackendServer::getInstance().run();

// DEBUG code
//    facial_recognition::Test t;
//    t.test_open_frontend_and_backend();

    return 0;
}




