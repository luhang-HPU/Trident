#include "backend_server/backend_server.h"
#include "frontend_server/frontend_server.h"

#include "local_test/test.h"

int main(int argc, char** argv) {
#ifdef POSEIDON_USE_ZLIB
    std::cout << "macro POSEIDON_USE_ZLIB: on" << std::endl;
#endif
#ifdef POSEIDON_USE_ZSTD
    std::cout << "macro POSEIDON_USE_ZSTD: on" << std::endl;
#endif

    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_SOFTWARE);

//    std::thread t1(&facial_recognition::BackendServer::run, &facial_recognition::BackendServer::getInstance());
//    std::thread t2(&facial_recognition::FrontendServer::run, &facial_recognition::FrontendServer::getInstance());

    facial_recognition::BackendServer::getInstance().run();
//    facial_recognition::FrontendServer::getInstance().run();


//    facial_recognition::Test t;
//    t.test_main();

    return 0;
}




