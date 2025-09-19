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

    facial_recognition::BackendServer::getInstance().run();
//    facial_recognition::FrontendServer::getInstance().run();


//    facial_recognition::Test t;
//    t.test_main();

    return 0;
}




