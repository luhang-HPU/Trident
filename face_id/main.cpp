#include "backend_server.h"

int main(int argc, char** argv) {
#ifdef POSEIDON_USE_ZLIB
    std::cout << "macro POSEIDON_USE_ZLIB: on" << std::endl;
#endif
#ifdef POSEIDON_USE_ZSTD
    std::cout << "macro POSEIDON_USE_ZSTD: on" << std::endl;
#endif

    facial_recognition::BackendServer::getInstance().run();

    return 0;
}



