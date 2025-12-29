#include "backend_server/backend_server.h"

#include "local_test/test.h"

int main(int argc, char** argv) {


    poseidon::PoseidonFactory::get_instance()->set_device_type(poseidon::DEVICE_HARDWARE);

    facial_recognition::BackendServer::getInstance().run();

    return 0;
}




