cmake_minimum_required(VERSION 3.10)
project(resnet20)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_executable(resnet20 ${CMAKE_CURRENT_LIST_DIR}/src/run/run_cnn.cpp ${CMAKE_CURRENT_LIST_DIR}/src/cnn/infer_poseidon.cpp ${CMAKE_CURRENT_LIST_DIR}/src/cnn/cnn_poseidon.cpp)
target_link_libraries (${PROJECT_NAME} /usr/poseidon/lib/libposeidon_shared.so gmp)

target_link_libraries(${PROJECT_NAME} Threads::Threads)

