cmake_minimum_required(VERSION 3.10)
project(poseidonresnet20)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)

#add_subdirectory(cnn)
#add_library(poseidon_lib SHARED ${POSEIDON_SOURCE_FILES})

add_executable(poseidonresnet20 test/run/run_cnn.cpp test/cnn/infer_poseidon.cpp test/cnn/cnn_poseidon.cpp)
target_link_libraries (${PROJECT_NAME} /usr/poseidon/lib/libposeidon_shared.so gmp)

target_link_libraries(${PROJECT_NAME} Threads::Threads)

