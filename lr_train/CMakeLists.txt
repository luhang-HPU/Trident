cmake_minimum_required(VERSION 3.10)
project(LR_train)

set(CMAKE_CXX_STANDARD 17)


add_executable(LR_train ${CMAKE_CURRENT_LIST_DIR}/LR_train.cpp)
target_link_libraries (${PROJECT_NAME} /usr/poseidon/lib/libposeidon_shared.so gmp)
