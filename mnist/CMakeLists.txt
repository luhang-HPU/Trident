cmake_minimum_required(VERSION 3.12)

add_executable(mnist mnist.cpp)
target_link_libraries(mnist poseidon_shared)
