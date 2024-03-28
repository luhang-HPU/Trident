cmake_minimum_required(VERSION 3.10)
project(heartstudy)

set(CMAKE_CXX_STANDARD 17)


add_executable(heartstudy heartstudy.cpp)
target_link_libraries (${PROJECT_NAME} /usr/poseidon/lib/libposeidon_shared.so gmp)
