cmake_minimum_required(VERSION 3.12)

add_executable(knn knn_POSEIDON.cpp)
target_link_libraries(knn poseidon_shared)
