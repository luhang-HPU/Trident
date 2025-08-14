cmake_minimum_required(VERSION 3.12)

add_executable(knn knn.cpp)
target_link_libraries(knn poseidon_shared)
