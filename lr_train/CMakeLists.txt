cmake_minimum_required(VERSION 3.12)

add_executable(ckks_lrtrain ckks_lrtrain.cpp batch_handler.h batch_handler.cpp)
target_link_libraries(ckks_lrtrain poseidon_shared)
