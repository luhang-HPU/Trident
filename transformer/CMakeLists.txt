add_library(transformer transformer.cpp)
message(STATUS "transformer (software version)")

target_link_libraries(transformer PUBLIC poseidon_shared)

add_executable(transformer_test main.cpp)
target_link_libraries(transformer_test transformer)
message(STATUS "transformer build success")