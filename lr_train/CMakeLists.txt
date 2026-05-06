cmake_minimum_required(VERSION 3.12)

add_executable(ckks_lrtrain ckks_lrtrain.cpp batch_handler.h batch_handler.cpp ckks_lrtrain_utils.h ckks_lrtrain_utils.cpp)
target_link_libraries(ckks_lrtrain poseidon_shared)

option(CKKS_LRTRAIN_BUILD_TESTS "Build tests for CKKS LRTrain" OFF)
if(CKKS_LRTRAIN_BUILD_TESTS)
    add_executable(ckks_lrtrain_tests)
    add_subdirectory(tests)
    target_include_directories(ckks_lrtrain_tests PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>)
    target_link_libraries(ckks_lrtrain_tests poseidon_shared GTest::gtest)
endif()
message(STATUS "CKKS LRTrain tests build success")
