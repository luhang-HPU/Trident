cmake_minimum_required(VERSION 3.12)

add_executable(knn knn.cpp)
target_link_libraries(knn poseidon_shared)

set(EXE_OUTPUT_DIR $<TARGET_FILE_DIR:knn>)
get_filename_component(SOURCE_FILE_PATH "train.jsonl" ABSOLUTE)

add_custom_command(
  TARGET knn
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${SOURCE_FILE_PATH}"
    "${EXE_OUTPUT_DIR}"
  COMMENT "Copying train.jsonl to executable directory: ${EXE_OUTPUT_DIR}"
)

option(KNN_BUILD_TESTS "Build tests for KNN" OFF)
if(KNN_BUILD_TESTS)
    add_executable(knn_tests)
    add_subdirectory(tests)
    target_include_directories(knn_tests PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>)
    target_link_libraries(knn_tests poseidon_shared GTest::gtest)
endif()
message(STATUS "KNN tests build success")
