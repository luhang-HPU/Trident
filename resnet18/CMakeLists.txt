cmake_minimum_required(VERSION 3.12)

add_library(
  resnet18_inference STATIC
  infer_config.cpp
  infer_runtime.cpp
  final_logits.cpp
  parameter_loader.cpp
  progress_log.cpp
  infer.cpp
  tensor_cipher.cpp
  encrypted_group_ops.cpp
  relu_approx.cpp
  chebyshev_relu.cpp
  encrypted_ops.cpp
  plain_cnn.cpp
)

target_include_directories(
  resnet18_inference
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet18_inference PUBLIC poseidon_shared)

add_executable(resnet18 resnet18.cpp)
target_link_libraries(resnet18 PRIVATE resnet18_inference)

add_executable(resnet18_chebyshev resnet18.cpp)
target_compile_definitions(resnet18_chebyshev PRIVATE RESNET18_DEFAULT_CHEBYSHEV=1)
target_link_libraries(resnet18_chebyshev PRIVATE resnet18_inference)

add_executable(resnet18_chebyshev_single22 resnet18.cpp)
target_compile_definitions(resnet18_chebyshev_single22 PRIVATE
  RESNET18_DEFAULT_CHEBYSHEV=1 RESNET18_DEFAULT_SINGLE22=1)
target_link_libraries(resnet18_chebyshev_single22 PRIVATE resnet18_inference)

add_executable(
  resnet18_plain
  resnet18_plain.cpp
  infer_config.cpp
  parameter_loader.cpp
  plain_cnn.cpp
  relu_approx.cpp
  chebyshev_relu.cpp
)

target_include_directories(
  resnet18_plain
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet18_plain poseidon_shared)

if(BUILD_TESTING)
  add_executable(resnet18_chebyshev_relu_test test_chebyshev_relu.cpp)
  target_include_directories(resnet18_chebyshev_relu_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(resnet18_chebyshev_relu_test resnet18_inference)
  add_test(NAME resnet18_chebyshev_relu COMMAND resnet18_chebyshev_relu_test)
  add_test(NAME resnet18_single22 COMMAND resnet18_chebyshev_relu_test 13 --single22)
  add_executable(resnet18_bootstrap_trim_test test_bootstrap_trim.cpp)
  target_link_libraries(resnet18_bootstrap_trim_test PRIVATE resnet18_inference)
  add_test(NAME resnet18_bootstrap_trim COMMAND resnet18_bootstrap_trim_test)
  set_tests_properties(resnet18_bootstrap_trim PROPERTIES ENVIRONMENT "RESNET18_THREADS=4")
  add_executable(resnet18_final_logits_test test_final_logits.cpp)
  target_link_libraries(resnet18_final_logits_test PRIVATE resnet18_inference)
  add_test(NAME resnet18_final_logits COMMAND resnet18_final_logits_test)
endif()
