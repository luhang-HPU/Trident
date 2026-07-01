cmake_minimum_required(VERSION 3.12)

add_executable(
  resnet18
  resnet18.cpp
  infer_config.cpp
  infer_runtime.cpp
  parameter_loader.cpp
  progress_log.cpp
  infer.cpp
  tensor_cipher.cpp
  tensor_cipher_group.cpp
  encrypted_group_ops.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
  plain_cnn.cpp
)

target_include_directories(
  resnet18
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet18 poseidon_shared)

add_executable(
  resnet18_plain
  resnet18_plain.cpp
  infer_config.cpp
  parameter_loader.cpp
  plain_cnn.cpp
  relu_approx.cpp
)

add_executable(
  resnet18_test_relu
  test_relu_correctness.cpp
  infer_config.cpp
  infer_runtime.cpp
  tensor_cipher.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
)

target_include_directories(
  resnet18_plain
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(
  resnet18_test_relu
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet18_plain poseidon_shared)
target_link_libraries(resnet18_test_relu poseidon_shared)
