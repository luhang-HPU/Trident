cmake_minimum_required(VERSION 3.12)

add_executable(
  resnet50
  resnet50.cpp
  infer_config.cpp
  infer_runtime.cpp
  parameter_loader.cpp
  progress_log.cpp
  infer.cpp
  multiplexed_ops.cpp
  tensor_cipher.cpp
  encrypted_group_ops.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  plain_cnn.cpp
)

target_include_directories(
  resnet50
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet50 poseidon_shared)

add_executable(
  resnet50_plain
  resnet50_plain.cpp
  infer_config.cpp
  parameter_loader.cpp
  plain_cnn.cpp
  relu_approx.cpp
)

target_include_directories(
  resnet50_plain
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet50_plain poseidon_shared)
