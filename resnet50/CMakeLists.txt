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
  tensor_cipher_group.cpp
  encrypted_group_ops.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
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

add_executable(
  resnet50_check_parameters
  check_parameters.cpp
  infer_config.cpp
  parameter_loader.cpp
  relu_approx.cpp
)

target_include_directories(
  resnet50_check_parameters
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet50_check_parameters poseidon_shared)

add_executable(
  resnet50_check_polyrelu_range
  check_polyrelu_range.cpp
  infer_config.cpp
  relu_approx.cpp
)

target_include_directories(
  resnet50_check_polyrelu_range
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet50_check_polyrelu_range poseidon_shared)

add_executable(
  resnet50_test_bootstrap_scale
  infer_config.cpp
  infer_runtime.cpp
  tensor_cipher.cpp
  relu_approx.cpp
  encrypted_ops.cpp
)

target_include_directories(
  resnet50_test_bootstrap_scale
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(resnet50_test_bootstrap_scale poseidon_shared)
