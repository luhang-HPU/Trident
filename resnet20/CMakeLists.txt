cmake_minimum_required(VERSION 3.12)

add_executable(
  resnet20
  resnet20.cpp
  infer_config.cpp
  infer_runtime.cpp
  parameter_loader.cpp
  infer.cpp
  tensor_cipher.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
  plain_cnn.cpp
)
add_executable(
  resnet20_test_bootstrap
  tensor_cipher.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
  test_bootstrap_levels.cpp
)
add_executable(
  resnet20_test_relu
  tensor_cipher.cpp
  relu_approx.cpp
  encrypted_ops.cpp
  encrypted_ops_trace.cpp
  test_relu_levels.cpp
)
foreach(target_name resnet20 resnet20_test_bootstrap resnet20_test_relu)
  target_include_directories(
    ${target_name}
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()

target_link_libraries(resnet20 poseidon_shared)
target_link_libraries(resnet20_test_bootstrap poseidon_shared)
target_link_libraries(resnet20_test_relu poseidon_shared)
