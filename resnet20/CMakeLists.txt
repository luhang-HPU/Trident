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
  execution_mode.h
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

add_library(trident_functional_bootstrap STATIC functional_bootstrap.cpp)
target_link_libraries(trident_functional_bootstrap PUBLIC poseidon_shared)
target_include_directories(trident_functional_bootstrap PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(resnet20_test_functional test_functional_bootstrap.cpp tensor_cipher.cpp)
target_link_libraries(resnet20_test_functional PRIVATE trident_functional_bootstrap)
add_test(NAME trident_functional_d15 COMMAND resnet20_test_functional 10 15 2)
add_test(NAME trident_functional_d31 COMMAND resnet20_test_functional 10 31 2)
add_test(NAME trident_functional_d15_q19_bound COMMAND resnet20_test_functional 10 15 2 2 0.25)
add_test(NAME trident_functional_d31_q20 COMMAND resnet20_test_functional 10 31 2 2)
target_link_libraries(resnet20 trident_functional_bootstrap)
