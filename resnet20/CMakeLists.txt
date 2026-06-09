cmake_minimum_required(VERSION 3.12)

add_executable(
  resnet20
  resnet20.cpp
  infer.cpp
  cnn.cpp
  plain_cnn.cpp
)
add_executable(
  resnet20_test_bootstrap
  test_bootstrap_levels.cpp
)
add_executable(
  resnet20_test_relu
  cnn.cpp
  test_relu_levels.cpp
)
target_link_libraries(resnet20 poseidon_shared)
target_link_libraries(resnet20_test_bootstrap poseidon_shared)
target_link_libraries(resnet20_test_relu poseidon_shared)
