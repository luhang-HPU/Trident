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
target_include_directories(
  resnet20
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    /home/guoshuai/github/poseidon/src
    /home/guoshuai/github/poseidon/build
)
target_include_directories(
  resnet20_test_bootstrap
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    /home/guoshuai/github/poseidon/src
    /home/guoshuai/github/poseidon/build
)
target_include_directories(
  resnet20_test_relu
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    /home/guoshuai/github/poseidon/src
    /home/guoshuai/github/poseidon/build
)
target_link_directories(resnet20 PRIVATE /home/guoshuai/github/poseidon/build)
target_link_directories(resnet20_test_bootstrap PRIVATE /home/guoshuai/github/poseidon/build)
target_link_directories(resnet20_test_relu PRIVATE /home/guoshuai/github/poseidon/build)
target_link_libraries(resnet20 poseidon_shared)
target_link_libraries(resnet20_test_bootstrap poseidon_shared)
target_link_libraries(resnet20_test_relu poseidon_shared)
set_target_properties(
  resnet20
  PROPERTIES
    BUILD_RPATH "/home/guoshuai/github/poseidon/build"
    INSTALL_RPATH "/home/guoshuai/github/poseidon/build")
set_target_properties(
  resnet20_test_bootstrap
  PROPERTIES
    BUILD_RPATH "/home/guoshuai/github/poseidon/build"
    INSTALL_RPATH "/home/guoshuai/github/poseidon/build")
set_target_properties(
  resnet20_test_relu
  PROPERTIES
    BUILD_RPATH "/home/guoshuai/github/poseidon/build"
    INSTALL_RPATH "/home/guoshuai/github/poseidon/build")
