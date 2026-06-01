cmake_minimum_required(VERSION 3.12)

add_executable(resnet20 resnet20.cpp)
target_include_directories(
  resnet20
  PRIVATE
    /home/guoshuai/github/poseidon/src
    /home/guoshuai/github/poseidon/build
)
target_link_directories(resnet20 PRIVATE /home/guoshuai/github/poseidon/build)
target_link_libraries(resnet20 poseidon_shared)
set_target_properties(
  resnet20
  PROPERTIES
    BUILD_RPATH "/home/guoshuai/github/poseidon/build"
    INSTALL_RPATH "/home/guoshuai/github/poseidon/build")
