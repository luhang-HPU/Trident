cmake_minimum_required(VERSION 3.12)

set(
  QWEN_PLAIN_SOURCES
  core/tensor.cpp
  io/safetensors.cpp
  model/qwen_config.cpp
  model/plain_attention.cpp
  model/plain_decoder.cpp
  model/plain_qwen.cpp
  ops/plain_ops.cpp
)

add_library(qwen_plain_core STATIC ${QWEN_PLAIN_SOURCES})
target_include_directories(
  qwen_plain_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../src
)

find_package(OpenMP)
if(OpenMP_CXX_FOUND)
  target_link_libraries(qwen_plain_core PUBLIC OpenMP::OpenMP_CXX)
endif()

add_executable(qwen_plain qwen_plain.cpp)
target_link_libraries(qwen_plain PRIVATE qwen_plain_core)

add_executable(qwen_plain_tests tests/qwen_plain_tests.cpp)
target_link_libraries(qwen_plain_tests PRIVATE qwen_plain_core)

add_test(NAME qwen_plain_tests COMMAND qwen_plain_tests)

set(
  QWEN_HE_SOURCES
  he/he_config.cpp
  he/he_runtime.cpp
  he/encrypted_tensor.cpp
  he/encrypted_ops.cpp
  he/approximation.cpp
  he/encrypted_attention.cpp
  he/comparison.cpp
  he/encrypted_decoder.cpp
  he/encrypted_model.cpp
  he/qwen25_05b_config.cpp
  he/validation_log.cpp
  ../resnet50/relu_approx.cpp
)

add_library(qwen_he_core STATIC ${QWEN_HE_SOURCES})
target_include_directories(
  qwen_he_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../resnet50
)
target_link_libraries(qwen_he_core PUBLIC qwen_plain_core poseidon_shared)

add_executable(qwen_he qwen_he.cpp)
target_link_libraries(qwen_he PRIVATE qwen_he_core)

add_executable(qwen_he_mlp qwen_he_mlp.cpp)
target_link_libraries(qwen_he_mlp PRIVATE qwen_he_core)

add_executable(qwen_he_qkv qwen_he_qkv.cpp)
target_link_libraries(qwen_he_qkv PRIVATE qwen_he_core)

add_executable(qwen_he_attention qwen_he_attention.cpp)
target_link_libraries(qwen_he_attention PRIVATE qwen_he_core)

add_executable(qwen_he_decoder qwen_he_decoder.cpp)
target_link_libraries(qwen_he_decoder PRIVATE qwen_he_core)

add_executable(qwen_poly_stack qwen_poly_stack.cpp)
target_link_libraries(qwen_poly_stack PRIVATE qwen_he_core)

add_executable(qwen_he_stack qwen_he_stack.cpp)
target_link_libraries(qwen_he_stack PRIVATE qwen_he_core)

add_executable(qwen_he_decode qwen_he_decode.cpp)
target_link_libraries(qwen_he_decode PRIVATE qwen_he_core)

add_executable(qwen_he_generate qwen_he_generate.cpp)
target_link_libraries(qwen_he_generate PRIVATE qwen_he_core)

add_executable(qwen_he_bootstrap qwen_he_bootstrap.cpp)
target_link_libraries(qwen_he_bootstrap PRIVATE qwen_he_core)

add_executable(qwen_he_tests tests/qwen_he_tests.cpp)
target_link_libraries(qwen_he_tests PRIVATE qwen_he_core)

add_executable(qwen_low_depth_poly_tests tests/qwen_low_depth_poly_tests.cpp)
target_link_libraries(qwen_low_depth_poly_tests PRIVATE qwen_he_core)

add_test(NAME qwen_he_tests COMMAND qwen_he_tests)
add_test(NAME qwen_low_depth_poly_tests COMMAND qwen_low_depth_poly_tests)
