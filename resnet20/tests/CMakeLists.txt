target_sources(resnet20_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/resnet20_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../resnet20.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../resnet20_ops.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../resnet20_params.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../resnet20_plain.cpp
)

target_include_directories(resnet20_tests PUBLIC ${CMAKE_CURRENT_LIST_DIR})
