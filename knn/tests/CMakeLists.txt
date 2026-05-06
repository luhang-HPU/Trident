target_sources(knn_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/knn_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../knn_utils.cpp
)

target_include_directories(knn_tests PUBLIC ${CMAKE_CURRENT_LIST_DIR})
