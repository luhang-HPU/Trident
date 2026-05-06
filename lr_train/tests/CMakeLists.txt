target_sources(ckks_lrtrain_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ckks_lrtrain_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../batch_handler.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../ckks_lrtrain_utils.cpp
)

target_include_directories(ckks_lrtrain_tests PUBLIC ${CMAKE_CURRENT_LIST_DIR})
