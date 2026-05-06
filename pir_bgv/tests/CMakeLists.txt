target_sources(pir_bgv_tests
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/pir_bgv_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests_runner.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../pir.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../pir_client.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../pir_server.cpp
)

target_include_directories(pir_bgv_tests PUBLIC ${CMAKE_CURRENT_LIST_DIR})