target_sources(heart_study_tests
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/heart_study_tests_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/tests_runner.cpp
)

target_include_directories(heart_study_tests PUBLIC ${CMAKE_CURRENT_LIST_DIR})