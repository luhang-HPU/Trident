target_sources(unit_tests
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/unit_tests_runner.cpp
)

add_subdirectory(common)
add_subdirectory(receiver)
add_subdirectory(sender)
