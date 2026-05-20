cmake_minimum_required(VERSION 3.12)

add_executable(resnet20
    resnet20_main.cpp
    resnet20.cpp
    resnet20_ops.cpp
    resnet20_params.cpp
    resnet20_plain.cpp
)
target_link_libraries(resnet20 poseidon_shared)

option(RESNET20_BUILD_TESTS "Build tests for ResNet-20" OFF)
if(RESNET20_BUILD_TESTS)
    set(RESNET20_GTEST_LIB "")
    if(TARGET GTest::gtest)
        set(RESNET20_GTEST_LIB GTest::gtest)
    elseif(TARGET GTest::GTest)
        set(RESNET20_GTEST_LIB GTest::GTest)
    elseif(GTEST_LIBRARIES)
        set(RESNET20_GTEST_LIB ${GTEST_LIBRARIES})
    else()
        find_package(GTest QUIET)
        if(TARGET GTest::gtest)
            set(RESNET20_GTEST_LIB GTest::gtest)
        elseif(TARGET GTest::GTest)
            set(RESNET20_GTEST_LIB GTest::GTest)
        else()
            set(RESNET20_GTEST_LIB ${GTEST_LIBRARIES})
        endif()
    endif()

    if(RESNET20_GTEST_LIB)
        add_executable(resnet20_tests)
        add_subdirectory(tests)
        target_include_directories(resnet20_tests PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>)
        target_link_libraries(resnet20_tests poseidon_shared ${RESNET20_GTEST_LIB})
    else()
        message(WARNING "RESNET20_BUILD_TESTS is ON, but GTest is unavailable; skipping resnet20_tests")
    endif()
endif()
message(STATUS "ResNet-20 tests build success")
