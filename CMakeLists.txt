cmake_minimum_required(VERSION 3.12)
project(APP_POSEIDON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)

include(FetchContent)

# 根据ASAN的值来设置编译器标志  
option(ASAN "Enable AddressSanitizer" OFF)
message(STATUS "ASAN: ${ASAN}")
if(ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address -static-libasan)
endif()

set(POSEIDON_USE_CXX17_OPTION_STR "Use C++17")
option(POSEIDON_USE_CXX17 ${POSEIDON_USE_CXX17_OPTION_STR} ON)
message(STATUS "POSEIDON_USE_CXX17: ${POSEIDON_USE_CXX17}")

# [option] CMAKE_BUILD_TYPE (default: "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
            STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG -fPIC -pthread ")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG -fPIC -pthread ")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lgmp  -fopenmp")

option(Build_GoogleTest "Build GoogleTest for Trident" ON)
if(Build_GoogleTest)
    if (NOT TARGET GTest::gtest)
        find_package(GTest)
        if (GTest_FOUND)
            message(STATUS "GTest found")
        elseif(NOT GTest_FOUND)
            message(STATUS "GTest not found")
            message(STATUS "GTest: downloading ...")
            FetchContent_Declare(
                    googletest
                    GIT_REPOSITORY https://github.com/google/googletest.git
                    GIT_TAG        58d77fa8070e8cec2dc1ed015d66b454c8d78850 # 1.12.1
            )
            FetchContent_MakeAvailable(googletest)
        endif()
    endif()
endif()

option(PIR "Build PIR for POSEIDON" ON)
message(STATUS "PIR: ${PIR}")
if (PIR)
    add_subdirectory(pir_bfv)
    add_subdirectory(pir_bgv)
endif()

option(APSI "Build applications for POSEIDON" ON)
message(STATUS "APSI: ${APSI}")
if (APSI)
    add_subdirectory(apsi)
endif()

option(LR_TRAIN "Build LR_TRAIN for POSEIDON" ON)
message(STATUS "LR_TRAIN: ${LR_TRAIN}")
if (LR_TRAIN)
    add_subdirectory(lr_train)
endif()

option(HEARTSTUDY "Build HEARTSTUDY for POSEIDON" ON)
message(STATUS "HEARTSTUDY: ${HEARTSTUDY}")
if (HEARTSTUDY)
    add_subdirectory(heartstudy)
endif()

option(KNN "Build KNN for POSEIDON" ON)
message(STATUS "KNN: ${KNN}")
if (KNN)
    add_subdirectory(knn)
endif()

option(MNIST "Build MNIST for POSEIDON" ON)
message(STATUS "MNIST: ${MNIST}")
if (MNIST)
    add_subdirectory(mnist)
endif()

option(RESNET20 "Build ResNet-20 for POSEIDON" ON)
message(STATUS "RESNET20: ${RESNET20}")
if (RESNET20)
    add_subdirectory(resnet20)
endif()

option(RESNET18 "Build ImageNet ResNet-18 for POSEIDON" ON)
message(STATUS "RESNET18: ${RESNET18}")
if (RESNET18)
    add_subdirectory(resnet18)
endif()
