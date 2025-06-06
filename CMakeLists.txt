cmake_minimum_required(VERSION 3.12)
project(APP_POSEIDON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 99)

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
SET (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lgmp  -fopenmp")

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

option(FACE_ID "Build FACE_ID for POSEIDON" ON)
message(STATUS "FACE_ID: ${FACE_ID}")
if (FACE_ID)
    add_subdirectory(face_id)
endif()

option(TRANSFORMER "Build TRANSFORMER for POSEIDON" ON)
message(STATUS "TRANSFORMER: ${TRANSFORMER}")
if (TRANSFORMER)
    add_subdirectory(transformer)
endif()

option(LR_TRAIN "Build LR_TRAIN for POSEIDON" ON)
message(STATUS "LR_TRAIN: ${LR_TRAIN}")
if (LR_TRAIN)
    add_subdirectory(lr_train)
endif()

option(HEARTSTUDY "Build HEARTSTUDY for POSEIDON" OFF)
message(STATUS "HEARTSTUDY: ${HEARTSTUDY}")
if (HEARTSTUDY)
    add_subdirectory(heartstudy)
endif()

