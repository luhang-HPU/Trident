cmake_minimum_required(VERSION 3.12)

set(project_name face_id)
project(${project_name})

set(FACEID_EXAMPLE
        main.cpp frontend_server.cpp json_helper.cpp
)

include_directories(../cinatra)
include_directories(../nlohmann_json)

# Compile Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
message(STATUS "CXX Standard: ${CMAKE_CXX_STANDARD}")

# Build Type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# libc++ or libstdc++&clang
option(BUILD_WITH_LIBCXX "Build with libc++" OFF)
message(STATUS "BUILD_WITH_LIBCXX: ${BUILD_WITH_LIBCXX}")
if(BUILD_WITH_LIBCXX AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
else()
endif()

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++20")
endif ()

# --------------------- Gcc
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
    #-ftree-slp-vectorize with coroutine cause link error. disable it util gcc fix.
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fno-tree-slp-vectorize")
endif()

# --------------------- Msvc
# Resolves C1128 complained by MSVC: number of sections exceeded object file format limit: compile with /bigobj.
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/bigobj>")
# Resolves C4737 complained by MSVC: C4737: Unable to perform required tail call. Performance may be degraded. "Release-Type only"
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/EHa>")
link_directories("C:/Program Files (x86)/Poseidon/lib")
add_executable(${project_name} ${FACEID_EXAMPLE})
target_compile_definitions(${project_name} PRIVATE ASYNC_SIMPLE_HAS_NOT_AIO)
target_link_libraries(${project_name} PRIVATE poseidon_shared)
target_include_directories(${project_name} PUBLIC "C:/Program Files (x86)/Poseidon/include")

if (ENABLE_SSL)
    target_link_libraries(${project_name} ${OPENSSL_LIBRARIES} pthread -ldl)
endif()

if (ENABLE_CLIENT_SSL)
    target_link_libraries(${project_name} ${OPENSSL_LIBRARIES} pthread -ldl)
endif()

if (ENABLE_GZIP)
    target_link_libraries(${project_name} ${ZLIB_LIBRARIES})
endif()

if (ENABLE_SIMD STREQUAL "AARCH64")
    if (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
        add_library(neon INTERFACE IMPORTED)
        target_compile_options(neon INTERFACE -march=armv8-a+fp+simd)
        target_link_libraries(${project_name} neon)
    endif ()
elseif (ENABLE_SIMD STREQUAL "SSE42")
    if (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_library(sse4_2 INTERFACE IMPORTED)
        if(MSVC)
            target_compile_options(sse4_2 INTERFACE /arch:SSE4.2)
        else()
            target_compile_options(sse4_2 INTERFACE -msse4.2)
        endif()
        target_link_libraries(${project_name} sse4_2)
    endif ()
elseif (ENABLE_SIMD STREQUAL "AVX2")
    if (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_library(avx2 INTERFACE IMPORTED)
        if(MSVC)
            target_compile_options(avx2 INTERFACE /arch:AVX2)
        else()
            target_compile_options(avx2 INTERFACE -mavx2)
        endif()
        target_link_libraries(${project_name} avx2)
        set(CMAKE_CXX_FLAGS "-fpermissive")
    endif ()
endif ()

install(TARGETS ${project_name} DESTINATION include)