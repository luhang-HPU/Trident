cmake_minimum_required(VERSION 3.10)
project(example)
find_package(Threads REQUIRED)
find_package(Kuku 2.1 REQUIRED)
find_package(Microsoft.GSL CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(fourq)

set(PSI_SOURCE_FILES ${PSI_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/item.h

    ${CMAKE_CURRENT_LIST_DIR}/psi.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ecpoint.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ecpoint.h
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp



)

add_executable(example ${PSI_SOURCE_FILES})


target_link_libraries (${PROJECT_NAME} /usr/poseidon/libposeidon_shared.so gmp)

target_link_libraries(${PROJECT_NAME} Threads::Threads)

target_link_libraries(${PROJECT_NAME} Kuku::kuku)

target_link_libraries(${PROJECT_NAME} Microsoft.GSL::GSL)


