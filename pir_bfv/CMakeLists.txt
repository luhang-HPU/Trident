option(PIR_USE_HARDWARE "USE HARDWARE TO RUN PIR of BFV" OFF)

if(PIR_USE_HARDWARE)
    message(STATUS "pir_bfv hardware version")
    add_definitions(-DPIR_USE_HARDWARE)
else()
    message(STATUS "pir_bfv software version")
endif()

file(GLOB PIR_BFV_SOURCE_FILES "*.cpp" "*.c")
add_executable(pir_bfv ${PIR_BFV_SOURCE_FILES})
target_link_libraries(pir_bfv PUBLIC poseidon_shared)
message(STATUS "PIR build success")