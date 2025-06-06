set(USE_HARDWARE OFF)
add_library(pir_of_bgv pir.h pir.cpp pir_client.h pir_client.cpp pir_server.h
        pir_server.cpp)
if(USE_HARDWARE)
    add_definitions(-DPIR_USE_HARDWARE)
    message(STATUS "pir hardware version")
else()
    message(STATUS "pir software version")
endif()

target_link_libraries(pir_of_bgv PUBLIC poseidon_shared)

add_executable(bgv_pir main.cpp)
target_link_libraries(bgv_pir pir_of_bgv)
message(STATUS "PIR build success")