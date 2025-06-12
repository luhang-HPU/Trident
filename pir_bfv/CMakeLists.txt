set(USE_HARDWARE OFF)

if(PIR_USE_HARDWARE)
    message(STATUS "pir hardware version")
    add_definitions(-DPIR_USE_HARDWARE)
else()
    message(STATUS "pir software version")
endif()

add_library(pir_of_bfv pir.h pir.cpp pir_client.h pir_client.cpp pir_server.h
        pir_server.cpp)
target_link_libraries(pir_of_bfv PUBLIC poseidon_shared)

add_executable(bfv_pir main.cpp)
target_link_libraries(bfv_pir pir_of_bfv)
message(STATUS "PIR build success")