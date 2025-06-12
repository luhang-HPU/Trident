set(PIR_USE_HARDWARE ON)

if(PIR_USE_HARDWARE)
    message(STATUS "pir_bfv hardware version")
    add_definitions(-DPIR_USE_HARDWARE)
else()
    message(STATUS "pir_bfv software version")
endif()

add_executable(pir_bfv pir.h pir.cpp pir_client.h pir_client.cpp pir_server.h
        pir_server.cpp main.cpp)
target_link_libraries(pir_bfv PUBLIC poseidon_shared)
message(STATUS "PIR build success")