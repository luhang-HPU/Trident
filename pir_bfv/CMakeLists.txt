set(USE_HARDWARE ON)
if(USE_HARDWARE)
    add_library(sealpir pir.h pir.cpp pir_client_hardware.h pir_client_hardware.cpp pir_server_hardware.h
            pir_server_hardware.cpp)
    add_definitions(-DPIR_USE_HARDWARE)
    #add_definitions(-DDEBUG)
    message(STATUS "pir hardware version")
else()
    add_library(sealpir pir.h pir.cpp pir_client.h pir_client.cpp pir_server.h
            pir_server.cpp)
    message(STATUS "pir software version")
endif()

target_link_libraries(sealpir PUBLIC poseidon_shared)

add_executable(main main.cpp)
target_link_libraries(main sealpir)
message(STATUS "PIR build success")