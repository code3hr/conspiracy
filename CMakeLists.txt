cmake_minimum_required(VERSION 3.16)
project(cyxwiz VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror -pedantic)
endif()

# Options
option(CYXWIZ_BUILD_TESTS "Build tests" ON)
option(CYXWIZ_TRANSPORT_WIFI "Enable WiFi Direct transport" ON)
option(CYXWIZ_TRANSPORT_BLUETOOTH "Enable Bluetooth transport" ON)
option(CYXWIZ_TRANSPORT_LORA "Enable LoRa transport" ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Core library sources
set(CYXWIZ_SOURCES
    src/util/memory.c
    src/util/log.c
    src/transport/transport.c
)

# Transport drivers (conditional)
if(CYXWIZ_TRANSPORT_WIFI)
    list(APPEND CYXWIZ_SOURCES src/transport/wifi_direct.c)
    add_compile_definitions(CYXWIZ_HAS_WIFI=1)
endif()

if(CYXWIZ_TRANSPORT_BLUETOOTH)
    list(APPEND CYXWIZ_SOURCES src/transport/bluetooth.c)
    add_compile_definitions(CYXWIZ_HAS_BLUETOOTH=1)
endif()

if(CYXWIZ_TRANSPORT_LORA)
    list(APPEND CYXWIZ_SOURCES src/transport/lora.c)
    add_compile_definitions(CYXWIZ_HAS_LORA=1)
endif()

# Static library
add_library(cyxwiz STATIC ${CYXWIZ_SOURCES})
target_include_directories(cyxwiz PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Daemon executable
add_executable(cyxwizd daemon/main.c)
target_link_libraries(cyxwizd PRIVATE cyxwiz)

# Tests
if(CYXWIZ_BUILD_TESTS)
    enable_testing()

    add_executable(test_transport tests/test_transport.c)
    target_link_libraries(test_transport PRIVATE cyxwiz)
    add_test(NAME test_transport COMMAND test_transport)
endif()

# Install
install(TARGETS cyxwiz cyxwizd
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/cyxwiz DESTINATION include)
