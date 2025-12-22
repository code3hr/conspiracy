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
option(CYXWIZ_HAS_CRYPTO "Enable crypto module (requires libsodium)" ON)

# Find libsodium
if(CYXWIZ_HAS_CRYPTO)
    # Try pkg-config first (Linux/macOS)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM QUIET libsodium)
    endif()

    # If pkg-config didn't find it, try find_package (vcpkg, manual install)
    if(NOT SODIUM_FOUND)
        find_package(unofficial-sodium QUIET CONFIG)
        if(unofficial-sodium_FOUND)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_LIBRARIES unofficial-sodium::sodium)
        endif()
    endif()

    # Manual fallback for Windows
    if(NOT SODIUM_FOUND)
        find_path(SODIUM_INCLUDE_DIR sodium.h
            PATHS
                "$ENV{SODIUM_ROOT}/include"
                "$ENV{PROGRAMFILES}/libsodium/include"
                "C:/libsodium/include"
        )
        find_library(SODIUM_LIBRARY
            NAMES sodium libsodium
            PATHS
                "$ENV{SODIUM_ROOT}/lib"
                "$ENV{PROGRAMFILES}/libsodium/lib"
                "C:/libsodium/lib"
        )
        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
        endif()
    endif()

    if(NOT SODIUM_FOUND)
        message(WARNING "libsodium not found, disabling crypto module")
        set(CYXWIZ_HAS_CRYPTO OFF)
    else()
        message(STATUS "Found libsodium: ${SODIUM_LIBRARIES}")
    endif()
endif()

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

# Core modules (peer discovery, routing)
list(APPEND CYXWIZ_SOURCES
    src/core/peer.c
    src/core/discovery.c
)

# Crypto module (conditional on libsodium)
if(CYXWIZ_HAS_CRYPTO)
    list(APPEND CYXWIZ_SOURCES
        src/crypto/crypto.c
        src/crypto/primitives.c
        src/crypto/sharing.c
        src/crypto/mac.c
    )
    add_compile_definitions(CYXWIZ_HAS_CRYPTO=1)
endif()

# Static library
add_library(cyxwiz STATIC ${CYXWIZ_SOURCES})
target_include_directories(cyxwiz PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Link libsodium if crypto is enabled
if(CYXWIZ_HAS_CRYPTO)
    if(SODIUM_INCLUDE_DIRS)
        target_include_directories(cyxwiz PUBLIC ${SODIUM_INCLUDE_DIRS})
    endif()
    target_link_libraries(cyxwiz PUBLIC ${SODIUM_LIBRARIES})
endif()

# Daemon executable
add_executable(cyxwizd daemon/main.c)
target_link_libraries(cyxwizd PRIVATE cyxwiz)

# Tests
if(CYXWIZ_BUILD_TESTS)
    enable_testing()

    add_executable(test_transport tests/test_transport.c)
    target_link_libraries(test_transport PRIVATE cyxwiz)
    add_test(NAME test_transport COMMAND test_transport)

    if(CYXWIZ_HAS_CRYPTO)
        add_executable(test_crypto tests/test_crypto.c)
        target_link_libraries(test_crypto PRIVATE cyxwiz)
        add_test(NAME test_crypto COMMAND test_crypto)
    endif()

    add_executable(test_peer tests/test_peer.c)
    target_link_libraries(test_peer PRIVATE cyxwiz)
    add_test(NAME test_peer COMMAND test_peer)
endif()

# Install
install(TARGETS cyxwiz cyxwizd
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/cyxwiz DESTINATION include)
