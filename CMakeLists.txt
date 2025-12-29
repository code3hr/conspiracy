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
option(CYXWIZ_BUILD_FUZZ "Build fuzz testing targets (requires clang)" OFF)
option(CYXWIZ_ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan" OFF)
option(CYXWIZ_TRANSPORT_WIFI "Enable WiFi Direct transport" ON)
option(CYXWIZ_TRANSPORT_BLUETOOTH "Enable Bluetooth transport" ON)
option(CYXWIZ_TRANSPORT_LORA "Enable LoRa transport" ON)
option(CYXWIZ_TRANSPORT_UDP "Enable UDP/Internet transport" ON)
option(CYXWIZ_HAS_CRYPTO "Enable crypto module (requires libsodium)" ON)

# Sanitizers (ASan + UBSan)
if(CYXWIZ_ENABLE_SANITIZERS)
    if(NOT MSVC)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
        message(STATUS "Sanitizers enabled: AddressSanitizer, UndefinedBehaviorSanitizer")
    else()
        message(WARNING "Sanitizers not supported on MSVC, ignoring CYXWIZ_ENABLE_SANITIZERS")
    endif()
endif()

# Find libsodium
if(CYXWIZ_HAS_CRYPTO)
    # Try vcpkg first (find_package with CONFIG)
    find_package(unofficial-sodium QUIET CONFIG)
    if(unofficial-sodium_FOUND)
        set(SODIUM_FOUND TRUE)
        set(SODIUM_TARGET unofficial-sodium::sodium)
        message(STATUS "Found libsodium via vcpkg")
    endif()

    # Try pkg-config (Linux/macOS)
    if(NOT SODIUM_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(SODIUM QUIET libsodium)
            if(SODIUM_FOUND)
                set(SODIUM_TARGET ${SODIUM_LIBRARIES})
                # Add library directories to link path (needed for Homebrew on macOS)
                if(SODIUM_LIBRARY_DIRS)
                    link_directories(${SODIUM_LIBRARY_DIRS})
                endif()
            endif()
        endif()
    endif()

    # Manual fallback for Windows
    if(NOT SODIUM_FOUND)
        find_path(SODIUM_INCLUDE_DIR sodium.h
            PATHS
                "$ENV{SODIUM_ROOT}/include"
                "$ENV{PROGRAMFILES}/libsodium/include"
                "C:/libsodium/include"
                "C:/vcpkg/installed/x64-windows/include"
        )
        find_library(SODIUM_LIBRARY
            NAMES sodium libsodium
            PATHS
                "$ENV{SODIUM_ROOT}/lib"
                "$ENV{PROGRAMFILES}/libsodium/lib"
                "C:/libsodium/lib"
                "C:/vcpkg/installed/x64-windows/lib"
        )
        if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
            set(SODIUM_FOUND TRUE)
            set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
            set(SODIUM_TARGET ${SODIUM_LIBRARY})
        endif()
    endif()

    if(NOT SODIUM_FOUND)
        message(WARNING "libsodium not found, disabling crypto module")
        set(CYXWIZ_HAS_CRYPTO OFF)
    else()
        message(STATUS "Found libsodium: ${SODIUM_TARGET}")
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
    if(WIN32)
        # Enable C++ for Windows WiFi Direct wrapper
        enable_language(CXX)
        set(CMAKE_CXX_STANDARD 17)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        list(APPEND CYXWIZ_SOURCES src/transport/wifi_direct_win.cpp)
        # Link Windows networking libraries
        list(APPEND CYXWIZ_PLATFORM_LIBS iphlpapi windowsapp)
    endif()
endif()

if(CYXWIZ_TRANSPORT_BLUETOOTH)
    list(APPEND CYXWIZ_SOURCES src/transport/bluetooth.c)
    add_compile_definitions(CYXWIZ_HAS_BLUETOOTH=1)
    if(WIN32)
        # Enable C++ for Windows Bluetooth wrapper (if not already enabled by WiFi)
        if(NOT CYXWIZ_TRANSPORT_WIFI)
            enable_language(CXX)
            set(CMAKE_CXX_STANDARD 17)
            set(CMAKE_CXX_STANDARD_REQUIRED ON)
        endif()
        list(APPEND CYXWIZ_SOURCES src/transport/bluetooth_win.cpp)
        # Link Windows Bluetooth libraries
        list(APPEND CYXWIZ_PLATFORM_LIBS bthprops ws2_32)
    elseif(UNIX AND NOT APPLE)
        # Link BlueZ on Linux
        list(APPEND CYXWIZ_PLATFORM_LIBS bluetooth)
    endif()
endif()

if(CYXWIZ_TRANSPORT_LORA)
    list(APPEND CYXWIZ_SOURCES src/transport/lora.c)
    add_compile_definitions(CYXWIZ_HAS_LORA=1)
endif()

if(CYXWIZ_TRANSPORT_UDP)
    list(APPEND CYXWIZ_SOURCES src/transport/udp.c)
    add_compile_definitions(CYXWIZ_HAS_UDP=1)
    if(WIN32)
        # Link Winsock on Windows
        list(APPEND CYXWIZ_PLATFORM_LIBS ws2_32)
    endif()
endif()

# Pluggable transports (traffic obfuscation)
option(CYXWIZ_OBFUSCATION "Enable pluggable transports (TLS obfuscation)" ON)
if(CYXWIZ_OBFUSCATION)
    list(APPEND CYXWIZ_SOURCES src/transport/obfuscation.c)
    add_compile_definitions(CYXWIZ_HAS_OBFUSCATION=1)
endif()

# Core modules (peer discovery, routing, compute, consensus)
list(APPEND CYXWIZ_SOURCES
    src/core/peer.c
    src/core/discovery.c
    src/core/routing.c
    src/core/compute.c
    src/core/storage.c
    src/core/consensus.c
)
add_compile_definitions(CYXWIZ_HAS_COMPUTE=1)
add_compile_definitions(CYXWIZ_HAS_STORAGE=1)
add_compile_definitions(CYXWIZ_HAS_CONSENSUS=1)

# Onion routing (requires crypto)
if(CYXWIZ_HAS_CRYPTO)
    list(APPEND CYXWIZ_SOURCES
        src/core/onion.c
    )
endif()

# Crypto module (conditional on libsodium)
if(CYXWIZ_HAS_CRYPTO)
    list(APPEND CYXWIZ_SOURCES
        src/crypto/crypto.c
        src/crypto/primitives.c
        src/crypto/sharing.c
        src/crypto/mac.c
        src/crypto/zkp.c
        src/crypto/privacy.c
        src/crypto/credentials.c
    )
    add_compile_definitions(CYXWIZ_HAS_CRYPTO=1)
    add_compile_definitions(CYXWIZ_HAS_PRIVACY=1)
endif()

# Static library
add_library(cyxwiz STATIC ${CYXWIZ_SOURCES})
target_include_directories(cyxwiz PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Link libsodium if crypto is enabled
if(CYXWIZ_HAS_CRYPTO)
    if(SODIUM_INCLUDE_DIRS)
        target_include_directories(cyxwiz PUBLIC ${SODIUM_INCLUDE_DIRS})
    endif()
    target_link_libraries(cyxwiz PUBLIC ${SODIUM_TARGET})
    # Use static libsodium on Windows
    if(WIN32)
        target_compile_definitions(cyxwiz PUBLIC SODIUM_STATIC=1)
    endif()
endif()

# Link platform-specific libraries (e.g., Winsock for UDP on Windows)
if(CYXWIZ_PLATFORM_LIBS)
    target_link_libraries(cyxwiz PUBLIC ${CYXWIZ_PLATFORM_LIBS})
endif()

# Daemon executable
add_executable(cyxwizd daemon/main.c)
target_link_libraries(cyxwizd PRIVATE cyxwiz)

# Bootstrap server (standalone tool)
if(CYXWIZ_TRANSPORT_UDP)
    add_executable(cyxwiz-bootstrap tools/bootstrap.c)
    if(WIN32)
        target_link_libraries(cyxwiz-bootstrap PRIVATE ws2_32)
    endif()
endif()

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

        add_executable(test_onion tests/test_onion.c)
        target_link_libraries(test_onion PRIVATE cyxwiz)
        add_test(NAME test_onion COMMAND test_onion)

        add_executable(test_zkp tests/test_zkp.c)
        target_link_libraries(test_zkp PRIVATE cyxwiz)
        add_test(NAME test_zkp COMMAND test_zkp)
    endif()

    add_executable(test_peer tests/test_peer.c)
    target_link_libraries(test_peer PRIVATE cyxwiz)
    add_test(NAME test_peer COMMAND test_peer)

    add_executable(test_routing tests/test_routing.c)
    target_link_libraries(test_routing PRIVATE cyxwiz)
    add_test(NAME test_routing COMMAND test_routing)

    add_executable(test_routing_multihop tests/test_routing_multihop.c)
    target_link_libraries(test_routing_multihop PRIVATE cyxwiz)
    add_test(NAME test_routing_multihop COMMAND test_routing_multihop)

    if(CYXWIZ_TRANSPORT_UDP)
        add_executable(test_udp tests/test_udp.c)
        target_link_libraries(test_udp PRIVATE cyxwiz)
        add_test(NAME test_udp COMMAND test_udp)
    endif()

    # Compute tests (requires crypto for MAC verification)
    if(CYXWIZ_HAS_CRYPTO)
        add_executable(test_compute tests/test_compute.c)
        target_link_libraries(test_compute PRIVATE cyxwiz)
        add_test(NAME test_compute COMMAND test_compute)

        add_executable(test_storage tests/test_storage.c)
        target_link_libraries(test_storage PRIVATE cyxwiz)
        add_test(NAME test_storage COMMAND test_storage)

        add_executable(test_consensus tests/test_consensus.c)
        target_link_libraries(test_consensus PRIVATE cyxwiz)
        add_test(NAME test_consensus COMMAND test_consensus)

        add_executable(test_privacy tests/test_privacy.c)
        target_link_libraries(test_privacy PRIVATE cyxwiz)
        add_test(NAME test_privacy COMMAND test_privacy)

        add_executable(test_anon_voting_e2e tests/test_anon_voting_e2e.c)
        target_link_libraries(test_anon_voting_e2e PRIVATE cyxwiz)
        add_test(NAME test_anon_voting_e2e COMMAND test_anon_voting_e2e)

        add_executable(test_anon_msg_e2e tests/test_anon_msg_e2e.c)
        target_link_libraries(test_anon_msg_e2e PRIVATE cyxwiz)
        add_test(NAME test_anon_msg_e2e COMMAND test_anon_msg_e2e)
    endif()
endif()

# Fuzz testing targets (requires clang with libFuzzer)
if(CYXWIZ_BUILD_FUZZ AND CYXWIZ_HAS_CRYPTO)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz_onion tests/fuzz/fuzz_onion.c)
        target_link_libraries(fuzz_onion PRIVATE cyxwiz)
        target_compile_options(fuzz_onion PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_onion PRIVATE -fsanitize=fuzzer,address,undefined)

        add_executable(fuzz_routing tests/fuzz/fuzz_routing.c)
        target_link_libraries(fuzz_routing PRIVATE cyxwiz)
        target_compile_options(fuzz_routing PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_routing PRIVATE -fsanitize=fuzzer,address,undefined)

        message(STATUS "Fuzz testing targets enabled")
    else()
        message(WARNING "Fuzz targets require Clang compiler, skipping")
    endif()
endif()

# Install
install(TARGETS cyxwiz cyxwizd
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/cyxwiz DESTINATION include)
