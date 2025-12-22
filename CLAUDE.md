# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CyxWiz Protocol is a decentralized mesh network protocol for anonymous, privacy-first computing. Written in C for maximum portability (phones to servers) and security control.

Core philosophy: "Own Nothing. Access Everything. Leave No Trace."

Key technical decisions:
- **MPC (Multi-Party Computation)** for encryption - compute on encrypted data, keys distributed across nodes
- **Complete mesh network replacement** - not an overlay on internet, direct device-to-device
- **Multi-transport**: WiFi Direct, Bluetooth Mesh, LoRa (all supported, protocol-agnostic)
- **LoRa-constrained design**: 250-byte max packet size (if it works on LoRa, it works everywhere)

## Build Commands

```bash
# Configure (Debug build)
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Configure (Release build)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build

# Run tests
ctest --test-dir build

# Run a single test
./build/test_transport

# Run daemon
./build/cyxwizd
```

### Build Options

```bash
# Disable specific transports
cmake -B build -DCYXWIZ_TRANSPORT_WIFI=OFF
cmake -B build -DCYXWIZ_TRANSPORT_BLUETOOTH=OFF
cmake -B build -DCYXWIZ_TRANSPORT_LORA=OFF

# Disable tests
cmake -B build -DCYXWIZ_BUILD_TESTS=OFF
```

## Code Structure

```
include/cyxwiz/       Public headers
  types.h             Error codes, node ID, message types, constants
  transport.h         Transport abstraction interface
  memory.h            Secure memory (zeroing, constant-time compare)
  log.h               Logging

src/
  transport/          Transport drivers
    transport.c       Transport manager (create/destroy)
    wifi_direct.c     WiFi Direct driver (stub)
    bluetooth.c       Bluetooth mesh driver (stub)
    lora.c            LoRa driver (stub)
  util/
    memory.c          Secure memory implementation
    log.c             Logging implementation

daemon/main.c         Node daemon entry point
tests/                Unit tests
```

## Transport Abstraction

All transports implement `cyxwiz_transport_ops_t`:
- `init` / `shutdown`
- `send` / `poll`
- `discover` / `stop_discover`
- `max_packet_size` - critical for LoRa compatibility

Protocol layer calls these without knowing underlying transport.

## Architecture Layers

1. **Network Layer** - Encrypted P2P mesh with onion routing
2. **Consensus Layer** - Proof of Useful Work + stake-weighted validation
3. **Protocol Layer** - Compute, Storage, Privacy protocols
4. **Application Layer** - UIs, wallets, SDKs

## Security Considerations

- Use `cyxwiz_secure_zero()` for clearing sensitive data
- Use `cyxwiz_secure_compare()` for constant-time comparisons (prevents timing attacks)
- Use `cyxwiz_free(ptr, size)` which zeros before freeing
- All packet sizes constrained to 250 bytes (LoRa limit)
