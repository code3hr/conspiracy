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

# Disable crypto (if libsodium not available)
cmake -B build -DCYXWIZ_HAS_CRYPTO=OFF

# Disable tests
cmake -B build -DCYXWIZ_BUILD_TESTS=OFF
```

### Dependencies

- **libsodium** (required for crypto module) - Install via:
  - Windows: `vcpkg install libsodium` or download from https://libsodium.org
  - Linux: `apt install libsodium-dev`
  - macOS: `brew install libsodium`

## Code Structure

```
include/cyxwiz/       Public headers
  types.h             Error codes, node ID, message types, constants
  transport.h         Transport abstraction interface
  peer.h              Peer table and discovery protocol
  crypto.h            MPC crypto (secret sharing, encryption, MACs)
  memory.h            Secure memory (zeroing, constant-time compare)
  log.h               Logging

src/
  core/               Core protocol modules
    peer.c            Peer table management
    discovery.c       Peer discovery protocol
  transport/          Transport drivers
    transport.c       Transport manager (create/destroy)
    wifi_direct.c     WiFi Direct driver (stub)
    bluetooth.c       Bluetooth mesh driver (stub)
    lora.c            LoRa driver (stub)
  crypto/             SPDZ-based MPC crypto
    crypto.c          Context management
    primitives.c      libsodium wrappers (encrypt, hash, random)
    sharing.c         Secret sharing (additive + threshold)
    mac.c             Information-theoretic MACs
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

## Crypto Module (SPDZ-based MPC)

SPDZ protocol implementation for secure multi-party computation:

### Key Types
- `cyxwiz_share_t` - Secret share with MAC (49 bytes, fits in LoRa packets)
- `cyxwiz_crypto_ctx_t` - Crypto context (MAC keys, threshold config)

### Core Operations
```c
// Initialize libsodium
cyxwiz_crypto_init();

// Create 3-of-5 MPC context
cyxwiz_crypto_create(&ctx, 3, 5, my_party_id);

// Split secret into shares
cyxwiz_crypto_share_secret(ctx, secret, 32, shares, &num_shares);

// Reconstruct from threshold shares
cyxwiz_crypto_reconstruct_secret(ctx, shares, num_shares, secret_out, 32);

// Local operations (no communication)
cyxwiz_crypto_share_add(a, b, result);      // result = a + b
cyxwiz_crypto_share_scalar_mul(share, scalar, result);

// Verify share integrity
cyxwiz_crypto_verify_share(ctx, share);

// Symmetric encryption (XChaCha20-Poly1305)
cyxwiz_crypto_encrypt(plaintext, len, key, ciphertext, &ct_len);
cyxwiz_crypto_decrypt(ciphertext, len, key, plaintext, &pt_len);
```

### Constants
- `CYXWIZ_KEY_SIZE` = 32 (256-bit keys)
- `CYXWIZ_MAC_SIZE` = 16 (128-bit MACs)
- `CYXWIZ_DEFAULT_THRESHOLD` = 3
- `CYXWIZ_DEFAULT_PARTIES` = 5

## Peer Discovery Module

Manages peer discovery and connection state:

### Key Types
- `cyxwiz_peer_t` - Peer info (ID, state, transport, capabilities, RSSI, timestamps)
- `cyxwiz_peer_table_t` - Table of known peers (max 64)
- `cyxwiz_discovery_t` - Discovery protocol context

### Peer States
```c
CYXWIZ_PEER_STATE_UNKNOWN      // Initial state
CYXWIZ_PEER_STATE_DISCOVERED   // Found but not connected
CYXWIZ_PEER_STATE_CONNECTING   // Handshake in progress
CYXWIZ_PEER_STATE_CONNECTED    // Active connection
CYXWIZ_PEER_STATE_DISCONNECTING // Graceful disconnect
CYXWIZ_PEER_STATE_FAILED       // Connection failed
```

### Core Operations
```c
// Create peer table
cyxwiz_peer_table_create(&table);
cyxwiz_peer_table_set_callback(table, on_state_change, user_data);

// Peer management
cyxwiz_peer_table_add(table, &node_id, transport, rssi);
cyxwiz_peer_table_find(table, &node_id);
cyxwiz_peer_table_remove(table, &node_id);
cyxwiz_peer_table_set_state(table, &node_id, new_state);

// Discovery
cyxwiz_discovery_create(&discovery, peer_table, transport, &local_id);
cyxwiz_discovery_start(discovery);
cyxwiz_discovery_poll(discovery, current_time_ms);  // Call in main loop
cyxwiz_discovery_stop(discovery);
```

### Constants
- `CYXWIZ_MAX_PEERS` = 64
- `CYXWIZ_PEER_TIMEOUT_MS` = 30000 (30 seconds)
- `CYXWIZ_DISCOVERY_INTERVAL_MS` = 5000 (5 seconds)

### Discovery Protocol Messages
- `CYXWIZ_DISC_ANNOUNCE` - Broadcast "I'm here"
- `CYXWIZ_DISC_ANNOUNCE_ACK` - Response to announce
- `CYXWIZ_DISC_PING` / `CYXWIZ_DISC_PONG` - Keepalive
- `CYXWIZ_DISC_GOODBYE` - Graceful disconnect

All messages fit in 37 bytes or less (LoRa-compatible).

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
