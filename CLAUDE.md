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
  routing.h           Mesh routing (route discovery, source routing)
  onion.h             Onion routing (layered encryption, circuits)
  crypto.h            MPC crypto (secret sharing, encryption, MACs)
  memory.h            Secure memory (zeroing, constant-time compare)
  log.h               Logging

src/
  core/               Core protocol modules
    peer.c            Peer table management
    discovery.c       Peer discovery protocol (with X25519 key exchange)
    routing.c         Mesh routing implementation
    onion.c           Onion routing implementation
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

## Routing Module

Hybrid mesh routing with on-demand route discovery and source routing:

### Key Types
- `cyxwiz_router_t` - Router context
- `cyxwiz_route_t` - Cached route (destination, hops, latency)
- `cyxwiz_route_req_t` - Route request message (broadcast flood)
- `cyxwiz_route_reply_t` - Route reply message (unicast back)
- `cyxwiz_routed_data_t` - Data packet with source route header

### Routing Algorithm
1. **Direct peer check** - If destination is a direct neighbor, send directly
2. **Cache lookup** - Use cached route if available and not expired
3. **Route discovery** - Broadcast ROUTE_REQ, destination replies with ROUTE_REPLY
4. **Source routing** - Sender embeds full path in packet header

### Core Operations
```c
// Create router
cyxwiz_router_create(&router, peer_table, transport, &local_id);
cyxwiz_router_set_callback(router, on_data_received, user_data);

// Lifecycle
cyxwiz_router_start(router);
cyxwiz_router_poll(router, current_time_ms);  // Call in main loop
cyxwiz_router_stop(router);

// Sending (discovers route if needed, queues while waiting)
cyxwiz_router_send(router, &destination, data, len);

// Route info
cyxwiz_router_has_route(router, &destination);
cyxwiz_router_get_route(router, &destination);
cyxwiz_router_invalidate_route(router, &destination);
```

### Constants
- `CYXWIZ_MAX_HOPS` = 5 (fits in 250-byte LoRa packet)
- `CYXWIZ_MAX_ROUTES` = 32 (cached routes)
- `CYXWIZ_MAX_PENDING` = 8 (messages awaiting route discovery)
- `CYXWIZ_MAX_ROUTED_PAYLOAD` = 48 bytes
- `CYXWIZ_ROUTE_TIMEOUT_MS` = 60000 (route cache expires after 60s)
- `CYXWIZ_ROUTE_REQ_TIMEOUT_MS` = 5000 (route discovery timeout)

### Routing Messages (0x20-0x2F)
- `CYXWIZ_MSG_ROUTE_REQ` (0x20) - Route request (broadcast)
- `CYXWIZ_MSG_ROUTE_REPLY` (0x21) - Route reply (unicast)
- `CYXWIZ_MSG_ROUTE_DATA` (0x22) - Routed data packet
- `CYXWIZ_MSG_ROUTE_ERROR` (0x23) - Route error notification
- `CYXWIZ_MSG_ONION_DATA` (0x24) - Onion-encrypted data packet

All messages fit within 250-byte LoRa limit.

## Onion Routing Module

Layered encryption for anonymous routing. Each hop only knows the previous and next hop, not the full path.

### Key Types
- `cyxwiz_onion_ctx_t` - Onion context (X25519 keypair, circuits, peer keys)
- `cyxwiz_circuit_t` - Onion circuit (hop list, per-hop keys)
- `cyxwiz_peer_key_t` - Shared secret with peer (from DH exchange)
- `cyxwiz_onion_data_t` - Onion-routed data packet
- `cyxwiz_onion_layer_t` - Decrypted layer (next_hop + inner data)

### How It Works
1. **Key Exchange** - Discovery announces include X25519 public keys
2. **Shared Secrets** - Each peer computes DH shared secret
3. **Per-Hop Keys** - Derived from shared secret with domain separation
4. **Onion Wrapping** - Sender encrypts layers from inside out
5. **Onion Peeling** - Each hop decrypts its layer, sees only next hop

### Payload Capacity
Due to XChaCha20-Poly1305 overhead (40 bytes/layer) + node ID (32 bytes):
- 1-hop: 173 bytes
- 2-hop: 101 bytes
- 3-hop: 29 bytes (max hops due to 250-byte LoRa limit)

### Core Operations
```c
// Create onion context (generates X25519 keypair)
cyxwiz_onion_create(&ctx, router, &local_id);

// Get public key for announcements
cyxwiz_onion_get_pubkey(ctx, pubkey);

// Add peer's public key (computes shared secret)
cyxwiz_onion_add_peer_key(ctx, &peer_id, peer_pubkey);

// Build circuit through hops
cyxwiz_onion_build_circuit(ctx, hops, hop_count, &circuit);

// Send via circuit
cyxwiz_onion_send(ctx, circuit, data, len);

// Set delivery callback
cyxwiz_onion_set_callback(ctx, on_delivery, user_data);

// Poll (expires old circuits)
cyxwiz_onion_poll(ctx, current_time_ms);

// Low-level wrap/unwrap
cyxwiz_onion_wrap(payload, len, hops, keys, hop_count, out, &out_len);
cyxwiz_onion_unwrap(onion, len, key, &next_hop, inner, &inner_len);
```

### Constants
- `CYXWIZ_MAX_ONION_HOPS` = 3
- `CYXWIZ_ONION_OVERHEAD` = 40 (nonce 24 + auth tag 16)
- `CYXWIZ_PUBKEY_SIZE` = 32
- `CYXWIZ_MAX_CIRCUITS` = 16
- `CYXWIZ_CIRCUIT_TIMEOUT_MS` = 60000

### Privacy Properties
| Property | With Onion | Without |
|----------|------------|---------|
| Path visibility | Hidden | Full path visible |
| Source anonymity | Yes (with circuit) | No |
| Content privacy | End-to-end encrypted | Plaintext |

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
