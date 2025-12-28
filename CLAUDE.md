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

# Run daemon (interactive mode)
./build/cyxwizd

# Run daemon (batch mode for scripting)
./build/cyxwizd --batch < commands.txt
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
  compute.h           Compute job marketplace
  storage.h           Distributed storage (K-of-N threshold)
  consensus.h         PoUW consensus with validators
  zkp.h               Zero-knowledge proofs
  privacy.h           Anonymous credentials
  memory.h            Secure memory (zeroing, constant-time compare)
  log.h               Logging

src/
  core/               Core protocol modules
    peer.c            Peer table management
    discovery.c       Peer discovery protocol (with X25519 key exchange)
    routing.c         Mesh routing implementation
    onion.c           Onion routing implementation
    compute.c         Distributed compute job marketplace
    storage.c         K-of-N threshold storage (CyxCloud)
    consensus.c       PoUW consensus with work credits
  transport/          Transport drivers
    transport.c       Transport manager (create/destroy)
    udp.c             UDP/Internet with NAT traversal (STUN)
    wifi_direct.c     WiFi Direct (Linux wpa_supplicant)
    wifi_direct_win.cpp  WiFi Direct Windows wrapper
    bluetooth.c       Bluetooth (Linux BlueZ L2CAP)
    bluetooth_win.cpp Bluetooth Windows wrapper (RFCOMM)
    lora.c            LoRa (Serial AT + Linux SPI for SX127x)
  crypto/             SPDZ-based MPC crypto
    crypto.c          Context management
    primitives.c      libsodium wrappers (encrypt, hash, random)
    sharing.c         Secret sharing (additive + threshold)
    mac.c             Information-theoretic MACs
    zkp.c             Zero-knowledge proofs (Schnorr)
    privacy.c         Anonymous credentials
  util/
    memory.c          Secure memory implementation
    log.c             Logging implementation

daemon/main.c         Node daemon with interactive commands
tests/                Unit tests (14 test suites)
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
- `CYXWIZ_DISC_GOODBYE` - Graceful disconnect (sent to all peers on stop)

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

## Compute Module

Distributed job marketplace for offloading computation to worker nodes.

### Key Types
- `cyxwiz_compute_ctx_t` - Compute context
- `cyxwiz_job_t` - Job entry (ID, type, state, payload, result)
- `cyxwiz_job_id_t` - 8-byte job identifier

### Job Types
```c
CYXWIZ_JOB_TYPE_HASH      // Compute BLAKE2b hash
CYXWIZ_JOB_TYPE_ENCRYPT   // Encrypt data
CYXWIZ_JOB_TYPE_DECRYPT   // Decrypt data
CYXWIZ_JOB_TYPE_VERIFY    // Verify signature/MAC
CYXWIZ_JOB_TYPE_CUSTOM    // Custom job (handler decides)
```

### Core Operations
```c
// Create compute context
cyxwiz_compute_create(&ctx, router, peer_table, crypto_ctx, &local_id);

// Enable worker mode (accept jobs)
cyxwiz_compute_enable_worker(ctx, max_concurrent);

// Set callbacks
cyxwiz_compute_set_complete_callback(ctx, on_complete, user_data);
cyxwiz_compute_set_execute_callback(ctx, on_execute, user_data);

// Submit job to worker
cyxwiz_compute_submit(ctx, &worker_id, job_type, payload, len, &job_id);

// Anonymous job submission (worker can't identify submitter)
cyxwiz_compute_submit_anonymous(ctx, &worker_id, job_type, payload, len, &job_id);
```

### Chunked Results
Results larger than 64 bytes are automatically chunked:
- Single packet: results ≤64 bytes sent inline
- Chunked: results >64 bytes split into 48-byte chunks (max 16 chunks = 768 bytes)
- MAC covers complete assembled result for integrity verification

### Constants
- `CYXWIZ_JOB_MAX_PAYLOAD` = 64 (single-packet payload)
- `CYXWIZ_JOB_CHUNK_SIZE` = 48 (bytes per chunk)
- `CYXWIZ_JOB_MAX_CHUNKS` = 16
- `CYXWIZ_JOB_MAX_TOTAL_PAYLOAD` = 768 (max chunked payload)
- `CYXWIZ_MAX_ACTIVE_JOBS` = 16

## Consensus Module

Proof of Useful Work (PoUW) consensus with stake-weighted validation.

### Key Types
- `cyxwiz_consensus_ctx_t` - Consensus context
- `cyxwiz_validator_t` - Validator info (stake, state, work credits)
- `cyxwiz_vote_t` - Block vote with signature

### Validator States
```c
CYXWIZ_VALIDATOR_ACTIVE    // Participating in consensus
CYXWIZ_VALIDATOR_INACTIVE  // Not participating
CYXWIZ_VALIDATOR_SLASHED   // Slashed for misbehavior
```

### Slashing
Validators are slashed for equivocation (voting for conflicting blocks):
```c
// Slash reasons
CYXWIZ_SLASH_EQUIVOCATION  // Conflicting votes in same round
CYXWIZ_SLASH_INACTIVITY    // Extended inactivity
CYXWIZ_SLASH_INVALID_BLOCK // Proposed invalid block

// When equivocation detected, validator is:
// 1. Marked as SLASHED
// 2. Loses stake
// 3. Slash report broadcast to network with evidence hash
```

### Core Operations
```c
// Create consensus context
cyxwiz_consensus_create(&ctx, router, crypto_ctx, &local_id);

// Register as validator
cyxwiz_consensus_register_validator(ctx, stake_amount);

// Submit work proof
cyxwiz_consensus_submit_work(ctx, work_proof, proof_len);

// Vote on block
cyxwiz_consensus_vote(ctx, &block_hash, approve);
```

## Privacy Module

Anonymous credentials, commitments, and privacy-preserving proofs.

### Key Types
- `cyxwiz_privacy_ctx_t` - Privacy context
- `cyxwiz_credential_t` - Anonymous credential
- `cyxwiz_commitment_t` - Pedersen commitment

### Message Types (0x70-0x7F)
```c
CYXWIZ_MSG_PEDERSEN_COMMIT     // Pedersen commitment
CYXWIZ_MSG_PEDERSEN_OPEN       // Commitment opening
CYXWIZ_MSG_RANGE_PROOF         // Range proof
CYXWIZ_MSG_CRED_ISSUE_REQ      // Credential issuance request
CYXWIZ_MSG_CRED_ISSUE_RESP     // Credential issuance response
CYXWIZ_MSG_CRED_SHOW           // Show credential
CYXWIZ_MSG_CRED_VERIFY         // Verify credential
CYXWIZ_MSG_ANON_VOTE           // Anonymous vote
CYXWIZ_MSG_SERVICE_TOKEN_REQ   // Service token request
CYXWIZ_MSG_SERVICE_TOKEN       // Service token
CYXWIZ_MSG_SERVICE_TOKEN_USE   // Use service token
CYXWIZ_MSG_REPUTATION_PROOF    // Reputation proof
```

### Core Operations
```c
// Create privacy context
cyxwiz_privacy_create(&ctx, router, &identity, &local_id);

// Set callbacks
cyxwiz_privacy_set_credential_callback(ctx, on_credential, user_data);
cyxwiz_privacy_set_vote_callback(ctx, on_vote, user_data);

// Handle incoming privacy messages
cyxwiz_privacy_handle_message(ctx, &from, data, len);

// Poll for timeouts
cyxwiz_privacy_poll(ctx, current_time_ms);
```

## Architecture Layers

1. **Network Layer** - Encrypted P2P mesh with onion routing
2. **Consensus Layer** - Proof of Useful Work + stake-weighted validation
3. **Protocol Layer** - Compute, Storage, Privacy protocols
4. **Application Layer** - UIs, wallets, SDKs

## Daemon Commands

The daemon (`cyxwizd`) provides interactive commands:

```bash
# Information
/help                    # Show all commands
/status                  # Node status (ID, peers, validators)
/peers                   # List connected peers

# Messaging
/send <peer_id> <msg>    # Send direct message
/anon <peer_id> <msg>    # Send via onion routing

# Storage (CyxCloud)
/store <data>            # Store data (returns 16-char hex ID)
/retrieve <storage_id>   # Retrieve by storage ID
/storage                 # Storage status

# Compute
/compute <data>          # Submit job to worker
/jobs                    # List active jobs

# Consensus
/validators              # Validator status
/credits                 # Work credit balance

# Control
/quit                    # Shutdown
```

### Batch Mode

For scripting/testing, use `--batch` flag:
```bash
echo -e "/status\n/peers\n/quit" | ./cyxwizd --batch
```

## Transport Drivers

### WiFi Direct (`wifi_direct.c`)
- Linux: wpa_supplicant control interface (`/var/run/wpa_supplicant`)
- Windows: WinRT wrapper (`wifi_direct_win.cpp`)
- P2P group formation, UDP data socket on port 19850

### Bluetooth (`bluetooth.c`)
- Linux: BlueZ L2CAP sockets
- Windows: RFCOMM via Winsock (`bluetooth_win.cpp`)
- Device discovery, connection management

### LoRa (`lora.c`)
- Serial: AT command modules (RYLR890/RYLR896)
- SPI: Direct SX127x register access (Linux)
- CSMA/CA collision avoidance
- Environment variables: `CYXWIZ_LORA_SERIAL`, `CYXWIZ_LORA_SPI`, `CYXWIZ_LORA_FREQ`

### UDP (`udp.c`)
- NAT traversal via STUN (Google, Cloudflare servers)
- UDP hole punching for peer-to-peer
- Bootstrap server for peer discovery

## Security Considerations

- Use `cyxwiz_secure_zero()` for clearing sensitive data
- Use `cyxwiz_secure_compare()` for constant-time comparisons (prevents timing attacks)
- Use `cyxwiz_free(ptr, size)` which zeros before freeing
- All packet sizes constrained to 250 bytes (LoRa limit)
