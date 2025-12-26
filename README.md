# CyxWiz Protocol
## WE OWN NOTHING
**The Decentralized Compute Protocol for a Truly Free Internet**

```
Own Nothing. Access Everything. Leave No Trace.
You Don't Even Exist.
```

---

## Vision

The future is scary. Surveillance capitalism tracks every click. Governments monitor every message. Big Tech owns your data, your identity, your digital soul.

**What if we built our own internet?**

CyxWiz Protocol is the answer. A decentralized mesh network where:
- **Everyone owns a piece** - No central servers, no gatekeepers
- **Everyone has something to say** - Censorship-resistant by design
- **No footprint, no trace** - True anonymity, not just privacy theater
- **You don't even exist** - No accounts, no identity, no tracking

### The Problem We're Solving

```
You buy a phone        → Tracked from purchase
You create an account  → Identity logged forever
You browse the web     → Every click recorded
You send a message     → Stored, analyzed, sold
You throw the phone    → Your data lives forever
```

**You own the device, but they own YOU.**

### Our Solution

Rather than buy a phone, use it once, and throw it away, you could just rent compute on CyxWiz Protocol. Stay anonymous. Gain your privacy and data back. Not controlled by any government or corporation. Being truly digital fingerprint FREE.

Like a hotel - you check in, use what you need, check out. No trace you were ever there.

---

## Technical Architecture

### Network Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                     CYXWIZ PROTOCOL NETWORK                     │
│                                                                 │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    │
│   │ Mobile  │    │Embedded │    │ Desktop │    │ Server  │    │
│   │ Phones  │    │   IoT   │    │   PCs   │    │  GPUs   │    │
│   └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘    │
│        │              │              │              │          │
│        └──────────────┴──────────────┴──────────────┘          │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│   ┌─────┴─────┐    ┌──────┴──────┐    ┌─────┴─────┐          │
│   │  COMPUTE  │    │   STORAGE   │    │  PRIVACY  │          │
│   │   LAYER   │    │  (CyxCloud) │    │   LAYER   │          │
│   └───────────┘    └─────────────┘    └───────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Protocol Stack

| Layer | Description |
|-------|-------------|
| **Application** | User interfaces, wallets, dApps, SDKs |
| **Protocol** | Compute, Storage, Privacy protocols |
| **Consensus** | Proof of Useful Work + stake-weighted validation |
| **Network** | Encrypted P2P mesh with onion routing |
| **Transport** | WiFi Direct, Bluetooth Mesh, LoRa |

### Multi-Transport Design

CyxWiz works over multiple physical transports - if internet infrastructure fails, the network continues:

| Transport | Range | Use Case |
|-----------|-------|----------|
| **UDP/Internet** | Global | Internet P2P with NAT traversal |
| **WiFi Direct** | ~250m | High-bandwidth local mesh |
| **Bluetooth Mesh** | ~100m | Urban density, low power |
| **LoRa** | ~10km | Rural areas, emergency networks |

The protocol is designed for LoRa's constraints (250-byte packets), ensuring it works everywhere. The UDP transport enables worldwide connectivity with STUN-based NAT traversal and bootstrap servers for peer discovery.

### What is MPC (Multi-Party Computation)?

MPC lets multiple parties compute on data **without anyone seeing the actual data**.

**Simple Example:** 5 people want to calculate their average salary without revealing individual salaries:

```
❌ Traditional: Everyone shares salary → Privacy gone

✅ MPC way:
   1. Each person splits salary into 5 random pieces
   2. Pieces distributed (each person gets 1 piece from everyone)
   3. Everyone computes on their pieces
   4. Combine results → Average revealed, individual salaries stay secret
```

**In CyxWiz:**

```
Your secret data
       │
       ▼
┌──────────────────────────────────────┐
│     Split into 5 encrypted shares    │
└──────────────────────────────────────┘
       │
   ┌───┴───┬───────┬───────┬───────┐
   ▼       ▼       ▼       ▼       ▼
┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐
│Node1│ │Node2│ │Node3│ │Node4│ │Node5│  ← Each sees random garbage
└─────┘ └─────┘ └─────┘ └─────┘ └─────┘
   │       │       │       │       │
   └───────┴───────┴───────┴───────┘
                   │
                   ▼
         Combine 3-of-5 shares → Only YOU can reconstruct
```

| Without MPC | With MPC |
|-------------|----------|
| Cloud sees your data | Cloud sees encrypted garbage |
| One hack = all leaked | Need to hack 3+ nodes |
| Trust the server | Trust no one |

### SPDZ Protocol

We use SPDZ (pronounced "Speedz"), an MPC protocol that provides:
- **Keys are never in one place** - Split across multiple nodes
- **Compute on encrypted data** - Nodes can't see what they're processing
- **Threshold security** - Need 3-of-5 nodes to decrypt (configurable)
- **Malicious adversary resistance** - MACs detect tampering

```
┌─────────────────────────────────────────────────────┐
│                  PRIVACY ARCHITECTURE               │
├─────────────────────────────────────────────────────┤
│  Onion Routing      → Multiple encrypted layers     │
│  Zero-Knowledge     → Prove without revealing       │
│  Encrypted Compute  → End-to-end, always           │
│  No Logging         → Nodes can't track users       │
│                                                     │
│  Result: TRUE ANONYMITY                            │
└─────────────────────────────────────────────────────┘
```

---

## Getting Started

### Prerequisites

- **CMake** 3.16+
- **C compiler** (GCC, Clang, or MSVC)
- **libsodium** (for crypto module)

### Installing Dependencies

**Windows:**
```bash
# Using vcpkg
vcpkg install libsodium

# Or download from https://libsodium.org
# Set SODIUM_ROOT environment variable to installation path
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install build-essential cmake libsodium-dev
```

**macOS:**
```bash
brew install cmake libsodium
```

### Building

```bash
# Clone the repository
git clone https://github.com/code3hr/conspiracy.git
cd conspiracy

# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build

# Run tests
ctest --test-dir build

# Run the node daemon
./build/cyxwizd          # Linux/macOS
.\build\Debug\cyxwizd    # Windows
```

### Build Options

```bash
# Disable specific transports
cmake -B build -DCYXWIZ_TRANSPORT_WIFI=OFF
cmake -B build -DCYXWIZ_TRANSPORT_BLUETOOTH=OFF
cmake -B build -DCYXWIZ_TRANSPORT_LORA=OFF

# Disable crypto (if libsodium unavailable)
cmake -B build -DCYXWIZ_HAS_CRYPTO=OFF

# Disable tests
cmake -B build -DCYXWIZ_BUILD_TESTS=OFF
```

### Running a Node

**Single node (local testing):**
```bash
./build/cyxwizd          # Linux/macOS
.uild\Release\cyxwizd  # Windows
```

**Multi-node network with bootstrap server:**
```bash
# Terminal 1: Start bootstrap server for peer discovery
./build/cyxwiz-bootstrap 9999

# Terminal 2: Start first daemon
CYXWIZ_BOOTSTRAP=127.0.0.1:9999 ./build/cyxwizd

# Terminal 3: Start second daemon
CYXWIZ_BOOTSTRAP=127.0.0.1:9999 ./build/cyxwizd
```

**Windows (PowerShell):**
```powershell
# Terminal 1
.uild\Release\cyxwiz-bootstrap.exe 9999

# Terminal 2
$env:CYXWIZ_BOOTSTRAP="127.0.0.1:9999"; .uild\Release\cyxwizd.exe

# Terminal 3
$env:CYXWIZ_BOOTSTRAP="127.0.0.1:9999"; .uild\Release\cyxwizd.exe
```

Output:
```
  ██████╗██╗   ██╗██╗  ██╗██╗    ██╗██╗███████╗
 ██╔════╝╚██╗ ██╔╝╚██╗██╔╝██║    ██║██║╚══███╔╝
 ██║      ╚████╔╝  ╚███╔╝ ██║ █╗ ██║██║  ███╔╝
 ██║       ╚██╔╝   ██╔██╗ ██║███╗██║██║ ███╔╝
 ╚██████╗   ██║   ██╔╝ ██╗╚███╔███╔╝██║███████╗
  ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚══════╝

 Own Nothing. Access Everything. Leave No Trace.
 Version 0.1.0

[INFO] Starting CyxWiz node daemon...
[INFO] Crypto subsystem initialized (libsodium 1.0.20)
[INFO] Local node ID: 7f6dfc16f02c56f1...
[INFO] UDP transport bound to port 49229
[INFO] Discovery started
[INFO] Router started
[INFO] Onion routing enabled
[INFO] Compute protocol enabled (worker mode)
[INFO] Storage protocol enabled (provider mode)
[INFO] Consensus protocol enabled (validator mode)
[INFO] Node running. Press Ctrl+C to stop.

# When peers connect:
[INFO] Peer 6932079b1d45d9b5... state: unknown -> discovered
[INFO] Peer 6932079b1d45d9b5... state: discovered -> connected
[INFO] Registered new validator (total: 1)
[INFO] Validator registration confirmed

# Consensus voting (automatic test after 30s with 2+ validators):
[INFO] Started job validation round (committee size: 2)
[INFO] Consensus reached: VALID (2/2 votes)
```

### Quick Start: Using the Library

**1. Initialize a Node**
```c
#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/onion.h"
#include "cyxwiz/crypto.h"

// Initialize crypto
cyxwiz_crypto_init();

// Create transport (UDP for internet, or WiFi/BT/LoRa for mesh)
cyxwiz_transport_t *transport;
cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);

// Create peer table and router
cyxwiz_peer_table_t *peers;
cyxwiz_peer_table_create(&peers);

cyxwiz_node_id_t my_id;
cyxwiz_node_id_random(&my_id);

cyxwiz_router_t *router;
cyxwiz_router_create(&router, peers, transport, &my_id);
cyxwiz_router_start(router);
```

**2. Discover Peers**
```c
#include "cyxwiz/peer.h"

// Start peer discovery
cyxwiz_discovery_t *discovery;
cyxwiz_discovery_create(&discovery, peers, transport, &my_id);
cyxwiz_discovery_start(discovery);

// Poll in your main loop
while (running) {
    cyxwiz_discovery_poll(discovery, cyxwiz_time_ms());
    cyxwiz_router_poll(router, cyxwiz_time_ms());
}
```

**3. Send Anonymous Messages**
```c
#include "cyxwiz/onion.h"

// Create onion context for anonymous routing
cyxwiz_onion_ctx_t *onion;
cyxwiz_onion_create(&onion, router, &my_id);

// Build 3-hop circuit to destination
cyxwiz_node_id_t hops[3] = {relay1, relay2, destination};
cyxwiz_circuit_t *circuit;
cyxwiz_onion_build_circuit(onion, hops, 3, &circuit);

// Send encrypted message through circuit
uint8_t message[] = "Hello, anonymous world!";
cyxwiz_onion_send(onion, circuit, message, sizeof(message));
```

**4. Store Data Across Network**
```c
#include "cyxwiz/storage.h"

// Create storage client (3-of-5 threshold)
cyxwiz_storage_client_t *storage;
cyxwiz_storage_client_create(&storage, router, 3, 5);

// Store data - automatically splits into shares
uint8_t data[] = "Secret document contents...";
cyxwiz_storage_id_t storage_id;
cyxwiz_storage_store(storage, data, sizeof(data), 3600, &storage_id);

// Retrieve data - reconstructs from any 3 shares
uint8_t retrieved[256];
size_t retrieved_len;
cyxwiz_storage_retrieve(storage, &storage_id, retrieved, &retrieved_len);
```

**5. Submit Compute Jobs**
```c
#include "cyxwiz/compute.h"

// Create compute client
cyxwiz_compute_client_t *compute;
cyxwiz_compute_client_create(&compute, router);

// Submit job to network workers
cyxwiz_job_t job = {
    .type = CYXWIZ_JOB_TYPE_WASM,
    .payload = wasm_bytecode,
    .payload_len = bytecode_len
};
cyxwiz_compute_submit(compute, &job);

// Results delivered via callback with MAC verification
```

---

## Project Structure

```
cyxwiz/
├── include/cyxwiz/          # Public headers
│   ├── types.h              # Core types, error codes
│   ├── transport.h          # Transport abstraction
│   ├── crypto.h             # MPC crypto API
│   ├── zkp.h                # Zero-knowledge proofs (Schnorr)
│   ├── privacy.h            # Privacy primitives (Pedersen, credentials)
│   ├── consensus.h          # PoUW consensus API
│   ├── compute.h            # Job marketplace API
│   ├── storage.h            # Distributed storage API
│   ├── memory.h             # Secure memory utilities
│   └── log.h                # Logging
│
├── src/
│   ├── transport/           # Transport drivers
│   │   ├── wifi_direct.c    # WiFi Direct
│   │   ├── bluetooth.c      # Bluetooth Mesh
│   │   ├── lora.c           # LoRa
│   │   └── udp.c            # UDP/Internet
│   ├── core/                # Core protocol modules
│   │   ├── peer.c           # Peer table management
│   │   ├── discovery.c      # Peer discovery
│   │   ├── routing.c        # Multi-hop message routing
│   │   ├── onion.c          # Onion routing
│   │   ├── compute.c        # Job marketplace
│   │   ├── storage.c        # Distributed storage
│   │   └── consensus.c      # PoUW consensus mechanism
│   ├── crypto/              # SPDZ MPC implementation
│   │   ├── crypto.c         # Context management
│   │   ├── sharing.c        # Secret sharing
│   │   ├── mac.c            # Information-theoretic MACs
│   │   ├── zkp.c            # Schnorr identity proofs
│   │   ├── privacy.c        # Pedersen commitments, range proofs
│   │   ├── credentials.c    # Anonymous credentials, service tokens
│   │   └── primitives.c     # libsodium wrappers
│   └── util/                # Utilities
│
├── daemon/                  # Node daemon
├── tests/                   # Unit tests
└── tools/                   # Development tools
```

---

## Roadmap

### Phase 1: Foundation ✅
- [x] Core project structure
- [x] Transport abstraction layer
- [x] WiFi Direct, Bluetooth, LoRa stubs
- [x] SPDZ crypto foundation
- [x] Secret sharing with MACs
- [x] Basic node daemon

### Phase 2: Network Core ✅
- [x] UDP/Internet transport with NAT traversal
- [x] Bootstrap node for peer discovery
- [x] Onion routing implementation
- [x] Message routing (multi-hop)
- [x] SPDZ online computation (Beaver triples)
- [x] Full threshold reconstruction (Shamir's Secret Sharing)

### Phase 3: Protocol Layer ✅
- [x] Compute protocol (job marketplace with MAC verification)
- [x] Storage protocol (CyxCloud distributed storage with K-of-N threshold)
- [x] Proof of Storage (Merkle-based storage verification)
- [x] Schnorr identity proofs (zero-knowledge peer authentication)
- [x] Consensus mechanism (Proof of Useful Work with committee validation)
- [x] Privacy protocol (Pedersen commitments, range proofs, anonymous credentials)

### Phase 4: Production
- [ ] Mobile support (iOS, Android)
- [ ] Browser extension
- [ ] SDK for developers
- [ ] Security audits
- [ ] Mainnet launch

---

## Implementation Status

### Cryptography Layer
| Feature | Status | Description |
|---------|--------|-------------|
| X25519 Key Exchange | ✅ | Elliptic curve Diffie-Hellman |
| XChaCha20-Poly1305 | ✅ | Authenticated encryption (libsodium) |
| BLAKE2b Hashing | ✅ | Fast cryptographic hashing |
| Shamir's Secret Sharing | ✅ | K-of-N threshold reconstruction |
| SPDZ MACs | ✅ | Information-theoretic authentication |
| Beaver Triples | ✅ | Secure multiplication preprocessing |
| Schnorr Identity Proofs | ✅ | Zero-knowledge peer authentication (64 bytes) |
| Ed25519 Identity Keys | ✅ | Master identity with X25519 derivation |

### Privacy Layer
| Feature | Status | Description |
|---------|--------|-------------|
| Pedersen Commitments | ✅ | Hiding commitments (C = v*G + r*H) |
| Homomorphic Operations | ✅ | Add/subtract commitments without opening |
| Range Proofs (16-bit) | ✅ | Prove value in [0, 65535] (96 bytes) |
| Anonymous Credentials | ✅ | Blind Schnorr signatures for unlinkable issuance |
| Credential Showing | ✅ | Prove credential ownership without revealing identity |
| Service Tokens | ✅ | Unlinkable tokens for compute/storage/bandwidth |
| Reputation Proofs | ✅ | Prove credits >= threshold without revealing amount |
| Anonymous Voting | ✅ | Vote in consensus without revealing validator identity |

### Network Layer
| Feature | Status | Description |
|---------|--------|-------------|
| Multi-hop Routing | ✅ | Source routing with path caching |
| Onion Routing | ✅ | 3-hop encrypted relay (XChaCha20-Poly1305) |
| Peer Discovery | ✅ | Broadcast-based with ANNOUNCE messages |
| Authenticated Discovery | ✅ | Schnorr proofs verify peer identity ownership |
| UDP Transport | ✅ | NAT traversal with STUN |
| Bootstrap Nodes | ✅ | Initial peer discovery servers |

### Protocol Layer
| Feature | Status | Description |
|---------|--------|-------------|
| Job Marketplace | ✅ | Distributed compute with MAC verification |
| Anonymous Compute | ✅ | SURB-based anonymous job submission and results |
| CyxCloud Storage | ✅ | K-of-N threshold distributed storage |
| Anonymous Storage | ✅ | SURB-based store/retrieve/delete without identity |
| Proof of Storage | ✅ | Merkle-based storage verification |
| Anonymous PoS | ✅ | Anonymous storage verification via SURBs |
| Anonymous Route Discovery | ✅ | SURB-based anonymous routing with destination tokens |
| PoUW Consensus | ✅ | Proof of Useful Work with 2/3+1 Byzantine fault tolerance |
| Validator Registration | ✅ | Schnorr proof-based validator identity verification |
| Work Credits | ✅ | Earn validation rights through compute/storage work |
| Committee Selection | ✅ | VRF-weighted selection based on work credits |
| Anonymous Consensus Voting | ✅ | Vote in validation rounds without revealing validator identity |
| Slashing | ✅ | Penalties for misbehavior (equivocation = ban) |

### Message Types Implemented
```
Discovery:    PING, PONG, DISCOVER, ANNOUNCE
Routing:      ROUTE_REQ, ROUTE_REPLY, ROUTE_DATA, ROUTE_ERROR, ONION_DATA,
              ANON_ROUTE_REQ, ANON_ROUTE_REPLY
Compute:      JOB_SUBMIT, JOB_CHUNK, JOB_ACCEPT/REJECT, JOB_STATUS, JOB_RESULT,
              JOB_SUBMIT_ANON (anonymous with SURB)
Storage:      STORE_REQ/ACK/REJECT, RETRIEVE_REQ/RESP, DELETE_REQ/ACK,
              STORE_REQ_ANON, RETRIEVE_REQ_ANON, DELETE_REQ_ANON (anonymous with SURBs)
Proof of Storage: POS_COMMITMENT, POS_CHALLENGE, POS_PROOF, POS_VERIFY_OK/FAIL,
              POS_CHALLENGE_ANON, POS_REQUEST_COMMIT_ANON (anonymous verification)
Consensus:    VALIDATOR_REGISTER, VALIDATOR_REG_ACK, WORK_CREDIT, VALIDATION_REQ,
              VALIDATION_VOTE, VALIDATION_RESULT, JOB_VALIDATE_REQ, STORAGE_VALIDATE_REQ,
              SLASH_REPORT, CREDIT_QUERY, CREDIT_RESPONSE, VALIDATOR_HEARTBEAT, ANON_VOTE
Privacy:      PEDERSEN_COMMIT, PEDERSEN_OPEN, RANGE_PROOF, CRED_ISSUE_REQ/RESP,
              CRED_SHOW, CRED_VERIFY, ANON_VOTE, SERVICE_TOKEN_REQ/USE, REPUTATION_PROOF
```

---

## CYXWIZ Token (CYWZ)

The native token that powers the protocol:

| Action | Token Flow |
|--------|-----------|
| Contribute Compute | Earn CYWZ |
| Contribute Storage | Earn CYWZ |
| Use Compute | Pay CYWZ |
| Use Storage | Pay CYWZ |
| Stake for Reputation | Lock CYWZ |
| Governance Voting | Hold CYWZ |

**Token Distribution:**
- 50% Network Rewards (node operators)
- 20% Development
- 15% Community (airdrops, grants)
- 10% Treasury (DAO-controlled)
- 5% Liquidity

---

## What You Can Build Today

The protocol is functional for these real-world applications **right now**:

### 1. Anonymous Mesh Messenger
Build a censorship-resistant chat application:
```
✅ Peer discovery over UDP/WiFi/Bluetooth/LoRa
✅ End-to-end encryption (XChaCha20-Poly1305)
✅ Onion routing hides who talks to whom
✅ Anonymous route discovery - find users without revealing yourself
✅ Works offline via LoRa in remote areas
```
**Use case:** Journalists, activists, disaster response teams

### 2. Distributed File Storage (CyxCloud)
Store files across the network with redundancy:
```
✅ K-of-N threshold storage (e.g., 3-of-5 nodes must survive)
✅ Shamir secret sharing splits data cryptographically
✅ Proof of Storage verifies nodes actually store your data
✅ No single node sees complete files
```
**Use case:** Backup critical documents, censorship-resistant publishing

### 3. Distributed Compute Network
Offload computation to network nodes:
```
✅ Job marketplace with worker discovery
✅ MAC verification ensures correct results
✅ Chunked transfer for large payloads
✅ Multi-party computation ready (SPDZ/Beaver triples)
```
**Use case:** Render farms, ML inference, batch processing

### 4. Emergency Communication Network
Maintain connectivity when infrastructure fails:
```
✅ Multi-transport: UDP → WiFi Direct → Bluetooth → LoRa
✅ Multi-hop routing extends range
✅ 250-byte packets fit LoRa constraints
✅ No central servers required
```
**Use case:** Natural disasters, remote expeditions, off-grid communities

### 5. Privacy-Preserving IoT Network
Connect sensors without exposing data:
```
✅ Lightweight protocol fits embedded devices
✅ Onion routing hides sensor locations
✅ Threshold storage for distributed sensor logs
✅ Compute offloading for resource-constrained nodes
```
**Use case:** Environmental monitoring, smart agriculture, asset tracking

---

## Example: Simple Anonymous Message

```c
#include "cyxwiz/routing.h"
#include "cyxwiz/onion.h"

// Send anonymous message to destination
cyxwiz_router_anon_discover(router, &dest_id, dest_pubkey);
// ... wait for route discovery ...
cyxwiz_onion_send(onion_ctx, circuit, message, len);
```

---

## Example: Anonymous Consensus Voting

Vote in consensus rounds without revealing your validator identity:

```c
#include "cyxwiz/consensus.h"
#include "cyxwiz/privacy.h"
#include "cyxwiz/crypto.h"

// Step 1: Obtain a validator credential (one-time setup)
// Request credential from network issuer
cyxwiz_cred_request_t request;
uint8_t blinding[32];
cyxwiz_cred_request_create(
    CYXWIZ_CRED_VOTE_ELIGIBLE,   // Credential type
    my_identity.public_key,      // Your identity (attribute)
    32,
    &request,
    blinding                      // Keep secret for unblinding
);

// Send request to issuer, receive blinded signature
// ... network exchange ...

// Unblind to get usable credential
cyxwiz_credential_t validator_cred;
cyxwiz_cred_unblind(
    blinded_sig,
    blinding,
    issuer_pubkey,
    my_identity.public_key, 32,
    expires_at,
    &validator_cred
);

// Step 2: Cast anonymous vote in a validation round
// When you receive a VALIDATION_REQ for a round you want to vote on:
uint8_t round_id[8];  // From VALIDATION_REQ message
bool vote = true;     // true = valid, false = invalid

// Check if round allows anonymous voting
if (cyxwiz_consensus_round_allows_anonymous(consensus_ctx, round_id)) {
    // Cast anonymous vote - your identity is hidden
    cyxwiz_error_t err = cyxwiz_consensus_vote_anonymous(
        consensus_ctx,
        round_id,
        vote,
        &validator_cred   // Proves eligibility without revealing identity
    );

    if (err == CYXWIZ_OK) {
        // Vote cast anonymously - no one knows which validator you are
    }
} else {
    // Round requires identified voting, use regular vote
    cyxwiz_consensus_vote(consensus_ctx, round_id, vote);
}
```

**How it works:**
- Credential proves you're an eligible validator without revealing *which* validator
- Each vote showing is unlinkable to other showings of the same credential
- Vote is broadcast to the network - observers see a valid vote but not who cast it
- Quorum is reached by combining anonymous and identified votes

**Use case:** Validators who want to vote without being targeted for their voting patterns

---

## CyxHost: Decentralized Web Hosting (Planned)

The CyxWiz network's secure infrastructure enables **decentralized web hosting** - users can offer to host services on their PCs, and clients can access them anonymously.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CYXHOST PROTOCOL                            │
│                                                                  │
│   Client                              Host Provider              │
│     │                                      │                     │
│     │  "I want to access my-blog"          │  "I host my-blog"   │
│     ▼                                      ▼                     │
│  ┌──────────┐    Onion Routing      ┌──────────────┐            │
│  │  CyxHost │◄─────────────────────►│  CyxHost     │            │
│  │  Client  │    (anonymous)        │  Server      │            │
│  └──────────┘                       └──────┬───────┘            │
│                                            │                     │
│                                     ┌──────▼───────┐            │
│                                     │ Local HTTP   │            │
│                                     │ Server:8080  │            │
│                                     └──────────────┘            │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│   Built on: Compute Layer + Storage Layer + Onion Routing        │
│   Security: Anonymous credentials + Work credits + Consensus     │
└──────────────────────────────────────────────────────────────────┘
```

### How It Works

| Step | Action |
|------|--------|
| 1. Register | Host proves eligibility with anonymous credential |
| 2. Announce | Host advertises service to network |
| 3. Discover | Client queries for service hosts |
| 4. Connect | Request routed through onion network |
| 5. Serve | Host proxies to local HTTP server |
| 6. Respond | Response returns via anonymous SURB |

### Message Types (0x80-0x8F)

```
Hosting:      SERVICE_REGISTER, SERVICE_UNREGISTER, SERVICE_QUERY,
              SERVICE_ANNOUNCE, SERVICE_REQUEST, SERVICE_RESPONSE,
              SERVICE_STREAM_START, SERVICE_STREAM_CHUNK, SERVICE_STREAM_END,
              SERVICE_HEALTH
```

### Example: Host a Website

```c
#include "cyxwiz/hosting.h"

// Step 1: Enable hosting on your node
cyxwiz_host_ctx_t *host;
cyxwiz_host_create(&host, router, consensus_ctx);

// Step 2: Register your service with anonymous credential
cyxwiz_service_config_t config = {
    .name = "my-blog",
    .type = CYXWIZ_SERVICE_HTTP,
    .local_port = 8080,           // Your local web server
    .max_connections = 100,
    .require_payment = true,      // Earn work credits
    .credits_per_request = 1
};

cyxwiz_host_register(host, &config, &my_host_credential);

// Step 3: Start serving - requests arrive automatically
cyxwiz_host_start(host);

// Incoming requests are proxied to localhost:8080
// You earn work credits for each request served
```

### Example: Access a Hosted Service

```c
#include "cyxwiz/hosting.h"

// Step 1: Create client
cyxwiz_host_client_t *client;
cyxwiz_host_client_create(&client, router, onion_ctx);

// Step 2: Discover hosts for service
cyxwiz_host_query(client, "my-blog", on_hosts_found);

// Step 3: Send request (routed anonymously)
cyxwiz_http_request_t req = {
    .method = "GET",
    .path = "/posts/hello-world",
    .headers = "Accept: text/html
"
};

cyxwiz_host_request(client, "my-blog", &req, on_response);

// Response arrives via SURB - host never knows who you are
```

### Security Features

| Feature | How It Works |
|---------|--------------|
| **Anonymous Hosting** | Credential proves host eligibility without revealing identity |
| **Anonymous Access** | Onion routing + SURBs hide client identity |
| **Verified Hosts** | Consensus validates host reputation via work credits |
| **DDoS Resistant** | Work credit requirement + rate limiting |
| **Censorship Resistant** | No central registry, services discovered via P2P |
| **Payment Optional** | Hosts can require credits or serve free |

### Use Cases

```
✅ Personal websites without revealing your IP
✅ Anonymous APIs and microservices
✅ Censorship-resistant blogs and forums
✅ Private file sharing portals
✅ Whistleblower submission systems
✅ Decentralized social media backends
✅ Anonymous e-commerce storefronts
```

### Infrastructure Reuse

CyxHost builds entirely on existing CyxWiz infrastructure:

| Component | Reuses |
|-----------|--------|
| Service Discovery | Peer announcements + consensus |
| Request Routing | Onion routing + SURBs |
| Session Storage | CyxCloud distributed storage |
| Authentication | Anonymous credentials |
| Payment | Work credits system |
| Health Checks | Validator heartbeat patterns |
| Load Balancing | Worker selection algorithms |

**Status:** Planned for Phase 4 - the secure network infrastructure is ready.

---

## Future Use Cases (Roadmap)

### For Individuals
- Rent GPU power for video editing without buying hardware
- Browse the web without being tracked
- Earn crypto by sharing idle compute

### For Developers
- Deploy anonymous applications
- Run CI/CD without vendor lock-in
- Access global compute on demand

### For Organizations
- Distributed computing without cloud monopolies
- Privacy compliance by design (GDPR, CCPA)
- Cost-effective scaling without vendor lock-in

---

## Contributing

We welcome contributions! Areas where help is needed:

1. **Transport Drivers** - Platform-specific WiFi Direct, Bluetooth, LoRa implementations
2. **Crypto** - SPDZ triple generation, threshold signatures
3. **Networking** - Peer discovery, routing protocols
4. **Documentation** - Tutorials, API docs
5. **Testing** - More test coverage, fuzzing

### Development Setup

```bash
# Clone
git clone https://github.com/code3hr/conspiracy.git
cd conspiracy

# Build with debug
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run tests
./build/Debug/test_transport
./build/Debug/test_crypto  # Requires libsodium
```

---

## Security

CyxWiz is security-critical software. We follow these principles:

- **Secure memory** - All sensitive data zeroed before freeing
- **Constant-time operations** - No timing side-channels
- **Defense in depth** - Multiple layers of encryption
- **Minimal trust** - Nodes can't see what they're processing

Found a vulnerability? Please report responsibly to the maintainers.

---

## License

[Add your license here]

---

## The Promise

```
We are building a new internet.

Where you own nothing, but access everything.
Where your data is yours alone.
Where surveillance is impossible.
Where everyone owns a piece.
Where everyone has a voice.
Where you leave no footprint.
Where you don't even exist.

CyxWiz Protocol is the future of computing.
Join us.
```

---

*"Own Nothing. Access Everything. Leave No Trace."*
