# CyxWiz Protocol

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
| **WiFi Direct** | ~250m | High-bandwidth local mesh |
| **Bluetooth Mesh** | ~100m | Urban density, low power |
| **LoRa** | ~10km | Rural areas, emergency networks |

The protocol is designed for LoRa's constraints (250-byte packets), ensuring it works everywhere.

### MPC Cryptography (SPDZ Protocol)

We use Multi-Party Computation so that:
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

```bash
./build/cyxwizd
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
[INFO] Crypto subsystem initialized (libsodium 1.0.18)
[INFO] Created crypto context: 3-of-5, party 1
[INFO] Created WiFi Direct transport
[INFO] Node running. Press Ctrl+C to stop.
```

---

## Project Structure

```
cyxwiz/
├── include/cyxwiz/          # Public headers
│   ├── types.h              # Core types, error codes
│   ├── transport.h          # Transport abstraction
│   ├── crypto.h             # MPC crypto API
│   ├── memory.h             # Secure memory utilities
│   └── log.h                # Logging
│
├── src/
│   ├── transport/           # Transport drivers
│   │   ├── wifi_direct.c    # WiFi Direct
│   │   ├── bluetooth.c      # Bluetooth Mesh
│   │   └── lora.c           # LoRa
│   ├── crypto/              # SPDZ MPC implementation
│   │   ├── crypto.c         # Context management
│   │   ├── sharing.c        # Secret sharing
│   │   ├── mac.c            # Information-theoretic MACs
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

### Phase 2: Network Core (In Progress)
- [ ] Peer discovery protocol
- [ ] Message routing
- [ ] Onion routing implementation
- [ ] SPDZ online computation (Beaver triples)
- [ ] Full threshold reconstruction

### Phase 3: Protocol Layer
- [ ] Compute protocol (job submission/execution)
- [ ] Storage protocol (CyxCloud)
- [ ] Privacy protocol (zero-knowledge proofs)
- [ ] Consensus mechanism

### Phase 4: Production
- [ ] Mobile support (iOS, Android)
- [ ] Browser extension
- [ ] SDK for developers
- [ ] Security audits
- [ ] Mainnet launch

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

## Use Cases

### For Individuals
- Rent GPU power for video editing without buying hardware
- Browse the web without being tracked
- Earn crypto by sharing idle compute
- Secure storage with zero-knowledge encryption

### For Developers
- Deploy anonymous applications
- Run CI/CD without vendor lock-in
- Access global compute on demand
- Build privacy-first products

### For Organizations
- Distributed computing without cloud monopolies
- Privacy compliance by design (GDPR, CCPA)
- No vendor surveillance
- Cost-effective scaling

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
