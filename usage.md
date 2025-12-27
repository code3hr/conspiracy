# CyxWiz Protocol - Usage Guide

## What CyxWiz Really Is

CyxWiz is a **secure overlay network** - a private network layer that runs on top of existing infrastructure. Think of it as your own private internet where:

```
Traditional Internet:
  You ──► ISP ──► Cloud Server ──► Recipient
  [Tracked] [Logged] [Controlled] [Visible]

CyxWiz Overlay:
  You ──► [Relay] ──► [Relay] ──► [Relay] ──► Recipient
  [Anonymous] [Encrypted] [Decentralized] [Private]
```

**Even when using public IP addresses, CyxWiz provides:**
- Sender anonymity (destination doesn't know who sent)
- Traffic analysis resistance (observers can't correlate traffic)
- Decentralized routing (no single point of failure)
- Threshold security (compromising one node reveals nothing)

## Operating Modes

1. **Node Operator** - Contribute resources, earn CYWZ
2. **User** - Consume resources, pay CYWZ

Both are anonymous. No accounts. No identity.

---

## Node Operation

### Starting a Node

```bash
# Basic start (interactive mode)
./cyxwizd

# Batch mode (for scripting/testing)
./cyxwizd --batch
./cyxwizd -b < commands.txt

# Show help
./cyxwizd --help
```

### Interactive Commands

Once the daemon is running, use these commands at the `>` prompt:

```bash
# Information
/help                    # Show all commands
/status                  # Show node status (ID, peers, validators)
/peers                   # List connected peers

# Messaging
/send <peer_id> <msg>    # Send direct message to peer
/anon <peer_id> <msg>    # Send anonymous message via onion routing

# Storage (CyxCloud)
/store <data>            # Store data across peers (returns storage ID)
/retrieve <storage_id>   # Retrieve stored data by 16-char hex ID
/storage                 # Show storage status

# Compute
/compute <data>          # Submit compute job to worker
/jobs                    # List active jobs

# Consensus
/validators              # List validators and registration status
/credits                 # Show work credits and earning rates

# Control
/quit                    # Graceful shutdown
```

Example session:
```
> /status
  Node ID:     c9ead21bcf6133fb...
  Peers:       3 connected
  Validators:  2 registered
  Onion:       enabled

> /storage
  Provider mode:     enabled
  Active operations: 0
  Stored items:      5
  Storage used:      12480 bytes

> /credits
  Current balance: 42 credits
  Credits are earned by:
    - Completing compute jobs: +10
    - Passing storage proofs:  +5
    - Validation participation: +2
    - Correct validation vote:  +3
```

### Node Types

| Type | Requirements | Role | Rewards |
|------|--------------|------|---------|
| **Relay** | Low (phone OK) | Route traffic | Base rate |
| **Compute** | Medium-High | Execute jobs | Per job |
| **Storage** | High disk | Store shards | Per GB/month |
| **Validator** | Stake required | Verify work | Block rewards |

### Node Lifecycle

```
┌─────────────┐
│   START     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  INIT       │ ← Load config, init crypto
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  DISCOVER   │ ← Find peers via transports
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  JOIN MESH  │ ← Exchange keys, establish routes
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  SERVE      │ ← Process requests, earn rewards
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  SHUTDOWN   │ ← Graceful exit, zero keys
└─────────────┘
```

---

## User Operations

### Anonymous Session

```
User                          Network
  │                              │
  │  1. Generate ephemeral key   │
  │─────────────────────────────>│
  │                              │
  │  2. Request compute          │
  │─────────────────────────────>│
  │                              │
  │  3. Job distributed (MPC)    │
  │                              │
  │  4. Result returned          │
  │<─────────────────────────────│
  │                              │
  │  5. Pay CYWZ                 │
  │─────────────────────────────>│
  │                              │
  │  6. Disconnect (no trace)    │
  │                              │
```

### Compute Request (Working API)

```c
#include "cyxwiz/compute.h"

// Create compute client
cyxwiz_compute_client_t *compute;
cyxwiz_compute_client_create(&compute, router);

// Submit job with MAC verification
cyxwiz_job_t job = {
    .type = CYXWIZ_JOB_TYPE_HASH,  // or ENCRYPT, DECRYPT, VERIFY, CUSTOM
    .payload = data,
    .payload_len = data_len
};

cyxwiz_job_id_t job_id;
cyxwiz_compute_submit(compute, &job, &job_id);

// Result callback verifies MAC automatically
void on_result(cyxwiz_job_id_t *id, uint8_t *result, size_t len, bool mac_valid) {
    if (mac_valid) { /* Trusted result */ }
}
```

### Storage Request (Working API)

```c
#include "cyxwiz/storage.h"

// Create storage client (3-of-5 threshold)
cyxwiz_storage_client_t *storage;
cyxwiz_storage_client_create(&storage, router, 3, 5);

// Store data - automatically split via Shamir's Secret Sharing
cyxwiz_storage_id_t id;
cyxwiz_storage_store(storage, data, data_len, 3600, &id);  // 1-hour TTL

// Retrieve data - reconstructs from any 3 of 5 providers
uint8_t retrieved[MAX_SIZE];
size_t retrieved_len;
cyxwiz_storage_retrieve(storage, &id, retrieved, &retrieved_len);

// Verify provider has data (Proof of Storage)
cyxwiz_proof_of_storage_challenge(storage, &id, &provider_id);
```

### Anonymous Messaging (Working API)

```c
#include "cyxwiz/onion.h"

// Create onion context and link to router
cyxwiz_onion_ctx_t *onion;
cyxwiz_onion_create(&onion, router, &my_id);
cyxwiz_router_set_onion_ctx(router, onion);

// Send anonymously - sender hidden from ALL nodes including destination
cyxwiz_router_send_anonymous(router, &destination, message, len);

// Or build explicit 3-hop circuit for more control
cyxwiz_node_id_t hops[3] = {relay1, relay2, destination};
cyxwiz_circuit_t *circuit;
cyxwiz_onion_build_circuit(onion, hops, 3, &circuit);
cyxwiz_onion_send(onion, circuit, message, len);  // 29 bytes max for 3-hop
```

---

## Privacy Model

### What Nodes See

| Node Type | Sees | Doesn't See |
|-----------|------|-------------|
| Entry node | Your transport address | Your identity, destination, data |
| Relay node | Previous hop, next hop | Source, destination, data |
| Compute node | Encrypted share of job | Full job, who submitted it |
| Exit node | Destination | Who you are |

### Anonymity Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│                    ANONYMITY LAYERS                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: No Accounts                                       │
│  ─────────────────────                                      │
│  You never create an identity. Ephemeral keys only.         │
│                                                             │
│  Layer 2: Onion Routing                                     │
│  ─────────────────────                                      │
│  Traffic bounces through 3+ nodes. Each only knows          │
│  previous and next hop.                                     │
│                                                             │
│  Layer 3: MPC Computation                                   │
│  ─────────────────────────                                  │
│  Jobs split across nodes. No single node sees full data.    │
│  Need 3-of-5 to reconstruct anything.                       │
│                                                             │
│  Layer 4: Zero Logging                                      │
│  ─────────────────────                                      │
│  Nodes physically cannot log what they can't see.           │
│  No metadata, no timestamps, nothing.                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Token Economics

### Earning CYWZ (Node Operators)

| Activity | Reward Rate |
|----------|-------------|
| Relay traffic | 0.001 CYWZ / MB |
| Compute job | 0.01-1.0 CYWZ / job |
| Storage | 0.1 CYWZ / GB / month |
| Validation | Block rewards |

### Spending CYWZ (Users)

| Service | Cost |
|---------|------|
| Light compute | 0.01 CYWZ |
| Heavy compute (GPU) | 0.1-10 CYWZ |
| Storage (1GB/month) | 0.1 CYWZ |
| Priority routing | 2x base rate |

### Staking

| Stake Amount | Benefit |
|--------------|---------|
| 100 CYWZ | Become validator candidate |
| 1000 CYWZ | Priority job assignment |
| 10000 CYWZ | Governance voting power |

---

## Current Implementation Status

### Fully Implemented & Tested

```
[✓] Node daemon with full lifecycle
[✓] Crypto initialization (libsodium - X25519, XChaCha20-Poly1305, BLAKE2b)
[✓] SPDZ-style MPC (3-of-5 threshold, Beaver triples, MACs)
[✓] Shamir's Secret Sharing with threshold reconstruction
[✓] Transport abstraction layer
[✓] UDP transport with NAT traversal (STUN + hole punching)
[✓] Peer discovery protocol (ANNOUNCE with X25519 pubkeys)
[✓] Mesh routing (route discovery, source routing, 5-hop max)
[✓] Onion routing (3-hop, XChaCha20-Poly1305 per layer)
[✓] Anonymous route discovery (SURB-based, hides origin AND destination)
[✓] Anonymous data sending (sender hidden from all nodes)
[✓] Distributed storage (CyxCloud with K-of-N threshold)
[✓] Proof of Storage (Merkle tree challenges)
[✓] Compute job marketplace (with MAC verification)
[✓] Chunked transfers (for large payloads)
[✓] PoUW Consensus (validators, work credits, committee selection)
[✓] Interactive daemon commands (/store, /compute, /validators, /credits)
[✓] Batch mode for scripting (--batch flag)
```

### Transport Drivers Implemented

```
[✓] WiFi Direct transport (Linux wpa_supplicant + Windows WinRT stubs)
[✓] Bluetooth transport (Linux BlueZ + Windows RFCOMM)
[✓] LoRa transport (Serial AT commands + Linux SPI for SX127x)
[✓] UDP transport with NAT traversal (STUN + hole punching)
```

### Planned

```
[ ] WASM sandbox for compute jobs
[ ] Token integration (CYWZ)
[ ] Mobile SDKs (iOS, Android)
[ ] CyxHost platform (serverless deployment)
```

---

## Configuration (Planned)

### Config File: `~/.cyxwiz/config.toml`

```toml
[node]
party_id = 1
threshold = 3
parties = 5

[transport]
wifi_direct = true
bluetooth = true
lora = false

[crypto]
key_refresh_interval = 3600  # seconds

[network]
max_peers = 50
discovery_interval = 30

[storage]
data_dir = "~/.cyxwiz/data"
max_storage_gb = 100

[logging]
level = "info"  # trace, debug, info, warn, error
file = "~/.cyxwiz/cyxwiz.log"
```

---

## Command Line Interface (Planned)

```bash
# Node management
cyxwiz start                  # Start node daemon
cyxwiz stop                   # Stop node
cyxwiz status                 # Show node status
cyxwiz peers                  # List connected peers

# Compute
cyxwiz run <job.wasm>         # Submit compute job
cyxwiz jobs                   # List running jobs
cyxwiz result <job-id>        # Get job result

# Storage
cyxwiz store <file>           # Store file
cyxwiz fetch <storage-id>     # Retrieve file
cyxwiz list                   # List stored files

# Wallet
cyxwiz balance                # Show CYWZ balance
cyxwiz send <amount> <dest>   # Send CYWZ
cyxwiz stake <amount>         # Stake CYWZ
cyxwiz unstake <amount>       # Unstake CYWZ

# Network
cyxwiz network stats          # Network statistics
cyxwiz network topology       # Visualize mesh
```

---

## Example Use Cases

### 1. Anonymous Video Rendering

```bash
# User has a video to render, doesn't want cloud providers to see it
cyxwiz run render.wasm --input video.mp4 --output rendered.mp4

# Job is:
# 1. Encrypted on user's device
# 2. Split across 5 compute nodes via MPC
# 3. Each node processes encrypted share
# 4. Result reconstructed only on user's device
# 5. Nodes never see the video
```

### 2. Censorship-Resistant Messaging

```bash
# Message routed through mesh, no central server
cyxwiz message send "Hello" --to <ephemeral-pubkey>

# Recipient's node:
cyxwiz message receive
```

### 3. Distributed AI Training

```bash
# Train model across global compute network
cyxwiz run train.wasm --model model.bin --data data.enc

# Data stays encrypted, model updates aggregated via MPC
```

### 4. Private File Storage

```bash
# Store file, encrypted and sharded across network
cyxwiz store secret-document.pdf
# Returns: storage-id: cyx_abc123...

# Retrieve later
cyxwiz fetch cyx_abc123... --output document.pdf
```

---

## Real-World Applications by Industry

### Healthcare & Medical

**Private Medical AI Diagnostics**
```bash
# Hospital processes patient scans without exposing to cloud AI providers
cyxwiz run diagnostic-ai.wasm --input encrypted-mri.dat

# Patient data never leaves local mesh
# AI model runs on encrypted shares
# Only hospital receives diagnosis
```

**Secure Medical Records Exchange**
```bash
# Patient controls their own health data
cyxwiz store medical-history.enc --redundancy 5
cyxwiz share cyx_medical_123 --with doctor-pubkey --expires 24h

# Doctor accesses temporarily, no permanent copy anywhere
```

**Anonymous Clinical Trial Data**
```bash
# Participants submit trial data without identity
cyxwiz submit trial-data.enc --study STD-2024-001

# Researchers aggregate via MPC - see statistics, never individual data
```

---

### Journalism & Media

**Source Protection**
```bash
# Whistleblower submits documents to journalist
cyxwiz message send document.pdf --to journalist-ephemeral-key

# No trace of sender
# Journalist cannot be compelled to reveal source (they don't know it)
```

**Collaborative Investigation**
```bash
# Journalists in different countries collaborate securely
cyxwiz workspace create --members reporter1,reporter2,reporter3
cyxwiz share investigation-files/ --workspace

# Governments cannot intercept or trace collaboration
```

**Censorship-Resistant Publishing**
```bash
# Publish article to mesh network
cyxwiz publish article.html --mirrors 100

# Content replicated across global mesh
# No single point of takedown
```

---

### Finance & Banking

**Private Transaction Analysis**
```bash
# Bank analyzes fraud patterns without exposing transaction data
cyxwiz run fraud-detection.wasm --input transactions.enc

# Model sees encrypted shares only
# Compliant with data protection regulations
```

**Secure Multi-Bank Clearing**
```bash
# Banks settle without revealing positions to each other
cyxwiz mpc-compute clearing.wasm --parties bank1,bank2,bank3,bank4,bank5

# Each bank provides encrypted input
# Only final settlement amounts revealed
```

**Anonymous Wealth Verification**
```bash
# Prove you have funds without revealing amount or source
cyxwiz prove-range balance.enc --min 100000 --max infinite

# Zero-knowledge proof of solvency
```

---

### Legal & Compliance

**Confidential Contract Execution**
```bash
# Smart contract with private inputs
cyxwiz contract execute settlement.wasm \
    --input-party1 terms1.enc \
    --input-party2 terms2.enc

# Contract executes on encrypted data
# Only agreed-upon outputs revealed
```

**Secure Legal Discovery**
```bash
# Search documents without exposing irrelevant content
cyxwiz search documents/ --query "keyword" --output relevant-only.enc

# Opposing counsel sees only relevant documents
# Other confidential info stays hidden
```

**Anonymous Tip Lines**
```bash
# Corporate ethics hotline with true anonymity
cyxwiz report submit --type ethics --company CORP123

# No IP logs, no metadata, no caller ID
# Retaliation impossible when identity truly unknown
```

---

### Research & Academia

**Federated Research Computing**
```bash
# Universities share compute power without centralization
cyxwiz compute submit simulation.wasm --pool academic-mesh

# Research runs on distributed nodes
# No single cloud provider controls infrastructure
```

**Private Genome Analysis**
```bash
# Analyze DNA without exposing genetic data
cyxwiz run gwas.wasm --input genome.enc

# Genetic information stays encrypted
# Only analysis results revealed
```

**Anonymous Peer Review**
```bash
# Truly blind peer review
cyxwiz review submit paper.pdf --to journal-mesh

# No way to trace author from submission
# Reviewers cannot identify authors through metadata
```

---

### Human Rights & Activism

**Protest Coordination**
```bash
# Coordinate without surveillance
cyxwiz mesh join protest-network
cyxwiz broadcast "Rally at location X"

# No central server to monitor
# Works even when internet is cut (LoRa fallback)
```

**Evidence Preservation**
```bash
# Document human rights abuses
cyxwiz store evidence-video.enc --geo-tag --timestamp
cyxwiz replicate --count 50 --regions global

# Evidence distributed globally
# Cannot be destroyed or tampered with
```

**Secure Aid Distribution**
```bash
# Distribute aid without compromising recipients
cyxwiz aid distribute --region conflict-zone --recipients encrypted-list

# Recipients verified cryptographically
# Aid workers cannot be forced to reveal beneficiaries
```

---

### Business & Enterprise

**Private Supply Chain Tracking**
```bash
# Track goods without revealing business relationships
cyxwiz track shipment-123 --query status

# Partners see relevant data only
# Competitors cannot analyze supply chain
```

**Confidential M&A Due Diligence**
```bash
# Share sensitive business data for acquisition review
cyxwiz dataroom create --expires 30d --audit-only
cyxwiz share financials.enc --dataroom DR-2024-001

# Time-limited access
# Automatic deletion after deal closes/fails
```

**Competitive Intelligence Protection**
```bash
# Aggregate market data without revealing sources
cyxwiz mpc-compute market-analysis.wasm --sources confidential

# Multiple data sources combine via MPC
# No single party learns others' data
```

---

### Gaming & Entertainment

**Private Multiplayer Gaming**
```bash
# Game state computed without central server
cyxwiz game host chess.wasm --players 2

# No game company tracking your play
# Cheat-proof via MPC verification
```

**Anonymous Content Creation**
```bash
# Create and monetize content without identity
cyxwiz publish video.enc --monetize --anonymous

# Earn CYWZ without linking to real identity
# Content cannot be demonetized by platform bias
```

**Decentralized Streaming**
```bash
# Stream live without platform censorship
cyxwiz stream start --source camera --to mesh

# Viewers connect via mesh
# No platform can cut your stream
```

---

### IoT & Edge Computing

**Private Smart Home**
```bash
# Smart home that doesn't phone home
cyxwiz iot connect thermostat,lights,cameras --local-mesh-only

# All device communication stays local
# No cloud dependency or data collection
```

**Distributed Sensor Networks**
```bash
# Environmental monitoring without central point of failure
cyxwiz sensor submit readings.enc --network environment-mesh

# Data aggregated across mesh
# No single point of compromise
```

**Autonomous Vehicle Mesh**
```bash
# Vehicles communicate directly, no cloud required
cyxwiz v2v join --transport lora,wifi-direct
cyxwiz v2v broadcast traffic-alert --radius 1km

# Works in tunnels, rural areas, network outages
```

---

### Personal Privacy

**Private AI Assistant**
```bash
# AI that doesn't harvest your data
cyxwiz ai query "What's the weather?" --model local-llm

# Query processed on encrypted mesh
# No conversation history stored anywhere
```

**Anonymous Internet Access**
```bash
# Browse without tracking
cyxwiz proxy start --mode anonymous

# Traffic routed through mesh
# No exit node knows your identity
```

**Private Backup**
```bash
# Backup data without trusting any single provider
cyxwiz backup ~/Documents --shards 5 --threshold 3

# Data split across mesh
# Even if 2 nodes compromised, data safe
```

---

### Disaster & Emergency Response

**Mesh Emergency Network**
```bash
# Communication when infrastructure fails
cyxwiz emergency join --transport lora

# Works without internet, cell towers, or power grid
# LoRa range: up to 10km between nodes
```

**Distributed Emergency Coordination**
```bash
# Coordinate rescue without central command
cyxwiz emergency broadcast "Need medical at GPS coords"
cyxwiz emergency resources --query "nearby-hospitals"

# Self-organizing mesh finds resources
# Works even in total infrastructure collapse
```

**Resilient Alert System**
```bash
# Warnings that cannot be censored or suppressed
cyxwiz alert broadcast "Tsunami warning" --priority critical

# Propagates through mesh regardless of government control
# Cannot be silenced
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Node operator sees data | MPC - no single node has full data |
| Traffic analysis | Onion routing, constant-rate padding |
| Sybil attack | Stake requirement for validators |
| Eclipse attack | Diverse peer selection |
| Key compromise | Threshold crypto, key refresh |

### What We Protect Against

- Government surveillance
- Corporate data harvesting
- AI tracking and profiling
- Metadata collection
- Traffic correlation

### What We Don't Protect Against

- User operational security failures
- Malware on user's device
- Physical access to user's device
- Bugs in implementation (audit needed)

---

## Next Steps

### Completed
1. ~~**Peer Discovery** - Nodes finding each other~~ ✓
2. ~~**Message Routing** - Data flowing through mesh~~ ✓
3. ~~**Onion Routing** - 3-hop layered encryption~~ ✓
4. ~~**Anonymous Route Discovery** - SURB-based hidden endpoints~~ ✓
5. ~~**Anonymous Data Sending** - Sender hidden from network~~ ✓
6. ~~**Storage Protocol** - CyxCloud K-of-N threshold storage~~ ✓
7. ~~**Proof of Storage** - Merkle-based verification~~ ✓
8. ~~**Job Protocol** - Compute marketplace with MAC verification~~ ✓

### Completed
9. ~~**Real Transports** - WiFi Direct/Bluetooth/LoRa drivers~~ ✓
10. ~~**Consensus Mechanism** - PoUW validators with work credits~~ ✓
11. ~~**Interactive Commands** - CLI for storage/compute/consensus~~ ✓

### Planned
12. **WASM Sandbox** - Secure code execution environment
13. **Token Integration** - CYWZ payments
14. **Mobile SDKs** - iOS/Android libraries
15. **CyxHost** - Serverless deployment platform

---

## What You Can Build Today

The protocol is **production-ready** for these applications:

| Application | Privacy Level | Status |
|-------------|---------------|--------|
| Anonymous messaging | Full (sender + receiver hidden) | ✓ Ready |
| Censorship-resistant publishing | High (distributed, no takedowns) | ✓ Ready |
| Secure file storage | High (K-of-N threshold) | ✓ Ready |
| Private compute jobs | High (MAC verified) | ✓ Ready |
| Emergency mesh networks | Medium (no internet required) | ✓ Ready |
| Whistleblower platforms | Full (anonymous route discovery) | ✓ Ready |

---

## Comparison: CyxWiz vs Alternatives

| Feature | CyxWiz | Tor | VPN | Signal |
|---------|--------|-----|-----|--------|
| Sender anonymity | ✓ | ✓ | ✗ | ✗ |
| Receiver anonymity | ✓ | Partial | ✗ | ✗ |
| Works without internet | ✓ | ✗ | ✗ | ✗ |
| Distributed storage | ✓ | ✗ | ✗ | ✗ |
| Distributed compute | ✓ | ✗ | ✗ | ✗ |
| No central infrastructure | ✓ | ✗* | ✗ | ✗ |
| Multi-transport | ✓ | ✗ | ✗ | ✗ |
| MPC-ready | ✓ | ✗ | ✗ | ✗ |

*Tor requires directory servers

---

## The Secure Overlay Network Vision

### Why This Matters

The internet was designed for openness, with privacy bolted on as an afterthought. CyxWiz inverts this - **privacy is the foundation, openness is optional**.

```
LAYER STACK:
┌─────────────────────────────────────────────────┐
│            YOUR APPLICATIONS                     │
│   (Messaging, Storage, Compute, Custom)          │
├─────────────────────────────────────────────────┤
│           CYXWIZ PROTOCOL LAYER                  │
│   Anonymity, Encryption, Threshold Security      │
├─────────────────────────────────────────────────┤
│           TRANSPORT LAYER                        │
│   UDP/WiFi Direct/Bluetooth/LoRa                 │
├─────────────────────────────────────────────────┤
│           PHYSICAL NETWORK                       │
│   Internet, Local Radio, Any connectivity        │
└─────────────────────────────────────────────────┘
```

### Real-World Impact

**For Individuals:**
- Own your data - no company can harvest it
- Communicate privately - no surveillance possible
- Compute anonymously - use resources without identity
- Survive infrastructure failures - network works offline

**For Organizations:**
- Zero-trust by design - every connection encrypted
- No vendor lock-in - run on any transport
- Compliance built-in - GDPR/HIPAA/privacy by architecture
- Resilient operations - continues when cloud fails

**For Society:**
- Censorship becomes technically impossible
- Surveillance capitalism loses its data source
- Whistleblowers have cryptographic protection
- Free speech has cryptographic enforcement

### The End Game

```
Today's Internet:                    CyxWiz Future:
─────────────────                    ───────────────
You are the product                  You are invisible
Your data is harvested               Your data is yours
Platforms control access             No gates, no keepers
Single points of failure             Distributed resilience
Trust the server                     Trust no one (trustless)
```

**Own Nothing. Access Everything. Leave No Trace.**
