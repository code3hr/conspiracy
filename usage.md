# CyxWiz Protocol - Usage Guide

## Overview

CyxWiz Protocol operates in two modes:

1. **Node Operator** - Contribute resources, earn CYWZ
2. **User** - Consume resources, pay CYWZ

Both are anonymous. No accounts. No identity.

---

## Node Operation

### Starting a Node

```bash
# Basic start
./cyxwizd

# With options (planned)
./cyxwizd --party-id 1 --threshold 3 --parties 5
./cyxwizd --transport wifi,bluetooth,lora
./cyxwizd --log-level debug
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

### Compute Request (Planned API)

```c
// Connect anonymously
cyxwiz_session_t *session = cyxwiz_connect();

// Submit job
cyxwiz_job_t job = {
    .type = CYXWIZ_JOB_COMPUTE,
    .code = encrypted_wasm_blob,
    .code_len = blob_len,
    .input = encrypted_input,
    .input_len = input_len
};

cyxwiz_job_id_t job_id;
cyxwiz_submit(session, &job, &job_id);

// Wait for result
cyxwiz_result_t result;
cyxwiz_wait(session, job_id, &result);

// Disconnect
cyxwiz_disconnect(session);  // All traces gone
```

### Storage Request (Planned API)

```c
// Store data
cyxwiz_store(session, data, data_len, &storage_id);

// Retrieve data
cyxwiz_retrieve(session, storage_id, buffer, &buffer_len);

// Delete (optional - data expires anyway)
cyxwiz_delete(session, storage_id);
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

### Working Now

```
[✓] Node daemon starts
[✓] Crypto initialization (libsodium)
[✓] 3-of-5 MPC context creation
[✓] Secret sharing with MACs
[✓] Share operations (add, subtract, scalar multiply)
[✓] Encryption/decryption
[✓] Transport abstraction layer
[✓] Logging infrastructure
[✓] Peer table management
[✓] Peer discovery protocol (announce/ack/ping/pong/goodbye)
[✓] Mesh routing (route discovery, source routing, route caching)
```

### Stubs (Transport drivers)

```
[ ] WiFi Direct transport (API ready, hardware integration needed)
[ ] Bluetooth transport (API ready, hardware integration needed)
[ ] LoRa transport (API ready, hardware integration needed)
```

### Not Started

```
[ ] Onion routing (layered encryption on top of source routing)
[ ] Job submission protocol
[ ] Compute execution (WASM sandbox)
[ ] Storage protocol
[ ] Token integration
[ ] Consensus mechanism
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

1. ~~**Peer Discovery** - Nodes finding each other~~ (Done)
2. ~~**Message Routing** - Data flowing through mesh~~ (Done)
3. **Onion Routing** - Layered encryption for traffic privacy
4. **Real Transports** - Actual WiFi/BT/LoRa hardware connections
5. **SPDZ Online** - Compute on encrypted shares
6. **Job Protocol** - Submitting/executing work
7. **WASM Sandbox** - Secure code execution
