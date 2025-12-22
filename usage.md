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
```

### Stubs (Not Functional)

```
[ ] WiFi Direct transport
[ ] Bluetooth transport
[ ] LoRa transport
[ ] Peer discovery
[ ] Message routing
```

### Not Started

```
[ ] Onion routing
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

1. **Peer Discovery** - Nodes finding each other
2. **Message Routing** - Data flowing through mesh
3. **Real Transports** - Actual WiFi/BT/LoRa connections
4. **SPDZ Online** - Compute on encrypted shares
5. **Job Protocol** - Submitting/executing work
