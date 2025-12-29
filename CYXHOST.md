# CyxHost Design Document

## Philosophy

```
"Own Nothing. Access Everything. Leave No Trace."
              │
              ▼
    ┌─────────────────┐
    │     CyxHost     │
    │                 │
    │  Pay. Use. Go.  │
    │                 │
    │  Like a cyber   │
    │  cafe - you     │
    │  don't own the  │
    │  computer, you  │
    │  rent time.     │
    └─────────────────┘
```

**Core Principles:**
- **No ownership**: Users don't own servers, they rent compute time
- **Ephemeral by default**: Everything wiped after session - zero trace
- **Anonymous access**: Pay with tokens, access via hidden endpoints
- **Decentralized hosting**: No single provider, hosts compete on reputation

## Overview

CyxHost is a decentralized hosting platform built on the CyxWiz protocol mesh network. Instead of traditional cloud providers (AWS, GCP, Azure), users rent compute from other nodes on the mesh, pay with CyxTokens, and access their services through hidden or relay endpoints.

```
Traditional Hosting:              CyxHost:

┌─────────┐    ┌─────────┐       ┌─────────┐    ┌─────────────────┐
│  User   │───►│  AWS    │       │  User   │───►│  CyxWiz Mesh    │
└─────────┘    │ (knows  │       └─────────┘    │  (anonymous,    │
               │  you)   │                      │   distributed)  │
               └─────────┘                      └─────────────────┘
                    │                                    │
               Single point                      No single point
               of failure                        of failure
               Logs everything                   Logs nothing
               KYC required                      Anonymous
```

## Architecture

### High-Level View

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           CyxHost Architecture                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│                              ┌───────────────┐                               │
│                              │  CyxHost      │                               │
│                              │  Client       │                               │
│                              │  (User)       │                               │
│                              └───────┬───────┘                               │
│                                      │                                        │
│                         1. Browse hosts, pay CYX                             │
│                                      │                                        │
│                                      ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         CyxWiz Mesh Network                             │  │
│  │                                                                         │  │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │  │
│  │   │ Host Node A │    │ Host Node B │    │ Host Node C │               │  │
│  │   │             │    │             │    │             │               │  │
│  │   │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │               │  │
│  │   │ │Container│ │    │ │Container│ │    │ │Container│ │               │  │
│  │   │ │(gVisor) │ │    │ │(gVisor) │ │    │ │(gVisor) │ │               │  │
│  │   │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │               │  │
│  │   │             │    │             │    │             │               │  │
│  │   │ CyxHost     │    │ CyxHost     │    │ CyxHost     │               │  │
│  │   │ Daemon      │    │ Daemon      │    │ Daemon      │               │  │
│  │   └─────────────┘    └─────────────┘    └─────────────┘               │  │
│  │                                                                         │  │
│  │   ┌─────────────┐    ┌─────────────┐                                   │  │
│  │   │ Relay Node  │    │ Validator   │                                   │  │
│  │   │ (Clearnet)  │    │ Node        │                                   │  │
│  │   └─────────────┘    └─────────────┘                                   │  │
│  │                                                                         │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
│                                      │                                        │
│                         2. Access via endpoint                               │
│                                      │                                        │
│                                      ▼                                        │
│                      ┌───────────────────────────────┐                       │
│                      │  Endpoints:                    │                       │
│                      │  • abc123.cyx (hidden)        │                       │
│                      │  • relay.cyxwiz.net/abc123    │                       │
│                      │    (clearnet)                 │                       │
│                      └───────────────────────────────┘                       │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Design Decisions

| Aspect | Choice | Rationale |
|--------|--------|-----------|
| Isolation | Sandboxed Containers (gVisor) | VM-level security, container speed |
| State | Fully Ephemeral | True "Leave No Trace" |
| Endpoints | Hidden + Optional Clearnet | Privacy by default, flexibility when needed |
| Payment | Time Blocks | Simple mental model, predictable costs |

## Part 1: Container Runtime

### 1.1 Why gVisor?

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Container Isolation Comparison                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Standard Docker:           gVisor (runsc):          Full VM:           │
│  ─────────────────          ────────────────          ────────           │
│                                                                          │
│  ┌───────────────┐         ┌───────────────┐         ┌───────────────┐  │
│  │  Container    │         │  Container    │         │  Guest OS     │  │
│  ├───────────────┤         ├───────────────┤         ├───────────────┤  │
│  │  Namespaces   │         │  Sentry       │         │  Guest Kernel │  │
│  │  cgroups      │         │  (user-space  │         ├───────────────┤  │
│  ├───────────────┤         │   kernel)     │         │  Hypervisor   │  │
│  │  HOST KERNEL  │◄─Risk   ├───────────────┤         ├───────────────┤  │
│  └───────────────┘         │  Gofer        │         │  HOST KERNEL  │  │
│                            │  (file proxy) │         └───────────────┘  │
│  Syscalls go               ├───────────────┤                            │
│  directly to host          │  HOST KERNEL  │◄─Protected                 │
│                            └───────────────┘                            │
│                                                                          │
│  Security:  LOW            Security: HIGH            Security: HIGHEST  │
│  Speed:     FAST           Speed:    FAST            Speed:    SLOW     │
│  Overhead:  MINIMAL        Overhead: LOW             Overhead: HIGH     │
│                                                                          │
│  Best for CyxHost: gVisor ────────────────────────────────────────────► │
│  (Best security/speed trade-off for untrusted multi-tenant workloads)   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 gVisor Architecture in CyxHost

```c
// Container configuration
typedef struct {
    char image_id[64];          // Image hash from CyxRegistry
    uint32_t cpu_shares;        // CPU allocation (1000 = 1 core)
    uint64_t memory_limit;      // RAM limit in bytes
    uint64_t disk_limit;        // tmpfs size limit
    uint16_t exposed_ports[8];  // Ports to expose via endpoint
    uint32_t duration_sec;      // Rental duration
} cyxhost_container_config_t;

// Runtime state
typedef struct {
    char container_id[32];      // Unique container ID
    pid_t sentry_pid;           // gVisor sentry process
    pid_t gofer_pid;            // gVisor gofer process
    uint64_t start_time;        // Unix timestamp
    uint64_t end_time;          // When to terminate
    cyxhost_endpoint_t endpoint; // Hidden/relay endpoint
    bool running;
} cyxhost_container_t;
```

### 1.3 Ephemeral Filesystem

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Ephemeral Storage Model                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Container View:                  Host Reality:                      │
│  ───────────────                  ─────────────                      │
│                                                                      │
│  /                                tmpfs (RAM only)                   │
│  ├── bin/                         │                                  │
│  ├── etc/                         │  ┌─────────────────────────┐    │
│  ├── home/                        │  │ Overlay Filesystem       │    │
│  │   └── user/                    │  │                          │    │
│  │       └── data/  ◄─────────────┼──┤ Upper: tmpfs (writable) │    │
│  ├── tmp/                         │  │ Lower: image (readonly)  │    │
│  └── var/                         │  └─────────────────────────┘    │
│                                   │                                  │
│  Writes go to RAM                 No disk touches ever              │
│  Reads from image layer           Image itself is read-only         │
│                                                                      │
│  ON TERMINATION:                                                     │
│  ────────────────                                                    │
│  1. SIGKILL container                                                │
│  2. Unmount overlay                                                  │
│  3. Wipe tmpfs (overwrite with zeros)                               │
│  4. Release memory back to system                                    │
│  5. Delete network namespace                                         │
│  6. Remove endpoint                                                  │
│                                                                      │
│  Result: Forensically unrecoverable                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 Secure Termination

```c
// Secure container termination
int cyxhost_container_terminate(cyxhost_container_t* container) {
    // 1. Stop accepting new connections
    cyxhost_endpoint_close(&container->endpoint);

    // 2. Kill container processes
    kill(container->sentry_pid, SIGKILL);
    kill(container->gofer_pid, SIGKILL);
    waitpid(container->sentry_pid, NULL, 0);
    waitpid(container->gofer_pid, NULL, 0);

    // 3. Secure wipe tmpfs
    // Overwrite all allocated memory with zeros
    char wipe_cmd[256];
    snprintf(wipe_cmd, sizeof(wipe_cmd),
        "dd if=/dev/zero of=/run/cyxhost/%s/upper/wipe bs=1M 2>/dev/null; "
        "sync; rm -f /run/cyxhost/%s/upper/wipe",
        container->container_id, container->container_id);
    system(wipe_cmd);

    // 4. Unmount overlay
    char overlay_path[128];
    snprintf(overlay_path, sizeof(overlay_path),
        "/run/cyxhost/%s/merged", container->container_id);
    umount2(overlay_path, MNT_DETACH);

    // 5. Remove tmpfs
    char tmpfs_path[128];
    snprintf(tmpfs_path, sizeof(tmpfs_path),
        "/run/cyxhost/%s/upper", container->container_id);
    umount2(tmpfs_path, MNT_DETACH);

    // 6. Clean up network namespace
    char netns_path[128];
    snprintf(netns_path, sizeof(netns_path),
        "/var/run/netns/%s", container->container_id);
    unlink(netns_path);

    // 7. Zero container metadata in memory
    cyxwiz_secure_zero(container, sizeof(*container));

    return CYXHOST_OK;
}
```

## Part 2: Endpoint System

### 2.1 Hidden Endpoints (.cyx)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Hidden Endpoint Architecture                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Container starts ──► Generate ephemeral X25519 keypair             │
│                              │                                       │
│                              ▼                                       │
│                       Public key hash                                │
│                              │                                       │
│                              ▼                                       │
│                    abc123def456.cyx  ◄── Hidden address             │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  Connection Flow:                                                    │
│                                                                      │
│  Client                    Mesh                         Container    │
│    │                         │                              │        │
│    │  1. Lookup abc123.cyx   │                              │        │
│    │─────────────────────────►│                              │        │
│    │                         │                              │        │
│    │  2. Build onion circuit │                              │        │
│    │─────────────────────────►│                              │        │
│    │                         │  3. Forward through hops     │        │
│    │                         │─────────────────────────────►│        │
│    │                         │                              │        │
│    │  4. E2E encrypted tunnel established                   │        │
│    │◄═══════════════════════════════════════════════════════►│        │
│    │                         │                              │        │
│                                                                      │
│  Properties:                                                         │
│  • No one knows container's physical location                       │
│  • Traffic encrypted end-to-end                                      │
│  • Address changes each session (unless user-derived)               │
│  • Only reachable via CyxWiz mesh                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Clearnet Relay

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Clearnet Relay Architecture                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  For services that NEED internet accessibility:                     │
│  • Public websites                                                   │
│  • APIs consumed by external apps                                   │
│  • Webhooks receivers                                               │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  Internet User              Relay Node                Container      │
│       │                         │                         │          │
│       │  HTTPS request          │                         │          │
│       │  relay.cyxwiz.net/abc   │                         │          │
│       │────────────────────────►│                         │          │
│       │                         │                         │          │
│       │                         │  Onion-routed request   │          │
│       │                         │────────────────────────►│          │
│       │                         │                         │          │
│       │                         │  Onion-routed response  │          │
│       │                         │◄────────────────────────│          │
│       │                         │                         │          │
│       │  HTTPS response         │                         │          │
│       │◄────────────────────────│                         │          │
│       │                         │                         │          │
│                                                                      │
│  What Relay Knows:           What Relay DOESN'T Know:               │
│  • Request came from IP X    • Container's location                 │
│  • Request size/timing       • Request content (E2E encrypted)      │
│  • Target container ID       • Response content                      │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  Relay Node Economics:                                               │
│  • Earns CYX for proxying traffic                                   │
│  • Stakes CYX to become relay                                       │
│  • Slashed if caught logging/tampering                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Endpoint Data Structures

```c
// Endpoint types
typedef enum {
    CYXHOST_ENDPOINT_HIDDEN,    // .cyx address only
    CYXHOST_ENDPOINT_RELAY,     // Clearnet via relay
    CYXHOST_ENDPOINT_BOTH,      // Both available
} cyxhost_endpoint_type_t;

// Hidden endpoint info
typedef struct {
    uint8_t pubkey[32];         // X25519 public key
    char address[64];           // abc123def456.cyx
    uint16_t port;              // Internal port
} cyxhost_hidden_endpoint_t;

// Relay endpoint info
typedef struct {
    cyxwiz_node_id_t relay_id;  // Relay node ID
    char url[128];              // relay.cyxwiz.net/abc123
    uint16_t port;              // External port
    uint64_t bandwidth_limit;   // Bytes/sec limit
} cyxhost_relay_endpoint_t;

// Combined endpoint
typedef struct {
    cyxhost_endpoint_type_t type;
    cyxhost_hidden_endpoint_t hidden;
    cyxhost_relay_endpoint_t relay;  // Only if type includes relay
} cyxhost_endpoint_t;
```

## Part 3: Payment System (CyxToken)

### 3.1 Token Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CyxToken Economy                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  EARN CYX:                        SPEND CYX:                        │
│  ─────────                        ──────────                        │
│  • Host containers (+++)          • Rent compute time               │
│  • Relay traffic (++)             • Store data (CyxCloud)           │
│  • Validate consensus (+)         • Priority routing                │
│  • Provide storage (+)            • Extended durations              │
│                                                                      │
│  STAKE CYX:                                                         │
│  ──────────                                                         │
│  • Become a host (min stake required)                               │
│  • Become a relay (min stake required)                              │
│  • Become a validator (min stake required)                          │
│  • Stake slashed for bad behavior                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Time Block Pricing

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Time Block Model                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Duration      Base Rate    Discount    Example (2 CPU, 4GB)        │
│  ──────────    ─────────    ────────    ─────────────────────       │
│  1 hour        100%         0%          10 CYX                       │
│  1 day         83%          17%         200 CYX (not 240)            │
│  1 week        60%          40%         1000 CYX (not 1680)          │
│  1 month       50%          50%         3000 CYX (not 6000)          │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  Pricing Factors:                                                    │
│  • CPU cores allocated                                               │
│  • RAM allocated                                                     │
│  • Bandwidth limit                                                   │
│  • Host reputation (higher rep = higher price)                      │
│  • Network demand (surge pricing during high load)                  │
│                                                                      │
│  Price Formula:                                                      │
│  base_rate = (cpu_cores * 5 + ram_gb * 2) * host_reputation_mult    │
│  final_price = base_rate * duration_hours * discount * demand_mult  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Escrow Contract

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Escrow Flow                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. USER INITIATES RENTAL                                           │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  User: "I want to rent Host A for 1 day"                │    │
│     │  User: Sends 200 CYX to escrow                          │    │
│     │  Escrow: Locks 200 CYX, creates rental contract         │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  2. HOST PROVIDES SERVICE                                           │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Host: Spawns container, provides endpoint              │    │
│     │  Host: Submits uptime proofs every hour                 │    │
│     │  Validators: Verify uptime proofs                       │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  3. COMPLETION (Happy Path)                                         │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Time expires OR user releases early                    │    │
│     │  Escrow: Releases CYX to host                           │    │
│     │  Host: Terminates container, wipes data                 │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  4. DISPUTE (Unhappy Path)                                          │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Case A: Host goes offline                              │    │
│     │    - Validators detect missing uptime proofs            │    │
│     │    - User refunded for remaining time                   │    │
│     │    - Host loses reputation                              │    │
│     │                                                          │    │
│     │  Case B: Host provides poor service                     │    │
│     │    - User submits complaint with evidence               │    │
│     │    - Validators review                                   │    │
│     │    - Partial refund + host reputation hit               │    │
│     │                                                          │    │
│     │  Case C: User claims false dispute                      │    │
│     │    - Validators review uptime proofs                    │    │
│     │    - Dispute rejected, host paid in full                │    │
│     │    - User loses dispute deposit                         │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Escrow Data Structures

```c
// Rental states
typedef enum {
    CYXHOST_RENTAL_PENDING,     // Payment received, waiting for host
    CYXHOST_RENTAL_ACTIVE,      // Container running
    CYXHOST_RENTAL_COMPLETED,   // Successfully finished
    CYXHOST_RENTAL_DISPUTED,    // Under dispute
    CYXHOST_RENTAL_REFUNDED,    // Refunded to user
} cyxhost_rental_state_t;

// Rental contract
typedef struct {
    uint8_t contract_id[32];        // Unique contract hash
    cyxwiz_node_id_t user_id;       // User's anonymous ID
    cyxwiz_node_id_t host_id;       // Host node ID

    uint64_t amount_cyx;            // Total payment in CYX
    uint64_t start_time;            // Rental start timestamp
    uint64_t end_time;              // Rental end timestamp

    cyxhost_container_config_t config;  // Container specifications
    cyxhost_rental_state_t state;       // Current state

    // Uptime tracking
    uint32_t expected_proofs;       // Number of proofs expected
    uint32_t received_proofs;       // Number of proofs received

    // Signatures
    uint8_t user_sig[64];           // User's signature
    uint8_t host_sig[64];           // Host's signature
} cyxhost_rental_contract_t;

// Uptime proof (submitted hourly by host)
typedef struct {
    uint8_t contract_id[32];        // Which contract
    uint64_t timestamp;             // When proof generated
    uint8_t container_hash[32];     // Hash of container state
    uint8_t host_sig[64];           // Host signature

    // Validator confirmations
    cyxwiz_node_id_t validators[3]; // Which validators confirmed
    uint8_t validator_sigs[3][64];  // Their signatures
} cyxhost_uptime_proof_t;
```

## Part 4: Image Registry (CyxRegistry)

### 4.1 Distributed Image Storage

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CyxRegistry Architecture                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Challenge: Container images are LARGE (100MB - 1GB+)               │
│  CyxWiz mesh has bandwidth constraints (especially LoRa)            │
│                                                                      │
│  Solution: Layered distribution with caching                        │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  Image Structure:                                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Image: myapp:v1.0                                          │   │
│  │  ┌─────────────────────────────────────────────────────┐   │   │
│  │  │  Layer 4: App code (2MB)         hash: abc123...    │   │   │
│  │  ├─────────────────────────────────────────────────────┤   │   │
│  │  │  Layer 3: Dependencies (50MB)    hash: def456...    │   │   │
│  │  ├─────────────────────────────────────────────────────┤   │   │
│  │  │  Layer 2: Runtime (30MB)         hash: ghi789...    │   │   │
│  │  ├─────────────────────────────────────────────────────┤   │   │
│  │  │  Layer 1: Base OS (100MB)        hash: jkl012...    │   │   │
│  │  └─────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Distribution Strategy:                                              │
│  1. Base layers (OS, runtime) pre-cached on host nodes             │
│  2. Only unique layers transferred for each deployment             │
│  3. Layers stored encrypted in CyxCloud                            │
│  4. Popular images replicated across mesh for fast access          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Pre-Cached Base Images

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Standard Base Images                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Every CyxHost node pre-caches these base images:                   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Image ID              │ Description        │ Size │ Cached  │  │
│  ├──────────────────────────────────────────────────────────────┤  │
│  │  cyxbase:alpine        │ Minimal Linux      │ 5MB  │ Always  │  │
│  │  cyxbase:debian-slim   │ Debian minimal     │ 30MB │ Always  │  │
│  │  cyxbase:node20        │ Node.js runtime    │ 80MB │ Popular │  │
│  │  cyxbase:python311     │ Python runtime     │ 60MB │ Popular │  │
│  │  cyxbase:rust          │ Rust runtime       │ 90MB │ Popular │  │
│  │  cyxbase:go            │ Go runtime         │ 70MB │ Popular │  │
│  │  cyxbase:nginx         │ Web server         │ 20MB │ Always  │  │
│  │  cyxbase:postgres      │ Database           │ 100MB│ Popular │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  User's app only needs to ship the diff layer!                      │
│  e.g., Node.js app: only ship app code (~5MB) not Node runtime     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.3 Image Manifest

```c
// Image layer
typedef struct {
    uint8_t hash[32];           // SHA256 of layer content
    uint64_t size;              // Compressed size
    uint64_t uncompressed_size; // Uncompressed size
    char media_type[64];        // application/vnd.oci.image.layer.v1.tar+gzip
} cyxregistry_layer_t;

// Image manifest
typedef struct {
    char name[128];             // Image name (e.g., "myapp")
    char tag[64];               // Tag (e.g., "v1.0")
    uint8_t manifest_hash[32];  // Hash of this manifest

    // Layers (bottom to top)
    cyxregistry_layer_t layers[16];
    uint8_t layer_count;

    // Configuration
    uint8_t config_hash[32];    // Hash of config blob

    // Signature
    uint8_t publisher_pubkey[32];
    uint8_t signature[64];

    // Storage locations (CyxCloud storage IDs)
    char layer_storage_ids[16][32];
} cyxregistry_manifest_t;

// Registry operations
int cyxregistry_push(const char* image_path, cyxregistry_manifest_t* manifest);
int cyxregistry_pull(const uint8_t* manifest_hash, const char* dest_path);
int cyxregistry_verify(const cyxregistry_manifest_t* manifest);
```

## Part 5: Host Daemon

### 5.1 Daemon Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CyxHost Daemon Architecture                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     cyxhostd                                 │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                                                              │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │   │
│  │  │  Container    │  │   Endpoint    │  │   Resource    │   │   │
│  │  │  Manager      │  │   Manager     │  │   Monitor     │   │   │
│  │  │               │  │               │  │               │   │   │
│  │  │  • Spawn      │  │  • Hidden     │  │  • CPU usage  │   │   │
│  │  │  • Terminate  │  │  • Relay      │  │  • RAM usage  │   │   │
│  │  │  • Monitor    │  │  • Routing    │  │  • Bandwidth  │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────┘   │   │
│  │                                                              │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │   │
│  │  │   Payment     │  │    Uptime     │  │    Image      │   │   │
│  │  │   Handler     │  │    Prover     │  │    Cache      │   │   │
│  │  │               │  │               │  │               │   │   │
│  │  │  • Escrow     │  │  • Generate   │  │  • Pull       │   │   │
│  │  │  • Verify     │  │  • Submit     │  │  • Store      │   │   │
│  │  │  • Release    │  │  • Verify     │  │  • Prune      │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────┘   │   │
│  │                                                              │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                     CyxWiz Protocol                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Daemon API

```c
// Host configuration
typedef struct {
    // Resource limits
    uint32_t max_containers;        // Max concurrent containers
    uint32_t max_cpu_cores;         // Total CPU cores to offer
    uint64_t max_memory;            // Total RAM to offer
    uint64_t max_bandwidth;         // Bytes/sec

    // Economic settings
    uint64_t min_stake;             // Minimum stake required
    uint64_t price_per_cpu_hour;    // CYX per CPU core per hour
    uint64_t price_per_gb_hour;     // CYX per GB RAM per hour

    // Network settings
    bool enable_relay;              // Act as clearnet relay
    bool enable_hidden;             // Accept hidden endpoint jobs

    // gVisor settings
    char runsc_path[256];           // Path to runsc binary
    char rootfs_path[256];          // Path to base images
} cyxhost_daemon_config_t;

// Daemon lifecycle
int cyxhostd_init(cyxhost_daemon_config_t* config);
int cyxhostd_start(void);
int cyxhostd_stop(void);

// Container management
int cyxhostd_spawn_container(cyxhost_rental_contract_t* contract,
                             cyxhost_container_t* container);
int cyxhostd_terminate_container(const char* container_id);
int cyxhostd_list_containers(cyxhost_container_t* containers,
                             size_t* count);

// Uptime proofs
int cyxhostd_generate_proof(const char* container_id,
                            cyxhost_uptime_proof_t* proof);

// Callbacks
typedef void (*cyxhostd_rental_callback_t)(cyxhost_rental_contract_t* contract);
void cyxhostd_set_rental_callback(cyxhostd_rental_callback_t cb);
```

### 5.3 Resource Verification

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Resource Verification                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Problem: How do users know a host actually has the resources       │
│           they claim to have?                                        │
│                                                                      │
│  Solution: Multi-layered verification                                │
│                                                                      │
│  1. SELF-REPORTED (Low Trust)                                       │
│     Host declares: "I have 8 CPU, 32GB RAM"                         │
│     Anyone can claim anything                                        │
│                                                                      │
│  2. STAKE-BACKED (Medium Trust)                                     │
│     Host stakes CYX proportional to claimed resources               │
│     Lying = slashing risk                                           │
│     Formula: stake_required = resources_claimed * base_rate         │
│                                                                      │
│  3. BENCHMARK PROOFS (High Trust)                                   │
│     Validators periodically challenge hosts:                        │
│     • CPU: "Compute hash of X within Y ms"                          │
│     • RAM: "Store and retrieve Z bytes"                             │
│     • Bandwidth: "Transfer N bytes in M seconds"                    │
│     Failures = reputation loss + potential slashing                 │
│                                                                      │
│  4. USER FEEDBACK (Continuous Trust)                                │
│     Users rate performance after rental                             │
│     Poor ratings = reputation loss                                  │
│     Good ratings = reputation boost                                 │
│                                                                      │
│  Reputation Score = f(stake, benchmarks, user_ratings, uptime)      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Part 6: Client Interface

### 6.1 CLI Commands

```bash
# Browse available hosts
cyxhost list
# Output:
# ID              CPU  RAM   Price/hr  Rep   Relay
# a3f8c21d...     4    8GB   25 CYX    95%   Yes
# b7e2d1f8...     2    4GB   10 CYX    88%   No
# c4a9f8e2...     8    16GB  50 CYX    92%   Yes

# Get host details
cyxhost info a3f8c21d
# Output:
# Host: a3f8c21d7b92...
# CPU: 4 cores (verified)
# RAM: 8 GB (verified)
# Bandwidth: 100 Mbps
# Uptime: 99.7% (30 days)
# Reputation: 95%
# Price: 25 CYX/hour
# Relay: Available
# Stake: 10,000 CYX

# Deploy a container
cyxhost deploy --image myapp:v1.0 --cpu 2 --ram 4g --duration 1d --host a3f8c21d
# Output:
# Deploying to host a3f8c21d...
# Payment: 200 CYX (1 day @ 2 CPU, 4GB)
# Confirm? [y/N] y
#
# Container deployed!
# ID: xyz789abc123
# Hidden endpoint: xyz789abc123.cyx:8080
# Relay endpoint: relay.cyxwiz.net/xyz789abc123:8080
# Expires: 2025-12-30 14:30:00 UTC

# Check container status
cyxhost status xyz789abc123
# Output:
# Container: xyz789abc123
# State: Running
# Uptime: 2h 15m
# CPU: 45% (of 2 cores)
# RAM: 1.2 GB (of 4 GB)
# Network: 12 MB in, 45 MB out
# Time remaining: 21h 45m
# Uptime proofs: 3/3 verified

# Extend rental
cyxhost extend xyz789abc123 --duration 1d
# Output:
# Extending rental by 1 day...
# Additional payment: 200 CYX
# Confirm? [y/N] y
# Rental extended until 2025-12-31 14:30:00 UTC

# Terminate early (no refund for remaining time)
cyxhost terminate xyz789abc123
# Output:
# Terminating container...
# Container terminated. Data securely wiped.

# View rental history
cyxhost history
# Output:
# ID              Host          Duration  Cost    Status
# xyz789abc123    a3f8c21d...   2 days    400 CYX Active
# abc456def789    b7e2d1f8...   1 hour    10 CYX  Completed
# def123xyz456    c4a9f8e2...   1 week    1000 CYX Refunded (host offline)
```

### 6.2 Client Library API

```c
// Client context
typedef struct cyxhost_client cyxhost_client_t;

// Initialize client
cyxhost_client_t* cyxhost_client_create(cyxwiz_ctx_t* cyxwiz_ctx);
void cyxhost_client_destroy(cyxhost_client_t* client);

// Browse hosts
typedef struct {
    cyxwiz_node_id_t host_id;
    uint32_t cpu_cores;
    uint64_t ram_bytes;
    uint64_t bandwidth;
    uint64_t price_per_hour;
    uint8_t reputation;         // 0-100
    bool relay_available;
} cyxhost_host_info_t;

int cyxhost_list_hosts(cyxhost_client_t* client,
                       cyxhost_host_info_t* hosts,
                       size_t* count);

// Deploy container
typedef struct {
    cyxwiz_node_id_t host_id;
    char image[128];            // Image name:tag or hash
    uint32_t cpu_shares;        // 1000 = 1 core
    uint64_t memory;            // RAM in bytes
    uint32_t duration_hours;    // Rental duration
    bool enable_relay;          // Want clearnet relay?
    uint16_t ports[8];          // Ports to expose
} cyxhost_deploy_request_t;

typedef struct {
    char container_id[32];
    cyxhost_endpoint_t endpoint;
    uint64_t expires_at;
    uint64_t cost_cyx;
} cyxhost_deploy_result_t;

int cyxhost_deploy(cyxhost_client_t* client,
                   cyxhost_deploy_request_t* request,
                   cyxhost_deploy_result_t* result);

// Manage container
int cyxhost_status(cyxhost_client_t* client,
                   const char* container_id,
                   cyxhost_container_status_t* status);
int cyxhost_extend(cyxhost_client_t* client,
                   const char* container_id,
                   uint32_t additional_hours);
int cyxhost_terminate(cyxhost_client_t* client,
                      const char* container_id);

// Connect to container
int cyxhost_connect(cyxhost_client_t* client,
                    const char* container_id,
                    uint16_t port,
                    cyxwiz_stream_t** stream);
```

## Part 7: Security Considerations

### 7.1 Threat Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Threat Model                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ATTACKER                     MITIGATION                            │
│  ────────                     ──────────                            │
│                                                                      │
│  Malicious Host               • gVisor isolation                    │
│  (wants to steal              • Encrypted storage                   │
│   user data)                  • No disk writes                      │
│                               • User holds keys                     │
│                                                                      │
│  Malicious User               • gVisor isolation                    │
│  (wants to escape             • Resource limits                     │
│   container)                  • No root in container               │
│                               • Seccomp filters                     │
│                                                                      │
│  Network Observer             • Onion routing                       │
│  (wants to trace              • E2E encryption                      │
│   traffic)                    • No cleartext IPs                    │
│                                                                      │
│  Relay Node                   • E2E encryption                      │
│  (wants to see                • Can't see content                   │
│   content)                    • Only sees encrypted bytes           │
│                                                                      │
│  Validator Collusion          • Multiple independent validators     │
│  (wants to steal              • Stake slashing                      │
│   escrow)                     • Cryptographic proofs                │
│                                                                      │
│  Forensic Analysis            • Ephemeral tmpfs                     │
│  (wants to recover            • Secure wipe                         │
│   data after session)         • Memory zeroing                      │
│                               • No persistent logs                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 gVisor Security Configuration

```c
// gVisor runtime configuration for CyxHost
const char* GVISOR_CONFIG = R"(
{
  "ociVersion": "1.0.0",
  "process": {
    "user": {"uid": 1000, "gid": 1000},
    "capabilities": {
      "bounding": [],
      "effective": [],
      "inheritable": [],
      "permitted": [],
      "ambient": []
    },
    "noNewPrivileges": true
  },
  "root": {
    "readonly": true
  },
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"},
      {"type": "user"}
    ],
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        // Whitelist only necessary syscalls
        {"names": ["read", "write", "open", ...],
         "action": "SCMP_ACT_ALLOW"}
      ]
    },
    "resources": {
      "memory": {"limit": MEMORY_LIMIT},
      "cpu": {"quota": CPU_QUOTA, "period": 100000}
    }
  }
}
)";
```

## Part 8: Implementation Phases

### Phase 1: Core Runtime
1. Implement gVisor container spawning
2. Implement ephemeral tmpfs overlay
3. Implement secure termination
4. Basic resource monitoring

### Phase 2: Endpoint System
1. Hidden endpoint generation
2. Integration with CyxWiz onion routing
3. Relay endpoint prototype
4. Port forwarding

### Phase 3: Payment Integration
1. CyxToken transfer integration
2. Escrow contract implementation
3. Uptime proof generation
4. Basic dispute handling

### Phase 4: Registry
1. Image manifest format
2. Layer storage in CyxCloud
3. Pull/push operations
4. Base image caching

### Phase 5: Host Daemon
1. Full cyxhostd implementation
2. Resource verification
3. Reputation tracking
4. Automatic pricing

### Phase 6: Client Tools
1. CLI implementation
2. Client library
3. GUI integration (in CyxWiz GUI)
4. Documentation

## Files to Create

### New Files
```
include/cyxwiz/
├── cyxhost.h           # Main CyxHost header
├── cyxhost_container.h # Container management
├── cyxhost_endpoint.h  # Endpoint types
├── cyxhost_payment.h   # Payment/escrow
├── cyxhost_registry.h  # Image registry
└── cyxhost_client.h    # Client API

src/cyxhost/
├── container.c         # Container lifecycle
├── gvisor.c            # gVisor integration
├── endpoint.c          # Endpoint management
├── payment.c           # Escrow handling
├── uptime.c            # Uptime proofs
├── registry.c          # Image registry
└── client.c            # Client operations

daemon/
└── cyxhostd.c          # Host daemon main

tools/
└── cyxhost.c           # CLI tool
```

### Modified Files
```
CMakeLists.txt          # Add cyxhost module
daemon/main.c           # Integrate cyxhostd option
include/cyxwiz/types.h  # Add cyxhost types
```

## Open Questions

1. **LoRa Compatibility**: Can container images be distributed over LoRa?
   - Probably need WiFi/UDP for image transfer
   - LoRa only for control plane

2. **Legal Considerations**: Relay nodes as "exit nodes"
   - Similar to Tor exit node legal issues
   - May need geographic restrictions

3. **DDoS Protection**: How to prevent abuse of hosted services?
   - Rate limiting per endpoint
   - Proof-of-work for access?

4. **Multi-Region**: Can a container migrate between hosts?
   - State is ephemeral, so restart on new host
   - Session continuity challenges

5. **Windows Support**: gVisor is Linux-only
   - Windows hosts would need different isolation (Hyper-V?)
   - Or Windows hosts only relay, not compute

---

## Part 9: Expanded Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Container Escape | Exploit gVisor, kernel vuln | Critical |
| Data Exfiltration | Host reads container memory | Critical |
| Resource Abuse | Cryptomining, DoS from container | High |
| Payment Fraud | Double-spend, escrow manipulation | High |
| Identity Exposure | Deanonymize user or host | High |
| Service Disruption | Kill containers, corrupt images | Medium |

### Detailed Threat Analysis

#### Container Escape
- **Description**: Malicious user code breaks out of gVisor sandbox
- **Attacker**: Renter with container access
- **Prerequisites**: gVisor vulnerability or misconfiguration
- **Impact**: Full host compromise, access to other containers
- **Likelihood**: Low (gVisor designed for this threat)
- **Mitigation**:
  - Keep gVisor updated
  - Minimal syscall whitelist
  - Host-level seccomp as defense-in-depth
  - Container runs as unprivileged user
  - No device access

#### Host Memory Snooping
- **Description**: Malicious host reads container RAM
- **Attacker**: Host operator
- **Prerequisites**: Physical/root access to host machine
- **Impact**: Exposure of container secrets, computation results
- **Likelihood**: Medium (hosts are untrusted)
- **Mitigation**:
  - Encrypt sensitive data in container
  - Use MPC for secrets that must be computed on
  - Ephemeral keys for each session
  - Future: Hardware enclaves (SGX/SEV)

#### Sybil Host Attack
- **Description**: Attacker runs many fake hosts to dominate network
- **Attacker**: Well-resourced adversary
- **Prerequisites**: Capital for stakes, infrastructure
- **Impact**: Control over hosting, censorship capability
- **Likelihood**: Low (expensive)
- **Mitigation**:
  - Stake requirement proportional to resources
  - Benchmark verification
  - Geographic diversity scoring
  - Long-term reputation weighting

#### Escrow Manipulation
- **Description**: Validators collude to steal escrowed funds
- **Attacker**: Validator cabal
- **Prerequisites**: Control of majority validators
- **Impact**: Theft of all escrowed payments
- **Likelihood**: Low (requires coordination)
- **Mitigation**:
  - Minimum 5 validators per escrow
  - Validators randomly selected
  - Time-locked releases
  - Cryptographic proofs required

### Security Assumptions
1. gVisor kernel emulation is secure against container escape
2. At least 2/3 of validators are honest
3. Host cannot break libsodium encryption
4. Network observers cannot correlate traffic across multiple circuits
5. Users don't leak identity through application behavior

### Trust Boundaries
```
                                   TRUST BOUNDARY 1
                                        │
 ┌──────────────┐    ┌──────────────┐   │   ┌──────────────┐
 │  User App    │───►│  Container   │───┼──►│  gVisor      │
 │  (Untrusted) │    │  Filesystem  │   │   │  Sentry      │
 └──────────────┘    └──────────────┘   │   └──────────────┘
                                        │          │
                                        │   TRUST BOUNDARY 2
                                        │          │
                                        │   ┌──────────────┐
                                        │   │  Host Kernel │
                                        │   │  (Untrusted  │
                                        │   │   by user)   │
                                        │   └──────────────┘
```

- **Trust boundary 1**: Container → gVisor (syscall filtering)
- **Trust boundary 2**: gVisor → Host kernel (limited syscall surface)
- **Trust boundary 3**: Host → Network (encryption required)

---

## Part 10: Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| Container | Process crash | Service unavailable | Health check fail | Auto-restart (if configured) |
| Container | OOM killed | Process terminated | cgroup event | User notified, restart optional |
| gVisor | Sentry crash | Container dead | Process exit | Container restart |
| Host | Node offline | All containers gone | Peer timeout | User refund, re-deploy elsewhere |
| Network | Partition | Endpoint unreachable | Connection timeout | Route around, retry |
| Escrow | Validator offline | Payment stuck | Timeout | Fallback validators |
| Image | Pull failed | Deploy fails | Error response | Retry from different peers |

### Recovery Procedures

#### Container Crash Recovery
```c
// Auto-restart policy
typedef struct {
    uint8_t max_restarts;       // Max restarts before giving up
    uint32_t restart_window_sec; // Window for counting restarts
    uint32_t restart_delay_ms;  // Delay between restarts (exponential)
    bool preserve_logs;         // Keep last N log lines for debugging
} cyxhost_restart_policy_t;

// Recovery flow
int cyxhost_container_recover(cyxhost_container_t* container) {
    if (container->restart_count >= policy.max_restarts) {
        // Too many restarts - notify user, refund partial
        cyxhost_notify_user(container, CYXHOST_EVENT_FAILED);
        return cyxhost_refund_partial(container);
    }

    // Exponential backoff
    uint32_t delay = policy.restart_delay_ms * (1 << container->restart_count);
    sleep_ms(delay);

    container->restart_count++;
    return cyxhost_container_start(container);
}
```

#### Host Failure Recovery
1. Validators detect host offline (missed uptime proofs)
2. Mark all host's containers as FAILED
3. Notify affected users via mesh
4. Calculate refund for remaining time
5. Process refunds from host's stake
6. Reduce host reputation score
7. User can re-deploy on different host

#### Escrow Timeout Recovery
```c
// If validators don't respond within timeout
int cyxhost_escrow_timeout_handler(cyxhost_rental_contract_t* contract) {
    if (time_since_last_proof(contract) > ESCROW_PROOF_TIMEOUT) {
        // Automatic refund to user
        cyxhost_refund_full(contract);
        cyxhost_penalize_host(contract->host_id);
        return CYXHOST_OK;
    }
    return CYXHOST_PENDING;
}
```

### Graceful Shutdown
```c
int cyxhost_daemon_shutdown(void) {
    // 1. Stop accepting new rentals
    cyxhostd_stop_accepting();

    // 2. Notify existing containers (30s warning)
    for (int i = 0; i < active_containers; i++) {
        cyxhost_notify_user(&containers[i], CYXHOST_EVENT_SHUTDOWN_SOON);
    }
    sleep(30);

    // 3. Terminate all containers cleanly
    for (int i = 0; i < active_containers; i++) {
        cyxhost_container_terminate(&containers[i]);
    }

    // 4. Submit final uptime proofs
    cyxhost_submit_final_proofs();

    // 5. Announce departure to network
    cyxwiz_discovery_send_goodbye();

    return CYXHOST_OK;
}
```

### What Cannot Be Recovered
- Container state after termination (by design)
- Data written only to ephemeral tmpfs
- Ephemeral endpoint keys
- In-flight requests during crash

---

## Part 11: Protocol Versioning

### Version Format
```
CyxHost Protocol: Major.Minor.Patch (SemVer)
Example: 2.1.0
```

### Version Negotiation
```c
// Host advertises version in capability announcement
typedef struct {
    uint8_t protocol_major;
    uint8_t protocol_minor;
    uint8_t protocol_patch;
    uint32_t features;          // Bitmap of supported features
} cyxhost_capability_t;

// Feature flags
#define CYXHOST_FEATURE_RELAY       (1 << 0)
#define CYXHOST_FEATURE_HIDDEN      (1 << 1)
#define CYXHOST_FEATURE_BENCHMARK   (1 << 2)
#define CYXHOST_FEATURE_MULTI_PORT  (1 << 3)
#define CYXHOST_FEATURE_SECRETS     (1 << 4)

// Client checks compatibility before deploy
bool cyxhost_compatible(cyxhost_capability_t* host, uint8_t min_major, uint8_t min_minor) {
    if (host->protocol_major < min_major) return false;
    if (host->protocol_major == min_major && host->protocol_minor < min_minor) return false;
    return true;
}
```

### Backwards Compatibility

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| New optional field in manifest | Patch | No |
| New container feature (opt-in) | Minor | No |
| New required field in contract | Major | Yes |
| Change escrow validation rules | Major | Yes |
| Image format change | Major | Yes |
| API endpoint change | Major | Yes |

### Migration Path
1. New version announced 60 days before mandatory
2. Hosts upgrade first (incentivized with bonus CYX)
3. Clients warned if using deprecated features
4. Old containers continue until rental expires
5. New deployments require new version after cutoff

### Container Image Versioning
```c
// Image manifest includes format version
typedef struct {
    uint8_t format_version;     // Manifest format version
    uint8_t min_host_version;   // Minimum CyxHost version required
    // ... rest of manifest
} cyxregistry_manifest_t;
```

---

## Part 12: Rate Limiting & DoS Protection

### Host-Side Limits

| Resource | Limit | Enforcement |
|----------|-------|-------------|
| Concurrent containers | configurable (default 8) | Hard reject new |
| Container CPU | cgroup quota | Throttled |
| Container RAM | cgroup limit | OOM kill |
| Container bandwidth | tc/iptables | Shaped |
| Uptime proof rate | 1/hour | Ignore extras |
| Deploy requests | 10/min per peer | 429 response |

### Container-Internal Limits

| Resource | Limit | Enforcement |
|----------|-------|-------------|
| Open files | 1024 | RLIMIT_NOFILE |
| Processes | 256 | RLIMIT_NPROC |
| Disk (tmpfs) | configured quota | -ENOSPC |
| Network connections | 1000 | iptables conntrack |
| Syscall rate | none (gVisor handles) | - |

### Network-Level DoS Protection
```c
// Per-endpoint rate limiting
typedef struct {
    uint64_t bytes_in_window;
    uint64_t window_start;
    uint64_t max_bytes_per_window;
    uint32_t window_duration_sec;
    uint32_t current_connections;
    uint32_t max_connections;
} cyxhost_endpoint_limits_t;

int cyxhost_check_endpoint_limit(cyxhost_endpoint_t* ep, size_t bytes) {
    cyxhost_endpoint_limits_t* limits = &ep->limits;

    // Reset window if expired
    if (now() - limits->window_start > limits->window_duration_sec) {
        limits->bytes_in_window = 0;
        limits->window_start = now();
    }

    // Check bandwidth
    if (limits->bytes_in_window + bytes > limits->max_bytes_per_window) {
        return CYXHOST_RATE_LIMITED;
    }

    // Check connections
    if (limits->current_connections >= limits->max_connections) {
        return CYXHOST_TOO_MANY_CONNECTIONS;
    }

    limits->bytes_in_window += bytes;
    return CYXHOST_OK;
}
```

### Abuse Response Escalation
1. **Warning**: Log suspicious activity
2. **Throttle**: Reduce bandwidth allocation
3. **Isolate**: Move container to restricted network
4. **Terminate**: Kill container, partial refund
5. **Ban**: Host refuses future rentals from peer

---

## Part 13: Monitoring & Observability

### Key Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cyxhost_containers_active` | Gauge | state | Active containers by state |
| `cyxhost_container_cpu_usage` | Gauge | container_id | CPU usage percentage |
| `cyxhost_container_mem_bytes` | Gauge | container_id | Memory usage |
| `cyxhost_container_net_bytes` | Counter | container_id, direction | Network I/O |
| `cyxhost_rentals_total` | Counter | status | Rental completions |
| `cyxhost_revenue_cyx` | Counter | - | Total CYX earned |
| `cyxhost_uptime_proofs_total` | Counter | status | Proofs submitted |
| `cyxhost_image_pulls_total` | Counter | status | Image pull operations |

### Health Checks
```c
// Host health status
typedef struct {
    bool daemon_running;
    bool gvisor_available;
    bool storage_healthy;
    bool network_connected;
    uint32_t active_containers;
    uint32_t capacity_remaining;
    uint64_t uptime_sec;
} cyxhost_health_t;

int cyxhost_health_check(cyxhost_health_t* health) {
    health->daemon_running = cyxhostd_is_running();
    health->gvisor_available = gvisor_check_runsc();
    health->storage_healthy = storage_check_tmpfs();
    health->network_connected = cyxwiz_peer_count() > 0;
    health->active_containers = cyxhost_container_count();
    health->capacity_remaining = config.max_containers - health->active_containers;
    health->uptime_sec = cyxhostd_uptime();
    return CYXHOST_OK;
}
```

### Logging

| Level | When to Use | Examples |
|-------|-------------|----------|
| ERROR | Unrecoverable | Container escape detected, escrow theft |
| WARN | Recoverable | Container OOM, failed proof submission |
| INFO | Normal ops | Container start/stop, rental complete |
| DEBUG | Troubleshooting | Syscall traces, network packets |

### Container Logs (Privacy-Preserving)
```c
// Containers can optionally stream logs to user (never stored on host)
typedef struct {
    bool enabled;
    uint32_t max_lines;         // Rolling buffer size
    bool encrypt_in_transit;    // E2E encrypt to user
} cyxhost_log_config_t;

// Log streaming to user only
void cyxhost_log_stream(cyxhost_container_t* container, const char* line) {
    if (!container->log_config.enabled) return;

    // Encrypt for user's eyes only
    uint8_t encrypted[MAX_LOG_LINE + CYXWIZ_OVERHEAD];
    size_t enc_len;
    cyxwiz_crypto_encrypt(line, strlen(line), container->user_session_key,
                          encrypted, &enc_len);

    // Send via onion to user
    cyxwiz_onion_send(container->user_circuit, encrypted, enc_len);
}
```

---

## Part 14: Resource Limits & Enforcement

### cgroups Configuration
```c
// Resource enforcement via cgroups v2
typedef struct {
    // CPU limits
    uint32_t cpu_shares;        // Relative weight (1000 = 1 core equivalent)
    uint64_t cpu_quota_us;      // Hard limit per period
    uint64_t cpu_period_us;     // Period (default 100000 = 100ms)

    // Memory limits
    uint64_t memory_limit;      // Hard limit in bytes
    uint64_t memory_soft;       // Soft limit (for reclaim)
    uint64_t memory_swap;       // Swap limit (0 = no swap)

    // I/O limits
    uint64_t io_read_bps;       // Read bytes/sec
    uint64_t io_write_bps;      // Write bytes/sec
    uint32_t io_read_iops;      // Read ops/sec
    uint32_t io_write_iops;     // Write ops/sec

    // PIDs
    uint32_t pids_max;          // Max processes
} cyxhost_cgroup_config_t;

int cyxhost_apply_cgroup(const char* container_id, cyxhost_cgroup_config_t* config) {
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path),
             "/sys/fs/cgroup/cyxhost/%s", container_id);

    // Create cgroup
    mkdir(cgroup_path, 0755);

    // CPU
    write_file("%s/cpu.max", "%lu %lu",
               config->cpu_quota_us, config->cpu_period_us);
    write_file("%s/cpu.weight", "%u", config->cpu_shares);

    // Memory
    write_file("%s/memory.max", "%lu", config->memory_limit);
    write_file("%s/memory.high", "%lu", config->memory_soft);
    write_file("%s/memory.swap.max", "%lu", config->memory_swap);

    // I/O
    write_file("%s/io.max", "default rbps=%lu wbps=%lu riops=%u wiops=%u",
               config->io_read_bps, config->io_write_bps,
               config->io_read_iops, config->io_write_iops);

    // PIDs
    write_file("%s/pids.max", "%u", config->pids_max);

    return CYXHOST_OK;
}
```

### Resource Overcommit Policy
```c
// Hosts can overcommit resources with configurable ratio
typedef struct {
    float cpu_overcommit;       // e.g., 2.0 = sell 2x physical CPUs
    float memory_overcommit;    // e.g., 1.5 = sell 1.5x physical RAM
    float bandwidth_overcommit; // e.g., 3.0 = sell 3x bandwidth
} cyxhost_overcommit_t;

// Admission control
bool cyxhost_can_accept(cyxhost_container_config_t* request) {
    uint64_t committed_cpu = current_committed_cpu();
    uint64_t committed_mem = current_committed_memory();

    uint64_t max_cpu = physical_cpu() * overcommit.cpu_overcommit;
    uint64_t max_mem = physical_memory() * overcommit.memory_overcommit;

    return (committed_cpu + request->cpu_shares <= max_cpu) &&
           (committed_mem + request->memory_limit <= max_mem);
}
```

---

## Part 15: Container Image Distribution

### Mesh Transfer Protocol
```c
// Large file transfer over mesh (for images)
typedef struct {
    uint8_t file_hash[32];      // SHA256 of complete file
    uint64_t total_size;        // Total bytes
    uint32_t chunk_size;        // Bytes per chunk (default 64KB)
    uint32_t chunk_count;       // Total chunks
} cyxhost_transfer_manifest_t;

// Chunk request/response
typedef struct {
    uint8_t file_hash[32];
    uint32_t chunk_index;
    uint8_t data[65536];        // Chunk data
    uint32_t data_len;
    uint8_t chunk_hash[32];     // SHA256 of this chunk
} cyxhost_transfer_chunk_t;

// Multi-source download (BitTorrent-style)
int cyxhost_pull_image_layer(uint8_t* layer_hash, uint8_t* dest) {
    // 1. Query DHT for peers that have this layer
    cyxwiz_node_id_t peers[16];
    int peer_count = cyxcloud_find_providers(layer_hash, peers, 16);

    // 2. Download chunks from multiple peers in parallel
    cyxhost_transfer_manifest_t manifest;
    cyxhost_get_manifest(peers[0], layer_hash, &manifest);

    uint8_t* chunk_status = calloc(manifest.chunk_count, 1);  // 0=need, 1=have

    while (!all_chunks_received(chunk_status, manifest.chunk_count)) {
        for (int i = 0; i < peer_count && !all_chunks_received(...); i++) {
            uint32_t chunk = next_needed_chunk(chunk_status);
            cyxhost_request_chunk(peers[i], layer_hash, chunk);
        }
        cyxhost_process_responses(dest, chunk_status);
    }

    // 3. Verify complete file hash
    uint8_t computed_hash[32];
    cyxwiz_crypto_hash(dest, manifest.total_size, computed_hash);
    return memcmp(computed_hash, layer_hash, 32) == 0 ? CYXHOST_OK : CYXHOST_CORRUPT;
}
```

### Layer Deduplication
```c
// Check if layer already exists locally
bool cyxhost_has_layer(uint8_t* layer_hash) {
    char path[256];
    snprintf(path, sizeof(path), "%s/layers/%s",
             config.rootfs_path, hash_to_hex(layer_hash));
    return access(path, F_OK) == 0;
}

// Pull only missing layers
int cyxhost_pull_image(cyxregistry_manifest_t* manifest) {
    for (int i = 0; i < manifest->layer_count; i++) {
        if (!cyxhost_has_layer(manifest->layers[i].hash)) {
            int err = cyxhost_pull_image_layer(manifest->layers[i].hash, NULL);
            if (err != CYXHOST_OK) return err;
        }
    }
    return CYXHOST_OK;
}
```

### Pre-fetch Strategy
```c
// Popular images pre-fetched based on network demand
void cyxhost_prefetch_popular(void) {
    // Query network for most-requested images
    cyxregistry_manifest_t popular[10];
    int count = cyxregistry_get_popular(popular, 10);

    for (int i = 0; i < count; i++) {
        if (!cyxhost_has_image(&popular[i])) {
            cyxhost_pull_image(&popular[i]);
        }
    }
}
```

---

## Part 16: Secrets Injection

### Secret Delivery Methods

#### Environment Variables (Simple)
```c
// Secrets passed as encrypted env vars
typedef struct {
    char name[64];              // ENV_VAR_NAME
    uint8_t encrypted_value[256]; // Encrypted with container session key
    size_t encrypted_len;
} cyxhost_secret_env_t;

int cyxhost_inject_env_secret(cyxhost_container_t* container,
                               cyxhost_secret_env_t* secret) {
    // Decrypt with container's session key
    char plaintext[256];
    size_t plain_len;
    cyxwiz_crypto_decrypt(secret->encrypted_value, secret->encrypted_len,
                          container->session_key, plaintext, &plain_len);

    // Set in container's environment
    setenv_in_container(container, secret->name, plaintext, plain_len);

    // Zero plaintext immediately
    cyxwiz_secure_zero(plaintext, sizeof(plaintext));

    return CYXHOST_OK;
}
```

#### Mounted Secrets (File-based)
```c
// Secrets mounted as tmpfs files
typedef struct {
    char mount_path[128];       // /run/secrets/my-secret
    uint8_t encrypted_content[4096];
    size_t encrypted_len;
    mode_t file_mode;           // 0400 (owner read only)
} cyxhost_secret_file_t;

int cyxhost_mount_secret(cyxhost_container_t* container,
                         cyxhost_secret_file_t* secret) {
    // Create tmpfs for secrets
    char secrets_dir[256];
    snprintf(secrets_dir, sizeof(secrets_dir),
             "/run/cyxhost/%s/secrets", container->container_id);
    mount("tmpfs", secrets_dir, "tmpfs", 0, "size=1M,mode=0700");

    // Decrypt and write
    uint8_t plaintext[4096];
    size_t plain_len;
    cyxwiz_crypto_decrypt(secret->encrypted_content, secret->encrypted_len,
                          container->session_key, plaintext, &plain_len);

    char secret_path[384];
    snprintf(secret_path, sizeof(secret_path), "%s%s",
             secrets_dir, secret->mount_path);
    write_file_secure(secret_path, plaintext, plain_len, secret->file_mode);

    cyxwiz_secure_zero(plaintext, sizeof(plaintext));

    return CYXHOST_OK;
}
```

#### MPC-Protected Secrets (High Security)
```c
// For highest security: secret never assembled on host
// Container receives shares, computes using MPC
typedef struct {
    char secret_id[64];         // Identifier
    cyxwiz_share_t shares[5];   // K-of-N shares
    uint8_t threshold;          // K value
    uint8_t total_shares;       // N value
} cyxhost_mpc_secret_t;

// Container SDK provides helpers to use shares
// e.g., decrypt(data, mpc_secret) computes in MPC without revealing key
```

### Secret Lifecycle
```c
// Secrets auto-expire with container
int cyxhost_cleanup_secrets(cyxhost_container_t* container) {
    // 1. Overwrite secret files with zeros
    char secrets_dir[256];
    snprintf(secrets_dir, sizeof(secrets_dir),
             "/run/cyxhost/%s/secrets", container->container_id);
    secure_wipe_directory(secrets_dir);

    // 2. Unmount secrets tmpfs
    umount2(secrets_dir, MNT_DETACH);

    // 3. Zero secret env vars from memory
    // (handled by container termination)

    return CYXHOST_OK;
}
```

---

## Part 17: Emergency Termination

### Immediate Kill (Panic Button)
```c
// Force-kill with no cleanup - for security emergencies
int cyxhost_emergency_kill(const char* container_id, const char* reason) {
    // Log reason (but not container contents)
    log_error("EMERGENCY KILL: %s - %s", container_id, reason);

    // 1. Immediately kill all container processes
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path),
             "/sys/fs/cgroup/cyxhost/%s/cgroup.kill", container_id);
    write_file(cgroup_path, "1");  // cgroup v2 kill switch

    // 2. Disable network immediately
    char netns[128];
    snprintf(netns, sizeof(netns), "%s", container_id);
    ip_netns_delete(netns);

    // 3. Force unmount (even if busy)
    char overlay_path[256];
    snprintf(overlay_path, sizeof(overlay_path),
             "/run/cyxhost/%s/merged", container_id);
    umount2(overlay_path, MNT_FORCE | MNT_DETACH);

    // 4. Wipe RAM (best effort, may be incomplete if compromised)
    char tmpfs_path[256];
    snprintf(tmpfs_path, sizeof(tmpfs_path),
             "/run/cyxhost/%s/upper", container_id);
    sync();  // Flush buffers
    umount2(tmpfs_path, MNT_FORCE | MNT_DETACH);

    // 5. Notify validators and user
    cyxhost_report_emergency(container_id, reason);

    return CYXHOST_OK;
}
```

### Auto-Termination Triggers
```c
// Conditions that trigger automatic emergency termination
typedef enum {
    CYXHOST_TRIGGER_ESCAPE_DETECTED,    // Possible container escape
    CYXHOST_TRIGGER_RESOURCE_ABUSE,     // Extreme resource consumption
    CYXHOST_TRIGGER_NETWORK_ABUSE,      // DDoS or attack traffic
    CYXHOST_TRIGGER_ILLEGAL_CONTENT,    // Content policy violation
    CYXHOST_TRIGGER_HOST_COMPROMISE,    // Host itself compromised
    CYXHOST_TRIGGER_PAYMENT_FRAUD,      // Escrow manipulation detected
} cyxhost_termination_trigger_t;

// Monitoring daemon checks for triggers
void cyxhost_security_monitor(void) {
    for (int i = 0; i < active_container_count; i++) {
        cyxhost_container_t* c = &containers[i];

        // Check for escape attempts
        if (gvisor_escape_detected(c)) {
            cyxhost_emergency_kill(c->container_id, "escape_attempt");
            continue;
        }

        // Check for resource abuse
        if (c->cpu_usage > 200 * c->config.cpu_shares) {  // 200% of allocated
            cyxhost_emergency_kill(c->container_id, "resource_abuse");
            continue;
        }

        // Check for network abuse
        if (detect_attack_traffic(c)) {
            cyxhost_emergency_kill(c->container_id, "network_abuse");
            continue;
        }
    }
}
```

### Post-Termination Forensics (Optional)
```c
// Host can optionally preserve metadata (not content) for dispute resolution
typedef struct {
    char container_id[32];
    uint64_t termination_time;
    cyxhost_termination_trigger_t reason;
    uint8_t resource_snapshot[256];     // CPU/RAM/Net stats at termination
    uint8_t validator_report_hash[32];  // Hash of report sent to validators
} cyxhost_termination_record_t;

// Store encrypted with host key only (never content, only metadata)
void cyxhost_record_termination(cyxhost_container_t* container,
                                cyxhost_termination_trigger_t reason) {
    cyxhost_termination_record_t record;
    // ... fill record ...

    // Store locally for dispute resolution
    cyxhost_store_record(&record);
}
```
