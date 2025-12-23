# CyxWiz Protocol - Practical Tutorials

Real-world usage examples for the CyxWiz decentralized protocol.

---

## Table of Contents

1. [Setting Up Your Node](#1-setting-up-your-node)
2. [Anonymous Messaging](#2-anonymous-messaging)
3. [Distributed File Storage](#3-distributed-file-storage)
4. [Anonymous Data Routing](#4-anonymous-data-routing)
5. [Emergency Mesh Network](#5-emergency-mesh-network)
6. [Compute Job Marketplace](#6-compute-job-marketplace)

---

## 1. Setting Up Your Node

### Scenario
You want to run a CyxWiz node that can communicate with others over the internet or local mesh networks.

### Step-by-Step

**1.1 Build the Project**
```bash
git clone https://github.com/code3hr/conspiracy.git
cd conspiracy
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

**1.2 Basic Node Initialization**
```c
#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/crypto.h"

int main(void) {
    // Initialize crypto subsystem (required for secure operations)
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        printf("Failed to init crypto: %s\n", cyxwiz_strerror(err));
        return 1;
    }

    // Generate unique node identity
    cyxwiz_node_id_t my_id;
    cyxwiz_node_id_random(&my_id);

    char hex_id[65];
    cyxwiz_node_id_to_hex(&my_id, hex_id);
    printf("Node ID: %s\n", hex_id);

    // Create UDP transport for internet connectivity
    cyxwiz_transport_t *transport;
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        printf("Failed to create transport: %s\n", cyxwiz_strerror(err));
        return 1;
    }

    // Create peer table (tracks discovered peers)
    cyxwiz_peer_table_t *peers;
    cyxwiz_peer_table_create(&peers);

    // Create router (handles message routing)
    cyxwiz_router_t *router;
    cyxwiz_router_create(&router, peers, transport, &my_id);
    cyxwiz_router_start(router);

    printf("Node is running!\n");

    // Main loop
    bool running = true;
    while (running) {
        uint64_t now = cyxwiz_time_ms();
        cyxwiz_router_poll(router, now);
        cyxwiz_sleep_ms(100);
    }

    // Cleanup
    cyxwiz_router_stop(router);
    cyxwiz_router_destroy(router);
    cyxwiz_peer_table_destroy(peers);
    cyxwiz_transport_destroy(transport);

    return 0;
}
```

**1.3 Run the Built-In Daemon**
```bash
# Linux/macOS
./build/cyxwizd

# Windows
.\build\Release\cyxwizd.exe
```

---

## 2. Anonymous Messaging

### Scenario
You want to send messages that cannot be traced back to you. Intermediate nodes see only encrypted data and don't know who is talking to whom.

### How It Works
```
You → [Relay1] → [Relay2] → [Relay3] → Recipient

Each relay only knows:
- Who gave them the message (previous hop)
- Who to give it to next (next hop)

No relay knows both the sender AND recipient.
```

### Step-by-Step

**2.1 Set Up Onion Routing**
```c
#include "cyxwiz/onion.h"

// After creating router (from Section 1)...

// Create onion context for anonymous routing
cyxwiz_onion_ctx_t *onion;
err = cyxwiz_onion_create(&onion, router, &my_id);
if (err != CYXWIZ_OK) {
    printf("Failed to create onion context\n");
    return 1;
}

// Link router and onion context together
cyxwiz_router_set_onion_ctx(router, onion);

// Get our public key (share with others so they can message us)
uint8_t my_pubkey[32];
cyxwiz_onion_get_pubkey(onion, my_pubkey);
```

**2.2 Add Peer Keys (From Peer Discovery)**
```c
// When you discover a peer, add their public key
// This enables onion routing through them
cyxwiz_node_id_t peer_id = /* from discovery */;
uint8_t peer_pubkey[32] = /* from ANNOUNCE message */;

cyxwiz_onion_add_peer_key(onion, &peer_id, peer_pubkey);
```

**2.3 Send Anonymous Message (Simple API)**
```c
// NEW: Send anonymously with automatic circuit building
cyxwiz_node_id_t recipient_id = /* target node */;
uint8_t message[] = "Hello from the shadows!";

err = cyxwiz_router_send_anonymous(
    router,
    &recipient_id,
    message,
    sizeof(message)
);

if (err == CYXWIZ_OK) {
    printf("Message sent anonymously!\n");
} else if (err == CYXWIZ_ERR_NO_KEY) {
    printf("Need to exchange keys with destination first\n");
}
```

**2.4 Send Anonymous Message (Manual Circuit)**
```c
// For more control, build circuit manually

// Define path: relay1 → relay2 → destination
cyxwiz_node_id_t hops[3] = {relay1_id, relay2_id, destination_id};

// Build circuit
cyxwiz_circuit_t *circuit;
err = cyxwiz_onion_build_circuit(onion, hops, 3, &circuit);
if (err != CYXWIZ_OK) {
    printf("Failed to build circuit: %s\n", cyxwiz_strerror(err));
    return;
}

// Send through circuit (max 29 bytes for 3-hop)
uint8_t msg[] = "Secret message";
cyxwiz_onion_send(onion, circuit, msg, sizeof(msg));
```

**2.5 Receive Anonymous Messages**
```c
// Set up callback for incoming anonymous messages
void on_anon_message(const cyxwiz_node_id_t *from,
                     const uint8_t *data,
                     size_t len,
                     void *user_data) {
    // Note: 'from' is the last relay, not the original sender!
    // The sender is anonymous.
    printf("Received anonymous message: %.*s\n", (int)len, data);
}

cyxwiz_onion_set_callback(onion, on_anon_message, NULL);
```

### Payload Size Limits
| Hops | Max Payload |
|------|-------------|
| 1 | 173 bytes |
| 2 | 101 bytes |
| 3 | 29 bytes |

---

## 3. Distributed File Storage

### Scenario
You want to store a file across the network so that:
- No single node has the complete file
- File survives even if some nodes go offline
- Data is encrypted and split cryptographically

### How It Works
```
Your File
    │
    ▼
[Shamir Secret Sharing: Split into 5 shares]
    │
    ├──► Node 1: Share 1
    ├──► Node 2: Share 2
    ├──► Node 3: Share 3
    ├──► Node 4: Share 4
    └──► Node 5: Share 5

Reconstruction: Need any 3 of 5 shares
```

### Step-by-Step

**3.1 Create Storage Client**
```c
#include "cyxwiz/storage.h"

// Create storage client with 3-of-5 threshold
// (need 3 nodes to reconstruct, data survives 2 node failures)
cyxwiz_storage_client_t *storage;
err = cyxwiz_storage_client_create(&storage, router, 3, 5);

// Set callback for storage events
void on_store_complete(cyxwiz_storage_id_t *id, cyxwiz_error_t result, void *ctx) {
    if (result == CYXWIZ_OK) {
        printf("File stored successfully!\n");
    }
}
cyxwiz_storage_client_set_callback(storage, on_store_complete, NULL);
```

**3.2 Store a File**
```c
// Read file into memory
FILE *f = fopen("secret_document.pdf", "rb");
fseek(f, 0, SEEK_END);
size_t file_size = ftell(f);
fseek(f, 0, SEEK_SET);

uint8_t *file_data = malloc(file_size);
fread(file_data, 1, file_size, f);
fclose(f);

// Store with 1-hour TTL (3600 seconds)
cyxwiz_storage_id_t storage_id;
err = cyxwiz_storage_store(
    storage,
    file_data,
    file_size,
    3600,           // TTL in seconds
    &storage_id
);

// Save storage_id - you'll need it to retrieve the file
char id_hex[65];
cyxwiz_node_id_to_hex(&storage_id, id_hex);
printf("Storage ID: %s\n", id_hex);

free(file_data);
```

**3.3 Retrieve a File**
```c
uint8_t retrieved[MAX_FILE_SIZE];
size_t retrieved_len;

err = cyxwiz_storage_retrieve(
    storage,
    &storage_id,
    retrieved,
    &retrieved_len
);

if (err == CYXWIZ_OK) {
    FILE *out = fopen("retrieved_document.pdf", "wb");
    fwrite(retrieved, 1, retrieved_len, out);
    fclose(out);
    printf("File retrieved: %zu bytes\n", retrieved_len);
}
```

**3.4 Verify Storage (Proof of Storage)**
```c
// Challenge a provider to prove they still have your data
cyxwiz_proof_of_storage_challenge(storage, &storage_id, &provider_id);

// Result comes via callback
void on_proof_result(bool verified, void *ctx) {
    if (verified) {
        printf("Provider verified - they have the data\n");
    } else {
        printf("Verification failed - data may be lost!\n");
    }
}
```

---

## 4. Anonymous Data Routing

### Scenario
You want to send data to a destination but don't want intermediate nodes to know you're the sender.

### Problem with Regular Routing
```c
// Regular routing exposes sender!
typedef struct {
    uint8_t type;
    cyxwiz_node_id_t origin;  // <-- Everyone sees this!
    cyxwiz_node_id_t path[];  // <-- Full path exposed!
    ...
} cyxwiz_routed_data_t;
```

### Solution: Anonymous Send
```c
// NEW API: cyxwiz_router_send_anonymous()
// Uses onion routing to hide sender identity

err = cyxwiz_router_send_anonymous(
    router,
    &destination,
    data,
    data_len
);
```

### How It Differs

| Aspect | Regular Send | Anonymous Send |
|--------|-------------|----------------|
| Sender visible | Yes | No |
| Path visible | Yes | No |
| Max payload | 48 bytes | ~101 bytes (2-hop) |
| Speed | Fast | Slightly slower |
| Use case | Performance | Privacy |

### Step-by-Step

**4.1 Setup Anonymous Routing**
```c
// Same as Section 2 - create onion context
cyxwiz_onion_ctx_t *onion;
cyxwiz_onion_create(&onion, router, &my_id);
cyxwiz_router_set_onion_ctx(router, onion);

// Add peer keys from discovery
for (int i = 0; i < peer_count; i++) {
    cyxwiz_onion_add_peer_key(onion, &peers[i].id, peers[i].pubkey);
}
```

**4.2 Check If Anonymous Route Exists**
```c
if (cyxwiz_router_has_anonymous_route(router, &destination)) {
    printf("Circuit to destination exists\n");
} else {
    printf("Will build circuit on first send\n");
}
```

**4.3 Send Data Anonymously**
```c
// Send sensor reading without revealing sensor location
uint8_t sensor_data[] = {
    0x01,  // Sensor type
    0x42, 0x48,  // Temperature: 72F
    0x23, 0x00,  // Humidity: 35%
};

err = cyxwiz_router_send_anonymous(
    router,
    &data_collector_id,
    sensor_data,
    sizeof(sensor_data)
);

if (err == CYXWIZ_OK) {
    // Data sent - collector cannot identify which sensor
    printf("Sensor data sent anonymously\n");
}
```

---

## 5. Emergency Mesh Network

### Scenario
Internet infrastructure is down. You need to communicate with others using only local radio/WiFi/Bluetooth.

### Network Formation
```
[Your Device] ←── WiFi Direct ──► [Neighbor 1]
                                      │
                                      │ LoRa (10km range)
                                      ▼
                                [Remote Device]
                                      │
                                      │ Bluetooth
                                      ▼
                                [Another Device]
```

### Step-by-Step

**5.1 Create Multi-Transport Node**
```c
// Try transports in order of capability
cyxwiz_transport_t *transport = NULL;
cyxwiz_error_t err;

// Try WiFi Direct first (highest bandwidth)
err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
if (err != CYXWIZ_OK) {
    // Fall back to Bluetooth
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_BLUETOOTH, &transport);
}
if (err != CYXWIZ_OK) {
    // Fall back to LoRa (longest range)
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_LORA, &transport);
}

if (err != CYXWIZ_OK) {
    printf("No transport available!\n");
    return 1;
}
```

**5.2 Start Peer Discovery**
```c
#include "cyxwiz/peer.h"

cyxwiz_discovery_t *discovery;
cyxwiz_discovery_create(&discovery, peers, transport, &my_id);
cyxwiz_discovery_start(discovery);

// Discovery callback
void on_peer_discovered(const cyxwiz_node_id_t *peer_id,
                        int rssi, void *ctx) {
    char hex[65];
    cyxwiz_node_id_to_hex(peer_id, hex);
    printf("Found peer: %.16s... (signal: %d dBm)\n", hex, rssi);
}
cyxwiz_discovery_set_callback(discovery, on_peer_discovered, NULL);
```

**5.3 Send Emergency Message**
```c
// Messages fit in 250-byte LoRa packets
uint8_t emergency[] = "EMERGENCY: Need medical supplies at coordinates 40.7128,-74.0060";

// Send to known rescue coordinator
cyxwiz_router_send(router, &coordinator_id, emergency, sizeof(emergency));

// Or broadcast to all peers
cyxwiz_node_id_t broadcast;
memset(&broadcast, 0xFF, sizeof(broadcast));
cyxwiz_router_send(router, &broadcast, emergency, sizeof(emergency));
```

**5.4 Multi-Hop Message Relay**
```c
// Messages automatically relay through intermediate nodes
// Range: Node1 ←─100m─► Node2 ←─100m─► Node3

// Message from Node1 to Node3 goes:
// Node1 → Node2 → Node3

// The router handles this automatically via route discovery
cyxwiz_router_send(router, &node3_id, message, len);
// Router broadcasts ROUTE_REQ, gets ROUTE_REPLY with path,
// then sends ROUTE_DATA along the path
```

---

## 6. Compute Job Marketplace

### Scenario
You need to run a computation but don't have the hardware. You submit a job to the network, and a worker node executes it.

### How It Works
```
You (Client)                   Network                    Worker Node
     │                            │                            │
     │── JOB_SUBMIT ─────────────►│                            │
     │                            │── JOB_ANNOUNCE ───────────►│
     │                            │                            │
     │                            │◄── JOB_ACCEPT ─────────────│
     │◄── JOB_ACCEPTED ───────────│                            │
     │                            │                            │
     │── JOB_CHUNK (data) ───────►│─────────────────────────►│
     │                            │                            │
     │                            │       [Worker executes]    │
     │                            │                            │
     │◄── JOB_RESULT ─────────────│◄────────────────────────── │
     │   (with MAC verification)  │                            │
```

### Step-by-Step (Client Side)

**6.1 Create Compute Client**
```c
#include "cyxwiz/compute.h"

cyxwiz_compute_client_t *compute;
cyxwiz_compute_client_create(&compute, router);

// Set callback for results
void on_job_result(cyxwiz_job_id_t *job_id,
                   const uint8_t *result,
                   size_t result_len,
                   bool mac_valid,
                   void *ctx) {
    if (mac_valid) {
        printf("Job complete! Result verified.\n");
        // Process result...
    } else {
        printf("WARNING: Result MAC invalid - possible tampering!\n");
    }
}
cyxwiz_compute_client_set_callback(compute, on_job_result, NULL);
```

**6.2 Submit a Job**
```c
// Create job specification
cyxwiz_job_t job;
memset(&job, 0, sizeof(job));

job.type = CYXWIZ_JOB_TYPE_WASM;  // WebAssembly job
job.payload = wasm_bytecode;
job.payload_len = bytecode_len;
job.max_memory = 64 * 1024 * 1024;  // 64MB max
job.max_time_ms = 30000;             // 30 second timeout
job.reward = 100;                    // CYWZ tokens

// Submit to network
cyxwiz_job_id_t job_id;
err = cyxwiz_compute_submit(compute, &job, &job_id);

if (err == CYXWIZ_OK) {
    printf("Job submitted, waiting for worker...\n");
}
```

### Step-by-Step (Worker Side)

**6.3 Create Compute Worker**
```c
cyxwiz_compute_worker_t *worker;
cyxwiz_compute_worker_create(&worker, router);

// Configure capabilities
cyxwiz_worker_config_t config = {
    .max_memory = 128 * 1024 * 1024,  // Can handle 128MB jobs
    .supported_types = CYXWIZ_JOB_TYPE_WASM | CYXWIZ_JOB_TYPE_SCRIPT,
    .cpu_cores = 4,
};
cyxwiz_compute_worker_set_config(worker, &config);

// Job handler
cyxwiz_error_t on_job(const cyxwiz_job_t *job,
                      uint8_t *result,
                      size_t *result_len,
                      void *ctx) {
    // Execute the job...
    // Return result with automatic MAC
    return CYXWIZ_OK;
}
cyxwiz_compute_worker_set_handler(worker, on_job, NULL);

// Start accepting jobs
cyxwiz_compute_worker_start(worker);
```

---

## Common Patterns

### Error Handling
```c
cyxwiz_error_t err = cyxwiz_some_function(...);
if (err != CYXWIZ_OK) {
    printf("Error: %s\n", cyxwiz_strerror(err));
    // Handle error...
}
```

### Main Loop Pattern
```c
bool running = true;
while (running) {
    uint64_t now = cyxwiz_time_ms();

    // Poll all subsystems
    cyxwiz_discovery_poll(discovery, now);
    cyxwiz_router_poll(router, now);
    cyxwiz_onion_poll(onion, now);
    cyxwiz_storage_client_poll(storage, now);
    cyxwiz_compute_client_poll(compute, now);

    cyxwiz_sleep_ms(10);  // Don't busy-wait
}
```

### Cleanup Pattern
```c
// Cleanup in reverse order of creation
cyxwiz_compute_client_destroy(compute);
cyxwiz_storage_client_destroy(storage);
cyxwiz_onion_destroy(onion);
cyxwiz_discovery_destroy(discovery);
cyxwiz_router_stop(router);
cyxwiz_router_destroy(router);
cyxwiz_peer_table_destroy(peers);
cyxwiz_transport_destroy(transport);
```

---

## Troubleshooting

### "No shared key with peer"
You need to exchange keys before using onion routing:
```c
// Make sure to add peer keys from ANNOUNCE messages
cyxwiz_onion_add_peer_key(onion, &peer_id, peer_pubkey);
```

### "Packet too large"
Onion routing has payload limits. For 3-hop circuits, max is 29 bytes:
```c
// Use fewer hops for larger payloads
cyxwiz_node_id_t hops[2] = {relay, destination};  // 2 hops = 101 bytes max
```

### "Route discovery timeout"
The destination might be unreachable:
```c
// Check if route exists first
if (!cyxwiz_router_has_route(router, &destination)) {
    printf("No route to destination\n");
}
```

### "Onion context required"
For anonymous features, you need to set up the onion context:
```c
cyxwiz_onion_ctx_t *onion;
cyxwiz_onion_create(&onion, router, &my_id);
cyxwiz_router_set_onion_ctx(router, onion);
```

---

*Last updated: December 2024*
*Protocol version: 0.1.0*
