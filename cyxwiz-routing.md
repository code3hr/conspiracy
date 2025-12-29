# CyxWiz Node Discovery & Message Routing

## Overview

This document explains how nodes discover each other and how messages are delivered to specific recipients in the CyxWiz mesh network.

## Phase 1: Discovery - Finding Peers

When a node joins the network, it needs to find other nodes to connect with.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Peer Discovery Protocol                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Step 1: Node Joins Network                                             │
│  ───────────────────────────                                            │
│                                                                          │
│     New Node                    Existing Nodes                          │
│        │                             │                                  │
│        │  ANNOUNCE (broadcast)       │                                  │
│        │  ┌─────────────────────┐    │                                  │
│        │  │ type: ANNOUNCE      │    │                                  │
│        │  │ node_id: abc123...  │    │                                  │
│        │  │ pubkey: X25519 key  │────►  All nearby nodes hear this     │
│        │  │ capabilities: 0x07  │    │                                  │
│        │  └─────────────────────┘    │                                  │
│        │                             │                                  │
│        │  ANNOUNCE_ACK (unicast)     │                                  │
│        │◄─────────────────────────────│                                  │
│        │  ┌─────────────────────┐    │                                  │
│        │  │ type: ANNOUNCE_ACK  │    │                                  │
│        │  │ node_id: def456...  │    │                                  │
│        │  │ pubkey: their key   │    │  Each node responds             │
│        │  └─────────────────────┘    │                                  │
│        │                             │                                  │
│                                                                          │
│  After this exchange:                                                   │
│  • Both nodes know each other's ID                                      │
│  • Both have exchanged X25519 public keys                               │
│  • Shared secret computed (for onion encryption)                        │
│  • Both added to peer tables                                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Discovery Message Format

```c
// Announce message (37 bytes - fits in LoRa packet)
typedef struct {
    uint8_t type;               // CYXWIZ_DISC_ANNOUNCE
    cyxwiz_node_id_t node_id;   // 32-byte node identifier
    uint8_t pubkey[32];         // X25519 public key for encryption
    uint8_t capabilities;       // What this node can do
} cyxwiz_disc_announce_t;
```

### Capabilities Flags

```c
#define CYXWIZ_CAP_RELAY    (1 << 0)  // Can relay messages
#define CYXWIZ_CAP_STORAGE  (1 << 1)  // Provides storage
#define CYXWIZ_CAP_COMPUTE  (1 << 2)  // Provides compute
#define CYXWIZ_CAP_EXIT     (1 << 3)  // Is a relay/exit node
```

## Phase 2: Maintaining Connections

Once peers are discovered, connections must be maintained.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Keepalive & State                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Periodic Ping/Pong (every few seconds):                                │
│                                                                          │
│     Node A                         Node B                               │
│        │                              │                                 │
│        │──── PING ───────────────────►│                                 │
│        │◄─── PONG ────────────────────│                                 │
│        │                              │                                 │
│                                                                          │
│  Peer States:                                                           │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │  UNKNOWN ──► DISCOVERED ──► CONNECTING ──► CONNECTED           │    │
│  │                                               │                 │    │
│  │                                               ▼                 │    │
│  │                              DISCONNECTING ◄── (timeout/error)  │    │
│  │                                   │                             │    │
│  │                                   ▼                             │    │
│  │                                FAILED                           │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  Graceful Disconnect:                                                   │
│        │                              │                                 │
│        │──── GOODBYE ────────────────►│  "I'm leaving cleanly"         │
│        │                              │                                 │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Peer Table

```c
// Each node maintains a table of known peers
typedef struct {
    cyxwiz_node_id_t node_id;
    uint8_t state;              // CONNECTED, DISCOVERED, etc.
    uint8_t transport;          // How we reach them
    int8_t rssi;                // Signal strength
    uint64_t last_seen;         // Timestamp
    uint8_t pubkey[32];         // Their X25519 key
} cyxwiz_peer_t;

#define CYXWIZ_MAX_PEERS 64     // Max peers per node
#define CYXWIZ_PEER_TIMEOUT_MS 30000  // 30 seconds
```

## Phase 3: Route Discovery - Finding a Path

When you want to message someone not directly connected, you need to discover a route.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Route Discovery                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  You (A) want to reach Target (E), but you only know B and C directly  │
│                                                                          │
│       A ─── B ─── D ─── E                                               │
│       │           │                                                      │
│       └─── C ─────┘                                                      │
│                                                                          │
│  Step 1: Broadcast ROUTE_REQ                                            │
│  ────────────────────────────                                           │
│                                                                          │
│     A                    B              C              D              E │
│     │                    │              │              │              │ │
│     │─── ROUTE_REQ ─────►│              │              │              │ │
│     │    dest=E          │─── forward ─►│              │              │ │
│     │    hops=[A]        │   hops=[A,B] │─── forward ─►│              │ │
│     │                    │              │   hops=[A,C] │─── forward ─►│ │
│     │                    │              │              │   hops=[A,B,D]│ │
│     │                    │              │              │              │ │
│     │                    │              │              │   "That's me!"│ │
│     │                    │              │              │              │ │
│                                                                          │
│  Step 2: Target Sends ROUTE_REPLY (unicast back)                        │
│  ───────────────────────────────────────────                            │
│                                                                          │
│     A                    B              C              D              E │
│     │                    │              │              │              │ │
│     │◄── ROUTE_REPLY ────│◄─────────────│◄─────────────│◄─────────────│ │
│     │    path=[A,B,D,E]  │              │              │              │ │
│     │                    │              │              │              │ │
│     │  "To reach E, go through B, then D"                             │ │
│     │                    │              │              │              │ │
│                                                                          │
│  Route is now CACHED (expires after 60s)                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Route Request Message

```c
typedef struct {
    uint8_t type;               // CYXWIZ_MSG_ROUTE_REQ
    uint8_t seq;                // Sequence number (prevent loops)
    cyxwiz_node_id_t source;    // Who started the request
    cyxwiz_node_id_t dest;      // Who we're looking for
    uint8_t hop_count;          // How many hops so far
    cyxwiz_node_id_t hops[CYXWIZ_MAX_HOPS];  // Path so far
} cyxwiz_route_req_t;
```

### Route Caching

```c
// Routes are cached to avoid repeated discovery
typedef struct {
    cyxwiz_node_id_t destination;
    uint8_t hop_count;
    cyxwiz_node_id_t hops[CYXWIZ_MAX_HOPS];
    uint32_t latency_ms;
    uint64_t discovered_at;
} cyxwiz_route_t;

#define CYXWIZ_MAX_ROUTES 32
#define CYXWIZ_ROUTE_TIMEOUT_MS 60000  // Cache for 60 seconds
```

## Phase 4: Source Routing - Sending Messages

Once a route is known, messages include the full path in the header.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Source Routing                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Now A knows path to E is: A → B → D → E                                │
│                                                                          │
│  Message includes FULL PATH in header:                                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────┐           │
│  │  ROUTE_DATA Packet                                       │           │
│  ├─────────────────────────────────────────────────────────┤           │
│  │  destination: E                                          │           │
│  │  hop_count: 3                                            │           │
│  │  current_hop: 0                                          │           │
│  │  path: [B, D, E]                                         │           │
│  │  payload: "Hello E!"                                     │           │
│  └─────────────────────────────────────────────────────────┘           │
│                                                                          │
│     A                    B                    D                    E    │
│     │                    │                    │                    │    │
│     │─── ROUTE_DATA ────►│                    │                    │    │
│     │    path=[B,D,E]    │                    │                    │    │
│     │    hop=0           │                    │                    │    │
│     │                    │                    │                    │    │
│     │                    │─── ROUTE_DATA ────►│                    │    │
│     │                    │    path=[B,D,E]    │                    │    │
│     │                    │    hop=1           │                    │    │
│     │                    │                    │                    │    │
│     │                    │                    │─── ROUTE_DATA ────►│    │
│     │                    │                    │    path=[B,D,E]    │    │
│     │                    │                    │    hop=2           │    │
│     │                    │                    │                    │    │
│     │                    │                    │             "Hello E!"  │
│     │                    │                    │                    │    │
│                                                                          │
│  Each hop increments current_hop and forwards to path[current_hop]      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Routed Data Message

```c
typedef struct {
    uint8_t type;               // CYXWIZ_MSG_ROUTE_DATA
    cyxwiz_node_id_t dest;      // Final destination
    uint8_t hop_count;          // Total hops in path
    uint8_t current_hop;        // Current position in path
    cyxwiz_node_id_t path[CYXWIZ_MAX_HOPS];
    uint8_t payload[CYXWIZ_MAX_ROUTED_PAYLOAD];  // 48 bytes
    uint8_t payload_len;
} cyxwiz_routed_data_t;
```

## Phase 5: Onion Routing - Anonymous Messaging

For privacy, source routing exposes too much. Onion routing encrypts in layers.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Onion Routing                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Problem with source routing: Every hop sees the full path!             │
│  Solution: Encrypt in layers, each hop only sees NEXT hop               │
│                                                                          │
│  Building the Onion (sender side):                                      │
│  ─────────────────────────────────                                      │
│                                                                          │
│  Start with innermost layer:                                            │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Layer 3 (encrypt with E's key):                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │  "Hello E!" (plaintext for E only)                         │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Layer 2 (encrypt with D's key):                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │  next_hop: E                                               │  │   │
│  │  │  inner: [Layer 3 encrypted blob]                           │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Layer 1 (encrypt with B's key):                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │  next_hop: D                                               │  │   │
│  │  │  inner: [Layer 2 encrypted blob]                           │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Peeling the Onion

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Onion Peeling                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│     A                    B                    D                    E    │
│     │                    │                    │                    │    │
│     │─── [Layer1[Layer2[Layer3]]] ──────────►│                    │    │
│     │                    │                    │                    │    │
│     │           B decrypts Layer 1            │                    │    │
│     │           Sees: next_hop=D              │                    │    │
│     │           Sees: encrypted blob          │                    │    │
│     │           Does NOT see: E or message    │                    │    │
│     │                    │                    │                    │    │
│     │                    │─── [Layer2[Layer3]] ──────────────────►│    │
│     │                    │                    │                    │    │
│     │                    │           D decrypts Layer 2            │    │
│     │                    │           Sees: next_hop=E              │    │
│     │                    │           Does NOT see: message         │    │
│     │                    │                    │                    │    │
│     │                    │                    │─── [Layer3] ──────►│    │
│     │                    │                    │                    │    │
│     │                    │                    │    E decrypts      │    │
│     │                    │                    │    Sees: "Hello E!"│    │
│     │                    │                    │                    │    │
│                                                                          │
│  What each node knows:                                                  │
│  ─────────────────────                                                  │
│  • A knows: Sending to E (built the circuit)                           │
│  • B knows: Got from A, send to D (that's all!)                        │
│  • D knows: Got from B, send to E (that's all!)                        │
│  • E knows: Message is for me (doesn't know it came from A)            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Onion Layer Structure

```c
// Each layer when decrypted reveals:
typedef struct {
    cyxwiz_node_id_t next_hop;      // Who to forward to
    uint8_t inner_data[200];        // Encrypted blob for next hop
    uint8_t inner_len;
} cyxwiz_onion_layer_t;

// Encryption uses XChaCha20-Poly1305
// 24-byte nonce + 16-byte auth tag = 40 bytes overhead per layer
#define CYXWIZ_ONION_OVERHEAD 40
```

### Payload Capacity

Due to encryption overhead and 250-byte LoRa limit:

| Hops | Available Payload |
|------|-------------------|
| 1 hop | 173 bytes |
| 2 hops | 101 bytes |
| 3 hops | 29 bytes |

```c
#define CYXWIZ_MAX_ONION_HOPS 3  // Limited by packet size
```

## Code Implementation

### Discovery (src/core/discovery.c)

```c
// Broadcast announcement to find peers
int cyxwiz_discovery_announce(cyxwiz_discovery_t* discovery) {
    cyxwiz_disc_announce_t announce = {
        .type = CYXWIZ_DISC_ANNOUNCE,
        .node_id = discovery->local_id,
        .pubkey = discovery->pubkey,      // X25519 for onion routing
        .capabilities = CYXWIZ_CAP_ALL
    };
    return transport->ops->send(transport, BROADCAST, &announce, sizeof(announce));
}

// Handle incoming announcement
int cyxwiz_discovery_handle_announce(cyxwiz_discovery_t* discovery,
                                      const cyxwiz_disc_announce_t* announce) {
    // Add to peer table
    cyxwiz_peer_table_add(discovery->peers, &announce->node_id,
                          discovery->transport, 0);

    // Store their public key for onion routing
    cyxwiz_onion_add_peer_key(discovery->onion, &announce->node_id,
                               announce->pubkey);

    // Send acknowledgment
    return send_announce_ack(discovery, &announce->node_id);
}
```

### Route Discovery (src/core/routing.c)

```c
// Find route to destination
int cyxwiz_router_send(cyxwiz_router_t* router,
                        const cyxwiz_node_id_t* dest,
                        const uint8_t* data, size_t len) {
    // 1. Check if destination is direct neighbor
    if (cyxwiz_peer_table_find(router->peers, dest)) {
        return direct_send(router, dest, data, len);
    }

    // 2. Check route cache
    cyxwiz_route_t* route = find_cached_route(router, dest);
    if (route) {
        return send_via_route(router, route, data, len);
    }

    // 3. Discover route (broadcast ROUTE_REQ)
    queue_pending(router, dest, data, len);
    return broadcast_route_request(router, dest);
}

// Handle route reply - cache the discovered route
int cyxwiz_router_handle_reply(cyxwiz_router_t* router,
                                const cyxwiz_route_reply_t* reply) {
    cyxwiz_route_t route = {
        .destination = reply->destination,
        .hop_count = reply->hop_count,
        .discovered_at = now_ms()
    };
    memcpy(route.hops, reply->path, reply->hop_count * sizeof(cyxwiz_node_id_t));

    // Cache route
    cache_route(router, &route);

    // Send any pending messages
    flush_pending(router, &reply->destination);

    return CYXWIZ_OK;
}
```

### Onion Wrapping (src/core/onion.c)

```c
// Wrap message in onion layers
int cyxwiz_onion_wrap(const uint8_t* payload, size_t len,
                       const cyxwiz_node_id_t* hops,
                       const uint8_t (*keys)[32],
                       int hop_count,
                       uint8_t* out, size_t* out_len) {
    uint8_t buffer[250];
    size_t current_len = len;

    // Start with payload
    memcpy(buffer, payload, len);

    // Wrap from innermost to outermost
    for (int i = hop_count - 1; i >= 0; i--) {
        // Build layer: next_hop + current data
        uint8_t layer[250];
        memcpy(layer, &hops[i + 1], sizeof(cyxwiz_node_id_t));  // next hop
        memcpy(layer + 32, buffer, current_len);

        // Encrypt with this hop's key (XChaCha20-Poly1305)
        size_t encrypted_len;
        cyxwiz_crypto_encrypt(layer, 32 + current_len, keys[i],
                               buffer, &encrypted_len);
        current_len = encrypted_len;
    }

    memcpy(out, buffer, current_len);
    *out_len = current_len;
    return CYXWIZ_OK;
}

// Unwrap one layer (called by each hop)
int cyxwiz_onion_unwrap(const uint8_t* onion, size_t len,
                         const uint8_t* key,
                         cyxwiz_node_id_t* next_hop,
                         uint8_t* inner, size_t* inner_len) {
    uint8_t decrypted[250];
    size_t dec_len;

    // Decrypt this layer
    int err = cyxwiz_crypto_decrypt(onion, len, key, decrypted, &dec_len);
    if (err != CYXWIZ_OK) return err;

    // Extract next hop (first 32 bytes)
    memcpy(next_hop, decrypted, sizeof(cyxwiz_node_id_t));

    // Rest is inner onion for next hop
    *inner_len = dec_len - 32;
    memcpy(inner, decrypted + 32, *inner_len);

    return CYXWIZ_OK;
}
```

## Complete Message Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Complete Message Flow                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. DISCOVERY (happens once when joining network)                       │
│     ──────────────────────────────────────────                          │
│     Alice broadcasts ANNOUNCE, learns about nearby nodes                │
│     Exchanges X25519 keys with each peer                                │
│     Builds peer table with states and capabilities                      │
│                                                                          │
│  2. ROUTE DISCOVERY (happens once per destination, cached)              │
│     ───────────────────────────────────────────────────                 │
│     Alice broadcasts ROUTE_REQ for Bob                                  │
│     Request floods through network (with loop prevention)               │
│     Bob responds with ROUTE_REPLY containing path                       │
│     Alice caches: "To reach Bob: go through X, Y, Z"                    │
│     Cache expires after 60 seconds                                      │
│                                                                          │
│  3. CIRCUIT BUILDING (for anonymous messaging)                          │
│     ─────────────────────────────────────────                           │
│     Alice selects hops (e.g., 3 nodes from route)                       │
│     Computes shared secrets with each hop (from discovery keys)         │
│     Shared secret = DH(alice_privkey, hop_pubkey)                       │
│                                                                          │
│  4. MESSAGE SENDING                                                      │
│     ────────────────                                                    │
│     Alice wraps message in onion layers (innermost to outermost)        │
│     Sends to first hop                                                  │
│     Each hop:                                                           │
│       - Decrypts their layer                                            │
│       - Sees only next_hop + encrypted blob                             │
│       - Forwards to next_hop                                            │
│     Bob receives and decrypts final layer                               │
│                                                                          │
│  Result:                                                                │
│  ───────                                                                │
│  • Bob gets message                                                     │
│  • No intermediate node knows both Alice AND Bob                        │
│  • No central server involved                                           │
│  • Works even without internet (WiFi Direct, Bluetooth, LoRa)           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## NAT Traversal (Internet/UDP Transport)

When using the internet, most nodes are behind NAT (Network Address Translation) routers. This creates a problem: nodes can't receive incoming connections.

### The NAT Problem

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NAT Problem                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Alice (behind NAT)              Bob (behind NAT)                       │
│                                                                          │
│  ┌─────────┐    ┌─────────┐      ┌─────────┐    ┌─────────┐            │
│  │  Alice  │    │  NAT    │      │  NAT    │    │   Bob   │            │
│  │192.168.1.5│──►│Router   │      │Router   │◄───│192.168.2.10│         │
│  └─────────┘    │1.2.3.4  │      │5.6.7.8  │    └─────────┘            │
│                 └─────────┘      └─────────┘                            │
│                      │                │                                  │
│                      │   Internet     │                                  │
│                      │                │                                  │
│                                                                          │
│  Problem:                                                               │
│  • Alice knows her IP as 192.168.1.5 (private, not routable)           │
│  • Bob knows his IP as 192.168.2.10 (private, not routable)            │
│  • Neither can directly reach each other                                │
│  • NAT blocks incoming connections by default                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Solution: STUN + UDP Hole Punching

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NAT Traversal Solution                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Step 1: STUN - Discover Public Address                                 │
│  ──────────────────────────────────────                                 │
│                                                                          │
│     Alice                   STUN Server                                 │
│        │                         │                                      │
│        │─── "What's my IP?" ────►│  (stun.l.google.com:19302)          │
│        │◄── "You're 1.2.3.4:5678"│                                      │
│        │                         │                                      │
│                                                                          │
│  Alice now knows:                                                       │
│  • Public IP: 1.2.3.4                                                   │
│  • Public Port: 5678 (assigned by NAT)                                  │
│                                                                          │
│  Step 2: Exchange via Bootstrap Server                                  │
│  ─────────────────────────────────────                                  │
│                                                                          │
│     Alice             Bootstrap             Bob                         │
│        │                  │                  │                          │
│        │── Register ─────►│                  │                          │
│        │   1.2.3.4:5678   │                  │                          │
│        │                  │◄── Register ─────│                          │
│        │                  │    5.6.7.8:9012  │                          │
│        │                  │                  │                          │
│        │◄── Peer List ────│                  │                          │
│        │   Bob@5.6.7.8:9012                  │                          │
│        │                  │                  │                          │
│                                                                          │
│  Step 3: UDP Hole Punching                                              │
│  ─────────────────────────                                              │
│                                                                          │
│     Alice                                   Bob                         │
│        │                                     │                          │
│        │──── UDP to 5.6.7.8:9012 ───────────►│  (may be dropped)       │
│        │                                     │                          │
│        │◄─── UDP to 1.2.3.4:5678 ────────────│  (may be dropped)       │
│        │                                     │                          │
│        │  Both NATs now have "holes" for each other                    │
│        │                                     │                          │
│        │──── UDP to 5.6.7.8:9012 ───────────►│  (SUCCESS!)             │
│        │◄─── UDP to 1.2.3.4:5678 ────────────│  (SUCCESS!)             │
│        │                                     │                          │
│        │  Direct P2P connection established!                           │
│        │                                     │                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UDP Hole Punching Explained                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Why does this work?                                                    │
│                                                                          │
│  1. When Alice sends UDP to Bob:                                        │
│     • Alice's NAT creates mapping: 192.168.1.5:X → 1.2.3.4:5678        │
│     • NAT remembers: "if response comes from 5.6.7.8, let it through"  │
│                                                                          │
│  2. When Bob sends UDP to Alice:                                        │
│     • Bob's NAT creates mapping: 192.168.2.10:Y → 5.6.7.8:9012         │
│     • NAT remembers: "if response comes from 1.2.3.4, let it through"  │
│                                                                          │
│  3. Now both NATs have "holes":                                         │
│     • Alice's NAT allows traffic from 5.6.7.8 → 1.2.3.4:5678           │
│     • Bob's NAT allows traffic from 1.2.3.4 → 5.6.7.8:9012             │
│                                                                          │
│  4. Direct P2P communication works!                                     │
│     • No relay needed                                                   │
│     • Bootstrap server only used for discovery                          │
│     • All traffic is direct peer-to-peer                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Code Implementation (src/transport/udp.c)

```c
// STUN servers used for NAT discovery
static const char* stun_servers[] = {
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    NULL
};

// Discover our public IP via STUN
int cyxwiz_udp_stun_discover(cyxwiz_udp_t* udp) {
    // Send STUN binding request
    uint8_t request[20];
    stun_build_binding_request(request);

    for (int i = 0; stun_servers[i]; i++) {
        sendto(udp->sock, request, 20, 0, stun_servers[i]);

        // Wait for response
        uint8_t response[100];
        int len = recvfrom(udp->sock, response, 100, 0, NULL, NULL);

        if (len > 0 && stun_parse_response(response, len,
                                            &udp->public_ip,
                                            &udp->public_port) == 0) {
            return CYXWIZ_OK;  // Got our public address
        }
    }
    return CYXWIZ_STUN_FAILED;
}

// Perform hole punching to reach peer
int cyxwiz_udp_hole_punch(cyxwiz_udp_t* udp,
                           const char* peer_ip, uint16_t peer_port) {
    struct sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr);

    // Send punch packets (some may be dropped, that's OK)
    uint8_t punch[4] = {0x00, 0x00, 0x00, 0x00};  // Empty punch packet

    for (int i = 0; i < 5; i++) {
        sendto(udp->sock, punch, 4, 0,
               (struct sockaddr*)&peer_addr, sizeof(peer_addr));
        usleep(100000);  // 100ms between punches
    }

    return CYXWIZ_OK;
}
```

### Bootstrap Server

The bootstrap server helps peers find each other initially:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Bootstrap Server                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  What it does:                                                          │
│  • Maintains list of active peers and their public addresses            │
│  • Helps new nodes discover existing network                            │
│  • Facilitates initial hole punching                                    │
│                                                                          │
│  What it DOESN'T do:                                                    │
│  • Route messages (peers talk directly after hole punch)               │
│  • Store any message content                                            │
│  • Know who talks to whom (just knows who's online)                    │
│                                                                          │
│  Environment variable to set bootstrap:                                 │
│  CYXWIZ_BOOTSTRAP=bootstrap.cyxwiz.net:19850                           │
│                                                                          │
│  Multiple bootstraps for redundancy:                                   │
│  • bootstrap1.cyxwiz.net                                               │
│  • bootstrap2.cyxwiz.net                                               │
│  • Or run your own!                                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### NAT Types and Success Rate

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NAT Type Compatibility                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  NAT Type            Description                Success Rate            │
│  ────────            ───────────                ────────────            │
│                                                                          │
│  Full Cone           Any external host can      ~100%                   │
│                      send to mapped port                                │
│                                                                          │
│  Restricted Cone     External host must have    ~90%                    │
│                      received packet first                              │
│                                                                          │
│  Port Restricted     External host:port must    ~80%                    │
│                      have received packet first                         │
│                                                                          │
│  Symmetric           Different mapping for      ~60% (need relay)       │
│                      each destination                                   │
│                                                                          │
│  Most home routers: Restricted Cone or Port Restricted                  │
│  Corporate firewalls: Often Symmetric (harder to punch)                │
│                                                                          │
│  Fallback: If hole punching fails, use CyxRelay node                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Fallback to Relay

When direct connection fails (symmetric NAT, strict firewalls):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Relay Fallback                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  If hole punching fails after several attempts:                         │
│                                                                          │
│     Alice                   Relay Node                   Bob            │
│        │                        │                         │             │
│        │─── Connect ───────────►│                         │             │
│        │                        │◄─── Connect ────────────│             │
│        │                        │                         │             │
│        │─── [Onion Msg] ───────►│─── [Onion Msg] ────────►│             │
│        │                        │                         │             │
│        │◄─── [Onion Msg] ───────│◄─── [Onion Msg] ────────│             │
│        │                        │                         │             │
│                                                                          │
│  Relay sees:                                                            │
│  • Two connections (doesn't know they're related)                       │
│  • Encrypted blobs (onion routing still applies!)                       │
│  • Cannot read content                                                  │
│                                                                          │
│  Trade-off:                                                             │
│  • Slightly higher latency                                              │
│  • Still end-to-end encrypted                                           │
│  • Still anonymous (onion layers)                                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Transport Independence

All of this works over any transport:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Transport Options                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Transport        Range        Internet?    Packet Size    Use Case     │
│  ─────────        ─────        ─────────    ───────────    ────────     │
│                                                                          │
│  WiFi Direct      ~100m        No           1400 bytes     Indoor       │
│  Bluetooth        ~10m         No           672 bytes      Close        │
│  LoRa             ~10km        No           250 bytes      Rural        │
│  UDP/Internet     Global       Yes          1400 bytes     Normal       │
│                                                                          │
│  Protocol layer is transport-agnostic:                                  │
│  • Same discovery messages                                              │
│  • Same routing logic                                                   │
│  • Same onion encryption                                                │
│  • Just different underlying send/receive                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Constants

```c
// Discovery
#define CYXWIZ_DISCOVERY_INTERVAL_MS  5000   // Announce every 5s
#define CYXWIZ_PEER_TIMEOUT_MS        30000  // Peer dead after 30s silence

// Routing
#define CYXWIZ_MAX_HOPS               5      // Max hops in route
#define CYXWIZ_MAX_ROUTES             32     // Cached routes
#define CYXWIZ_ROUTE_TIMEOUT_MS       60000  // Route cache TTL

// Onion
#define CYXWIZ_MAX_ONION_HOPS         3      // Privacy vs payload tradeoff
#define CYXWIZ_CIRCUIT_TIMEOUT_MS     60000  // Circuit cache TTL
#define CYXWIZ_ONION_OVERHEAD         40     // Bytes per layer (nonce + tag)
```

## Summary

| Phase | Purpose | Messages |
|-------|---------|----------|
| Discovery | Find peers | ANNOUNCE, ANNOUNCE_ACK, PING, PONG, GOODBYE |
| Route Discovery | Find path to destination | ROUTE_REQ, ROUTE_REPLY, ROUTE_ERROR |
| Source Routing | Send via known path | ROUTE_DATA |
| Onion Routing | Anonymous delivery | ONION_DATA |

The key insight: **Discovery happens locally, routes are discovered on-demand, and onion routing ensures no single node knows both sender and receiver.**
