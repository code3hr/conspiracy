# CyxHost: Decentralized Web Hosting Protocol

## Design Document v1.0

---

## Executive Summary

CyxHost extends the CyxWiz Protocol to enable **decentralized web hosting** where anyone can:
- **Host services** on their PC and earn work credits
- **Access services** anonymously through the mesh network
- **Publish content** without revealing their identity or location

The network's existing security infrastructure (onion routing, anonymous credentials, consensus) provides the foundation for a censorship-resistant hosting layer.

---

## Problem Statement

### Current Web Hosting Challenges

```
Traditional Hosting:
├── Centralized servers → Single point of failure
├── IP addresses exposed → DDoS targets, legal threats
├── Identity required → No anonymous publishing
├── Censorship possible → Takedowns, domain seizures
├── Vendor lock-in → AWS, Cloudflare control
└── Privacy violations → User tracking, logs
```

### CyxHost Solution

```
Decentralized Hosting:
├── Distributed across peers → No single point of failure
├── Onion routing → Host/client IPs hidden
├── Anonymous credentials → Publish without identity
├── Censorship resistant → No central authority
├── No vendor lock-in → Run on any device
└── Privacy by design → No logs, no tracking
```

---

## Architecture Overview

### System Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                            │
│                                                                      │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│   │  Web Browser │  │   CLI Tool   │  │   REST API   │             │
│   │   + Proxy    │  │  cyxhost-cli │  │   Client     │             │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│          └─────────────────┼─────────────────┘                      │
│                            ▼                                         │
├─────────────────────────────────────────────────────────────────────┤
│                         CYXHOST PROTOCOL                             │
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    Service Registry                          │   │
│   │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │   │
│   │  │my-blog  │  │ api-v1  │  │ files   │  │  chat   │        │   │
│   │  │ 3 hosts │  │ 5 hosts │  │ 2 hosts │  │ 1 host  │        │   │
│   │  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   ┌──────────────────┐  ┌──────────────────┐                        │
│   │   Host Manager   │  │  Client Manager  │                        │
│   │  - Registration  │  │  - Discovery     │                        │
│   │  - HTTP Proxy    │  │  - Load Balance  │                        │
│   │  - Health Check  │  │  - Retry Logic   │                        │
│   └────────┬─────────┘  └────────┬─────────┘                        │
│            └──────────┬──────────┘                                   │
│                       ▼                                              │
├─────────────────────────────────────────────────────────────────────┤
│                      CYXWIZ INFRASTRUCTURE                           │
│                                                                      │
│   ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│   │  Onion    │  │  Storage  │  │ Consensus │  │  Privacy  │       │
│   │  Routing  │  │ (Session) │  │(Validate) │  │  (Creds)  │       │
│   └───────────┘  └───────────┘  └───────────┘  └───────────┘       │
│                                                                      │
│   ┌───────────┐  ┌───────────┐  ┌───────────┐                       │
│   │   Peer    │  │  Router   │  │ Transport │                       │
│   │  Discovery│  │  (Mesh)   │  │   (UDP)   │                       │
│   └───────────┘  └───────────┘  └───────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
                    CLIENT                                    HOST
                      │                                         │
                      │  1. SERVICE_QUERY("my-blog")           │
                      ├────────────────────────────────────────►│
                      │                                         │
                      │  2. SERVICE_ANNOUNCE(host_info)         │
                      │◄────────────────────────────────────────┤
                      │                                         │
                      │  3. Build onion circuit to host         │
                      │         (3-hop encrypted)               │
                      │                                         │
                      │  4. SERVICE_REQUEST(GET /index.html)    │
                      ├═══════════════════════════════════════►│
                      │     [Onion Layer 1]                     │
                      │        [Onion Layer 2]                  │
                      │           [Onion Layer 3]               │ 5. Proxy to
                      │              [HTTP Request]─────────────┼──►localhost:8080
                      │                                         │
                      │  6. SERVICE_RESPONSE(200 OK, html)      │◄── Local server
                      │◄═══════════════════════════════════════┤
                      │     [Reply via SURB - anonymous]        │
                      │                                         │
```

---

## Protocol Specification

### Message Types (0x80-0x8F)

| Code | Name | Direction | Size | Description |
|------|------|-----------|------|-------------|
| 0x80 | SERVICE_REGISTER | Host→Network | 128 | Register service |
| 0x81 | SERVICE_UNREGISTER | Host→Network | 40 | Stop hosting |
| 0x82 | SERVICE_QUERY | Client→Network | 48 | Find service hosts |
| 0x83 | SERVICE_ANNOUNCE | Host→Client | 96 | Advertise availability |
| 0x84 | SERVICE_REQUEST | Client→Host | var | HTTP request |
| 0x85 | SERVICE_RESPONSE | Host→Client | var | HTTP response |
| 0x86 | SERVICE_STREAM_START | Either | 64 | Begin streaming |
| 0x87 | SERVICE_STREAM_CHUNK | Either | var | Stream data |
| 0x88 | SERVICE_STREAM_END | Either | 32 | End streaming |
| 0x89 | SERVICE_HEALTH | Network→Host | 32 | Health probe |
| 0x8A | SERVICE_HEALTH_ACK | Host→Network | 32 | Health response |
| 0x8B | SERVICE_RATING | Client→Network | 64 | Rate service |
| 0x8C | SERVICE_STATS | Host→Network | 96 | Usage statistics |

### Message Structures

```c
/* Service Registration (128 bytes) */
typedef struct {
    uint8_t type;                    /* 0x80 */
    uint8_t service_name[32];        /* Service identifier */
    uint8_t service_type;            /* HTTP, TCP, UDP, CUSTOM */
    uint16_t local_port;             /* Port on host machine */
    uint16_t max_connections;        /* Concurrent limit */
    uint8_t flags;                   /* REQUIRE_PAYMENT, ANONYMOUS_ONLY, etc */
    uint16_t credits_per_request;    /* Cost in work credits */
    uint64_t ttl;                    /* Registration lifetime */
    cyxwiz_cred_show_proof_t proof;  /* Anonymous host credential (112 bytes) */
} cyxwiz_service_register_msg_t;

/* Service Query (48 bytes) */
typedef struct {
    uint8_t type;                    /* 0x82 */
    uint8_t service_name[32];        /* Service to find */
    uint8_t flags;                   /* PREFER_LOW_LATENCY, PREFER_FREE, etc */
    uint8_t max_results;             /* How many hosts to return */
    uint8_t nonce[14];               /* Prevent replay */
} cyxwiz_service_query_msg_t;

/* Service Announce (96 bytes) */
typedef struct {
    uint8_t type;                    /* 0x83 */
    uint8_t service_name[32];        /* Service identifier */
    cyxwiz_node_id_t host_id;        /* Host's node ID (for routing) */
    uint8_t host_pubkey[32];         /* X25519 for onion circuit */
    uint16_t credits_per_request;    /* Cost */
    uint16_t current_connections;    /* Load info */
    uint16_t max_connections;
    uint8_t latency_ms;              /* Average response time */
    uint8_t uptime_percent;          /* Reliability */
    uint8_t flags;
    uint8_t reserved[5];
} cyxwiz_service_announce_msg_t;

/* Service Request (variable, up to MTU) */
typedef struct {
    uint8_t type;                    /* 0x84 */
    uint8_t request_id[8];           /* Correlation ID */
    uint8_t service_name[32];        /* Target service */
    uint16_t payload_len;            /* HTTP request length */
    uint8_t payload[];               /* HTTP request bytes */
    /* Followed by SURB for anonymous reply */
} cyxwiz_service_request_msg_t;

/* Service Response (variable, up to MTU) */
typedef struct {
    uint8_t type;                    /* 0x85 */
    uint8_t request_id[8];           /* Correlation ID */
    uint16_t status_code;            /* HTTP status */
    uint16_t payload_len;            /* HTTP response length */
    uint8_t payload[];               /* HTTP response bytes */
} cyxwiz_service_response_msg_t;
```

### Service Types

```c
typedef enum {
    CYXWIZ_SERVICE_HTTP = 0x01,      /* HTTP/HTTPS proxy */
    CYXWIZ_SERVICE_TCP = 0x02,       /* Raw TCP tunnel */
    CYXWIZ_SERVICE_UDP = 0x03,       /* Raw UDP tunnel */
    CYXWIZ_SERVICE_WEBSOCKET = 0x04, /* WebSocket support */
    CYXWIZ_SERVICE_CUSTOM = 0xFF     /* Custom protocol */
} cyxwiz_service_type_t;
```

### Service Flags

```c
#define CYXWIZ_SERVICE_REQUIRE_PAYMENT    0x01  /* Must pay credits */
#define CYXWIZ_SERVICE_ANONYMOUS_ONLY     0x02  /* Reject identified requests */
#define CYXWIZ_SERVICE_VERIFIED_HOST      0x04  /* Host verified by consensus */
#define CYXWIZ_SERVICE_STREAMING          0x08  /* Supports streaming */
#define CYXWIZ_SERVICE_PRIVATE            0x10  /* Invite-only access */
```

---

## Component Design

### 1. Service Registry

The registry is **distributed** - no central server. Each node maintains a local cache of known services.

```c
/* Local service registry */
typedef struct {
    /* Services this node hosts */
    cyxwiz_hosted_service_t hosted[CYXWIZ_MAX_HOSTED_SERVICES];
    size_t hosted_count;

    /* Known services on the network */
    cyxwiz_service_entry_t known[CYXWIZ_MAX_KNOWN_SERVICES];
    size_t known_count;

    /* Query callbacks */
    cyxwiz_service_found_cb_t on_service_found;
    void *user_data;
} cyxwiz_service_registry_t;

/* Service entry in registry */
typedef struct {
    char name[33];                   /* Service name */
    cyxwiz_node_id_t hosts[8];       /* Known hosts (max 8 per service) */
    uint8_t host_pubkeys[8][32];     /* Host X25519 keys */
    uint16_t host_credits[8];        /* Cost per request */
    uint8_t host_count;
    uint64_t last_updated;
    uint8_t reputation[8];           /* 0-100 per host */
} cyxwiz_service_entry_t;
```

**Discovery Protocol:**

```
1. Client broadcasts SERVICE_QUERY to peers
2. Peers check local registry and forward query
3. Hosts respond with SERVICE_ANNOUNCE
4. Client caches multiple hosts for load balancing
5. Registry entries expire after TTL (default: 5 minutes)
```

### 2. Host Manager

```c
typedef struct {
    cyxwiz_router_t *router;
    cyxwiz_consensus_ctx_t *consensus;
    cyxwiz_service_registry_t *registry;

    /* Local services */
    struct {
        char name[33];
        uint16_t local_port;
        cyxwiz_service_type_t type;
        uint16_t credits_per_request;
        uint64_t requests_served;
        uint64_t credits_earned;
        bool active;
    } services[CYXWIZ_MAX_HOSTED_SERVICES];
    size_t service_count;

    /* Connection tracking */
    cyxwiz_host_connection_t connections[256];
    size_t connection_count;

    /* Credential for anonymous hosting */
    cyxwiz_credential_t host_credential;
} cyxwiz_host_ctx_t;
```

**Host API:**

```c
/* Create host context */
cyxwiz_error_t cyxwiz_host_create(
    cyxwiz_host_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_consensus_ctx_t *consensus);

/* Register a service */
cyxwiz_error_t cyxwiz_host_register(
    cyxwiz_host_ctx_t *ctx,
    const char *service_name,
    cyxwiz_service_type_t type,
    uint16_t local_port,
    uint16_t credits_per_request,
    const cyxwiz_credential_t *host_cred);

/* Unregister a service */
cyxwiz_error_t cyxwiz_host_unregister(
    cyxwiz_host_ctx_t *ctx,
    const char *service_name);

/* Start serving (call in main loop) */
cyxwiz_error_t cyxwiz_host_poll(
    cyxwiz_host_ctx_t *ctx,
    uint64_t now_ms);

/* Get statistics */
cyxwiz_error_t cyxwiz_host_stats(
    cyxwiz_host_ctx_t *ctx,
    const char *service_name,
    cyxwiz_host_stats_t *stats);
```

### 3. Client Manager

```c
typedef struct {
    cyxwiz_router_t *router;
    cyxwiz_onion_ctx_t *onion;
    cyxwiz_service_registry_t *registry;

    /* Pending requests */
    struct {
        uint8_t request_id[8];
        char service_name[33];
        cyxwiz_circuit_t *circuit;
        cyxwiz_service_response_cb_t callback;
        void *user_data;
        uint64_t sent_at;
        uint8_t retries;
    } pending[64];
    size_t pending_count;

    /* Circuit cache per service */
    struct {
        char service_name[33];
        cyxwiz_circuit_t *circuits[4];
        uint8_t circuit_count;
    } circuit_cache[16];
} cyxwiz_host_client_t;
```

**Client API:**

```c
/* Create client context */
cyxwiz_error_t cyxwiz_host_client_create(
    cyxwiz_host_client_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_onion_ctx_t *onion);

/* Discover hosts for a service */
cyxwiz_error_t cyxwiz_host_query(
    cyxwiz_host_client_t *ctx,
    const char *service_name,
    cyxwiz_service_found_cb_t callback,
    void *user_data);

/* Send HTTP request to service */
cyxwiz_error_t cyxwiz_host_request(
    cyxwiz_host_client_t *ctx,
    const char *service_name,
    const char *method,
    const char *path,
    const char *headers,
    const uint8_t *body,
    size_t body_len,
    cyxwiz_service_response_cb_t callback,
    void *user_data);

/* Simplified GET request */
cyxwiz_error_t cyxwiz_host_get(
    cyxwiz_host_client_t *ctx,
    const char *service_name,
    const char *path,
    cyxwiz_service_response_cb_t callback,
    void *user_data);
```

### 4. HTTP Proxy

The host runs a local proxy that:
1. Receives `SERVICE_REQUEST` from network
2. Decodes HTTP request from payload
3. Forwards to local HTTP server
4. Encodes response as `SERVICE_RESPONSE`
5. Sends back via SURB (anonymous)

```c
/* Internal proxy connection */
typedef struct {
    int socket_fd;                   /* TCP connection to local server */
    uint8_t request_id[8];           /* For response correlation */
    cyxwiz_node_id_t client_id;      /* For direct reply (if not anonymous) */
    uint8_t surb[CYXWIZ_SURB_SIZE];  /* For anonymous reply */
    bool use_surb;
    uint64_t started_at;

    /* Buffering for large responses */
    uint8_t response_buffer[65536];
    size_t response_len;
    bool streaming;
} cyxwiz_proxy_connection_t;
```

---

## Security Model

### Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| **Host IP exposure** | Onion routing hides host behind 3+ relays |
| **Client tracking** | SURB replies prevent host from learning client |
| **Service enumeration** | Query flood protection, rate limiting |
| **DDoS on host** | Work credit requirement, connection limits |
| **Malicious host** | Reputation system, consensus validation |
| **Content censorship** | No central registry, P2P discovery |
| **Sybil attack** | Work credit staking required to host |

### Authentication Flow

```
Host Registration:
1. Host obtains HOST_ELIGIBLE credential from network
2. Credential proves: "I have X work credits staked"
3. Registration includes credential show proof
4. Network validates proof without learning host identity

Client Request:
1. Client discovers host via SERVICE_ANNOUNCE
2. Builds onion circuit to host (3 hops)
3. Request includes SURB for anonymous reply
4. Host processes request, replies via SURB
5. Neither party learns the other's identity
```

### Work Credit Economics

```
Hosting costs work credits (anti-spam):
- Register service: 10 credits (stake)
- Per request served: +1 credit (earn)
- Bandwidth used: -0.1 credits per KB

Accessing costs work credits:
- Per request: 1-10 credits (set by host)
- Free tier: Hosts can waive payment
```

---

## Implementation Plan

### Phase 1: Core Protocol (2 weeks)
- [ ] Message type definitions (0x80-0x8C)
- [ ] Service registry data structures
- [ ] Basic SERVICE_REGISTER/QUERY/ANNOUNCE handlers
- [ ] Unit tests for protocol layer

### Phase 2: Host Manager (2 weeks)
- [ ] Host context and API
- [ ] Local service registration
- [ ] SERVICE_REQUEST handler
- [ ] HTTP proxy to localhost
- [ ] Health check responder

### Phase 3: Client Manager (2 weeks)
- [ ] Client context and API
- [ ] Service discovery with caching
- [ ] Circuit building for hosts
- [ ] Request/response with SURB
- [ ] Retry and timeout logic

### Phase 4: Integration (1 week)
- [ ] Daemon integration (cyxwizd)
- [ ] CLI tool (cyxhost-cli)
- [ ] End-to-end testing
- [ ] Documentation

### Phase 5: Advanced Features (2 weeks)
- [ ] Streaming support (SERVICE_STREAM_*)
- [ ] Load balancing across hosts
- [ ] Reputation and rating system
- [ ] WebSocket tunneling
- [ ] Browser proxy extension

---

## File Structure

```
include/cyxwiz/
├── hosting.h           # Public API

src/core/
├── hosting.c           # Host manager
├── hosting_client.c    # Client manager
├── hosting_proxy.c     # HTTP proxy
├── hosting_registry.c  # Service registry

daemon/
├── main.c              # Add hosting initialization

tools/
├── cyxhost-cli.c       # Command-line tool

tests/
├── test_hosting.c      # Unit tests
├── test_hosting_e2e.c  # Integration tests
```

---

## API Summary

### Host Side

```c
// Initialize
cyxwiz_host_create(&host, router, consensus);

// Register service
cyxwiz_host_register(host, "my-api", CYXWIZ_SERVICE_HTTP, 8080, 1, &cred);

// Serve (in main loop)
while (running) {
    cyxwiz_host_poll(host, now_ms);
}

// Cleanup
cyxwiz_host_unregister(host, "my-api");
cyxwiz_host_destroy(host);
```

### Client Side

```c
// Initialize
cyxwiz_host_client_create(&client, router, onion);

// Discover
cyxwiz_host_query(client, "my-api", on_found, NULL);

// Request
cyxwiz_host_get(client, "my-api", "/users", on_response, NULL);

// With body
cyxwiz_host_request(client, "my-api", "POST", "/users",
    "Content-Type: application/json\r\n",
    json_body, json_len, on_response, NULL);

// Cleanup
cyxwiz_host_client_destroy(client);
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Service registration latency | < 500ms |
| Service discovery latency | < 2s |
| Request-response latency (3-hop) | < 5s |
| Max concurrent connections per host | 100+ |
| Max services per node | 16 |
| Uptime for hosted services | 99%+ |

---

## Conclusion

CyxHost extends the CyxWiz network with decentralized hosting capabilities, leveraging the existing secure infrastructure:

- **Onion routing** provides anonymity for both hosts and clients
- **Anonymous credentials** allow hosting without identity exposure
- **Work credits** prevent abuse and reward service providers
- **Consensus validation** ensures host reliability
- **P2P discovery** eliminates central points of failure

The protocol is designed to fit within existing message size constraints while enabling real-world web hosting scenarios.

---

*Document Version: 1.0*
*Status: Design Phase*
*Author: CyxWiz Protocol Team*
