# CyxRelay Design Document

## Philosophy

```
"Own Nothing. Access Everything. Leave No Trace."
              │
              ▼
    ┌─────────────────┐
    │    CyxRelay     │
    │                 │
    │  The bridge     │
    │  between        │
    │  worlds.        │
    │                 │
    │  Mesh ↔ Internet│
    └─────────────────┘
```

CyxRelay nodes act as bridges between the CyxWiz mesh network and the clearnet (regular internet). They enable services hosted on the mesh to be accessible from anywhere, while maintaining the privacy of the service location.

## Overview

### The Problem

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Why We Need Relays                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Hidden endpoints (.cyx) are great for privacy but...              │
│                                                                      │
│  Problem 1: Not accessible from regular internet                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Browser ──✗──► abc123.cyx                                   │   │
│  │  (browsers don't speak CyxWiz protocol)                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Problem 2: Mobile apps can't easily integrate                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  iOS/Android apps need HTTP endpoints                        │   │
│  │  Full CyxWiz client too heavy for mobile                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Problem 3: Webhooks from external services                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  GitHub, Stripe, etc. need public URLs to POST to           │   │
│  │  They can't reach .cyx addresses                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Solution: Relay nodes that bridge both worlds                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### The Solution

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay Architecture                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Internet                  Relay Node                 CyxWiz Mesh   │
│                                                                      │
│  ┌─────────┐           ┌─────────────┐           ┌─────────────┐   │
│  │ Browser │           │             │           │  Container  │   │
│  │ or App  │──HTTPS───►│   CyxRelay  │──Onion───►│  (hidden)   │   │
│  │         │◄──HTTPS───│             │◄──Onion───│             │   │
│  └─────────┘           └─────────────┘           └─────────────┘   │
│                                                                      │
│  What Relay Sees:          What Relay DOESN'T See:                 │
│  • Client IP address       • Container location                    │
│  • Request timing          • Request content (E2E encrypted)       │
│  • Target service ID       • Response content                      │
│  • Data size               • Who owns the container                │
│                                                                      │
│  Security Model:                                                    │
│  • Relay is similar to Tor exit node                               │
│  • Sees metadata, not content                                      │
│  • Multiple relays = no single point of surveillance               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Architecture

### Relay Node Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay Node Architecture                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      cyxrelayd                               │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                                                              │   │
│  │  ┌─────────────────┐  ┌─────────────────┐                   │   │
│  │  │  HTTPS Server   │  │  WebSocket      │                   │   │
│  │  │  (TLS 1.3)      │  │  Server         │                   │   │
│  │  │                 │  │                 │                   │   │
│  │  │  • Port 443     │  │  • Real-time    │                   │   │
│  │  │  • Let's Encrypt│  │  • Bidirectional│                   │   │
│  │  └────────┬────────┘  └────────┬────────┘                   │   │
│  │           │                    │                             │   │
│  │           └────────┬───────────┘                             │   │
│  │                    │                                         │   │
│  │           ┌────────▼────────┐                               │   │
│  │           │  Request Router │                               │   │
│  │           │                 │                               │   │
│  │           │  • Parse target │                               │   │
│  │           │  • Rate limit   │                               │   │
│  │           │  • Auth check   │                               │   │
│  │           └────────┬────────┘                               │   │
│  │                    │                                         │   │
│  │           ┌────────▼────────┐                               │   │
│  │           │  Mesh Connector │                               │   │
│  │           │                 │                               │   │
│  │           │  • Onion routing│                               │   │
│  │           │  • E2E encrypt  │                               │   │
│  │           │  • Circuit mgmt │                               │   │
│  │           └────────┬────────┘                               │   │
│  │                    │                                         │   │
│  ├────────────────────┼────────────────────────────────────────┤   │
│  │                    ▼                                         │   │
│  │             CyxWiz Protocol                                  │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### URL Structure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay URL Format                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Format: https://<relay-domain>/<service-id>[/<path>]              │
│                                                                      │
│  Examples:                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  https://relay1.cyxwiz.net/abc123def456                     │   │
│  │          └──────┬────────┘ └─────┬──────┘                   │   │
│  │            relay domain    service ID                        │   │
│  │                                                              │   │
│  │  https://relay1.cyxwiz.net/abc123def456/api/users           │   │
│  │          └──────┬────────┘ └─────┬──────┘└───┬───┘          │   │
│  │            relay domain    service ID    path                │   │
│  │                                                              │   │
│  │  wss://relay1.cyxwiz.net/abc123def456/ws                    │   │
│  │          └──────┬────────┘ └─────┬──────┘└┬┘                │   │
│  │            relay domain    service ID   websocket            │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Service ID:                                                        │
│  • First 12 chars of container's hidden address (abc123def456.cyx) │
│  • Acts as routing key                                              │
│  • Relay looks up full .cyx address from service ID                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Request Flow

### HTTP Request Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HTTP Request Flow                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Client                 Relay                    Container          │
│    │                      │                          │               │
│    │ 1. HTTPS Request     │                          │               │
│    │ GET /abc123/api/data │                          │               │
│    │─────────────────────►│                          │               │
│    │                      │                          │               │
│    │                      │ 2. Extract service ID    │               │
│    │                      │    abc123 → abc123...cyx │               │
│    │                      │                          │               │
│    │                      │ 3. Build onion circuit   │               │
│    │                      │    (if not cached)       │               │
│    │                      │                          │               │
│    │                      │ 4. Wrap request in onion │               │
│    │                      │    E2E encrypted         │               │
│    │                      │                          │               │
│    │                      │ 5. Forward via mesh      │               │
│    │                      │─────────────────────────►│               │
│    │                      │                          │               │
│    │                      │                          │ 6. Container  │
│    │                      │                          │    processes  │
│    │                      │                          │    request    │
│    │                      │                          │               │
│    │                      │ 7. Response via mesh     │               │
│    │                      │◄─────────────────────────│               │
│    │                      │                          │               │
│    │                      │ 8. Unwrap onion response │               │
│    │                      │                          │               │
│    │ 9. HTTPS Response    │                          │               │
│    │◄─────────────────────│                          │               │
│    │                      │                          │               │
│                                                                      │
│  Timing: ~100-500ms depending on mesh path length                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### WebSocket Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WebSocket Flow                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Client                 Relay                    Container          │
│    │                      │                          │               │
│    │ 1. WS Upgrade        │                          │               │
│    │ GET /abc123/ws       │                          │               │
│    │ Upgrade: websocket   │                          │               │
│    │─────────────────────►│                          │               │
│    │                      │                          │               │
│    │                      │ 2. Establish circuit     │               │
│    │                      │────────────────────────► │               │
│    │                      │                          │               │
│    │                      │ 3. Circuit established   │               │
│    │                      │◄────────────────────────│               │
│    │                      │                          │               │
│    │ 4. WS Upgrade OK     │                          │               │
│    │◄─────────────────────│                          │               │
│    │                      │                          │               │
│    │ 5. WS Message        │                          │               │
│    │═════════════════════►│                          │               │
│    │                      │═════════════════════════►│               │
│    │                      │                          │               │
│    │                      │ 6. WS Response           │               │
│    │                      │◄═════════════════════════│               │
│    │◄═════════════════════│                          │               │
│    │                      │                          │               │
│    │      ... bidirectional real-time ...           │               │
│    │                      │                          │               │
│    │ N. Close             │                          │               │
│    │═════════════════════►│═════════════════════════►│               │
│    │                      │                          │               │
│                                                                      │
│  Relay maintains persistent circuit for WS duration                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Threat Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay Threat Model                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ATTACKER                WHAT THEY SEE              MITIGATION      │
│  ────────                ──────────────              ──────────      │
│                                                                      │
│  Network Observer        • Client IP                • Use Tor to    │
│  (ISP, nation-state)     • Relay IP                   reach relay  │
│                          • Encrypted bytes          • Multiple     │
│                          • Timing                     relays       │
│                                                                      │
│  Malicious Relay         • Client IP                • E2E encrypt  │
│                          • Service ID               • Relay can't  │
│                          • Request size               see content  │
│                          • NOT content              • Rotate relays│
│                                                                      │
│  Multiple Colluding      • Same as single           • Use different│
│  Relays                    relay per client           relay per    │
│                                                        service     │
│                                                                      │
│  Container Operator      • Request content          • Relay hides  │
│                          • NOT client IP              client IP   │
│                          • NOT path to relay                       │
│                                                                      │
│  Global Adversary        • Traffic correlation      • Padding      │
│  (all relays + ISPs)     • Can link client to       • Cover traffic│
│                            container                • Mix networks │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### End-to-End Encryption

```
┌─────────────────────────────────────────────────────────────────────┐
│                    E2E Encryption Through Relay                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Even though relay handles the connection, content is protected:   │
│                                                                      │
│  Layer 1: HTTPS (Client ↔ Relay)                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Protects from network observers between client and relay │   │
│  │  • Relay terminates TLS (can see decrypted at this point)   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 2: Onion Encryption (Relay ↔ Container via Mesh)            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Each hop encrypted with hop's key                        │   │
│  │  • Relay is first hop, container is destination             │   │
│  │  • Path through mesh hidden from each hop                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 3: Application E2E (Optional - Client ↔ Container)          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • For maximum security, encrypt payload at application     │   │
│  │  • Client encrypts with container's public key              │   │
│  │  • Even relay can't see content                             │   │
│  │  • Requires client to know container's key                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Recommended: Use Layer 3 for sensitive data                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Legal Considerations

### Exit Node Liability

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Legal Considerations                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CyxRelay nodes are similar to Tor exit nodes:                     │
│  • Traffic from many users appears to originate from relay         │
│  • Relay operators may receive abuse complaints                    │
│  • Legal status varies by jurisdiction                             │
│                                                                      │
│  Protections:                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  1. Common Carrier Analogy                                   │   │
│  │     • Relay doesn't choose or modify content                │   │
│  │     • Similar to ISP or phone company                       │   │
│  │                                                              │   │
│  │  2. No Content Visibility                                    │   │
│  │     • E2E encryption means relay can't see content          │   │
│  │     • Can't be held responsible for unknown content         │   │
│  │                                                              │   │
│  │  3. Terms of Service                                         │   │
│  │     • Clear ToS prohibiting illegal use                     │   │
│  │     • Best-effort abuse response                            │   │
│  │                                                              │   │
│  │  4. Geographic Distribution                                  │   │
│  │     • Relays in privacy-friendly jurisdictions              │   │
│  │     • No single country can shut down all relays            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Operator Recommendations:                                          │
│  • Consult local legal counsel                                     │
│  • Use dedicated IP (not home connection)                          │
│  • Maintain logs only as required by law                           │
│  • Have abuse response process                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Economics

### Relay Incentives

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay Economics                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Why run a relay?                                                   │
│                                                                      │
│  Revenue:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Earn CYX per GB relayed                                  │   │
│  │  • Base rate: 0.1 CYX per GB                               │   │
│  │  • Premium for low-latency: +20%                            │   │
│  │  • Premium for high-bandwidth: +10%                         │   │
│  │                                                              │   │
│  │  Example: 10TB/month relay                                  │   │
│  │  = 10,000 GB × 0.1 CYX = 1,000 CYX/month                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Costs:                                                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Server: $50-200/month (depending on bandwidth)           │   │
│  │  • Domain + TLS cert: ~$10/month                            │   │
│  │  • Stake: 2,000 CYX locked                                  │   │
│  │  • Ops time: Variable                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Requirements:                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Minimum:                                                    │   │
│  │  • 100 Mbps symmetric bandwidth                             │   │
│  │  • 99.5% uptime                                             │   │
│  │  • 2,000 CYX stake                                          │   │
│  │  • Valid TLS certificate                                    │   │
│  │  • Static IP                                                │   │
│  │                                                              │   │
│  │  Recommended:                                                │   │
│  │  • 1 Gbps bandwidth                                         │   │
│  │  • 99.9% uptime                                             │   │
│  │  • Geographic diversity                                     │   │
│  │  • DDoS protection                                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### Relay Configuration

```c
// Relay configuration
typedef struct {
    // Network
    char domain[256];           // relay1.cyxwiz.net
    uint16_t https_port;        // 443
    uint16_t ws_port;           // 443 (same, via upgrade)
    char tls_cert_path[256];    // /etc/cyxrelay/cert.pem
    char tls_key_path[256];     // /etc/cyxrelay/key.pem

    // Limits
    uint64_t max_bandwidth;     // Bytes per second
    uint32_t max_connections;   // Concurrent connections
    uint32_t request_timeout;   // Milliseconds
    uint64_t max_request_size;  // Bytes

    // Economics
    uint64_t price_per_gb;      // CYX per GB relayed
    uint64_t min_payment;       // Minimum to accept request

    // Privacy
    bool log_requests;          // Log metadata (not content)
    uint32_t log_retention;     // Days to keep logs
} cyxrelay_config_t;

// Active connection
typedef struct {
    uint64_t conn_id;           // Unique connection ID
    int client_fd;              // Client socket
    char service_id[32];        // Target service

    // Circuit to container
    cyxwiz_circuit_t* circuit;

    // Stats
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t started_at;

    // WebSocket state
    bool is_websocket;
    uint8_t ws_state;
} cyxrelay_conn_t;

// Service registration
typedef struct {
    char service_id[16];        // Short ID for URL
    char cyx_address[64];       // Full .cyx address
    uint8_t owner_pubkey[32];   // For payment/auth
    uint64_t bandwidth_limit;   // Per-service limit
    bool enabled;
} cyxrelay_service_t;
```

### API Functions

```c
// Initialize relay
int cyxrelay_init(cyxrelay_config_t* config);
int cyxrelay_start(void);
int cyxrelay_stop(void);

// Service management
int cyxrelay_register_service(cyxrelay_service_t* service);
int cyxrelay_unregister_service(const char* service_id);
int cyxrelay_list_services(cyxrelay_service_t* services, size_t* count);

// Connection handling (internal)
int cyxrelay_handle_http(int client_fd, const char* request);
int cyxrelay_handle_websocket(int client_fd);
int cyxrelay_forward_to_mesh(cyxrelay_conn_t* conn,
                              const uint8_t* data, size_t len);

// Stats
int cyxrelay_get_stats(cyxrelay_stats_t* stats);
```

## CLI Commands

```bash
# Start relay daemon
cyxrelayd --config /etc/cyxrelay/config.yaml

# Register a service
cyxrelay register --service-id myapp --cyx-address abc123def456.cyx
# Output:
# Service registered!
# Public URL: https://relay1.cyxwiz.net/myapp

# List services
cyxrelay services
# Output:
# Service ID    CYX Address              Bandwidth    Status
# myapp         abc123def456.cyx         100 GB/mo    Active
# api           def789ghi012.cyx         500 GB/mo    Active

# Check stats
cyxrelay stats
# Output:
# Relay: relay1.cyxwiz.net
# Uptime: 45 days
# Total relayed: 2.5 TB
# Active connections: 156
# Services: 12
# Earnings: 250 CYX (this month)

# View recent traffic (metadata only)
cyxrelay logs --tail 10
# Output:
# 2025-12-29 12:34:56 | myapp | 203.0.113.45 | GET /api/users | 1.2KB | 145ms
# 2025-12-29 12:34:57 | api   | 198.51.100.1 | POST /data     | 45KB  | 230ms
# ...

# Withdraw earnings
cyxrelay withdraw --amount 200 --to 0x7a3f8c21...
# Output:
# Withdrawing 200 CYX to 0x7a3f8c21...
# Transaction confirmed.
```

## Implementation Files

```
include/cyxwiz/
├── cyxrelay.h          # Main relay header
├── cyxrelay_http.h     # HTTP handling
├── cyxrelay_ws.h       # WebSocket handling
└── cyxrelay_circuit.h  # Circuit management

src/relay/
├── relay.c             # Core relay logic
├── http.c              # HTTP server
├── websocket.c         # WebSocket server
├── circuit.c           # Mesh circuit management
├── service.c           # Service registry
└── stats.c             # Statistics

daemon/
└── cyxrelayd.c         # Relay daemon main

tools/
└── cyxrelay.c          # CLI tool
```

## Open Questions

1. **Trust Model**: How do users choose which relay to trust?
   - Reputation system?
   - Multiple relays for redundancy?

2. **Payment**: How do users pay for relay usage?
   - Per-request micropayments?
   - Pre-paid bandwidth?
   - Service owner pays?

3. **DDoS Protection**: How to protect relays from DDoS?
   - Rate limiting per IP?
   - Proof-of-work for requests?
   - CDN in front?

4. **Censorship**: What if relays are blocked in certain countries?
   - Domain fronting?
   - Pluggable transports?

5. **Discovery**: How do users find available relays?
   - Hardcoded list?
   - DHT discovery?
   - DNS-based discovery?

---

## Expanded Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Traffic Analysis | Correlate client to container | High |
| Service Enumeration | Discover hidden services | Medium |
| Relay Compromise | Attacker controls relay | High |
| DDoS | Overwhelm relay resources | Medium |
| Man-in-the-Middle | Intercept TLS | Critical |
| Legal Seizure | Relay hardware confiscated | Medium |

### Detailed Threat Analysis

#### Traffic Analysis Attack
- **Description**: Correlate client requests with container responses via timing/size
- **Attacker**: Global passive adversary (nation-state)
- **Prerequisites**: Observe both relay and mesh traffic
- **Impact**: Deanonymization of users/services
- **Likelihood**: Medium (requires significant resources)
- **Mitigation**:
  - Traffic padding to fixed sizes
  - Delay randomization
  - Cover traffic (dummy requests)
  - Multiple relay hops

#### Malicious Relay Operator
- **Description**: Relay operator logs or manipulates traffic
- **Attacker**: Relay operator or insider
- **Prerequisites**: Control of relay
- **Impact**: Metadata collection, selective blocking
- **Likelihood**: Medium
- **Mitigation**:
  - E2E encryption (relay can't read content)
  - Multiple relay options (user choice)
  - Reputation/auditing system
  - Open-source verifiable code

#### TLS Downgrade/MITM
- **Description**: Attacker intercepts HTTPS between client and relay
- **Attacker**: Network observer with CA access
- **Prerequisites**: Compromised CA or DNS
- **Impact**: Full traffic visibility
- **Likelihood**: Low (certificate transparency)
- **Mitigation**:
  - Certificate pinning option
  - HSTS preload
  - Certificate transparency monitoring
  - DANE/DNSSEC

### Security Assumptions
1. TLS 1.3 provides confidentiality
2. Onion routing hides container location
3. Relay operator is semi-honest (follows protocol, may observe)
4. Client trusts relay with metadata (not content)

### Trust Boundaries
```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│  Client          │        │  Relay           │        │  Container       │
│  (plaintext)     │──TLS──►│  (metadata only) │─Onion─►│  (plaintext)     │
└──────────────────┘        └──────────────────┘        └──────────────────┘
        │                            │                           │
   TRUST BOUNDARY 1            TRUST BOUNDARY 2           TRUST BOUNDARY 3
   (TLS termination)           (Onion wrapping)          (Content access)
```

---

## Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| TLS | Cert expired | Connection refused | Monitoring | Auto-renew |
| HTTP Server | Crash | 503 errors | Health check | Auto-restart |
| Mesh Connection | Circuit broken | Timeouts | Circuit timeout | Rebuild circuit |
| Service | Unreachable | 504 Gateway Timeout | Multiple retries | Return error |
| Disk | Full | Logs stop | Disk monitor | Rotate/cleanup |
| Network | Saturated | High latency | Bandwidth monitor | Rate limit |

### Recovery Procedures

#### Circuit Recovery
```c
// Automatic circuit recovery for failed mesh connections
int cyxrelay_circuit_recover(cyxrelay_conn_t* conn) {
    // 1. Destroy broken circuit
    if (conn->circuit) {
        cyxwiz_onion_destroy_circuit(conn->circuit);
        conn->circuit = NULL;
    }

    // 2. Attempt to rebuild (with backoff)
    int retries = 3;
    int delay_ms = 100;

    for (int i = 0; i < retries; i++) {
        cyxwiz_circuit_t* new_circuit;
        int err = cyxwiz_onion_build_circuit_to(
            relay_ctx->onion,
            conn->cyx_address,
            &new_circuit
        );

        if (err == CYXWIZ_OK) {
            conn->circuit = new_circuit;
            log_info("Circuit recovered for %s", conn->service_id);
            return CYXRELAY_OK;
        }

        sleep_ms(delay_ms);
        delay_ms *= 2;  // Exponential backoff
    }

    return CYXRELAY_CIRCUIT_FAILED;
}
```

#### Graceful Shutdown
```c
int cyxrelay_shutdown(void) {
    // 1. Stop accepting new connections
    cyxrelay_stop_listening();

    // 2. Notify active connections (give 30s to finish)
    for (int i = 0; i < conn_count; i++) {
        send_close_notification(&connections[i]);
    }
    sleep(30);

    // 3. Force-close remaining connections
    for (int i = 0; i < conn_count; i++) {
        close_connection(&connections[i]);
    }

    // 4. Destroy all circuits
    cyxwiz_onion_destroy_all_circuits(relay_ctx->onion);

    // 5. Submit final stats
    cyxrelay_submit_final_stats();

    // 6. Announce departure
    cyxrelay_announce_offline();

    return CYXRELAY_OK;
}
```

#### Automatic TLS Renewal
```c
// Check and renew certificate before expiry
void cyxrelay_tls_maintenance(void) {
    time_t expiry = get_cert_expiry(config.tls_cert_path);
    time_t now = time(NULL);
    time_t days_until_expiry = (expiry - now) / 86400;

    if (days_until_expiry < 30) {
        log_info("Certificate expiring in %ld days, renewing...", days_until_expiry);

        // ACME renewal (Let's Encrypt)
        int err = acme_renew_certificate(config.domain,
                                          config.tls_cert_path,
                                          config.tls_key_path);
        if (err == 0) {
            // Hot-reload certificate
            cyxrelay_reload_tls();
            log_info("Certificate renewed successfully");
        } else {
            log_error("Certificate renewal failed: %d", err);
            // Alert operator
            send_alert("TLS cert renewal failed");
        }
    }
}
```

### What Cannot Be Recovered
- In-flight WebSocket messages at crash
- Lost client connections (must reconnect)
- Circuits through unavailable mesh nodes

---

## Protocol Versioning

### Version Format
```
CyxRelay Protocol: Major.Minor.Patch (SemVer)
Example: 1.0.0
```

### API Versioning
```c
// Response headers include version
// X-CyxRelay-Version: 1.0.0
// X-CyxRelay-Min-Version: 1.0.0

// Feature detection via OPTIONS
// OPTIONS /abc123/ HTTP/1.1
// Returns:
// Allow: GET, POST, PUT, DELETE, OPTIONS
// X-CyxRelay-Features: websocket,streaming,e2e-encrypt
```

### Client Compatibility
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Version Compatibility Matrix                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Client Version    Relay v1.0    Relay v1.1    Relay v2.0          │
│  ────────────      ──────────    ──────────    ──────────          │
│  v1.0              ✓ Full        ✓ Full        ✗ Upgrade req       │
│  v1.1              ✓ Full        ✓ Full        ✗ Upgrade req       │
│  v2.0              ✓ Basic*      ✓ Basic*      ✓ Full              │
│                                                                      │
│  * Basic = HTTP only, no new v2 features                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Backwards Compatibility

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| New header | Patch | No |
| New optional feature | Minor | No |
| URL structure change | Major | Yes |
| Auth scheme change | Major | Yes |
| Protocol change | Major | Yes |

---

## Rate Limiting & DoS Protection

### Request Limits

| Resource | Limit | Window | Response |
|----------|-------|--------|----------|
| Requests per IP | 1000 | 1 min | 429 Too Many Requests |
| Connections per IP | 50 | - | Refuse new |
| Bandwidth per IP | 100 MB | 1 min | Throttle |
| Request size | 10 MB | - | 413 Payload Too Large |
| WebSocket messages | 100/s | - | Close connection |

### Per-Service Limits
```c
// Services can configure their own limits
typedef struct {
    uint32_t requests_per_minute;
    uint32_t concurrent_connections;
    uint64_t bandwidth_per_hour;
    bool require_payment;
    uint64_t min_payment_per_request;
} cyxrelay_service_limits_t;

int cyxrelay_check_service_limit(cyxrelay_service_t* service,
                                  const char* client_ip) {
    cyxrelay_service_limits_t* limits = &service->limits;

    // Check per-client rate
    uint32_t client_requests = get_client_request_count(service, client_ip);
    if (client_requests >= limits->requests_per_minute) {
        return CYXRELAY_RATE_LIMITED;
    }

    // Check service-wide bandwidth
    if (service->bandwidth_used >= limits->bandwidth_per_hour) {
        return CYXRELAY_BANDWIDTH_EXCEEDED;
    }

    return CYXRELAY_OK;
}
```

### DDoS Mitigation Layers
```
┌─────────────────────────────────────────────────────────────────────┐
│                    DDoS Protection Stack                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Layer 1: CDN/Proxy (Cloudflare, etc.)                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Absorb volumetric attacks                                │   │
│  │  • Geographic distribution                                   │   │
│  │  • Bot detection                                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 2: Connection Limits                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Max connections per IP                                   │   │
│  │  • SYN flood protection                                     │   │
│  │  • Connection timeout                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 3: Application Rate Limits                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Token bucket per IP                                      │   │
│  │  • Request size limits                                      │   │
│  │  • Bandwidth throttling                                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 4: Service-Specific                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Per-service limits                                       │   │
│  │  • Payment requirements                                     │   │
│  │  • Proof-of-work challenges                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Monitoring & Observability

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cyxrelay_requests_total` | Counter | Total requests by service, status |
| `cyxrelay_request_duration_ms` | Histogram | Request latency |
| `cyxrelay_bytes_relayed` | Counter | Bytes transferred |
| `cyxrelay_connections_active` | Gauge | Current connections |
| `cyxrelay_circuits_active` | Gauge | Active mesh circuits |
| `cyxrelay_circuit_build_duration_ms` | Histogram | Circuit setup time |
| `cyxrelay_errors_total` | Counter | Errors by type |
| `cyxrelay_services_active` | Gauge | Registered services |

### Health Checks
```c
typedef struct {
    bool http_server_healthy;
    bool mesh_connected;
    bool tls_valid;
    uint32_t active_connections;
    uint32_t active_circuits;
    uint64_t uptime_seconds;
    uint64_t bytes_relayed_today;
} cyxrelay_health_t;

// GET /health
// Returns: {"status": "healthy", "uptime": 123456, ...}

// GET /ready
// Returns: {"ready": true} if accepting traffic

int cyxrelay_health_check(cyxrelay_health_t* health) {
    health->http_server_healthy = is_server_running();
    health->mesh_connected = cyxwiz_peer_count() > 0;
    health->tls_valid = time(NULL) < get_cert_expiry(config.tls_cert_path);
    health->active_connections = connection_count;
    health->active_circuits = circuit_count;
    health->uptime_seconds = time(NULL) - start_time;
    health->bytes_relayed_today = stats.bytes_today;
    return CYXRELAY_OK;
}
```

### Logging (Privacy-Preserving)

| Level | What to Log | What NOT to Log |
|-------|-------------|-----------------|
| ERROR | Crash details, system errors | Request content |
| WARN | Rate limits hit, circuit failures | Client data |
| INFO | Request summary (size, timing) | Full URLs, headers |
| DEBUG | Protocol details | Plaintext data |

```c
// Example log format (privacy-preserving)
// 2025-12-29T12:34:56Z INFO req service=abc123 method=GET size=1234 latency=145ms status=200
// Note: No client IP in default logs (unless required by law)
```

---

## Traffic Shaping

### QoS Policies
```c
// Traffic classes
typedef enum {
    CYXRELAY_QOS_REALTIME,      // WebSocket, streaming (lowest latency)
    CYXRELAY_QOS_INTERACTIVE,   // API calls (low latency)
    CYXRELAY_QOS_BULK,          // Large downloads (throughput)
    CYXRELAY_QOS_BACKGROUND,    // Low priority
} cyxrelay_qos_class_t;

// Bandwidth allocation
typedef struct {
    uint64_t realtime_bps;      // 20% of bandwidth
    uint64_t interactive_bps;   // 40% of bandwidth
    uint64_t bulk_bps;          // 30% of bandwidth
    uint64_t background_bps;    // 10% of bandwidth
} cyxrelay_qos_config_t;

cyxrelay_qos_class_t cyxrelay_classify_request(cyxrelay_conn_t* conn) {
    if (conn->is_websocket) {
        return CYXRELAY_QOS_REALTIME;
    }
    if (conn->expected_size < 10 * 1024) {  // <10KB
        return CYXRELAY_QOS_INTERACTIVE;
    }
    if (conn->expected_size < 1024 * 1024) {  // <1MB
        return CYXRELAY_QOS_BULK;
    }
    return CYXRELAY_QOS_BACKGROUND;
}
```

### Priority Queues
```c
// Token bucket per QoS class
typedef struct {
    uint64_t tokens;
    uint64_t max_tokens;
    uint64_t refill_rate;       // tokens per second
    uint64_t last_refill;
} token_bucket_t;

int cyxrelay_send_with_qos(cyxrelay_conn_t* conn,
                            const uint8_t* data, size_t len) {
    cyxrelay_qos_class_t qos = cyxrelay_classify_request(conn);
    token_bucket_t* bucket = &qos_buckets[qos];

    // Refill tokens
    refill_bucket(bucket);

    // Wait for tokens if needed
    while (bucket->tokens < len) {
        sleep_ms(10);
        refill_bucket(bucket);
    }

    // Consume tokens and send
    bucket->tokens -= len;
    return send_data(conn, data, len);
}
```

---

## Abuse Policy

### Prohibited Activities
```
┌─────────────────────────────────────────────────────────────────────┐
│                    CyxRelay Acceptable Use Policy                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PROHIBITED:                                                         │
│  ───────────                                                        │
│  1. Child Sexual Abuse Material (CSAM)                              │
│  2. Terrorism planning or recruitment                               │
│  3. Direct incitement to violence                                   │
│  4. Malware distribution                                            │
│  5. Attacks on critical infrastructure                              │
│  6. Human trafficking coordination                                  │
│                                                                      │
│  ALLOWED (relay operator may not approve, but will relay):          │
│  ─────────────────────────────────────────────────────────          │
│  • Political speech                                                 │
│  • Whistleblowing                                                   │
│  • Journalism                                                       │
│  • Privacy-seeking individuals                                      │
│  • Circumventing censorship                                         │
│  • Legal adult content                                              │
│                                                                      │
│  NOTE: Relay cannot see encrypted content, so enforcement is        │
│  limited to metadata analysis and responding to legal requests.     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Abuse Response Process
```c
// Abuse report handling
typedef struct {
    char report_id[32];
    char service_id[16];
    char reporter_email[256];
    char description[4096];
    char evidence_url[512];
    uint64_t received_at;
    uint8_t status;             // PENDING, REVIEWED, ACTIONED, REJECTED
} cyxrelay_abuse_report_t;

// Response timeline
// 1. Report received: ACK within 24 hours
// 2. Initial review: within 72 hours
// 3. If actionable: Service notified, given 48 hours to respond
// 4. If no response: Service may be blocked from this relay
// 5. Severe (CSAM, etc.): Immediate block, report to authorities
```

### Automatic Detection
```c
// Hash-based detection (for known bad content)
// Using PhotoDNA-style hashing for CSAM detection
// Note: Applied to unencrypted metadata only (URLs, headers)

typedef struct {
    uint8_t hash[32];           // Hash of known bad content
    uint8_t severity;           // 1=block, 2=log, 3=rate-limit
    char category[32];          // "csam", "malware", etc.
} blocklist_entry_t;

int cyxrelay_check_blocklist(const char* url, const char* headers) {
    // Check URL against known bad hashes
    uint8_t url_hash[32];
    crypto_hash(url_hash, url, strlen(url));

    for (int i = 0; i < blocklist_count; i++) {
        if (memcmp(url_hash, blocklist[i].hash, 32) == 0) {
            log_warn("Blocklist hit: category=%s", blocklist[i].category);
            return blocklist[i].severity;
        }
    }

    return 0;  // Not blocked
}
```

---

## Legal Safe Harbor

### Operator Protection Template
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Legal Safe Harbor Template                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [RELAY_NAME] RELAY OPERATOR NOTICE                                 │
│                                                                      │
│  This server operates as a CyxRelay node, providing encrypted       │
│  proxy services between internet clients and CyxWiz mesh network    │
│  endpoints. Similar to Tor exit nodes:                              │
│                                                                      │
│  1. COMMON CARRIER STATUS                                           │
│     This relay transmits data without modification or inspection.   │
│     The operator does not select, modify, or control the content   │
│     of communications passing through.                              │
│                                                                      │
│  2. ENCRYPTION                                                       │
│     All communications are end-to-end encrypted. The operator      │
│     cannot access the content of any communication.                 │
│                                                                      │
│  3. NO LOGGING                                                       │
│     [Unless required by law, ] this relay does not log traffic     │
│     content, IP addresses, or other identifying information.        │
│                                                                      │
│  4. ABUSE HANDLING                                                   │
│     Abuse reports should be sent to: [EMAIL]                        │
│     The operator will respond within [TIMEFRAME].                   │
│                                                                      │
│  5. LEGAL REQUESTS                                                   │
│     Legal requests must be sent to: [ADDRESS]                       │
│     The operator will comply with valid legal process.              │
│                                                                      │
│  This relay is operated by: [OPERATOR_NAME]                         │
│  Contact: [EMAIL]                                                    │
│  Jurisdiction: [COUNTRY]                                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Jurisdiction Considerations
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Relay Jurisdiction Guide                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  FAVORABLE JURISDICTIONS:                                           │
│  • Switzerland: Strong privacy laws, neutral                        │
│  • Iceland: Press freedom protections                               │
│  • Netherlands: Favorable court precedents for proxies             │
│  • Romania: Limited data retention requirements                     │
│                                                                      │
│  CHALLENGING JURISDICTIONS:                                         │
│  • United States: DMCA takedowns, NSL concerns                     │
│  • United Kingdom: Investigatory Powers Act                        │
│  • Australia: Anti-encryption laws                                  │
│  • China/Russia/Iran: May be illegal to operate                    │
│                                                                      │
│  RECOMMENDATIONS:                                                    │
│  1. Consult local legal counsel before operating                   │
│  2. Use dedicated infrastructure (not home connection)              │
│  3. Maintain minimal logs                                           │
│  4. Have abuse response process documented                          │
│  5. Consider operating through legal entity                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Censorship Resistance

### Techniques
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Censorship Resistance Techniques                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DOMAIN FRONTING                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Use CDN domain in SNI (e.g., cloudfront.net)             │   │
│  │  • Actual Host header points to relay                       │   │
│  │  • Censor sees CDN domain, not relay                        │   │
│  │  • Note: Many CDNs have blocked this                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  2. ENCRYPTED SNI (ESNI/ECH)                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Encrypt Server Name Indication in TLS handshake          │   │
│  │  • Censor can't see which domain being accessed             │   │
│  │  • Requires DNS-over-HTTPS and ESNI-supporting server       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  3. PLUGGABLE TRANSPORTS                                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Obfuscate TLS to look like other protocols               │   │
│  │  • Options: obfs4, meek, shadowsocks                        │   │
│  │  • Makes DPI-based blocking harder                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  4. RELAY ROTATION                                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Many relays across many IPs/domains                      │   │
│  │  • Whack-a-mole: block one, another appears                 │   │
│  │  • Discovery via DHT, Tor, or out-of-band                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  5. STEGANOGRAPHY (Future)                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Hide traffic in innocuous protocols (video, images)      │   │
│  │  • Very hard to detect                                      │   │
│  │  • High overhead                                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Bridge Mode
```c
// For censored regions: relay can operate as bridge
typedef struct {
    bool bridge_mode;
    char pluggable_transport[32];   // "obfs4", "meek", etc.
    char bridge_line[512];          // Connection string for clients
    bool private;                   // Not listed publicly
} cyxrelay_bridge_config_t;

// Generate bridge line for distribution
// obfs4 1.2.3.4:443 FINGERPRINT cert=CERT iat-mode=0
char* cyxrelay_get_bridge_line(void) {
    static char bridge_line[512];
    snprintf(bridge_line, sizeof(bridge_line),
             "%s %s:%d %s cert=%s iat-mode=%d",
             config.pluggable_transport,
             config.public_ip,
             config.https_port,
             relay_fingerprint,
             bridge_cert,
             config.iat_mode);
    return bridge_line;
}
```
