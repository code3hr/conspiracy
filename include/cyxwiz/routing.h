/*
 * CyxWiz Protocol - Message Routing
 *
 * Implements hybrid mesh routing:
 * - On-demand route discovery (broadcast ROUTE_REQ, unicast ROUTE_REPLY)
 * - Source routing for data (path embedded in packet header)
 * - Route caching with timeout
 */

#ifndef CYXWIZ_ROUTING_H
#define CYXWIZ_ROUTING_H

#include "types.h"
#include "transport.h"
#include "peer.h"

/* Routing constants */
#define CYXWIZ_MAX_HOPS 5               /* Max hops in source route (fits 250-byte LoRa) */
#define CYXWIZ_MAX_ROUTES 32            /* Max cached routes */
#define CYXWIZ_MAX_PENDING 8            /* Max pending messages */
#define CYXWIZ_MAX_SEEN_REQUESTS 64     /* Max tracked request IDs */
#define CYXWIZ_ROUTE_TIMEOUT_MS 60000   /* Route cache timeout (60s) */
#define CYXWIZ_ROUTE_REQ_TIMEOUT_MS 5000  /* Route discovery timeout */
#define CYXWIZ_PENDING_TIMEOUT_MS 10000   /* Pending message timeout */
#define CYXWIZ_DEFAULT_TTL 10           /* Default time-to-live */

/* Maximum payload in routed data packet */
#define CYXWIZ_MAX_ROUTED_PAYLOAD 48    /* ~200 byte header, 50 for data */

/* Routing message types are defined in types.h:
 * CYXWIZ_MSG_ROUTE_REQ    (0x20) - Route request (broadcast)
 * CYXWIZ_MSG_ROUTE_REPLY  (0x21) - Route reply (unicast)
 * CYXWIZ_MSG_ROUTE_DATA   (0x22) - Routed data packet
 * CYXWIZ_MSG_ROUTE_ERROR  (0x23) - Route error notification
 */

/*
 * Route entry (cached discovered route)
 */
typedef struct {
    cyxwiz_node_id_t destination;
    uint8_t hop_count;
    cyxwiz_node_id_t hops[CYXWIZ_MAX_HOPS];  /* Path to destination */
    uint64_t discovered_at;
    uint16_t latency_ms;                     /* Estimated latency */
    bool valid;
} cyxwiz_route_t;

/*
 * Router context
 */
typedef struct cyxwiz_router cyxwiz_router_t;

/*
 * Delivery callback - called when data arrives for this node
 */
typedef void (*cyxwiz_delivery_callback_t)(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data
);

/* ============ Route Request Message ============ */

/*
 * Route request (broadcast flood to find destination)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_ROUTE_MSG_REQ */
    uint32_t request_id;                 /* Unique request ID */
    cyxwiz_node_id_t origin;             /* Who wants the route */
    cyxwiz_node_id_t destination;        /* Who we're looking for */
    uint8_t hop_count;                   /* Hops so far */
    cyxwiz_node_id_t path[CYXWIZ_MAX_HOPS];  /* Accumulated path */
    uint8_t ttl;                         /* Time-to-live */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_route_req_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Route Reply Message ============ */

/*
 * Route reply (unicast back along discovered path)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_ROUTE_MSG_REPLY */
    uint32_t request_id;                 /* Matching request ID */
    cyxwiz_node_id_t destination;        /* Final destination */
    uint8_t hop_count;                   /* Full path length */
    cyxwiz_node_id_t path[CYXWIZ_MAX_HOPS];  /* Full path */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_route_reply_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Routed Data Message ============ */

/*
 * Routed data packet (source routing)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_ROUTE_MSG_DATA */
    cyxwiz_node_id_t origin;             /* Original sender */
    uint8_t hop_count;                   /* Total hops in route */
    uint8_t current_hop;                 /* Which hop we're at */
    cyxwiz_node_id_t path[CYXWIZ_MAX_HOPS];
    uint8_t payload_len;
    /* payload follows */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_routed_data_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Route Error Message ============ */

/*
 * Route error (notify sender of broken path)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_ROUTE_MSG_ERROR */
    cyxwiz_node_id_t origin;             /* Original sender */
    cyxwiz_node_id_t broken_link;        /* Node that couldn't be reached */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_route_error_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Anonymous Routing Constants ============ */

#define CYXWIZ_ANON_VERSION 1            /* Protocol version */
#define CYXWIZ_DEST_TOKEN_SIZE 48        /* Encrypted destination marker */
#define CYXWIZ_SURB_HEADER_SIZE 88       /* Onion header in SURB */
#define CYXWIZ_SURB_SIZE 120             /* Total SURB size (32 + 88) */
#define CYXWIZ_REQUEST_NONCE_SIZE 16     /* Request deduplication nonce */
#define CYXWIZ_ANON_REPLY_PAYLOAD_SIZE 128 /* Encrypted reply data (payload + MAC) */
#define CYXWIZ_SURB_HOPS 2               /* Number of hops in SURB */
#define CYXWIZ_DEST_TOKEN_MAGIC 0x43595857 /* "CYXW" magic bytes */

/* ============ Single-Use Reply Block (SURB) ============ */

/*
 * SURB - enables anonymous replies without revealing origin
 * Origin builds this with onion-encrypted routing back to itself
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    cyxwiz_node_id_t first_hop;          /* Where to send reply (32 bytes) */
    uint8_t onion_header[CYXWIZ_SURB_HEADER_SIZE]; /* Encrypted routing info */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_surb_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Anonymous Route Request ============ */

/*
 * Anonymous route request - hides origin and destination
 * Total size: 219 bytes (fits 250-byte LoRa MTU)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_MSG_ANON_ROUTE_REQ (0x25) */
    uint8_t version;                     /* Protocol version */
    uint8_t ephemeral_pubkey[32];        /* X25519 per-request public key */
    uint8_t dest_token[CYXWIZ_DEST_TOKEN_SIZE]; /* Encrypted destination marker */
    cyxwiz_surb_t surb;                  /* Reply path back to origin */
    uint8_t request_nonce[CYXWIZ_REQUEST_NONCE_SIZE]; /* Deduplication */
    uint8_t ttl;                         /* Time-to-live */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_anon_route_req_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Anonymous Route Reply ============ */

/*
 * Anonymous route reply - travels via SURB path
 * Total size: 193 bytes
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_MSG_ANON_ROUTE_REPLY (0x26) */
    cyxwiz_node_id_t next_hop;           /* From SURB unwrap (or zeros if final) */
    uint8_t onion_payload[CYXWIZ_ANON_REPLY_PAYLOAD_SIZE]; /* Encrypted reply */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_anon_route_reply_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * Reply payload (decrypted at origin)
 * Note: Path is NOT included - revealing path defeats anonymity.
 * Origin establishes onion circuit to communicate with destination.
 * Total size: 16 + 32 + 32 + 1 = 81 bytes
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t request_nonce[CYXWIZ_REQUEST_NONCE_SIZE]; /* Echo request nonce */
    cyxwiz_node_id_t responder_id;       /* Destination's node ID */
    uint8_t responder_pubkey[32];        /* For circuit establishment */
    uint8_t reserved;                    /* Reserved for future use */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_anon_reply_payload_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Router Lifecycle ============ */

/*
 * Create router context
 */
cyxwiz_error_t cyxwiz_router_create(
    cyxwiz_router_t **router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy router context
 */
void cyxwiz_router_destroy(cyxwiz_router_t *router);

/*
 * Set delivery callback for received data
 */
void cyxwiz_router_set_callback(
    cyxwiz_router_t *router,
    cyxwiz_delivery_callback_t callback,
    void *user_data
);

/*
 * Set callback for onion messages
 * Called when CYXWIZ_MSG_ONION_DATA is received
 * The onion layer handles decryption and routing
 */
void cyxwiz_router_set_onion_callback(
    cyxwiz_router_t *router,
    cyxwiz_delivery_callback_t callback,
    void *user_data
);

/*
 * Start router
 */
cyxwiz_error_t cyxwiz_router_start(cyxwiz_router_t *router);

/*
 * Stop router
 */
cyxwiz_error_t cyxwiz_router_stop(cyxwiz_router_t *router);

/*
 * Poll router (call in main loop)
 * - Processes pending route discoveries
 * - Times out stale routes
 * - Retries failed sends
 */
cyxwiz_error_t cyxwiz_router_poll(
    cyxwiz_router_t *router,
    uint64_t current_time_ms
);

/* ============ Sending Messages ============ */

/*
 * Send data to destination
 * - If destination is direct peer, sends directly
 * - If route cached, uses source routing
 * - Otherwise, initiates route discovery and queues message
 */
cyxwiz_error_t cyxwiz_router_send(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len
);

/*
 * Check if route to destination exists
 */
bool cyxwiz_router_has_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination
);

/*
 * Get route info (for debugging/stats)
 * Returns NULL if no route
 */
const cyxwiz_route_t *cyxwiz_router_get_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination
);

/*
 * Invalidate route to destination
 */
void cyxwiz_router_invalidate_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination
);

/* ============ Message Handling ============ */

/*
 * Handle incoming routing message
 * Called by transport receive callback
 */
cyxwiz_error_t cyxwiz_router_handle_message(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ Anonymous Routing ============ */

/* Forward declaration for onion context */
typedef struct cyxwiz_onion_ctx cyxwiz_onion_ctx_t;

/*
 * Set onion context for anonymous routing
 * Required for SURB creation and destination token crypto
 */
void cyxwiz_router_set_onion_ctx(
    cyxwiz_router_t *router,
    cyxwiz_onion_ctx_t *onion_ctx
);

/*
 * Initiate anonymous route discovery
 * Hides both origin and destination from intermediate nodes
 *
 * @param router        Router context
 * @param destination   Destination node ID
 * @param dest_pubkey   Destination's X25519 public key
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_router_anon_discover(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *dest_pubkey
);

/*
 * Check if anonymous discovery is pending for destination
 */
bool cyxwiz_router_anon_discovery_pending(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination
);

/* ============ Anonymous Data Sending ============ */

/*
 * Send data anonymously via onion routing
 * Hides sender identity from all intermediate nodes and destination
 *
 * Requires onion context to be set on router via cyxwiz_router_set_onion_ctx()
 *
 * @param router        Router context
 * @param destination   Destination node ID
 * @param data          Data to send
 * @param len           Data length (max depends on hop count, typically 101 bytes)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_NOT_INITIALIZED if onion context not set
 *                      CYXWIZ_ERR_PACKET_TOO_LARGE if data exceeds max payload
 *                      CYXWIZ_ERR_NO_ROUTE if no peers available for circuit
 */
cyxwiz_error_t cyxwiz_router_send_anonymous(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len
);

/*
 * Check if anonymous route (circuit) exists to destination
 */
bool cyxwiz_router_has_anonymous_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination
);

/*
 * Send data via SURB (Single-Use Reply Block)
 * Used by compute layer for anonymous job result delivery
 *
 * The SURB contains pre-computed onion routing to the original requester.
 * The sender (worker) cannot identify the final destination.
 *
 * @param router        Router context
 * @param surb          SURB from anonymous request
 * @param data          Data to send
 * @param len           Data length (max CYXWIZ_ANON_REPLY_PAYLOAD_SIZE - 16)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_NOT_INITIALIZED if onion context not set
 *                      CYXWIZ_ERR_PACKET_TOO_LARGE if data exceeds max payload
 */
cyxwiz_error_t cyxwiz_router_send_via_surb(
    cyxwiz_router_t *router,
    const cyxwiz_surb_t *surb,
    const uint8_t *data,
    size_t len
);

/*
 * Create a SURB for anonymous reply
 * Used by compute layer for anonymous job submission
 *
 * @param router        Router context
 * @param surb_out      Output SURB structure
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_NOT_INITIALIZED if onion context not set
 *                      CYXWIZ_ERR_INSUFFICIENT_RELAYS if not enough relay peers
 */
cyxwiz_error_t cyxwiz_router_create_surb(
    cyxwiz_router_t *router,
    cyxwiz_surb_t *surb_out
);

/*
 * Check if SURB creation is possible
 * Requires onion context and at least CYXWIZ_SURB_HOPS relay peers with keys
 *
 * @param router        Router context
 * @return              true if SURB can be created
 */
bool cyxwiz_router_can_create_surb(const cyxwiz_router_t *router);

/* ============ Statistics ============ */

/*
 * Get routing statistics
 */
size_t cyxwiz_router_route_count(const cyxwiz_router_t *router);
size_t cyxwiz_router_pending_count(const cyxwiz_router_t *router);

#endif /* CYXWIZ_ROUTING_H */
