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

/* ============ Statistics ============ */

/*
 * Get routing statistics
 */
size_t cyxwiz_router_route_count(const cyxwiz_router_t *router);
size_t cyxwiz_router_pending_count(const cyxwiz_router_t *router);

#endif /* CYXWIZ_ROUTING_H */
