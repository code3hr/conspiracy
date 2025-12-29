/*
 * CyxWiz Protocol - Message Routing
 *
 * Implements hybrid mesh routing:
 * - On-demand route discovery
 * - Source routing for data packets
 * - Route caching with timeout
 */

#include "cyxwiz/routing.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"
#include "cyxwiz/onion.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include "cyxwiz/crypto.h"
#include <sodium.h>
#endif

#include <string.h>

/*
 * Seen request entry (for deduplication)
 */
typedef struct {
    uint32_t request_id;
    cyxwiz_node_id_t origin;
    uint64_t seen_at;
} cyxwiz_seen_request_t;

/*
 * Pending message (waiting for route discovery)
 */
typedef struct {
    cyxwiz_node_id_t destination;
    uint8_t data[CYXWIZ_MAX_ROUTED_PAYLOAD];
    size_t len;
    uint64_t queued_at;
    bool valid;
} cyxwiz_pending_msg_t;

/*
 * Active route discovery
 */
typedef struct {
    uint32_t request_id;
    cyxwiz_node_id_t destination;
    uint64_t started_at;
    bool active;
} cyxwiz_active_discovery_t;

/*
 * Seen anonymous request (deduplication by nonce, not origin)
 */
typedef struct {
    uint8_t request_nonce[CYXWIZ_REQUEST_NONCE_SIZE];
    uint64_t seen_at;
} cyxwiz_seen_anon_request_t;

/*
 * Active anonymous route discovery
 */
typedef struct {
    uint8_t request_nonce[CYXWIZ_REQUEST_NONCE_SIZE];
    cyxwiz_node_id_t destination;
    uint8_t ephemeral_sk[32];    /* Per-request ephemeral secret key */
    uint8_t ephemeral_pk[32];    /* Per-request ephemeral public key */
    uint64_t started_at;
    bool active;
} cyxwiz_anon_discovery_t;

/*
 * Router context
 */
struct cyxwiz_router {
    cyxwiz_peer_table_t *peer_table;
    cyxwiz_transport_t *transport;
    cyxwiz_node_id_t local_id;

    /* Route cache */
    cyxwiz_route_t routes[CYXWIZ_MAX_ROUTES];
    size_t route_count;

    /* Seen requests (deduplication) */
    cyxwiz_seen_request_t seen[CYXWIZ_MAX_SEEN_REQUESTS];
    size_t seen_count;

    /* Pending messages */
    cyxwiz_pending_msg_t pending[CYXWIZ_MAX_PENDING];

    /* Active discoveries */
    cyxwiz_active_discovery_t discoveries[CYXWIZ_MAX_PENDING];

    /* Delivery callback */
    cyxwiz_delivery_callback_t on_delivery;
    void *user_data;

    /* Onion message callback */
    cyxwiz_delivery_callback_t on_onion;
    void *onion_user_data;

    /* Onion context (for anonymous routing) */
    cyxwiz_onion_ctx_t *onion_ctx;

    /* Anonymous routing state */
    cyxwiz_seen_anon_request_t anon_seen[CYXWIZ_MAX_SEEN_REQUESTS];
    size_t anon_seen_count;
    cyxwiz_anon_discovery_t anon_discoveries[CYXWIZ_MAX_PENDING];

    /* Pending ACKs for timeout tracking */
    cyxwiz_pending_ack_t pending_acks[CYXWIZ_MAX_PENDING_ACKS];

    /* Fragment reassembly */
    cyxwiz_frag_reassembly_t reassembly[CYXWIZ_MAX_REASSEMBLY];
    uint32_t next_frag_message_id;

    /* State */
    bool running;
    uint32_t next_request_id;
    uint64_t last_cleanup;
};

/* ============ Forward Declarations ============ */

static cyxwiz_error_t handle_route_req(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_req_t *req);

static cyxwiz_error_t handle_route_reply(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_reply_t *reply);

static cyxwiz_error_t handle_route_data(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len);

static cyxwiz_error_t handle_route_error(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_error_t *err);

static cyxwiz_error_t handle_relay_ack(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_relay_ack_t *ack);

static cyxwiz_error_t handle_frag_data(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len);

static void check_reassembly_timeouts(
    cyxwiz_router_t *router,
    uint64_t now);

static bool is_request_seen(
    cyxwiz_router_t *router,
    uint32_t request_id,
    const cyxwiz_node_id_t *origin);

static void mark_request_seen(
    cyxwiz_router_t *router,
    uint32_t request_id,
    const cyxwiz_node_id_t *origin,
    uint64_t now);

static cyxwiz_route_t *find_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination);

static cyxwiz_error_t add_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const cyxwiz_node_id_t *path,
    uint8_t hop_count);

static cyxwiz_error_t start_route_discovery(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination);

static cyxwiz_error_t send_pending_messages(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination);

static bool is_direct_peer(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination);

static uint32_t compute_message_id(const uint8_t *data, size_t len);
static void track_pending_ack(cyxwiz_router_t *router, uint32_t message_id,
                              const cyxwiz_node_id_t *first_hop);
static void clear_pending_ack(cyxwiz_router_t *router, uint32_t message_id);

/* Anonymous routing forward declarations */
#ifdef CYXWIZ_HAS_CRYPTO
static cyxwiz_error_t handle_anon_route_req(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_anon_route_req_t *req);

static cyxwiz_error_t handle_anon_route_reply(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_anon_route_reply_t *reply);

static bool is_anon_request_seen(
    cyxwiz_router_t *router,
    const uint8_t *nonce);

static void mark_anon_request_seen(
    cyxwiz_router_t *router,
    const uint8_t *nonce,
    uint64_t now);

static cyxwiz_error_t create_dest_token(
    const uint8_t *ephemeral_sk,
    const uint8_t *dest_pubkey,
    uint8_t *token_out);

static bool try_decrypt_dest_token(
    cyxwiz_onion_ctx_t *onion_ctx,
    const uint8_t *ephemeral_pk,
    const uint8_t *token);

static cyxwiz_error_t create_surb(
    cyxwiz_router_t *router,
    const uint8_t *request_nonce,
    cyxwiz_surb_t *surb_out,
    uint8_t *reply_key_out);
#endif

/* ============ Route Reputation ============ */

/*
 * Compute total reputation score for a route
 * Higher score = more reliable path
 * Returns 0 if any hop is blacklisted (below CYXWIZ_MIN_RELAY_REPUTATION)
 */
static uint16_t compute_route_reputation(
    cyxwiz_peer_table_t *peer_table,
    const cyxwiz_node_id_t *hops,
    uint8_t hop_count)
{
    uint16_t total = 0;
    for (uint8_t i = 0; i < hop_count; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(peer_table, &hops[i]);
        uint8_t rep;
        if (peer != NULL) {
            rep = cyxwiz_peer_reputation(peer);
            /* Reject route if any hop is blacklisted */
            if (rep < CYXWIZ_MIN_RELAY_REPUTATION) {
                return 0;
            }
            total += rep;
        } else {
            total += 50;  /* Unknown peer gets neutral score */
        }
    }
    return total;
}

/* ============ Router Lifecycle ============ */

cyxwiz_error_t cyxwiz_router_create(
    cyxwiz_router_t **router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id)
{
    if (router == NULL || peer_table == NULL || transport == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_router_t *r = cyxwiz_calloc(1, sizeof(cyxwiz_router_t));
    if (r == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    r->peer_table = peer_table;
    r->transport = transport;
    memcpy(&r->local_id, local_id, sizeof(cyxwiz_node_id_t));
    r->route_count = 0;
    r->seen_count = 0;
    r->on_delivery = NULL;
    r->user_data = NULL;
    r->on_onion = NULL;
    r->onion_user_data = NULL;
    r->onion_ctx = NULL;
    r->anon_seen_count = 0;
    r->running = false;
    r->next_request_id = 1;
    r->last_cleanup = 0;

    /* Initialize pending and discoveries */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        r->pending[i].valid = false;
        r->discoveries[i].active = false;
        r->anon_discoveries[i].active = false;
    }

    /* Initialize routes */
    for (size_t i = 0; i < CYXWIZ_MAX_ROUTES; i++) {
        r->routes[i].valid = false;
    }

    *router = r;

    char hex_id[65];
    cyxwiz_node_id_to_hex(local_id, hex_id);
    CYXWIZ_INFO("Created router for node %.16s...", hex_id);

    return CYXWIZ_OK;
}

void cyxwiz_router_destroy(cyxwiz_router_t *router)
{
    if (router == NULL) {
        return;
    }

    if (router->running) {
        cyxwiz_router_stop(router);
    }

    cyxwiz_free(router, sizeof(cyxwiz_router_t));
    CYXWIZ_DEBUG("Destroyed router");
}

void cyxwiz_router_set_callback(
    cyxwiz_router_t *router,
    cyxwiz_delivery_callback_t callback,
    void *user_data)
{
    if (router == NULL) {
        return;
    }
    router->on_delivery = callback;
    router->user_data = user_data;
}

void cyxwiz_router_set_onion_callback(
    cyxwiz_router_t *router,
    cyxwiz_delivery_callback_t callback,
    void *user_data)
{
    if (router == NULL) {
        return;
    }
    router->on_onion = callback;
    router->onion_user_data = user_data;
}

void cyxwiz_router_set_onion_ctx(
    cyxwiz_router_t *router,
    cyxwiz_onion_ctx_t *onion_ctx)
{
    if (router == NULL) {
        return;
    }
    router->onion_ctx = onion_ctx;
}

cyxwiz_error_t cyxwiz_router_start(cyxwiz_router_t *router)
{
    if (router == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (router->running) {
        return CYXWIZ_OK;
    }

    router->running = true;
    router->last_cleanup = cyxwiz_time_ms();

    CYXWIZ_INFO("Router started");
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_router_stop(cyxwiz_router_t *router)
{
    if (router == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!router->running) {
        return CYXWIZ_OK;
    }

    router->running = false;

    CYXWIZ_INFO("Router stopped");
    return CYXWIZ_OK;
}

/* ============ Polling ============ */

cyxwiz_error_t cyxwiz_router_poll(
    cyxwiz_router_t *router,
    uint64_t current_time_ms)
{
    if (router == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!router->running) {
        return CYXWIZ_OK;
    }

    /* Cleanup stale routes and seen requests periodically */
    if (current_time_ms - router->last_cleanup >= 5000) {
        /* Expire old routes */
        for (size_t i = 0; i < CYXWIZ_MAX_ROUTES; i++) {
            if (router->routes[i].valid) {
                uint64_t age = current_time_ms - router->routes[i].discovered_at;
                if (age > CYXWIZ_ROUTE_TIMEOUT_MS) {
                    router->routes[i].valid = false;
                    router->route_count--;
                    CYXWIZ_DEBUG("Route expired");
                }
            }
        }

        /* Expire old seen requests */
        size_t new_count = 0;
        for (size_t i = 0; i < router->seen_count; i++) {
            uint64_t age = current_time_ms - router->seen[i].seen_at;
            if (age <= CYXWIZ_ROUTE_REQ_TIMEOUT_MS * 2) {
                if (i != new_count) {
                    router->seen[new_count] = router->seen[i];
                }
                new_count++;
            }
        }
        router->seen_count = new_count;

        /* Check for timed out route discoveries */
        for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
            if (router->discoveries[i].active) {
                uint64_t age = current_time_ms - router->discoveries[i].started_at;
                if (age > CYXWIZ_ROUTE_REQ_TIMEOUT_MS) {
                    router->discoveries[i].active = false;

                    char hex_id[65];
                    cyxwiz_node_id_to_hex(&router->discoveries[i].destination, hex_id);
                    CYXWIZ_WARN("Route discovery timed out for %.16s...", hex_id);

                    /* Clear pending messages for this destination */
                    for (size_t j = 0; j < CYXWIZ_MAX_PENDING; j++) {
                        if (router->pending[j].valid &&
                            cyxwiz_node_id_cmp(&router->pending[j].destination,
                                              &router->discoveries[i].destination) == 0) {
                            router->pending[j].valid = false;
                        }
                    }
                }
            }
        }

        /* Expire old pending messages */
        for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
            if (router->pending[i].valid) {
                uint64_t age = current_time_ms - router->pending[i].queued_at;
                if (age > CYXWIZ_PENDING_TIMEOUT_MS) {
                    router->pending[i].valid = false;
                    CYXWIZ_DEBUG("Pending message expired");
                }
            }
        }

        /* Check for ACK timeouts - mark relay failure if no ACK received */
        for (size_t i = 0; i < CYXWIZ_MAX_PENDING_ACKS; i++) {
            if (router->pending_acks[i].valid) {
                uint64_t age = current_time_ms - router->pending_acks[i].sent_at;
                if (age > CYXWIZ_ACK_TIMEOUT_MS) {
                    /* No ACK received - record relay failure for first hop */
                    cyxwiz_peer_table_relay_failure(router->peer_table,
                        &router->pending_acks[i].first_hop);
                    router->pending_acks[i].valid = false;
                    CYXWIZ_DEBUG("ACK timeout - relay failure recorded");
                }
            }
        }

        /* Check for fragment reassembly timeouts */
        check_reassembly_timeouts(router, current_time_ms);

        router->last_cleanup = current_time_ms;
    }

    return CYXWIZ_OK;
}

/* ============ Sending ============ */

cyxwiz_error_t cyxwiz_router_send(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len)
{
    if (router == NULL || destination == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if destination is broadcast (all 0xFF) - use full transport MTU */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));
    if (cyxwiz_node_id_cmp(destination, &broadcast_id) == 0) {
        if (len > CYXWIZ_MAX_PACKET_SIZE) {
            return CYXWIZ_ERR_PACKET_TOO_LARGE;
        }
        /* Broadcast directly via transport */
        return router->transport->ops->send(
            router->transport, destination, data, len);
    }

    /* Check if destination is us */
    if (cyxwiz_node_id_cmp(destination, &router->local_id) == 0) {
        /* Deliver to self - no size limit for local delivery */
        if (router->on_delivery != NULL) {
            router->on_delivery(&router->local_id, data, len, router->user_data);
        }
        return CYXWIZ_OK;
    }

    /* Check if destination is a direct peer */
    if (is_direct_peer(router, destination)) {
        /* Send directly (no routing needed) - uses full transport MTU */
        if (len > CYXWIZ_MAX_PACKET_SIZE) {
            return CYXWIZ_ERR_PACKET_TOO_LARGE;
        }
        return router->transport->ops->send(
            router->transport, destination, data, len);
    }

    /* For multi-hop routed messages, enforce smaller payload limit */
    if (len > CYXWIZ_MAX_ROUTED_PAYLOAD) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Check if we have a cached route */
    cyxwiz_route_t *route = find_route(router, destination);
    if (route != NULL && route->valid) {
        /* Send via source route */
        uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
        cyxwiz_routed_data_t *msg = (cyxwiz_routed_data_t *)packet;

        msg->type = CYXWIZ_MSG_ROUTE_DATA;
        memcpy(&msg->origin, &router->local_id, sizeof(cyxwiz_node_id_t));
        msg->hop_count = route->hop_count;
        msg->current_hop = 0;
        memcpy(msg->path, route->hops, sizeof(cyxwiz_node_id_t) * route->hop_count);
        msg->payload_len = (uint8_t)len;

        size_t header_size = sizeof(cyxwiz_routed_data_t);
        memcpy(packet + header_size, data, len);

        /* Pad to MTU for traffic analysis prevention */
        cyxwiz_pad_message(packet, header_size + len, CYXWIZ_PADDED_SIZE);

        /* Send to first hop */
        cyxwiz_error_t err = router->transport->ops->send(
            router->transport, &route->hops[0], packet, CYXWIZ_PADDED_SIZE);

        if (err != CYXWIZ_OK) {
            /* First hop unreachable - invalidate route and retry */
            CYXWIZ_WARN("Route to first hop failed, invalidating and retrying");
            cyxwiz_peer_table_relay_failure(router->peer_table, &route->hops[0]);
            cyxwiz_router_invalidate_route(router, destination);

            /* Queue for rediscovery (recursive call triggers discovery) */
            return cyxwiz_router_send(router, destination, data, len);
        }

        /* Track pending ACK for relay success/failure detection */
        uint32_t msg_id = compute_message_id(data, len);
        track_pending_ack(router, msg_id, &route->hops[0]);

        return CYXWIZ_OK;
    }

    /* No route - queue message and start discovery */
    /* Find free pending slot */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (!router->pending[i].valid) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Queue the message */
    memcpy(&router->pending[slot].destination, destination, sizeof(cyxwiz_node_id_t));
    memcpy(router->pending[slot].data, data, len);
    router->pending[slot].len = len;
    router->pending[slot].queued_at = cyxwiz_time_ms();
    router->pending[slot].valid = true;

    /* Start route discovery if not already in progress */
    bool discovery_active = false;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (router->discoveries[i].active &&
            cyxwiz_node_id_cmp(&router->discoveries[i].destination, destination) == 0) {
            discovery_active = true;
            break;
        }
    }

    if (!discovery_active) {
        start_route_discovery(router, destination);
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(destination, hex_id);
    CYXWIZ_DEBUG("Queued message for %.16s..., waiting for route", hex_id);

    return CYXWIZ_OK;
}

bool cyxwiz_router_has_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    if (router == NULL || destination == NULL) {
        return false;
    }

    /* Direct peer counts as having a route */
    if (is_direct_peer(router, destination)) {
        return true;
    }

    cyxwiz_route_t *route = find_route(router, destination);
    return route != NULL && route->valid;
}

const cyxwiz_route_t *cyxwiz_router_get_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    if (router == NULL || destination == NULL) {
        return NULL;
    }
    return find_route(router, destination);
}

void cyxwiz_router_invalidate_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    if (router == NULL || destination == NULL) {
        return;
    }

    cyxwiz_route_t *route = find_route(router, destination);
    if (route != NULL) {
        route->valid = false;
        router->route_count--;

        char hex_id[65];
        cyxwiz_node_id_to_hex(destination, hex_id);
        CYXWIZ_DEBUG("Invalidated route to %.16s...", hex_id);
    }
}

/* ============ Message Handling ============ */

cyxwiz_error_t cyxwiz_router_handle_message(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (router == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case CYXWIZ_MSG_ROUTE_REQ:
            if (len >= sizeof(cyxwiz_route_req_t)) {
                return handle_route_req(router, from, (const cyxwiz_route_req_t *)data);
            }
            break;

        case CYXWIZ_MSG_ROUTE_REPLY:
            if (len >= sizeof(cyxwiz_route_reply_t)) {
                return handle_route_reply(router, from, (const cyxwiz_route_reply_t *)data);
            }
            break;

        case CYXWIZ_MSG_ROUTE_DATA:
            if (len >= sizeof(cyxwiz_routed_data_t)) {
                return handle_route_data(router, from, data, len);
            }
            break;

        case CYXWIZ_MSG_ROUTE_ERROR:
            if (len >= sizeof(cyxwiz_route_error_t)) {
                return handle_route_error(router, from, (const cyxwiz_route_error_t *)data);
            }
            break;

        case CYXWIZ_MSG_RELAY_ACK:
            if (len >= sizeof(cyxwiz_relay_ack_t)) {
                return handle_relay_ack(router, from, (const cyxwiz_relay_ack_t *)data);
            }
            break;

        case CYXWIZ_MSG_FRAG_DATA:
            if (len >= sizeof(cyxwiz_frag_data_t)) {
                return handle_frag_data(router, from, data, len);
            }
            break;

        case CYXWIZ_MSG_ONION_DATA:
            /* Forward to onion layer for decryption/routing */
            if (router->on_onion != NULL) {
                router->on_onion(from, data, len, router->onion_user_data);
            } else {
                CYXWIZ_WARN("Received onion message but no handler registered");
            }
            break;

#ifdef CYXWIZ_HAS_CRYPTO
        case CYXWIZ_MSG_ANON_ROUTE_REQ:
            if (len >= sizeof(cyxwiz_anon_route_req_t)) {
                return handle_anon_route_req(router, from, (const cyxwiz_anon_route_req_t *)data);
            }
            break;

        case CYXWIZ_MSG_ANON_ROUTE_REPLY:
            if (len >= sizeof(cyxwiz_anon_route_reply_t)) {
                return handle_anon_route_reply(router, from, (const cyxwiz_anon_route_reply_t *)data);
            }
            break;
#endif

        default:
            CYXWIZ_DEBUG("Unknown routing message type: 0x%02x", msg_type);
            break;
    }

    return CYXWIZ_OK;
}

/* ============ Statistics ============ */

size_t cyxwiz_router_route_count(const cyxwiz_router_t *router)
{
    if (router == NULL) {
        return 0;
    }
    return router->route_count;
}

size_t cyxwiz_router_pending_count(const cyxwiz_router_t *router)
{
    if (router == NULL) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (router->pending[i].valid) {
            count++;
        }
    }
    return count;
}

cyxwiz_peer_table_t *cyxwiz_router_get_peer_table(cyxwiz_router_t *router)
{
    if (router == NULL) {
        return NULL;
    }
    return router->peer_table;
}

/* ============ Internal Functions ============ */

static bool is_direct_peer(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(router->peer_table, destination);
    return peer != NULL && peer->state == CYXWIZ_PEER_STATE_CONNECTED;
}

/* Compute simple message ID from data (FNV-1a hash) */
static uint32_t compute_message_id(const uint8_t *data, size_t len)
{
    uint32_t hash = 2166136261u;  /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;  /* FNV prime */
    }
    return hash;
}

/* Track pending ACK for sent message */
static void track_pending_ack(cyxwiz_router_t *router, uint32_t message_id,
                              const cyxwiz_node_id_t *first_hop)
{
    /* Find empty slot */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_ACKS; i++) {
        if (!router->pending_acks[i].valid) {
            router->pending_acks[i].message_id = message_id;
            memcpy(&router->pending_acks[i].first_hop, first_hop, sizeof(cyxwiz_node_id_t));
            router->pending_acks[i].sent_at = cyxwiz_time_ms();
            router->pending_acks[i].valid = true;
            return;
        }
    }
    /* Table full - oldest entry will be evicted by timeout */
}

/* Clear pending ACK (on successful ACK receipt) */
static void clear_pending_ack(cyxwiz_router_t *router, uint32_t message_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_ACKS; i++) {
        if (router->pending_acks[i].valid &&
            router->pending_acks[i].message_id == message_id) {
            router->pending_acks[i].valid = false;
            return;
        }
    }
}

static cyxwiz_route_t *find_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ROUTES; i++) {
        if (router->routes[i].valid &&
            cyxwiz_node_id_cmp(&router->routes[i].destination, destination) == 0) {
            return &router->routes[i];
        }
    }
    return NULL;
}

static cyxwiz_error_t add_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const cyxwiz_node_id_t *path,
    uint8_t hop_count)
{
    /* Compute reputation of new route */
    uint16_t new_reputation = compute_route_reputation(router->peer_table, path, hop_count);

    /* Check if route already exists */
    cyxwiz_route_t *existing = find_route(router, destination);
    if (existing != NULL) {
        /* Only replace if new route has better reputation */
        if (new_reputation > existing->reputation_sum) {
            existing->hop_count = hop_count;
            memcpy(existing->hops, path, sizeof(cyxwiz_node_id_t) * hop_count);
            existing->discovered_at = cyxwiz_time_ms();
            existing->reputation_sum = new_reputation;

            char hex_id[65];
            cyxwiz_node_id_to_hex(destination, hex_id);
            CYXWIZ_DEBUG("Updated route to %.16s... (rep %u -> %u)",
                         hex_id, existing->reputation_sum, new_reputation);
        }
        return CYXWIZ_OK;
    }

    /* Find free slot */
    for (size_t i = 0; i < CYXWIZ_MAX_ROUTES; i++) {
        if (!router->routes[i].valid) {
            memcpy(&router->routes[i].destination, destination, sizeof(cyxwiz_node_id_t));
            router->routes[i].hop_count = hop_count;
            memcpy(router->routes[i].hops, path, sizeof(cyxwiz_node_id_t) * hop_count);
            router->routes[i].discovered_at = cyxwiz_time_ms();
            router->routes[i].latency_ms = 0;
            router->routes[i].reputation_sum = new_reputation;
            router->routes[i].valid = true;
            router->route_count++;

            char hex_id[65];
            cyxwiz_node_id_to_hex(destination, hex_id);
            CYXWIZ_INFO("Added route to %.16s... (%d hops, rep %u)",
                        hex_id, hop_count, new_reputation);

            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_NOMEM;
}

static bool is_request_seen(
    cyxwiz_router_t *router,
    uint32_t request_id,
    const cyxwiz_node_id_t *origin)
{
    for (size_t i = 0; i < router->seen_count; i++) {
        if (router->seen[i].request_id == request_id &&
            cyxwiz_node_id_cmp(&router->seen[i].origin, origin) == 0) {
            return true;
        }
    }
    return false;
}

static void mark_request_seen(
    cyxwiz_router_t *router,
    uint32_t request_id,
    const cyxwiz_node_id_t *origin,
    uint64_t now)
{
    if (router->seen_count >= CYXWIZ_MAX_SEEN_REQUESTS) {
        /* Shift array (remove oldest) */
        for (size_t i = 0; i < router->seen_count - 1; i++) {
            router->seen[i] = router->seen[i + 1];
        }
        router->seen_count--;
    }

    router->seen[router->seen_count].request_id = request_id;
    memcpy(&router->seen[router->seen_count].origin, origin, sizeof(cyxwiz_node_id_t));
    router->seen[router->seen_count].seen_at = now;
    router->seen_count++;
}

static cyxwiz_error_t start_route_discovery(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    /* Find free discovery slot */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (!router->discoveries[i].active) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    uint32_t request_id = router->next_request_id++;

    /* Record active discovery */
    router->discoveries[slot].request_id = request_id;
    memcpy(&router->discoveries[slot].destination, destination, sizeof(cyxwiz_node_id_t));
    router->discoveries[slot].started_at = cyxwiz_time_ms();
    router->discoveries[slot].active = true;

    /* Build route request */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = request_id;
    memcpy(&req.origin, &router->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, destination, sizeof(cyxwiz_node_id_t));
    req.hop_count = 0;
    req.ttl = CYXWIZ_DEFAULT_TTL;

    /* Broadcast to all connected peers */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    char hex_id[65];
    cyxwiz_node_id_to_hex(destination, hex_id);
    CYXWIZ_INFO("Starting route discovery for %.16s...", hex_id);

    return router->transport->ops->send(
        router->transport, &broadcast_id, (uint8_t *)&req, sizeof(req));
}

static cyxwiz_error_t send_pending_messages(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (router->pending[i].valid &&
            cyxwiz_node_id_cmp(&router->pending[i].destination, destination) == 0) {

            /* Send the queued message */
            cyxwiz_error_t err = cyxwiz_router_send(
                router,
                destination,
                router->pending[i].data,
                router->pending[i].len);

            /* Clear from queue regardless of success */
            router->pending[i].valid = false;

            if (err != CYXWIZ_OK) {
                CYXWIZ_WARN("Failed to send pending message: %s", cyxwiz_strerror(err));
            }
        }
    }

    /* Clear active discovery */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (router->discoveries[i].active &&
            cyxwiz_node_id_cmp(&router->discoveries[i].destination, destination) == 0) {
            router->discoveries[i].active = false;
        }
    }

    return CYXWIZ_OK;
}

/* ============ Message Handlers ============ */

static cyxwiz_error_t handle_route_req(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_req_t *req)
{
    CYXWIZ_UNUSED(from);

    /* Check if we've seen this request */
    if (is_request_seen(router, req->request_id, &req->origin)) {
        return CYXWIZ_OK;  /* Already processed, drop */
    }

    /* Mark as seen */
    mark_request_seen(router, req->request_id, &req->origin, cyxwiz_time_ms());

    /* Check TTL */
    if (req->ttl == 0) {
        return CYXWIZ_ERR_TTL_EXPIRED;
    }

    /* Check if we are the destination */
    if (cyxwiz_node_id_cmp(&req->destination, &router->local_id) == 0) {
        /* Send route reply back */
        cyxwiz_route_reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.type = CYXWIZ_MSG_ROUTE_REPLY;
        reply.request_id = req->request_id;
        memcpy(&reply.destination, &req->origin, sizeof(cyxwiz_node_id_t));
        reply.hop_count = req->hop_count + 1;

        /* Copy path and add ourselves at the end */
        memcpy(reply.path, req->path, sizeof(cyxwiz_node_id_t) * req->hop_count);
        memcpy(&reply.path[req->hop_count], &router->local_id, sizeof(cyxwiz_node_id_t));

        /* Send to previous hop (or origin if we're first hop) */
        const cyxwiz_node_id_t *next_hop = (req->hop_count > 0)
            ? &req->path[req->hop_count - 1]
            : &req->origin;

        char hex_id[65];
        cyxwiz_node_id_to_hex(&req->origin, hex_id);
        CYXWIZ_INFO("Sending route reply to %.16s...", hex_id);

        return router->transport->ops->send(
            router->transport, next_hop, (uint8_t *)&reply, sizeof(reply));
    }

    /* Check if path is full */
    if (req->hop_count >= CYXWIZ_MAX_HOPS) {
        return CYXWIZ_OK;  /* Can't add more hops */
    }

    /* Forward to our peers */
    cyxwiz_route_req_t forward;
    memcpy(&forward, req, sizeof(forward));
    forward.ttl = req->ttl - 1;
    forward.hop_count = req->hop_count + 1;
    memcpy(&forward.path[req->hop_count], &router->local_id, sizeof(cyxwiz_node_id_t));

    /* Broadcast to all connected peers */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    return router->transport->ops->send(
        router->transport, &broadcast_id, (uint8_t *)&forward, sizeof(forward));
}

static cyxwiz_error_t handle_route_reply(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_reply_t *reply)
{
    CYXWIZ_UNUSED(from);

    /* Check if this reply is for us (we initiated the discovery) */
    if (cyxwiz_node_id_cmp(&reply->destination, &router->local_id) == 0) {
        /* We found a route! */
        char hex_id[65];
        cyxwiz_node_id_to_hex(&reply->path[reply->hop_count - 1], hex_id);
        CYXWIZ_INFO("Route discovered to %.16s... (%d hops)", hex_id, reply->hop_count);

        /* Cache the route - path is from us to destination */
        add_route(router, &reply->path[reply->hop_count - 1], reply->path, reply->hop_count);

        /* Send pending messages */
        send_pending_messages(router, &reply->path[reply->hop_count - 1]);

        return CYXWIZ_OK;
    }

    /* Forward reply towards origin */
    /* Find our position in the path */
    int our_pos = -1;
    for (uint8_t i = 0; i < reply->hop_count; i++) {
        if (cyxwiz_node_id_cmp(&reply->path[i], &router->local_id) == 0) {
            our_pos = (int)i;
            break;
        }
    }

    if (our_pos < 0) {
        /* We're not in the path, shouldn't happen */
        CYXWIZ_WARN("Received route reply but not in path");
        return CYXWIZ_OK;
    }

    /* Send to previous hop */
    const cyxwiz_node_id_t *next_hop;
    if (our_pos == 0) {
        next_hop = &reply->destination;  /* Send to origin */
    } else {
        next_hop = &reply->path[our_pos - 1];
    }

    return router->transport->ops->send(
        router->transport, next_hop, (const uint8_t *)reply, sizeof(*reply));
}

static cyxwiz_error_t handle_route_data(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    const cyxwiz_routed_data_t *msg = (const cyxwiz_routed_data_t *)data;
    size_t header_size = sizeof(cyxwiz_routed_data_t);

    if (len < header_size + msg->payload_len) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if we are the destination */
    if (msg->current_hop >= msg->hop_count - 1 ||
        cyxwiz_node_id_cmp(&msg->path[msg->hop_count - 1], &router->local_id) == 0) {
        /* Deliver to application */
        if (router->on_delivery != NULL) {
            router->on_delivery(
                &msg->origin,
                data + header_size,
                msg->payload_len,
                router->user_data);
        }

        /* Update reputation: mark all hops as relay successes */
        for (uint8_t i = 0; i < msg->hop_count; i++) {
            cyxwiz_peer_table_relay_success(router->peer_table, &msg->path[i]);
        }

        /* Send RELAY_ACK back to origin */
        cyxwiz_relay_ack_t ack;
        memset(&ack, 0, sizeof(ack));
        ack.type = CYXWIZ_MSG_RELAY_ACK;
        ack.message_id = 0;  /* TODO: compute hash of message */
        memcpy(&ack.origin, &msg->origin, sizeof(cyxwiz_node_id_t));
        ack.hop_count = msg->hop_count;
        ack.current_hop = msg->hop_count - 1;

        /* Build reverse path */
        for (uint8_t i = 0; i < msg->hop_count; i++) {
            memcpy(&ack.path[i], &msg->path[msg->hop_count - 1 - i],
                   sizeof(cyxwiz_node_id_t));
        }

        /* Send ACK to first hop of reverse path (or origin if direct) */
        if (msg->hop_count > 1) {
            router->transport->ops->send(router->transport,
                &ack.path[0], (uint8_t *)&ack, sizeof(ack));
        } else {
            router->transport->ops->send(router->transport,
                &msg->origin, (uint8_t *)&ack, sizeof(ack));
        }

        char hex_id[65];
        cyxwiz_node_id_to_hex(&msg->origin, hex_id);
        CYXWIZ_DEBUG("Delivered %d bytes from %.16s...", msg->payload_len, hex_id);

        return CYXWIZ_OK;
    }

    /* Forward to next hop */
    uint8_t next_hop_idx = msg->current_hop + 1;
    if (next_hop_idx >= msg->hop_count) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Create forwarded message with updated current_hop */
    uint8_t forward[CYXWIZ_MAX_PACKET_SIZE];
    memcpy(forward, data, len);
    cyxwiz_routed_data_t *fwd_msg = (cyxwiz_routed_data_t *)forward;
    fwd_msg->current_hop = next_hop_idx;

    cyxwiz_error_t err = router->transport->ops->send(
        router->transport,
        &msg->path[next_hop_idx],
        forward,
        len);

    if (err != CYXWIZ_OK) {
        /* Send failed - notify origin and mark failure */
        CYXWIZ_WARN("Forward to next hop failed, sending ROUTE_ERROR");

        cyxwiz_peer_table_relay_failure(router->peer_table, &msg->path[next_hop_idx]);

        /* Send ROUTE_ERROR back to origin */
        cyxwiz_route_error_t route_err;
        memset(&route_err, 0, sizeof(route_err));
        route_err.type = CYXWIZ_MSG_ROUTE_ERROR;
        memcpy(&route_err.origin, &msg->origin, sizeof(cyxwiz_node_id_t));
        memcpy(&route_err.broken_link, &msg->path[next_hop_idx], sizeof(cyxwiz_node_id_t));

        /* Send error back along path (previous hop or origin) */
        if (msg->current_hop > 0) {
            router->transport->ops->send(router->transport,
                &msg->path[msg->current_hop - 1],
                (uint8_t *)&route_err, sizeof(route_err));
        } else {
            router->transport->ops->send(router->transport,
                &msg->origin,
                (uint8_t *)&route_err, sizeof(route_err));
        }

        return err;
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_route_error(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_error_t *err)
{
    CYXWIZ_UNUSED(from);

    /* Update reputation: mark broken link as relay failure */
    cyxwiz_peer_table_relay_failure(router->peer_table, &err->broken_link);

    /* Invalidate any route going through the broken link */
    for (size_t i = 0; i < CYXWIZ_MAX_ROUTES; i++) {
        if (router->routes[i].valid) {
            for (uint8_t j = 0; j < router->routes[i].hop_count; j++) {
                if (cyxwiz_node_id_cmp(&router->routes[i].hops[j], &err->broken_link) == 0) {
                    router->routes[i].valid = false;
                    router->route_count--;

                    char hex_id[65];
                    cyxwiz_node_id_to_hex(&router->routes[i].destination, hex_id);
                    CYXWIZ_WARN("Invalidated route to %.16s... (broken link)", hex_id);
                    break;
                }
            }
        }
    }

    return CYXWIZ_OK;
}

/*
 * Handle relay acknowledgment
 * Forward to next hop or accept if we are the origin
 */
static cyxwiz_error_t handle_relay_ack(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_relay_ack_t *ack)
{
    CYXWIZ_UNUSED(from);

    /* Check if we are the origin */
    if (cyxwiz_node_id_cmp(&ack->origin, &router->local_id) == 0) {
        /* ACK received - message was successfully delivered */
        CYXWIZ_DEBUG("Received relay ACK for message %u", ack->message_id);

        /* Clear pending ACK and record success for first hop */
        clear_pending_ack(router, ack->message_id);
        if (ack->hop_count > 0) {
            /* Record relay success for first hop (last in reverse path) */
            cyxwiz_peer_table_relay_success(router->peer_table,
                &ack->path[ack->hop_count - 1]);
        }
        return CYXWIZ_OK;
    }

    /* We are an intermediate hop - record success and forward */
    if (ack->current_hop > 0) {
        /* Mark the hop we received from as relay success */
        cyxwiz_peer_table_relay_success(router->peer_table, from);

        /* Forward to next hop in the ACK path */
        cyxwiz_relay_ack_t fwd_ack;
        memcpy(&fwd_ack, ack, sizeof(fwd_ack));
        fwd_ack.current_hop = ack->current_hop - 1;

        router->transport->ops->send(
            router->transport,
            &ack->path[fwd_ack.current_hop],
            (uint8_t *)&fwd_ack,
            sizeof(fwd_ack));
    }

    return CYXWIZ_OK;
}

/* ============ Anonymous Routing Implementation ============ */

#ifdef CYXWIZ_HAS_CRYPTO

/* Context string for destination token key derivation */
static const char DEST_TOKEN_CONTEXT[] = "cyxwiz_dest_v1";

/*
 * Check if an anonymous request nonce has been seen
 */
static bool is_anon_request_seen(
    cyxwiz_router_t *router,
    const uint8_t *nonce)
{
    for (size_t i = 0; i < router->anon_seen_count; i++) {
        if (memcmp(router->anon_seen[i].request_nonce, nonce,
                   CYXWIZ_REQUEST_NONCE_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Mark an anonymous request nonce as seen
 */
static void mark_anon_request_seen(
    cyxwiz_router_t *router,
    const uint8_t *nonce,
    uint64_t now)
{
    if (router->anon_seen_count >= CYXWIZ_MAX_SEEN_REQUESTS) {
        /* Shift array (remove oldest) */
        for (size_t i = 0; i < router->anon_seen_count - 1; i++) {
            router->anon_seen[i] = router->anon_seen[i + 1];
        }
        router->anon_seen_count--;
    }

    memcpy(router->anon_seen[router->anon_seen_count].request_nonce, nonce,
           CYXWIZ_REQUEST_NONCE_SIZE);
    router->anon_seen[router->anon_seen_count].seen_at = now;
    router->anon_seen_count++;
}

/*
 * Create encrypted destination token
 * Token = XChaCha20-Poly1305(key = BLAKE2b(ECDH(ephemeral_sk, dest_pubkey)),
 *                            plaintext = MAGIC[4] || padding[4])
 */
static cyxwiz_error_t create_dest_token(
    const uint8_t *ephemeral_sk,
    const uint8_t *dest_pubkey,
    uint8_t *token_out)
{
    uint8_t shared_secret[32];
    uint8_t derived_key[CYXWIZ_KEY_SIZE];

    /* X25519 DH with destination's public key */
    if (crypto_scalarmult(shared_secret, ephemeral_sk, dest_pubkey) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Derive key from shared secret */
    if (crypto_generichash(derived_key, CYXWIZ_KEY_SIZE,
                           shared_secret, 32,
                           (const uint8_t *)DEST_TOKEN_CONTEXT,
                           sizeof(DEST_TOKEN_CONTEXT) - 1) != 0) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return CYXWIZ_ERR_CRYPTO;
    }
    sodium_memzero(shared_secret, sizeof(shared_secret));

    /* Build plaintext: magic bytes + padding */
    uint8_t plaintext[8];
    uint32_t magic = CYXWIZ_DEST_TOKEN_MAGIC;
    memcpy(plaintext, &magic, 4);
    randombytes_buf(plaintext + 4, 4);  /* Random padding */

    /* Encrypt with XChaCha20-Poly1305 */
    uint8_t nonce[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    /* token = nonce (24) + ciphertext (8 + 16 tag) = 48 bytes */
    memcpy(token_out, nonce, sizeof(nonce));
    if (crypto_secretbox_easy(token_out + sizeof(nonce), plaintext, 8,
                              nonce, derived_key) != 0) {
        sodium_memzero(derived_key, sizeof(derived_key));
        return CYXWIZ_ERR_CRYPTO;
    }

    sodium_memzero(derived_key, sizeof(derived_key));
    return CYXWIZ_OK;
}

/*
 * Try to decrypt destination token using our keys
 * Returns true if this node is the intended destination
 */
static bool try_decrypt_dest_token(
    cyxwiz_onion_ctx_t *onion_ctx,
    const uint8_t *ephemeral_pk,
    const uint8_t *token)
{
    if (onion_ctx == NULL) {
        return false;
    }

    /* Compute ECDH shared secret: our_sk * ephemeral_pk */
    uint8_t shared_secret[32];
    if (cyxwiz_onion_compute_ecdh(onion_ctx, ephemeral_pk, shared_secret) != CYXWIZ_OK) {
        return false;
    }

    /* Derive encryption key from shared secret */
    uint8_t derived_key[CYXWIZ_KEY_SIZE];
    if (crypto_generichash(derived_key, CYXWIZ_KEY_SIZE,
                           shared_secret, 32,
                           (const uint8_t *)DEST_TOKEN_CONTEXT,
                           sizeof(DEST_TOKEN_CONTEXT) - 1) != 0) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return false;
    }
    sodium_memzero(shared_secret, sizeof(shared_secret));

    /* Parse the token: nonce (24) + ciphertext (8 + 16 tag = 24) */
    const uint8_t *nonce = token;
    const uint8_t *ciphertext = token + crypto_secretbox_xchacha20poly1305_NONCEBYTES;

    /* Try to decrypt */
    uint8_t plaintext[8];
    if (crypto_secretbox_open_easy(plaintext, ciphertext, 8 + crypto_secretbox_MACBYTES,
                                    nonce, derived_key) != 0) {
        /* Decryption failed - we are not the destination */
        sodium_memzero(derived_key, sizeof(derived_key));
        return false;
    }
    sodium_memzero(derived_key, sizeof(derived_key));

    /* Check magic bytes */
    uint32_t magic;
    memcpy(&magic, plaintext, 4);
    if (magic != CYXWIZ_DEST_TOKEN_MAGIC) {
        CYXWIZ_DEBUG("Token decrypted but magic mismatch");
        return false;
    }

    /* We are the intended destination! */
    CYXWIZ_DEBUG("Destination token verified - we are the destination");
    return true;
}

/*
 * Create a Single-Use Reply Block (SURB) for anonymous replies
 *
 * The SURB contains:
 * - first_hop: The first relay node to send the reply to
 * - onion_header: Encrypted routing info for 2 hops back to us
 */
static cyxwiz_error_t create_surb(
    cyxwiz_router_t *router,
    const uint8_t *request_nonce,
    cyxwiz_surb_t *surb_out,
    uint8_t *reply_key_out)
{
    CYXWIZ_UNUSED(request_nonce);

    if (router->onion_ctx == NULL) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Select relay nodes from known peers */
    cyxwiz_node_id_t relays[CYXWIZ_SURB_HOPS];
    uint8_t hop_keys[CYXWIZ_SURB_HOPS][CYXWIZ_KEY_SIZE];
    size_t relay_count = 0;

    /* Find peers we have shared keys with */
    for (size_t i = 0; i < 64 && relay_count < CYXWIZ_SURB_HOPS; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(
            router->peer_table, i);

        if (peer == NULL || peer->state != CYXWIZ_PEER_STATE_CONNECTED) {
            continue;
        }

        if (!cyxwiz_onion_has_key(router->onion_ctx, &peer->id)) {
            continue;
        }

        /* Copy peer ID as relay */
        memcpy(&relays[relay_count], &peer->id, sizeof(cyxwiz_node_id_t));

        /* Derive hop key using onion key derivation */
        /* The key is derived from our shared secret with this peer */
        uint8_t shared[CYXWIZ_KEY_SIZE];
        cyxwiz_onion_derive_hop_key(shared, &router->local_id,
                                    &peer->id, hop_keys[relay_count]);

        relay_count++;
    }

    if (relay_count < CYXWIZ_SURB_HOPS) {
        CYXWIZ_WARN("Not enough relay nodes for SURB (have %zu, need %d)",
                    relay_count, CYXWIZ_SURB_HOPS);
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Set first hop */
    memcpy(&surb_out->first_hop, &relays[0], sizeof(cyxwiz_node_id_t));

    /* Build onion header (routing info encrypted for each hop)
     * Structure for 2-hop SURB header:
     * Layer 2: Encrypt(key2, final_dest || zeros)  -> inner
     * Layer 1: Encrypt(key1, relay2 || inner)      -> header
     */

    /* The onion header contains routing info back to us */
    /* Final destination is our local_id with zeros as marker */
    uint8_t layer2_plain[sizeof(cyxwiz_node_id_t)];
    memset(layer2_plain, 0, sizeof(layer2_plain));  /* Zeros = final dest */

    /* Encrypt innermost layer for hop 2 (final hop -> us) */
    /* Note: Full implementation would encrypt here with proper keys */
    CYXWIZ_UNUSED(layer2_plain);
    CYXWIZ_UNUSED(hop_keys);

    /* For simplicity, use secretbox (would need proper nonce handling) */
    /* In production, use deterministic nonce from request_nonce */

    /* Build the onion header */
    memset(surb_out->onion_header, 0, CYXWIZ_SURB_HEADER_SIZE);

    /* For now, embed routing info directly (simplified)
     * Real implementation would use proper onion encryption */
    memcpy(surb_out->onion_header, &relays[1], sizeof(cyxwiz_node_id_t));
    memcpy(surb_out->onion_header + sizeof(cyxwiz_node_id_t),
           &router->local_id, sizeof(cyxwiz_node_id_t));

    /* Generate reply key for the origin to decrypt the reply */
    randombytes_buf(reply_key_out, CYXWIZ_KEY_SIZE);

    CYXWIZ_DEBUG("Created SURB with %zu relay hops", relay_count);

    return CYXWIZ_OK;
}

/*
 * Handle incoming anonymous route request
 */
static cyxwiz_error_t handle_anon_route_req(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_anon_route_req_t *req)
{
    CYXWIZ_UNUSED(from);

    /* Check version */
    if (req->version != CYXWIZ_ANON_VERSION) {
        CYXWIZ_DEBUG("Unknown anon route version: %d", req->version);
        return CYXWIZ_OK;
    }

    /* Check if we've seen this request (by nonce, not origin) */
    if (is_anon_request_seen(router, req->request_nonce)) {
        return CYXWIZ_OK;  /* Already processed */
    }

    /* Mark as seen */
    mark_anon_request_seen(router, req->request_nonce, cyxwiz_time_ms());

    /* Check TTL */
    if (req->ttl == 0) {
        return CYXWIZ_ERR_TTL_EXPIRED;
    }

    /* Try to decrypt destination token - are we the destination? */
    if (try_decrypt_dest_token(router->onion_ctx, req->ephemeral_pubkey,
                               req->dest_token)) {
        /* We are the destination! Send reply via SURB */
        CYXWIZ_INFO("Anonymous route request received - we are destination");

        /* Build reply payload */
        cyxwiz_anon_reply_payload_t payload;
        memset(&payload, 0, sizeof(payload));
        memcpy(payload.request_nonce, req->request_nonce,
               CYXWIZ_REQUEST_NONCE_SIZE);
        memcpy(&payload.responder_id, &router->local_id,
               sizeof(cyxwiz_node_id_t));

        /* Add our public key for circuit establishment */
        if (router->onion_ctx != NULL) {
            cyxwiz_onion_get_pubkey(router->onion_ctx, payload.responder_pubkey);
        }

        payload.reserved = 0;

        /* Build anonymous reply using SURB */
        cyxwiz_anon_route_reply_t reply;
        memset(&reply, 0, sizeof(reply));
        reply.type = CYXWIZ_MSG_ANON_ROUTE_REPLY;

        /* The SURB tells us where to send the reply */
        memcpy(&reply.next_hop, &req->surb.first_hop, sizeof(cyxwiz_node_id_t));

        /* Encrypt payload with SURB keys (simplified - would need proper
         * onion wrapping in production) */
        /* For now, just copy the onion header and payload */
        memcpy(reply.onion_payload, &payload, sizeof(payload));

        /* Send reply to SURB first hop */
        return router->transport->ops->send(
            router->transport,
            &req->surb.first_hop,
            (uint8_t *)&reply,
            sizeof(reply));
    }

    /* Not for us - forward the request */
    cyxwiz_anon_route_req_t forward;
    memcpy(&forward, req, sizeof(forward));
    forward.ttl = req->ttl - 1;

    /* Broadcast to all connected peers */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    return router->transport->ops->send(
        router->transport, &broadcast_id, (uint8_t *)&forward, sizeof(forward));
}

/*
 * Handle incoming anonymous route reply
 */
static cyxwiz_error_t handle_anon_route_reply(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_anon_route_reply_t *reply)
{
    CYXWIZ_UNUSED(from);

    /* Check if next_hop is zeros (we are final destination) */
    if (cyxwiz_node_id_is_zero(&reply->next_hop)) {
        /* This reply is for us - we initiated the anonymous discovery */
        CYXWIZ_INFO("Received anonymous route reply");

        /* Decrypt the payload to get route info */
        /* The payload should be encrypted with our reply key */
        const cyxwiz_anon_reply_payload_t *payload =
            (const cyxwiz_anon_reply_payload_t *)reply->onion_payload;

        /* Find the matching anon discovery */
        for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
            if (router->anon_discoveries[i].active &&
                memcmp(router->anon_discoveries[i].request_nonce,
                       payload->request_nonce,
                       CYXWIZ_REQUEST_NONCE_SIZE) == 0) {

                /* Found matching discovery - got identity confirmation */
                char hex_id[65];
                cyxwiz_node_id_to_hex(&payload->responder_id, hex_id);
                CYXWIZ_INFO("Anonymous route discovered to %.16s...", hex_id);

                /* Note: No path in anonymous reply - origin will use onion routing */

                /* Mark discovery complete */
                router->anon_discoveries[i].active = false;

                /* Securely clear ephemeral keys */
                sodium_memzero(router->anon_discoveries[i].ephemeral_sk, 32);

                return CYXWIZ_OK;
            }
        }

        CYXWIZ_WARN("Received anon reply but no matching discovery");
        return CYXWIZ_OK;
    }

    /* We are an intermediate relay - forward to next hop */
    /* Unwrap one layer of the SURB and forward */

    /* In a full implementation, we would:
     * 1. Decrypt our layer of the onion_payload
     * 2. Extract the new next_hop
     * 3. Forward the modified reply
     */

    /* For now, just forward to next_hop */
    return router->transport->ops->send(
        router->transport,
        &reply->next_hop,
        (const uint8_t *)reply,
        sizeof(*reply));
}

/*
 * Initiate anonymous route discovery
 */
cyxwiz_error_t cyxwiz_router_anon_discover(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *dest_pubkey)
{
    if (router == NULL || destination == NULL || dest_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (router->onion_ctx == NULL) {
        CYXWIZ_ERROR("Onion context required for anonymous routing");
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Find free discovery slot */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (!router->anon_discoveries[i].active) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Generate ephemeral X25519 keypair for this request */
    cyxwiz_anon_discovery_t *disc = &router->anon_discoveries[slot];
    crypto_box_keypair(disc->ephemeral_pk, disc->ephemeral_sk);

    /* Generate unique request nonce */
    randombytes_buf(disc->request_nonce, CYXWIZ_REQUEST_NONCE_SIZE);

    /* Store destination and timing */
    memcpy(&disc->destination, destination, sizeof(cyxwiz_node_id_t));
    disc->started_at = cyxwiz_time_ms();
    disc->active = true;

    /* Build anonymous route request */
    cyxwiz_anon_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ANON_ROUTE_REQ;
    req.version = CYXWIZ_ANON_VERSION;
    memcpy(req.ephemeral_pubkey, disc->ephemeral_pk, 32);

    /* Create encrypted destination token */
    cyxwiz_error_t err = create_dest_token(disc->ephemeral_sk, dest_pubkey,
                                           req.dest_token);
    if (err != CYXWIZ_OK) {
        disc->active = false;
        sodium_memzero(disc->ephemeral_sk, 32);
        return err;
    }

    /* Create SURB for anonymous reply path */
    uint8_t reply_key[CYXWIZ_KEY_SIZE];
    err = create_surb(router, disc->request_nonce, &req.surb, reply_key);
    if (err != CYXWIZ_OK) {
        disc->active = false;
        sodium_memzero(disc->ephemeral_sk, 32);
        return err;
    }

    /* Copy nonce and set TTL */
    memcpy(req.request_nonce, disc->request_nonce, CYXWIZ_REQUEST_NONCE_SIZE);
    req.ttl = CYXWIZ_DEFAULT_TTL;

    /* Broadcast to all connected peers */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    char hex_id[65];
    cyxwiz_node_id_to_hex(destination, hex_id);
    CYXWIZ_INFO("Starting anonymous route discovery for %.16s...", hex_id);

    return router->transport->ops->send(
        router->transport, &broadcast_id, (uint8_t *)&req, sizeof(req));
}

/*
 * Check if anonymous discovery is pending for destination
 */
bool cyxwiz_router_anon_discovery_pending(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    if (router == NULL || destination == NULL) {
        return false;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (router->anon_discoveries[i].active &&
            cyxwiz_node_id_cmp(&router->anon_discoveries[i].destination,
                               destination) == 0) {
            return true;
        }
    }

    return false;
}

/*
 * Send data anonymously via onion routing
 * Hides sender identity from all intermediate nodes and destination
 */
cyxwiz_error_t cyxwiz_router_send_anonymous(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len)
{
    if (router == NULL || destination == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Require onion context for anonymous sending */
    if (router->onion_ctx == NULL) {
        CYXWIZ_ERROR("Onion context required for anonymous sending");
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Check payload size (2-hop onion max = 101 bytes) */
    size_t max_payload = cyxwiz_onion_max_payload(2);
    if (len > max_payload) {
        CYXWIZ_WARN("Payload too large for anonymous send: %zu > %zu",
                    len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Delegate to onion layer which handles circuit building */
    cyxwiz_error_t err = cyxwiz_onion_send_to(
        router->onion_ctx, destination, data, len);

    if (err == CYXWIZ_OK) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(destination, hex_id);
        CYXWIZ_DEBUG("Sent %zu bytes anonymously to %.16s...", len, hex_id);
    }

    return err;
}

/*
 * Check if anonymous route (circuit) exists to destination
 */
bool cyxwiz_router_has_anonymous_route(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    if (router == NULL || destination == NULL) {
        return false;
    }

    if (router->onion_ctx == NULL) {
        return false;
    }

    return cyxwiz_onion_has_circuit_to(router->onion_ctx, destination);
}

/*
 * Send data via SURB (Single-Use Reply Block)
 * Used by compute layer for anonymous job result delivery
 */
cyxwiz_error_t cyxwiz_router_send_via_surb(
    cyxwiz_router_t *router,
    const cyxwiz_surb_t *surb,
    const uint8_t *data,
    size_t len)
{
    if (router == NULL || surb == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check payload size (must fit in onion_payload minus MAC) */
    size_t max_payload = CYXWIZ_ANON_REPLY_PAYLOAD_SIZE - CYXWIZ_MAC_SIZE;
    if (len > max_payload) {
        CYXWIZ_WARN("Payload too large for SURB send: %zu > %zu", len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Build anonymous reply message to carry the data */
    cyxwiz_anon_route_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = CYXWIZ_MSG_ANON_ROUTE_REPLY;

    /* SURB onion_header encodes the next_hop for relay nodes
     * The first_hop knows how to unwrap and forward */
    /* For the first hop, extract next_hop from onion_header if needed
     * For simplicity, we put zeros in next_hop and let first_hop handle routing */
    memset(&reply.next_hop, 0, sizeof(reply.next_hop));

    /* Copy the SURB onion header into the first part of onion_payload
     * This allows relay nodes to unwrap and forward */
    memcpy(reply.onion_payload, surb->onion_header, CYXWIZ_SURB_HEADER_SIZE);

    /* Append the actual payload data after the header */
    size_t offset = CYXWIZ_SURB_HEADER_SIZE;
    if (offset + len <= CYXWIZ_ANON_REPLY_PAYLOAD_SIZE) {
        memcpy(reply.onion_payload + offset, data, len);
    }

    /* Send to SURB's first hop - they will unwrap and forward */
    char hex_hop[65];
    cyxwiz_node_id_to_hex(&surb->first_hop, hex_hop);
    CYXWIZ_DEBUG("Sending %zu bytes via SURB to first_hop %.16s...", len, hex_hop);

    return router->transport->ops->send(
        router->transport,
        &surb->first_hop,
        (uint8_t *)&reply,
        sizeof(reply));
}

/*
 * Create a SURB for anonymous reply (public wrapper)
 */
cyxwiz_error_t cyxwiz_router_create_surb(
    cyxwiz_router_t *router,
    cyxwiz_surb_t *surb_out)
{
    if (router == NULL || surb_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Generate a random nonce for SURB creation */
    uint8_t nonce[CYXWIZ_REQUEST_NONCE_SIZE];
    randombytes_buf(nonce, sizeof(nonce));

    /* Reply key is not needed externally for compute jobs
     * (results are MACed with job-specific key) */
    uint8_t reply_key[CYXWIZ_KEY_SIZE];

    cyxwiz_error_t err = create_surb(router, nonce, surb_out, reply_key);

    /* Clear reply key - not needed for compute SURB */
    sodium_memzero(reply_key, sizeof(reply_key));

    return err;
}

/*
 * Check if SURB creation is possible
 */
bool cyxwiz_router_can_create_surb(const cyxwiz_router_t *router)
{
    if (router == NULL || router->onion_ctx == NULL) {
        return false;
    }

    /* Count peers with shared keys */
    size_t relay_count = 0;
    for (size_t i = 0; i < 64 && relay_count < CYXWIZ_SURB_HOPS; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(
            router->peer_table, i);

        if (peer == NULL || peer->state != CYXWIZ_PEER_STATE_CONNECTED) {
            continue;
        }

        if (!cyxwiz_onion_has_key(router->onion_ctx, &peer->id)) {
            continue;
        }

        relay_count++;
    }

    return relay_count >= CYXWIZ_SURB_HOPS;
}

#endif /* CYXWIZ_HAS_CRYPTO */

/* ============ Message Fragmentation ============ */

/*
 * Check for reassembly timeouts and clear stale entries
 */
static void check_reassembly_timeouts(
    cyxwiz_router_t *router,
    uint64_t now)
{
    for (size_t i = 0; i < CYXWIZ_MAX_REASSEMBLY; i++) {
        if (router->reassembly[i].valid) {
            uint64_t age = now - router->reassembly[i].started_at;
            if (age > CYXWIZ_FRAG_TIMEOUT_MS) {
                router->reassembly[i].valid = false;
                CYXWIZ_DEBUG("Fragment reassembly timeout (msg_id %u)",
                    router->reassembly[i].message_id);
            }
        }
    }
}

/*
 * Find or create reassembly slot for a message
 */
static cyxwiz_frag_reassembly_t *find_or_create_reassembly(
    cyxwiz_router_t *router,
    uint32_t message_id,
    const cyxwiz_node_id_t *origin,
    uint8_t frag_total,
    uint64_t now)
{
    /* Look for existing reassembly for this message */
    for (size_t i = 0; i < CYXWIZ_MAX_REASSEMBLY; i++) {
        if (router->reassembly[i].valid &&
            router->reassembly[i].message_id == message_id &&
            cyxwiz_node_id_cmp(&router->reassembly[i].origin, origin) == 0) {
            return &router->reassembly[i];
        }
    }

    /* Find free slot */
    for (size_t i = 0; i < CYXWIZ_MAX_REASSEMBLY; i++) {
        if (!router->reassembly[i].valid) {
            cyxwiz_frag_reassembly_t *r = &router->reassembly[i];
            memset(r, 0, sizeof(*r));
            r->message_id = message_id;
            memcpy(&r->origin, origin, sizeof(cyxwiz_node_id_t));
            r->frag_total = frag_total;
            r->frag_received = 0;
            r->frag_bitmap = 0;
            r->started_at = now;
            r->valid = true;
            return r;
        }
    }

    CYXWIZ_WARN("Fragment reassembly table full");
    return NULL;
}

/*
 * Handle incoming fragmented data
 */
static cyxwiz_error_t handle_frag_data(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    const cyxwiz_frag_data_t *frag = (const cyxwiz_frag_data_t *)data;
    size_t header_size = sizeof(cyxwiz_frag_data_t);

    /* Validate header */
    if (len < header_size) {
        CYXWIZ_WARN("Fragment data too short");
        return CYXWIZ_ERR_INVALID;
    }

    if (frag->frag_total > CYXWIZ_FRAG_MAX_COUNT) {
        CYXWIZ_WARN("Fragment count too high: %u", frag->frag_total);
        return CYXWIZ_ERR_INVALID;
    }

    if (frag->frag_index >= frag->frag_total) {
        CYXWIZ_WARN("Invalid fragment index: %u/%u", frag->frag_index, frag->frag_total);
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if this is for us */
    if (cyxwiz_node_id_cmp(&frag->destination, &router->local_id) != 0) {
        /* Forward to next hop (if we have a route) */
        return cyxwiz_router_send(router, &frag->destination, data, len);
    }

    /* This fragment is for us - reassemble */
    uint64_t now = cyxwiz_time_ms();
    cyxwiz_frag_reassembly_t *r = find_or_create_reassembly(
        router, frag->message_id, &frag->origin, frag->frag_total, now);

    if (r == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Check for duplicate fragment */
    uint8_t frag_bit = (1 << frag->frag_index);
    if (r->frag_bitmap & frag_bit) {
        CYXWIZ_DEBUG("Duplicate fragment %u/%u", frag->frag_index, frag->frag_total);
        return CYXWIZ_OK;  /* Already have this fragment */
    }

    /* Copy fragment data */
    const uint8_t *frag_payload = data + header_size;
    size_t frag_payload_len = len - header_size;

    if (frag_payload_len > CYXWIZ_FRAG_MAX_PAYLOAD) {
        CYXWIZ_WARN("Fragment payload too large: %zu", frag_payload_len);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Store at correct offset */
    size_t offset = (size_t)frag->frag_index * CYXWIZ_FRAG_MAX_PAYLOAD;
    memcpy(r->data + offset, frag_payload, frag_payload_len);
    r->fragment_lens[frag->frag_index] = frag_payload_len;

    /* Mark fragment as received */
    r->frag_bitmap |= frag_bit;
    r->frag_received++;

    CYXWIZ_DEBUG("Received fragment %u/%u (msg_id %u)",
        frag->frag_index + 1, frag->frag_total, frag->message_id);

    /* Check if all fragments received */
    if (r->frag_received >= r->frag_total) {
        /* Calculate total size */
        size_t total_len = 0;
        for (uint8_t i = 0; i < r->frag_total; i++) {
            total_len += r->fragment_lens[i];
        }

        /* Compact the data (fragments may have different sizes) */
        uint8_t reassembled[CYXWIZ_FRAG_MAX_TOTAL];
        size_t pos = 0;
        for (uint8_t i = 0; i < r->frag_total; i++) {
            size_t src_offset = (size_t)i * CYXWIZ_FRAG_MAX_PAYLOAD;
            memcpy(reassembled + pos, r->data + src_offset, r->fragment_lens[i]);
            pos += r->fragment_lens[i];
        }

        CYXWIZ_INFO("Reassembled fragmented message: %zu bytes from %u fragments",
            total_len, r->frag_total);

        /* Clear reassembly slot */
        r->valid = false;

        /* Deliver to application */
        if (router->on_delivery != NULL) {
            router->on_delivery(&frag->origin, reassembled, total_len, router->user_data);
        }
    }

    return CYXWIZ_OK;
}

/*
 * Send large data with automatic fragmentation
 */
cyxwiz_error_t cyxwiz_router_send_large(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len)
{
    if (router == NULL || destination == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* If small enough, send directly */
    if (len <= CYXWIZ_MAX_ROUTED_PAYLOAD) {
        return cyxwiz_router_send(router, destination, data, len);
    }

    /* Check max size */
    if (len > CYXWIZ_FRAG_MAX_TOTAL) {
        CYXWIZ_WARN("Data too large for fragmentation: %zu > %d",
            len, CYXWIZ_FRAG_MAX_TOTAL);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Calculate number of fragments needed */
    uint8_t frag_total = (uint8_t)((len + CYXWIZ_FRAG_MAX_PAYLOAD - 1) / CYXWIZ_FRAG_MAX_PAYLOAD);
    if (frag_total > CYXWIZ_FRAG_MAX_COUNT) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Generate message ID */
    uint32_t message_id = router->next_frag_message_id++;

    CYXWIZ_DEBUG("Fragmenting %zu bytes into %u fragments (msg_id %u)",
        len, frag_total, message_id);

    /* Send each fragment */
    size_t offset = 0;
    for (uint8_t i = 0; i < frag_total; i++) {
        size_t frag_len = CYXWIZ_FRAG_MAX_PAYLOAD;
        if (offset + frag_len > len) {
            frag_len = len - offset;
        }

        /* Build fragment packet */
        uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
        cyxwiz_frag_data_t *frag = (cyxwiz_frag_data_t *)packet;

        frag->type = CYXWIZ_MSG_FRAG_DATA;
        frag->message_id = message_id;
        frag->frag_index = i;
        frag->frag_total = frag_total;
        frag->frag_len = (uint8_t)frag_len;
        memcpy(&frag->origin, &router->local_id, sizeof(cyxwiz_node_id_t));
        memcpy(&frag->destination, destination, sizeof(cyxwiz_node_id_t));

        /* Copy payload */
        memcpy(packet + sizeof(cyxwiz_frag_data_t), data + offset, frag_len);

        size_t packet_len = sizeof(cyxwiz_frag_data_t) + frag_len;

        /* Send fragment */
        cyxwiz_error_t err = cyxwiz_router_send(router, destination, packet, packet_len);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send fragment %u/%u: %d", i + 1, frag_total, err);
            return err;
        }

        offset += frag_len;
    }

    return CYXWIZ_OK;
}
