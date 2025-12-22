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
    r->running = false;
    r->next_request_id = 1;
    r->last_cleanup = 0;

    /* Initialize pending and discoveries */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        r->pending[i].valid = false;
        r->discoveries[i].active = false;
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

    if (len > CYXWIZ_MAX_ROUTED_PAYLOAD) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Check if destination is us */
    if (cyxwiz_node_id_cmp(destination, &router->local_id) == 0) {
        /* Deliver to self */
        if (router->on_delivery != NULL) {
            router->on_delivery(&router->local_id, data, len, router->user_data);
        }
        return CYXWIZ_OK;
    }

    /* Check if destination is a direct peer */
    if (is_direct_peer(router, destination)) {
        /* Send directly (no routing needed) */
        return router->transport->ops->send(
            router->transport, destination, data, len);
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

        /* Send to first hop */
        return router->transport->ops->send(
            router->transport, &route->hops[0], packet, header_size + len);
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

        case CYXWIZ_MSG_ONION_DATA:
            /* Forward to onion layer for decryption/routing */
            if (router->on_onion != NULL) {
                router->on_onion(from, data, len, router->onion_user_data);
            } else {
                CYXWIZ_WARN("Received onion message but no handler registered");
            }
            break;

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

/* ============ Internal Functions ============ */

static bool is_direct_peer(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *destination)
{
    const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(router->peer_table, destination);
    return peer != NULL && peer->state == CYXWIZ_PEER_STATE_CONNECTED;
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
    /* Check if route already exists */
    cyxwiz_route_t *existing = find_route(router, destination);
    if (existing != NULL) {
        /* Update existing route */
        existing->hop_count = hop_count;
        memcpy(existing->hops, path, sizeof(cyxwiz_node_id_t) * hop_count);
        existing->discovered_at = cyxwiz_time_ms();
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
            router->routes[i].valid = true;
            router->route_count++;

            char hex_id[65];
            cyxwiz_node_id_to_hex(destination, hex_id);
            CYXWIZ_INFO("Added route to %.16s... (%d hops)", hex_id, hop_count);

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

    return router->transport->ops->send(
        router->transport,
        &msg->path[next_hop_idx],
        forward,
        len);
}

static cyxwiz_error_t handle_route_error(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *from,
    const cyxwiz_route_error_t *err)
{
    CYXWIZ_UNUSED(from);

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
