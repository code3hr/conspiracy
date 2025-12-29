/*
 * CyxWiz Protocol - Multi-Hop Routing Integration Tests
 *
 * Tests for verifying multi-hop message routing:
 * - Route request forwarding
 * - Route reply handling
 * - Data forwarding through intermediate nodes
 * - Request deduplication
 * - TTL handling
 */

#include "cyxwiz/types.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("  Testing: %s... ", #name); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while (0)

/* ============ Mock Transport ============ */

#define MAX_SENT_MESSAGES 32
#define MAX_MESSAGE_SIZE 256

typedef struct {
    cyxwiz_node_id_t sent_to[MAX_SENT_MESSAGES];
    uint8_t sent_data[MAX_SENT_MESSAGES][MAX_MESSAGE_SIZE];
    size_t sent_len[MAX_SENT_MESSAGES];
    size_t send_count;
    bool is_broadcast[MAX_SENT_MESSAGES];
} mock_transport_state_t;

static mock_transport_state_t g_mock_state;

static void mock_reset(void)
{
    memset(&g_mock_state, 0, sizeof(g_mock_state));
}

static bool is_broadcast_id(const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < sizeof(cyxwiz_node_id_t); i++) {
        if (id->bytes[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static cyxwiz_error_t mock_send(cyxwiz_transport_t *transport,
                                 const cyxwiz_node_id_t *to,
                                 const uint8_t *data,
                                 size_t len)
{
    CYXWIZ_UNUSED(transport);

    if (g_mock_state.send_count >= MAX_SENT_MESSAGES) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    size_t idx = g_mock_state.send_count;
    memcpy(&g_mock_state.sent_to[idx], to, sizeof(cyxwiz_node_id_t));
    memcpy(g_mock_state.sent_data[idx], data, len < MAX_MESSAGE_SIZE ? len : MAX_MESSAGE_SIZE);
    g_mock_state.sent_len[idx] = len;
    g_mock_state.is_broadcast[idx] = is_broadcast_id(to);
    g_mock_state.send_count++;

    return CYXWIZ_OK;
}

static cyxwiz_error_t mock_init(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return CYXWIZ_OK;
}

static cyxwiz_error_t mock_shutdown(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return CYXWIZ_OK;
}

static cyxwiz_error_t mock_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return CYXWIZ_OK;
}

static cyxwiz_error_t mock_stop_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return CYXWIZ_OK;
}

static size_t mock_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return CYXWIZ_MAX_PACKET_SIZE;
}

static cyxwiz_error_t mock_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(timeout_ms);
    return CYXWIZ_OK;
}

static const cyxwiz_transport_ops_t mock_ops = {
    .init = mock_init,
    .shutdown = mock_shutdown,
    .send = mock_send,
    .discover = mock_discover,
    .stop_discover = mock_stop_discover,
    .max_packet_size = mock_max_packet_size,
    .poll = mock_poll
};

static cyxwiz_transport_t *create_mock_transport(void)
{
    cyxwiz_transport_t *transport = cyxwiz_calloc(1, sizeof(cyxwiz_transport_t));
    if (transport == NULL) {
        return NULL;
    }
    transport->type = CYXWIZ_TRANSPORT_WIFI_DIRECT;
    transport->ops = &mock_ops;
    transport->driver_data = NULL;
    return transport;
}

static void destroy_mock_transport(cyxwiz_transport_t *transport)
{
    if (transport != NULL) {
        cyxwiz_free(transport, sizeof(cyxwiz_transport_t));
    }
}

/* ============ Helper Functions ============ */

/* Create a predictable node ID for testing */
static void make_node_id(cyxwiz_node_id_t *id, uint8_t value)
{
    memset(id->bytes, value, sizeof(id->bytes));
}

/* Check if the last sent message was to a specific destination */
static bool last_sent_to(const cyxwiz_node_id_t *expected)
{
    if (g_mock_state.send_count == 0) {
        return false;
    }
    size_t idx = g_mock_state.send_count - 1;
    return memcmp(&g_mock_state.sent_to[idx], expected, sizeof(cyxwiz_node_id_t)) == 0;
}

/* Check if a broadcast was sent */
static bool broadcast_sent(void)
{
    for (size_t i = 0; i < g_mock_state.send_count; i++) {
        if (g_mock_state.is_broadcast[i]) {
            return true;
        }
    }
    return false;
}

/* Get the message type from last sent message */
static uint8_t last_sent_type(void)
{
    if (g_mock_state.send_count == 0) {
        return 0;
    }
    return g_mock_state.sent_data[g_mock_state.send_count - 1][0];
}

/* ============ Tests ============ */

/*
 * Test: Route request forwarding
 * Create intermediate node B, send ROUTE_REQ through it
 * Verify B receives and forwards the request with itself added to path
 */
static int test_route_req_forwarding(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create B's router */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_b, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_b);
    cyxwiz_router_start(router);

    /* Add A and C as connected peers of B */
    cyxwiz_peer_table_add(peer_table, &id_a, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_a, CYXWIZ_PEER_STATE_CONNECTED);
    cyxwiz_peer_table_add(peer_table, &id_c, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_c, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REQ from A looking for C */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 12345;
    memcpy(&req.origin, &id_a, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, &id_c, sizeof(cyxwiz_node_id_t));
    req.hop_count = 0;
    req.ttl = 10;

    /* Deliver to B's router */
    cyxwiz_router_handle_message(router, &id_a, (uint8_t *)&req, sizeof(req));

    /* Verify B forwarded the request (broadcast) */
    bool result = broadcast_sent();
    if (!result) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify forwarded message has B in path */
    if (g_mock_state.send_count == 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_route_req_t *fwd = (cyxwiz_route_req_t *)g_mock_state.sent_data[0];
    if (fwd->hop_count != 1) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (memcmp(&fwd->path[0], &id_b, sizeof(cyxwiz_node_id_t)) != 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify TTL was decremented */
    if (fwd->ttl != 9) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/*
 * Test: Route reply at destination
 * When destination receives ROUTE_REQ, it should send ROUTE_REPLY back
 */
static int test_route_reply_at_destination(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create C's router (the destination) */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_c, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_c);
    cyxwiz_router_start(router);

    /* Add B as connected peer */
    cyxwiz_peer_table_add(peer_table, &id_b, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_b, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REQ from A (via B) looking for C */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 12345;
    memcpy(&req.origin, &id_a, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, &id_c, sizeof(cyxwiz_node_id_t));  /* C is destination */
    req.hop_count = 1;
    memcpy(&req.path[0], &id_b, sizeof(cyxwiz_node_id_t));  /* B is in path */
    req.ttl = 9;

    /* Deliver to C's router */
    cyxwiz_router_handle_message(router, &id_b, (uint8_t *)&req, sizeof(req));

    /* Verify C sent ROUTE_REPLY */
    if (g_mock_state.send_count == 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (last_sent_type() != CYXWIZ_MSG_ROUTE_REPLY) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify reply was sent to B (previous hop) */
    if (!last_sent_to(&id_b)) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify reply contains C in path */
    cyxwiz_route_reply_t *reply = (cyxwiz_route_reply_t *)g_mock_state.sent_data[0];
    if (reply->hop_count != 2) {  /* B and C */
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/*
 * Test: Route reply forwarding at intermediate node
 */
static int test_route_reply_forwarding(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create B's router (intermediate node) */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_b, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_b);
    cyxwiz_router_start(router);

    /* Add A and C as connected peers */
    cyxwiz_peer_table_add(peer_table, &id_a, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_a, CYXWIZ_PEER_STATE_CONNECTED);
    cyxwiz_peer_table_add(peer_table, &id_c, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_c, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REPLY from C going to A, via B */
    cyxwiz_route_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = CYXWIZ_MSG_ROUTE_REPLY;
    reply.request_id = 12345;
    memcpy(&reply.destination, &id_a, sizeof(cyxwiz_node_id_t));  /* Going to A */
    reply.hop_count = 2;
    memcpy(&reply.path[0], &id_b, sizeof(cyxwiz_node_id_t));  /* B is first hop */
    memcpy(&reply.path[1], &id_c, sizeof(cyxwiz_node_id_t));  /* C is destination */

    /* Deliver to B's router (from C) */
    cyxwiz_router_handle_message(router, &id_c, (uint8_t *)&reply, sizeof(reply));

    /* Verify B forwarded reply to A */
    if (g_mock_state.send_count == 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (!last_sent_to(&id_a)) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (last_sent_type() != CYXWIZ_MSG_ROUTE_REPLY) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/*
 * Test: Data forwarding through intermediate node
 */
static int test_data_forwarding(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create B's router (intermediate node) */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_b, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_b);
    cyxwiz_router_start(router);

    /* Add A and C as connected peers */
    cyxwiz_peer_table_add(peer_table, &id_a, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_a, CYXWIZ_PEER_STATE_CONNECTED);
    cyxwiz_peer_table_add(peer_table, &id_c, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_c, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build routed data from A to C via B */
    uint8_t packet[256];
    cyxwiz_routed_data_t *data = (cyxwiz_routed_data_t *)packet;
    memset(packet, 0, sizeof(packet));
    data->type = CYXWIZ_MSG_ROUTE_DATA;
    memcpy(&data->origin, &id_a, sizeof(cyxwiz_node_id_t));
    data->hop_count = 2;
    data->current_hop = 0;  /* At B (index 0) */
    memcpy(&data->path[0], &id_b, sizeof(cyxwiz_node_id_t));
    memcpy(&data->path[1], &id_c, sizeof(cyxwiz_node_id_t));
    data->payload_len = 5;
    memcpy(packet + sizeof(cyxwiz_routed_data_t), "Hello", 5);

    /* Deliver to B's router */
    cyxwiz_router_handle_message(router, &id_a, packet, sizeof(cyxwiz_routed_data_t) + 5);

    /* Verify B forwarded to C */
    if (g_mock_state.send_count == 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (!last_sent_to(&id_c)) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify current_hop was incremented */
    cyxwiz_routed_data_t *fwd = (cyxwiz_routed_data_t *)g_mock_state.sent_data[0];
    if (fwd->current_hop != 1) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Delivery tracking for test_data_delivery */
static bool g_delivered = false;
static uint8_t g_delivered_data[256];
static size_t g_delivered_len = 0;

static void delivery_callback(const cyxwiz_node_id_t *from,
                               const uint8_t *data,
                               size_t len,
                               void *user_data)
{
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(user_data);
    g_delivered = true;
    if (len <= sizeof(g_delivered_data)) {
        memcpy(g_delivered_data, data, len);
    }
    g_delivered_len = len;
}

/*
 * Test: Data delivery at final destination
 */
static int test_data_delivery(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create C's router (destination) */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_c, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_c);
    cyxwiz_router_start(router);

    /* Reset delivery tracking */
    g_delivered = false;
    g_delivered_len = 0;

    cyxwiz_router_set_callback(router, delivery_callback, NULL);

    /* Add B as connected peer */
    cyxwiz_peer_table_add(peer_table, &id_b, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_b, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build routed data from A to C via B (already at C) */
    uint8_t packet[256];
    cyxwiz_routed_data_t *data = (cyxwiz_routed_data_t *)packet;
    memset(packet, 0, sizeof(packet));
    data->type = CYXWIZ_MSG_ROUTE_DATA;
    memcpy(&data->origin, &id_a, sizeof(cyxwiz_node_id_t));
    data->hop_count = 2;
    data->current_hop = 1;  /* At C (index 1) */
    memcpy(&data->path[0], &id_b, sizeof(cyxwiz_node_id_t));
    memcpy(&data->path[1], &id_c, sizeof(cyxwiz_node_id_t));
    data->payload_len = 5;
    memcpy(packet + sizeof(cyxwiz_routed_data_t), "Hello", 5);

    /* Deliver to C's router */
    cyxwiz_router_handle_message(router, &id_b, packet, sizeof(cyxwiz_routed_data_t) + 5);

    /* Verify data was delivered to callback (not forwarded) */
    if (!g_delivered) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (g_delivered_len != 5 || memcmp(g_delivered_data, "Hello", 5) != 0) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Exactly one message should have been sent: RELAY_ACK */
    if (g_mock_state.send_count != 1) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify it was a RELAY_ACK */
    if (last_sent_type() != CYXWIZ_MSG_RELAY_ACK) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/*
 * Test: Request deduplication
 * Same ROUTE_REQ should only be processed once
 */
static int test_request_deduplication(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create B's router */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_b, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_b);
    cyxwiz_router_start(router);

    /* Add peers */
    cyxwiz_peer_table_add(peer_table, &id_a, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_a, CYXWIZ_PEER_STATE_CONNECTED);
    cyxwiz_peer_table_add(peer_table, &id_c, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_c, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REQ */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 99999;
    memcpy(&req.origin, &id_a, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, &id_c, sizeof(cyxwiz_node_id_t));
    req.hop_count = 0;
    req.ttl = 10;

    /* Send first time */
    cyxwiz_router_handle_message(router, &id_a, (uint8_t *)&req, sizeof(req));
    size_t first_count = g_mock_state.send_count;

    /* Send same request again */
    cyxwiz_router_handle_message(router, &id_a, (uint8_t *)&req, sizeof(req));
    size_t second_count = g_mock_state.send_count;

    /* Second should not generate new messages (deduplicated) */
    bool result = (first_count > 0 && second_count == first_count);

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return result ? 1 : 0;
}

/*
 * Test: TTL expiry stops forwarding
 */
static int test_ttl_expiry(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create B's router */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_b, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_b);
    cyxwiz_router_start(router);

    /* Add peers */
    cyxwiz_peer_table_add(peer_table, &id_a, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_a, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REQ with TTL=0 */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 77777;
    memcpy(&req.origin, &id_a, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, &id_c, sizeof(cyxwiz_node_id_t));
    req.hop_count = 0;
    req.ttl = 0;  /* Expired! */

    /* Send to B */
    cyxwiz_router_handle_message(router, &id_a, (uint8_t *)&req, sizeof(req));

    /* Should NOT forward (TTL expired) */
    bool result = (g_mock_state.send_count == 0);

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return result ? 1 : 0;
}

/*
 * Test: Route error invalidates cached routes
 */
static int test_route_error(void)
{
    mock_reset();

    cyxwiz_node_id_t id_a, id_b, id_c;
    make_node_id(&id_a, 0xAA);
    make_node_id(&id_b, 0xBB);
    make_node_id(&id_c, 0xCC);

    /* Create A's router */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_a, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_a);
    cyxwiz_router_start(router);

    /* Add B as peer */
    cyxwiz_peer_table_add(peer_table, &id_b, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_b, CYXWIZ_PEER_STATE_CONNECTED);

    /* Simulate route discovery: A receives ROUTE_REPLY for C via B */
    cyxwiz_route_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = CYXWIZ_MSG_ROUTE_REPLY;
    reply.request_id = 11111;
    memcpy(&reply.destination, &id_a, sizeof(cyxwiz_node_id_t));  /* Reply is for A */
    reply.hop_count = 2;
    memcpy(&reply.path[0], &id_b, sizeof(cyxwiz_node_id_t));
    memcpy(&reply.path[1], &id_c, sizeof(cyxwiz_node_id_t));

    cyxwiz_router_handle_message(router, &id_b, (uint8_t *)&reply, sizeof(reply));

    /* Verify route was cached */
    if (!cyxwiz_router_has_route(router, &id_c)) {
        cyxwiz_router_destroy(router);
        destroy_mock_transport(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Now send ROUTE_ERROR indicating B is broken */
    cyxwiz_route_error_t error;
    memset(&error, 0, sizeof(error));
    error.type = CYXWIZ_MSG_ROUTE_ERROR;
    memcpy(&error.origin, &id_a, sizeof(cyxwiz_node_id_t));
    memcpy(&error.broken_link, &id_b, sizeof(cyxwiz_node_id_t));

    cyxwiz_router_handle_message(router, &id_b, (uint8_t *)&error, sizeof(error));

    /* Route should now be invalidated */
    bool result = !cyxwiz_router_has_route(router, &id_c);

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return result ? 1 : 0;
}

/*
 * Test: Max hops limit
 */
static int test_max_hops_limit(void)
{
    mock_reset();

    cyxwiz_node_id_t id_local, id_origin, id_dest;
    make_node_id(&id_local, 0x11);
    make_node_id(&id_origin, 0x00);
    make_node_id(&id_dest, 0xFF);

    /* Create router */
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;

    cyxwiz_peer_table_create(&peer_table);
    transport = create_mock_transport();
    memcpy(&transport->local_id, &id_local, sizeof(cyxwiz_node_id_t));
    cyxwiz_router_create(&router, peer_table, transport, &id_local);
    cyxwiz_router_start(router);

    /* Add a peer */
    cyxwiz_node_id_t id_peer;
    make_node_id(&id_peer, 0x22);
    cyxwiz_peer_table_add(peer_table, &id_peer, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &id_peer, CYXWIZ_PEER_STATE_CONNECTED);

    /* Build ROUTE_REQ with max hops already reached */
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 88888;
    memcpy(&req.origin, &id_origin, sizeof(cyxwiz_node_id_t));
    memcpy(&req.destination, &id_dest, sizeof(cyxwiz_node_id_t));
    req.hop_count = CYXWIZ_MAX_HOPS;  /* Already at max! */
    req.ttl = 10;

    /* Fill path with dummy hops */
    for (int i = 0; i < CYXWIZ_MAX_HOPS; i++) {
        make_node_id(&req.path[i], (uint8_t)(0x30 + i));
    }

    /* Send to router */
    cyxwiz_router_handle_message(router, &id_peer, (uint8_t *)&req, sizeof(req));

    /* Should NOT forward (path full) */
    bool result = (g_mock_state.send_count == 0);

    cyxwiz_router_destroy(router);
    destroy_mock_transport(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return result ? 1 : 0;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Multi-Hop Routing Tests\n");
    printf("==============================\n\n");

    TEST(route_req_forwarding);
    TEST(route_reply_at_destination);
    TEST(route_reply_forwarding);
    TEST(data_forwarding);
    TEST(data_delivery);
    TEST(request_deduplication);
    TEST(ttl_expiry);
    TEST(route_error);
    TEST(max_hops_limit);

    printf("\n==============================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
