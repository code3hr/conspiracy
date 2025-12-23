/*
 * CyxWiz Protocol - Routing Tests
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

/* Test router creation and destruction */
static int test_router_create_destroy(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_error_t err;

    /* Create peer table */
    err = cyxwiz_peer_table_create(&peer_table);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create transport */
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    if (err != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Generate local ID */
    cyxwiz_node_id_random(&local_id);

    /* Create router */
    err = cyxwiz_router_create(&router, peer_table, transport, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (router == NULL) {
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Verify initial state */
    if (cyxwiz_router_route_count(router) != 0) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (cyxwiz_router_pending_count(router) != 0) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Cleanup */
    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test router start/stop */
static int test_router_start_stop(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);

    /* Start router */
    err = cyxwiz_router_start(router);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Start again should be OK */
    err = cyxwiz_router_start(router);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Stop router */
    err = cyxwiz_router_stop(router);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Stop again should be OK */
    err = cyxwiz_router_stop(router);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test has_route for direct peer */
static int test_has_route_direct_peer(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, peer_id;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&peer_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* No route initially */
    if (cyxwiz_router_has_route(router, &peer_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Add peer to table */
    cyxwiz_peer_table_add(peer_table, &peer_id, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &peer_id, CYXWIZ_PEER_STATE_CONNECTED);

    /* Now should have route (direct peer) */
    if (!cyxwiz_router_has_route(router, &peer_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test route request message format */
static int test_route_req_format(void)
{
    cyxwiz_route_req_t req;
    memset(&req, 0, sizeof(req));

    req.type = CYXWIZ_MSG_ROUTE_REQ;
    req.request_id = 12345;
    req.ttl = 10;
    req.hop_count = 0;

    /* Verify type field can be set and read */
    if (req.type != CYXWIZ_MSG_ROUTE_REQ) {
        return 0;
    }

    /* Verify size fits in LoRa packet */
    if (sizeof(cyxwiz_route_req_t) > CYXWIZ_MAX_PACKET_SIZE) {
        return 0;
    }

    return 1;
}

/* Test route reply message format */
static int test_route_reply_format(void)
{
    cyxwiz_route_reply_t reply;
    memset(&reply, 0, sizeof(reply));

    reply.type = CYXWIZ_MSG_ROUTE_REPLY;
    reply.request_id = 12345;
    reply.hop_count = 3;

    /* Verify type field is first byte */
    uint8_t *bytes = (uint8_t *)&reply;
    if (bytes[0] != CYXWIZ_MSG_ROUTE_REPLY) {
        return 0;
    }

    /* Verify size fits in LoRa packet */
    if (sizeof(cyxwiz_route_reply_t) > CYXWIZ_MAX_PACKET_SIZE) {
        return 0;
    }

    return 1;
}

/* Test routed data message format */
static int test_routed_data_format(void)
{
    cyxwiz_routed_data_t data;
    memset(&data, 0, sizeof(data));

    data.type = CYXWIZ_MSG_ROUTE_DATA;
    data.hop_count = 3;
    data.current_hop = 0;
    data.payload_len = 10;

    /* Verify type field can be set and read */
    if (data.type != CYXWIZ_MSG_ROUTE_DATA) {
        return 0;
    }

    /* Verify header size leaves room for payload */
    if (sizeof(cyxwiz_routed_data_t) + CYXWIZ_MAX_ROUTED_PAYLOAD > CYXWIZ_MAX_PACKET_SIZE) {
        return 0;
    }

    return 1;
}

/* Test router poll */
static int test_router_poll(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Poll should succeed */
    uint64_t now = cyxwiz_time_ms();
    err = cyxwiz_router_poll(router, now);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Poll again */
    err = cyxwiz_router_poll(router, now + 1000);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test send to self */
static int test_send_to_self(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Send to self should succeed (loopback) */
    uint8_t data[] = "Hello, self!";
    err = cyxwiz_router_send(router, &local_id, data, sizeof(data));
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test invalidate route */
static int test_invalidate_route(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, dest_id;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&dest_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Initially no route */
    if (cyxwiz_router_get_route(router, &dest_id) != NULL) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Invalidate non-existent route should be safe */
    cyxwiz_router_invalidate_route(router, &dest_id);

    /* Still no route */
    if (cyxwiz_router_get_route(router, &dest_id) != NULL) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test anonymous route request message format */
static int test_anon_route_req_format(void)
{
    cyxwiz_anon_route_req_t req;
    memset(&req, 0, sizeof(req));

    req.type = CYXWIZ_MSG_ANON_ROUTE_REQ;
    req.version = CYXWIZ_ANON_VERSION;
    req.ttl = CYXWIZ_DEFAULT_TTL;

    /* Verify type field is first byte */
    uint8_t *bytes = (uint8_t *)&req;
    if (bytes[0] != CYXWIZ_MSG_ANON_ROUTE_REQ) {
        return 0;
    }

    /* Verify size fits in LoRa packet (should be ~219 bytes) */
    if (sizeof(cyxwiz_anon_route_req_t) > CYXWIZ_MAX_PACKET_SIZE) {
        printf("anon_route_req too large: %zu > %d", sizeof(cyxwiz_anon_route_req_t), CYXWIZ_MAX_PACKET_SIZE);
        return 0;
    }

    /* Verify expected size range */
    if (sizeof(cyxwiz_anon_route_req_t) < 200 || sizeof(cyxwiz_anon_route_req_t) > 230) {
        printf("unexpected size: %zu", sizeof(cyxwiz_anon_route_req_t));
        return 0;
    }

    return 1;
}

/* Test anonymous route reply message format */
static int test_anon_route_reply_format(void)
{
    cyxwiz_anon_route_reply_t reply;
    memset(&reply, 0, sizeof(reply));

    reply.type = CYXWIZ_MSG_ANON_ROUTE_REPLY;

    /* Verify type field is first byte */
    uint8_t *bytes = (uint8_t *)&reply;
    if (bytes[0] != CYXWIZ_MSG_ANON_ROUTE_REPLY) {
        return 0;
    }

    /* Verify size fits in LoRa packet (should be ~193 bytes) */
    if (sizeof(cyxwiz_anon_route_reply_t) > CYXWIZ_MAX_PACKET_SIZE) {
        printf("anon_route_reply too large: %zu > %d", sizeof(cyxwiz_anon_route_reply_t), CYXWIZ_MAX_PACKET_SIZE);
        return 0;
    }

    return 1;
}

/* Test SURB structure format */
static int test_surb_format(void)
{
    cyxwiz_surb_t surb;
    memset(&surb, 0, sizeof(surb));

    /* Verify SURB size is as expected (120 bytes = 32 first_hop + 88 onion_header) */
    if (sizeof(cyxwiz_surb_t) != CYXWIZ_SURB_SIZE) {
        printf("surb size mismatch: %zu != %d", sizeof(cyxwiz_surb_t), CYXWIZ_SURB_SIZE);
        return 0;
    }

    /* Verify first_hop is at start */
    if (sizeof(surb.first_hop) != CYXWIZ_NODE_ID_LEN) {
        return 0;
    }

    /* Verify onion_header size */
    if (sizeof(surb.onion_header) != CYXWIZ_SURB_HEADER_SIZE) {
        return 0;
    }

    return 1;
}

/* Test anonymous reply payload format */
static int test_anon_reply_payload_format(void)
{
    cyxwiz_anon_reply_payload_t payload;
    memset(&payload, 0, sizeof(payload));

    /* Verify payload fields exist and are properly sized */
    if (sizeof(payload.request_nonce) != CYXWIZ_REQUEST_NONCE_SIZE) {
        return 0;
    }

    if (sizeof(payload.responder_id) != sizeof(cyxwiz_node_id_t)) {
        return 0;
    }

    if (sizeof(payload.responder_pubkey) != 32) {
        return 0;
    }

    /* Verify payload structure is compact (~81 bytes) */
    if (sizeof(cyxwiz_anon_reply_payload_t) > 100) {
        printf("payload too large: %zu (expected ~81)", sizeof(cyxwiz_anon_reply_payload_t));
        return 0;
    }

    /* Verify payload fits in reply's onion_payload */
    if (sizeof(cyxwiz_anon_reply_payload_t) > CYXWIZ_ANON_REPLY_PAYLOAD_SIZE) {
        printf("payload too large: %zu > %d", sizeof(cyxwiz_anon_reply_payload_t), CYXWIZ_ANON_REPLY_PAYLOAD_SIZE);
        return 0;
    }

    return 1;
}

/* Test anonymous discovery pending */
static int test_anon_discovery_pending(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, dest_id;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&dest_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Initially no discovery pending */
    if (cyxwiz_router_anon_discovery_pending(router, &dest_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* NULL checks */
    if (cyxwiz_router_anon_discovery_pending(NULL, &dest_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (cyxwiz_router_anon_discovery_pending(router, NULL)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test anonymous send requires onion context */
static int test_anon_send_requires_onion_ctx(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, dest_id;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&dest_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Without onion context, anonymous send should fail */
    uint8_t data[] = "anonymous test";
    cyxwiz_error_t err = cyxwiz_router_send_anonymous(router, &dest_id, data, sizeof(data));

    /* Should fail with CYXWIZ_ERR_NOT_INITIALIZED */
    if (err != CYXWIZ_ERR_NOT_INITIALIZED) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test anonymous route check */
static int test_has_anonymous_route(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, dest_id;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&dest_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Without onion context, should return false */
    if (cyxwiz_router_has_anonymous_route(router, &dest_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* NULL checks */
    if (cyxwiz_router_has_anonymous_route(NULL, &dest_id)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    if (cyxwiz_router_has_anonymous_route(router, NULL)) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

/* Test anonymous send parameter validation */
static int test_anon_send_validation(void)
{
    cyxwiz_node_id_t dest_id;
    cyxwiz_node_id_random(&dest_id);
    uint8_t data[] = "test";

    /* NULL router should fail */
    cyxwiz_error_t err = cyxwiz_router_send_anonymous(NULL, &dest_id, data, sizeof(data));
    if (err == CYXWIZ_OK) {
        return 0;
    }

    return 1;
}

/* Test payload size limit */
static int test_payload_size_limit(void)
{
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_node_id_t local_id, dest_id;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&peer_table);
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    cyxwiz_node_id_random(&local_id);
    cyxwiz_node_id_random(&dest_id);
    cyxwiz_router_create(&router, peer_table, transport, &local_id);
    cyxwiz_router_start(router);

    /* Add destination as peer so we have a route */
    cyxwiz_peer_table_add(peer_table, &dest_id, CYXWIZ_TRANSPORT_WIFI_DIRECT, -50);
    cyxwiz_peer_table_set_state(peer_table, &dest_id, CYXWIZ_PEER_STATE_CONNECTED);

    /* Send exactly max payload */
    uint8_t data[CYXWIZ_MAX_ROUTED_PAYLOAD];
    memset(data, 0xAA, sizeof(data));
    err = cyxwiz_router_send(router, &dest_id, data, CYXWIZ_MAX_ROUTED_PAYLOAD);
    if (err != CYXWIZ_OK) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    /* Send over max payload should fail */
    uint8_t big_data[CYXWIZ_MAX_ROUTED_PAYLOAD + 1];
    memset(big_data, 0xBB, sizeof(big_data));
    err = cyxwiz_router_send(router, &dest_id, big_data, sizeof(big_data));
    if (err != CYXWIZ_ERR_PACKET_TOO_LARGE) {
        cyxwiz_router_destroy(router);
        cyxwiz_transport_destroy(transport);
        cyxwiz_peer_table_destroy(peer_table);
        return 0;
    }

    cyxwiz_router_destroy(router);
    cyxwiz_transport_destroy(transport);
    cyxwiz_peer_table_destroy(peer_table);

    return 1;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Routing Tests\n");
    printf("====================\n\n");

    TEST(router_create_destroy);
    TEST(router_start_stop);
    TEST(has_route_direct_peer);
    TEST(route_req_format);
    TEST(route_reply_format);
    TEST(routed_data_format);
    TEST(router_poll);
    TEST(send_to_self);
    TEST(invalidate_route);
    TEST(payload_size_limit);

    /* Anonymous routing tests */
    TEST(anon_route_req_format);
    TEST(anon_route_reply_format);
    TEST(surb_format);
    TEST(anon_reply_payload_format);
    TEST(anon_discovery_pending);
    TEST(anon_send_requires_onion_ctx);
    TEST(has_anonymous_route);
    TEST(anon_send_validation);

    printf("\n====================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
