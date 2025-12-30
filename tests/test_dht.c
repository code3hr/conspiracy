/*
 * CyxWiz Protocol - DHT Tests
 *
 * Tests for Kademlia-style Distributed Hash Table implementation.
 */

/* Disable MSVC warning C4127: conditional expression is constant */
#ifdef _MSC_VER
#pragma warning(disable: 4127)
#endif

#include "cyxwiz/types.h"
#include "cyxwiz/dht.h"
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
        int result = test_##name(); \
        if (result == 1) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else if (result == -1) { \
            printf("SKIP (not available in this environment)\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while (0)

/* Test XOR distance calculation */
static int test_xor_distance(void)
{
    cyxwiz_node_id_t a, b;
    uint8_t distance[CYXWIZ_NODE_ID_LEN];

    /* Test 1: Same ID should give zero distance */
    memset(&a, 0x55, sizeof(a));
    memcpy(&b, &a, sizeof(b));

    cyxwiz_dht_xor_distance(&a, &b, distance);

    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        if (distance[i] != 0) {
            return 0;
        }
    }

    /* Test 2: Opposite bytes should give 0xFF */
    memset(&a, 0x00, sizeof(a));
    memset(&b, 0xFF, sizeof(b));

    cyxwiz_dht_xor_distance(&a, &b, distance);

    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        if (distance[i] != 0xFF) {
            return 0;
        }
    }

    /* Test 3: Known XOR */
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.bytes[0] = 0x80;  /* 10000000 */
    b.bytes[0] = 0x40;  /* 01000000 */

    cyxwiz_dht_xor_distance(&a, &b, distance);

    /* XOR should be 0xC0 (11000000) */
    if (distance[0] != 0xC0) {
        return 0;
    }

    return 1;
}

/* Test distance comparison */
static int test_distance_cmp(void)
{
    uint8_t dist_a[CYXWIZ_NODE_ID_LEN];
    uint8_t dist_b[CYXWIZ_NODE_ID_LEN];

    /* Test 1: Equal distances */
    memset(dist_a, 0x55, sizeof(dist_a));
    memset(dist_b, 0x55, sizeof(dist_b));

    if (cyxwiz_dht_distance_cmp(dist_a, dist_b) != 0) {
        return 0;
    }

    /* Test 2: a < b */
    memset(dist_a, 0, sizeof(dist_a));
    memset(dist_b, 0, sizeof(dist_b));
    dist_a[0] = 0x10;
    dist_b[0] = 0x20;

    if (cyxwiz_dht_distance_cmp(dist_a, dist_b) >= 0) {
        return 0;
    }

    /* Test 3: a > b */
    if (cyxwiz_dht_distance_cmp(dist_b, dist_a) <= 0) {
        return 0;
    }

    return 1;
}

/* Test bucket index calculation */
static int test_bucket_index(void)
{
    cyxwiz_node_id_t local, remote;

    /* Test 1: Same node should return -1 */
    memset(&local, 0x55, sizeof(local));
    memcpy(&remote, &local, sizeof(remote));

    int idx = cyxwiz_dht_bucket_index(&local, &remote);
    if (idx != -1) {
        return 0;
    }

    /* Test 2: First bit different -> bucket 0 */
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));
    local.bytes[0] = 0x00;   /* 00000000 */
    remote.bytes[0] = 0x80;  /* 10000000 */

    idx = cyxwiz_dht_bucket_index(&local, &remote);
    if (idx != 0) {
        printf("(expected 0, got %d) ", idx);
        return 0;
    }

    /* Test 3: Second bit different -> bucket 1 */
    local.bytes[0] = 0x00;   /* 00000000 */
    remote.bytes[0] = 0x40;  /* 01000000 */

    idx = cyxwiz_dht_bucket_index(&local, &remote);
    if (idx != 1) {
        printf("(expected 1, got %d) ", idx);
        return 0;
    }

    /* Test 4: 8th bit different -> bucket 7 */
    local.bytes[0] = 0x00;   /* 00000000 */
    remote.bytes[0] = 0x01;  /* 00000001 */

    idx = cyxwiz_dht_bucket_index(&local, &remote);
    if (idx != 7) {
        printf("(expected 7, got %d) ", idx);
        return 0;
    }

    /* Test 5: First bit of second byte different -> bucket 8 */
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));
    remote.bytes[1] = 0x80;

    idx = cyxwiz_dht_bucket_index(&local, &remote);
    if (idx != 8) {
        printf("(expected 8, got %d) ", idx);
        return 0;
    }

    return 1;
}

/* Test DHT message structure sizes */
static int test_message_sizes(void)
{
    /* Verify packed structures fit in LoRa MTU */

    /* PING: 37 bytes */
    if (sizeof(cyxwiz_dht_ping_t) != 37) {
        printf("(ping size %zu != 37) ", sizeof(cyxwiz_dht_ping_t));
        return 0;
    }

    /* PONG: 37 bytes */
    if (sizeof(cyxwiz_dht_pong_t) != 37) {
        printf("(pong size %zu != 37) ", sizeof(cyxwiz_dht_pong_t));
        return 0;
    }

    /* FIND_NODE: 37 bytes */
    if (sizeof(cyxwiz_dht_find_node_t) != 37) {
        printf("(find_node size %zu != 37) ", sizeof(cyxwiz_dht_find_node_t));
        return 0;
    }

    /* FIND_NODE_RESP header: 6 bytes */
    if (sizeof(cyxwiz_dht_find_node_resp_t) != 6) {
        printf("(find_node_resp size %zu != 6) ", sizeof(cyxwiz_dht_find_node_resp_t));
        return 0;
    }

    /* Node entry: 36 bytes */
    if (sizeof(cyxwiz_dht_node_entry_t) != 36) {
        printf("(node_entry size %zu != 36) ", sizeof(cyxwiz_dht_node_entry_t));
        return 0;
    }

    /* Full FIND_NODE_RESP with 6 nodes: 6 + 6*36 = 222 bytes < 250 */
    size_t max_resp = sizeof(cyxwiz_dht_find_node_resp_t) +
                      CYXWIZ_DHT_MAX_PEERS_RESP * sizeof(cyxwiz_dht_node_entry_t);
    if (max_resp > CYXWIZ_MAX_PACKET_SIZE) {
        printf("(max response %zu > %d) ", max_resp, CYXWIZ_MAX_PACKET_SIZE);
        return 0;
    }

    return 1;
}

/* Test DHT creation without router (should work with NULL router for basic testing) */
static int test_dht_create_null_params(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_error_t err;

    /* NULL output param */
    memset(&local_id, 0x11, sizeof(local_id));
    err = cyxwiz_dht_create(NULL, NULL, &local_id);
    if (err != CYXWIZ_ERR_INVALID) {
        return 0;
    }

    /* NULL local_id */
    err = cyxwiz_dht_create(&dht, NULL, NULL);
    if (err != CYXWIZ_ERR_INVALID) {
        return 0;
    }

    return 1;
}

/* Test DHT stats on empty DHT */
static int test_dht_empty_stats(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_dht_stats_t stats;

    memset(&local_id, 0x22, sizeof(local_id));

    /* Create with NULL router (basic mode) */
    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK || dht == NULL) {
        return 0;
    }

    /* Get stats */
    cyxwiz_dht_get_stats(dht, &stats);

    /* Empty DHT should have zero stats */
    if (stats.total_nodes != 0 ||
        stats.active_buckets != 0 ||
        stats.pending_lookups != 0 ||
        stats.messages_sent != 0 ||
        stats.messages_received != 0) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

/* Test adding nodes to DHT */
static int test_dht_add_node(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id, node1, node2;
    cyxwiz_dht_stats_t stats;

    memset(&local_id, 0, sizeof(local_id));
    local_id.bytes[0] = 0x00;

    /* Create DHT */
    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK || dht == NULL) {
        return 0;
    }

    /* Add a node in bucket 0 (MSB different) */
    memset(&node1, 0, sizeof(node1));
    node1.bytes[0] = 0x80;  /* Different in first bit */

    err = cyxwiz_dht_add_node(dht, &node1);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_get_stats(dht, &stats);
    if (stats.total_nodes != 1) {
        printf("(expected 1 node, got %zu) ", stats.total_nodes);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    /* Add another node in different bucket */
    memset(&node2, 0, sizeof(node2));
    node2.bytes[0] = 0x40;  /* Different in second bit */

    err = cyxwiz_dht_add_node(dht, &node2);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_get_stats(dht, &stats);
    if (stats.total_nodes != 2) {
        printf("(expected 2 nodes, got %zu) ", stats.total_nodes);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    /* Adding same node again should not increase count */
    err = cyxwiz_dht_add_node(dht, &node1);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_get_stats(dht, &stats);
    if (stats.total_nodes != 2) {
        printf("(duplicate node increased count to %zu) ", stats.total_nodes);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

/* Test get_closest functionality */
static int test_dht_get_closest(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id, target;
    cyxwiz_node_id_t nodes[8];
    cyxwiz_node_id_t closest[CYXWIZ_DHT_K];

    memset(&local_id, 0, sizeof(local_id));

    /* Create DHT */
    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Add 8 nodes with varying distances */
    for (int i = 0; i < 8; i++) {
        memset(&nodes[i], 0, sizeof(nodes[i]));
        nodes[i].bytes[0] = (uint8_t)(1 << (7 - i));  /* 0x80, 0x40, 0x20, ... */
        cyxwiz_dht_add_node(dht, &nodes[i]);
    }

    /* Target is close to node with 0x01 (smallest distance from 0x00 target) */
    memset(&target, 0, sizeof(target));
    target.bytes[0] = 0x01;

    /* Get closest */
    size_t count = cyxwiz_dht_get_closest(dht, &target, closest, CYXWIZ_DHT_K);

    if (count != 8) {
        printf("(expected 8 closest, got %zu) ", count);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    /* First closest should be the node that matches (0x01 XOR 0x01 = 0x00) */
    /* Actually nodes[7] has bytes[0] = 0x01 */
    if (closest[0].bytes[0] != 0x01) {
        printf("(first closest bytes[0] = 0x%02x, expected 0x01) ", closest[0].bytes[0]);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

/* Test DHT poll with no router (should not crash) */
static int test_dht_poll_no_router(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id;

    memset(&local_id, 0x33, sizeof(local_id));

    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Poll should work without crashing even with no router */
    err = cyxwiz_dht_poll(dht, 1000);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    err = cyxwiz_dht_poll(dht, 2000);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

/* Test self-add prevention */
static int test_dht_no_self_add(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_dht_stats_t stats;

    memset(&local_id, 0x44, sizeof(local_id));

    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Try to add self - should be silently ignored */
    err = cyxwiz_dht_add_node(dht, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_get_stats(dht, &stats);
    if (stats.total_nodes != 0) {
        printf("(self was added: %zu nodes) ", stats.total_nodes);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

/* Test bucket capacity (K=8) */
static int test_dht_bucket_capacity(void)
{
    cyxwiz_dht_t *dht = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_dht_stats_t stats;

    memset(&local_id, 0, sizeof(local_id));

    cyxwiz_error_t err = cyxwiz_dht_create(&dht, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Add K nodes to same bucket (all have first bit = 1, so bucket 0) */
    for (int i = 0; i < CYXWIZ_DHT_K; i++) {
        cyxwiz_node_id_t node;
        memset(&node, 0, sizeof(node));
        node.bytes[0] = 0x80;  /* First bit different = bucket 0 */
        node.bytes[31] = (uint8_t)i;  /* Unique nodes */

        err = cyxwiz_dht_add_node(dht, &node);
        if (err != CYXWIZ_OK) {
            cyxwiz_dht_destroy(dht);
            return 0;
        }
    }

    cyxwiz_dht_get_stats(dht, &stats);
    if (stats.total_nodes != CYXWIZ_DHT_K) {
        printf("(expected %d nodes, got %zu) ", CYXWIZ_DHT_K, stats.total_nodes);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    /* Should have exactly 1 active bucket */
    if (stats.active_buckets != 1) {
        printf("(expected 1 bucket, got %zu) ", stats.active_buckets);
        cyxwiz_dht_destroy(dht);
        return 0;
    }

    cyxwiz_dht_destroy(dht);
    return 1;
}

int main(void)
{
    printf("CyxWiz DHT Tests\n");
    printf("================\n\n");

    printf("Utility Functions:\n");
    TEST(xor_distance);
    TEST(distance_cmp);
    TEST(bucket_index);

    printf("\nMessage Structures:\n");
    TEST(message_sizes);

    printf("\nDHT Operations:\n");
    TEST(dht_create_null_params);
    TEST(dht_empty_stats);
    TEST(dht_add_node);
    TEST(dht_get_closest);
    TEST(dht_poll_no_router);
    TEST(dht_no_self_add);
    TEST(dht_bucket_capacity);

    printf("\n================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
