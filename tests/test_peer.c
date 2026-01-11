/*
 * CyxWiz Protocol - Peer Discovery Tests
 */

#include "cyxwiz/types.h"
#include "cyxwiz/peer.h"
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

/* Test peer table creation */
static int test_peer_table_create(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_peer_table_create(&table);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    if (table == NULL) {
        return 0;
    }

    if (cyxwiz_peer_table_count(table) != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test adding peers */
static int test_peer_table_add(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&table);

    /* Generate a random node ID */
    cyxwiz_node_id_random(&id);

    /* Add peer */
    err = cyxwiz_peer_table_add(table, &id, CYXWIZ_TRANSPORT_UDP, -50);
    if (err != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Check count */
    if (cyxwiz_peer_table_count(table) != 1) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Add same peer again (should update, not add new) */
    err = cyxwiz_peer_table_add(table, &id, CYXWIZ_TRANSPORT_UDP, -40);
    if (err != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Count should still be 1 */
    if (cyxwiz_peer_table_count(table) != 1) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test finding peers */
static int test_peer_table_find(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id1, id2;
    const cyxwiz_peer_t *peer;

    cyxwiz_peer_table_create(&table);

    cyxwiz_node_id_random(&id1);
    cyxwiz_node_id_random(&id2);

    cyxwiz_peer_table_add(table, &id1, CYXWIZ_TRANSPORT_UDP, -50);

    /* Find existing peer */
    peer = cyxwiz_peer_table_find(table, &id1);
    if (peer == NULL) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    if (cyxwiz_node_id_cmp(&peer->id, &id1) != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Find non-existing peer */
    peer = cyxwiz_peer_table_find(table, &id2);
    if (peer != NULL) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test removing peers */
static int test_peer_table_remove(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id1, id2;
    cyxwiz_error_t err;

    cyxwiz_peer_table_create(&table);

    cyxwiz_node_id_random(&id1);
    cyxwiz_node_id_random(&id2);

    cyxwiz_peer_table_add(table, &id1, CYXWIZ_TRANSPORT_UDP, -50);
    cyxwiz_peer_table_add(table, &id2, CYXWIZ_TRANSPORT_UDP, -60);

    if (cyxwiz_peer_table_count(table) != 2) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Remove first peer */
    err = cyxwiz_peer_table_remove(table, &id1);
    if (err != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    if (cyxwiz_peer_table_count(table) != 1) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify id1 is gone */
    if (cyxwiz_peer_table_find(table, &id1) != NULL) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify id2 still exists */
    if (cyxwiz_peer_table_find(table, &id2) == NULL) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test peer state changes */
static int test_peer_table_set_state(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id;
    const cyxwiz_peer_t *peer;

    cyxwiz_peer_table_create(&table);
    cyxwiz_node_id_random(&id);

    cyxwiz_peer_table_add(table, &id, CYXWIZ_TRANSPORT_UDP, -50);

    /* Initial state should be DISCOVERED */
    peer = cyxwiz_peer_table_find(table, &id);
    if (peer->state != CYXWIZ_PEER_STATE_DISCOVERED) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Change to CONNECTED */
    cyxwiz_peer_table_set_state(table, &id, CYXWIZ_PEER_STATE_CONNECTED);

    peer = cyxwiz_peer_table_find(table, &id);
    if (peer->state != CYXWIZ_PEER_STATE_CONNECTED) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test node ID comparison */
static int test_node_id_cmp(void)
{
    cyxwiz_node_id_t id1, id2;

    memset(&id1, 0xAA, sizeof(id1));
    memset(&id2, 0xAA, sizeof(id2));

    /* Same IDs should be equal */
    if (cyxwiz_node_id_cmp(&id1, &id2) != 0) {
        return 0;
    }

    /* Different IDs should not be equal */
    id2.bytes[0] = 0xBB;
    if (cyxwiz_node_id_cmp(&id1, &id2) == 0) {
        return 0;
    }

    return 1;
}

/* Test node ID to hex conversion */
static int test_node_id_to_hex(void)
{
    cyxwiz_node_id_t id;
    char hex[65];

    memset(&id, 0, sizeof(id));
    id.bytes[0] = 0xAB;
    id.bytes[1] = 0xCD;

    cyxwiz_node_id_to_hex(&id, hex);

    /* First 4 chars should be "abcd" */
    if (hex[0] != 'a' || hex[1] != 'b' || hex[2] != 'c' || hex[3] != 'd') {
        return 0;
    }

    /* Rest should be zeros */
    for (int i = 4; i < 64; i++) {
        if (hex[i] != '0') {
            return 0;
        }
    }

    /* Null terminated */
    if (hex[64] != '\0') {
        return 0;
    }

    return 1;
}

/* Test peer state names */
static int test_peer_state_name(void)
{
    if (strcmp(cyxwiz_peer_state_name(CYXWIZ_PEER_STATE_UNKNOWN), "unknown") != 0) {
        return 0;
    }

    if (strcmp(cyxwiz_peer_state_name(CYXWIZ_PEER_STATE_DISCOVERED), "discovered") != 0) {
        return 0;
    }

    if (strcmp(cyxwiz_peer_state_name(CYXWIZ_PEER_STATE_CONNECTED), "connected") != 0) {
        return 0;
    }

    return 1;
}

/* Test connected count */
static int test_peer_table_connected_count(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id1, id2, id3;

    cyxwiz_peer_table_create(&table);

    cyxwiz_node_id_random(&id1);
    cyxwiz_node_id_random(&id2);
    cyxwiz_node_id_random(&id3);

    cyxwiz_peer_table_add(table, &id1, CYXWIZ_TRANSPORT_UDP, -50);
    cyxwiz_peer_table_add(table, &id2, CYXWIZ_TRANSPORT_UDP, -60);
    cyxwiz_peer_table_add(table, &id3, CYXWIZ_TRANSPORT_UDP, -70);

    /* Initially all DISCOVERED, none connected */
    if (cyxwiz_peer_table_connected_count(table) != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Set two as connected */
    cyxwiz_peer_table_set_state(table, &id1, CYXWIZ_PEER_STATE_CONNECTED);
    cyxwiz_peer_table_set_state(table, &id2, CYXWIZ_PEER_STATE_CONNECTED);

    if (cyxwiz_peer_table_connected_count(table) != 2) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Counter for iteration test */
static int iteration_count = 0;

static int count_peers(const cyxwiz_peer_t *peer, void *user_data)
{
    (void)peer;
    (void)user_data;
    iteration_count++;
    return 0; /* Continue iteration */
}

/* Test peer iteration */
static int test_peer_table_iterate(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id1, id2;

    cyxwiz_peer_table_create(&table);

    cyxwiz_node_id_random(&id1);
    cyxwiz_node_id_random(&id2);

    cyxwiz_peer_table_add(table, &id1, CYXWIZ_TRANSPORT_UDP, -50);
    cyxwiz_peer_table_add(table, &id2, CYXWIZ_TRANSPORT_UDP, -60);

    iteration_count = 0;
    cyxwiz_peer_table_iterate(table, count_peers, NULL);

    if (iteration_count != 2) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

/* Test that new peers have zeroed fields (security fix verification) */
static int test_peer_init_zeroed(void)
{
    cyxwiz_peer_table_t *table = NULL;
    cyxwiz_node_id_t id;
    const cyxwiz_peer_t *peer;

    cyxwiz_peer_table_create(&table);
    cyxwiz_node_id_random(&id);

    cyxwiz_peer_table_add(table, &id, CYXWIZ_TRANSPORT_UDP, -50);

    peer = cyxwiz_peer_table_find(table, &id);
    if (peer == NULL) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify rate limiting fields are zeroed */
    if (peer->msgs_this_window != 0 || peer->rate_violations != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify latency tracking fields are zeroed */
    if (peer->latency_idx != 0 || peer->latency_count != 0 || peer->jitter_ms != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify reputation fields are zeroed */
    if (peer->relay_successes != 0 || peer->relay_failures != 0) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    /* Verify dead peer detection fields are zeroed */
    if (peer->consecutive_failures != 0 || peer->ping_pending != false) {
        cyxwiz_peer_table_destroy(table);
        return 0;
    }

    cyxwiz_peer_table_destroy(table);
    return 1;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Peer Discovery Tests\n");
    printf("============================\n\n");

    TEST(peer_table_create);
    TEST(peer_table_add);
    TEST(peer_table_find);
    TEST(peer_table_remove);
    TEST(peer_table_set_state);
    TEST(node_id_cmp);
    TEST(node_id_to_hex);
    TEST(peer_state_name);
    TEST(peer_table_connected_count);
    TEST(peer_table_iterate);
    TEST(peer_init_zeroed);

    printf("\n============================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
