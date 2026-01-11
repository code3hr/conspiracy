/*
 * CyxWiz Protocol - Anonymous Messaging End-to-End Test
 *
 * Tests sending anonymous messages via onion routing between nodes.
 */

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/onion.h"
#include "cyxwiz/log.h"
#include "cyxwiz/memory.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/*
 * Test with 3 nodes to verify multi-hop routing works.
 * With ephemeral per-layer keys, each relay can decrypt its layer
 * independently using ECDH with the ephemeral public key.
 */
#define NUM_NODES 3
#define TEST_MESSAGE "Hello!"  /* Shorter to fit 2-hop payload limit (37 bytes) */

/* Node state */
typedef struct {
    cyxwiz_node_id_t id;
    cyxwiz_peer_table_t *peers;
    cyxwiz_router_t *router;
    cyxwiz_onion_ctx_t *onion;
    bool received_message;
    char received_data[256];
    size_t received_len;
} test_node_t;

static test_node_t g_nodes[NUM_NODES];

/* Onion delivery callback */
static void on_onion_delivery(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    test_node_t *node = (test_node_t *)user_data;

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);

    printf("  Node received %zu bytes via onion from %.16s...\n", len, hex_id);

    if (len > 0 && len < sizeof(node->received_data)) {
        memcpy(node->received_data, data, len);
        node->received_len = len;
        node->received_message = true;
    }
}

/* Mock transport for direct node-to-node communication */
static cyxwiz_error_t mock_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    /* Get sender ID from transport */
    const cyxwiz_node_id_t *from = &transport->local_id;

    /* Find target node and deliver directly */
    for (int i = 0; i < NUM_NODES; i++) {
        if (memcmp(&g_nodes[i].id, to, sizeof(cyxwiz_node_id_t)) == 0) {
            /* Simulate receiving the message */
            if (g_nodes[i].router != NULL) {
                /* Check if it's an onion message */
                if (len > 0 && data[0] == CYXWIZ_MSG_ONION_DATA) {
                    /* Forward to onion layer with correct sender */
                    cyxwiz_onion_handle_message(g_nodes[i].onion, from, data, len);
                }
            }
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_PEER_NOT_FOUND;
}

static cyxwiz_transport_ops_t mock_ops = {
    .init = NULL,
    .shutdown = NULL,
    .send = mock_send,
    .discover = NULL,
};

/* Each node needs its own transport to track local_id */
static cyxwiz_transport_t g_transports[NUM_NODES];

/* Initialize all nodes */
static int init_nodes(void)
{
    cyxwiz_error_t err;

    for (int i = 0; i < NUM_NODES; i++) {
        /* Generate random node ID */
        cyxwiz_node_id_random(&g_nodes[i].id);

        char hex_id[65];
        cyxwiz_node_id_to_hex(&g_nodes[i].id, hex_id);
        printf("  Node %d ID: %.16s...\n", i, hex_id);

        /* Initialize per-node transport with local_id */
        g_transports[i].type = CYXWIZ_TRANSPORT_UDP;
        g_transports[i].ops = &mock_ops;
        memcpy(&g_transports[i].local_id, &g_nodes[i].id, sizeof(cyxwiz_node_id_t));

        /* Create peer table */
        err = cyxwiz_peer_table_create(&g_nodes[i].peers);
        if (err != CYXWIZ_OK) {
            printf("  Failed to create peer table for node %d\n", i);
            return 0;
        }

        /* Create router with per-node transport */
        err = cyxwiz_router_create(&g_nodes[i].router, g_nodes[i].peers,
                                    &g_transports[i], &g_nodes[i].id);
        if (err != CYXWIZ_OK) {
            printf("  Failed to create router for node %d\n", i);
            return 0;
        }

        /* Create onion context */
        err = cyxwiz_onion_create(&g_nodes[i].onion, g_nodes[i].router,
                                   &g_nodes[i].id);
        if (err != CYXWIZ_OK) {
            printf("  Failed to create onion context for node %d\n", i);
            return 0;
        }

        /* Set delivery callback */
        cyxwiz_onion_set_callback(g_nodes[i].onion, on_onion_delivery, &g_nodes[i]);

        g_nodes[i].received_message = false;
        g_nodes[i].received_len = 0;
    }

    return 1;
}

/* Connect all nodes (add each other as peers and exchange keys) */
static int connect_nodes(void)
{
    cyxwiz_error_t err;

    for (int i = 0; i < NUM_NODES; i++) {
        for (int j = 0; j < NUM_NODES; j++) {
            if (i == j) continue;

            /* Add as peer using the correct API */
            err = cyxwiz_peer_table_add(g_nodes[i].peers, &g_nodes[j].id,
                                        CYXWIZ_TRANSPORT_UDP, -50);
            if (err != CYXWIZ_OK) {
                printf("  Failed to add peer %d to node %d (err=%d)\n", j, i, err);
                return 0;
            }

            /* Set peer as active */
            cyxwiz_peer_table_set_state(g_nodes[i].peers, &g_nodes[j].id,
                                        CYXWIZ_PEER_STATE_CONNECTED);

            /* Exchange onion keys */
            uint8_t pubkey[CYXWIZ_PUBKEY_SIZE];
            err = cyxwiz_onion_get_pubkey(g_nodes[j].onion, pubkey);
            if (err == CYXWIZ_OK) {
                cyxwiz_onion_add_peer_key(g_nodes[i].onion, &g_nodes[j].id, pubkey);
            }
        }
    }

    printf("  All nodes connected and keys exchanged\n");
    return 1;
}

/* Clean up nodes */
static void cleanup_nodes(void)
{
    for (int i = 0; i < NUM_NODES; i++) {
        if (g_nodes[i].onion != NULL) {
            cyxwiz_onion_destroy(g_nodes[i].onion);
        }
        if (g_nodes[i].router != NULL) {
            cyxwiz_router_destroy(g_nodes[i].router);
        }
        if (g_nodes[i].peers != NULL) {
            cyxwiz_peer_table_destroy(g_nodes[i].peers);
        }
    }
}

/* Test sending anonymous message */
static int test_anon_message(void)
{
    /*
     * With 3 nodes, send from Node 0 to Node 2.
     * The circuit builder will select Node 1 as a relay if available.
     */
    int dest_node = NUM_NODES - 1;  /* Last node is destination */

    printf("\n  Sending anonymous message from Node 0 to Node %d...\n", dest_node);

    const char *message = TEST_MESSAGE;
    size_t msg_len = strlen(message);

    cyxwiz_error_t err = cyxwiz_onion_send_to(
        g_nodes[0].onion,
        &g_nodes[dest_node].id,
        (const uint8_t *)message,
        msg_len
    );

    if (err != CYXWIZ_OK) {
        printf("  FAIL: cyxwiz_onion_send_to returned %d\n", err);
        return 0;
    }

    printf("  Message sent via onion routing (may have used relay)\n");

    /* Check if destination received it */
    /* Note: In this mock setup, the message should be delivered synchronously */
    if (!g_nodes[dest_node].received_message) {
        printf("  FAIL: Node %d did not receive the message\n", dest_node);
        return 0;
    }

    /* Verify content */
    if (g_nodes[dest_node].received_len != msg_len) {
        printf("  FAIL: Received length mismatch (%zu vs %zu)\n",
               g_nodes[dest_node].received_len, msg_len);
        return 0;
    }

    if (memcmp(g_nodes[dest_node].received_data, message, msg_len) != 0) {
        printf("  FAIL: Message content mismatch\n");
        return 0;
    }

    printf("  SUCCESS: Node %d received: \"%.*s\"\n",
           dest_node, (int)g_nodes[dest_node].received_len, g_nodes[dest_node].received_data);

    return 1;
}

int main(void)
{
    int result = 0;

    cyxwiz_log_init(CYXWIZ_LOG_WARN);

    printf("\nCyxWiz Anonymous Messaging E2E Test\n");
    printf("====================================\n\n");

    /* Initialize crypto */
    if (cyxwiz_crypto_init() != CYXWIZ_OK) {
        printf("FAIL: Could not initialize crypto\n");
        return 1;
    }

    printf("Step 1: Creating %d nodes...\n", NUM_NODES);
    if (!init_nodes()) {
        printf("FAIL: Could not initialize nodes\n");
        cleanup_nodes();
        return 1;
    }

    printf("\nStep 2: Connecting nodes...\n");
    if (!connect_nodes()) {
        printf("FAIL: Could not connect nodes\n");
        cleanup_nodes();
        return 1;
    }

    printf("\nStep 3: Testing anonymous messaging...\n");
    if (test_anon_message()) {
        printf("\n====================================\n");
        printf("TEST PASSED: Anonymous messaging works!\n");
        printf("====================================\n\n");
        result = 0;
    } else {
        printf("\n====================================\n");
        printf("TEST FAILED\n");
        printf("====================================\n\n");
        result = 1;
    }

    cleanup_nodes();
    return result;
}
