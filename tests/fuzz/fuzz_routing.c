/*
 * CyxWiz Protocol - Routing Message Fuzz Target
 *
 * Tests routing message parsing with random data.
 * Build with: cmake -DCYXWIZ_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
 * Run with: ./fuzz_routing corpus/ -max_len=250
 */

#include "cyxwiz/types.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Static context for fuzzing (reused across invocations) */
static cyxwiz_router_t *g_router = NULL;
static cyxwiz_peer_table_t *g_peer_table = NULL;
static cyxwiz_node_id_t g_local_id;

/* Dummy delivery callback */
static void dummy_callback(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data
)
{
    (void)from;
    (void)data;
    (void)len;
    (void)user_data;
}

/* Initialize fuzzing context once */
static int init_fuzz_context(void)
{
    static int initialized = 0;
    if (initialized) {
        return 1;
    }

    /* Initialize crypto */
    if (cyxwiz_crypto_init() != CYXWIZ_OK) {
        return 0;
    }

    /* Generate local ID */
    cyxwiz_crypto_random(g_local_id.bytes, sizeof(g_local_id.bytes));

    /* Create peer table */
    if (cyxwiz_peer_table_create(&g_peer_table) != CYXWIZ_OK) {
        return 0;
    }

    /* Create router (without transport - just for message parsing) */
    if (cyxwiz_router_create(&g_router, g_peer_table, NULL, &g_local_id) != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(g_peer_table);
        return 0;
    }

    cyxwiz_router_set_callback(g_router, dummy_callback, NULL);

    initialized = 1;
    return 1;
}

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Need at least message type byte */
    if (size < 1) {
        return 0;
    }

    /* Initialize context */
    if (!init_fuzz_context()) {
        return 0;
    }

    /* Generate a fake sender ID from the input */
    cyxwiz_node_id_t from;
    if (size >= CYXWIZ_NODE_ID_LEN) {
        memcpy(from.bytes, data, CYXWIZ_NODE_ID_LEN);
    } else {
        memset(from.bytes, 0, sizeof(from.bytes));
        memcpy(from.bytes, data, size);
    }

    /* Try to handle as routing message - should not crash */
    cyxwiz_error_t err = cyxwiz_router_handle_message(
        g_router,
        &from,
        data,
        size
    );

    /* Suppress unused variable warning */
    (void)err;

    return 0;
}
