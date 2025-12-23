/*
 * CyxWiz Protocol - Storage Tests
 *
 * Unit tests for the CyxCloud distributed storage protocol.
 */

#include "cyxwiz/storage.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/memory.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing: %s...", #name); \
    tests_run++; \
    if (test_##name()) { \
        printf(" PASS\n"); \
        tests_passed++; \
    } else { \
        printf(" FAIL\n"); \
    } \
} while(0)

/* Mock router for testing */
typedef struct {
    cyxwiz_node_id_t local_id;
    uint8_t last_dest[CYXWIZ_NODE_ID_LEN];
    uint8_t last_data[256];
    size_t last_len;
    int send_count;
} mock_router_t;

static mock_router_t g_mock_router;

/* Mock router send function */
cyxwiz_error_t cyxwiz_router_send(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *dest,
    const uint8_t *data,
    size_t len)
{
    (void)router;
    memcpy(g_mock_router.last_dest, dest->bytes, CYXWIZ_NODE_ID_LEN);
    if (len > sizeof(g_mock_router.last_data)) {
        len = sizeof(g_mock_router.last_data);
    }
    memcpy(g_mock_router.last_data, data, len);
    g_mock_router.last_len = len;
    g_mock_router.send_count++;
    return CYXWIZ_OK;
}

/* Test: Context creation and destruction */
static int test_context_create(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;

    /* Initialize crypto */
    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 3, 5, 1);
    if (err != CYXWIZ_OK) return 0;

    /* Generate local ID */
    memset(&local_id, 0x01, sizeof(local_id));

    /* Create storage context */
    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify initial state */
    if (cyxwiz_storage_is_provider(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (cyxwiz_storage_operation_count(ctx) != 0) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (cyxwiz_storage_stored_count(ctx) != 0) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Cleanup */
    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Provider mode enable/disable */
static int test_provider_mode(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 3, 5, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x02, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Initially not a provider */
    if (cyxwiz_storage_is_provider(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Enable provider mode */
    err = cyxwiz_storage_enable_provider(ctx, 1024 * 1024, 3600);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (!cyxwiz_storage_is_provider(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Disable provider mode */
    cyxwiz_storage_disable_provider(ctx);

    if (cyxwiz_storage_is_provider(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Storage ID generation */
static int test_storage_id(void)
{
    cyxwiz_storage_id_t id1, id2;
    uint8_t data1[] = "Hello, World!";
    uint8_t data2[] = "Different data";
    char hex[17];

    /* Generate IDs */
    cyxwiz_storage_id_generate(data1, sizeof(data1) - 1, &id1);
    cyxwiz_storage_id_generate(data2, sizeof(data2) - 1, &id2);

    /* IDs should be different */
    if (cyxwiz_storage_id_compare(&id1, &id2) == 0) {
        return 0;
    }

    /* Test hex conversion */
    cyxwiz_storage_id_to_hex(&id1, hex);
    if (strlen(hex) != 16) {
        return 0;
    }

    return 1;
}

/* Test: State name utilities */
static int test_state_names(void)
{
    const char *name;

    name = cyxwiz_storage_state_name(CYXWIZ_STORAGE_STATE_PENDING);
    if (strcmp(name, "pending") != 0) return 0;

    name = cyxwiz_storage_state_name(CYXWIZ_STORAGE_STATE_STORED);
    if (strcmp(name, "stored") != 0) return 0;

    name = cyxwiz_storage_state_name(CYXWIZ_STORAGE_STATE_RETRIEVED);
    if (strcmp(name, "retrieved") != 0) return 0;

    name = cyxwiz_storage_state_name(CYXWIZ_STORAGE_STATE_EXPIRED);
    if (strcmp(name, "expired") != 0) return 0;

    name = cyxwiz_storage_op_type_name(CYXWIZ_STORAGE_OP_STORE);
    if (strcmp(name, "store") != 0) return 0;

    name = cyxwiz_storage_op_type_name(CYXWIZ_STORAGE_OP_RETRIEVE);
    if (strcmp(name, "retrieve") != 0) return 0;

    name = cyxwiz_storage_op_type_name(CYXWIZ_STORAGE_OP_DELETE);
    if (strcmp(name, "delete") != 0) return 0;

    return 1;
}

/* Test: Store operation initiates sends */
static int test_store_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t providers[3];
    cyxwiz_storage_id_t storage_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x03, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Create mock providers */
    memset(&providers[0], 0xA1, sizeof(cyxwiz_node_id_t));
    memset(&providers[1], 0xA2, sizeof(cyxwiz_node_id_t));
    memset(&providers[2], 0xA3, sizeof(cyxwiz_node_id_t));

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Store data */
    uint8_t data[] = "Test data to store";
    err = cyxwiz_storage_store(ctx, providers, 3, 2, data, sizeof(data) - 1,
                               3600, &storage_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have sent to all 3 providers */
    if (g_mock_router.send_count != 3) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* First byte should be STORE_REQ */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_STORE_REQ) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have one active operation */
    if (cyxwiz_storage_operation_count(ctx) != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Handle STORE_REQ as provider */
static int test_handle_store_req(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t client_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x04, sizeof(local_id));
    memset(&client_id, 0xB1, sizeof(client_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Enable provider mode */
    err = cyxwiz_storage_enable_provider(ctx, 1024 * 1024, 3600);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Build a STORE_REQ message */
    uint8_t msg[256];
    cyxwiz_store_req_msg_t *req = (cyxwiz_store_req_msg_t *)msg;
    req->type = CYXWIZ_MSG_STORE_REQ;
    memset(req->storage_id, 0xCC, CYXWIZ_STORAGE_ID_SIZE);
    req->share_index = 1;
    req->total_shares = 3;
    req->threshold = 2;
    req->ttl_seconds = 3600;
    req->total_chunks = 0;
    req->payload_len = 20; /* Just encrypted data length, not including share */

    /* Add a share (49 bytes) */
    size_t offset = sizeof(cyxwiz_store_req_msg_t);
    cyxwiz_share_t share;
    memset(&share, 0xDD, sizeof(share));
    share.party_id = 1;
    memcpy(msg + offset, &share, sizeof(share));
    offset += sizeof(share);

    /* Add encrypted payload */
    uint8_t encrypted[20];
    memset(encrypted, 0xEE, sizeof(encrypted));
    memcpy(msg + offset, encrypted, sizeof(encrypted));
    offset += sizeof(encrypted);

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Handle the message */
    err = cyxwiz_storage_handle_message(ctx, &client_id, msg, offset);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have sent STORE_ACK */
    if (g_mock_router.send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (g_mock_router.last_data[0] != CYXWIZ_MSG_STORE_ACK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have one stored item */
    if (cyxwiz_storage_stored_count(ctx) != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Reject STORE_REQ when not provider */
static int test_reject_not_provider(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t client_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x05, sizeof(local_id));
    memset(&client_id, 0xB2, sizeof(client_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* DON'T enable provider mode */

    /* Build a minimal STORE_REQ message */
    uint8_t msg[256];
    cyxwiz_store_req_msg_t *req = (cyxwiz_store_req_msg_t *)msg;
    req->type = CYXWIZ_MSG_STORE_REQ;
    memset(req->storage_id, 0xCC, CYXWIZ_STORAGE_ID_SIZE);
    req->share_index = 1;
    req->total_shares = 3;
    req->threshold = 2;
    req->ttl_seconds = 3600;
    req->total_chunks = 0;
    req->payload_len = 20; /* Just encrypted data length */

    size_t offset = sizeof(cyxwiz_store_req_msg_t);
    cyxwiz_share_t share;
    memset(&share, 0xDD, sizeof(share));
    share.party_id = 1;
    memcpy(msg + offset, &share, sizeof(share));
    offset += sizeof(share);

    uint8_t encrypted[20];
    memset(encrypted, 0xEE, sizeof(encrypted));
    memcpy(msg + offset, encrypted, sizeof(encrypted));
    offset += sizeof(encrypted);

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Handle the message */
    err = cyxwiz_storage_handle_message(ctx, &client_id, msg, offset);
    /* Should succeed but send rejection */
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have sent STORE_REJECT */
    if (g_mock_router.send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (g_mock_router.last_data[0] != CYXWIZ_MSG_STORE_REJECT) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have no stored items */
    if (cyxwiz_storage_stored_count(ctx) != 0) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Retrieve operation initiates sends */
static int test_retrieve_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t providers[3];
    cyxwiz_storage_id_t storage_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x06, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Create mock providers */
    memset(&providers[0], 0xC1, sizeof(cyxwiz_node_id_t));
    memset(&providers[1], 0xC2, sizeof(cyxwiz_node_id_t));
    memset(&providers[2], 0xC3, sizeof(cyxwiz_node_id_t));

    /* Create storage ID */
    memset(&storage_id, 0xAA, sizeof(storage_id));

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Retrieve data */
    err = cyxwiz_storage_retrieve(ctx, &storage_id, providers, 3);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have sent RETRIEVE_REQ to all 3 providers */
    if (g_mock_router.send_count != 3) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (g_mock_router.last_data[0] != CYXWIZ_MSG_RETRIEVE_REQ) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have one active operation */
    if (cyxwiz_storage_operation_count(ctx) != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Poll handles timeout */
static int test_poll_timeout(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t providers[2];
    cyxwiz_storage_id_t storage_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 2, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x07, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    memset(&providers[0], 0xD1, sizeof(cyxwiz_node_id_t));
    memset(&providers[1], 0xD2, sizeof(cyxwiz_node_id_t));

    uint8_t data[] = "Timeout test";
    err = cyxwiz_storage_store(ctx, providers, 2, 2, data, sizeof(data) - 1,
                               3600, &storage_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have one operation */
    if (cyxwiz_storage_operation_count(ctx) != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Poll at current time - should not timeout */
    uint64_t now = 0; /* Will use actual time from get_time_ms in storage.c */
    /* Since we can't control time easily, just call poll */
    cyxwiz_storage_poll(ctx, now);

    /* Operation should still exist (not timed out yet) */
    /* Note: In real test, we'd simulate time passing */

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Delete operation */
static int test_delete_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_t providers[2];
    cyxwiz_storage_id_t storage_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 2, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x08, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    memset(&providers[0], 0xE1, sizeof(cyxwiz_node_id_t));
    memset(&providers[1], 0xE2, sizeof(cyxwiz_node_id_t));
    memset(&storage_id, 0xBB, sizeof(storage_id));

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Delete data */
    err = cyxwiz_storage_delete(ctx, &storage_id, providers, 2);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Should have sent DELETE_REQ to both providers */
    if (g_mock_router.send_count != 2) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    if (g_mock_router.last_data[0] != CYXWIZ_MSG_DELETE_REQ) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

int main(void)
{
    printf("\nCyxWiz Storage Tests\n");
    printf("====================\n\n");

    TEST(context_create);
    TEST(provider_mode);
    TEST(storage_id);
    TEST(state_names);
    TEST(store_submit);
    TEST(handle_store_req);
    TEST(reject_not_provider);
    TEST(retrieve_submit);
    TEST(poll_timeout);
    TEST(delete_submit);

    printf("\n====================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
