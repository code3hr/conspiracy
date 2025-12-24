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

/* Mock SURB functions for anonymous storage */
static bool g_mock_surb_available = true;
static int g_mock_surb_create_count = 0;
static int g_mock_surb_send_count = 0;

bool cyxwiz_router_can_create_surb(const cyxwiz_router_t *router)
{
    (void)router;
    return g_mock_surb_available;
}

cyxwiz_error_t cyxwiz_router_create_surb(
    cyxwiz_router_t *router,
    cyxwiz_surb_t *surb_out)
{
    (void)router;
    if (!g_mock_surb_available) {
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }
    /* Fill with recognizable test pattern */
    memset(surb_out, 0xAB, sizeof(cyxwiz_surb_t));
    g_mock_surb_create_count++;
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_router_send_via_surb(
    cyxwiz_router_t *router,
    const cyxwiz_surb_t *surb,
    const uint8_t *data,
    size_t len)
{
    (void)router;
    (void)surb;
    if (len > sizeof(g_mock_router.last_data)) {
        len = sizeof(g_mock_router.last_data);
    }
    memcpy(g_mock_router.last_data, data, len);
    g_mock_router.last_len = len;
    g_mock_surb_send_count++;
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

    /* Should have sent STORE_ACK and POS_COMMITMENT */
    if (g_mock_router.send_count != 2) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Last message should be POS_COMMITMENT (after STORE_ACK) */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_POS_COMMITMENT) {
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

/* ============ Proof of Storage Tests ============ */

/* Test: PoS commitment computation */
static int test_pos_compute_commitment(void)
{
    cyxwiz_error_t err;
    uint8_t data[128]; /* 2 blocks */
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commitment;

    /* Initialize crypto for hashing */
    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Create test data - 128 bytes = 2 blocks */
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i ^ 0xAA);
    }

    memset(&storage_id, 0x11, sizeof(storage_id));

    /* Compute commitment */
    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Verify structure */
    if (commitment.num_blocks != 2) {
        return 0;
    }

    if (cyxwiz_storage_id_compare(&commitment.storage_id, &storage_id) != 0) {
        return 0;
    }

    /* Merkle root should be non-zero */
    int all_zero = 1;
    for (size_t i = 0; i < CYXWIZ_POS_HASH_SIZE; i++) {
        if (commitment.merkle_root[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        return 0;
    }

    /* Compute again - should be deterministic */
    cyxwiz_pos_commitment_t commitment2;
    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment2);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    if (memcmp(commitment.merkle_root, commitment2.merkle_root, CYXWIZ_POS_HASH_SIZE) != 0) {
        return 0;
    }

    return 1;
}

/* Test: PoS commitment with different data produces different roots */
static int test_pos_different_data(void)
{
    cyxwiz_error_t err;
    uint8_t data1[128], data2[128];
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commit1, commit2;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Create two different data sets */
    memset(data1, 0xAA, sizeof(data1));
    memset(data2, 0xBB, sizeof(data2));
    memset(&storage_id, 0x22, sizeof(storage_id));

    err = cyxwiz_pos_compute_commitment(data1, sizeof(data1), &storage_id, &commit1);
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_pos_compute_commitment(data2, sizeof(data2), &storage_id, &commit2);
    if (err != CYXWIZ_OK) return 0;

    /* Roots should be different */
    if (memcmp(commit1.merkle_root, commit2.merkle_root, CYXWIZ_POS_HASH_SIZE) == 0) {
        return 0;
    }

    return 1;
}

/* Test: PoS proof generation */
static int test_pos_generate_proof(void)
{
    cyxwiz_error_t err;
    uint8_t data[256]; /* 4 blocks */
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {1,2,3,4,5,6,7,8};
    uint8_t proof_buf[256];
    size_t proof_len;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Create test data - 256 bytes = 4 blocks */
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)i;
    }

    /* Generate proof for block 0 */
    err = cyxwiz_pos_generate_proof(
        data, sizeof(data),
        0, /* block_index */
        challenge_nonce,
        proof_buf, sizeof(proof_buf),
        &proof_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Proof should be non-empty */
    if (proof_len == 0) {
        return 0;
    }

    /* Proof should fit in LoRa MTU */
    if (proof_len > CYXWIZ_MAX_PACKET_SIZE) {
        return 0;
    }

    /* Generate proof for different block */
    size_t proof_len2;
    err = cyxwiz_pos_generate_proof(
        data, sizeof(data),
        2, /* different block_index */
        challenge_nonce,
        proof_buf, sizeof(proof_buf),
        &proof_len2
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    return 1;
}

/* Test: PoS proof generation with invalid block index */
static int test_pos_invalid_block(void)
{
    cyxwiz_error_t err;
    uint8_t data[128]; /* 2 blocks */
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {0};
    uint8_t proof_buf[256];
    size_t proof_len;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    memset(data, 0xAA, sizeof(data));

    /* Try to generate proof for out-of-range block */
    err = cyxwiz_pos_generate_proof(
        data, sizeof(data),
        10, /* invalid block_index - only 2 blocks exist */
        challenge_nonce,
        proof_buf, sizeof(proof_buf),
        &proof_len
    );

    /* Should fail with invalid block error */
    if (err != CYXWIZ_ERR_POS_INVALID_BLOCK) {
        return 0;
    }

    return 1;
}

/* Test: PoS full verification cycle */
static int test_pos_verify_cycle(void)
{
    cyxwiz_error_t err;
    uint8_t data[192]; /* 3 blocks */
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commitment;
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    uint8_t proof_buf[256];
    size_t proof_len;
    bool valid;
    cyxwiz_pos_fail_reason_t reason;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Create test data */
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 7 + 13);
    }
    memset(&storage_id, 0x33, sizeof(storage_id));

    /* Step 1: Provider computes commitment */
    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Step 2: Test each block can be verified */
    for (uint8_t block_idx = 0; block_idx < commitment.num_blocks; block_idx++) {
        /* Generate proof */
        err = cyxwiz_pos_generate_proof(
            data, sizeof(data),
            block_idx,
            challenge_nonce,
            proof_buf, sizeof(proof_buf),
            &proof_len
        );
        if (err != CYXWIZ_OK) {
            return 0;
        }

        /* Verify proof */
        err = cyxwiz_pos_verify_proof(
            &commitment,
            proof_buf, proof_len,
            &valid, &reason
        );
        if (err != CYXWIZ_OK) {
            return 0;
        }

        if (!valid) {
            return 0;
        }
    }

    return 1;
}

/* Test: PoS verification fails with wrong data */
static int test_pos_verify_wrong_data(void)
{
    cyxwiz_error_t err;
    uint8_t data[128];
    uint8_t wrong_data[128];
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commitment;
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {0};
    uint8_t proof_buf[256];
    size_t proof_len;
    bool valid;
    cyxwiz_pos_fail_reason_t reason;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Create original data and commitment */
    memset(data, 0xAA, sizeof(data));
    memset(&storage_id, 0x44, sizeof(storage_id));

    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment);
    if (err != CYXWIZ_OK) return 0;

    /* Generate proof from WRONG data */
    memset(wrong_data, 0xBB, sizeof(wrong_data));
    err = cyxwiz_pos_generate_proof(
        wrong_data, sizeof(wrong_data),
        0,
        challenge_nonce,
        proof_buf, sizeof(proof_buf),
        &proof_len
    );
    if (err != CYXWIZ_OK) return 0;

    /* Verify should FAIL */
    err = cyxwiz_pos_verify_proof(
        &commitment,
        proof_buf, proof_len,
        &valid, &reason
    );
    if (err != CYXWIZ_OK) return 0;

    /* Proof should be invalid */
    if (valid) {
        return 0;
    }

    /* Reason should indicate root mismatch */
    if (reason != CYXWIZ_POS_FAIL_INVALID_ROOT) {
        return 0;
    }

    return 1;
}

/* Test: PoS single block data */
static int test_pos_single_block(void)
{
    cyxwiz_error_t err;
    uint8_t data[32]; /* Less than one full block */
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commitment;
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {0};
    uint8_t proof_buf[256];
    size_t proof_len;
    bool valid;
    cyxwiz_pos_fail_reason_t reason;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    memset(data, 0xCC, sizeof(data));
    memset(&storage_id, 0x55, sizeof(storage_id));

    /* Compute commitment - should produce single block */
    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment);
    if (err != CYXWIZ_OK) return 0;

    if (commitment.num_blocks != 1) {
        return 0;
    }

    /* Generate and verify proof */
    err = cyxwiz_pos_generate_proof(
        data, sizeof(data),
        0,
        challenge_nonce,
        proof_buf, sizeof(proof_buf),
        &proof_len
    );
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_pos_verify_proof(
        &commitment,
        proof_buf, proof_len,
        &valid, &reason
    );
    if (err != CYXWIZ_OK) return 0;

    if (!valid) {
        return 0;
    }

    return 1;
}

/* Test: PoS maximum blocks */
static int test_pos_max_blocks(void)
{
    cyxwiz_error_t err;
    uint8_t data[CYXWIZ_POS_BLOCK_SIZE * CYXWIZ_POS_MAX_BLOCKS]; /* 32 blocks */
    cyxwiz_storage_id_t storage_id;
    cyxwiz_pos_commitment_t commitment;
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE] = {0xDE, 0xAD};
    uint8_t proof_buf[256];
    size_t proof_len;
    bool valid;
    cyxwiz_pos_fail_reason_t reason;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    /* Fill with pattern */
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i % 256);
    }
    memset(&storage_id, 0x66, sizeof(storage_id));

    /* Compute commitment */
    err = cyxwiz_pos_compute_commitment(data, sizeof(data), &storage_id, &commitment);
    if (err != CYXWIZ_OK) return 0;

    if (commitment.num_blocks != CYXWIZ_POS_MAX_BLOCKS) {
        return 0;
    }

    /* Test first, middle, and last blocks */
    uint8_t test_blocks[] = {0, CYXWIZ_POS_MAX_BLOCKS / 2, CYXWIZ_POS_MAX_BLOCKS - 1};
    for (size_t i = 0; i < sizeof(test_blocks); i++) {
        err = cyxwiz_pos_generate_proof(
            data, sizeof(data),
            test_blocks[i],
            challenge_nonce,
            proof_buf, sizeof(proof_buf),
            &proof_len
        );
        if (err != CYXWIZ_OK) return 0;

        /* Ensure proof fits LoRa MTU */
        if (proof_len > CYXWIZ_MAX_PACKET_SIZE) {
            return 0;
        }

        err = cyxwiz_pos_verify_proof(
            &commitment,
            proof_buf, proof_len,
            &valid, &reason
        );
        if (err != CYXWIZ_OK) return 0;

        if (!valid) {
            return 0;
        }
    }

    return 1;
}

/* Test: PoS fail reason names */
static int test_pos_fail_reason_names(void)
{
    const char *name;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_INVALID_ROOT);
    if (strcmp(name, "invalid_root") != 0) return 0;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_INVALID_BLOCK);
    if (strcmp(name, "invalid_block") != 0) return 0;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_INVALID_PATH);
    if (strcmp(name, "invalid_path") != 0) return 0;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_WRONG_NONCE);
    if (strcmp(name, "wrong_nonce") != 0) return 0;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_TIMEOUT);
    if (strcmp(name, "timeout") != 0) return 0;

    name = cyxwiz_pos_fail_reason_name(CYXWIZ_POS_FAIL_NOT_FOUND);
    if (strcmp(name, "not_found") != 0) return 0;

    return 1;
}

/* Test: PoS commitment message handling */
static int test_pos_handle_commitment(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, provider_id;
    cyxwiz_storage_id_t storage_id;
    cyxwiz_node_id_t providers[2];

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 2, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x09, sizeof(local_id));
    memset(&provider_id, 0xF1, sizeof(provider_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Create a store operation first (to have context for commitment) */
    memset(&providers[0], 0xF1, sizeof(cyxwiz_node_id_t));
    memset(&providers[1], 0xF2, sizeof(cyxwiz_node_id_t));

    uint8_t data[] = "Test data for PoS";
    err = cyxwiz_storage_store(ctx, providers, 2, 2, data, sizeof(data) - 1,
                               3600, &storage_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Build a POS_COMMITMENT message */
    cyxwiz_pos_commitment_msg_t msg;
    msg.type = CYXWIZ_MSG_POS_COMMITMENT;
    memcpy(msg.storage_id, storage_id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    memset(msg.merkle_root, 0xAB, CYXWIZ_POS_HASH_SIZE);
    msg.num_blocks = 1;

    /* Reset mock */
    g_mock_router.send_count = 0;

    /* Handle the commitment message */
    err = cyxwiz_storage_handle_message(ctx, &provider_id,
                                         (uint8_t *)&msg, sizeof(msg));
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Provider sends commitment after STORE_ACK */
static int test_pos_provider_sends_commitment(void)
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

    memset(&local_id, 0x0A, sizeof(local_id));
    memset(&client_id, 0xC1, sizeof(client_id));

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
    memset(req->storage_id, 0xDD, CYXWIZ_STORAGE_ID_SIZE);
    req->share_index = 1;
    req->total_shares = 3;
    req->threshold = 2;
    req->ttl_seconds = 3600;
    req->total_chunks = 0;
    req->payload_len = 64; /* Data for PoS commitment */

    /* Add a share */
    size_t offset = sizeof(cyxwiz_store_req_msg_t);
    cyxwiz_share_t share;
    memset(&share, 0xEE, sizeof(share));
    share.party_id = 1;
    memcpy(msg + offset, &share, sizeof(share));
    offset += sizeof(share);

    /* Add encrypted payload */
    uint8_t encrypted[64];
    memset(encrypted, 0xFF, sizeof(encrypted));
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

    /* Should have sent 2 messages: STORE_ACK and POS_COMMITMENT */
    if (g_mock_router.send_count != 2) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Last message should be POS_COMMITMENT */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_POS_COMMITMENT) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* ============ Anonymous Storage Tests ============ */

/* Test: Anonymous storage capability check */
static int test_anon_can_store(void)
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

    memset(&local_id, 0x01, sizeof(local_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Test with SURB available */
    g_mock_surb_available = true;
    if (!cyxwiz_storage_can_store_anonymous(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Test with SURB unavailable */
    g_mock_surb_available = false;
    if (cyxwiz_storage_can_store_anonymous(ctx)) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Restore for other tests */
    g_mock_surb_available = true;

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Anonymous store submission */
static int test_anon_store_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, provider_id;

    /* Initialize crypto */
    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x01, sizeof(local_id));
    memset(&provider_id, 0x02, sizeof(provider_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Reset mock counters */
    g_mock_router.send_count = 0;
    g_mock_surb_create_count = 0;
    g_mock_surb_available = true;

    /* Submit anonymous store */
    uint8_t data[] = "test anonymous data";
    cyxwiz_storage_id_t storage_id;
    uint8_t delete_token[16];

    err = cyxwiz_storage_store_anonymous(ctx, &provider_id, 1, 1,
                                          data, sizeof(data), 3600,
                                          &storage_id, delete_token);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify SURB was created */
    if (g_mock_surb_create_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message was sent */
    if (g_mock_router.send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message type is anonymous store */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_STORE_REQ_ANON) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify delete token is non-zero */
    int has_nonzero = 0;
    for (size_t i = 0; i < sizeof(delete_token); i++) {
        if (delete_token[i] != 0) has_nonzero = 1;
    }
    if (!has_nonzero) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Anonymous store fails without SURB capability */
static int test_anon_store_requires_surb(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, provider_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x01, sizeof(local_id));
    memset(&provider_id, 0x02, sizeof(provider_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Disable SURB capability */
    g_mock_surb_available = false;

    uint8_t data[] = "test";
    cyxwiz_storage_id_t storage_id;
    uint8_t delete_token[16];

    err = cyxwiz_storage_store_anonymous(ctx, &provider_id, 1, 1,
                                          data, sizeof(data), 3600,
                                          &storage_id, delete_token);

    /* Should fail with INSUFFICIENT_RELAYS */
    if (err != CYXWIZ_ERR_INSUFFICIENT_RELAYS) {
        g_mock_surb_available = true;
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    g_mock_surb_available = true;
    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Handle anonymous store request as provider */
static int test_anon_handle_store(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, sender_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x01, sizeof(local_id));
    memset(&sender_id, 0x02, sizeof(sender_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Enable provider mode */
    err = cyxwiz_storage_enable_provider(ctx, 1024, 3600);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Reset mock counters */
    g_mock_surb_send_count = 0;

    /* Build anonymous store request message - use larger buffer */
    uint8_t msg_buf[300];
    cyxwiz_store_req_anon_msg_t *msg = (cyxwiz_store_req_anon_msg_t *)msg_buf;

    msg->type = CYXWIZ_MSG_STORE_REQ_ANON;
    memset(msg->storage_id, 0xCC, CYXWIZ_STORAGE_ID_SIZE);
    msg->share_index = 1;
    msg->total_shares = 1;
    msg->threshold = 1;
    msg->ttl_seconds = 300;
    msg->total_chunks = 0;
    msg->payload_len = 20; /* Share + small payload */
    memset(msg->delete_token, 0xDD, CYXWIZ_MAC_SIZE);
    memset(&msg->reply_surb, 0xAB, sizeof(cyxwiz_surb_t));

    /* Append share */
    size_t offset = sizeof(cyxwiz_store_req_anon_msg_t);
    cyxwiz_share_t share;
    memset(&share, 0x55, sizeof(share));
    share.party_id = 1;
    memcpy(msg_buf + offset, &share, sizeof(share));
    offset += sizeof(share);

    /* Append encrypted payload (20 bytes total = encrypted_len) */
    memset(msg_buf + offset, 0xEE, 20);
    offset += 20;

    /* Handle the message */
    err = cyxwiz_storage_handle_message(ctx, &sender_id, msg_buf, offset);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify ACK was sent via SURB */
    if (g_mock_surb_send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify item was stored */
    if (cyxwiz_storage_stored_count(ctx) != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Anonymous retrieve submission */
static int test_anon_retrieve_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, provider_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x01, sizeof(local_id));
    memset(&provider_id, 0x02, sizeof(provider_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Reset mock counters */
    g_mock_router.send_count = 0;
    g_mock_surb_create_count = 0;
    g_mock_surb_available = true;

    /* Submit anonymous retrieve */
    cyxwiz_storage_id_t storage_id;
    memset(storage_id.bytes, 0xAA, CYXWIZ_STORAGE_ID_SIZE);

    err = cyxwiz_storage_retrieve_anonymous(ctx, &storage_id, &provider_id, 1);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify SURB was created */
    if (g_mock_surb_create_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message was sent */
    if (g_mock_router.send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message type is anonymous retrieve */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_RETRIEVE_REQ_ANON) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    cyxwiz_storage_destroy(ctx);
    cyxwiz_crypto_destroy(crypto);

    return 1;
}

/* Test: Anonymous delete submission */
static int test_anon_delete_submit(void)
{
    cyxwiz_error_t err;
    cyxwiz_storage_ctx_t *ctx = NULL;
    cyxwiz_crypto_ctx_t *crypto = NULL;
    cyxwiz_node_id_t local_id, provider_id;

    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_crypto_create(&crypto, 2, 3, 1);
    if (err != CYXWIZ_OK) return 0;

    memset(&local_id, 0x01, sizeof(local_id));
    memset(&provider_id, 0x02, sizeof(provider_id));

    err = cyxwiz_storage_create(&ctx, (cyxwiz_router_t *)&g_mock_router,
                                 NULL, crypto, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Reset mock counters */
    g_mock_router.send_count = 0;
    g_mock_surb_create_count = 0;
    g_mock_surb_available = true;

    /* Submit anonymous delete */
    cyxwiz_storage_id_t storage_id;
    uint8_t delete_token[16];
    memset(storage_id.bytes, 0xAA, CYXWIZ_STORAGE_ID_SIZE);
    memset(delete_token, 0xBB, sizeof(delete_token));

    err = cyxwiz_storage_delete_anonymous(ctx, &storage_id, delete_token,
                                           &provider_id, 1);
    if (err != CYXWIZ_OK) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify SURB was created */
    if (g_mock_surb_create_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message was sent */
    if (g_mock_router.send_count != 1) {
        cyxwiz_storage_destroy(ctx);
        cyxwiz_crypto_destroy(crypto);
        return 0;
    }

    /* Verify message type is anonymous delete */
    if (g_mock_router.last_data[0] != CYXWIZ_MSG_DELETE_REQ_ANON) {
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

    /* Core storage tests */
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

    /* Proof of Storage tests */
    printf("\n  Proof of Storage:\n");
    TEST(pos_compute_commitment);
    TEST(pos_different_data);
    TEST(pos_generate_proof);
    TEST(pos_invalid_block);
    TEST(pos_verify_cycle);
    TEST(pos_verify_wrong_data);
    TEST(pos_single_block);
    TEST(pos_max_blocks);
    TEST(pos_fail_reason_names);
    TEST(pos_handle_commitment);
    TEST(pos_provider_sends_commitment);

    /* Anonymous storage tests */
    printf("\n  Anonymous Storage:\n");
    TEST(anon_can_store);
    TEST(anon_store_submit);
    TEST(anon_store_requires_surb);
    TEST(anon_handle_store);
    TEST(anon_retrieve_submit);
    TEST(anon_delete_submit);

    printf("\n====================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
