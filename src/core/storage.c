/*
 * CyxWiz Protocol - CyxCloud Storage Implementation
 *
 * Implements distributed storage with K-of-N threshold secret sharing:
 * - Encrypt data with random key
 * - Split key using Shamir's Secret Sharing
 * - Distribute shares + encrypted data to providers
 * - Reconstruct by collecting K shares
 */

#include "cyxwiz/storage.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"
#include "cyxwiz/routing.h"

#include <string.h>

/* ============ Internal Context ============ */

struct cyxwiz_storage_ctx {
    /* Dependencies */
    cyxwiz_router_t *router;
    cyxwiz_peer_table_t *peer_table;
    cyxwiz_crypto_ctx_t *crypto_ctx;
    cyxwiz_node_id_t local_id;

    /* Client-side: Active storage operations */
    cyxwiz_storage_op_t operations[CYXWIZ_MAX_ACTIVE_STORAGE_OPS];
    size_t operation_count;

    /* Provider-side: Stored items */
    cyxwiz_stored_item_t stored_items[CYXWIZ_MAX_STORED_ITEMS];
    size_t stored_count;
    size_t storage_used_bytes;
    size_t storage_max_bytes;
    uint32_t max_ttl_seconds;

    /* Provider mode */
    bool is_provider;

    /* Callbacks */
    cyxwiz_storage_complete_cb_t on_complete;
    void *complete_user_data;

    /* State */
    bool running;
    uint64_t last_poll;
};

/* ============ Forward Declarations ============ */

static cyxwiz_storage_op_t *find_operation(cyxwiz_storage_ctx_t *ctx,
                                           const cyxwiz_storage_id_t *storage_id);
static cyxwiz_storage_op_t *alloc_operation(cyxwiz_storage_ctx_t *ctx);
static void free_operation(cyxwiz_storage_op_t *op);
static cyxwiz_stored_item_t *find_stored_item(cyxwiz_storage_ctx_t *ctx,
                                               const cyxwiz_storage_id_t *storage_id);
static cyxwiz_stored_item_t *alloc_stored_item(cyxwiz_storage_ctx_t *ctx);
static void free_stored_item(cyxwiz_storage_ctx_t *ctx, cyxwiz_stored_item_t *item);

static cyxwiz_error_t send_store_req(cyxwiz_storage_ctx_t *ctx,
                                      const cyxwiz_node_id_t *to,
                                      cyxwiz_storage_op_t *op,
                                      uint8_t share_index,
                                      const cyxwiz_share_t *share);
static cyxwiz_error_t send_store_chunk(cyxwiz_storage_ctx_t *ctx,
                                        const cyxwiz_node_id_t *to,
                                        const cyxwiz_storage_id_t *storage_id,
                                        uint8_t chunk_index,
                                        const uint8_t *data, size_t len);
static cyxwiz_error_t send_store_ack(cyxwiz_storage_ctx_t *ctx,
                                      const cyxwiz_node_id_t *to,
                                      const cyxwiz_storage_id_t *storage_id,
                                      uint8_t share_index,
                                      uint64_t expires_at);
static cyxwiz_error_t send_store_reject(cyxwiz_storage_ctx_t *ctx,
                                         const cyxwiz_node_id_t *to,
                                         const cyxwiz_storage_id_t *storage_id,
                                         cyxwiz_storage_reject_reason_t reason);
static cyxwiz_error_t send_retrieve_req(cyxwiz_storage_ctx_t *ctx,
                                         const cyxwiz_node_id_t *to,
                                         const cyxwiz_storage_id_t *storage_id);
static cyxwiz_error_t send_retrieve_resp(cyxwiz_storage_ctx_t *ctx,
                                          const cyxwiz_node_id_t *to,
                                          cyxwiz_stored_item_t *item);
static cyxwiz_error_t send_delete_req(cyxwiz_storage_ctx_t *ctx,
                                       const cyxwiz_node_id_t *to,
                                       const cyxwiz_storage_id_t *storage_id,
                                       const uint8_t *mac);
static cyxwiz_error_t send_delete_ack(cyxwiz_storage_ctx_t *ctx,
                                       const cyxwiz_node_id_t *to,
                                       const cyxwiz_storage_id_t *storage_id);

static cyxwiz_error_t handle_store_req(cyxwiz_storage_ctx_t *ctx,
                                        const cyxwiz_node_id_t *from,
                                        const uint8_t *data, size_t len);
static cyxwiz_error_t handle_store_chunk(cyxwiz_storage_ctx_t *ctx,
                                          const cyxwiz_node_id_t *from,
                                          const uint8_t *data, size_t len);
static cyxwiz_error_t handle_store_ack(cyxwiz_storage_ctx_t *ctx,
                                        const cyxwiz_node_id_t *from,
                                        const uint8_t *data, size_t len);
static cyxwiz_error_t handle_store_reject(cyxwiz_storage_ctx_t *ctx,
                                           const cyxwiz_node_id_t *from,
                                           const uint8_t *data, size_t len);
static cyxwiz_error_t handle_retrieve_req(cyxwiz_storage_ctx_t *ctx,
                                           const cyxwiz_node_id_t *from,
                                           const uint8_t *data, size_t len);
static cyxwiz_error_t handle_retrieve_resp(cyxwiz_storage_ctx_t *ctx,
                                            const cyxwiz_node_id_t *from,
                                            const uint8_t *data, size_t len);
static cyxwiz_error_t handle_delete_req(cyxwiz_storage_ctx_t *ctx,
                                         const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);
static cyxwiz_error_t handle_delete_ack(cyxwiz_storage_ctx_t *ctx,
                                         const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);

static cyxwiz_error_t try_reconstruct(cyxwiz_storage_ctx_t *ctx, cyxwiz_storage_op_t *op);
static void complete_operation(cyxwiz_storage_ctx_t *ctx, cyxwiz_storage_op_t *op,
                               const uint8_t *data, size_t data_len);

/* External router function */
extern cyxwiz_error_t cyxwiz_router_send(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *dest,
    const uint8_t *data,
    size_t len
);

/* Time utility */
static uint64_t get_time_ms(void);

#ifdef _WIN32
#include <windows.h>
static uint64_t get_time_ms(void) {
    return GetTickCount64();
}
#else
#include <time.h>
static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
#endif

/* ============ Context Lifecycle ============ */

cyxwiz_error_t cyxwiz_storage_create(
    cyxwiz_storage_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_crypto_ctx_t *crypto_ctx,
    const cyxwiz_node_id_t *local_id)
{
    if (ctx == NULL || router == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_storage_ctx_t *s = cyxwiz_calloc(1, sizeof(cyxwiz_storage_ctx_t));
    if (s == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    s->router = router;
    s->peer_table = peer_table;
    s->crypto_ctx = crypto_ctx;
    memcpy(&s->local_id, local_id, sizeof(cyxwiz_node_id_t));

    s->operation_count = 0;
    s->stored_count = 0;
    s->storage_used_bytes = 0;
    s->storage_max_bytes = 0;
    s->max_ttl_seconds = 0;
    s->is_provider = false;

    s->on_complete = NULL;
    s->complete_user_data = NULL;
    s->running = true;
    s->last_poll = 0;

    /* Initialize all slots as invalid */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        s->operations[i].valid = false;
    }
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
        s->stored_items[i].valid = false;
    }

    CYXWIZ_INFO("Created storage context");
    *ctx = s;
    return CYXWIZ_OK;
}

void cyxwiz_storage_destroy(cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Clear all operations */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        if (ctx->operations[i].valid) {
            free_operation(&ctx->operations[i]);
        }
    }

    /* Clear all stored items */
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
        if (ctx->stored_items[i].valid) {
            free_stored_item(ctx, &ctx->stored_items[i]);
        }
    }

    CYXWIZ_INFO("Destroyed storage context");
    cyxwiz_free(ctx, sizeof(cyxwiz_storage_ctx_t));
}

/* ============ Provider Mode ============ */

cyxwiz_error_t cyxwiz_storage_enable_provider(
    cyxwiz_storage_ctx_t *ctx,
    size_t max_storage_bytes,
    uint32_t max_ttl_seconds)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (max_storage_bytes == 0) {
        max_storage_bytes = 1024 * 1024; /* 1MB default */
    }
    if (max_ttl_seconds == 0) {
        max_ttl_seconds = CYXWIZ_STORAGE_MAX_TTL_SEC;
    }

    ctx->is_provider = true;
    ctx->storage_max_bytes = max_storage_bytes;
    ctx->max_ttl_seconds = max_ttl_seconds;

    CYXWIZ_INFO("Enabled storage provider (max: %zu bytes, TTL: %u sec)",
                max_storage_bytes, max_ttl_seconds);
    return CYXWIZ_OK;
}

void cyxwiz_storage_disable_provider(cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->is_provider = false;
    CYXWIZ_INFO("Disabled storage provider");
}

bool cyxwiz_storage_is_provider(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return ctx->is_provider;
}

/* ============ Callbacks ============ */

void cyxwiz_storage_set_complete_callback(
    cyxwiz_storage_ctx_t *ctx,
    cyxwiz_storage_complete_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->on_complete = callback;
    ctx->complete_user_data = user_data;
}

/* ============ Client Operations ============ */

cyxwiz_error_t cyxwiz_storage_store(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *providers,
    size_t num_providers,
    uint8_t threshold,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    cyxwiz_storage_id_t *storage_id_out)
{
    if (ctx == NULL || providers == NULL || data == NULL || storage_id_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (num_providers < 1 || num_providers > CYXWIZ_MAX_STORAGE_PROVIDERS) {
        CYXWIZ_ERROR("Invalid number of providers: %zu", num_providers);
        return CYXWIZ_ERR_INVALID;
    }

    if (threshold < 1 || threshold > num_providers) {
        CYXWIZ_ERROR("Invalid threshold: %u (providers: %zu)", threshold, num_providers);
        return CYXWIZ_ERR_INVALID;
    }

    /* Check data size (must leave room for encryption overhead) */
    size_t max_plaintext = CYXWIZ_STORAGE_MAX_PAYLOAD - CYXWIZ_CRYPTO_OVERHEAD;
    if (data_len > max_plaintext) {
        CYXWIZ_ERROR("Data too large: %zu > %zu", data_len, max_plaintext);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = CYXWIZ_STORAGE_DEFAULT_TTL_SEC;
    }

    /* Allocate operation */
    cyxwiz_storage_op_t *op = alloc_operation(ctx);
    if (op == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Generate storage ID */
    cyxwiz_storage_id_generate(data, data_len, &op->id);
    memcpy(storage_id_out, &op->id, sizeof(cyxwiz_storage_id_t));

    /* Initialize operation */
    op->state = CYXWIZ_STORAGE_STATE_DISTRIBUTING;
    op->op_type = CYXWIZ_STORAGE_OP_STORE;
    memcpy(&op->owner, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    op->threshold = threshold;
    op->num_shares = (uint8_t)num_providers;
    op->ttl_seconds = ttl_seconds;
    op->created_at = get_time_ms();
    op->is_owner = true;
    op->providers_confirmed = 0;

    /* Copy original data */
    op->data = cyxwiz_calloc(1, data_len);
    if (op->data == NULL) {
        free_operation(op);
        return CYXWIZ_ERR_NOMEM;
    }
    memcpy(op->data, data, data_len);
    op->data_len = data_len;

    /* Generate random encryption key */
    cyxwiz_crypto_random_key(op->encryption_key);

    /* Encrypt data */
    size_t encrypted_len = data_len + CYXWIZ_CRYPTO_OVERHEAD;
    op->encrypted_data = cyxwiz_calloc(1, encrypted_len);
    if (op->encrypted_data == NULL) {
        free_operation(op);
        return CYXWIZ_ERR_NOMEM;
    }

    cyxwiz_error_t err = cyxwiz_crypto_encrypt(
        data, data_len,
        op->encryption_key,
        op->encrypted_data, &op->encrypted_len
    );
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to encrypt data: %d", err);
        free_operation(op);
        return err;
    }

    /* Split encryption key into shares */
    cyxwiz_share_t shares[CYXWIZ_MAX_STORAGE_PROVIDERS];
    size_t num_shares_out;

    /* Need a crypto context configured for num_providers parties */
    err = cyxwiz_crypto_share_secret(
        ctx->crypto_ctx,
        op->encryption_key,
        CYXWIZ_KEY_SIZE,
        shares,
        &num_shares_out
    );
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to split key: %d", err);
        free_operation(op);
        return err;
    }

    /* Calculate chunking */
    if (op->encrypted_len <= 64) {
        op->total_chunks = 0; /* Inline with STORE_REQ */
    } else {
        op->total_chunks = (uint8_t)((op->encrypted_len + CYXWIZ_STORAGE_CHUNK_SIZE - 1) /
                                     CYXWIZ_STORAGE_CHUNK_SIZE);
    }

    /* Initialize provider slots and send STORE_REQ to each */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].share_index = (uint8_t)(i + 1); /* 1-indexed like party_id */
        op->providers[i].confirmed = false;
        op->providers[i].retrieved = false;
        op->providers[i].sent_at = get_time_ms();

        /* Use shares[i] - note: shares are 0-indexed but party_id is 1-indexed */
        err = send_store_req(ctx, &providers[i], op, (uint8_t)(i + 1), &shares[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send STORE_REQ to provider %zu: %d", i, err);
        }
    }

    /* Secure zero the shares */
    cyxwiz_secure_zero(shares, sizeof(shares));

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&op->id, id_hex);
    CYXWIZ_INFO("Storage store initiated: %s (%zu bytes, %u-of-%u threshold)",
                id_hex, data_len, threshold, (unsigned)num_providers);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_storage_retrieve(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *providers,
    size_t num_providers)
{
    if (ctx == NULL || storage_id == NULL || providers == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (num_providers < 1 || num_providers > CYXWIZ_MAX_STORAGE_PROVIDERS) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if operation already exists */
    cyxwiz_storage_op_t *existing = find_operation(ctx, storage_id);
    if (existing != NULL) {
        CYXWIZ_WARN("Retrieve operation already exists for this ID");
        return CYXWIZ_ERR_ALREADY_INIT;
    }

    /* Allocate operation */
    cyxwiz_storage_op_t *op = alloc_operation(ctx);
    if (op == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize operation */
    memcpy(&op->id, storage_id, sizeof(cyxwiz_storage_id_t));
    op->state = CYXWIZ_STORAGE_STATE_RETRIEVING;
    op->op_type = CYXWIZ_STORAGE_OP_RETRIEVE;
    memcpy(&op->owner, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    op->num_shares = (uint8_t)num_providers;
    op->threshold = 0; /* Will be set when we receive responses */
    op->created_at = get_time_ms();
    op->is_owner = true;
    op->providers_retrieved = 0;

    /* Initialize provider slots and send RETRIEVE_REQ to each */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].share_index = 0; /* Unknown until response */
        op->providers[i].confirmed = false;
        op->providers[i].retrieved = false;
        op->providers[i].sent_at = get_time_ms();

        cyxwiz_error_t err = send_retrieve_req(ctx, &providers[i], storage_id);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send RETRIEVE_REQ to provider %zu: %d", i, err);
        }
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_INFO("Storage retrieve initiated: %s (from %zu providers)",
                id_hex, num_providers);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_storage_delete(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *providers,
    size_t num_providers)
{
    if (ctx == NULL || storage_id == NULL || providers == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (num_providers < 1 || num_providers > CYXWIZ_MAX_STORAGE_PROVIDERS) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Allocate operation */
    cyxwiz_storage_op_t *op = alloc_operation(ctx);
    if (op == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize operation */
    memcpy(&op->id, storage_id, sizeof(cyxwiz_storage_id_t));
    op->state = CYXWIZ_STORAGE_STATE_DELETING;
    op->op_type = CYXWIZ_STORAGE_OP_DELETE;
    memcpy(&op->owner, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    op->num_shares = (uint8_t)num_providers;
    op->created_at = get_time_ms();
    op->is_owner = true;
    op->providers_confirmed = 0;

    /* Compute ownership MAC: MAC(storage_id || owner_id) */
    uint8_t mac_input[CYXWIZ_STORAGE_ID_SIZE + CYXWIZ_NODE_ID_LEN];
    memcpy(mac_input, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(mac_input + CYXWIZ_STORAGE_ID_SIZE, ctx->local_id.bytes, CYXWIZ_NODE_ID_LEN);

    uint8_t mac[CYXWIZ_MAC_SIZE];
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx->crypto_ctx, mac_input, mac);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to compute ownership MAC: %d", err);
        free_operation(op);
        return err;
    }

    /* Initialize provider slots and send DELETE_REQ to each */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].confirmed = false;
        op->providers[i].sent_at = get_time_ms();

        err = send_delete_req(ctx, &providers[i], storage_id, mac);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send DELETE_REQ to provider %zu: %d", i, err);
        }
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_INFO("Storage delete initiated: %s (to %zu providers)",
                id_hex, num_providers);

    return CYXWIZ_OK;
}

/* ============ Polling ============ */

cyxwiz_error_t cyxwiz_storage_poll(
    cyxwiz_storage_ctx_t *ctx,
    uint64_t now_ms)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    ctx->last_poll = now_ms;

    /* Check for operation timeouts */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        cyxwiz_storage_op_t *op = &ctx->operations[i];
        if (!op->valid) {
            continue;
        }

        /* Skip completed operations */
        if (op->state == CYXWIZ_STORAGE_STATE_STORED ||
            op->state == CYXWIZ_STORAGE_STATE_RETRIEVED ||
            op->state == CYXWIZ_STORAGE_STATE_DELETED ||
            op->state == CYXWIZ_STORAGE_STATE_FAILED) {
            continue;
        }

        /* Check timeout */
        if (now_ms - op->created_at > CYXWIZ_STORAGE_OP_TIMEOUT_MS) {
            char id_hex[17];
            cyxwiz_storage_id_to_hex(&op->id, id_hex);
            CYXWIZ_WARN("Storage operation %s timed out", id_hex);

            op->state = CYXWIZ_STORAGE_STATE_FAILED;
            complete_operation(ctx, op, NULL, 0);
        }
    }

    /* Provider-side: Check for TTL expiry */
    if (ctx->is_provider) {
        for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
            cyxwiz_stored_item_t *item = &ctx->stored_items[i];
            if (!item->valid) {
                continue;
            }

            if (now_ms >= item->expires_at) {
                char id_hex[17];
                cyxwiz_storage_id_to_hex(&item->id, id_hex);
                CYXWIZ_DEBUG("Storage item %s expired", id_hex);

                free_stored_item(ctx, item);
            }
        }
    }

    return CYXWIZ_OK;
}

/* ============ Message Handling ============ */

cyxwiz_error_t cyxwiz_storage_handle_message(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (ctx == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case CYXWIZ_MSG_STORE_REQ:
            return handle_store_req(ctx, from, data, len);
        case CYXWIZ_MSG_STORE_CHUNK:
            return handle_store_chunk(ctx, from, data, len);
        case CYXWIZ_MSG_STORE_ACK:
            return handle_store_ack(ctx, from, data, len);
        case CYXWIZ_MSG_STORE_REJECT:
            return handle_store_reject(ctx, from, data, len);
        case CYXWIZ_MSG_RETRIEVE_REQ:
            return handle_retrieve_req(ctx, from, data, len);
        case CYXWIZ_MSG_RETRIEVE_RESP:
            return handle_retrieve_resp(ctx, from, data, len);
        case CYXWIZ_MSG_RETRIEVE_CHUNK:
            /* Same handling as STORE_CHUNK but for retrieve context */
            return handle_store_chunk(ctx, from, data, len);
        case CYXWIZ_MSG_DELETE_REQ:
            return handle_delete_req(ctx, from, data, len);
        case CYXWIZ_MSG_DELETE_ACK:
            return handle_delete_ack(ctx, from, data, len);
        default:
            CYXWIZ_DEBUG("Unknown storage message type: 0x%02X", msg_type);
            return CYXWIZ_ERR_INVALID;
    }
}

/* ============ Message Handlers ============ */

static cyxwiz_error_t handle_store_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_store_req_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_store_req_msg_t *msg = (const cyxwiz_store_req_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Check if we're a provider */
    if (!ctx->is_provider) {
        CYXWIZ_DEBUG("Rejecting STORE_REQ %s: not a provider", id_hex);
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_DISABLED);
        return CYXWIZ_OK;
    }

    /* Check TTL */
    uint32_t ttl = msg->ttl_seconds;
    if (ttl > ctx->max_ttl_seconds) {
        CYXWIZ_DEBUG("Rejecting STORE_REQ %s: TTL too long (%u > %u)",
                     id_hex, ttl, ctx->max_ttl_seconds);
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_TTL_TOO_LONG);
        return CYXWIZ_OK;
    }

    /* Check for duplicate */
    if (find_stored_item(ctx, &storage_id) != NULL) {
        CYXWIZ_DEBUG("Rejecting STORE_REQ %s: duplicate", id_hex);
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_DUPLICATE);
        return CYXWIZ_OK;
    }

    /* Parse share from message */
    const uint8_t *share_data = data + sizeof(cyxwiz_store_req_msg_t);
    size_t remaining = len - sizeof(cyxwiz_store_req_msg_t);

    if (remaining < sizeof(cyxwiz_share_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check storage capacity */
    uint16_t payload_len = msg->payload_len;
    if (ctx->storage_used_bytes + payload_len > ctx->storage_max_bytes) {
        CYXWIZ_DEBUG("Rejecting STORE_REQ %s: storage full", id_hex);
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_FULL);
        return CYXWIZ_OK;
    }

    /* Allocate stored item */
    cyxwiz_stored_item_t *item = alloc_stored_item(ctx);
    if (item == NULL) {
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_FULL);
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize item */
    memcpy(&item->id, &storage_id, sizeof(cyxwiz_storage_id_t));
    memcpy(&item->owner, from, sizeof(cyxwiz_node_id_t));
    memcpy(&item->share, share_data, sizeof(cyxwiz_share_t));
    item->share_index = msg->share_index;
    item->total_chunks = msg->total_chunks;
    item->received_chunks = 0;
    item->chunk_bitmap = 0;
    item->stored_at = get_time_ms();
    item->expires_at = item->stored_at + ((uint64_t)ttl * 1000);

    /* Allocate encrypted data buffer */
    item->encrypted_data = cyxwiz_calloc(1, payload_len);
    if (item->encrypted_data == NULL) {
        free_stored_item(ctx, item);
        send_store_reject(ctx, from, &storage_id, CYXWIZ_STORAGE_REJECT_FULL);
        return CYXWIZ_ERR_NOMEM;
    }
    item->encrypted_len = payload_len;

    /* If inline payload (total_chunks == 0), copy it now */
    if (msg->total_chunks == 0) {
        const uint8_t *payload = share_data + sizeof(cyxwiz_share_t);
        size_t payload_remaining = remaining - sizeof(cyxwiz_share_t);

        if (payload_remaining < payload_len) {
            free_stored_item(ctx, item);
            return CYXWIZ_ERR_INVALID;
        }

        memcpy(item->encrypted_data, payload, payload_len);
        ctx->storage_used_bytes += payload_len;

        /* Send ACK immediately */
        CYXWIZ_DEBUG("Stored item %s (share %u, %u bytes)",
                     id_hex, item->share_index, payload_len);
        send_store_ack(ctx, from, &storage_id, item->share_index, item->expires_at);
    } else {
        /* Wait for chunks */
        CYXWIZ_DEBUG("Awaiting %u chunks for item %s", msg->total_chunks, id_hex);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_store_chunk(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_store_chunk_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_store_chunk_msg_t *msg = (const cyxwiz_store_chunk_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    uint8_t chunk_index = msg->chunk_index;
    uint8_t chunk_len = msg->chunk_len;

    if (chunk_index >= item->total_chunks) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check for duplicate */
    if (item->chunk_bitmap & (1 << chunk_index)) {
        return CYXWIZ_OK; /* Already received */
    }

    /* Copy chunk data */
    const uint8_t *chunk_data = data + sizeof(cyxwiz_store_chunk_msg_t);
    size_t offset = (size_t)chunk_index * CYXWIZ_STORAGE_CHUNK_SIZE;

    if (offset + chunk_len > item->encrypted_len) {
        return CYXWIZ_ERR_INVALID;
    }

    memcpy(item->encrypted_data + offset, chunk_data, chunk_len);
    item->chunk_bitmap |= (1 << chunk_index);
    item->received_chunks++;

    /* Check if all chunks received */
    if (item->received_chunks == item->total_chunks) {
        ctx->storage_used_bytes += item->encrypted_len;

        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_DEBUG("Stored item %s complete (share %u, %zu bytes)",
                     id_hex, item->share_index, item->encrypted_len);

        send_store_ack(ctx, from, &storage_id, item->share_index, item->expires_at);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_store_ack(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_store_ack_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_store_ack_msg_t *msg = (const cyxwiz_store_ack_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find operation */
    cyxwiz_storage_op_t *op = find_operation(ctx, &storage_id);
    if (op == NULL || op->op_type != CYXWIZ_STORAGE_OP_STORE) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Mark provider as confirmed */
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, from, sizeof(cyxwiz_node_id_t)) == 0) {
            if (!op->providers[i].confirmed) {
                op->providers[i].confirmed = true;
                op->providers_confirmed++;

                char id_hex[17];
                cyxwiz_storage_id_to_hex(&storage_id, id_hex);
                CYXWIZ_DEBUG("Store ACK for %s from provider %zu (%u/%u confirmed)",
                             id_hex, i, op->providers_confirmed, op->threshold);
            }
            break;
        }
    }

    /* Check if we have enough confirmations */
    if (op->providers_confirmed >= op->threshold) {
        op->state = CYXWIZ_STORAGE_STATE_STORED;
        op->completed_at = get_time_ms();

        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_INFO("Storage complete: %s (%u confirmations)",
                    id_hex, op->providers_confirmed);

        complete_operation(ctx, op, op->data, op->data_len);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_store_reject(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_store_reject_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_store_reject_msg_t *msg = (const cyxwiz_store_reject_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);
    CYXWIZ_WARN("Store rejected for %s: reason %u", id_hex, msg->reason);

    /* Find operation - don't fail it immediately, other providers might succeed */
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(ctx);

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_retrieve_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_retrieve_req_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_retrieve_req_msg_t *msg = (const cyxwiz_retrieve_req_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_DEBUG("Retrieve request for unknown item: %s", id_hex);
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Check if expired */
    uint64_t now = get_time_ms();
    if (now >= item->expires_at) {
        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_DEBUG("Retrieve request for expired item: %s", id_hex);
        free_stored_item(ctx, item);
        return CYXWIZ_ERR_STORAGE_EXPIRED;
    }

    /* Send response */
    return send_retrieve_resp(ctx, from, item);
}

static cyxwiz_error_t handle_retrieve_resp(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_retrieve_resp_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_retrieve_resp_msg_t *msg = (const cyxwiz_retrieve_resp_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find operation */
    cyxwiz_storage_op_t *op = find_operation(ctx, &storage_id);
    if (op == NULL || op->op_type != CYXWIZ_STORAGE_OP_RETRIEVE) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Parse share */
    const uint8_t *share_data = data + sizeof(cyxwiz_retrieve_resp_msg_t);
    size_t remaining = len - sizeof(cyxwiz_retrieve_resp_msg_t);

    if (remaining < sizeof(cyxwiz_share_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find provider slot */
    int provider_idx = -1;
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, from, sizeof(cyxwiz_node_id_t)) == 0) {
            provider_idx = (int)i;
            break;
        }
    }

    if (provider_idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    /* Check for duplicate */
    if (op->providers[provider_idx].retrieved) {
        return CYXWIZ_OK;
    }

    /* Store share */
    memcpy(&op->retrieved_shares[op->providers_retrieved], share_data, sizeof(cyxwiz_share_t));
    op->providers[provider_idx].retrieved = true;
    op->providers[provider_idx].share_index = msg->share_index;
    op->providers_retrieved++;

    /* First response sets the threshold */
    if (op->threshold == 0) {
        /* We don't have threshold info from provider, use default */
        op->threshold = CYXWIZ_DEFAULT_THRESHOLD;
    }

    /* Store encrypted data (from first response only) */
    if (op->encrypted_data == NULL && msg->total_chunks == 0) {
        uint16_t payload_len = msg->payload_len;
        const uint8_t *payload = share_data + sizeof(cyxwiz_share_t);

        if (remaining >= sizeof(cyxwiz_share_t) + payload_len) {
            op->encrypted_data = cyxwiz_calloc(1, payload_len);
            if (op->encrypted_data != NULL) {
                memcpy(op->encrypted_data, payload, payload_len);
                op->encrypted_len = payload_len;
            }
        }
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);
    CYXWIZ_DEBUG("Retrieve response for %s: share %u (%u/%u collected)",
                 id_hex, msg->share_index, op->providers_retrieved, op->threshold);

    /* Try to reconstruct if we have enough shares */
    if (op->providers_retrieved >= op->threshold && op->encrypted_data != NULL) {
        return try_reconstruct(ctx, op);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_delete_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_delete_req_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_delete_req_msg_t *msg = (const cyxwiz_delete_req_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Verify ownership MAC */
    uint8_t mac_input[CYXWIZ_STORAGE_ID_SIZE + CYXWIZ_NODE_ID_LEN];
    memcpy(mac_input, storage_id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(mac_input + CYXWIZ_STORAGE_ID_SIZE, from->bytes, CYXWIZ_NODE_ID_LEN);

    uint8_t expected_mac[CYXWIZ_MAC_SIZE];
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx->crypto_ctx, mac_input, expected_mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    if (cyxwiz_secure_compare(msg->mac, expected_mac, CYXWIZ_MAC_SIZE) != 0) {
        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_WARN("Delete request for %s: MAC mismatch (unauthorized)", id_hex);
        return CYXWIZ_ERR_STORAGE_UNAUTHORIZED;
    }

    /* Delete item */
    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);
    CYXWIZ_DEBUG("Deleted item %s", id_hex);

    free_stored_item(ctx, item);
    send_delete_ack(ctx, from, &storage_id);

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_delete_ack(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_delete_ack_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_delete_ack_msg_t *msg = (const cyxwiz_delete_ack_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find operation */
    cyxwiz_storage_op_t *op = find_operation(ctx, &storage_id);
    if (op == NULL || op->op_type != CYXWIZ_STORAGE_OP_DELETE) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Mark provider as confirmed */
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, from, sizeof(cyxwiz_node_id_t)) == 0) {
            if (!op->providers[i].confirmed) {
                op->providers[i].confirmed = true;
                op->providers_confirmed++;
            }
            break;
        }
    }

    /* Check if all providers confirmed */
    if (op->providers_confirmed >= op->num_shares) {
        op->state = CYXWIZ_STORAGE_STATE_DELETED;
        op->completed_at = get_time_ms();

        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_INFO("Delete complete: %s", id_hex);

        complete_operation(ctx, op, NULL, 0);
    }

    return CYXWIZ_OK;
}

/* ============ Message Senders ============ */

static cyxwiz_error_t send_store_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    cyxwiz_storage_op_t *op,
    uint8_t share_index,
    const cyxwiz_share_t *share)
{
    /* Build message */
    uint8_t buf[256];
    cyxwiz_store_req_msg_t *msg = (cyxwiz_store_req_msg_t *)buf;

    msg->type = CYXWIZ_MSG_STORE_REQ;
    memcpy(msg->storage_id, op->id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->share_index = share_index;
    msg->total_shares = op->num_shares;
    msg->threshold = op->threshold;
    msg->ttl_seconds = op->ttl_seconds;
    msg->total_chunks = op->total_chunks;
    msg->payload_len = (uint16_t)op->encrypted_len;

    /* Append share */
    size_t offset = sizeof(cyxwiz_store_req_msg_t);
    memcpy(buf + offset, share, sizeof(cyxwiz_share_t));
    offset += sizeof(cyxwiz_share_t);

    /* If inline payload, append encrypted data */
    if (op->total_chunks == 0) {
        memcpy(buf + offset, op->encrypted_data, op->encrypted_len);
        offset += op->encrypted_len;
    }

    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, to, buf, offset);

    /* If chunked, send chunks */
    if (err == CYXWIZ_OK && op->total_chunks > 0) {
        for (uint8_t i = 0; i < op->total_chunks; i++) {
            size_t chunk_offset = (size_t)i * CYXWIZ_STORAGE_CHUNK_SIZE;
            size_t chunk_len = op->encrypted_len - chunk_offset;
            if (chunk_len > CYXWIZ_STORAGE_CHUNK_SIZE) {
                chunk_len = CYXWIZ_STORAGE_CHUNK_SIZE;
            }

            err = send_store_chunk(ctx, to, &op->id, i,
                                   op->encrypted_data + chunk_offset, chunk_len);
            if (err != CYXWIZ_OK) {
                break;
            }
        }
    }

    return err;
}

static cyxwiz_error_t send_store_chunk(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t chunk_index,
    const uint8_t *data,
    size_t len)
{
    uint8_t buf[256];
    cyxwiz_store_chunk_msg_t *msg = (cyxwiz_store_chunk_msg_t *)buf;

    msg->type = CYXWIZ_MSG_STORE_CHUNK;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->chunk_index = chunk_index;
    msg->chunk_len = (uint8_t)len;

    memcpy(buf + sizeof(cyxwiz_store_chunk_msg_t), data, len);

    return cyxwiz_router_send(ctx->router, to, buf,
                               sizeof(cyxwiz_store_chunk_msg_t) + len);
}

static cyxwiz_error_t send_store_ack(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t share_index,
    uint64_t expires_at)
{
    cyxwiz_store_ack_msg_t msg;
    msg.type = CYXWIZ_MSG_STORE_ACK;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg.share_index = share_index;
    msg.expires_at = expires_at;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_store_reject(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    cyxwiz_storage_reject_reason_t reason)
{
    cyxwiz_store_reject_msg_t msg;
    msg.type = CYXWIZ_MSG_STORE_REJECT;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg.reason = (uint8_t)reason;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_retrieve_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id)
{
    cyxwiz_retrieve_req_msg_t msg;
    msg.type = CYXWIZ_MSG_RETRIEVE_REQ;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_retrieve_resp(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    cyxwiz_stored_item_t *item)
{
    uint8_t buf[256];
    cyxwiz_retrieve_resp_msg_t *msg = (cyxwiz_retrieve_resp_msg_t *)buf;

    msg->type = CYXWIZ_MSG_RETRIEVE_RESP;
    memcpy(msg->storage_id, item->id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->share_index = item->share_index;
    msg->total_chunks = 0; /* Inline for simplicity */
    msg->payload_len = (uint16_t)item->encrypted_len;

    size_t offset = sizeof(cyxwiz_retrieve_resp_msg_t);
    memcpy(buf + offset, &item->share, sizeof(cyxwiz_share_t));
    offset += sizeof(cyxwiz_share_t);

    /* Inline encrypted data if it fits */
    if (item->encrypted_len <= 64) {
        memcpy(buf + offset, item->encrypted_data, item->encrypted_len);
        offset += item->encrypted_len;
    }

    return cyxwiz_router_send(ctx->router, to, buf, offset);
}

static cyxwiz_error_t send_delete_req(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    const uint8_t *mac)
{
    cyxwiz_delete_req_msg_t msg;
    msg.type = CYXWIZ_MSG_DELETE_REQ;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(msg.mac, mac, CYXWIZ_MAC_SIZE);

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_delete_ack(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id)
{
    cyxwiz_delete_ack_msg_t msg;
    msg.type = CYXWIZ_MSG_DELETE_ACK;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

/* ============ Helper Functions ============ */

static cyxwiz_storage_op_t *find_operation(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        if (ctx->operations[i].valid &&
            memcmp(ctx->operations[i].id.bytes, storage_id->bytes,
                   CYXWIZ_STORAGE_ID_SIZE) == 0) {
            return &ctx->operations[i];
        }
    }
    return NULL;
}

static cyxwiz_storage_op_t *alloc_operation(cyxwiz_storage_ctx_t *ctx)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        if (!ctx->operations[i].valid) {
            memset(&ctx->operations[i], 0, sizeof(cyxwiz_storage_op_t));
            ctx->operations[i].valid = true;
            ctx->operation_count++;
            return &ctx->operations[i];
        }
    }
    return NULL;
}

static void free_operation(cyxwiz_storage_op_t *op)
{
    if (op == NULL) {
        return;
    }

    if (op->data != NULL) {
        cyxwiz_secure_zero(op->data, op->data_len);
        cyxwiz_free(op->data, op->data_len);
    }
    if (op->encrypted_data != NULL) {
        cyxwiz_secure_zero(op->encrypted_data, op->encrypted_len);
        cyxwiz_free(op->encrypted_data, op->encrypted_len);
    }

    cyxwiz_secure_zero(op->encryption_key, sizeof(op->encryption_key));
    cyxwiz_secure_zero(op->retrieved_shares, sizeof(op->retrieved_shares));

    op->valid = false;
}

static cyxwiz_stored_item_t *find_stored_item(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
        if (ctx->stored_items[i].valid &&
            memcmp(ctx->stored_items[i].id.bytes, storage_id->bytes,
                   CYXWIZ_STORAGE_ID_SIZE) == 0) {
            return &ctx->stored_items[i];
        }
    }
    return NULL;
}

static cyxwiz_stored_item_t *alloc_stored_item(cyxwiz_storage_ctx_t *ctx)
{
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
        if (!ctx->stored_items[i].valid) {
            memset(&ctx->stored_items[i], 0, sizeof(cyxwiz_stored_item_t));
            ctx->stored_items[i].valid = true;
            ctx->stored_count++;
            return &ctx->stored_items[i];
        }
    }
    return NULL;
}

static void free_stored_item(cyxwiz_storage_ctx_t *ctx, cyxwiz_stored_item_t *item)
{
    if (item == NULL) {
        return;
    }

    if (item->encrypted_data != NULL) {
        ctx->storage_used_bytes -= item->encrypted_len;
        cyxwiz_secure_zero(item->encrypted_data, item->encrypted_len);
        cyxwiz_free(item->encrypted_data, item->encrypted_len);
    }

    cyxwiz_secure_zero(&item->share, sizeof(item->share));
    memset(item, 0, sizeof(cyxwiz_stored_item_t));
    item->valid = false;
    ctx->stored_count--;
}

static cyxwiz_error_t try_reconstruct(cyxwiz_storage_ctx_t *ctx, cyxwiz_storage_op_t *op)
{
    /* Reconstruct encryption key from shares */
    uint8_t reconstructed_key[CYXWIZ_KEY_SIZE];

    cyxwiz_error_t err = cyxwiz_crypto_reconstruct_secret(
        ctx->crypto_ctx,
        op->retrieved_shares,
        op->providers_retrieved,
        reconstructed_key,
        CYXWIZ_KEY_SIZE
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to reconstruct key: %d", err);
        op->state = CYXWIZ_STORAGE_STATE_FAILED;
        complete_operation(ctx, op, NULL, 0);
        return err;
    }

    /* Decrypt data */
    size_t plaintext_len = op->encrypted_len - CYXWIZ_CRYPTO_OVERHEAD;
    uint8_t *plaintext = cyxwiz_calloc(1, plaintext_len);
    if (plaintext == NULL) {
        cyxwiz_secure_zero(reconstructed_key, sizeof(reconstructed_key));
        op->state = CYXWIZ_STORAGE_STATE_FAILED;
        complete_operation(ctx, op, NULL, 0);
        return CYXWIZ_ERR_NOMEM;
    }

    size_t actual_len;
    err = cyxwiz_crypto_decrypt(
        op->encrypted_data, op->encrypted_len,
        reconstructed_key,
        plaintext, &actual_len
    );

    cyxwiz_secure_zero(reconstructed_key, sizeof(reconstructed_key));

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to decrypt data: %d", err);
        cyxwiz_free(plaintext, plaintext_len);
        op->state = CYXWIZ_STORAGE_STATE_FAILED;
        complete_operation(ctx, op, NULL, 0);
        return err;
    }

    /* Success */
    op->state = CYXWIZ_STORAGE_STATE_RETRIEVED;
    op->completed_at = get_time_ms();

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&op->id, id_hex);
    CYXWIZ_INFO("Retrieve complete: %s (%zu bytes)", id_hex, actual_len);

    complete_operation(ctx, op, plaintext, actual_len);

    cyxwiz_secure_zero(plaintext, plaintext_len);
    cyxwiz_free(plaintext, plaintext_len);

    return CYXWIZ_OK;
}

static void complete_operation(
    cyxwiz_storage_ctx_t *ctx,
    cyxwiz_storage_op_t *op,
    const uint8_t *data,
    size_t data_len)
{
    if (ctx->on_complete != NULL) {
        ctx->on_complete(ctx, op, data, data_len, ctx->complete_user_data);
    }

    /* Free operation after callback */
    free_operation(op);
    ctx->operation_count--;
}

/* ============ Utilities ============ */

const cyxwiz_storage_op_t *cyxwiz_storage_get_operation(
    const cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id)
{
    if (ctx == NULL || storage_id == NULL) {
        return NULL;
    }
    return find_operation((cyxwiz_storage_ctx_t *)ctx, storage_id);
}

size_t cyxwiz_storage_operation_count(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->operation_count;
}

size_t cyxwiz_storage_stored_count(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->stored_count;
}

size_t cyxwiz_storage_used_bytes(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->storage_used_bytes;
}

const char *cyxwiz_storage_state_name(cyxwiz_storage_state_t state)
{
    switch (state) {
        case CYXWIZ_STORAGE_STATE_PENDING:      return "pending";
        case CYXWIZ_STORAGE_STATE_DISTRIBUTING: return "distributing";
        case CYXWIZ_STORAGE_STATE_STORED:       return "stored";
        case CYXWIZ_STORAGE_STATE_RETRIEVING:   return "retrieving";
        case CYXWIZ_STORAGE_STATE_RETRIEVED:    return "retrieved";
        case CYXWIZ_STORAGE_STATE_DELETING:     return "deleting";
        case CYXWIZ_STORAGE_STATE_DELETED:      return "deleted";
        case CYXWIZ_STORAGE_STATE_FAILED:       return "failed";
        case CYXWIZ_STORAGE_STATE_EXPIRED:      return "expired";
        default:                                return "unknown";
    }
}

const char *cyxwiz_storage_op_type_name(cyxwiz_storage_op_type_t type)
{
    switch (type) {
        case CYXWIZ_STORAGE_OP_STORE:    return "store";
        case CYXWIZ_STORAGE_OP_RETRIEVE: return "retrieve";
        case CYXWIZ_STORAGE_OP_DELETE:   return "delete";
        default:                         return "unknown";
    }
}

int cyxwiz_storage_id_compare(
    const cyxwiz_storage_id_t *a,
    const cyxwiz_storage_id_t *b)
{
    if (a == NULL || b == NULL) {
        return -1;
    }
    return memcmp(a->bytes, b->bytes, CYXWIZ_STORAGE_ID_SIZE);
}

void cyxwiz_storage_id_to_hex(
    const cyxwiz_storage_id_t *id,
    char *hex_out)
{
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < CYXWIZ_STORAGE_ID_SIZE; i++) {
        hex_out[i * 2] = hex_chars[(id->bytes[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[id->bytes[i] & 0x0F];
    }
    hex_out[CYXWIZ_STORAGE_ID_SIZE * 2] = '\0';
}

void cyxwiz_storage_id_generate(
    const uint8_t *data,
    size_t data_len,
    cyxwiz_storage_id_t *id_out)
{
    /* Hash: data || random_salt */
    uint8_t salt[8];
    cyxwiz_crypto_random(salt, sizeof(salt));

    uint8_t hash_input[CYXWIZ_STORAGE_MAX_PAYLOAD + 8];
    size_t input_len = data_len;
    if (input_len > CYXWIZ_STORAGE_MAX_PAYLOAD) {
        input_len = CYXWIZ_STORAGE_MAX_PAYLOAD;
    }
    memcpy(hash_input, data, input_len);
    memcpy(hash_input + input_len, salt, sizeof(salt));

    uint8_t hash[32];
    cyxwiz_crypto_hash(hash_input, input_len + sizeof(salt), hash, sizeof(hash));

    /* Take first 8 bytes as ID */
    memcpy(id_out->bytes, hash, CYXWIZ_STORAGE_ID_SIZE);
}
