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

    /* Proof of Storage */
    cyxwiz_pos_challenge_state_t pos_challenges[CYXWIZ_MAX_POS_CHALLENGES];
    size_t pos_challenge_count;
    cyxwiz_pos_result_cb_t on_pos_result;
    void *pos_result_user_data;

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

/* Proof of Storage helpers */
static void merkle_hash_block(const uint8_t *block, size_t len, uint8_t *out);
static size_t merkle_build_tree(const uint8_t *data, size_t data_len,
                                 uint8_t tree[][CYXWIZ_POS_HASH_SIZE],
                                 size_t *num_leaves_out);
static void merkle_get_proof(const uint8_t tree[][CYXWIZ_POS_HASH_SIZE],
                              size_t tree_size, size_t num_leaves,
                              uint8_t block_index,
                              uint8_t path[][CYXWIZ_POS_HASH_SIZE],
                              uint8_t *depth_out, uint8_t *positions_out);
static bool merkle_verify_path(const uint8_t *block_data, size_t block_len,
                                uint8_t block_index,
                                const uint8_t path[][CYXWIZ_POS_HASH_SIZE],
                                uint8_t depth, uint8_t sibling_positions,
                                const uint8_t *expected_root);

/* PoS message handlers */
static cyxwiz_error_t handle_pos_commitment(cyxwiz_storage_ctx_t *ctx,
                                             const cyxwiz_node_id_t *from,
                                             const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_challenge(cyxwiz_storage_ctx_t *ctx,
                                            const cyxwiz_node_id_t *from,
                                            const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_proof(cyxwiz_storage_ctx_t *ctx,
                                        const cyxwiz_node_id_t *from,
                                        const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_verify_ok(cyxwiz_storage_ctx_t *ctx,
                                            const cyxwiz_node_id_t *from,
                                            const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_verify_fail(cyxwiz_storage_ctx_t *ctx,
                                              const cyxwiz_node_id_t *from,
                                              const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_request_commit(cyxwiz_storage_ctx_t *ctx,
                                                 const cyxwiz_node_id_t *from,
                                                 const uint8_t *data, size_t len);

/* PoS message senders */
static cyxwiz_error_t send_pos_commitment(cyxwiz_storage_ctx_t *ctx,
                                           const cyxwiz_node_id_t *to,
                                           const cyxwiz_pos_commitment_t *commitment);
static cyxwiz_error_t send_pos_challenge_msg(cyxwiz_storage_ctx_t *ctx,
                                              const cyxwiz_node_id_t *to,
                                              const cyxwiz_storage_id_t *storage_id,
                                              uint8_t block_index,
                                              const uint8_t *nonce,
                                              uint8_t sequence);
static cyxwiz_error_t send_pos_proof_msg(cyxwiz_storage_ctx_t *ctx,
                                          const cyxwiz_node_id_t *to,
                                          cyxwiz_stored_item_t *item,
                                          uint8_t block_index,
                                          const uint8_t *nonce);
static cyxwiz_error_t send_pos_verify_ok_msg(cyxwiz_storage_ctx_t *ctx,
                                              const cyxwiz_node_id_t *to,
                                              const cyxwiz_storage_id_t *storage_id,
                                              uint8_t sequence);
static cyxwiz_error_t send_pos_verify_fail_msg(cyxwiz_storage_ctx_t *ctx,
                                                const cyxwiz_node_id_t *to,
                                                const cyxwiz_storage_id_t *storage_id,
                                                uint8_t sequence,
                                                cyxwiz_pos_fail_reason_t reason);

/* Anonymous PoS message senders and handlers */
static cyxwiz_error_t send_pos_challenge_anon_msg(cyxwiz_storage_ctx_t *ctx,
                                                   const cyxwiz_node_id_t *to,
                                                   const cyxwiz_storage_id_t *storage_id,
                                                   uint8_t block_index,
                                                   const uint8_t *nonce,
                                                   const cyxwiz_surb_t *reply_surb);
static cyxwiz_error_t send_pos_request_commit_anon_msg(cyxwiz_storage_ctx_t *ctx,
                                                        const cyxwiz_node_id_t *to,
                                                        const cyxwiz_storage_id_t *storage_id,
                                                        const cyxwiz_surb_t *reply_surb);
static cyxwiz_error_t send_pos_commitment_via_surb(cyxwiz_storage_ctx_t *ctx,
                                                    const cyxwiz_surb_t *surb,
                                                    const cyxwiz_pos_commitment_t *commitment);
static cyxwiz_error_t send_pos_proof_via_surb(cyxwiz_storage_ctx_t *ctx,
                                               const cyxwiz_surb_t *surb,
                                               cyxwiz_stored_item_t *item,
                                               uint8_t block_index,
                                               const uint8_t *nonce);
static cyxwiz_error_t handle_pos_challenge_anon(cyxwiz_storage_ctx_t *ctx,
                                                 const cyxwiz_node_id_t *from,
                                                 const uint8_t *data, size_t len);
static cyxwiz_error_t handle_pos_request_commit_anon(cyxwiz_storage_ctx_t *ctx,
                                                      const cyxwiz_node_id_t *from,
                                                      const uint8_t *data, size_t len);

/* Anonymous storage helpers */
static cyxwiz_error_t send_store_req_anon(cyxwiz_storage_ctx_t *ctx,
                                           const cyxwiz_node_id_t *to,
                                           cyxwiz_storage_op_t *op,
                                           uint8_t share_index,
                                           const cyxwiz_share_t *share,
                                           const cyxwiz_surb_t *reply_surb);
static cyxwiz_error_t send_store_ack_via_surb(cyxwiz_storage_ctx_t *ctx,
                                               const cyxwiz_surb_t *surb,
                                               const cyxwiz_storage_id_t *storage_id,
                                               uint8_t share_index,
                                               uint64_t expires_at);
static cyxwiz_error_t send_retrieve_req_anon(cyxwiz_storage_ctx_t *ctx,
                                              const cyxwiz_node_id_t *to,
                                              const cyxwiz_storage_id_t *storage_id,
                                              const cyxwiz_surb_t *reply_surb);
static cyxwiz_error_t send_retrieve_resp_via_surb(cyxwiz_storage_ctx_t *ctx,
                                                   const cyxwiz_surb_t *surb,
                                                   cyxwiz_stored_item_t *item);
static cyxwiz_error_t send_delete_req_anon(cyxwiz_storage_ctx_t *ctx,
                                            const cyxwiz_node_id_t *to,
                                            const cyxwiz_storage_id_t *storage_id,
                                            const uint8_t *delete_token,
                                            const cyxwiz_surb_t *reply_surb);
static cyxwiz_error_t send_delete_ack_via_surb(cyxwiz_storage_ctx_t *ctx,
                                                const cyxwiz_surb_t *surb,
                                                const cyxwiz_storage_id_t *storage_id);
static cyxwiz_error_t handle_store_req_anon(cyxwiz_storage_ctx_t *ctx,
                                             const cyxwiz_node_id_t *from,
                                             const uint8_t *data, size_t len);
static cyxwiz_error_t handle_retrieve_req_anon(cyxwiz_storage_ctx_t *ctx,
                                                const cyxwiz_node_id_t *from,
                                                const uint8_t *data, size_t len);
static cyxwiz_error_t handle_delete_req_anon(cyxwiz_storage_ctx_t *ctx,
                                              const cyxwiz_node_id_t *from,
                                              const uint8_t *data, size_t len);

/* PoS challenge state helpers */
static cyxwiz_pos_challenge_state_t *find_pos_challenge(cyxwiz_storage_ctx_t *ctx,
                                                         const cyxwiz_storage_id_t *storage_id,
                                                         const cyxwiz_node_id_t *provider_id);
static cyxwiz_pos_challenge_state_t *alloc_pos_challenge(cyxwiz_storage_ctx_t *ctx);
static void free_pos_challenge(cyxwiz_storage_ctx_t *ctx,
                                cyxwiz_pos_challenge_state_t *challenge);

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

    /* PoS initialization */
    s->pos_challenge_count = 0;
    s->on_pos_result = NULL;
    s->pos_result_user_data = NULL;

    /* Initialize all slots as invalid */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_STORAGE_OPS; i++) {
        s->operations[i].valid = false;
    }
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_ITEMS; i++) {
        s->stored_items[i].valid = false;
    }
    for (size_t i = 0; i < CYXWIZ_MAX_POS_CHALLENGES; i++) {
        s->pos_challenges[i].active = false;
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

/* ============ Anonymous Client Operations ============ */

bool cyxwiz_storage_can_store_anonymous(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }

    return cyxwiz_router_can_create_surb(ctx->router);
}

cyxwiz_error_t cyxwiz_storage_store_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *providers,
    size_t num_providers,
    uint8_t threshold,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    cyxwiz_storage_id_t *storage_id_out,
    uint8_t *delete_token_out)
{
    if (ctx == NULL || providers == NULL || data == NULL ||
        storage_id_out == NULL || delete_token_out == NULL) {
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

    /* Check SURB capability */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        CYXWIZ_ERROR("Cannot create SURB - insufficient relay peers");
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Check data size */
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

    /* Generate random delete token */
    cyxwiz_crypto_random(op->delete_token, CYXWIZ_MAC_SIZE);
    memcpy(delete_token_out, op->delete_token, CYXWIZ_MAC_SIZE);

    /* Initialize operation as anonymous */
    op->state = CYXWIZ_STORAGE_STATE_DISTRIBUTING;
    op->op_type = CYXWIZ_STORAGE_OP_STORE;
    op->is_anonymous = true;
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
        op->total_chunks = 0;
    } else {
        op->total_chunks = (uint8_t)((op->encrypted_len + CYXWIZ_STORAGE_CHUNK_SIZE - 1) /
                                     CYXWIZ_STORAGE_CHUNK_SIZE);
    }

    /* Create SURBs and send anonymous STORE_REQ to each provider */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].share_index = (uint8_t)(i + 1);
        op->providers[i].confirmed = false;
        op->providers[i].retrieved = false;
        op->providers[i].sent_at = get_time_ms();

        /* Create SURB for this provider's reply */
        err = cyxwiz_router_create_surb(ctx->router, &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to create SURB for provider %zu: %s", i, cyxwiz_strerror(err));
            continue;
        }

        err = send_store_req_anon(ctx, &providers[i], op, (uint8_t)(i + 1),
                                   &shares[i], &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send anonymous STORE_REQ to provider %zu: %d", i, err);
        }
    }

    cyxwiz_secure_zero(shares, sizeof(shares));

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&op->id, id_hex);
    CYXWIZ_INFO("Anonymous storage store initiated: %s (%zu bytes, %u-of-%u threshold)",
                id_hex, data_len, threshold, (unsigned)num_providers);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_storage_retrieve_anonymous(
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

    /* Check SURB capability */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        CYXWIZ_ERROR("Cannot create SURB - insufficient relay peers");
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
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

    /* Initialize operation as anonymous */
    memcpy(&op->id, storage_id, sizeof(cyxwiz_storage_id_t));
    op->state = CYXWIZ_STORAGE_STATE_RETRIEVING;
    op->op_type = CYXWIZ_STORAGE_OP_RETRIEVE;
    op->is_anonymous = true;
    memcpy(&op->owner, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    op->num_shares = (uint8_t)num_providers;
    op->threshold = 0;
    op->created_at = get_time_ms();
    op->is_owner = true;
    op->providers_retrieved = 0;

    /* Initialize provider slots and send anonymous RETRIEVE_REQ */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].retrieved = false;
        op->providers[i].sent_at = get_time_ms();

        /* Create SURB for this provider's reply */
        cyxwiz_error_t err = cyxwiz_router_create_surb(ctx->router, &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to create SURB for provider %zu: %s", i, cyxwiz_strerror(err));
            continue;
        }

        err = send_retrieve_req_anon(ctx, &providers[i], storage_id, &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send anonymous RETRIEVE_REQ to provider %zu: %d", i, err);
        }
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_INFO("Anonymous storage retrieve initiated: %s (from %zu providers)",
                id_hex, num_providers);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_storage_delete_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const uint8_t *delete_token,
    const cyxwiz_node_id_t *providers,
    size_t num_providers)
{
    if (ctx == NULL || storage_id == NULL || delete_token == NULL || providers == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (num_providers < 1 || num_providers > CYXWIZ_MAX_STORAGE_PROVIDERS) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check SURB capability */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        CYXWIZ_ERROR("Cannot create SURB - insufficient relay peers");
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Allocate operation */
    cyxwiz_storage_op_t *op = alloc_operation(ctx);
    if (op == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize operation as anonymous */
    memcpy(&op->id, storage_id, sizeof(cyxwiz_storage_id_t));
    op->state = CYXWIZ_STORAGE_STATE_DELETING;
    op->op_type = CYXWIZ_STORAGE_OP_DELETE;
    op->is_anonymous = true;
    memcpy(&op->owner, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    op->num_shares = (uint8_t)num_providers;
    op->created_at = get_time_ms();
    op->is_owner = true;
    op->providers_confirmed = 0;
    memcpy(op->delete_token, delete_token, CYXWIZ_MAC_SIZE);

    /* Initialize provider slots and send anonymous DELETE_REQ */
    for (size_t i = 0; i < num_providers; i++) {
        memcpy(&op->providers[i].provider_id, &providers[i], sizeof(cyxwiz_node_id_t));
        op->providers[i].confirmed = false;
        op->providers[i].sent_at = get_time_ms();

        /* Create SURB for this provider's reply */
        cyxwiz_error_t err = cyxwiz_router_create_surb(ctx->router, &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to create SURB for provider %zu: %s", i, cyxwiz_strerror(err));
            continue;
        }

        err = send_delete_req_anon(ctx, &providers[i], storage_id,
                                    delete_token, &op->reply_surbs[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_WARN("Failed to send anonymous DELETE_REQ to provider %zu: %d", i, err);
        }
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_INFO("Anonymous storage delete initiated: %s (to %zu providers)",
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

        /* Proof of Storage messages */
        case CYXWIZ_MSG_POS_COMMITMENT:
            return handle_pos_commitment(ctx, from, data, len);
        case CYXWIZ_MSG_POS_CHALLENGE:
            return handle_pos_challenge(ctx, from, data, len);
        case CYXWIZ_MSG_POS_PROOF:
            return handle_pos_proof(ctx, from, data, len);
        case CYXWIZ_MSG_POS_VERIFY_OK:
            return handle_pos_verify_ok(ctx, from, data, len);
        case CYXWIZ_MSG_POS_VERIFY_FAIL:
            return handle_pos_verify_fail(ctx, from, data, len);
        case CYXWIZ_MSG_POS_REQUEST_COMMIT:
            return handle_pos_request_commit(ctx, from, data, len);
        case CYXWIZ_MSG_POS_CHALLENGE_ANON:
            return handle_pos_challenge_anon(ctx, from, data, len);
        case CYXWIZ_MSG_POS_REQUEST_COMMIT_ANON:
            return handle_pos_request_commit_anon(ctx, from, data, len);

        /* Anonymous storage messages */
        case CYXWIZ_MSG_STORE_REQ_ANON:
            return handle_store_req_anon(ctx, from, data, len);
        case CYXWIZ_MSG_RETRIEVE_REQ_ANON:
            return handle_retrieve_req_anon(ctx, from, data, len);
        case CYXWIZ_MSG_DELETE_REQ_ANON:
            return handle_delete_req_anon(ctx, from, data, len);

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

        /* Compute and send PoS commitment */
        cyxwiz_error_t pos_err = cyxwiz_pos_compute_commitment(
            item->encrypted_data, item->encrypted_len,
            &storage_id, &item->pos_commitment);
        if (pos_err == CYXWIZ_OK) {
            item->has_pos_commitment = true;
            send_pos_commitment(ctx, from, &item->pos_commitment);
        }
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

        /* Compute and send PoS commitment */
        cyxwiz_error_t pos_err = cyxwiz_pos_compute_commitment(
            item->encrypted_data, item->encrypted_len,
            &storage_id, &item->pos_commitment);
        if (pos_err == CYXWIZ_OK) {
            item->has_pos_commitment = true;
            send_pos_commitment(ctx, from, &item->pos_commitment);
        }
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

/* ============ Anonymous Message Handlers ============ */

static cyxwiz_error_t handle_store_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_store_req_anon_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_store_req_anon_msg_t *msg = (const cyxwiz_store_req_anon_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Check if we're a provider */
    if (!ctx->is_provider) {
        CYXWIZ_DEBUG("Ignoring anonymous STORE_REQ %s: not a provider", id_hex);
        /* Cannot send reject via SURB - just ignore */
        return CYXWIZ_OK;
    }

    /* Check TTL */
    uint32_t ttl = msg->ttl_seconds;
    if (ttl > ctx->max_ttl_seconds) {
        CYXWIZ_DEBUG("Ignoring anonymous STORE_REQ %s: TTL too long", id_hex);
        return CYXWIZ_OK;
    }

    /* Check for duplicate */
    if (find_stored_item(ctx, &storage_id) != NULL) {
        CYXWIZ_DEBUG("Ignoring anonymous STORE_REQ %s: duplicate", id_hex);
        return CYXWIZ_OK;
    }

    /* Parse share from message */
    const uint8_t *share_data = data + sizeof(cyxwiz_store_req_anon_msg_t);
    size_t remaining = len - sizeof(cyxwiz_store_req_anon_msg_t);

    if (remaining < sizeof(cyxwiz_share_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check storage capacity */
    uint16_t payload_len = msg->payload_len;
    if (ctx->storage_used_bytes + payload_len > ctx->storage_max_bytes) {
        CYXWIZ_DEBUG("Ignoring anonymous STORE_REQ %s: storage full", id_hex);
        return CYXWIZ_OK;
    }

    /* Allocate stored item */
    cyxwiz_stored_item_t *item = alloc_stored_item(ctx);
    if (item == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize item - no owner ID for anonymous storage */
    memcpy(&item->id, &storage_id, sizeof(cyxwiz_storage_id_t));
    memset(&item->owner, 0, sizeof(cyxwiz_node_id_t)); /* Anonymous - no owner */
    memcpy(&item->share, share_data, sizeof(cyxwiz_share_t));
    item->share_index = msg->share_index;
    item->total_chunks = msg->total_chunks;
    item->received_chunks = 0;
    item->chunk_bitmap = 0;
    item->stored_at = get_time_ms();
    item->expires_at = item->stored_at + ((uint64_t)ttl * 1000);
    item->is_anonymous = true;
    memcpy(item->delete_token, msg->delete_token, CYXWIZ_MAC_SIZE);

    /* Allocate encrypted data buffer */
    item->encrypted_data = cyxwiz_calloc(1, payload_len);
    if (item->encrypted_data == NULL) {
        free_stored_item(ctx, item);
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

        /* Compute PoS commitment (but don't send - owner will request anonymously) */
        cyxwiz_error_t pos_err = cyxwiz_pos_compute_commitment(
            item->encrypted_data, item->encrypted_len,
            &storage_id, &item->pos_commitment);
        if (pos_err == CYXWIZ_OK) {
            item->has_pos_commitment = true;
            CYXWIZ_DEBUG("Computed PoS commitment for anonymous item %s (%u blocks)",
                         id_hex, item->pos_commitment.num_blocks);
        }

        /* Send ACK via SURB */
        CYXWIZ_DEBUG("Anonymous stored item %s (share %u, %u bytes)",
                     id_hex, item->share_index, payload_len);

        return send_store_ack_via_surb(ctx, &msg->reply_surb, &storage_id,
                                        item->share_index, item->expires_at);
    }

    /* Chunked storage - wait for chunks before sending ACK */
    CYXWIZ_DEBUG("Anonymous STORE_REQ %s: waiting for %u chunks",
                 id_hex, item->total_chunks);

    /* Store SURB for later ACK (would need to add surb field to stored_item) */
    /* For now, send immediate ACK even for chunked - simplified */
    /* Note: PoS commitment computed after all chunks received */
    return send_store_ack_via_surb(ctx, &msg->reply_surb, &storage_id,
                                    item->share_index, item->expires_at);
}

static cyxwiz_error_t handle_retrieve_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_retrieve_req_anon_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_retrieve_req_anon_msg_t *msg = (const cyxwiz_retrieve_req_anon_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        CYXWIZ_DEBUG("Anonymous RETRIEVE_REQ %s: not found", id_hex);
        /* Cannot send error response via SURB for not found */
        return CYXWIZ_OK;
    }

    /* Check expiry */
    if (get_time_ms() >= item->expires_at) {
        CYXWIZ_DEBUG("Anonymous RETRIEVE_REQ %s: expired", id_hex);
        free_stored_item(ctx, item);
        return CYXWIZ_OK;
    }

    /* No ownership check for anonymous retrieve - anyone with ID can retrieve */
    CYXWIZ_DEBUG("Anonymous RETRIEVE_REQ %s: sending share %u via SURB",
                 id_hex, item->share_index);

    return send_retrieve_resp_via_surb(ctx, &msg->reply_surb, item);
}

static cyxwiz_error_t handle_delete_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_delete_req_anon_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_delete_req_anon_msg_t *msg = (const cyxwiz_delete_req_anon_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        CYXWIZ_DEBUG("Anonymous DELETE_REQ %s: not found", id_hex);
        return CYXWIZ_OK;
    }

    /* Verify delete token for anonymous items */
    if (!item->is_anonymous) {
        CYXWIZ_DEBUG("Anonymous DELETE_REQ %s: item was not stored anonymously", id_hex);
        return CYXWIZ_OK;
    }

    /* Compare delete tokens using constant-time comparison */
    bool token_match = true;
    for (size_t i = 0; i < CYXWIZ_MAC_SIZE; i++) {
        if (item->delete_token[i] != msg->delete_token[i]) {
            token_match = false;
        }
    }

    if (!token_match) {
        CYXWIZ_DEBUG("Anonymous DELETE_REQ %s: invalid delete token", id_hex);
        return CYXWIZ_OK;
    }

    /* Delete the item */
    CYXWIZ_DEBUG("Anonymous DELETE_REQ %s: deleting item", id_hex);
    free_stored_item(ctx, item);

    /* Send ACK via SURB */
    return send_delete_ack_via_surb(ctx, &msg->reply_surb, &storage_id);
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

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, offset, CYXWIZ_PADDED_SIZE);

    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);

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

    size_t msg_len = sizeof(cyxwiz_store_chunk_msg_t) + len;

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
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

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, offset, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
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

/* ============ Anonymous Storage Send Functions ============ */

static cyxwiz_error_t send_store_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    cyxwiz_storage_op_t *op,
    uint8_t share_index,
    const cyxwiz_share_t *share,
    const cyxwiz_surb_t *reply_surb)
{
    /* Build message - use larger buffer for packed struct safety */
    uint8_t buf[300];
    cyxwiz_store_req_anon_msg_t *msg = (cyxwiz_store_req_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_STORE_REQ_ANON;
    memcpy(msg->storage_id, op->id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->share_index = share_index;
    msg->total_shares = op->num_shares;
    msg->threshold = op->threshold;
    msg->ttl_seconds = op->ttl_seconds;
    msg->total_chunks = op->total_chunks;
    msg->payload_len = (uint16_t)op->encrypted_len;
    memcpy(msg->delete_token, op->delete_token, CYXWIZ_MAC_SIZE);
    memcpy(&msg->reply_surb, reply_surb, sizeof(cyxwiz_surb_t));

    /* Append share */
    size_t offset = sizeof(cyxwiz_store_req_anon_msg_t);
    memcpy(buf + offset, share, sizeof(cyxwiz_share_t));
    offset += sizeof(cyxwiz_share_t);

    /* If inline payload, append encrypted data */
    if (op->total_chunks == 0) {
        memcpy(buf + offset, op->encrypted_data, op->encrypted_len);
        offset += op->encrypted_len;
    }

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, offset, CYXWIZ_PADDED_SIZE);

    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);

    /* If chunked, send chunks (via normal route, not anonymous) */
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

static cyxwiz_error_t send_store_ack_via_surb(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_surb_t *surb,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t share_index,
    uint64_t expires_at)
{
    uint8_t buf[256];
    cyxwiz_store_ack_msg_t *msg = (cyxwiz_store_ack_msg_t *)buf;

    msg->type = CYXWIZ_MSG_STORE_ACK;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->share_index = share_index;
    msg->expires_at = expires_at;

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_store_ack_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, surb, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_retrieve_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_surb_t *reply_surb)
{
    uint8_t buf[256];
    cyxwiz_retrieve_req_anon_msg_t *msg = (cyxwiz_retrieve_req_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_RETRIEVE_REQ_ANON;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(&msg->reply_surb, reply_surb, sizeof(cyxwiz_surb_t));

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_retrieve_req_anon_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_retrieve_resp_via_surb(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_surb_t *surb,
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

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, offset, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, surb, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_delete_req_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    const uint8_t *delete_token,
    const cyxwiz_surb_t *reply_surb)
{
    uint8_t buf[256];
    cyxwiz_delete_req_anon_msg_t *msg = (cyxwiz_delete_req_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_DELETE_REQ_ANON;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(msg->delete_token, delete_token, CYXWIZ_MAC_SIZE);
    memcpy(&msg->reply_surb, reply_surb, sizeof(cyxwiz_surb_t));

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_delete_req_anon_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_delete_ack_via_surb(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_surb_t *surb,
    const cyxwiz_storage_id_t *storage_id)
{
    uint8_t buf[256];
    cyxwiz_delete_ack_msg_t *msg = (cyxwiz_delete_ack_msg_t *)buf;

    msg->type = CYXWIZ_MSG_DELETE_ACK;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_delete_ack_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, surb, buf, CYXWIZ_PADDED_SIZE);
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

/* ============ Proof of Storage - Merkle Tree Functions ============ */

/*
 * Hash a single block using BLAKE2b-256
 */
static void merkle_hash_block(const uint8_t *block, size_t len, uint8_t *out)
{
    cyxwiz_crypto_hash(block, len, out, CYXWIZ_POS_HASH_SIZE);
}

/*
 * Round up to next power of 2
 */
static size_t next_power_of_2(size_t n)
{
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

/*
 * Build a complete Merkle tree from data blocks
 * Returns total tree size (nodes), sets num_leaves_out
 * Tree is stored in array form: leaves at indices [tree_size/2, tree_size-1]
 */
static size_t merkle_build_tree(
    const uint8_t *data,
    size_t data_len,
    uint8_t tree[][CYXWIZ_POS_HASH_SIZE],
    size_t *num_leaves_out)
{
    /* Calculate number of blocks */
    size_t num_blocks = (data_len + CYXWIZ_POS_BLOCK_SIZE - 1) / CYXWIZ_POS_BLOCK_SIZE;
    if (num_blocks == 0) num_blocks = 1;
    if (num_blocks > CYXWIZ_POS_MAX_BLOCKS) num_blocks = CYXWIZ_POS_MAX_BLOCKS;

    /* Pad to power of 2 for complete binary tree */
    size_t num_leaves = next_power_of_2(num_blocks);
    size_t tree_size = num_leaves * 2;

    *num_leaves_out = num_leaves;

    /* Hash data blocks into leaf positions */
    for (size_t i = 0; i < num_leaves; i++) {
        size_t leaf_idx = num_leaves + i; /* Leaves at [num_leaves, 2*num_leaves-1] */

        if (i < num_blocks) {
            size_t offset = i * CYXWIZ_POS_BLOCK_SIZE;
            size_t block_len = data_len - offset;
            if (block_len > CYXWIZ_POS_BLOCK_SIZE) {
                block_len = CYXWIZ_POS_BLOCK_SIZE;
            }
            merkle_hash_block(data + offset, block_len, tree[leaf_idx]);
        } else {
            /* Padding with zeros for empty leaves */
            memset(tree[leaf_idx], 0, CYXWIZ_POS_HASH_SIZE);
        }
    }

    /* Build internal nodes bottom-up */
    for (size_t i = num_leaves - 1; i >= 1; i--) {
        size_t left = i * 2;
        size_t right = i * 2 + 1;

        /* Hash(left || right) */
        uint8_t combined[CYXWIZ_POS_HASH_SIZE * 2];
        memcpy(combined, tree[left], CYXWIZ_POS_HASH_SIZE);
        memcpy(combined + CYXWIZ_POS_HASH_SIZE, tree[right], CYXWIZ_POS_HASH_SIZE);
        merkle_hash_block(combined, CYXWIZ_POS_HASH_SIZE * 2, tree[i]);
    }

    return tree_size;
}

/*
 * Get proof path for a specific block index
 * path contains sibling hashes, positions indicates left(0) or right(1)
 */
static void merkle_get_proof(
    const uint8_t tree[][CYXWIZ_POS_HASH_SIZE],
    size_t tree_size,
    size_t num_leaves,
    uint8_t block_index,
    uint8_t path[][CYXWIZ_POS_HASH_SIZE],
    uint8_t *depth_out,
    uint8_t *positions_out)
{
    CYXWIZ_UNUSED(tree_size);

    uint8_t depth = 0;
    uint8_t positions = 0;

    /* Start at leaf */
    size_t idx = num_leaves + block_index;

    /* Walk up to root (but not including root at index 1) */
    while (idx > 1) {
        size_t sibling_idx;
        if (idx % 2 == 0) {
            /* We're left child, sibling is right */
            sibling_idx = idx + 1;
            positions |= (1 << depth); /* Sibling on right */
        } else {
            /* We're right child, sibling is left */
            sibling_idx = idx - 1;
            /* Sibling on left, bit stays 0 */
        }

        memcpy(path[depth], tree[sibling_idx], CYXWIZ_POS_HASH_SIZE);
        depth++;

        /* Move to parent */
        idx = idx / 2;
    }

    *depth_out = depth;
    *positions_out = positions;
}

/*
 * Verify a Merkle proof by reconstructing the root
 */
static bool merkle_verify_path(
    const uint8_t *block_data,
    size_t block_len,
    uint8_t block_index,
    const uint8_t path[][CYXWIZ_POS_HASH_SIZE],
    uint8_t depth,
    uint8_t sibling_positions,
    const uint8_t *expected_root)
{
    CYXWIZ_UNUSED(block_index);

    /* Start with hash of the block */
    uint8_t current[CYXWIZ_POS_HASH_SIZE];
    merkle_hash_block(block_data, block_len, current);

    /* Walk up the tree */
    for (uint8_t i = 0; i < depth; i++) {
        uint8_t combined[CYXWIZ_POS_HASH_SIZE * 2];

        if (sibling_positions & (1 << i)) {
            /* Sibling on right: current || sibling */
            memcpy(combined, current, CYXWIZ_POS_HASH_SIZE);
            memcpy(combined + CYXWIZ_POS_HASH_SIZE, path[i], CYXWIZ_POS_HASH_SIZE);
        } else {
            /* Sibling on left: sibling || current */
            memcpy(combined, path[i], CYXWIZ_POS_HASH_SIZE);
            memcpy(combined + CYXWIZ_POS_HASH_SIZE, current, CYXWIZ_POS_HASH_SIZE);
        }

        merkle_hash_block(combined, CYXWIZ_POS_HASH_SIZE * 2, current);
    }

    /* Compare computed root with expected */
    return cyxwiz_secure_compare(current, expected_root, CYXWIZ_POS_HASH_SIZE) == 0;
}

/* ============ Proof of Storage - Challenge State Helpers ============ */

static cyxwiz_pos_challenge_state_t *find_pos_challenge(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_POS_CHALLENGES; i++) {
        if (ctx->pos_challenges[i].active &&
            cyxwiz_storage_id_compare(&ctx->pos_challenges[i].storage_id, storage_id) == 0 &&
            memcmp(&ctx->pos_challenges[i].provider_id, provider_id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &ctx->pos_challenges[i];
        }
    }
    return NULL;
}

static cyxwiz_pos_challenge_state_t *alloc_pos_challenge(cyxwiz_storage_ctx_t *ctx)
{
    for (size_t i = 0; i < CYXWIZ_MAX_POS_CHALLENGES; i++) {
        if (!ctx->pos_challenges[i].active) {
            memset(&ctx->pos_challenges[i], 0, sizeof(cyxwiz_pos_challenge_state_t));
            ctx->pos_challenges[i].active = true;
            ctx->pos_challenge_count++;
            return &ctx->pos_challenges[i];
        }
    }
    return NULL;
}

static void free_pos_challenge(cyxwiz_storage_ctx_t *ctx, cyxwiz_pos_challenge_state_t *challenge)
{
    if (challenge == NULL || !challenge->active) {
        return;
    }
    cyxwiz_secure_zero(challenge, sizeof(cyxwiz_pos_challenge_state_t));
    challenge->active = false;
    ctx->pos_challenge_count--;
}

/* ============ Proof of Storage - Message Senders ============ */

static cyxwiz_error_t send_pos_commitment(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_pos_commitment_t *commitment)
{
    cyxwiz_pos_commitment_msg_t msg;
    msg.type = CYXWIZ_MSG_POS_COMMITMENT;
    memcpy(msg.storage_id, commitment->storage_id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(msg.merkle_root, commitment->merkle_root, CYXWIZ_POS_HASH_SIZE);
    msg.num_blocks = commitment->num_blocks;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_pos_challenge_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t block_index,
    const uint8_t *nonce,
    uint8_t sequence)
{
    cyxwiz_pos_challenge_msg_t msg;
    msg.type = CYXWIZ_MSG_POS_CHALLENGE;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg.block_index = block_index;
    memcpy(msg.challenge_nonce, nonce, CYXWIZ_POS_CHALLENGE_SIZE);
    msg.sequence = sequence;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_pos_proof_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    cyxwiz_stored_item_t *item,
    uint8_t block_index,
    const uint8_t *nonce)
{
    /* Build Merkle tree */
    uint8_t tree[CYXWIZ_POS_MAX_BLOCKS * 2][CYXWIZ_POS_HASH_SIZE];
    size_t num_leaves;
    size_t tree_size = merkle_build_tree(item->encrypted_data, item->encrypted_len,
                                         tree, &num_leaves);

    /* Get proof path */
    uint8_t path[CYXWIZ_POS_MAX_PROOF_DEPTH][CYXWIZ_POS_HASH_SIZE];
    uint8_t depth, positions;
    merkle_get_proof((const uint8_t (*)[CYXWIZ_POS_HASH_SIZE])tree,
                     tree_size, num_leaves, block_index, path, &depth, &positions);

    /* Extract block data */
    size_t block_offset = (size_t)block_index * CYXWIZ_POS_BLOCK_SIZE;
    size_t block_len = item->encrypted_len - block_offset;
    if (block_len > CYXWIZ_POS_BLOCK_SIZE) {
        block_len = CYXWIZ_POS_BLOCK_SIZE;
    }

    /* Build message */
    uint8_t buf[256];
    cyxwiz_pos_proof_msg_t *msg = (cyxwiz_pos_proof_msg_t *)buf;

    msg->type = CYXWIZ_MSG_POS_PROOF;
    memcpy(msg->storage_id, item->id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->block_index = block_index;
    memcpy(msg->challenge_nonce, nonce, CYXWIZ_POS_CHALLENGE_SIZE);
    msg->block_len = (uint8_t)block_len;
    msg->proof_depth = depth;
    msg->sibling_positions = positions;

    /* Append block data */
    size_t offset = sizeof(cyxwiz_pos_proof_msg_t);
    memcpy(buf + offset, item->encrypted_data + block_offset, block_len);
    offset += block_len;

    /* Append proof path */
    for (uint8_t i = 0; i < depth; i++) {
        memcpy(buf + offset, path[i], CYXWIZ_POS_HASH_SIZE);
        offset += CYXWIZ_POS_HASH_SIZE;
    }

    return cyxwiz_router_send(ctx->router, to, buf, offset);
}

static cyxwiz_error_t send_pos_verify_ok_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t sequence)
{
    cyxwiz_pos_verify_ok_msg_t msg;
    msg.type = CYXWIZ_MSG_POS_VERIFY_OK;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg.sequence = sequence;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_pos_verify_fail_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t sequence,
    cyxwiz_pos_fail_reason_t reason)
{
    cyxwiz_pos_verify_fail_msg_t msg;
    msg.type = CYXWIZ_MSG_POS_VERIFY_FAIL;
    memcpy(msg.storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg.sequence = sequence;
    msg.reason = (uint8_t)reason;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

/* ============ Anonymous PoS - Message Senders ============ */

static cyxwiz_error_t send_pos_challenge_anon_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    uint8_t block_index,
    const uint8_t *nonce,
    const cyxwiz_surb_t *reply_surb)
{
    uint8_t buf[256];
    cyxwiz_pos_challenge_anon_msg_t *msg = (cyxwiz_pos_challenge_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_POS_CHALLENGE_ANON;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->block_index = block_index;
    memcpy(msg->challenge_nonce, nonce, CYXWIZ_POS_CHALLENGE_SIZE);
    memcpy(&msg->reply_surb, reply_surb, sizeof(cyxwiz_surb_t));

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_pos_challenge_anon_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_pos_request_commit_anon_msg(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_surb_t *reply_surb)
{
    uint8_t buf[256];
    cyxwiz_pos_request_commit_anon_msg_t *msg = (cyxwiz_pos_request_commit_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_POS_REQUEST_COMMIT_ANON;
    memcpy(msg->storage_id, storage_id->bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(&msg->reply_surb, reply_surb, sizeof(cyxwiz_surb_t));

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_pos_request_commit_anon_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_pos_commitment_via_surb(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_surb_t *surb,
    const cyxwiz_pos_commitment_t *commitment)
{
    uint8_t buf[256];
    cyxwiz_pos_commitment_msg_t *msg = (cyxwiz_pos_commitment_msg_t *)buf;

    msg->type = CYXWIZ_MSG_POS_COMMITMENT;
    memcpy(msg->storage_id, commitment->storage_id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    memcpy(msg->merkle_root, commitment->merkle_root, CYXWIZ_POS_HASH_SIZE);
    msg->num_blocks = commitment->num_blocks;

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, sizeof(cyxwiz_pos_commitment_msg_t), CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, surb, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_pos_proof_via_surb(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_surb_t *surb,
    cyxwiz_stored_item_t *item,
    uint8_t block_index,
    const uint8_t *nonce)
{
    /* Build Merkle tree */
    uint8_t tree[CYXWIZ_POS_MAX_BLOCKS * 2][CYXWIZ_POS_HASH_SIZE];
    size_t num_leaves;
    size_t tree_size = merkle_build_tree(item->encrypted_data, item->encrypted_len,
                                         tree, &num_leaves);

    /* Get proof path */
    uint8_t path[CYXWIZ_POS_MAX_PROOF_DEPTH][CYXWIZ_POS_HASH_SIZE];
    uint8_t depth, positions;
    merkle_get_proof((const uint8_t (*)[CYXWIZ_POS_HASH_SIZE])tree,
                     tree_size, num_leaves, block_index, path, &depth, &positions);

    /* Extract block data */
    size_t block_offset = (size_t)block_index * CYXWIZ_POS_BLOCK_SIZE;
    size_t block_len = item->encrypted_len - block_offset;
    if (block_len > CYXWIZ_POS_BLOCK_SIZE) {
        block_len = CYXWIZ_POS_BLOCK_SIZE;
    }

    /* Build message */
    uint8_t buf[256];
    cyxwiz_pos_proof_msg_t *msg = (cyxwiz_pos_proof_msg_t *)buf;

    msg->type = CYXWIZ_MSG_POS_PROOF;
    memcpy(msg->storage_id, item->id.bytes, CYXWIZ_STORAGE_ID_SIZE);
    msg->block_index = block_index;
    memcpy(msg->challenge_nonce, nonce, CYXWIZ_POS_CHALLENGE_SIZE);
    msg->block_len = (uint8_t)block_len;
    msg->proof_depth = depth;
    msg->sibling_positions = positions;

    /* Append block data */
    size_t offset = sizeof(cyxwiz_pos_proof_msg_t);
    memcpy(buf + offset, item->encrypted_data + block_offset, block_len);
    offset += block_len;

    /* Append proof path */
    for (uint8_t i = 0; i < depth; i++) {
        memcpy(buf + offset, path[i], CYXWIZ_POS_HASH_SIZE);
        offset += CYXWIZ_POS_HASH_SIZE;
    }

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, offset, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, surb, buf, CYXWIZ_PADDED_SIZE);
}

/* ============ Proof of Storage - Message Handlers ============ */

static cyxwiz_error_t handle_pos_commitment(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_pos_commitment_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_commitment_msg_t *msg = (const cyxwiz_pos_commitment_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find the storage operation */
    cyxwiz_storage_op_t *op = find_operation(ctx, &storage_id);
    if (op == NULL || op->op_type != CYXWIZ_STORAGE_OP_STORE) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Find the provider slot */
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, from, sizeof(cyxwiz_node_id_t)) == 0) {
            /* Store the commitment */
            memcpy(op->pos_commitments[i].merkle_root, msg->merkle_root, CYXWIZ_POS_HASH_SIZE);
            op->pos_commitments[i].num_blocks = msg->num_blocks;
            memcpy(&op->pos_commitments[i].storage_id, &storage_id, sizeof(cyxwiz_storage_id_t));
            op->pos_commitments_received++;

            char id_hex[17];
            cyxwiz_storage_id_to_hex(&storage_id, id_hex);
            CYXWIZ_DEBUG("Received PoS commitment for %s from provider %zu (%u blocks)",
                         id_hex, i, msg->num_blocks);
            break;
        }
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_pos_challenge(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_pos_challenge_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_challenge_msg_t *msg = (const cyxwiz_pos_challenge_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_DEBUG("PoS challenge for unknown item: %s", id_hex);
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Validate block index */
    size_t num_blocks = (item->encrypted_len + CYXWIZ_POS_BLOCK_SIZE - 1) / CYXWIZ_POS_BLOCK_SIZE;
    if (msg->block_index >= num_blocks) {
        char id_hex[17];
        cyxwiz_storage_id_to_hex(&storage_id, id_hex);
        CYXWIZ_DEBUG("PoS challenge for invalid block %u (max %zu) in %s",
                     msg->block_index, num_blocks - 1, id_hex);
        return CYXWIZ_ERR_POS_INVALID_BLOCK;
    }

    /* Generate and send proof */
    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);
    CYXWIZ_DEBUG("Generating PoS proof for %s block %u", id_hex, msg->block_index);

    return send_pos_proof_msg(ctx, from, item, msg->block_index, msg->challenge_nonce);
}

static cyxwiz_error_t handle_pos_proof(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_pos_proof_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_proof_msg_t *msg = (const cyxwiz_pos_proof_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find the pending challenge */
    cyxwiz_pos_challenge_state_t *challenge = find_pos_challenge(ctx, &storage_id, from);
    if (challenge == NULL) {
        return CYXWIZ_ERR_POS_NO_COMMITMENT;
    }

    /* Verify nonce matches */
    if (memcmp(msg->challenge_nonce, challenge->challenge_nonce, CYXWIZ_POS_CHALLENGE_SIZE) != 0) {
        send_pos_verify_fail_msg(ctx, from, &storage_id, challenge->sequence,
                                  CYXWIZ_POS_FAIL_WRONG_NONCE);
        if (ctx->on_pos_result != NULL) {
            ctx->on_pos_result(ctx, &storage_id, from, false,
                               CYXWIZ_POS_FAIL_WRONG_NONCE, ctx->pos_result_user_data);
        }
        free_pos_challenge(ctx, challenge);
        return CYXWIZ_OK;
    }

    /* Extract block data and proof path */
    const uint8_t *block_data = data + sizeof(cyxwiz_pos_proof_msg_t);
    size_t remaining = len - sizeof(cyxwiz_pos_proof_msg_t);

    if (remaining < msg->block_len) {
        return CYXWIZ_ERR_INVALID;
    }

    const uint8_t *proof_path_data = block_data + msg->block_len;
    remaining -= msg->block_len;

    if (remaining < (size_t)msg->proof_depth * CYXWIZ_POS_HASH_SIZE) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Copy proof path */
    uint8_t path[CYXWIZ_POS_MAX_PROOF_DEPTH][CYXWIZ_POS_HASH_SIZE];
    for (uint8_t i = 0; i < msg->proof_depth; i++) {
        memcpy(path[i], proof_path_data + i * CYXWIZ_POS_HASH_SIZE, CYXWIZ_POS_HASH_SIZE);
    }

    /* Verify the proof */
    bool valid = merkle_verify_path(block_data, msg->block_len, msg->block_index,
                                    (const uint8_t (*)[CYXWIZ_POS_HASH_SIZE])path,
                                    msg->proof_depth, msg->sibling_positions,
                                    challenge->commitment.merkle_root);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    if (valid) {
        CYXWIZ_DEBUG("PoS proof verified for %s block %u", id_hex, msg->block_index);
        send_pos_verify_ok_msg(ctx, from, &storage_id, challenge->sequence);

        if (ctx->on_pos_result != NULL) {
            ctx->on_pos_result(ctx, &storage_id, from, true,
                               CYXWIZ_POS_FAIL_NONE, ctx->pos_result_user_data);
        }
    } else {
        CYXWIZ_WARN("PoS proof FAILED for %s block %u", id_hex, msg->block_index);
        send_pos_verify_fail_msg(ctx, from, &storage_id, challenge->sequence,
                                  CYXWIZ_POS_FAIL_INVALID_ROOT);

        if (ctx->on_pos_result != NULL) {
            ctx->on_pos_result(ctx, &storage_id, from, false,
                               CYXWIZ_POS_FAIL_INVALID_ROOT, ctx->pos_result_user_data);
        }
    }

    free_pos_challenge(ctx, challenge);
    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_pos_verify_ok(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_pos_verify_ok_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_verify_ok_msg_t *msg = (const cyxwiz_pos_verify_ok_msg_t *)data;

    char id_hex[17];
    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    CYXWIZ_DEBUG("PoS verified OK for %s (seq %u)", id_hex, msg->sequence);
    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_pos_verify_fail(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_pos_verify_fail_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_verify_fail_msg_t *msg = (const cyxwiz_pos_verify_fail_msg_t *)data;

    char id_hex[17];
    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    CYXWIZ_WARN("PoS verify FAILED for %s (seq %u, reason %u)",
                id_hex, msg->sequence, msg->reason);
    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_pos_request_commit(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (len < sizeof(cyxwiz_pos_request_commit_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_request_commit_msg_t *msg = (const cyxwiz_pos_request_commit_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Compute commitment if not already done */
    if (!item->has_pos_commitment) {
        cyxwiz_error_t err = cyxwiz_pos_compute_commitment(
            item->encrypted_data, item->encrypted_len,
            &item->id, &item->pos_commitment);
        if (err != CYXWIZ_OK) {
            return err;
        }
        item->has_pos_commitment = true;
    }

    /* Send commitment */
    return send_pos_commitment(ctx, from, &item->pos_commitment);
}

/* ============ Anonymous PoS - Message Handlers ============ */

static cyxwiz_error_t handle_pos_challenge_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_pos_challenge_anon_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_challenge_anon_msg_t *msg = (const cyxwiz_pos_challenge_anon_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        CYXWIZ_DEBUG("Anonymous PoS challenge for unknown item: %s", id_hex);
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Validate block index */
    size_t num_blocks = (item->encrypted_len + CYXWIZ_POS_BLOCK_SIZE - 1) / CYXWIZ_POS_BLOCK_SIZE;
    if (msg->block_index >= num_blocks) {
        CYXWIZ_DEBUG("Anonymous PoS challenge for invalid block %u (max %zu) in %s",
                     msg->block_index, num_blocks - 1, id_hex);
        return CYXWIZ_ERR_POS_INVALID_BLOCK;
    }

    /* Generate and send proof via SURB */
    CYXWIZ_DEBUG("Generating anonymous PoS proof for %s block %u", id_hex, msg->block_index);

    return send_pos_proof_via_surb(ctx, &msg->reply_surb, item,
                                    msg->block_index, msg->challenge_nonce);
}

static cyxwiz_error_t handle_pos_request_commit_anon(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_pos_request_commit_anon_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_request_commit_anon_msg_t *msg = (const cyxwiz_pos_request_commit_anon_msg_t *)data;

    cyxwiz_storage_id_t storage_id;
    memcpy(storage_id.bytes, msg->storage_id, CYXWIZ_STORAGE_ID_SIZE);

    char id_hex[17];
    cyxwiz_storage_id_to_hex(&storage_id, id_hex);

    /* Find stored item */
    cyxwiz_stored_item_t *item = find_stored_item(ctx, &storage_id);
    if (item == NULL) {
        CYXWIZ_DEBUG("Anonymous commitment request for unknown item: %s", id_hex);
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Compute commitment if not already done */
    if (!item->has_pos_commitment) {
        cyxwiz_error_t err = cyxwiz_pos_compute_commitment(
            item->encrypted_data, item->encrypted_len,
            &item->id, &item->pos_commitment);
        if (err != CYXWIZ_OK) {
            return err;
        }
        item->has_pos_commitment = true;
    }

    CYXWIZ_DEBUG("Sending anonymous PoS commitment for %s", id_hex);

    /* Send commitment via SURB */
    return send_pos_commitment_via_surb(ctx, &msg->reply_surb, &item->pos_commitment);
}

/* ============ Proof of Storage - Public API ============ */

void cyxwiz_pos_set_result_callback(
    cyxwiz_storage_ctx_t *ctx,
    cyxwiz_pos_result_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->on_pos_result = callback;
    ctx->pos_result_user_data = user_data;
}

cyxwiz_error_t cyxwiz_pos_compute_commitment(
    const uint8_t *data,
    size_t data_len,
    const cyxwiz_storage_id_t *storage_id,
    cyxwiz_pos_commitment_t *commitment)
{
    if (data == NULL || storage_id == NULL || commitment == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Build Merkle tree */
    uint8_t tree[CYXWIZ_POS_MAX_BLOCKS * 2][CYXWIZ_POS_HASH_SIZE];
    size_t num_leaves;
    merkle_build_tree(data, data_len, tree, &num_leaves);

    /* Root is at index 1 */
    memcpy(commitment->merkle_root, tree[1], CYXWIZ_POS_HASH_SIZE);

    /* Calculate number of actual blocks */
    size_t num_blocks = (data_len + CYXWIZ_POS_BLOCK_SIZE - 1) / CYXWIZ_POS_BLOCK_SIZE;
    if (num_blocks == 0) num_blocks = 1;
    if (num_blocks > 255) num_blocks = 255;
    commitment->num_blocks = (uint8_t)num_blocks;

    memcpy(&commitment->storage_id, storage_id, sizeof(cyxwiz_storage_id_t));

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_pos_store_commitment(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id,
    const cyxwiz_pos_commitment_t *commitment)
{
    if (ctx == NULL || storage_id == NULL || provider_id == NULL || commitment == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find the storage operation */
    cyxwiz_storage_op_t *op = find_operation(ctx, storage_id);
    if (op == NULL) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Find the provider slot */
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, provider_id, sizeof(cyxwiz_node_id_t)) == 0) {
            memcpy(&op->pos_commitments[i], commitment, sizeof(cyxwiz_pos_commitment_t));
            op->pos_commitments_received++;
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_PEER_NOT_FOUND;
}

cyxwiz_error_t cyxwiz_pos_challenge(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id)
{
    if (ctx == NULL || storage_id == NULL || provider_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if challenge already pending */
    if (find_pos_challenge(ctx, storage_id, provider_id) != NULL) {
        return CYXWIZ_ERR_POS_CHALLENGE_PENDING;
    }

    /* Find the storage operation to get commitment */
    cyxwiz_storage_op_t *op = find_operation(ctx, storage_id);
    if (op == NULL) {
        return CYXWIZ_ERR_STORAGE_NOT_FOUND;
    }

    /* Find the provider's commitment */
    cyxwiz_pos_commitment_t *commitment = NULL;
    for (size_t i = 0; i < op->num_shares; i++) {
        if (memcmp(&op->providers[i].provider_id, provider_id, sizeof(cyxwiz_node_id_t)) == 0) {
            commitment = &op->pos_commitments[i];
            break;
        }
    }

    if (commitment == NULL || commitment->num_blocks == 0) {
        return CYXWIZ_ERR_POS_NO_COMMITMENT;
    }

    /* Allocate challenge state */
    cyxwiz_pos_challenge_state_t *challenge = alloc_pos_challenge(ctx);
    if (challenge == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize challenge */
    memcpy(&challenge->storage_id, storage_id, sizeof(cyxwiz_storage_id_t));
    memcpy(&challenge->provider_id, provider_id, sizeof(cyxwiz_node_id_t));
    memcpy(&challenge->commitment, commitment, sizeof(cyxwiz_pos_commitment_t));
    challenge->sent_at = get_time_ms();
    challenge->sequence = 0;

    /* Generate random nonce */
    cyxwiz_crypto_random(challenge->challenge_nonce, CYXWIZ_POS_CHALLENGE_SIZE);

    /* Pick random block to challenge */
    uint8_t random_byte;
    cyxwiz_crypto_random(&random_byte, 1);
    challenge->block_index = random_byte % commitment->num_blocks;

    /* Send challenge */
    cyxwiz_error_t err = send_pos_challenge_msg(ctx, provider_id, storage_id,
                                                 challenge->block_index,
                                                 challenge->challenge_nonce,
                                                 challenge->sequence);

    if (err != CYXWIZ_OK) {
        free_pos_challenge(ctx, challenge);
        return err;
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_DEBUG("Sent PoS challenge for %s block %u", id_hex, challenge->block_index);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_pos_generate_proof(
    const uint8_t *data,
    size_t data_len,
    uint8_t block_index,
    const uint8_t *challenge_nonce,
    uint8_t *proof_buf,
    size_t proof_buf_size,
    size_t *proof_len)
{
    if (data == NULL || proof_buf == NULL || proof_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Validate block index */
    size_t num_blocks = (data_len + CYXWIZ_POS_BLOCK_SIZE - 1) / CYXWIZ_POS_BLOCK_SIZE;
    if (num_blocks == 0) num_blocks = 1;
    if (block_index >= num_blocks) {
        return CYXWIZ_ERR_POS_INVALID_BLOCK;
    }

    /* Build Merkle tree */
    uint8_t tree[CYXWIZ_POS_MAX_BLOCKS * 2][CYXWIZ_POS_HASH_SIZE];
    size_t num_leaves;
    size_t tree_size = merkle_build_tree(data, data_len, tree, &num_leaves);

    /* Get proof path */
    uint8_t path[CYXWIZ_POS_MAX_PROOF_DEPTH][CYXWIZ_POS_HASH_SIZE];
    uint8_t depth, positions;
    merkle_get_proof((const uint8_t (*)[CYXWIZ_POS_HASH_SIZE])tree,
                     tree_size, num_leaves, block_index, path, &depth, &positions);

    /* Extract block data */
    size_t block_offset = (size_t)block_index * CYXWIZ_POS_BLOCK_SIZE;
    size_t block_len = data_len - block_offset;
    if (block_len > CYXWIZ_POS_BLOCK_SIZE) {
        block_len = CYXWIZ_POS_BLOCK_SIZE;
    }

    /* Calculate required size */
    size_t required = sizeof(cyxwiz_pos_proof_msg_t) + block_len + depth * CYXWIZ_POS_HASH_SIZE;
    if (proof_buf_size < required) {
        return CYXWIZ_ERR_BUFFER_TOO_SMALL;
    }

    /* Build proof message (without storage_id, which caller provides) */
    cyxwiz_pos_proof_msg_t *msg = (cyxwiz_pos_proof_msg_t *)proof_buf;
    msg->type = CYXWIZ_MSG_POS_PROOF;
    memset(msg->storage_id, 0, CYXWIZ_STORAGE_ID_SIZE); /* Caller fills in */
    msg->block_index = block_index;
    memcpy(msg->challenge_nonce, challenge_nonce, CYXWIZ_POS_CHALLENGE_SIZE);
    msg->block_len = (uint8_t)block_len;
    msg->proof_depth = depth;
    msg->sibling_positions = positions;

    /* Append block data */
    size_t offset = sizeof(cyxwiz_pos_proof_msg_t);
    memcpy(proof_buf + offset, data + block_offset, block_len);
    offset += block_len;

    /* Append proof path */
    for (uint8_t i = 0; i < depth; i++) {
        memcpy(proof_buf + offset, path[i], CYXWIZ_POS_HASH_SIZE);
        offset += CYXWIZ_POS_HASH_SIZE;
    }

    *proof_len = offset;
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_pos_verify_proof(
    const cyxwiz_pos_commitment_t *commitment,
    const uint8_t *proof_data,
    size_t proof_len,
    bool *valid_out,
    cyxwiz_pos_fail_reason_t *reason_out)
{
    if (commitment == NULL || proof_data == NULL || valid_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    *valid_out = false;
    if (reason_out != NULL) {
        *reason_out = CYXWIZ_POS_FAIL_INVALID_ROOT;
    }

    if (proof_len < sizeof(cyxwiz_pos_proof_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_pos_proof_msg_t *msg = (const cyxwiz_pos_proof_msg_t *)proof_data;

    /* Extract block data and proof path */
    const uint8_t *block_data = proof_data + sizeof(cyxwiz_pos_proof_msg_t);
    size_t remaining = proof_len - sizeof(cyxwiz_pos_proof_msg_t);

    if (remaining < msg->block_len) {
        return CYXWIZ_ERR_INVALID;
    }

    const uint8_t *proof_path_data = block_data + msg->block_len;
    remaining -= msg->block_len;

    if (remaining < (size_t)msg->proof_depth * CYXWIZ_POS_HASH_SIZE) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Copy proof path */
    uint8_t path[CYXWIZ_POS_MAX_PROOF_DEPTH][CYXWIZ_POS_HASH_SIZE];
    for (uint8_t i = 0; i < msg->proof_depth; i++) {
        memcpy(path[i], proof_path_data + i * CYXWIZ_POS_HASH_SIZE, CYXWIZ_POS_HASH_SIZE);
    }

    /* Verify the proof */
    *valid_out = merkle_verify_path(block_data, msg->block_len, msg->block_index,
                                    (const uint8_t (*)[CYXWIZ_POS_HASH_SIZE])path,
                                    msg->proof_depth, msg->sibling_positions,
                                    commitment->merkle_root);

    if (*valid_out && reason_out != NULL) {
        *reason_out = CYXWIZ_POS_FAIL_NONE;
    }

    return CYXWIZ_OK;
}

size_t cyxwiz_pos_challenge_count(const cyxwiz_storage_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->pos_challenge_count;
}

const char *cyxwiz_pos_fail_reason_name(cyxwiz_pos_fail_reason_t reason)
{
    switch (reason) {
        case CYXWIZ_POS_FAIL_INVALID_ROOT:  return "invalid_root";
        case CYXWIZ_POS_FAIL_INVALID_BLOCK: return "invalid_block";
        case CYXWIZ_POS_FAIL_INVALID_PATH:  return "invalid_path";
        case CYXWIZ_POS_FAIL_WRONG_NONCE:   return "wrong_nonce";
        case CYXWIZ_POS_FAIL_TIMEOUT:       return "timeout";
        case CYXWIZ_POS_FAIL_NOT_FOUND:     return "not_found";
        default:                            return "unknown";
    }
}

/* ============ Anonymous Proof of Storage - Public API ============ */

cyxwiz_error_t cyxwiz_pos_challenge_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id,
    const cyxwiz_pos_commitment_t *commitment)
{
    if (ctx == NULL || storage_id == NULL || provider_id == NULL || commitment == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if we can create SURBs */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Allocate challenge state */
    cyxwiz_pos_challenge_state_t *challenge = alloc_pos_challenge(ctx);
    if (challenge == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize challenge */
    memcpy(&challenge->storage_id, storage_id, sizeof(cyxwiz_storage_id_t));
    memcpy(&challenge->provider_id, provider_id, sizeof(cyxwiz_node_id_t));
    memcpy(&challenge->commitment, commitment, sizeof(cyxwiz_pos_commitment_t));
    challenge->sent_at = get_time_ms();
    challenge->sequence = 0;
    challenge->is_anonymous = true;

    /* Generate random nonce */
    cyxwiz_crypto_random(challenge->challenge_nonce, CYXWIZ_POS_CHALLENGE_SIZE);

    /* Pick random block to challenge */
    uint8_t random_byte;
    cyxwiz_crypto_random(&random_byte, 1);
    challenge->block_index = random_byte % commitment->num_blocks;

    /* Create SURB for proof response */
    cyxwiz_surb_t reply_surb;
    cyxwiz_error_t err = cyxwiz_router_create_surb(ctx->router, &reply_surb);
    if (err != CYXWIZ_OK) {
        free_pos_challenge(ctx, challenge);
        return err;
    }

    /* Send anonymous challenge */
    err = send_pos_challenge_anon_msg(ctx, provider_id, storage_id,
                                       challenge->block_index,
                                       challenge->challenge_nonce,
                                       &reply_surb);
    if (err != CYXWIZ_OK) {
        free_pos_challenge(ctx, challenge);
        return err;
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_DEBUG("Sent anonymous PoS challenge for %s block %u", id_hex, challenge->block_index);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_pos_request_commitment_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id)
{
    if (ctx == NULL || storage_id == NULL || provider_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if we can create SURBs */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Create SURB for commitment response */
    cyxwiz_surb_t reply_surb;
    cyxwiz_error_t err = cyxwiz_router_create_surb(ctx->router, &reply_surb);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Send anonymous commitment request */
    err = send_pos_request_commit_anon_msg(ctx, provider_id, storage_id, &reply_surb);
    if (err != CYXWIZ_OK) {
        return err;
    }

    char id_hex[17];
    cyxwiz_storage_id_to_hex(storage_id, id_hex);
    CYXWIZ_DEBUG("Sent anonymous PoS commitment request for %s", id_hex);

    return CYXWIZ_OK;
}
