/*
 * CyxWiz Protocol - CyxCloud Distributed Storage
 *
 * Distributed storage protocol using K-of-N threshold secret sharing.
 * Data is encrypted with a random key, the key is split using Shamir's
 * Secret Sharing, and each share + encrypted data is distributed to
 * N storage providers. Retrieval requires K providers to reconstruct.
 */

#ifndef CYXWIZ_STORAGE_H
#define CYXWIZ_STORAGE_H

#include "types.h"
#include "crypto.h"

/* Forward declarations */
typedef struct cyxwiz_storage_ctx cyxwiz_storage_ctx_t;
typedef struct cyxwiz_router cyxwiz_router_t;
typedef struct cyxwiz_peer_table cyxwiz_peer_table_t;

/* ============ Constants ============ */

#define CYXWIZ_STORAGE_ID_SIZE 8           /* Storage operation identifier */
#define CYXWIZ_MAX_STORAGE_PROVIDERS 8     /* Max N for K-of-N */
#define CYXWIZ_MAX_ACTIVE_STORAGE_OPS 16   /* Max concurrent operations */
#define CYXWIZ_MAX_STORED_ITEMS 64         /* Max items per provider */
#define CYXWIZ_STORAGE_CHUNK_SIZE 128      /* Per-chunk payload */
#define CYXWIZ_STORAGE_MAX_CHUNKS 16       /* Max chunks = 2KB */
#define CYXWIZ_STORAGE_MAX_PAYLOAD (CYXWIZ_STORAGE_CHUNK_SIZE * CYXWIZ_STORAGE_MAX_CHUNKS)
#define CYXWIZ_STORAGE_OP_TIMEOUT_MS 60000 /* 60 second operation timeout */
#define CYXWIZ_STORAGE_DEFAULT_TTL_SEC 3600  /* 1 hour default TTL */
#define CYXWIZ_STORAGE_MAX_TTL_SEC 86400     /* 24 hour max TTL */

/* ============ Storage ID ============ */

typedef struct {
    uint8_t bytes[CYXWIZ_STORAGE_ID_SIZE];
} cyxwiz_storage_id_t;

/* ============ States and Enums ============ */

typedef enum {
    CYXWIZ_STORAGE_STATE_PENDING = 0,     /* Operation initiated */
    CYXWIZ_STORAGE_STATE_DISTRIBUTING,    /* Sending shares to providers */
    CYXWIZ_STORAGE_STATE_STORED,          /* All required confirmations received */
    CYXWIZ_STORAGE_STATE_RETRIEVING,      /* Fetching shares from providers */
    CYXWIZ_STORAGE_STATE_RETRIEVED,       /* Reconstruction complete */
    CYXWIZ_STORAGE_STATE_DELETING,        /* Deletion in progress */
    CYXWIZ_STORAGE_STATE_DELETED,         /* Deletion confirmed */
    CYXWIZ_STORAGE_STATE_FAILED,          /* Operation failed */
    CYXWIZ_STORAGE_STATE_EXPIRED          /* TTL expired (provider-side) */
} cyxwiz_storage_state_t;

typedef enum {
    CYXWIZ_STORAGE_OP_STORE = 0,
    CYXWIZ_STORAGE_OP_RETRIEVE,
    CYXWIZ_STORAGE_OP_DELETE
} cyxwiz_storage_op_type_t;

typedef enum {
    CYXWIZ_STORAGE_REJECT_FULL = 0x01,        /* Storage capacity full */
    CYXWIZ_STORAGE_REJECT_TTL_TOO_LONG = 0x02,/* Requested TTL exceeds max */
    CYXWIZ_STORAGE_REJECT_DISABLED = 0x03,    /* Provider mode disabled */
    CYXWIZ_STORAGE_REJECT_INVALID = 0x04,     /* Invalid request format */
    CYXWIZ_STORAGE_REJECT_DUPLICATE = 0x05    /* ID already exists */
} cyxwiz_storage_reject_reason_t;

/* ============ Provider Slot (tracks one provider in an operation) ============ */

typedef struct {
    cyxwiz_node_id_t provider_id;         /* Provider node ID */
    uint8_t share_index;                  /* Which share (1..N) */
    bool confirmed;                       /* Has provider ACKed? */
    bool retrieved;                       /* Has share been retrieved? */
    uint64_t sent_at;                     /* When request was sent */
} cyxwiz_provider_slot_t;

/* ============ Storage Operation (client-side) ============ */

typedef struct {
    cyxwiz_storage_id_t id;               /* Unique storage identifier */
    cyxwiz_storage_state_t state;         /* Current state */
    cyxwiz_storage_op_type_t op_type;     /* Store/Retrieve/Delete */
    cyxwiz_node_id_t owner;               /* Who owns this data */

    /* Original data (client-side, for store operations) */
    uint8_t *data;                        /* Original plaintext (heap allocated) */
    size_t data_len;                      /* Data length */

    /* Encryption key for content-addressed storage */
    uint8_t encryption_key[CYXWIZ_KEY_SIZE]; /* Random key, shared via Shamir */

    /* Encrypted data buffer (for retrieval) */
    uint8_t *encrypted_data;              /* Encrypted data (heap allocated) */
    size_t encrypted_len;                 /* Length of encrypted data */

    /* Threshold sharing parameters */
    uint8_t threshold;                    /* K - shares needed to reconstruct */
    uint8_t num_shares;                   /* N - total shares distributed */

    /* Provider tracking */
    cyxwiz_provider_slot_t providers[CYXWIZ_MAX_STORAGE_PROVIDERS];
    uint8_t providers_confirmed;          /* Count of confirmed providers */
    uint8_t providers_retrieved;          /* Count of retrieved shares */

    /* Retrieved shares for reconstruction */
    cyxwiz_share_t retrieved_shares[CYXWIZ_MAX_STORAGE_PROVIDERS];

    /* TTL */
    uint32_t ttl_seconds;                 /* Time-to-live in seconds */
    uint64_t expires_at;                  /* Absolute expiry timestamp */

    /* Timing */
    uint64_t created_at;
    uint64_t completed_at;

    /* Chunking for large encrypted payloads */
    uint8_t total_chunks;
    uint8_t received_chunks;
    uint16_t chunk_bitmap;

    /* Flags */
    bool is_owner;                        /* Are we the data owner? */
    bool valid;                           /* Is this slot in use? */
} cyxwiz_storage_op_t;

/* ============ Stored Item (provider-side) ============ */

typedef struct {
    cyxwiz_storage_id_t id;               /* Storage ID */
    cyxwiz_node_id_t owner;               /* Who owns this data */
    cyxwiz_share_t share;                 /* The Shamir share */
    uint8_t share_index;                  /* Which share index (1..N) */

    /* Encrypted payload */
    uint8_t *encrypted_data;              /* Heap allocated encrypted data */
    size_t encrypted_len;                 /* Length of encrypted data */

    /* Chunking state (for receiving) */
    uint8_t total_chunks;
    uint8_t received_chunks;
    uint16_t chunk_bitmap;

    /* TTL */
    uint64_t expires_at;                  /* Absolute expiry timestamp */
    uint64_t stored_at;                   /* When stored */

    bool valid;
} cyxwiz_stored_item_t;

/* ============ Message Structures ============ */

#pragma pack(push, 1)

/* Store request (0x40) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORE_REQ */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE]; /* 8 bytes */
    uint8_t share_index;                  /* Which share (1-indexed) */
    uint8_t total_shares;                 /* N in K-of-N */
    uint8_t threshold;                    /* K in K-of-N */
    uint32_t ttl_seconds;                 /* TTL in seconds */
    uint8_t total_chunks;                 /* 0 = inline payload, >0 = chunked */
    uint16_t payload_len;                 /* Total encrypted payload length */
    /* cyxwiz_share_t share follows (49 bytes) */
    /* If total_chunks == 0, encrypted payload follows share */
} cyxwiz_store_req_msg_t;

/* Store chunk (0x41) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORE_CHUNK */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t chunk_index;
    uint8_t chunk_len;
    /* uint8_t data[chunk_len] follows */
} cyxwiz_store_chunk_msg_t;

/* Store ACK (0x42) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORE_ACK */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t share_index;                  /* Which share was stored */
    uint64_t expires_at;                  /* When data will expire */
} cyxwiz_store_ack_msg_t;

/* Store Reject (0x43) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORE_REJECT */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t reason;                       /* cyxwiz_storage_reject_reason_t */
} cyxwiz_store_reject_msg_t;

/* Retrieve request (0x44) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_RETRIEVE_REQ */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
} cyxwiz_retrieve_req_msg_t;

/* Retrieve response (0x45) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_RETRIEVE_RESP */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t share_index;
    uint8_t total_chunks;                 /* 0 = inline payload */
    uint16_t payload_len;
    /* cyxwiz_share_t share follows (49 bytes) */
    /* If total_chunks == 0, encrypted payload follows share */
} cyxwiz_retrieve_resp_msg_t;

/* Retrieve chunk (0x46) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_RETRIEVE_CHUNK */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t chunk_index;
    uint8_t chunk_len;
    /* uint8_t data[chunk_len] follows */
} cyxwiz_retrieve_chunk_msg_t;

/* Delete request (0x47) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_DELETE_REQ */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
    uint8_t mac[CYXWIZ_MAC_SIZE];         /* MAC proving ownership */
} cyxwiz_delete_req_msg_t;

/* Delete ACK (0x48) */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_DELETE_ACK */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];
} cyxwiz_delete_ack_msg_t;

/* Storage query (0x49) - broadcast to find providers */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORAGE_QUERY */
    uint32_t min_bytes;                   /* Minimum storage needed */
    uint32_t min_ttl_seconds;             /* Minimum TTL support needed */
} cyxwiz_storage_query_msg_t;

/* Storage announce (0x4A) - response to query */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORAGE_ANNOUNCE */
    uint32_t available_bytes;             /* Available storage */
    uint32_t max_ttl_seconds;             /* Maximum TTL supported */
    uint8_t current_load;                 /* 0-100% load */
} cyxwiz_storage_announce_msg_t;

#pragma pack(pop)

/* ============ Callbacks ============ */

/*
 * Called when a storage operation completes (store, retrieve, or delete)
 *
 * @param ctx       Storage context
 * @param op        The completed operation
 * @param data      For retrieve: reconstructed plaintext (NULL if failed)
 * @param data_len  Length of data
 * @param user_data User-provided context
 */
typedef void (*cyxwiz_storage_complete_cb_t)(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_op_t *op,
    const uint8_t *data,
    size_t data_len,
    void *user_data
);

/* ============ Context Lifecycle ============ */

/*
 * Create a storage context
 *
 * @param ctx           Output context pointer
 * @param router        Router for sending messages
 * @param peer_table    Peer table for lookups
 * @param crypto_ctx    Crypto context for encryption/sharing
 * @param local_id      This node's ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_create(
    cyxwiz_storage_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_crypto_ctx_t *crypto_ctx,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy a storage context, securely zeroing all data
 */
void cyxwiz_storage_destroy(cyxwiz_storage_ctx_t *ctx);

/* ============ Provider Mode ============ */

/*
 * Enable storage provider mode
 *
 * @param ctx               Storage context
 * @param max_storage_bytes Maximum bytes to store
 * @param max_ttl_seconds   Maximum TTL to accept
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_enable_provider(
    cyxwiz_storage_ctx_t *ctx,
    size_t max_storage_bytes,
    uint32_t max_ttl_seconds
);

/*
 * Disable storage provider mode
 */
void cyxwiz_storage_disable_provider(cyxwiz_storage_ctx_t *ctx);

/*
 * Check if provider mode is enabled
 */
bool cyxwiz_storage_is_provider(const cyxwiz_storage_ctx_t *ctx);

/* ============ Client Operations ============ */

/*
 * Store data across N providers with K-of-N threshold
 *
 * The data is encrypted with a random key, then the key is split
 * using Shamir's Secret Sharing. Each provider receives one share
 * plus the encrypted data.
 *
 * @param ctx           Storage context
 * @param providers     Array of N provider node IDs
 * @param num_providers N - total providers (must be <= CYXWIZ_MAX_STORAGE_PROVIDERS)
 * @param threshold     K - minimum shares needed to reconstruct (must be <= N)
 * @param data          Data to store
 * @param data_len      Length of data (max CYXWIZ_STORAGE_MAX_PAYLOAD - CYXWIZ_CRYPTO_OVERHEAD)
 * @param ttl_seconds   Time-to-live in seconds
 * @param storage_id_out Output: generated storage ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_store(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *providers,
    size_t num_providers,
    uint8_t threshold,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    cyxwiz_storage_id_t *storage_id_out
);

/*
 * Retrieve data from providers
 *
 * Sends RETRIEVE_REQ to all providers and collects K shares
 * to reconstruct the encryption key, then decrypts the data.
 * Completion callback is invoked when done.
 *
 * @param ctx           Storage context
 * @param storage_id    ID of data to retrieve
 * @param providers     Array of provider node IDs
 * @param num_providers Number of providers (need at least threshold)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_retrieve(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *providers,
    size_t num_providers
);

/*
 * Delete stored data from all providers
 *
 * Sends DELETE_REQ with ownership MAC to each provider.
 *
 * @param ctx           Storage context
 * @param storage_id    ID of data to delete
 * @param providers     Array of provider node IDs
 * @param num_providers Number of providers
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_delete(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *providers,
    size_t num_providers
);

/* ============ Polling ============ */

/*
 * Poll for timeouts and TTL expiry
 * Should be called periodically from main loop
 *
 * @param ctx       Storage context
 * @param now_ms    Current time in milliseconds
 * @return          CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_poll(
    cyxwiz_storage_ctx_t *ctx,
    uint64_t now_ms
);

/* ============ Message Handling ============ */

/*
 * Handle incoming storage protocol message
 *
 * @param ctx       Storage context
 * @param from      Sender node ID
 * @param data      Message data
 * @param len       Message length
 * @return          CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_handle_message(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ Callbacks ============ */

/*
 * Set completion callback for storage operations
 */
void cyxwiz_storage_set_complete_callback(
    cyxwiz_storage_ctx_t *ctx,
    cyxwiz_storage_complete_cb_t callback,
    void *user_data
);

/* ============ Utilities ============ */

/*
 * Get operation by storage ID
 * Returns NULL if not found
 */
const cyxwiz_storage_op_t *cyxwiz_storage_get_operation(
    const cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id
);

/*
 * Get number of active operations
 */
size_t cyxwiz_storage_operation_count(const cyxwiz_storage_ctx_t *ctx);

/*
 * Get number of stored items (provider-side)
 */
size_t cyxwiz_storage_stored_count(const cyxwiz_storage_ctx_t *ctx);

/*
 * Get storage usage in bytes (provider-side)
 */
size_t cyxwiz_storage_used_bytes(const cyxwiz_storage_ctx_t *ctx);

/*
 * Get human-readable state name
 */
const char *cyxwiz_storage_state_name(cyxwiz_storage_state_t state);

/*
 * Get human-readable operation type name
 */
const char *cyxwiz_storage_op_type_name(cyxwiz_storage_op_type_t type);

/*
 * Compare two storage IDs
 * Returns 0 if equal, non-zero otherwise
 */
int cyxwiz_storage_id_compare(
    const cyxwiz_storage_id_t *a,
    const cyxwiz_storage_id_t *b
);

/*
 * Convert storage ID to hex string
 * hex_out must be at least 17 bytes (16 hex chars + null)
 */
void cyxwiz_storage_id_to_hex(
    const cyxwiz_storage_id_t *id,
    char *hex_out
);

/*
 * Generate a storage ID from data hash + random salt
 */
void cyxwiz_storage_id_generate(
    const uint8_t *data,
    size_t data_len,
    cyxwiz_storage_id_t *id_out
);

#endif /* CYXWIZ_STORAGE_H */
