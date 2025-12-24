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
#include "routing.h"

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

/* ============ Proof of Storage Constants ============ */

#define CYXWIZ_POS_BLOCK_SIZE 64            /* 64-byte blocks (fits LoRa) */
#define CYXWIZ_POS_MAX_BLOCKS 32            /* Max blocks (2KB data) */
#define CYXWIZ_POS_HASH_SIZE 32             /* BLAKE2b-256 output */
#define CYXWIZ_POS_MAX_PROOF_DEPTH 5        /* log2(32) = 5 */
#define CYXWIZ_POS_CHALLENGE_SIZE 8         /* Nonce size */
#define CYXWIZ_POS_CHALLENGE_TIMEOUT_MS 30000 /* 30 second timeout */
#define CYXWIZ_MAX_POS_CHALLENGES 8         /* Max concurrent challenges */

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

/* ============ Proof of Storage Types ============ */

/* PoS verification failure reasons */
typedef enum {
    CYXWIZ_POS_FAIL_INVALID_ROOT = 0x01,   /* Merkle root mismatch */
    CYXWIZ_POS_FAIL_INVALID_BLOCK = 0x02,  /* Block hash mismatch */
    CYXWIZ_POS_FAIL_INVALID_PATH = 0x03,   /* Merkle path invalid */
    CYXWIZ_POS_FAIL_WRONG_NONCE = 0x04,    /* Challenge nonce mismatch */
    CYXWIZ_POS_FAIL_TIMEOUT = 0x05,        /* Response too slow */
    CYXWIZ_POS_FAIL_NOT_FOUND = 0x06       /* Storage ID not found */
} cyxwiz_pos_fail_reason_t;

/* PoS commitment - Merkle root of data blocks */
typedef struct {
    uint8_t merkle_root[CYXWIZ_POS_HASH_SIZE];  /* 32 bytes */
    uint8_t num_blocks;                          /* Number of data blocks */
    cyxwiz_storage_id_t storage_id;              /* 8 bytes - reference */
} cyxwiz_pos_commitment_t;

/* PoS challenge state (owner-side tracking) */
typedef struct {
    cyxwiz_storage_id_t storage_id;              /* Which data */
    cyxwiz_node_id_t provider_id;                /* Which provider */
    cyxwiz_pos_commitment_t commitment;          /* Stored commitment */
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE]; /* Freshness nonce */
    uint8_t block_index;                         /* Challenged block */
    uint8_t sequence;                            /* Challenge sequence number */
    uint64_t sent_at;                            /* When challenge was sent */
    bool active;                                 /* Is this slot in use? */
} cyxwiz_pos_challenge_state_t;

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

    /* Anonymous storage support */
    bool is_anonymous;                    /* Is this an anonymous operation? */
    uint8_t delete_token[CYXWIZ_MAC_SIZE]; /* Token for anonymous deletion */
    cyxwiz_surb_t reply_surbs[CYXWIZ_MAX_STORAGE_PROVIDERS]; /* SURBs for provider replies */

    /* Proof of Storage - commitments received from providers */
    cyxwiz_pos_commitment_t pos_commitments[CYXWIZ_MAX_STORAGE_PROVIDERS];
    uint8_t pos_commitments_received;     /* Count of commitments received */
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

    /* Proof of Storage commitment */
    cyxwiz_pos_commitment_t pos_commitment;
    bool has_pos_commitment;              /* Was commitment computed? */

    /* Anonymous storage support */
    bool is_anonymous;                    /* Was this stored anonymously? */
    uint8_t delete_token[CYXWIZ_MAC_SIZE]; /* Token for anonymous deletion */

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

/* ============ Proof of Storage Messages ============ */

/* POS_COMMITMENT (0x50) - Provider -> Owner after successful storage */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_COMMITMENT */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
    uint8_t merkle_root[CYXWIZ_POS_HASH_SIZE];   /* 32 bytes */
    uint8_t num_blocks;                          /* Number of data blocks */
} cyxwiz_pos_commitment_msg_t;
/* Total: 42 bytes */

/* POS_CHALLENGE (0x51) - Owner -> Provider */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_CHALLENGE */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
    uint8_t block_index;                         /* Which block to prove */
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE]; /* 8 bytes freshness */
    uint8_t sequence;                            /* Challenge sequence number */
} cyxwiz_pos_challenge_msg_t;
/* Total: 19 bytes */

/* POS_PROOF (0x52) - Provider -> Owner
 * Variable length: header + block_data + proof_path
 * Max size: 21 + 64 + (5 * 32) = 245 bytes (fits LoRa MTU) */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_PROOF */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
    uint8_t block_index;                         /* Which block */
    uint8_t challenge_nonce[CYXWIZ_POS_CHALLENGE_SIZE]; /* 8 bytes - echo back */
    uint8_t block_len;                           /* Actual block length */
    uint8_t proof_depth;                         /* Number of proof path entries */
    uint8_t sibling_positions;                   /* Bitmap: 0=left, 1=right */
    /* Variable: uint8_t block_data[block_len] follows */
    /* Variable: uint8_t proof_path[proof_depth][32] follows */
} cyxwiz_pos_proof_msg_t;
/* Header: 21 bytes */

/* POS_VERIFY_OK (0x53) - Owner -> Provider */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_VERIFY_OK */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
    uint8_t sequence;                            /* Which challenge */
} cyxwiz_pos_verify_ok_msg_t;
/* Total: 10 bytes */

/* POS_VERIFY_FAIL (0x54) - Owner -> Provider */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_VERIFY_FAIL */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
    uint8_t sequence;                            /* Which challenge */
    uint8_t reason;                              /* cyxwiz_pos_fail_reason_t */
} cyxwiz_pos_verify_fail_msg_t;
/* Total: 11 bytes */

/* POS_REQUEST_COMMIT (0x55) - Owner -> Provider (retry) */
typedef struct {
    uint8_t type;                                /* CYXWIZ_MSG_POS_REQUEST_COMMIT */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE];  /* 8 bytes */
} cyxwiz_pos_request_commit_msg_t;
/* Total: 9 bytes */

/* ============ Anonymous Storage Messages ============ */

/* Anonymous store request (0x4B) - with SURB for reply */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_STORE_REQ_ANON */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE]; /* 8 bytes */
    uint8_t share_index;                  /* Which share (1-indexed) */
    uint8_t total_shares;                 /* N in K-of-N */
    uint8_t threshold;                    /* K in K-of-N */
    uint32_t ttl_seconds;                 /* TTL in seconds */
    uint8_t total_chunks;                 /* 0 = inline payload, >0 = chunked */
    uint16_t payload_len;                 /* Total encrypted payload length */
    uint8_t delete_token[CYXWIZ_MAC_SIZE]; /* 16 bytes - token for anonymous deletion */
    cyxwiz_surb_t reply_surb;             /* 120 bytes - anonymous reply path */
    /* cyxwiz_share_t share follows (49 bytes) */
    /* If total_chunks == 0, encrypted payload follows share */
} cyxwiz_store_req_anon_msg_t;

/* Anonymous retrieve request (0x4C) - with SURB for reply */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_RETRIEVE_REQ_ANON */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE]; /* 8 bytes */
    cyxwiz_surb_t reply_surb;             /* 120 bytes - anonymous reply path */
} cyxwiz_retrieve_req_anon_msg_t;

/* Anonymous delete request (0x4D) - with token and SURB */
typedef struct {
    uint8_t type;                         /* CYXWIZ_MSG_DELETE_REQ_ANON */
    uint8_t storage_id[CYXWIZ_STORAGE_ID_SIZE]; /* 8 bytes */
    uint8_t delete_token[CYXWIZ_MAC_SIZE]; /* 16 bytes - pre-shared token */
    cyxwiz_surb_t reply_surb;             /* 120 bytes - anonymous reply path */
} cyxwiz_delete_req_anon_msg_t;

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

/* ============ Anonymous Client Operations ============ */

/*
 * Check if anonymous storage operations are possible
 * Requires sufficient relay peers to create SURBs
 *
 * @param ctx  Storage context
 * @return     true if anonymous operations can be performed
 */
bool cyxwiz_storage_can_store_anonymous(const cyxwiz_storage_ctx_t *ctx);

/*
 * Store data anonymously across N providers
 *
 * Same as cyxwiz_storage_store() but uses SURBs for provider replies,
 * so providers cannot identify the data owner. A random delete_token
 * is generated and returned for later deletion.
 *
 * @param ctx             Storage context
 * @param providers       Array of N provider node IDs
 * @param num_providers   N - total providers
 * @param threshold       K - minimum shares needed to reconstruct
 * @param data            Data to store
 * @param data_len        Length of data
 * @param ttl_seconds     Time-to-live in seconds
 * @param storage_id_out  Output: generated storage ID
 * @param delete_token_out Output: 16-byte token for anonymous deletion
 * @return                CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_store_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_node_id_t *providers,
    size_t num_providers,
    uint8_t threshold,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds,
    cyxwiz_storage_id_t *storage_id_out,
    uint8_t *delete_token_out
);

/*
 * Retrieve data anonymously from providers
 *
 * Same as cyxwiz_storage_retrieve() but uses SURBs for provider replies.
 * Provider cannot identify who is requesting the data.
 *
 * @param ctx           Storage context
 * @param storage_id    ID of data to retrieve
 * @param providers     Array of provider node IDs
 * @param num_providers Number of providers
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_retrieve_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *providers,
    size_t num_providers
);

/*
 * Delete stored data anonymously using delete token
 *
 * Uses the delete_token from store_anonymous() to prove authorization
 * without revealing identity.
 *
 * @param ctx           Storage context
 * @param storage_id    ID of data to delete
 * @param delete_token  16-byte token from store_anonymous()
 * @param providers     Array of provider node IDs
 * @param num_providers Number of providers
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_storage_delete_anonymous(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const uint8_t *delete_token,
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

/* ============ Proof of Storage API ============ */

/*
 * Callback for PoS verification results
 *
 * @param ctx         Storage context
 * @param storage_id  Storage ID that was challenged
 * @param provider_id Provider that was challenged
 * @param valid       true if proof was valid, false otherwise
 * @param reason      If invalid, the failure reason
 * @param user_data   User-provided context
 */
typedef void (*cyxwiz_pos_result_cb_t)(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id,
    bool valid,
    cyxwiz_pos_fail_reason_t reason,
    void *user_data
);

/*
 * Set PoS result callback
 */
void cyxwiz_pos_set_result_callback(
    cyxwiz_storage_ctx_t *ctx,
    cyxwiz_pos_result_cb_t callback,
    void *user_data
);

/*
 * Compute Merkle commitment for data (provider-side)
 *
 * @param data        Encrypted data
 * @param data_len    Length of data
 * @param storage_id  Storage ID for reference
 * @param commitment  Output commitment structure
 * @return            CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pos_compute_commitment(
    const uint8_t *data,
    size_t data_len,
    const cyxwiz_storage_id_t *storage_id,
    cyxwiz_pos_commitment_t *commitment
);

/*
 * Store a commitment received from a provider (owner-side)
 *
 * @param ctx         Storage context
 * @param storage_id  Storage ID
 * @param provider_id Provider that sent commitment
 * @param commitment  The commitment to store
 * @return            CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pos_store_commitment(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id,
    const cyxwiz_pos_commitment_t *commitment
);

/*
 * Issue a PoS challenge to a provider (owner-side)
 *
 * @param ctx         Storage context
 * @param storage_id  Storage ID to challenge
 * @param provider_id Provider to challenge
 * @return            CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pos_challenge(
    cyxwiz_storage_ctx_t *ctx,
    const cyxwiz_storage_id_t *storage_id,
    const cyxwiz_node_id_t *provider_id
);

/*
 * Generate a proof for a challenged block (provider-side)
 *
 * @param data            Encrypted data
 * @param data_len        Length of data
 * @param block_index     Which block to prove
 * @param challenge_nonce The challenge nonce to echo
 * @param proof_buf       Output buffer for proof message
 * @param proof_buf_size  Size of output buffer
 * @param proof_len       Output: actual proof length
 * @return                CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pos_generate_proof(
    const uint8_t *data,
    size_t data_len,
    uint8_t block_index,
    const uint8_t *challenge_nonce,
    uint8_t *proof_buf,
    size_t proof_buf_size,
    size_t *proof_len
);

/*
 * Verify a proof received from a provider (owner-side)
 *
 * @param commitment      The stored commitment to verify against
 * @param proof_data      Raw proof message data
 * @param proof_len       Length of proof message
 * @param valid_out       Output: true if valid
 * @param reason_out      Output: failure reason if invalid
 * @return                CYXWIZ_OK on success (even if proof is invalid)
 */
cyxwiz_error_t cyxwiz_pos_verify_proof(
    const cyxwiz_pos_commitment_t *commitment,
    const uint8_t *proof_data,
    size_t proof_len,
    bool *valid_out,
    cyxwiz_pos_fail_reason_t *reason_out
);

/*
 * Get number of active PoS challenges
 */
size_t cyxwiz_pos_challenge_count(const cyxwiz_storage_ctx_t *ctx);

/*
 * Get human-readable PoS failure reason name
 */
const char *cyxwiz_pos_fail_reason_name(cyxwiz_pos_fail_reason_t reason);

#endif /* CYXWIZ_STORAGE_H */
