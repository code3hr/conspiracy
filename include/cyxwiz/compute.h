/*
 * CyxWiz Protocol - Compute Layer
 *
 * Implements a job marketplace for distributed computation:
 * - Job submission to worker nodes
 * - Job execution with configurable handlers
 * - Result delivery with MAC-based verification
 * - Chunking for large payloads (> 64 bytes)
 */

#ifndef CYXWIZ_COMPUTE_H
#define CYXWIZ_COMPUTE_H

#include "types.h"
#include "routing.h"
#include "peer.h"
#include "crypto.h"

/* ============ Constants ============ */

/* Job ID size (compact for LoRa packets) */
#define CYXWIZ_JOB_ID_SIZE 8

/* Payload limits */
#define CYXWIZ_JOB_MAX_PAYLOAD 64       /* Max single-packet payload */
#define CYXWIZ_JOB_MAX_CHUNKS 16        /* Max chunks per job */
#define CYXWIZ_JOB_CHUNK_SIZE 48        /* Payload per chunk */
#define CYXWIZ_JOB_MAX_TOTAL_PAYLOAD (CYXWIZ_JOB_MAX_CHUNKS * CYXWIZ_JOB_CHUNK_SIZE)

/* Anonymous job limits (SURB adds 120 bytes overhead) */
#define CYXWIZ_JOB_ANON_HEADER_SIZE 132 /* 12 base + 120 SURB */
#define CYXWIZ_JOB_ANON_MAX_PAYLOAD (CYXWIZ_MAX_PACKET_SIZE - CYXWIZ_JOB_ANON_HEADER_SIZE)

/* Capacity limits */
#define CYXWIZ_MAX_ACTIVE_JOBS 16       /* Max concurrent jobs tracked */
#define CYXWIZ_DEFAULT_WORKER_CAPACITY 4 /* Default concurrent jobs for worker */

/* Timeouts */
#define CYXWIZ_JOB_TIMEOUT_MS 30000     /* 30 second job timeout */
#define CYXWIZ_JOB_CHUNK_TIMEOUT_MS 5000 /* 5 second chunk timeout */

/* ============ Types ============ */

/* Job ID */
typedef struct {
    uint8_t bytes[CYXWIZ_JOB_ID_SIZE];
} cyxwiz_job_id_t;

/* Job states */
typedef enum {
    CYXWIZ_JOB_STATE_PENDING = 0,       /* Submitted, waiting for worker */
    CYXWIZ_JOB_STATE_ASSIGNED,          /* Assigned to worker, awaiting accept */
    CYXWIZ_JOB_STATE_RUNNING,           /* Worker executing */
    CYXWIZ_JOB_STATE_COMPLETED,         /* Completed successfully */
    CYXWIZ_JOB_STATE_FAILED,            /* Execution failed */
    CYXWIZ_JOB_STATE_TIMEOUT            /* Worker did not respond */
} cyxwiz_job_state_t;

/* Job types (extensible) */
typedef enum {
    CYXWIZ_JOB_TYPE_HASH = 0x01,        /* Compute BLAKE2b hash */
    CYXWIZ_JOB_TYPE_ENCRYPT = 0x02,     /* Encrypt data */
    CYXWIZ_JOB_TYPE_DECRYPT = 0x03,     /* Decrypt data */
    CYXWIZ_JOB_TYPE_VERIFY = 0x04,      /* Verify signature/MAC */
    CYXWIZ_JOB_TYPE_CUSTOM = 0xFF       /* Custom job (handler decides) */
} cyxwiz_job_type_t;

/* Rejection reasons */
typedef enum {
    CYXWIZ_REJECT_BUSY = 0x01,          /* Worker at capacity */
    CYXWIZ_REJECT_UNSUPPORTED = 0x02,   /* Job type not supported */
    CYXWIZ_REJECT_INVALID = 0x03,       /* Invalid job format */
    CYXWIZ_REJECT_TIMEOUT = 0x04        /* Chunk assembly timed out */
} cyxwiz_reject_reason_t;

/*
 * Job entry - tracked by submitter and worker
 */
typedef struct {
    cyxwiz_job_id_t id;                 /* Unique job identifier */
    cyxwiz_job_type_t type;             /* Type of computation */
    cyxwiz_job_state_t state;           /* Current state */
    cyxwiz_node_id_t worker;            /* Assigned worker (if any) */

    /* Submitter identity (anonymous or direct) */
    bool is_anonymous;                  /* True if anonymous submission */
    union {
        cyxwiz_node_id_t direct_id;     /* Direct submitter ID */
        cyxwiz_surb_t reply_surb;       /* Anonymous reply path (SURB) */
    } submitter;

    /* Payload (assembled from chunks if needed) */
    uint8_t payload[CYXWIZ_JOB_MAX_TOTAL_PAYLOAD];
    size_t payload_len;                 /* Total payload length */
    uint8_t total_chunks;               /* Number of chunks (0 = single packet) */
    uint8_t received_chunks;            /* Chunks received so far */
    uint16_t chunk_bitmap;              /* Which chunks received (bitmask) */

    /* Result */
    uint8_t result[CYXWIZ_JOB_MAX_PAYLOAD];
    size_t result_len;
    uint8_t result_mac[CYXWIZ_MAC_SIZE]; /* MAC for result verification */

    /* Timing */
    uint64_t submitted_at;
    uint64_t started_at;
    uint64_t completed_at;

    /* Flags */
    bool is_submitter;                  /* Are we the submitter or worker? */
    bool mac_valid;                     /* Was result MAC valid? */
    bool valid;                         /* Is this slot in use? */
} cyxwiz_job_t;

/* ============ Message Structures ============ */

#pragma pack(push, 1)

/*
 * Job submit message (0x30)
 * Total: 12 + payload bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_SUBMIT */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t job_type;                   /* cyxwiz_job_type_t */
    uint8_t total_chunks;               /* 0 = payload in this packet */
    uint8_t payload_len;                /* Length of inline payload */
    /* uint8_t payload[] follows if total_chunks == 0 */
} cyxwiz_job_submit_msg_t;

/*
 * Anonymous job submit message (0x3B)
 * Includes SURB for anonymous reply - worker cannot identify submitter
 * Total: 132 + payload bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_SUBMIT_ANON */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t job_type;                   /* cyxwiz_job_type_t */
    uint8_t total_chunks;               /* 0 = payload in this packet */
    uint8_t payload_len;                /* Length of inline payload */
    cyxwiz_surb_t reply_surb;           /* 120 bytes - anonymous reply path */
    /* uint8_t payload[] follows if total_chunks == 0 */
} cyxwiz_job_submit_anon_msg_t;

/*
 * Job chunk message (0x31)
 * Total: 11 + chunk_len bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_CHUNK */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t chunk_index;                /* 0-indexed chunk number */
    uint8_t chunk_len;                  /* Bytes in this chunk */
    /* uint8_t data[chunk_len] follows */
} cyxwiz_job_chunk_msg_t;

/*
 * Job accept message (0x32)
 * Total: 9 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_ACCEPT */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
} cyxwiz_job_accept_msg_t;

/*
 * Job reject message (0x33)
 * Total: 10 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_REJECT */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t reason;                     /* cyxwiz_reject_reason_t */
} cyxwiz_job_reject_msg_t;

/*
 * Job status message (0x34)
 * Total: 10 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_STATUS */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t state;                      /* cyxwiz_job_state_t */
} cyxwiz_job_status_msg_t;

/*
 * Job result message (0x35)
 * Total: 27 + result_len bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_RESULT */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t state;                      /* COMPLETED or FAILED */
    uint8_t total_chunks;               /* 0 = result in this packet */
    uint8_t result_len;                 /* Length of inline result */
    uint8_t mac[CYXWIZ_MAC_SIZE];       /* 16 bytes - MAC over job_id || result */
    /* uint8_t result[] follows if total_chunks == 0 */
} cyxwiz_job_result_msg_t;

/*
 * Job result chunk (0x36)
 * Same structure as job chunk
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_RESULT_CHUNK */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
    uint8_t chunk_index;
    uint8_t chunk_len;
    /* uint8_t data[chunk_len] follows */
} cyxwiz_job_result_chunk_msg_t;

/*
 * Job acknowledge (0x37)
 * Total: 9 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_ACK */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
} cyxwiz_job_ack_msg_t;

/*
 * Job cancel (0x38)
 * Total: 9 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_CANCEL */
    uint8_t job_id[CYXWIZ_JOB_ID_SIZE]; /* 8 bytes */
} cyxwiz_job_cancel_msg_t;

/*
 * Worker query (0x39) - broadcast to find workers
 * Total: 2 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_QUERY */
    uint8_t job_types;                  /* Bitmask of needed job types */
} cyxwiz_job_query_msg_t;

/*
 * Worker announce (0x3A) - response to query
 * Total: 5 bytes
 */
typedef struct {
    uint8_t type;                       /* CYXWIZ_MSG_JOB_ANNOUNCE */
    uint8_t job_types;                  /* Bitmask of supported types */
    uint8_t capacity;                   /* Available job slots */
    uint16_t avg_latency_ms;            /* Recent average execution time */
} cyxwiz_job_announce_msg_t;

#pragma pack(pop)

/* ============ Opaque Context ============ */

typedef struct cyxwiz_compute_ctx cyxwiz_compute_ctx_t;

/* ============ Callbacks ============ */

/*
 * Completion callback - called when a submitted job completes
 *
 * @param ctx           Compute context
 * @param job           Job that completed
 * @param result        Result data (may be NULL if failed)
 * @param result_len    Length of result
 * @param mac_valid     Was the result MAC valid?
 * @param user_data     User-provided context
 */
typedef void (*cyxwiz_job_complete_cb_t)(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_t *job,
    const uint8_t *result,
    size_t result_len,
    bool mac_valid,
    void *user_data
);

/*
 * Execution callback - called when worker receives a job to execute
 *
 * @param ctx           Compute context
 * @param job           Job to execute
 * @param result_out    Buffer to write result (CYXWIZ_JOB_MAX_PAYLOAD bytes)
 * @param result_len    Output: length of result written
 * @param user_data     User-provided context
 * @return              CYXWIZ_OK on success, error code on failure
 */
typedef cyxwiz_error_t (*cyxwiz_job_execute_cb_t)(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_t *job,
    uint8_t *result_out,
    size_t *result_len,
    void *user_data
);

/* ============ Context Lifecycle ============ */

/*
 * Create a compute context
 *
 * @param ctx           Output context pointer
 * @param router        Router for sending messages
 * @param peer_table    Peer table for worker discovery
 * @param crypto_ctx    Crypto context for MAC computation
 * @param local_id      This node's ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_create(
    cyxwiz_compute_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_crypto_ctx_t *crypto_ctx,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy a compute context
 */
void cyxwiz_compute_destroy(cyxwiz_compute_ctx_t *ctx);

/*
 * Enable worker mode (accept and execute jobs)
 *
 * @param ctx               Compute context
 * @param max_concurrent    Maximum concurrent jobs to accept
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_enable_worker(
    cyxwiz_compute_ctx_t *ctx,
    size_t max_concurrent
);

/*
 * Disable worker mode
 */
void cyxwiz_compute_disable_worker(cyxwiz_compute_ctx_t *ctx);

/*
 * Check if worker mode is enabled
 */
bool cyxwiz_compute_is_worker(const cyxwiz_compute_ctx_t *ctx);

/*
 * Poll for events (call in main loop)
 * Handles timeouts, retransmissions, etc.
 *
 * @param ctx           Compute context
 * @param now_ms        Current time in milliseconds
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_poll(
    cyxwiz_compute_ctx_t *ctx,
    uint64_t now_ms
);

/* ============ Callbacks ============ */

/*
 * Set completion callback (for submitters)
 */
void cyxwiz_compute_set_complete_callback(
    cyxwiz_compute_ctx_t *ctx,
    cyxwiz_job_complete_cb_t callback,
    void *user_data
);

/*
 * Set execution callback (for workers)
 */
void cyxwiz_compute_set_execute_callback(
    cyxwiz_compute_ctx_t *ctx,
    cyxwiz_job_execute_cb_t callback,
    void *user_data
);

/* ============ Job Submission ============ */

/*
 * Submit a job to a specific worker
 *
 * @param ctx           Compute context
 * @param worker        Worker node ID
 * @param type          Job type
 * @param payload       Job payload data
 * @param payload_len   Length of payload
 * @param job_id_out    Output: assigned job ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_submit(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *worker,
    cyxwiz_job_type_t type,
    const uint8_t *payload,
    size_t payload_len,
    cyxwiz_job_id_t *job_id_out
);

/*
 * Submit a job anonymously - worker cannot identify submitter
 * Uses SURB (Single-Use Reply Block) for anonymous result delivery.
 * Maximum payload is CYXWIZ_JOB_ANON_MAX_PAYLOAD (118 bytes).
 *
 * @param ctx           Compute context
 * @param worker        Worker node ID
 * @param type          Job type
 * @param payload       Job payload data
 * @param payload_len   Length of payload (max 118 bytes)
 * @param job_id_out    Output: assigned job ID
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_PACKET_TOO_LARGE if payload exceeds anonymous limit
 *                      CYXWIZ_ERR_INSUFFICIENT_RELAYS if not enough peers for SURB
 */
cyxwiz_error_t cyxwiz_compute_submit_anonymous(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *worker,
    cyxwiz_job_type_t type,
    const uint8_t *payload,
    size_t payload_len,
    cyxwiz_job_id_t *job_id_out
);

/*
 * Check if context supports anonymous job submission
 * Requires at least CYXWIZ_SURB_HOPS relay peers for SURB creation.
 *
 * @param ctx           Compute context
 * @return              true if anonymous submission is possible
 */
bool cyxwiz_compute_can_submit_anonymous(const cyxwiz_compute_ctx_t *ctx);

/*
 * Cancel a pending or running job
 *
 * @param ctx           Compute context
 * @param job_id        Job to cancel
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_cancel(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id
);

/*
 * Get job by ID
 *
 * @param ctx           Compute context
 * @param job_id        Job ID to find
 * @return              Job pointer, or NULL if not found
 */
const cyxwiz_job_t *cyxwiz_compute_get_job(
    const cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id
);

/*
 * Get count of active jobs
 */
size_t cyxwiz_compute_job_count(const cyxwiz_compute_ctx_t *ctx);

/* ============ Message Handling ============ */

/*
 * Handle incoming compute message
 * Called by router/transport when message type is 0x30-0x3F
 *
 * @param ctx           Compute context
 * @param from          Sender node ID
 * @param data          Message data
 * @param len           Message length
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_handle_message(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ MAC Verification ============ */

/*
 * Compute MAC for result verification
 * MAC is computed over: job_id || result
 *
 * @param ctx           Compute context
 * @param job_id        Job ID
 * @param result        Result data
 * @param result_len    Result length
 * @param mac_out       Output MAC (CYXWIZ_MAC_SIZE bytes)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_compute_result_mac(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id,
    const uint8_t *result,
    size_t result_len,
    uint8_t *mac_out
);

/*
 * Verify result MAC
 *
 * @param ctx           Compute context
 * @param job_id        Job ID
 * @param result        Result data
 * @param result_len    Result length
 * @param mac           MAC to verify
 * @return              CYXWIZ_OK if valid, CYXWIZ_ERR_MAC_INVALID if not
 */
cyxwiz_error_t cyxwiz_compute_verify_result(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id,
    const uint8_t *result,
    size_t result_len,
    const uint8_t *mac
);

/* ============ Utilities ============ */

/*
 * Get job state name
 */
const char *cyxwiz_job_state_name(cyxwiz_job_state_t state);

/*
 * Get job type name
 */
const char *cyxwiz_job_type_name(cyxwiz_job_type_t type);

/*
 * Compare two job IDs
 * @return 0 if equal, non-zero otherwise
 */
int cyxwiz_job_id_compare(
    const cyxwiz_job_id_t *a,
    const cyxwiz_job_id_t *b
);

/*
 * Convert job ID to hex string
 * @param id        Job ID
 * @param hex_out   Output buffer (must be at least 17 bytes)
 */
void cyxwiz_job_id_to_hex(
    const cyxwiz_job_id_t *id,
    char *hex_out
);

#endif /* CYXWIZ_COMPUTE_H */
