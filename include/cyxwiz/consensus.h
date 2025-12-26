/*
 * CyxWiz Protocol - Proof of Useful Work Consensus
 *
 * Implements PoUW consensus where validators earn rights through:
 * - Executing compute jobs for the network
 * - Providing and proving storage availability
 * - Participating in validation committees
 *
 * Key features:
 * - Work credits earned by useful work (compute, storage)
 * - Committee selection weighted by work credits
 * - 2/3+1 Byzantine fault tolerance
 * - Schnorr proofs for validator identity and votes
 * - All messages fit 250-byte LoRa MTU
 */

#ifndef CYXWIZ_CONSENSUS_H
#define CYXWIZ_CONSENSUS_H

#include "types.h"
#include "zkp.h"
#include "privacy.h"

/* Forward declarations */
typedef struct cyxwiz_router cyxwiz_router_t;
typedef struct cyxwiz_peer_table cyxwiz_peer_table_t;
typedef struct cyxwiz_compute_ctx cyxwiz_compute_ctx_t;
typedef struct cyxwiz_storage_client cyxwiz_storage_client_t;

/* ============ Constants ============ */

#define CYXWIZ_CONSENSUS_ID_SIZE 8           /* Consensus round identifier */
#define CYXWIZ_MAX_VALIDATORS 32             /* Max validators in committee */
#define CYXWIZ_MIN_COMMITTEE_SIZE 2          /* Min validators for quorum (5 for production) */
#define CYXWIZ_QUORUM_THRESHOLD 67           /* 2/3 + 1 for BFT (percentage) */
#define CYXWIZ_MAX_ACTIVE_VALIDATIONS 16     /* Concurrent validations */
#define CYXWIZ_WORK_CREDIT_DECAY_MS 3600000  /* Credits decay over 1 hour */
#define CYXWIZ_VALIDATION_TIMEOUT_MS 30000   /* 30 second validation round */
#define CYXWIZ_SLASHING_THRESHOLD 3          /* Failed validations before slash */
#define CYXWIZ_VALIDATOR_HEARTBEAT_MS 30000  /* Heartbeat interval */

/* Work credit values */
#define CYXWIZ_CREDIT_COMPUTE_JOB 10         /* Credits per compute job */
#define CYXWIZ_CREDIT_STORAGE_PROOF 5        /* Credits per PoS challenge */
#define CYXWIZ_CREDIT_VALIDATION 2           /* Credits for participating */
#define CYXWIZ_CREDIT_CORRECT_VOTE 3         /* Bonus for correct vote */

/* ============ Consensus Types ============ */

/* Validator states */
typedef enum {
    CYXWIZ_VALIDATOR_INACTIVE = 0,           /* Not registered */
    CYXWIZ_VALIDATOR_PENDING,                /* Registration pending */
    CYXWIZ_VALIDATOR_ACTIVE,                 /* Active validator */
    CYXWIZ_VALIDATOR_SLASHED                 /* Slashed for misbehavior */
} cyxwiz_validator_state_t;

/* Validation result */
typedef enum {
    CYXWIZ_VALIDATION_PENDING = 0,
    CYXWIZ_VALIDATION_VALID,                 /* Consensus: valid */
    CYXWIZ_VALIDATION_INVALID,               /* Consensus: invalid */
    CYXWIZ_VALIDATION_INCONCLUSIVE,          /* No quorum reached */
    CYXWIZ_VALIDATION_TIMEOUT                /* Timed out */
} cyxwiz_validation_result_t;

/* Validation target type */
typedef enum {
    CYXWIZ_VALIDATE_JOB_RESULT = 0x01,       /* Verify compute job result */
    CYXWIZ_VALIDATE_STORAGE_PROOF = 0x02     /* Verify storage provider */
} cyxwiz_validation_type_t;

/* Slashing reasons */
typedef enum {
    CYXWIZ_SLASH_FALSE_POSITIVE = 0x01,      /* Approved invalid work */
    CYXWIZ_SLASH_FALSE_NEGATIVE = 0x02,      /* Rejected valid work */
    CYXWIZ_SLASH_OFFLINE = 0x03,             /* Failed to participate */
    CYXWIZ_SLASH_EQUIVOCATION = 0x04         /* Conflicting votes */
} cyxwiz_slash_reason_t;

/* Work type for credit reporting */
typedef enum {
    CYXWIZ_WORK_COMPUTE = 0x01,              /* Completed compute job */
    CYXWIZ_WORK_STORAGE = 0x02,              /* Passed PoS challenge */
    CYXWIZ_WORK_VALIDATION = 0x03            /* Participated in validation */
} cyxwiz_work_type_t;

/* ============ Validator Entry ============ */

typedef struct {
    cyxwiz_node_id_t node_id;                /* Validator's node ID */
    uint8_t ed25519_pubkey[CYXWIZ_ED25519_PK_SIZE]; /* Identity key */
    cyxwiz_validator_state_t state;          /* Current state */

    /* Work credits (accumulated useful work) */
    uint32_t work_credits;                   /* Current credit balance */
    uint64_t credits_updated_at;             /* Last update timestamp */

    /* Statistics */
    uint32_t jobs_validated;                 /* Jobs executed */
    uint32_t storage_proofs_passed;          /* PoS challenges passed */
    uint32_t validations_participated;       /* Committee participations */
    uint32_t validations_correct;            /* Correct votes */

    /* Slashing */
    uint8_t consecutive_failures;            /* Failed validations in a row */
    uint64_t slashed_at;                     /* When slashed (0 if not) */

    /* Registration */
    uint64_t registered_at;                  /* Registration timestamp */
    bool identity_verified;                  /* Schnorr proof valid */
} cyxwiz_validator_t;

/* ============ Consensus Round ============ */

typedef struct {
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* Unique round ID */
    cyxwiz_validation_type_t type;           /* What we're validating */
    cyxwiz_validation_result_t result;       /* Final result */

    /* Target identification */
    union {
        struct {
            uint8_t job_id[8];               /* Job being validated */
            uint8_t result_hash[32];         /* Hash of claimed result */
            uint8_t result_mac[16];          /* MAC from worker */
        } job;
        struct {
            uint8_t storage_id[8];           /* Storage being validated */
            cyxwiz_node_id_t provider_id;    /* Provider node */
            uint8_t challenged_block;        /* Block index */
        } storage;
    } target;

    /* Committee */
    cyxwiz_node_id_t committee[CYXWIZ_MAX_VALIDATORS];
    uint8_t committee_size;

    /* Votes (bitmap for efficiency) */
    uint32_t votes_valid;                    /* Bitmap: voted valid */
    uint32_t votes_invalid;                  /* Bitmap: voted invalid */
    uint8_t vote_count;                      /* Total votes received */

    /* Anonymous votes (from privacy protocol) */
    uint8_t anon_votes_valid;                /* Anonymous valid votes */
    uint8_t anon_votes_invalid;              /* Anonymous invalid votes */
    bool allows_anonymous;                   /* Whether round accepts anon votes */

    /* Timing */
    uint64_t started_at;
    uint64_t completed_at;

    bool active;
} cyxwiz_consensus_round_t;

/* ============ Message Structures (0x60-0x6B) ============ */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/*
 * Validator Registration Request (0x60)
 * Total: 130 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATOR_REGISTER */
    cyxwiz_node_id_t node_id;                /* 32 bytes */
    uint8_t ed25519_pubkey[CYXWIZ_ED25519_PK_SIZE]; /* 32 bytes */
    cyxwiz_schnorr_proof_t identity_proof;   /* 64 bytes */
    uint8_t capabilities;                    /* CYXWIZ_PEER_CAP_* flags */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validator_register_msg_t;

/*
 * Validator Registration ACK (0x61)
 * Total: 42 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATOR_REG_ACK */
    cyxwiz_node_id_t node_id;                /* Registered validator */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* Registration round */
    uint8_t result;                          /* cyxwiz_validation_result_t */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validator_reg_ack_msg_t;

/*
 * Work Credit Report (0x62)
 * Total: 60 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_WORK_CREDIT */
    cyxwiz_node_id_t validator_id;           /* 32 bytes */
    uint8_t work_type;                       /* cyxwiz_work_type_t */
    uint8_t work_id[8];                      /* Job ID or Storage ID */
    uint16_t credits_earned;                 /* Credits claimed */
    uint8_t proof_hash[16];                  /* Truncated hash of work proof */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_work_credit_msg_t;

/*
 * Validation Request (0x63)
 * Total: 82 bytes max
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATION_REQ */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* 8 bytes */
    uint8_t validation_type;                 /* cyxwiz_validation_type_t */
    uint8_t target_data[64];                 /* Type-specific target info */
    uint8_t committee_seed[8];               /* For deterministic selection */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validation_req_msg_t;

/*
 * Validation Vote (0x64)
 * Total: 106 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATION_VOTE */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* 8 bytes */
    cyxwiz_node_id_t validator_id;           /* Who's voting (32 bytes) */
    uint8_t vote;                            /* 0=invalid, 1=valid */
    cyxwiz_schnorr_proof_t vote_proof;       /* 64 bytes - proves vote ownership */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validation_vote_msg_t;

/*
 * Validation Result (0x65)
 * Total: 51 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATION_RESULT */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* 8 bytes */
    uint8_t result;                          /* cyxwiz_validation_result_t */
    uint8_t votes_valid;                     /* Count of valid votes */
    uint8_t votes_invalid;                   /* Count of invalid votes */
    uint8_t result_hash[32];                 /* Hash of verified result */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validation_result_msg_t;

/*
 * Job Validation Challenge (0x66)
 * Total: 79 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_JOB_VALIDATE_REQ */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* 8 bytes */
    uint8_t job_id[8];                       /* 8 bytes */
    uint8_t job_type;                        /* cyxwiz_job_type_t */
    uint8_t payload_len;                     /* Payload length */
    uint8_t payload[48];                     /* Job payload for re-execution */
    uint8_t claimed_result_hash[16];         /* Truncated hash of claimed result */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_job_validate_req_msg_t;

/*
 * Storage Validation Challenge (0x67)
 * Total: 52 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_STORAGE_VALIDATE_REQ */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* 8 bytes */
    uint8_t storage_id[8];                   /* 8 bytes */
    cyxwiz_node_id_t provider_id;            /* 32 bytes */
    uint8_t challenge_nonce[8];              /* Shared nonce */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_storage_validate_req_msg_t;

/*
 * Slashing Report (0x68)
 * Total: 108 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_SLASH_REPORT */
    cyxwiz_node_id_t offender_id;            /* 32 bytes - who misbehaved */
    cyxwiz_node_id_t reporter_id;            /* 32 bytes - who's reporting */
    uint8_t reason;                          /* cyxwiz_slash_reason_t */
    uint8_t round_id[CYXWIZ_CONSENSUS_ID_SIZE]; /* Evidence round */
    uint8_t evidence_hash[32];               /* Hash of evidence */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_slash_report_msg_t;

/*
 * Credit Query (0x69)
 * Total: 33 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_CREDIT_QUERY */
    cyxwiz_node_id_t validator_id;           /* 32 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_credit_query_msg_t;

/*
 * Credit Response (0x6A)
 * Total: 45 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_CREDIT_RESPONSE */
    cyxwiz_node_id_t validator_id;           /* 32 bytes */
    uint32_t current_credits;                /* 4 bytes */
    uint32_t total_earned;                   /* Lifetime earnings */
    uint32_t total_slashed;                  /* Lifetime slashings */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_credit_response_msg_t;

/*
 * Validator Heartbeat (0x6B)
 * Total: 38 bytes
 */
typedef struct {
    uint8_t type;                            /* CYXWIZ_MSG_VALIDATOR_HEARTBEAT */
    cyxwiz_node_id_t validator_id;           /* 32 bytes */
    uint16_t current_credits;                /* Truncated credit balance */
    uint8_t pending_validations;             /* Current workload */
    uint8_t capabilities;                    /* Updated capabilities */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_validator_heartbeat_msg_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Callbacks ============ */

/*
 * Called when validation round completes
 */
typedef void (*cyxwiz_validation_complete_cb_t)(
    const cyxwiz_consensus_round_t *round,
    cyxwiz_validation_result_t result,
    void *user_data
);

/*
 * Called when work credits change
 */
typedef void (*cyxwiz_credits_change_cb_t)(
    const cyxwiz_node_id_t *validator_id,
    uint32_t old_credits,
    uint32_t new_credits,
    void *user_data
);

/*
 * Called when validator state changes
 */
typedef void (*cyxwiz_validator_state_cb_t)(
    const cyxwiz_validator_t *validator,
    cyxwiz_validator_state_t old_state,
    void *user_data
);

/* ============ Consensus Context ============ */

typedef struct cyxwiz_consensus_ctx cyxwiz_consensus_ctx_t;

/* ============ Lifecycle ============ */

/*
 * Create consensus context
 */
cyxwiz_error_t cyxwiz_consensus_create(
    cyxwiz_consensus_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    const cyxwiz_identity_keypair_t *identity
);

/*
 * Destroy consensus context
 */
void cyxwiz_consensus_destroy(cyxwiz_consensus_ctx_t *ctx);

/*
 * Poll for events (call periodically)
 */
cyxwiz_error_t cyxwiz_consensus_poll(
    cyxwiz_consensus_ctx_t *ctx,
    uint64_t now_ms
);

/* ============ Validator Registration ============ */

/*
 * Register as validator
 * Broadcasts registration with identity proof
 */
cyxwiz_error_t cyxwiz_consensus_register_validator(
    cyxwiz_consensus_ctx_t *ctx
);

/*
 * Check if we're registered
 */
bool cyxwiz_consensus_is_registered(const cyxwiz_consensus_ctx_t *ctx);

/*
 * Get our validator state
 */
cyxwiz_validator_state_t cyxwiz_consensus_get_state(
    const cyxwiz_consensus_ctx_t *ctx
);

/* ============ Work Credits ============ */

/*
 * Report completed work
 */
cyxwiz_error_t cyxwiz_consensus_report_work(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_work_type_t work_type,
    const uint8_t *work_id,
    uint16_t credits_earned
);

/*
 * Get current work credit balance
 */
uint32_t cyxwiz_consensus_get_credits(const cyxwiz_consensus_ctx_t *ctx);

/*
 * Get validator by ID
 */
const cyxwiz_validator_t *cyxwiz_consensus_get_validator(
    const cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *node_id
);

/* ============ Validation ============ */

/*
 * Request validation of job result
 */
cyxwiz_error_t cyxwiz_consensus_validate_job(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *job_id,
    const uint8_t *result,
    size_t result_len,
    const uint8_t *result_mac
);

/*
 * Request validation of storage provider
 */
cyxwiz_error_t cyxwiz_consensus_validate_storage(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *storage_id,
    const cyxwiz_node_id_t *provider_id
);

/*
 * Cast vote in validation round (called by committee members)
 */
cyxwiz_error_t cyxwiz_consensus_vote(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id,
    bool valid
);

/*
 * Cast anonymous vote using privacy protocol
 *
 * Votes without revealing validator identity. Requires valid
 * validator credential obtained through anonymous credential system.
 * The vote is sent via onion routing for maximum unlinkability.
 *
 * @param ctx               Consensus context
 * @param round_id          Round identifier (8 bytes)
 * @param valid             Vote (true = valid, false = invalid)
 * @param validator_cred    Validator's anonymous credential
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR if not registered
 *                          CYXWIZ_ERR_CREDENTIAL_INVALID if credential invalid
 */
cyxwiz_error_t cyxwiz_consensus_vote_anonymous(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id,
    bool valid,
    const cyxwiz_credential_t *validator_cred
);

/*
 * Check if round allows anonymous voting
 *
 * Some rounds may require identified voting for accountability.
 *
 * @param ctx               Consensus context
 * @param round_id          Round identifier
 * @return                  true if anonymous voting allowed
 */
bool cyxwiz_consensus_round_allows_anonymous(
    const cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id
);

/* ============ Committee Selection ============ */

/*
 * Select committee for validation round
 * Uses VRF-like deterministic selection weighted by credits
 */
cyxwiz_error_t cyxwiz_consensus_select_committee(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *seed,
    cyxwiz_node_id_t *committee_out,
    uint8_t *committee_size_out
);

/*
 * Check if we're in the committee for a round
 */
bool cyxwiz_consensus_in_committee(
    const cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id
);

/* ============ Callbacks ============ */

void cyxwiz_consensus_set_validation_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_validation_complete_cb_t callback,
    void *user_data
);

void cyxwiz_consensus_set_credits_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_credits_change_cb_t callback,
    void *user_data
);

void cyxwiz_consensus_set_state_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_validator_state_cb_t callback,
    void *user_data
);

/* ============ Message Handling ============ */

/*
 * Handle incoming consensus message (0x60-0x6F)
 */
cyxwiz_error_t cyxwiz_consensus_handle_message(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ Statistics ============ */

size_t cyxwiz_consensus_validator_count(const cyxwiz_consensus_ctx_t *ctx);
size_t cyxwiz_consensus_active_rounds(const cyxwiz_consensus_ctx_t *ctx);

/* ============ Utilities ============ */

const char *cyxwiz_validator_state_name(cyxwiz_validator_state_t state);
const char *cyxwiz_validation_result_name(cyxwiz_validation_result_t result);
const char *cyxwiz_slash_reason_name(cyxwiz_slash_reason_t reason);

#endif /* CYXWIZ_CONSENSUS_H */
