/*
 * CyxWiz Protocol - Privacy Primitives
 *
 * Implements:
 * - Pedersen commitments with Ed25519 second generator
 * - Compact range proofs for 16-bit values
 * - Anonymous credentials with blind signatures
 * - Service tokens and reputation proofs
 */

#ifndef CYXWIZ_PRIVACY_H
#define CYXWIZ_PRIVACY_H

#include "types.h"
#include "zkp.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Pedersen commitment constants */
#define CYXWIZ_PEDERSEN_POINT_SIZE     32   /* Compressed Ed25519 point */
#define CYXWIZ_PEDERSEN_SCALAR_SIZE    32   /* Ed25519 scalar */
#define CYXWIZ_PEDERSEN_BLINDING_SIZE  32   /* Blinding factor */

/* Range proof constants */
#define CYXWIZ_RANGE_BITS_16           16   /* 16-bit range [0, 65535] */
#define CYXWIZ_RANGE_PROOF_16_SIZE     96   /* Compact 16-bit range proof */

/* Credential constants */
#define CYXWIZ_CRED_SIGNATURE_SIZE     64   /* Schnorr-based signature */
#define CYXWIZ_CRED_ATTRIBUTE_SIZE     32   /* BLAKE2b hash of attribute */
#define CYXWIZ_CRED_NONCE_SIZE         16   /* Issuance nonce */
#define CYXWIZ_CRED_BLINDING_SIZE      32   /* Blinding factor for blind sig */
#define CYXWIZ_CRED_SHOW_PROOF_SIZE    112  /* Credential show proof */
#define CYXWIZ_CRED_CONTEXT_SIZE       16   /* Context tag for showing */

/* Service token constants */
#define CYXWIZ_TOKEN_SERIAL_SIZE       32   /* Unique token serial */

/* Message ID sizes */
#define CYXWIZ_COMMIT_ID_SIZE          8    /* Commitment identifier */
#define CYXWIZ_PROOF_ID_SIZE           8    /* Proof identifier */

/* ============================================================================
 * Pedersen Commitments
 * ============================================================================ */

/*
 * Pedersen commitment
 *
 * C = v*G + r*H where:
 *   v = value being committed
 *   r = random blinding factor
 *   G = Ed25519 base point
 *   H = second generator (hash_to_curve)
 *
 * Properties:
 *   - Perfectly hiding (C reveals nothing about v)
 *   - Computationally binding (cannot open to different value)
 *   - Additively homomorphic: C(v1) + C(v2) = C(v1 + v2)
 */
typedef struct {
    uint8_t point[CYXWIZ_PEDERSEN_POINT_SIZE];
} cyxwiz_pedersen_commitment_t;

/*
 * Pedersen opening (reveals value and blinding)
 */
typedef struct {
    uint8_t value[CYXWIZ_PEDERSEN_SCALAR_SIZE];     /* Committed value */
    uint8_t blinding[CYXWIZ_PEDERSEN_BLINDING_SIZE]; /* Blinding factor r */
} cyxwiz_pedersen_opening_t;

/* ============================================================================
 * Range Proofs
 * ============================================================================ */

/*
 * Compact 16-bit range proof
 *
 * Proves that committed value is in [0, 2^16 - 1] without revealing value.
 * Uses binary decomposition with aggregated OR-proofs.
 */
typedef struct {
    uint8_t commitment[CYXWIZ_PEDERSEN_POINT_SIZE]; /* Pedersen commitment */
    uint8_t proof[CYXWIZ_RANGE_PROOF_16_SIZE];      /* Aggregated proof */
} cyxwiz_range_proof_16_t;

/* ============================================================================
 * Anonymous Credentials
 * ============================================================================ */

/*
 * Credential types
 */
typedef enum {
    CYXWIZ_CRED_VALIDATOR = 0x01,      /* Validator membership */
    CYXWIZ_CRED_SERVICE_ACCESS = 0x02, /* Service access rights */
    CYXWIZ_CRED_REPUTATION = 0x03,     /* Reputation level */
    CYXWIZ_CRED_VOTE_ELIGIBLE = 0x04   /* Vote eligibility */
} cyxwiz_credential_type_t;

/*
 * Blinded credential request
 *
 * User blinds their attribute before sending to issuer.
 * Issuer signs without seeing the actual attribute.
 */
typedef struct {
    uint8_t blinded_msg[CYXWIZ_PEDERSEN_SCALAR_SIZE]; /* Blinded attribute hash */
    uint8_t nonce[CYXWIZ_CRED_NONCE_SIZE];            /* Request nonce */
    uint8_t cred_type;                                 /* Credential type */
} cyxwiz_cred_request_t;

/*
 * Issued credential (unblinded by recipient)
 */
typedef struct {
    uint8_t signature[CYXWIZ_CRED_SIGNATURE_SIZE];    /* Schnorr signature */
    uint8_t issuer_pubkey[CYXWIZ_ED25519_PK_SIZE];    /* Issuer's public key */
    uint8_t attribute_hash[CYXWIZ_CRED_ATTRIBUTE_SIZE]; /* Hash of attribute */
    uint8_t cred_type;                                 /* Credential type */
    uint64_t issued_at;                                /* Issuance timestamp */
    uint64_t expires_at;                               /* Expiration timestamp */
} cyxwiz_credential_t;

/*
 * Credential show proof (unlinkable presentation)
 *
 * Proves possession of valid credential without revealing identity.
 * Each showing is unlinkable to other showings of same credential.
 */
typedef struct {
    uint8_t commitment[CYXWIZ_PEDERSEN_POINT_SIZE];   /* Commitment to credential */
    uint8_t response[CYXWIZ_PEDERSEN_SCALAR_SIZE];    /* Schnorr response */
    uint8_t challenge[CYXWIZ_PEDERSEN_SCALAR_SIZE];   /* Fiat-Shamir challenge */
    uint8_t context_tag[CYXWIZ_CRED_CONTEXT_SIZE];    /* Application context */
} cyxwiz_cred_show_proof_t;

/* ============================================================================
 * Service Tokens
 * ============================================================================ */

/*
 * Service token types
 */
typedef enum {
    CYXWIZ_TOKEN_COMPUTE = 0x01,    /* Compute job access */
    CYXWIZ_TOKEN_STORAGE = 0x02,    /* Storage access */
    CYXWIZ_TOKEN_BANDWIDTH = 0x03   /* Network bandwidth */
} cyxwiz_service_token_type_t;

/*
 * Service access token
 *
 * Unlinkable token that grants access to services.
 * Obtained via blind signature, spent anonymously.
 */
typedef struct {
    uint8_t serial[CYXWIZ_TOKEN_SERIAL_SIZE];         /* Unique token serial */
    uint8_t signature[CYXWIZ_CRED_SIGNATURE_SIZE];    /* Blind signature */
    uint8_t issuer_pubkey[CYXWIZ_ED25519_PK_SIZE];    /* Issuer public key */
    uint8_t token_type;                                /* Token type */
    uint16_t units;                                    /* Service units */
    uint64_t expires_at;                               /* Expiration */
} cyxwiz_service_token_t;

/* ============================================================================
 * Message Structures (all ≤ 250 bytes for LoRa compatibility)
 * ============================================================================ */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/* PEDERSEN_COMMIT (0x70) - Announce commitment - 121 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t commit_id[CYXWIZ_COMMIT_ID_SIZE];         /* 8 bytes */
    cyxwiz_pedersen_commitment_t commitment;           /* 32 bytes */
    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE];        /* 16 bytes */
    cyxwiz_schnorr_proof_t auth_proof;                /* 64 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_pedersen_commit_msg_t;

/* PEDERSEN_OPEN (0x71) - Reveal commitment - 73 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t commit_id[CYXWIZ_COMMIT_ID_SIZE];         /* 8 bytes */
    cyxwiz_pedersen_opening_t opening;                 /* 64 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_pedersen_open_msg_t;

/* RANGE_PROOF (0x72) - Range proof - 148 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t proof_id[CYXWIZ_PROOF_ID_SIZE];           /* 8 bytes */
    uint8_t range_bits;                                /* 1 byte */
    uint16_t min_value;                                /* 2 bytes */
    cyxwiz_range_proof_16_t range_proof;              /* 128 bytes */
    uint8_t context[CYXWIZ_COMMIT_ID_SIZE];           /* 8 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_range_proof_msg_t;

/* CRED_ISSUE_REQ (0x73) - Request credential - 114 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    cyxwiz_cred_request_t request;                    /* 49 bytes */
    cyxwiz_schnorr_proof_t identity_proof;            /* 64 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_cred_issue_req_msg_t;

/* CRED_ISSUE_RESP (0x74) - Credential response - 121 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t nonce[CYXWIZ_CRED_NONCE_SIZE];            /* 16 bytes */
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];  /* 64 bytes */
    uint8_t issuer_pubkey[CYXWIZ_ED25519_PK_SIZE];    /* 32 bytes */
    uint64_t expires_at;                               /* 8 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_cred_issue_resp_msg_t;

/* CRED_SHOW (0x75) - Present credential - 130 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t cred_type;                                 /* 1 byte */
    cyxwiz_cred_show_proof_t proof;                   /* 112 bytes */
    uint8_t service_context[CYXWIZ_CRED_CONTEXT_SIZE]; /* 16 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_cred_show_msg_t;

/* CRED_VERIFY (0x76) - Verification result - 50 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t cred_type;                                 /* 1 byte */
    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE];        /* 16 bytes */
    uint8_t result;                                    /* 1 byte (0=fail, 1=ok) */
    uint8_t issuer_pubkey[CYXWIZ_ED25519_PK_SIZE];    /* 32 bytes - optional */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_cred_verify_msg_t;

/* ANON_VOTE (0x77) - Anonymous vote - 186 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t round_id[CYXWIZ_COMMIT_ID_SIZE];          /* 8 bytes */
    uint8_t vote;                                      /* 1 byte */
    cyxwiz_cred_show_proof_t cred_proof;              /* 112 bytes */
    uint8_t vote_commitment[CYXWIZ_PEDERSEN_POINT_SIZE]; /* 32 bytes */
    uint8_t vote_proof[CYXWIZ_PEDERSEN_SCALAR_SIZE];  /* 32 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_anon_vote_msg_t;

/* SERVICE_TOKEN_REQ (0x78) - Request token - 100 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t token_type;                                /* 1 byte */
    uint8_t blinded_serial[CYXWIZ_TOKEN_SERIAL_SIZE]; /* 32 bytes */
    uint16_t units_requested;                          /* 2 bytes */
    cyxwiz_schnorr_proof_t payment_proof;             /* 64 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_service_token_req_msg_t;

/* SERVICE_TOKEN (0x79) - Issue token - 108 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t token_type;                                /* 1 byte */
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];  /* 64 bytes */
    uint16_t units_granted;                            /* 2 bytes */
    uint8_t issuer_pubkey[CYXWIZ_ED25519_PK_SIZE];    /* 32 bytes */
    uint64_t expires_at;                               /* 8 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_service_token_msg_t;

/* SERVICE_TOKEN_USE (0x7A) - Use token - 148 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t token_type;                                /* 1 byte */
    uint8_t serial_commitment[CYXWIZ_PEDERSEN_POINT_SIZE]; /* 32 bytes */
    uint8_t token_proof[CYXWIZ_RANGE_PROOF_16_SIZE];  /* 96 bytes */
    uint16_t units_to_use;                             /* 2 bytes */
    uint8_t request_nonce[CYXWIZ_CRED_CONTEXT_SIZE];  /* 16 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_service_token_use_msg_t;

/* REPUTATION_PROOF (0x7B) - Prove reputation - 211 bytes */
typedef struct {
    uint8_t type;                                      /* 1 byte */
    uint8_t context[CYXWIZ_COMMIT_ID_SIZE];           /* 8 bytes */
    uint16_t min_credits_claimed;                      /* 2 bytes */
    cyxwiz_range_proof_16_t range_proof;              /* 128 bytes */
    uint8_t timestamp[CYXWIZ_COMMIT_ID_SIZE];         /* 8 bytes */
    cyxwiz_schnorr_proof_t freshness_proof;           /* 64 bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_reputation_proof_msg_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============================================================================
 * Pedersen Commitment API
 * ============================================================================ */

/*
 * Initialize Pedersen parameters
 *
 * Computes second generator H using hash-to-curve.
 * Must be called before using Pedersen functions.
 *
 * @return          CYXWIZ_OK on success
 *                  CYXWIZ_ERR_NOT_INITIALIZED if crypto not initialized
 */
cyxwiz_error_t cyxwiz_pedersen_init(void);

/*
 * Create Pedersen commitment
 *
 * C = v*G + r*H where r is randomly generated.
 *
 * @param value         32-byte value to commit (scalar)
 * @param commit_out    Output commitment
 * @param opening_out   Output opening (value + blinding)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pedersen_commit(
    const uint8_t *value,
    cyxwiz_pedersen_commitment_t *commit_out,
    cyxwiz_pedersen_opening_t *opening_out);

/*
 * Create Pedersen commitment for uint64 value
 *
 * @param value         Value to commit
 * @param commit_out    Output commitment
 * @param opening_out   Output opening
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pedersen_commit_u64(
    uint64_t value,
    cyxwiz_pedersen_commitment_t *commit_out,
    cyxwiz_pedersen_opening_t *opening_out);

/*
 * Verify Pedersen commitment opening
 *
 * Checks: C == v*G + r*H
 *
 * @param commitment    Commitment to verify
 * @param opening       Opening (value + blinding)
 * @return              CYXWIZ_OK if valid
 *                      CYXWIZ_ERR_COMMITMENT_INVALID if invalid
 */
cyxwiz_error_t cyxwiz_pedersen_verify(
    const cyxwiz_pedersen_commitment_t *commitment,
    const cyxwiz_pedersen_opening_t *opening);

/*
 * Add two Pedersen commitments
 *
 * C3 = C1 + C2 (homomorphic addition)
 *
 * @param c1            First commitment
 * @param c2            Second commitment
 * @param result        Output commitment (c1 + c2)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pedersen_add(
    const cyxwiz_pedersen_commitment_t *c1,
    const cyxwiz_pedersen_commitment_t *c2,
    cyxwiz_pedersen_commitment_t *result);

/*
 * Subtract two Pedersen commitments
 *
 * C3 = C1 - C2
 *
 * @param c1            First commitment
 * @param c2            Second commitment
 * @param result        Output commitment (c1 - c2)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_pedersen_sub(
    const cyxwiz_pedersen_commitment_t *c1,
    const cyxwiz_pedersen_commitment_t *c2,
    cyxwiz_pedersen_commitment_t *result);

/* ============================================================================
 * Range Proof API
 * ============================================================================ */

/*
 * Create 16-bit range proof
 *
 * Proves value is in [0, 65535] without revealing value.
 *
 * @param value         Value to prove (0-65535)
 * @param proof_out     Output range proof
 * @param opening_out   Output opening (for later reveal if needed)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_INVALID if value > 65535
 */
cyxwiz_error_t cyxwiz_range_proof_create_16(
    uint16_t value,
    cyxwiz_range_proof_16_t *proof_out,
    cyxwiz_pedersen_opening_t *opening_out);

/*
 * Verify 16-bit range proof
 *
 * @param proof         Proof to verify
 * @return              CYXWIZ_OK if valid
 *                      CYXWIZ_ERR_RANGE_PROOF_FAILED if invalid
 */
cyxwiz_error_t cyxwiz_range_proof_verify_16(
    const cyxwiz_range_proof_16_t *proof);

/*
 * Create range proof for value >= min_threshold
 *
 * Proves value >= min without revealing actual value.
 *
 * @param value             Actual value
 * @param min_threshold     Minimum value to prove
 * @param proof_out         Output proof (proves value - min >= 0)
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_INVALID if value < min_threshold
 */
cyxwiz_error_t cyxwiz_range_proof_create_geq(
    uint16_t value,
    uint16_t min_threshold,
    cyxwiz_range_proof_16_t *proof_out);

/*
 * Verify range proof for value >= min_threshold
 *
 * @param proof             Proof to verify
 * @param min_threshold     Claimed minimum value
 * @return                  CYXWIZ_OK if valid
 *                          CYXWIZ_ERR_RANGE_PROOF_FAILED if invalid
 */
cyxwiz_error_t cyxwiz_range_proof_verify_geq(
    const cyxwiz_range_proof_16_t *proof,
    uint16_t min_threshold);

/* ============================================================================
 * Anonymous Credential API
 * ============================================================================ */

/*
 * Create blinded credential request
 *
 * Blinds the attribute before sending to issuer.
 * Issuer signs without seeing the actual attribute value.
 *
 * @param cred_type         Type of credential
 * @param attribute         Attribute to credential (e.g., node ID)
 * @param attr_len          Attribute length
 * @param request_out       Output blinded request
 * @param blinding_out      Output blinding factor (keep secret, 32 bytes)
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_cred_request_create(
    cyxwiz_credential_type_t cred_type,
    const uint8_t *attribute,
    size_t attr_len,
    cyxwiz_cred_request_t *request_out,
    uint8_t *blinding_out);

/*
 * Issue credential (issuer side)
 *
 * Signs the blinded attribute. The signature can be unblinded
 * by the requester to obtain a valid credential.
 *
 * @param issuer_key        Issuer's identity keypair
 * @param request           Blinded credential request
 * @param expires_at        Expiration timestamp (0 = no expiration)
 * @param blinded_sig_out   Output blinded signature (64 bytes)
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_cred_issue(
    const cyxwiz_identity_keypair_t *issuer_key,
    const cyxwiz_cred_request_t *request,
    uint64_t expires_at,
    uint8_t *blinded_sig_out);

/*
 * Unblind issued credential (requester side)
 *
 * Removes blinding from signature to obtain valid credential.
 *
 * @param blinded_sig       Blinded signature from issuer
 * @param blinding          Blinding factor used in request
 * @param issuer_pubkey     Issuer's public key
 * @param attribute         Original attribute
 * @param attr_len          Attribute length
 * @param expires_at        Expiration from issuer
 * @param cred_out          Output unblinded credential
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_CREDENTIAL_INVALID if unblinding fails
 */
cyxwiz_error_t cyxwiz_cred_unblind(
    const uint8_t *blinded_sig,
    const uint8_t *blinding,
    const uint8_t *issuer_pubkey,
    const uint8_t *attribute,
    size_t attr_len,
    uint64_t expires_at,
    cyxwiz_credential_t *cred_out);

/*
 * Create credential show proof (unlinkable presentation)
 *
 * Proves possession of valid credential without revealing identity.
 * Each showing is unlinkable to other showings.
 *
 * @param credential        Valid credential
 * @param context           Application context (16 bytes, prevents replay)
 * @param proof_out         Output show proof
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_cred_show_create(
    const cyxwiz_credential_t *credential,
    const uint8_t *context,
    cyxwiz_cred_show_proof_t *proof_out);

/*
 * Verify credential show proof
 *
 * Verifies proof without learning the credential holder's identity.
 *
 * @param proof             Show proof to verify
 * @param expected_type     Expected credential type
 * @param issuer_pubkey     Expected issuer's public key
 * @param current_time      Current timestamp (for expiration check)
 * @return                  CYXWIZ_OK if valid
 *                          CYXWIZ_ERR_CREDENTIAL_EXPIRED if expired
 *                          CYXWIZ_ERR_CREDENTIAL_INVALID if invalid
 */
cyxwiz_error_t cyxwiz_cred_show_verify(
    const cyxwiz_cred_show_proof_t *proof,
    cyxwiz_credential_type_t expected_type,
    const uint8_t *issuer_pubkey,
    uint64_t current_time);

/* ============================================================================
 * Service Token API
 * ============================================================================ */

/*
 * Create service token request
 *
 * @param token_type        Type of token
 * @param units             Units of service requested
 * @param request_out       Output blinded request message
 * @param request_len_out   Output request length
 * @param blinding_out      Output blinding factor (32 bytes)
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_service_token_request(
    cyxwiz_service_token_type_t token_type,
    uint16_t units,
    uint8_t *request_out,
    size_t *request_len_out,
    uint8_t *blinding_out);

/*
 * Unblind service token response
 *
 * @param blinded_response  Response from token issuer
 * @param blinding          Blinding factor from request
 * @param issuer_pubkey     Issuer's public key
 * @param token_out         Output valid token
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_service_token_unblind(
    const uint8_t *blinded_response,
    const uint8_t *blinding,
    const uint8_t *issuer_pubkey,
    cyxwiz_service_token_t *token_out);

/*
 * Create token usage proof
 *
 * @param token             Token to use
 * @param units_to_use      Units to spend
 * @param context           Service context (16 bytes)
 * @param proof_out         Output usage proof message
 * @param proof_len_out     Output proof length
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_TOKEN_INSUFFICIENT if units > available
 */
cyxwiz_error_t cyxwiz_service_token_use(
    const cyxwiz_service_token_t *token,
    uint16_t units_to_use,
    const uint8_t *context,
    uint8_t *proof_out,
    size_t *proof_len_out);

/*
 * Verify service token usage
 *
 * @param proof             Usage proof
 * @param proof_len         Proof length
 * @param issuer_pubkey     Expected issuer's public key
 * @param current_time      Current timestamp
 * @return                  CYXWIZ_OK if valid
 *                          CYXWIZ_ERR_TOKEN_EXPIRED if expired
 */
cyxwiz_error_t cyxwiz_service_token_verify(
    const uint8_t *proof,
    size_t proof_len,
    const uint8_t *issuer_pubkey,
    uint64_t current_time);

/* ============================================================================
 * Reputation Proof API
 * ============================================================================ */

/*
 * Create reputation proof
 *
 * Proves work credits >= min_threshold without revealing actual amount.
 *
 * @param actual_credits    Actual credit balance
 * @param min_threshold     Minimum credits to prove
 * @param identity          Node identity (for freshness binding)
 * @param proof_out         Output reputation proof message
 * @param proof_len_out     Output proof length
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_INVALID if actual < min
 */
cyxwiz_error_t cyxwiz_reputation_proof_create(
    uint32_t actual_credits,
    uint16_t min_threshold,
    const cyxwiz_identity_keypair_t *identity,
    uint8_t *proof_out,
    size_t *proof_len_out);

/*
 * Verify reputation proof
 *
 * @param proof             Proof to verify
 * @param proof_len         Proof length
 * @param required_min      Required minimum credits
 * @param max_age_ms        Maximum proof age in milliseconds
 * @param current_time_ms   Current time in milliseconds
 * @return                  CYXWIZ_OK if valid
 *                          CYXWIZ_ERR_RANGE_PROOF_FAILED if invalid
 *                          CYXWIZ_ERR_TIMEOUT if too old
 */
cyxwiz_error_t cyxwiz_reputation_proof_verify(
    const uint8_t *proof,
    size_t proof_len,
    uint16_t required_min,
    uint64_t max_age_ms,
    uint64_t current_time_ms);

/* ============================================================================
 * Anonymous Voting API
 * ============================================================================ */

/*
 * Create anonymous vote message
 *
 * Vote in consensus without revealing validator identity.
 * Requires pre-obtained validator credential.
 *
 * @param validator_cred    Validator credential
 * @param round_id          Consensus round ID (8 bytes)
 * @param vote              Vote (true = valid, false = invalid)
 * @param msg_out           Output vote message buffer
 * @param msg_len_out       Output message length
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_privacy_vote_anonymous(
    const cyxwiz_credential_t *validator_cred,
    const uint8_t *round_id,
    bool vote,
    uint8_t *msg_out,
    size_t *msg_len_out);

/*
 * Verify anonymous vote
 *
 * @param msg               Vote message
 * @param msg_len           Message length
 * @param issuer_pubkey     Validator credential issuer's public key
 * @param current_time      Current timestamp
 * @param vote_out          Output vote value
 * @return                  CYXWIZ_OK if valid
 */
cyxwiz_error_t cyxwiz_privacy_verify_anon_vote(
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *issuer_pubkey,
    uint64_t current_time,
    bool *vote_out);

/* ============================================================================
 * Message Handling
 * ============================================================================ */

/*
 * Handle incoming privacy protocol message
 *
 * @param from              Sender's node ID
 * @param data              Message data
 * @param len               Message length
 * @return                  CYXWIZ_OK on success
 *                          CYXWIZ_ERR_INVALID if unknown message type
 */
cyxwiz_error_t cyxwiz_privacy_handle_message(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len);

#endif /* CYXWIZ_PRIVACY_H */
