/*
 * CyxWiz Protocol - Zero-Knowledge Proofs
 *
 * Schnorr identity proofs using Ed25519 primitives.
 * Proves ownership of node identity without revealing private keys.
 */

#ifndef CYXWIZ_ZKP_H
#define CYXWIZ_ZKP_H

#include "types.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Schnorr proof size constants */
#define CYXWIZ_SCHNORR_COMMITMENT_SIZE 32   /* R - compressed Ed25519 point */
#define CYXWIZ_SCHNORR_RESPONSE_SIZE   32   /* s - scalar mod L */
#define CYXWIZ_SCHNORR_PROOF_SIZE      64   /* R + s */
#define CYXWIZ_SCHNORR_CHALLENGE_SIZE  64   /* BLAKE2b output before reduction */

/* Ed25519 key sizes */
#define CYXWIZ_ED25519_PK_SIZE 32
#define CYXWIZ_ED25519_SK_SIZE 64   /* libsodium expanded format: seed || pk */

/* X25519 key size (for derivation) */
#define CYXWIZ_X25519_KEY_SIZE 32

/*
 * Schnorr identity proof
 *
 * Non-interactive proof of knowledge of Ed25519 private key.
 * Uses Fiat-Shamir heuristic: c = BLAKE2b(R || P || context)
 *
 * Protocol:
 *   Prover has (x, P) where P = x*G
 *   1. k = random scalar
 *   2. R = k*G (commitment)
 *   3. c = BLAKE2b(R || P || context) mod L (challenge)
 *   4. s = k + c*x mod L (response)
 *
 * Verifier checks: s*G == R + c*P
 */
typedef struct {
    uint8_t commitment[CYXWIZ_SCHNORR_COMMITMENT_SIZE];  /* R = k*G */
    uint8_t response[CYXWIZ_SCHNORR_RESPONSE_SIZE];      /* s = k + c*x mod L */
} cyxwiz_schnorr_proof_t;

/*
 * Ed25519 identity keypair
 *
 * Master identity for a node. Used for:
 *   - Schnorr identity proofs
 *   - Deriving X25519 keys for onion routing
 *   - Deriving node ID
 */
typedef struct {
    uint8_t public_key[CYXWIZ_ED25519_PK_SIZE];
    uint8_t secret_key[CYXWIZ_ED25519_SK_SIZE];
} cyxwiz_identity_keypair_t;

/*
 * Proof context for domain separation
 *
 * Prevents proof replay across different contexts.
 * Example contexts: "cyxwiz_announce_v1", "cyxwiz_job_auth"
 */
typedef struct {
    const uint8_t *context;     /* Application-specific context string */
    size_t context_len;         /* Length of context string */
} cyxwiz_proof_context_t;

/* ============================================================================
 * Identity Keypair Management
 * ============================================================================ */

/*
 * Generate a new identity keypair (Ed25519)
 *
 * Creates a cryptographically secure random Ed25519 keypair.
 * This is the master identity for a node.
 *
 * @param keypair   Output keypair (caller allocated)
 * @return          CYXWIZ_OK on success
 *                  CYXWIZ_ERR_INVALID if keypair is NULL
 *                  CYXWIZ_ERR_NOT_INITIALIZED if crypto not initialized
 */
cyxwiz_error_t cyxwiz_identity_keygen(cyxwiz_identity_keypair_t *keypair);

/*
 * Derive X25519 public key from Ed25519 identity
 *
 * Used for onion routing compatibility. The derived key can be used
 * with X25519 key exchange for establishing shared secrets.
 *
 * @param keypair       Ed25519 identity keypair
 * @param x25519_pk     Output X25519 public key (32 bytes, caller allocated)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_INVALID if parameters are NULL
 *                      CYXWIZ_ERR_CRYPTO on conversion failure
 */
cyxwiz_error_t cyxwiz_identity_to_x25519_pk(
    const cyxwiz_identity_keypair_t *keypair,
    uint8_t *x25519_pk);

/*
 * Derive X25519 secret key from Ed25519 identity
 *
 * Used for onion routing compatibility.
 *
 * @param keypair       Ed25519 identity keypair
 * @param x25519_sk     Output X25519 secret key (32 bytes, caller allocated)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_INVALID if parameters are NULL
 *                      CYXWIZ_ERR_CRYPTO on conversion failure
 */
cyxwiz_error_t cyxwiz_identity_to_x25519_sk(
    const cyxwiz_identity_keypair_t *keypair,
    uint8_t *x25519_sk);

/*
 * Derive node ID from identity public key
 *
 * Node ID = BLAKE2b(Ed25519_public_key, 32 bytes)
 *
 * This provides a consistent mapping from identity to node ID,
 * allowing verification that a node ID corresponds to a given identity.
 *
 * @param keypair       Identity keypair
 * @param node_id       Output node ID
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_INVALID if parameters are NULL
 */
cyxwiz_error_t cyxwiz_identity_to_node_id(
    const cyxwiz_identity_keypair_t *keypair,
    cyxwiz_node_id_t *node_id);

/*
 * Verify that a node ID matches an Ed25519 public key
 *
 * Checks: node_id == BLAKE2b(ed25519_pk)
 *
 * @param ed25519_pk    Ed25519 public key (32 bytes)
 * @param node_id       Node ID to verify
 * @return              true if node ID matches public key
 */
bool cyxwiz_identity_verify_node_id(
    const uint8_t *ed25519_pk,
    const cyxwiz_node_id_t *node_id);

/*
 * Securely destroy identity keypair
 *
 * Zeros the secret key to prevent memory leaks.
 *
 * @param keypair       Keypair to destroy
 */
void cyxwiz_identity_destroy(cyxwiz_identity_keypair_t *keypair);

/* ============================================================================
 * Schnorr Identity Proofs
 * ============================================================================ */

/*
 * Generate non-interactive Schnorr identity proof
 *
 * Proves knowledge of secret key corresponding to public key
 * without revealing the secret key.
 *
 * Uses Fiat-Shamir heuristic: c = BLAKE2b(R || P || context)
 *
 * @param keypair       Identity keypair (prover's keys)
 * @param context       Proof context for domain separation (may be NULL)
 * @param proof_out     Output proof (64 bytes)
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_INVALID if keypair or proof_out is NULL
 *                      CYXWIZ_ERR_CRYPTO on cryptographic error
 */
cyxwiz_error_t cyxwiz_schnorr_prove(
    const cyxwiz_identity_keypair_t *keypair,
    const cyxwiz_proof_context_t *context,
    cyxwiz_schnorr_proof_t *proof_out);

/*
 * Verify non-interactive Schnorr identity proof
 *
 * Verifies that the prover knows the secret key for the given public key.
 *
 * @param public_key    Prover's Ed25519 public key (32 bytes)
 * @param proof         The proof to verify
 * @param context       Proof context (must match prover's context)
 * @return              CYXWIZ_OK if proof is valid
 *                      CYXWIZ_ERR_PROOF_INVALID if proof is invalid
 *                      CYXWIZ_ERR_INVALID if parameters are NULL
 */
cyxwiz_error_t cyxwiz_schnorr_verify(
    const uint8_t *public_key,
    const cyxwiz_schnorr_proof_t *proof,
    const cyxwiz_proof_context_t *context);

/*
 * Generate Schnorr proof bound to a specific message
 *
 * Like cyxwiz_schnorr_prove, but binds the proof to a message.
 * Useful for proving identity while authenticating a specific message.
 *
 * The message is included in the Fiat-Shamir challenge:
 *   c = BLAKE2b(R || P || message)
 *
 * @param keypair       Identity keypair
 * @param message       Message to bind to proof
 * @param message_len   Message length
 * @param proof_out     Output proof
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_schnorr_prove_message(
    const cyxwiz_identity_keypair_t *keypair,
    const uint8_t *message,
    size_t message_len,
    cyxwiz_schnorr_proof_t *proof_out);

/*
 * Verify Schnorr proof bound to a message
 *
 * @param public_key    Prover's public key
 * @param message       Message that was bound
 * @param message_len   Message length
 * @param proof         The proof to verify
 * @return              CYXWIZ_OK if valid
 *                      CYXWIZ_ERR_PROOF_INVALID if invalid
 */
cyxwiz_error_t cyxwiz_schnorr_verify_message(
    const uint8_t *public_key,
    const uint8_t *message,
    size_t message_len,
    const cyxwiz_schnorr_proof_t *proof);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/*
 * Initialize proof context
 *
 * Helper to create a proof context from a string.
 *
 * @param context_out   Output context structure
 * @param ctx_string    Context string (e.g., "cyxwiz_announce_v1")
 * @param ctx_len       Context string length
 */
void cyxwiz_proof_context_init(
    cyxwiz_proof_context_t *context_out,
    const uint8_t *ctx_string,
    size_t ctx_len);

#endif /* CYXWIZ_ZKP_H */
