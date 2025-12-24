/*
 * CyxWiz Protocol - Zero-Knowledge Proofs
 *
 * Schnorr identity proofs using libsodium Ed25519 primitives.
 *
 * This implements non-interactive Schnorr proofs using the Fiat-Shamir
 * heuristic where the challenge is derived as:
 *   c = BLAKE2b(R || P || context) mod L
 *
 * The proof (R, s) is 64 bytes and verifies as: s*G == R + c*P
 */

#include "cyxwiz/zkp.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

#include <string.h>

/* ============================================================================
 * Identity Keypair Management
 * ============================================================================ */

cyxwiz_error_t cyxwiz_identity_keygen(cyxwiz_identity_keypair_t *keypair)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(keypair);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (keypair == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Generate Ed25519 keypair using libsodium */
    if (crypto_sign_keypair(keypair->public_key, keypair->secret_key) != 0) {
        CYXWIZ_ERROR("Failed to generate Ed25519 keypair");
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_identity_to_x25519_pk(
    const cyxwiz_identity_keypair_t *keypair,
    uint8_t *x25519_pk)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(keypair);
    CYXWIZ_UNUSED(x25519_pk);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (keypair == NULL || x25519_pk == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Convert Ed25519 public key to X25519 (Curve25519) public key */
    if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk, keypair->public_key) != 0) {
        CYXWIZ_ERROR("Failed to convert Ed25519 pk to X25519");
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_identity_to_x25519_sk(
    const cyxwiz_identity_keypair_t *keypair,
    uint8_t *x25519_sk)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(keypair);
    CYXWIZ_UNUSED(x25519_sk);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (keypair == NULL || x25519_sk == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Convert Ed25519 secret key to X25519 secret key */
    if (crypto_sign_ed25519_sk_to_curve25519(x25519_sk, keypair->secret_key) != 0) {
        CYXWIZ_ERROR("Failed to convert Ed25519 sk to X25519");
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_identity_to_node_id(
    const cyxwiz_identity_keypair_t *keypair,
    cyxwiz_node_id_t *node_id)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(keypair);
    CYXWIZ_UNUSED(node_id);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (keypair == NULL || node_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Node ID = BLAKE2b(Ed25519_public_key, 32 bytes) */
    return cyxwiz_crypto_hash(
        keypair->public_key,
        CYXWIZ_ED25519_PK_SIZE,
        node_id->bytes,
        CYXWIZ_NODE_ID_LEN);
#endif
}

bool cyxwiz_identity_verify_node_id(
    const uint8_t *ed25519_pk,
    const cyxwiz_node_id_t *node_id)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ed25519_pk);
    CYXWIZ_UNUSED(node_id);
    return false;
#else
    if (ed25519_pk == NULL || node_id == NULL) {
        return false;
    }

    /* Compute expected node ID */
    cyxwiz_node_id_t expected;
    if (cyxwiz_crypto_hash(ed25519_pk, CYXWIZ_ED25519_PK_SIZE,
                           expected.bytes, CYXWIZ_NODE_ID_LEN) != CYXWIZ_OK) {
        return false;
    }

    /* Constant-time comparison */
    return sodium_memcmp(expected.bytes, node_id->bytes, CYXWIZ_NODE_ID_LEN) == 0;
#endif
}

void cyxwiz_identity_destroy(cyxwiz_identity_keypair_t *keypair)
{
    if (keypair == NULL) {
        return;
    }

    /* Zero secret key */
    cyxwiz_secure_zero(keypair->secret_key, sizeof(keypair->secret_key));
    cyxwiz_secure_zero(keypair->public_key, sizeof(keypair->public_key));
}

/* ============================================================================
 * Internal Helper: Compute Fiat-Shamir Challenge
 * ============================================================================ */

#ifdef CYXWIZ_HAS_CRYPTO
/*
 * Compute Fiat-Shamir challenge: c = BLAKE2b(R || P || context) mod L
 *
 * Returns a 32-byte scalar reduced modulo L (Ed25519 group order).
 */
static cyxwiz_error_t compute_challenge(
    const uint8_t *commitment,          /* R (32 bytes) */
    const uint8_t *public_key,          /* P (32 bytes) */
    const uint8_t *context,             /* Optional context */
    size_t context_len,
    uint8_t *challenge_out)             /* Output: 32-byte scalar */
{
    crypto_generichash_state state;
    uint8_t hash[64];  /* 64 bytes for reduction to scalar */

    /* Initialize BLAKE2b with 64-byte output */
    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Hash: R || P || context */
    if (crypto_generichash_update(&state, commitment, 32) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    if (crypto_generichash_update(&state, public_key, 32) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    if (context != NULL && context_len > 0) {
        if (crypto_generichash_update(&state, context, context_len) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
    }

    if (crypto_generichash_final(&state, hash, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Reduce 64-byte hash to scalar mod L */
    crypto_core_ed25519_scalar_reduce(challenge_out, hash);

    /* Clean up */
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;
}

/*
 * Extract the secret scalar from Ed25519 secret key.
 *
 * libsodium Ed25519 secret key format: [seed (32 bytes) || public_key (32 bytes)]
 * The actual scalar x is derived by SHA512(seed) with bit clamping.
 */
static void extract_scalar_from_sk(const uint8_t *sk, uint8_t *scalar_out)
{
    uint8_t hash[64];

    /* SHA512(seed) where seed is first 32 bytes of sk */
    crypto_hash_sha512(hash, sk, 32);

    /* Ed25519 bit clamping */
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    /* Copy first 32 bytes as the scalar */
    memcpy(scalar_out, hash, 32);

    /* Clean up */
    cyxwiz_secure_zero(hash, sizeof(hash));
}
#endif

/* ============================================================================
 * Schnorr Identity Proofs
 * ============================================================================ */

cyxwiz_error_t cyxwiz_schnorr_prove(
    const cyxwiz_identity_keypair_t *keypair,
    const cyxwiz_proof_context_t *context,
    cyxwiz_schnorr_proof_t *proof_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(keypair);
    CYXWIZ_UNUSED(context);
    CYXWIZ_UNUSED(proof_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (keypair == NULL || proof_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_error_t err;
    uint8_t k[32];          /* Random nonce (scalar) */
    uint8_t k_full[64];     /* Full random for reduction */
    uint8_t c[32];          /* Challenge scalar */
    uint8_t x[32];          /* Secret key scalar */
    uint8_t cx[32];         /* c * x */

    /* 1. Generate random nonce k and reduce to scalar */
    randombytes_buf(k_full, 64);
    crypto_core_ed25519_scalar_reduce(k, k_full);

    /* 2. Compute R = k * G (commitment) */
    if (crypto_scalarmult_ed25519_base_noclamp(proof_out->commitment, k) != 0) {
        err = CYXWIZ_ERR_CRYPTO;
        goto cleanup;
    }

    /* 3. Compute challenge c = BLAKE2b(R || P || context) mod L */
    err = compute_challenge(
        proof_out->commitment,
        keypair->public_key,
        context ? context->context : NULL,
        context ? context->context_len : 0,
        c);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* 4. Extract secret scalar x from Ed25519 secret key */
    extract_scalar_from_sk(keypair->secret_key, x);

    /* 5. Compute s = k + c*x mod L */
    crypto_core_ed25519_scalar_mul(cx, c, x);
    crypto_core_ed25519_scalar_add(proof_out->response, k, cx);

    err = CYXWIZ_OK;

cleanup:
    /* Zero sensitive data */
    cyxwiz_secure_zero(k, sizeof(k));
    cyxwiz_secure_zero(k_full, sizeof(k_full));
    cyxwiz_secure_zero(c, sizeof(c));
    cyxwiz_secure_zero(x, sizeof(x));
    cyxwiz_secure_zero(cx, sizeof(cx));

    return err;
#endif
}

cyxwiz_error_t cyxwiz_schnorr_verify(
    const uint8_t *public_key,
    const cyxwiz_schnorr_proof_t *proof,
    const cyxwiz_proof_context_t *context)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(public_key);
    CYXWIZ_UNUSED(proof);
    CYXWIZ_UNUSED(context);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (public_key == NULL || proof == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_error_t err;
    uint8_t c[32];          /* Challenge scalar */
    uint8_t sG[32];         /* s * G */
    uint8_t cP[32];         /* c * P */
    uint8_t R_plus_cP[32];  /* R + c*P */

    /* 1. Validate that R (commitment) is a valid point on the curve */
    if (crypto_core_ed25519_is_valid_point(proof->commitment) != 1) {
        CYXWIZ_DEBUG("Invalid commitment point");
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* 2. Validate that P (public key) is a valid point */
    if (crypto_core_ed25519_is_valid_point(public_key) != 1) {
        CYXWIZ_DEBUG("Invalid public key point");
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* 3. Recompute challenge c = BLAKE2b(R || P || context) mod L */
    err = compute_challenge(
        proof->commitment,
        public_key,
        context ? context->context : NULL,
        context ? context->context_len : 0,
        c);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* 4. Compute s * G */
    if (crypto_scalarmult_ed25519_base_noclamp(sG, proof->response) != 0) {
        CYXWIZ_DEBUG("Failed to compute s*G");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* 5. Compute c * P */
    if (crypto_scalarmult_ed25519_noclamp(cP, c, public_key) != 0) {
        CYXWIZ_DEBUG("Failed to compute c*P");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* 6. Compute R + c*P */
    if (crypto_core_ed25519_add(R_plus_cP, proof->commitment, cP) != 0) {
        CYXWIZ_DEBUG("Failed to compute R + c*P");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* 7. Verify s*G == R + c*P (constant-time comparison) */
    if (sodium_memcmp(sG, R_plus_cP, 32) != 0) {
        CYXWIZ_DEBUG("Schnorr verification failed: s*G != R + c*P");
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Message-Bound Proofs
 * ============================================================================ */

cyxwiz_error_t cyxwiz_schnorr_prove_message(
    const cyxwiz_identity_keypair_t *keypair,
    const uint8_t *message,
    size_t message_len,
    cyxwiz_schnorr_proof_t *proof_out)
{
    /* Message is used as context for the proof */
    cyxwiz_proof_context_t ctx;
    ctx.context = message;
    ctx.context_len = message_len;

    return cyxwiz_schnorr_prove(keypair, &ctx, proof_out);
}

cyxwiz_error_t cyxwiz_schnorr_verify_message(
    const uint8_t *public_key,
    const uint8_t *message,
    size_t message_len,
    const cyxwiz_schnorr_proof_t *proof)
{
    /* Message is used as context for verification */
    cyxwiz_proof_context_t ctx;
    ctx.context = message;
    ctx.context_len = message_len;

    return cyxwiz_schnorr_verify(public_key, proof, &ctx);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

void cyxwiz_proof_context_init(
    cyxwiz_proof_context_t *context_out,
    const uint8_t *ctx_string,
    size_t ctx_len)
{
    if (context_out == NULL) {
        return;
    }

    context_out->context = ctx_string;
    context_out->context_len = ctx_len;
}
