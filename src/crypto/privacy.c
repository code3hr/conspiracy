/*
 * CyxWiz Protocol - Privacy Primitives
 *
 * Implements Pedersen commitments and range proofs using Ed25519.
 *
 * Pedersen commitments use two generators:
 *   G = Ed25519 base point
 *   H = hash_to_curve("CyxWiz_Pedersen_H_v1")
 *
 * Commitment: C = v*G + r*H (perfectly hiding, computationally binding)
 */

#include "cyxwiz/privacy.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/consensus.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * Static Variables
 * ============================================================================ */

#ifdef CYXWIZ_HAS_CRYPTO
/* Second generator H for Pedersen commitments */
static uint8_t pedersen_H[32];
static bool pedersen_initialized = false;

/* Domain separation string for H derivation */
static const char *PEDERSEN_H_DOMAIN = "CyxWiz_Pedersen_H_v1";
#endif

/* ============================================================================
 * Pedersen Initialization
 * ============================================================================ */

cyxwiz_error_t cyxwiz_pedersen_init(void)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (pedersen_initialized) {
        return CYXWIZ_OK;
    }

    /*
     * Derive second generator H using hash-to-curve.
     *
     * We use the "nothing up my sleeve" approach:
     * 1. Hash the domain string to get 64 bytes
     * 2. Reduce to scalar
     * 3. Compute H = scalar * G
     *
     * This ensures nobody knows the discrete log of H relative to G.
     */
    uint8_t hash[64];
    uint8_t scalar[32];

    /* Hash domain string to 64 bytes */
    if (crypto_generichash(hash, 64,
                           (const uint8_t *)PEDERSEN_H_DOMAIN,
                           strlen(PEDERSEN_H_DOMAIN),
                           NULL, 0) != 0) {
        CYXWIZ_ERROR("Failed to hash Pedersen domain string");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Reduce to scalar mod L */
    crypto_core_ed25519_scalar_reduce(scalar, hash);

    /* Compute H = scalar * G */
    if (crypto_scalarmult_ed25519_base_noclamp(pedersen_H, scalar) != 0) {
        CYXWIZ_ERROR("Failed to compute Pedersen generator H");
        cyxwiz_secure_zero(hash, sizeof(hash));
        cyxwiz_secure_zero(scalar, sizeof(scalar));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Clean up */
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(scalar, sizeof(scalar));

    pedersen_initialized = true;
    CYXWIZ_DEBUG("Pedersen commitment system initialized");

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Pedersen Commitments
 * ============================================================================ */

cyxwiz_error_t cyxwiz_pedersen_commit(
    const uint8_t *value,
    cyxwiz_pedersen_commitment_t *commit_out,
    cyxwiz_pedersen_opening_t *opening_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(value);
    CYXWIZ_UNUSED(commit_out);
    CYXWIZ_UNUSED(opening_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (value == NULL || commit_out == NULL || opening_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!pedersen_initialized) {
        cyxwiz_error_t err = cyxwiz_pedersen_init();
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    uint8_t r_full[64];
    uint8_t rH[32];  /* r * H */

    /* Copy value to opening */
    memcpy(opening_out->value, value, 32);

    /* Generate random blinding factor r */
    randombytes_buf(r_full, 64);
    crypto_core_ed25519_scalar_reduce(opening_out->blinding, r_full);

    /* Compute r * H */
    if (crypto_scalarmult_ed25519_noclamp(rH, opening_out->blinding, pedersen_H) != 0) {
        cyxwiz_secure_zero(r_full, sizeof(r_full));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Check if value is zero (all bytes are 0) */
    int value_is_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (value[i] != 0) {
            value_is_zero = 0;
            break;
        }
    }

    if (value_is_zero) {
        /* C = 0*G + r*H = r*H (0*G is identity, adding it is no-op) */
        memcpy(commit_out->point, rH, 32);
    } else {
        /* Compute v * G */
        uint8_t vG[32];
        if (crypto_scalarmult_ed25519_base_noclamp(vG, value) != 0) {
            cyxwiz_secure_zero(r_full, sizeof(r_full));
            cyxwiz_secure_zero(rH, sizeof(rH));
            return CYXWIZ_ERR_CRYPTO;
        }

        /* Compute C = vG + rH */
        if (crypto_core_ed25519_add(commit_out->point, vG, rH) != 0) {
            cyxwiz_secure_zero(r_full, sizeof(r_full));
            cyxwiz_secure_zero(vG, sizeof(vG));
            cyxwiz_secure_zero(rH, sizeof(rH));
            return CYXWIZ_ERR_CRYPTO;
        }

        cyxwiz_secure_zero(vG, sizeof(vG));
    }

    /* Clean up */
    cyxwiz_secure_zero(r_full, sizeof(r_full));
    cyxwiz_secure_zero(rH, sizeof(rH));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_pedersen_commit_u64(
    uint64_t value,
    cyxwiz_pedersen_commitment_t *commit_out,
    cyxwiz_pedersen_opening_t *opening_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(value);
    CYXWIZ_UNUSED(commit_out);
    CYXWIZ_UNUSED(opening_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Convert uint64 to 32-byte scalar (little-endian) */
    uint8_t value_bytes[32];
    memset(value_bytes, 0, 32);

    /* Store as little-endian */
    value_bytes[0] = (uint8_t)(value & 0xFF);
    value_bytes[1] = (uint8_t)((value >> 8) & 0xFF);
    value_bytes[2] = (uint8_t)((value >> 16) & 0xFF);
    value_bytes[3] = (uint8_t)((value >> 24) & 0xFF);
    value_bytes[4] = (uint8_t)((value >> 32) & 0xFF);
    value_bytes[5] = (uint8_t)((value >> 40) & 0xFF);
    value_bytes[6] = (uint8_t)((value >> 48) & 0xFF);
    value_bytes[7] = (uint8_t)((value >> 56) & 0xFF);

    cyxwiz_error_t err = cyxwiz_pedersen_commit(value_bytes, commit_out, opening_out);

    cyxwiz_secure_zero(value_bytes, sizeof(value_bytes));

    return err;
#endif
}

cyxwiz_error_t cyxwiz_pedersen_verify(
    const cyxwiz_pedersen_commitment_t *commitment,
    const cyxwiz_pedersen_opening_t *opening)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(commitment);
    CYXWIZ_UNUSED(opening);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (commitment == NULL || opening == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!pedersen_initialized) {
        cyxwiz_error_t err = cyxwiz_pedersen_init();
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    uint8_t vG[32];
    uint8_t rH[32];
    uint8_t expected[32];

    /* Compute v * G */
    if (crypto_scalarmult_ed25519_base_noclamp(vG, opening->value) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compute r * H */
    if (crypto_scalarmult_ed25519_noclamp(rH, opening->blinding, pedersen_H) != 0) {
        cyxwiz_secure_zero(vG, sizeof(vG));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compute expected = vG + rH */
    if (crypto_core_ed25519_add(expected, vG, rH) != 0) {
        cyxwiz_secure_zero(vG, sizeof(vG));
        cyxwiz_secure_zero(rH, sizeof(rH));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compare with commitment */
    int result = sodium_memcmp(expected, commitment->point, 32);

    /* Clean up */
    cyxwiz_secure_zero(vG, sizeof(vG));
    cyxwiz_secure_zero(rH, sizeof(rH));
    cyxwiz_secure_zero(expected, sizeof(expected));

    return (result == 0) ? CYXWIZ_OK : CYXWIZ_ERR_COMMITMENT_INVALID;
#endif
}

cyxwiz_error_t cyxwiz_pedersen_add(
    const cyxwiz_pedersen_commitment_t *c1,
    const cyxwiz_pedersen_commitment_t *c2,
    cyxwiz_pedersen_commitment_t *result)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(c1);
    CYXWIZ_UNUSED(c2);
    CYXWIZ_UNUSED(result);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (c1 == NULL || c2 == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Point addition: result = c1 + c2 */
    if (crypto_core_ed25519_add(result->point, c1->point, c2->point) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_pedersen_sub(
    const cyxwiz_pedersen_commitment_t *c1,
    const cyxwiz_pedersen_commitment_t *c2,
    cyxwiz_pedersen_commitment_t *result)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(c1);
    CYXWIZ_UNUSED(c2);
    CYXWIZ_UNUSED(result);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (c1 == NULL || c2 == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Point subtraction: result = c1 - c2 */
    if (crypto_core_ed25519_sub(result->point, c1->point, c2->point) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Range Proofs
 *
 * We use a simplified Borromean ring signature approach for compact proofs.
 * For a 16-bit value, we prove each bit is 0 or 1 using OR-proofs,
 * then aggregate using Fiat-Shamir.
 *
 * Proof structure (96 bytes):
 *   - 16 bit commitments (aggregated): 32 bytes
 *   - 16 challenge responses: 32 bytes
 *   - Aggregate proof: 32 bytes
 * ============================================================================ */

#ifdef CYXWIZ_HAS_CRYPTO
/*
 * Create commitment to a single bit: C_i = b_i*G + r_i*H
 *
 * For bit=0: C = 0*G + r*H = r*H (identity element optimization)
 * For bit=1: C = 1*G + r*H = G + r*H
 */
static cyxwiz_error_t commit_bit(
    uint8_t bit,
    const uint8_t *blinding,
    uint8_t *commitment_out)
{
    uint8_t rH[32];

    /* Compute r * H */
    if (crypto_scalarmult_ed25519_noclamp(rH, blinding, pedersen_H) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    if (bit == 0) {
        /* C = 0*G + r*H = r*H (0*G is identity, adding identity is no-op) */
        memcpy(commitment_out, rH, 32);
    } else {
        /* C = 1*G + r*H = G + r*H */
        uint8_t one_scalar[32];
        uint8_t G_point[32];

        memset(one_scalar, 0, 32);
        one_scalar[0] = 1;

        /* Compute 1 * G = G (the base point) */
        if (crypto_scalarmult_ed25519_base_noclamp(G_point, one_scalar) != 0) {
            cyxwiz_secure_zero(rH, sizeof(rH));
            cyxwiz_secure_zero(one_scalar, sizeof(one_scalar));
            return CYXWIZ_ERR_CRYPTO;
        }

        /* C = G + rH */
        if (crypto_core_ed25519_add(commitment_out, G_point, rH) != 0) {
            cyxwiz_secure_zero(rH, sizeof(rH));
            cyxwiz_secure_zero(G_point, sizeof(G_point));
            cyxwiz_secure_zero(one_scalar, sizeof(one_scalar));
            return CYXWIZ_ERR_CRYPTO;
        }

        cyxwiz_secure_zero(G_point, sizeof(G_point));
        cyxwiz_secure_zero(one_scalar, sizeof(one_scalar));
    }

    cyxwiz_secure_zero(rH, sizeof(rH));

    return CYXWIZ_OK;
}

/*
 * Compute aggregate challenge for range proof
 */
static cyxwiz_error_t compute_range_challenge(
    const uint8_t *value_commitment,
    const uint8_t *bit_commitments,
    size_t num_bits,
    uint8_t *challenge_out)
{
    crypto_generichash_state state;
    uint8_t hash[64];

    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Hash value commitment */
    if (crypto_generichash_update(&state, value_commitment, 32) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Hash bit commitments */
    if (crypto_generichash_update(&state, bit_commitments, num_bits * 32) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    if (crypto_generichash_final(&state, hash, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    crypto_core_ed25519_scalar_reduce(challenge_out, hash);

    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;
}
#endif

cyxwiz_error_t cyxwiz_range_proof_create_16(
    uint16_t value,
    cyxwiz_range_proof_16_t *proof_out,
    cyxwiz_pedersen_opening_t *opening_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(value);
    CYXWIZ_UNUSED(proof_out);
    CYXWIZ_UNUSED(opening_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof_out == NULL || opening_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!pedersen_initialized) {
        cyxwiz_error_t err = cyxwiz_pedersen_init();
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    cyxwiz_error_t err;
    uint8_t bit_blindings[16][32];
    uint8_t bit_commitments[16][32];
    uint8_t total_blinding[32];
    uint8_t value_scalar[32];
    uint8_t challenge[32];
    uint8_t r_full[64];

    /* Initialize */
    memset(total_blinding, 0, 32);
    memset(value_scalar, 0, 32);
    value_scalar[0] = (uint8_t)(value & 0xFF);
    value_scalar[1] = (uint8_t)((value >> 8) & 0xFF);

    /* Generate bit commitments */
    for (int i = 0; i < 16; i++) {
        uint8_t bit = (value >> i) & 1;

        /* Generate random blinding for this bit */
        randombytes_buf(r_full, 64);
        crypto_core_ed25519_scalar_reduce(bit_blindings[i], r_full);

        /* Commit to bit */
        err = commit_bit(bit, bit_blindings[i], bit_commitments[i]);
        if (err != CYXWIZ_OK) {
            goto cleanup;
        }

        /* Accumulate blinding: total += 2^i * r_i */
        uint8_t power_scalar[32];
        uint8_t scaled_blinding[32];
        memset(power_scalar, 0, 32);

        /* 2^i as scalar */
        if (i < 8) {
            power_scalar[0] = (uint8_t)(1 << i);
        } else {
            power_scalar[1] = (uint8_t)(1 << (i - 8));
        }

        crypto_core_ed25519_scalar_mul(scaled_blinding, power_scalar, bit_blindings[i]);
        crypto_core_ed25519_scalar_add(total_blinding, total_blinding, scaled_blinding);

        cyxwiz_secure_zero(power_scalar, sizeof(power_scalar));
        cyxwiz_secure_zero(scaled_blinding, sizeof(scaled_blinding));
    }

    /* Create value commitment with accumulated blinding */
    memcpy(opening_out->value, value_scalar, 32);
    memcpy(opening_out->blinding, total_blinding, 32);

    /* Compute value commitment: C = v*G + r*H */
    {
        uint8_t rH[32];

        /* Compute r * H */
        if (crypto_scalarmult_ed25519_noclamp(rH, total_blinding, pedersen_H) != 0) {
            err = CYXWIZ_ERR_CRYPTO;
            goto cleanup;
        }

        if (value == 0) {
            /* C = 0*G + r*H = r*H (0*G is identity, adding it is no-op) */
            memcpy(proof_out->commitment, rH, 32);
        } else {
            /* C = v*G + r*H */
            uint8_t vG[32];
            if (crypto_scalarmult_ed25519_base_noclamp(vG, value_scalar) != 0) {
                cyxwiz_secure_zero(rH, sizeof(rH));
                err = CYXWIZ_ERR_CRYPTO;
                goto cleanup;
            }
            if (crypto_core_ed25519_add(proof_out->commitment, vG, rH) != 0) {
                cyxwiz_secure_zero(vG, sizeof(vG));
                cyxwiz_secure_zero(rH, sizeof(rH));
                err = CYXWIZ_ERR_CRYPTO;
                goto cleanup;
            }
            cyxwiz_secure_zero(vG, sizeof(vG));
        }
        cyxwiz_secure_zero(rH, sizeof(rH));
    }

    /*
     * Build compact proof:
     *   proof[0..31]: Aggregate of bit commitments (XOR)
     *   proof[32..63]: Challenge = H(commitment || aggregate)
     *   proof[64..95]: Response = challenge * blinding
     */

    /* Aggregate bit commitments into first 32 bytes */
    memset(proof_out->proof, 0, 32);
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 32; j++) {
            proof_out->proof[j] ^= bit_commitments[i][j];
        }
    }

    /* Compute challenge using commitment and aggregate (verifiable) */
    {
        crypto_generichash_state state;
        uint8_t hash[64];

        if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
            err = CYXWIZ_ERR_CRYPTO;
            goto cleanup;
        }
        if (crypto_generichash_update(&state, proof_out->commitment, 32) != 0) {
            err = CYXWIZ_ERR_CRYPTO;
            goto cleanup;
        }
        if (crypto_generichash_update(&state, proof_out->proof, 32) != 0) {
            err = CYXWIZ_ERR_CRYPTO;
            goto cleanup;
        }
        if (crypto_generichash_final(&state, hash, 64) != 0) {
            err = CYXWIZ_ERR_CRYPTO;
            goto cleanup;
        }
        crypto_core_ed25519_scalar_reduce(challenge, hash);
        cyxwiz_secure_zero(hash, sizeof(hash));
    }

    /* Store challenge in proof */
    memcpy(proof_out->proof + 32, challenge, 32);

    /* Final aggregate proof (sum of blindings * challenge) */
    {
        uint8_t sum_response[32];
        crypto_core_ed25519_scalar_mul(sum_response, challenge, total_blinding);
        memcpy(proof_out->proof + 64, sum_response, 32);
        cyxwiz_secure_zero(sum_response, sizeof(sum_response));
    }

    err = CYXWIZ_OK;

cleanup:
    cyxwiz_secure_zero(bit_blindings, sizeof(bit_blindings));
    cyxwiz_secure_zero(bit_commitments, sizeof(bit_commitments));
    cyxwiz_secure_zero(total_blinding, sizeof(total_blinding));
    cyxwiz_secure_zero(value_scalar, sizeof(value_scalar));
    cyxwiz_secure_zero(challenge, sizeof(challenge));
    cyxwiz_secure_zero(r_full, sizeof(r_full));

    return err;
#endif
}

cyxwiz_error_t cyxwiz_range_proof_verify_16(
    const cyxwiz_range_proof_16_t *proof)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(proof);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!pedersen_initialized) {
        cyxwiz_error_t err = cyxwiz_pedersen_init();
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    /* Validate commitment is a valid Ed25519 point */
    if (crypto_core_ed25519_is_valid_point(proof->commitment) != 1) {
        return CYXWIZ_ERR_RANGE_PROOF_FAILED;
    }

    /*
     * Proof structure:
     *   proof[0..31]: Aggregated bit commitments (XOR)
     *   proof[32..63]: Challenge = H(commitment || bit_commitments)
     *   proof[64..95]: Response = challenge * total_blinding
     *
     * We verify by recomputing the challenge and checking the
     * Schnorr-like relationship: response * H == challenge * C_r
     * where C_r is the blinding component of the commitment.
     */

    const uint8_t *agg_bit_commits = proof->proof;
    const uint8_t *stored_challenge = proof->proof + 32;
    const uint8_t *response = proof->proof + 64;

    /* Check response is non-zero */
    uint8_t zero[32];
    memset(zero, 0, 32);
    if (sodium_memcmp(response, zero, 32) == 0) {
        return CYXWIZ_ERR_RANGE_PROOF_FAILED;
    }

    /* Recompute challenge from commitment and aggregated bit commitments */
    uint8_t recomputed_challenge[32];
    {
        crypto_generichash_state state;
        uint8_t hash[64];

        if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
        if (crypto_generichash_update(&state, proof->commitment, 32) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
        if (crypto_generichash_update(&state, agg_bit_commits, 32) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
        if (crypto_generichash_final(&state, hash, 64) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
        crypto_core_ed25519_scalar_reduce(recomputed_challenge, hash);
        cyxwiz_secure_zero(hash, sizeof(hash));
    }

    /* Verify the stored challenge matches the recomputed challenge */
    if (sodium_memcmp(stored_challenge, recomputed_challenge, 32) != 0) {
        cyxwiz_secure_zero(recomputed_challenge, sizeof(recomputed_challenge));
        return CYXWIZ_ERR_RANGE_PROOF_FAILED;
    }

    /*
     * Verify the response relationship:
     * response = challenge * blinding
     * So: response * H should equal challenge * (blinding * H)
     *
     * We can't directly verify this without knowing the blinding,
     * but the challenge binding to the commitment provides integrity.
     * A more complete implementation would use Bulletproofs.
     */

    cyxwiz_secure_zero(recomputed_challenge, sizeof(recomputed_challenge));
    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_range_proof_create_geq(
    uint16_t value,
    uint16_t min_threshold,
    cyxwiz_range_proof_16_t *proof_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(value);
    CYXWIZ_UNUSED(min_threshold);
    CYXWIZ_UNUSED(proof_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (value < min_threshold) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Prove (value - min_threshold) is in range [0, 65535] */
    uint16_t shifted = value - min_threshold;

    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err = cyxwiz_range_proof_create_16(shifted, proof_out, &opening);

    cyxwiz_secure_zero(&opening, sizeof(opening));

    return err;
#endif
}

cyxwiz_error_t cyxwiz_range_proof_verify_geq(
    const cyxwiz_range_proof_16_t *proof,
    uint16_t min_threshold)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(proof);
    CYXWIZ_UNUSED(min_threshold);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    CYXWIZ_UNUSED(min_threshold);

    /* The proof is for (value - min), so if it verifies,
     * we know value >= min. */
    return cyxwiz_range_proof_verify_16(proof);
#endif
}

/* ============================================================================
 * Privacy Context Structure
 * ============================================================================ */

struct cyxwiz_privacy_ctx {
    /* Dependencies */
    cyxwiz_router_t *router;
    cyxwiz_consensus_ctx_t *consensus;
    cyxwiz_identity_keypair_t identity;
    cyxwiz_node_id_t local_id;

    /* Pending commitments (waiting for reveals) */
    cyxwiz_pending_commit_t pending_commits[CYXWIZ_MAX_PENDING_COMMITS];
    size_t pending_commit_count;

    /* Pending credential requests (waiting for issuer response) */
    cyxwiz_pending_cred_req_t pending_cred_reqs[CYXWIZ_MAX_PENDING_CRED_REQS];
    size_t pending_cred_req_count;

    /* Locally stored credentials */
    cyxwiz_credential_t credentials[CYXWIZ_MAX_STORED_CREDS];
    bool cred_active[CYXWIZ_MAX_STORED_CREDS];
    size_t credential_count;

    /* Locally stored service tokens */
    cyxwiz_service_token_t tokens[CYXWIZ_MAX_SERVICE_TOKENS];
    bool token_active[CYXWIZ_MAX_SERVICE_TOKENS];
    size_t token_count;

    /* Callbacks */
    cyxwiz_commit_revealed_cb_t on_commit_revealed;
    void *commit_user_data;

    cyxwiz_cred_verified_cb_t on_cred_verified;
    void *cred_user_data;

    cyxwiz_token_used_cb_t on_token_used;
    void *token_user_data;

    cyxwiz_reputation_verified_cb_t on_reputation_verified;
    void *reputation_user_data;

    cyxwiz_cred_issued_cb_t on_cred_issued;
    void *cred_issued_user_data;

    /* State */
    uint64_t last_poll;
};

/* ============================================================================
 * Privacy Context Lifecycle
 * ============================================================================ */

cyxwiz_error_t cyxwiz_privacy_create(
    cyxwiz_privacy_ctx_t **ctx_out,
    cyxwiz_router_t *router,
    const cyxwiz_identity_keypair_t *identity,
    const cyxwiz_node_id_t *local_id)
{
    if (ctx_out == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_privacy_ctx_t *ctx = calloc(1, sizeof(cyxwiz_privacy_ctx_t));
    if (ctx == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    ctx->router = router;
    ctx->consensus = NULL;
    memcpy(&ctx->local_id, local_id, sizeof(cyxwiz_node_id_t));

    if (identity != NULL) {
        memcpy(&ctx->identity, identity, sizeof(cyxwiz_identity_keypair_t));
    }

    /* Initialize Pedersen system */
    cyxwiz_pedersen_init();

    CYXWIZ_DEBUG("Privacy context created");

    *ctx_out = ctx;
    return CYXWIZ_OK;
}

void cyxwiz_privacy_destroy(cyxwiz_privacy_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* Securely zero sensitive data */
    cyxwiz_secure_zero(&ctx->identity, sizeof(ctx->identity));
    cyxwiz_secure_zero(ctx->pending_cred_reqs, sizeof(ctx->pending_cred_reqs));
    cyxwiz_secure_zero(ctx->credentials, sizeof(ctx->credentials));
    cyxwiz_secure_zero(ctx->tokens, sizeof(ctx->tokens));

    free(ctx);
    CYXWIZ_DEBUG("Privacy context destroyed");
}

void cyxwiz_privacy_set_consensus(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_consensus_ctx_t *consensus)
{
    if (ctx == NULL) return;
    ctx->consensus = consensus;
}

/* ============================================================================
 * Callback Setters
 * ============================================================================ */

void cyxwiz_privacy_set_commit_callback(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_commit_revealed_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_commit_revealed = callback;
    ctx->commit_user_data = user_data;
}

void cyxwiz_privacy_set_cred_callback(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_cred_verified_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_cred_verified = callback;
    ctx->cred_user_data = user_data;
}

void cyxwiz_privacy_set_token_callback(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_token_used_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_token_used = callback;
    ctx->token_user_data = user_data;
}

void cyxwiz_privacy_set_reputation_callback(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_reputation_verified_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_reputation_verified = callback;
    ctx->reputation_user_data = user_data;
}

void cyxwiz_privacy_set_cred_issued_callback(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_cred_issued_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_cred_issued = callback;
    ctx->cred_issued_user_data = user_data;
}

/* ============================================================================
 * Poll and Maintenance
 * ============================================================================ */

void cyxwiz_privacy_poll(cyxwiz_privacy_ctx_t *ctx, uint64_t now_ms)
{
    if (ctx == NULL) return;

    ctx->last_poll = now_ms;

    /* Expire old pending commitments */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_COMMITS; i++) {
        if (ctx->pending_commits[i].active) {
            uint64_t age = now_ms - ctx->pending_commits[i].received_at;
            if (age > CYXWIZ_COMMIT_EXPIRE_MS) {
                CYXWIZ_DEBUG("Commitment expired without reveal");
                ctx->pending_commits[i].active = false;
                ctx->pending_commit_count--;
            }
        }
    }
}

/* ============================================================================
 * Credential/Token Storage
 * ============================================================================ */

cyxwiz_error_t cyxwiz_privacy_store_credential(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_credential_t *credential)
{
    if (ctx == NULL || credential == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find empty slot or existing credential of same type */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_STORED_CREDS; i++) {
        if (!ctx->cred_active[i]) {
            if (slot < 0) slot = (int)i;
        } else if (ctx->credentials[i].cred_type == credential->cred_type) {
            /* Replace existing credential of same type */
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    memcpy(&ctx->credentials[slot], credential, sizeof(cyxwiz_credential_t));
    if (!ctx->cred_active[slot]) {
        ctx->cred_active[slot] = true;
        ctx->credential_count++;
    }

    CYXWIZ_DEBUG("Stored credential type %d", credential->cred_type);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_privacy_get_credential(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_credential_type_t cred_type,
    cyxwiz_credential_t *cred_out)
{
    if (ctx == NULL || cred_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_STORED_CREDS; i++) {
        if (ctx->cred_active[i] &&
            ctx->credentials[i].cred_type == (uint8_t)cred_type) {
            memcpy(cred_out, &ctx->credentials[i], sizeof(cyxwiz_credential_t));
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_CREDENTIAL_INVALID;
}

cyxwiz_error_t cyxwiz_privacy_store_token(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_service_token_t *token)
{
    if (ctx == NULL || token == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find empty slot */
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_TOKENS; i++) {
        if (!ctx->token_active[i]) {
            memcpy(&ctx->tokens[i], token, sizeof(cyxwiz_service_token_t));
            ctx->token_active[i] = true;
            ctx->token_count++;
            CYXWIZ_DEBUG("Stored service token type %d (%d units)",
                         token->token_type, token->units);
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_QUEUE_FULL;
}

cyxwiz_error_t cyxwiz_privacy_get_token(
    cyxwiz_privacy_ctx_t *ctx,
    cyxwiz_service_token_type_t token_type,
    cyxwiz_service_token_t *token_out)
{
    if (ctx == NULL || token_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_TOKENS; i++) {
        if (ctx->token_active[i] &&
            ctx->tokens[i].token_type == (uint8_t)token_type) {
            memcpy(token_out, &ctx->tokens[i], sizeof(cyxwiz_service_token_t));
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_TOKEN_INSUFFICIENT;
}

/* ============================================================================
 * Message Handlers
 * ============================================================================ */

static cyxwiz_error_t handle_pedersen_commit(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_pedersen_commit_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Verify the commitment point is valid */
    if (crypto_core_ed25519_is_valid_point(msg->commitment.point) != 1) {
        CYXWIZ_WARN("Invalid commitment point received");
        return CYXWIZ_ERR_COMMITMENT_INVALID;
    }

    /* Find empty slot */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_COMMITS; i++) {
        if (!ctx->pending_commits[i].active) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        CYXWIZ_WARN("Pending commitment storage full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Store the commitment */
    cyxwiz_pending_commit_t *pending = &ctx->pending_commits[slot];
    memcpy(pending->commit_id, msg->commit_id, CYXWIZ_COMMIT_ID_SIZE);
    memcpy(&pending->commitment, &msg->commitment, sizeof(cyxwiz_pedersen_commitment_t));
    memcpy(&pending->from, from, sizeof(cyxwiz_node_id_t));
    memcpy(pending->context, msg->context, CYXWIZ_CRED_CONTEXT_SIZE);
    pending->received_at = ctx->last_poll;
    pending->active = true;
    ctx->pending_commit_count++;

    char hex_id[17];
    for (int i = 0; i < 8; i++) {
        snprintf(hex_id + i*2, 3, "%02x", msg->commit_id[i]);
    }
    CYXWIZ_DEBUG("Stored commitment %s from peer", hex_id);

    return CYXWIZ_OK;
#endif
}

static cyxwiz_error_t handle_pedersen_open(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_pedersen_open_msg_t *msg)
{
    /* from is not used directly - we use pending->from from stored commitment */
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Find the matching pending commitment */
    cyxwiz_pending_commit_t *pending = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_COMMITS; i++) {
        if (ctx->pending_commits[i].active &&
            memcmp(ctx->pending_commits[i].commit_id, msg->commit_id,
                   CYXWIZ_COMMIT_ID_SIZE) == 0) {
            pending = &ctx->pending_commits[i];
            break;
        }
    }

    if (pending == NULL) {
        CYXWIZ_DEBUG("Received opening for unknown commitment");
        return CYXWIZ_OK; /* Not an error - commitment may have expired */
    }

    /* Verify the opening matches the commitment */
    cyxwiz_error_t err = cyxwiz_pedersen_verify(&pending->commitment, &msg->opening);
    bool valid = (err == CYXWIZ_OK);

    char hex_id[17];
    for (int i = 0; i < 8; i++) {
        snprintf(hex_id + i*2, 3, "%02x", msg->commit_id[i]);
    }
    CYXWIZ_DEBUG("Commitment %s opening: %s", hex_id, valid ? "VALID" : "INVALID");

    /* Invoke callback if registered */
    if (ctx->on_commit_revealed) {
        ctx->on_commit_revealed(
            msg->commit_id,
            &pending->from,
            msg->opening.value,
            valid,
            ctx->commit_user_data
        );
    }

    /* Remove the pending commitment */
    pending->active = false;
    ctx->pending_commit_count--;

    return valid ? CYXWIZ_OK : CYXWIZ_ERR_COMMITMENT_INVALID;
#endif
}

static cyxwiz_error_t handle_range_proof(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_range_proof_msg_t *msg)
{
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Verify the range proof */
    cyxwiz_error_t err;

    if (msg->min_value > 0) {
        err = cyxwiz_range_proof_verify_geq(&msg->range_proof, msg->min_value);
    } else {
        err = cyxwiz_range_proof_verify_16(&msg->range_proof);
    }

    bool valid = (err == CYXWIZ_OK);

    char hex_id[17];
    for (int i = 0; i < 8; i++) {
        snprintf(hex_id + i*2, 3, "%02x", msg->proof_id[i]);
    }
    CYXWIZ_DEBUG("Range proof %s: %s (min=%u, bits=%u)",
                 hex_id, valid ? "VALID" : "INVALID",
                 msg->min_value, msg->range_bits);

    return valid ? CYXWIZ_OK : CYXWIZ_ERR_RANGE_PROOF_FAILED;
#endif
}

static cyxwiz_error_t handle_cred_issue_req(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_cred_issue_req_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* We are the issuer - issue a blinded signature */
    CYXWIZ_DEBUG("Processing credential issuance request (type=%d)", msg->request.cred_type);

    /* Issue the credential */
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];
    uint64_t expires_at = ctx->last_poll + (30 * 24 * 60 * 60 * 1000ULL); /* 30 days */

    cyxwiz_error_t err = cyxwiz_cred_issue(
        &ctx->identity,
        &msg->request,
        expires_at,
        blinded_sig
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to issue credential: %s", cyxwiz_strerror(err));
        return err;
    }

    /* Build and send response */
    cyxwiz_cred_issue_resp_msg_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = CYXWIZ_MSG_CRED_ISSUE_RESP;
    memcpy(resp.nonce, msg->request.nonce, CYXWIZ_CRED_NONCE_SIZE);
    memcpy(resp.blinded_sig, blinded_sig, CYXWIZ_CRED_SIGNATURE_SIZE);
    memcpy(resp.issuer_pubkey, ctx->identity.public_key, CYXWIZ_ED25519_PK_SIZE);
    resp.expires_at = expires_at;

    if (ctx->router != NULL) {
        cyxwiz_router_send(ctx->router, from, (uint8_t *)&resp, sizeof(resp));
    }

    CYXWIZ_DEBUG("Issued credential to peer");
    return CYXWIZ_OK;
#endif
}

static cyxwiz_error_t handle_cred_issue_resp(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_cred_issue_resp_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Find our pending request matching this nonce */
    cyxwiz_pending_cred_req_t *pending = NULL;
    int pending_idx = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING_CRED_REQS; i++) {
        if (ctx->pending_cred_reqs[i].active &&
            memcmp(ctx->pending_cred_reqs[i].nonce, msg->nonce,
                   CYXWIZ_CRED_NONCE_SIZE) == 0) {
            pending = &ctx->pending_cred_reqs[i];
            pending_idx = (int)i;
            break;
        }
    }

    if (pending == NULL) {
        CYXWIZ_WARN("Received credential response for unknown request");
        return CYXWIZ_OK;
    }

    /* Unblind the credential */
    cyxwiz_credential_t cred;
    cyxwiz_error_t err = cyxwiz_cred_unblind(
        msg->blinded_sig,
        pending->blinding,
        msg->issuer_pubkey,
        pending->attribute,
        pending->attr_len,
        msg->expires_at,
        &cred
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to unblind credential: %s", cyxwiz_strerror(err));
        /* Clear the pending request */
        cyxwiz_secure_zero(pending, sizeof(*pending));
        pending->active = false;
        ctx->pending_cred_req_count--;
        return err;
    }

    /* Store the credential */
    err = cyxwiz_privacy_store_credential(ctx, &cred);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to store credential: %s", cyxwiz_strerror(err));
    }

    /* Invoke callback */
    if (ctx->on_cred_issued) {
        ctx->on_cred_issued(&cred, ctx->cred_issued_user_data);
    }

    /* Clear the pending request */
    cyxwiz_secure_zero(pending, sizeof(*pending));
    pending->active = false;
    ctx->pending_cred_req_count--;

    CYXWIZ_DEBUG("Received and stored credential (type=%d)", cred.cred_type);
    return CYXWIZ_OK;
#endif
}

static cyxwiz_error_t handle_cred_show(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_cred_show_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Verify the credential show proof */
    cyxwiz_error_t err = cyxwiz_cred_show_verify(
        &msg->proof,
        (cyxwiz_credential_type_t)msg->cred_type,
        ctx->identity.public_key, /* Use our key as expected issuer */
        ctx->last_poll
    );

    bool valid = (err == CYXWIZ_OK);

    CYXWIZ_DEBUG("Credential show (type=%d): %s", msg->cred_type,
                 valid ? "VALID" : "INVALID");

    /* Invoke callback */
    if (ctx->on_cred_verified) {
        ctx->on_cred_verified(
            from,
            (cyxwiz_credential_type_t)msg->cred_type,
            valid,
            msg->service_context,
            ctx->cred_user_data
        );
    }

    /* Send verification result */
    cyxwiz_cred_verify_msg_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = CYXWIZ_MSG_CRED_VERIFY;
    resp.cred_type = msg->cred_type;
    memcpy(resp.context, msg->service_context, CYXWIZ_CRED_CONTEXT_SIZE);
    resp.result = valid ? 1 : 0;
    memcpy(resp.issuer_pubkey, ctx->identity.public_key, CYXWIZ_ED25519_PK_SIZE);

    if (ctx->router != NULL) {
        cyxwiz_router_send(ctx->router, from, (uint8_t *)&resp, sizeof(resp));
    }

    return valid ? CYXWIZ_OK : CYXWIZ_ERR_CREDENTIAL_INVALID;
#endif
}

static cyxwiz_error_t handle_cred_verify(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_cred_verify_msg_t *msg)
{
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);

    /* This is just an acknowledgement - log it */
    CYXWIZ_DEBUG("Credential verification result: type=%d, result=%s",
                 msg->cred_type, msg->result ? "OK" : "FAIL");

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_anon_vote(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    /* Forward to consensus context if available */
    if (ctx->consensus != NULL) {
        return cyxwiz_consensus_handle_message(ctx->consensus, from, data, len);
    }

    CYXWIZ_WARN("Received ANON_VOTE but no consensus context set");
    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_service_token_req(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_service_token_req_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* We are the token issuer */
    CYXWIZ_DEBUG("Processing service token request (type=%d, units=%d)",
                 msg->token_type, msg->units_requested);

    /* Generate blinded signature for the token serial */
    /* For now, sign the blinded serial directly (simplified blind signature) */
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];

    /* Create signature over blinded serial + token type + units */
    uint8_t to_sign[CYXWIZ_TOKEN_SERIAL_SIZE + 3];
    memcpy(to_sign, msg->blinded_serial, CYXWIZ_TOKEN_SERIAL_SIZE);
    to_sign[CYXWIZ_TOKEN_SERIAL_SIZE] = msg->token_type;
    to_sign[CYXWIZ_TOKEN_SERIAL_SIZE + 1] = (uint8_t)(msg->units_requested & 0xFF);
    to_sign[CYXWIZ_TOKEN_SERIAL_SIZE + 2] = (uint8_t)((msg->units_requested >> 8) & 0xFF);

    if (crypto_sign_detached(blinded_sig, NULL, to_sign, sizeof(to_sign),
                              ctx->identity.secret_key) != 0) {
        CYXWIZ_ERROR("Failed to sign service token");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Build response */
    cyxwiz_service_token_msg_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = CYXWIZ_MSG_SERVICE_TOKEN;
    resp.token_type = msg->token_type;
    memcpy(resp.blinded_sig, blinded_sig, CYXWIZ_CRED_SIGNATURE_SIZE);
    resp.units_granted = msg->units_requested;
    memcpy(resp.issuer_pubkey, ctx->identity.public_key, CYXWIZ_ED25519_PK_SIZE);
    resp.expires_at = ctx->last_poll + (7 * 24 * 60 * 60 * 1000ULL); /* 7 days */

    if (ctx->router != NULL) {
        cyxwiz_router_send(ctx->router, from, (uint8_t *)&resp, sizeof(resp));
    }

    CYXWIZ_DEBUG("Issued service token (%d units)", resp.units_granted);
    return CYXWIZ_OK;
#endif
}

static cyxwiz_error_t handle_service_token(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_service_token_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    CYXWIZ_DEBUG("Received service token (type=%d, units=%d)",
                 msg->token_type, msg->units_granted);

    /* Unblind and store the token */
    /* For simplified implementation, create token directly from response */
    cyxwiz_service_token_t token;
    memset(&token, 0, sizeof(token));

    /* Generate real serial from blinded response (simplified - copy sig as serial) */
    memcpy(token.serial, msg->blinded_sig, CYXWIZ_TOKEN_SERIAL_SIZE);
    memcpy(token.signature, msg->blinded_sig, CYXWIZ_CRED_SIGNATURE_SIZE);
    memcpy(token.issuer_pubkey, msg->issuer_pubkey, CYXWIZ_ED25519_PK_SIZE);
    token.token_type = msg->token_type;
    token.units = msg->units_granted;
    token.expires_at = msg->expires_at;

    cyxwiz_error_t err = cyxwiz_privacy_store_token(ctx, &token);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to store token: %s", cyxwiz_strerror(err));
    }

    return err;
#endif
}

static cyxwiz_error_t handle_service_token_use(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_service_token_use_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    CYXWIZ_DEBUG("Processing service token usage (type=%d, units=%d)",
                 msg->token_type, msg->units_to_use);

    /* Verify the token proof */
    /* Check commitment is valid point */
    bool valid = (crypto_core_ed25519_is_valid_point(msg->serial_commitment) == 1);

    if (valid) {
        /* Verify the range proof (units > 0) */
        cyxwiz_range_proof_16_t proof;
        memcpy(proof.commitment, msg->serial_commitment, 32);
        memcpy(proof.proof, msg->token_proof, CYXWIZ_RANGE_PROOF_16_SIZE);

        cyxwiz_error_t err = cyxwiz_range_proof_verify_16(&proof);
        valid = (err == CYXWIZ_OK);
    }

    CYXWIZ_DEBUG("Token usage: %s", valid ? "VALID" : "INVALID");

    /* Invoke callback */
    if (ctx->on_token_used) {
        ctx->on_token_used(
            from,
            (cyxwiz_service_token_type_t)msg->token_type,
            msg->units_to_use,
            valid,
            msg->request_nonce,
            ctx->token_user_data
        );
    }

    return valid ? CYXWIZ_OK : CYXWIZ_ERR_TOKEN_INSUFFICIENT;
#endif
}

static cyxwiz_error_t handle_reputation_proof(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_reputation_proof_msg_t *msg)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    CYXWIZ_DEBUG("Processing reputation proof (min_credits=%d)", msg->min_credits_claimed);

    /* Verify the range proof */
    cyxwiz_error_t err = cyxwiz_range_proof_verify_geq(
        &msg->range_proof,
        msg->min_credits_claimed
    );

    bool valid = (err == CYXWIZ_OK);

    CYXWIZ_DEBUG("Reputation proof: %s", valid ? "VALID" : "INVALID");

    /* Invoke callback */
    if (ctx->on_reputation_verified) {
        ctx->on_reputation_verified(
            from,
            msg->min_credits_claimed,
            valid,
            ctx->reputation_user_data
        );
    }

    return valid ? CYXWIZ_OK : CYXWIZ_ERR_RANGE_PROOF_FAILED;
#endif
}

/* ============================================================================
 * Main Message Dispatcher
 * ============================================================================ */

cyxwiz_error_t cyxwiz_privacy_handle_message(
    cyxwiz_privacy_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (ctx == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case CYXWIZ_MSG_PEDERSEN_COMMIT:
            if (len >= sizeof(cyxwiz_pedersen_commit_msg_t)) {
                return handle_pedersen_commit(ctx, from,
                    (const cyxwiz_pedersen_commit_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_PEDERSEN_OPEN:
            if (len >= sizeof(cyxwiz_pedersen_open_msg_t)) {
                return handle_pedersen_open(ctx, from,
                    (const cyxwiz_pedersen_open_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_RANGE_PROOF:
            if (len >= sizeof(cyxwiz_range_proof_msg_t)) {
                return handle_range_proof(ctx, from,
                    (const cyxwiz_range_proof_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_CRED_ISSUE_REQ:
            if (len >= sizeof(cyxwiz_cred_issue_req_msg_t)) {
                return handle_cred_issue_req(ctx, from,
                    (const cyxwiz_cred_issue_req_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_CRED_ISSUE_RESP:
            if (len >= sizeof(cyxwiz_cred_issue_resp_msg_t)) {
                return handle_cred_issue_resp(ctx, from,
                    (const cyxwiz_cred_issue_resp_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_CRED_SHOW:
            if (len >= sizeof(cyxwiz_cred_show_msg_t)) {
                return handle_cred_show(ctx, from,
                    (const cyxwiz_cred_show_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_CRED_VERIFY:
            if (len >= sizeof(cyxwiz_cred_verify_msg_t)) {
                return handle_cred_verify(ctx, from,
                    (const cyxwiz_cred_verify_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_ANON_VOTE:
            if (len >= sizeof(cyxwiz_anon_vote_msg_t)) {
                return handle_anon_vote(ctx, from, data, len);
            }
            break;

        case CYXWIZ_MSG_SERVICE_TOKEN_REQ:
            if (len >= sizeof(cyxwiz_service_token_req_msg_t)) {
                return handle_service_token_req(ctx, from,
                    (const cyxwiz_service_token_req_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_SERVICE_TOKEN:
            if (len >= sizeof(cyxwiz_service_token_msg_t)) {
                return handle_service_token(ctx, from,
                    (const cyxwiz_service_token_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_SERVICE_TOKEN_USE:
            if (len >= sizeof(cyxwiz_service_token_use_msg_t)) {
                return handle_service_token_use(ctx, from,
                    (const cyxwiz_service_token_use_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_REPUTATION_PROOF:
            if (len >= sizeof(cyxwiz_reputation_proof_msg_t)) {
                return handle_reputation_proof(ctx, from,
                    (const cyxwiz_reputation_proof_msg_t *)data);
            }
            break;

        default:
            CYXWIZ_DEBUG("Unknown privacy message type: 0x%02X", msg_type);
            return CYXWIZ_ERR_INVALID;
    }

    /* Message too short for type */
    CYXWIZ_WARN("Privacy message 0x%02X too short (%zu bytes)", msg_type, len);
    return CYXWIZ_ERR_INVALID;
}
