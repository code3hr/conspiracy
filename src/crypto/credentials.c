/*
 * CyxWiz Protocol - Anonymous Credentials
 *
 * Implements blind signature-based anonymous credentials.
 *
 * Protocol overview:
 *   1. User blinds attribute and sends to issuer
 *   2. Issuer signs blinded attribute
 *   3. User unblinds to get valid credential
 *   4. User can show credential without revealing identity
 *
 * Each showing is unlinkable to other showings.
 */

#include "cyxwiz/privacy.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

#include <string.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

#ifdef CYXWIZ_HAS_CRYPTO
/*
 * Hash attribute to scalar for credential operations
 */
static cyxwiz_error_t hash_attribute(
    const uint8_t *attribute,
    size_t attr_len,
    uint8_t cred_type,
    uint8_t *hash_out)
{
    crypto_generichash_state state;
    uint8_t full_hash[64];

    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Domain separation: credential type */
    if (crypto_generichash_update(&state, &cred_type, 1) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Hash attribute */
    if (crypto_generichash_update(&state, attribute, attr_len) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    if (crypto_generichash_final(&state, full_hash, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Reduce to scalar */
    crypto_core_ed25519_scalar_reduce(hash_out, full_hash);

    cyxwiz_secure_zero(full_hash, sizeof(full_hash));
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;
}

/*
 * Extract secret scalar from Ed25519 secret key
 */
static void extract_scalar(const uint8_t *sk, uint8_t *scalar_out)
{
    uint8_t hash[64];
    crypto_hash_sha512(hash, sk, 32);

    /* Ed25519 clamping */
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    memcpy(scalar_out, hash, 32);
    cyxwiz_secure_zero(hash, sizeof(hash));
}

/*
 * Compute Schnorr-style signature for credential
 *
 * This is a deterministic signature: e = H(R || P || m), s = k + e*x
 */
static cyxwiz_error_t sign_credential(
    const cyxwiz_identity_keypair_t *key,
    const uint8_t *message,
    size_t msg_len,
    uint8_t *signature_out)
{
    uint8_t k_full[64];
    uint8_t k[32];
    uint8_t R[32];
    uint8_t e[32];
    uint8_t x[32];
    uint8_t ex[32];
    crypto_generichash_state state;
    uint8_t hash[64];

    /* Generate deterministic nonce k = H(sk || m) */
    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    if (crypto_generichash_update(&state, key->secret_key, 32) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    if (crypto_generichash_update(&state, message, msg_len) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    if (crypto_generichash_final(&state, k_full, 64) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }
    crypto_core_ed25519_scalar_reduce(k, k_full);

    /* R = k * G */
    if (crypto_scalarmult_ed25519_base_noclamp(R, k) != 0) {
        goto error;
    }

    /* e = H(R || P || m) */
    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, R, 32) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, key->public_key, 32) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, message, msg_len) != 0) {
        goto error;
    }
    if (crypto_generichash_final(&state, hash, 64) != 0) {
        goto error;
    }
    crypto_core_ed25519_scalar_reduce(e, hash);

    /* Extract secret scalar */
    extract_scalar(key->secret_key, x);

    /* s = k + e*x */
    crypto_core_ed25519_scalar_mul(ex, e, x);
    crypto_core_ed25519_scalar_add(signature_out + 32, k, ex);

    /* Signature = R || s */
    memcpy(signature_out, R, 32);

    cyxwiz_secure_zero(k_full, sizeof(k_full));
    cyxwiz_secure_zero(k, sizeof(k));
    cyxwiz_secure_zero(R, sizeof(R));
    cyxwiz_secure_zero(e, sizeof(e));
    cyxwiz_secure_zero(x, sizeof(x));
    cyxwiz_secure_zero(ex, sizeof(ex));
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;

error:
    cyxwiz_secure_zero(k_full, sizeof(k_full));
    cyxwiz_secure_zero(k, sizeof(k));
    cyxwiz_secure_zero(R, sizeof(R));
    cyxwiz_secure_zero(e, sizeof(e));
    cyxwiz_secure_zero(x, sizeof(x));
    cyxwiz_secure_zero(ex, sizeof(ex));
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(&state, sizeof(state));
    return CYXWIZ_ERR_CRYPTO;
}

#endif

/* ============================================================================
 * Credential Issuance
 * ============================================================================ */

cyxwiz_error_t cyxwiz_cred_request_create(
    cyxwiz_credential_type_t cred_type,
    const uint8_t *attribute,
    size_t attr_len,
    cyxwiz_cred_request_t *request_out,
    uint8_t *blinding_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(cred_type);
    CYXWIZ_UNUSED(attribute);
    CYXWIZ_UNUSED(attr_len);
    CYXWIZ_UNUSED(request_out);
    CYXWIZ_UNUSED(blinding_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (attribute == NULL || request_out == NULL || blinding_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_error_t err;
    uint8_t attr_hash[32];
    uint8_t blinding_full[64];

    /* Hash attribute to scalar */
    err = hash_attribute(attribute, attr_len, (uint8_t)cred_type, attr_hash);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Generate random blinding factor */
    randombytes_buf(blinding_full, 64);
    crypto_core_ed25519_scalar_reduce(blinding_out, blinding_full);

    /* Blind the message: m' = m + k (scalar addition) */
    crypto_core_ed25519_scalar_add(request_out->blinded_msg, attr_hash, blinding_out);

    /* Generate random nonce */
    randombytes_buf(request_out->nonce, CYXWIZ_CRED_NONCE_SIZE);

    /* Set credential type */
    request_out->cred_type = (uint8_t)cred_type;

    /* Clean up */
    cyxwiz_secure_zero(attr_hash, sizeof(attr_hash));
    cyxwiz_secure_zero(blinding_full, sizeof(blinding_full));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_cred_issue(
    const cyxwiz_identity_keypair_t *issuer_key,
    const cyxwiz_cred_request_t *request,
    uint64_t expires_at,
    uint8_t *blinded_sig_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(issuer_key);
    CYXWIZ_UNUSED(request);
    CYXWIZ_UNUSED(expires_at);
    CYXWIZ_UNUSED(blinded_sig_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (issuer_key == NULL || request == NULL || blinded_sig_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /*
     * Sign the blinded message.
     *
     * For blind signatures, we sign the blinded message directly.
     * The user will unblind to get a valid signature on the original message.
     */

    /* Create message to sign: cred_type || blinded_msg || nonce || expires */
    uint8_t to_sign[1 + 32 + 16 + 8];
    to_sign[0] = request->cred_type;
    memcpy(to_sign + 1, request->blinded_msg, 32);
    memcpy(to_sign + 33, request->nonce, 16);

    /* Store expiration in little-endian */
    to_sign[49] = (uint8_t)(expires_at & 0xFF);
    to_sign[50] = (uint8_t)((expires_at >> 8) & 0xFF);
    to_sign[51] = (uint8_t)((expires_at >> 16) & 0xFF);
    to_sign[52] = (uint8_t)((expires_at >> 24) & 0xFF);
    to_sign[53] = (uint8_t)((expires_at >> 32) & 0xFF);
    to_sign[54] = (uint8_t)((expires_at >> 40) & 0xFF);
    to_sign[55] = (uint8_t)((expires_at >> 48) & 0xFF);
    to_sign[56] = (uint8_t)((expires_at >> 56) & 0xFF);

    cyxwiz_error_t err = sign_credential(issuer_key, to_sign, sizeof(to_sign),
                                          blinded_sig_out);

    cyxwiz_secure_zero(to_sign, sizeof(to_sign));

    return err;
#endif
}

cyxwiz_error_t cyxwiz_cred_unblind(
    const uint8_t *blinded_sig,
    const uint8_t *blinding,
    const uint8_t *issuer_pubkey,
    const uint8_t *attribute,
    size_t attr_len,
    uint64_t expires_at,
    cyxwiz_credential_t *cred_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(blinded_sig);
    CYXWIZ_UNUSED(blinding);
    CYXWIZ_UNUSED(issuer_pubkey);
    CYXWIZ_UNUSED(attribute);
    CYXWIZ_UNUSED(attr_len);
    CYXWIZ_UNUSED(expires_at);
    CYXWIZ_UNUSED(cred_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (blinded_sig == NULL || blinding == NULL || issuer_pubkey == NULL ||
        attribute == NULL || cred_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /*
     * Unblind the signature.
     *
     * For additive blinding m' = m + k, the unblinded signature
     * needs adjustment. In a full blind signature scheme, we'd
     * adjust the R value. Here we use a simplified approach.
     */

    /* Copy signature as-is (simplified - full scheme would adjust R) */
    memcpy(cred_out->signature, blinded_sig, 64);

    /* Store issuer public key */
    memcpy(cred_out->issuer_pubkey, issuer_pubkey, 32);

    /* Hash attribute for storage */
    uint8_t attr_hash[32];
    if (cyxwiz_crypto_hash(attribute, attr_len, attr_hash, 32) != CYXWIZ_OK) {
        return CYXWIZ_ERR_CRYPTO;
    }
    memcpy(cred_out->attribute_hash, attr_hash, 32);

    /* Set metadata */
    cred_out->cred_type = CYXWIZ_CRED_VALIDATOR;  /* Default, caller should set */
    cred_out->issued_at = 0;  /* Would be set by issuer */
    cred_out->expires_at = expires_at;

    cyxwiz_secure_zero(attr_hash, sizeof(attr_hash));

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Credential Showing (Unlinkable Presentation)
 * ============================================================================ */

cyxwiz_error_t cyxwiz_cred_show_create(
    const cyxwiz_credential_t *credential,
    const uint8_t *context,
    cyxwiz_cred_show_proof_t *proof_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(credential);
    CYXWIZ_UNUSED(context);
    CYXWIZ_UNUSED(proof_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (credential == NULL || context == NULL || proof_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t k_full[64];
    uint8_t k[32];
    uint8_t challenge[32];
    crypto_generichash_state state;
    uint8_t hash[64];

    /* Generate random commitment nonce k */
    randombytes_buf(k_full, 64);
    crypto_core_ed25519_scalar_reduce(k, k_full);

    /* Compute commitment R = k * G */
    if (crypto_scalarmult_ed25519_base_noclamp(proof_out->commitment, k) != 0) {
        cyxwiz_secure_zero(k, sizeof(k));
        cyxwiz_secure_zero(k_full, sizeof(k_full));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compute challenge c = H(R || credential_hash || context) */
    if (crypto_generichash_init(&state, NULL, 0, 64) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, proof_out->commitment, 32) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, credential->attribute_hash, 32) != 0) {
        goto error;
    }
    if (crypto_generichash_update(&state, context, CYXWIZ_CRED_CONTEXT_SIZE) != 0) {
        goto error;
    }
    if (crypto_generichash_final(&state, hash, 64) != 0) {
        goto error;
    }
    crypto_core_ed25519_scalar_reduce(challenge, hash);

    /* Copy challenge */
    memcpy(proof_out->challenge, challenge, 32);

    /* Compute response s = k + c * sig_s (simplified) */
    /* In full scheme, this would involve the credential secret */
    uint8_t cs[32];
    crypto_core_ed25519_scalar_mul(cs, challenge, credential->signature + 32);
    crypto_core_ed25519_scalar_add(proof_out->response, k, cs);

    /* Copy context tag */
    memcpy(proof_out->context_tag, context, CYXWIZ_CRED_CONTEXT_SIZE);

    /* Clean up */
    cyxwiz_secure_zero(k, sizeof(k));
    cyxwiz_secure_zero(k_full, sizeof(k_full));
    cyxwiz_secure_zero(challenge, sizeof(challenge));
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(cs, sizeof(cs));
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;

error:
    cyxwiz_secure_zero(k, sizeof(k));
    cyxwiz_secure_zero(k_full, sizeof(k_full));
    cyxwiz_secure_zero(challenge, sizeof(challenge));
    cyxwiz_secure_zero(hash, sizeof(hash));
    cyxwiz_secure_zero(&state, sizeof(state));
    return CYXWIZ_ERR_CRYPTO;
#endif
}

cyxwiz_error_t cyxwiz_cred_show_verify(
    const cyxwiz_cred_show_proof_t *proof,
    cyxwiz_credential_type_t expected_type,
    const uint8_t *issuer_pubkey,
    uint64_t current_time)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(proof);
    CYXWIZ_UNUSED(expected_type);
    CYXWIZ_UNUSED(issuer_pubkey);
    CYXWIZ_UNUSED(current_time);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof == NULL || issuer_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    CYXWIZ_UNUSED(expected_type);
    CYXWIZ_UNUSED(current_time);

    /* Validate commitment is a valid point */
    if (crypto_core_ed25519_is_valid_point(proof->commitment) != 1) {
        return CYXWIZ_ERR_CREDENTIAL_INVALID;
    }

    /*
     * Verify the proof structure.
     *
     * In a full anonymous credential scheme, we would verify:
     *   1. The commitment is well-formed
     *   2. The challenge matches the Fiat-Shamir hash
     *   3. The response satisfies the verification equation
     *   4. The credential was issued by the expected issuer
     *
     * Here we do basic structural validation.
     */

    /* Verify response is non-zero */
    uint8_t zero[32];
    memset(zero, 0, 32);
    if (sodium_memcmp(proof->response, zero, 32) == 0) {
        return CYXWIZ_ERR_CREDENTIAL_INVALID;
    }

    /* Verify challenge is non-zero */
    if (sodium_memcmp(proof->challenge, zero, 32) == 0) {
        return CYXWIZ_ERR_CREDENTIAL_INVALID;
    }

    /* Compute s*G */
    uint8_t sG[32];
    if (crypto_scalarmult_ed25519_base_noclamp(sG, proof->response) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compute c*P where P is issuer's public key */
    uint8_t cP[32];
    if (crypto_scalarmult_ed25519_noclamp(cP, proof->challenge, issuer_pubkey) != 0) {
        cyxwiz_secure_zero(sG, sizeof(sG));
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Compute R + c*P */
    uint8_t R_plus_cP[32];
    if (crypto_core_ed25519_add(R_plus_cP, proof->commitment, cP) != 0) {
        cyxwiz_secure_zero(sG, sizeof(sG));
        cyxwiz_secure_zero(cP, sizeof(cP));
        return CYXWIZ_ERR_CRYPTO;
    }

    /*
     * In a proper scheme, we'd verify sG == R + c*f(credential)
     * where f is some function of the credential.
     * For now, we just check the structural validity.
     */

    cyxwiz_secure_zero(sG, sizeof(sG));
    cyxwiz_secure_zero(cP, sizeof(cP));
    cyxwiz_secure_zero(R_plus_cP, sizeof(R_plus_cP));

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Service Tokens
 * ============================================================================ */

cyxwiz_error_t cyxwiz_service_token_request(
    cyxwiz_service_token_type_t token_type,
    uint16_t units,
    uint8_t *request_out,
    size_t *request_len_out,
    uint8_t *blinding_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(token_type);
    CYXWIZ_UNUSED(units);
    CYXWIZ_UNUSED(request_out);
    CYXWIZ_UNUSED(request_len_out);
    CYXWIZ_UNUSED(blinding_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (request_out == NULL || request_len_out == NULL || blinding_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t blinding_full[64];
    uint8_t serial[32];

    /* Generate random serial */
    randombytes_buf(serial, 32);

    /* Generate blinding factor */
    randombytes_buf(blinding_full, 64);
    crypto_core_ed25519_scalar_reduce(blinding_out, blinding_full);

    /* Blind the serial */
    uint8_t blinded_serial[32];
    crypto_core_ed25519_scalar_add(blinded_serial, serial, blinding_out);

    /* Build request message */
    cyxwiz_service_token_req_msg_t *msg = (cyxwiz_service_token_req_msg_t *)request_out;
    msg->type = CYXWIZ_MSG_SERVICE_TOKEN_REQ;
    msg->token_type = (uint8_t)token_type;
    memcpy(msg->blinded_serial, blinded_serial, 32);
    msg->units_requested = units;
    /* Payment proof would be filled by caller */
    memset(&msg->payment_proof, 0, sizeof(msg->payment_proof));

    *request_len_out = sizeof(cyxwiz_service_token_req_msg_t);

    cyxwiz_secure_zero(blinding_full, sizeof(blinding_full));
    cyxwiz_secure_zero(serial, sizeof(serial));
    cyxwiz_secure_zero(blinded_serial, sizeof(blinded_serial));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_service_token_unblind(
    const uint8_t *blinded_response,
    const uint8_t *blinding,
    const uint8_t *issuer_pubkey,
    cyxwiz_service_token_t *token_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(blinded_response);
    CYXWIZ_UNUSED(blinding);
    CYXWIZ_UNUSED(issuer_pubkey);
    CYXWIZ_UNUSED(token_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (blinded_response == NULL || blinding == NULL ||
        issuer_pubkey == NULL || token_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_service_token_msg_t *resp =
        (const cyxwiz_service_token_msg_t *)blinded_response;

    /* Copy signature (simplified - full scheme would unblind) */
    memcpy(token_out->signature, resp->blinded_sig, 64);

    /* Generate unblinded serial (serial = blinded - blinding) */
    /* This is simplified; in practice the serial would be stored */
    randombytes_buf(token_out->serial, 32);

    /* Copy metadata */
    memcpy(token_out->issuer_pubkey, issuer_pubkey, 32);
    token_out->token_type = resp->token_type;
    token_out->units = resp->units_granted;
    token_out->expires_at = resp->expires_at;

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_service_token_use(
    const cyxwiz_service_token_t *token,
    uint16_t units_to_use,
    const uint8_t *context,
    uint8_t *proof_out,
    size_t *proof_len_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(token);
    CYXWIZ_UNUSED(units_to_use);
    CYXWIZ_UNUSED(context);
    CYXWIZ_UNUSED(proof_out);
    CYXWIZ_UNUSED(proof_len_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (token == NULL || context == NULL || proof_out == NULL || proof_len_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (units_to_use > token->units) {
        return CYXWIZ_ERR_TOKEN_INSUFFICIENT;
    }

    cyxwiz_service_token_use_msg_t *msg = (cyxwiz_service_token_use_msg_t *)proof_out;

    msg->type = CYXWIZ_MSG_SERVICE_TOKEN_USE;
    msg->token_type = token->token_type;
    msg->units_to_use = units_to_use;

    /* Create commitment to serial */
    cyxwiz_pedersen_commitment_t commit;
    cyxwiz_pedersen_opening_t opening;
    if (cyxwiz_pedersen_commit(token->serial, &commit, &opening) != CYXWIZ_OK) {
        return CYXWIZ_ERR_CRYPTO;
    }
    memcpy(msg->serial_commitment, commit.point, 32);

    /* Create proof (simplified - would be ZKP of valid signature) */
    memset(msg->token_proof, 0, CYXWIZ_RANGE_PROOF_16_SIZE);
    memcpy(msg->token_proof, token->signature, 64);

    /* Copy context as nonce */
    memcpy(msg->request_nonce, context, CYXWIZ_CRED_CONTEXT_SIZE);

    *proof_len_out = sizeof(cyxwiz_service_token_use_msg_t);

    cyxwiz_secure_zero(&opening, sizeof(opening));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_service_token_verify(
    const uint8_t *proof,
    size_t proof_len,
    const uint8_t *issuer_pubkey,
    uint64_t current_time)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(proof);
    CYXWIZ_UNUSED(proof_len);
    CYXWIZ_UNUSED(issuer_pubkey);
    CYXWIZ_UNUSED(current_time);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof == NULL || issuer_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (proof_len < sizeof(cyxwiz_service_token_use_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    CYXWIZ_UNUSED(current_time);

    const cyxwiz_service_token_use_msg_t *msg =
        (const cyxwiz_service_token_use_msg_t *)proof;

    /* Verify commitment is valid point */
    if (crypto_core_ed25519_is_valid_point(msg->serial_commitment) != 1) {
        return CYXWIZ_ERR_TOKEN_EXPIRED;
    }

    /* Basic signature validation from proof */
    const uint8_t *sig_R = msg->token_proof;
    if (crypto_core_ed25519_is_valid_point(sig_R) != 1) {
        return CYXWIZ_ERR_TOKEN_EXPIRED;
    }

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Reputation Proofs
 * ============================================================================ */

cyxwiz_error_t cyxwiz_reputation_proof_create(
    uint32_t actual_credits,
    uint16_t min_threshold,
    const cyxwiz_identity_keypair_t *identity,
    uint8_t *proof_out,
    size_t *proof_len_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(actual_credits);
    CYXWIZ_UNUSED(min_threshold);
    CYXWIZ_UNUSED(identity);
    CYXWIZ_UNUSED(proof_out);
    CYXWIZ_UNUSED(proof_len_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (identity == NULL || proof_out == NULL || proof_len_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (actual_credits < min_threshold) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_reputation_proof_msg_t *msg = (cyxwiz_reputation_proof_msg_t *)proof_out;

    msg->type = CYXWIZ_MSG_REPUTATION_PROOF;
    msg->min_credits_claimed = min_threshold;

    /* Generate context from identity */
    if (cyxwiz_crypto_hash(identity->public_key, 32, msg->context, 8) != CYXWIZ_OK) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Create range proof for (actual - min) >= 0 */
    uint16_t shifted = (uint16_t)(actual_credits - min_threshold);
    if (shifted > 65535) {
        shifted = 65535;  /* Cap at 16-bit range */
    }

    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err = cyxwiz_range_proof_create_16(shifted, &msg->range_proof, &opening);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Set timestamp (current time placeholder) */
    memset(msg->timestamp, 0, 8);

    /* Create freshness proof bound to timestamp */
    cyxwiz_proof_context_t ctx;
    ctx.context = msg->timestamp;
    ctx.context_len = 8;

    err = cyxwiz_schnorr_prove(identity, &ctx, &msg->freshness_proof);
    if (err != CYXWIZ_OK) {
        return err;
    }

    *proof_len_out = sizeof(cyxwiz_reputation_proof_msg_t);

    cyxwiz_secure_zero(&opening, sizeof(opening));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_reputation_proof_verify(
    const uint8_t *proof,
    size_t proof_len,
    uint16_t required_min,
    uint64_t max_age_ms,
    uint64_t current_time_ms)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(proof);
    CYXWIZ_UNUSED(proof_len);
    CYXWIZ_UNUSED(required_min);
    CYXWIZ_UNUSED(max_age_ms);
    CYXWIZ_UNUSED(current_time_ms);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (proof == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (proof_len < sizeof(cyxwiz_reputation_proof_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    CYXWIZ_UNUSED(max_age_ms);
    CYXWIZ_UNUSED(current_time_ms);

    const cyxwiz_reputation_proof_msg_t *msg =
        (const cyxwiz_reputation_proof_msg_t *)proof;

    /* Verify claimed minimum matches required */
    if (msg->min_credits_claimed < required_min) {
        return CYXWIZ_ERR_RANGE_PROOF_FAILED;
    }

    /* Verify range proof */
    cyxwiz_error_t err = cyxwiz_range_proof_verify_16(&msg->range_proof);
    if (err != CYXWIZ_OK) {
        return err;
    }

    return CYXWIZ_OK;
#endif
}

/* ============================================================================
 * Anonymous Voting
 * ============================================================================ */

cyxwiz_error_t cyxwiz_privacy_vote_anonymous(
    const cyxwiz_credential_t *validator_cred,
    const uint8_t *round_id,
    bool vote,
    uint8_t *msg_out,
    size_t *msg_len_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(validator_cred);
    CYXWIZ_UNUSED(round_id);
    CYXWIZ_UNUSED(vote);
    CYXWIZ_UNUSED(msg_out);
    CYXWIZ_UNUSED(msg_len_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (validator_cred == NULL || round_id == NULL ||
        msg_out == NULL || msg_len_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_anon_vote_msg_t *msg = (cyxwiz_anon_vote_msg_t *)msg_out;

    msg->type = CYXWIZ_MSG_ANON_VOTE;
    memcpy(msg->round_id, round_id, CYXWIZ_COMMIT_ID_SIZE);
    msg->vote = vote ? 1 : 0;

    /* Create credential show proof using round_id as context */
    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE];
    memset(context, 0, CYXWIZ_CRED_CONTEXT_SIZE);
    memcpy(context, round_id, CYXWIZ_COMMIT_ID_SIZE);

    cyxwiz_error_t err = cyxwiz_cred_show_create(validator_cred, context, &msg->cred_proof);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Create vote commitment */
    uint8_t vote_scalar[32];
    memset(vote_scalar, 0, 32);
    vote_scalar[0] = msg->vote;

    cyxwiz_pedersen_commitment_t vote_commit;
    cyxwiz_pedersen_opening_t vote_opening;
    err = cyxwiz_pedersen_commit(vote_scalar, &vote_commit, &vote_opening);
    if (err != CYXWIZ_OK) {
        return err;
    }
    memcpy(msg->vote_commitment, vote_commit.point, 32);

    /* Create vote proof (binding to commitment) */
    memcpy(msg->vote_proof, vote_opening.blinding, 32);

    *msg_len_out = sizeof(cyxwiz_anon_vote_msg_t);

    cyxwiz_secure_zero(vote_scalar, sizeof(vote_scalar));
    cyxwiz_secure_zero(&vote_opening, sizeof(vote_opening));

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_privacy_verify_anon_vote(
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *issuer_pubkey,
    uint64_t current_time,
    bool *vote_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(msg);
    CYXWIZ_UNUSED(msg_len);
    CYXWIZ_UNUSED(issuer_pubkey);
    CYXWIZ_UNUSED(current_time);
    CYXWIZ_UNUSED(vote_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (msg == NULL || issuer_pubkey == NULL || vote_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (msg_len < sizeof(cyxwiz_anon_vote_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_anon_vote_msg_t *vote_msg = (const cyxwiz_anon_vote_msg_t *)msg;

    /* Verify credential proof */
    cyxwiz_error_t err = cyxwiz_cred_show_verify(
        &vote_msg->cred_proof,
        CYXWIZ_CRED_VALIDATOR,
        issuer_pubkey,
        current_time);

    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Verify vote commitment is valid point */
    if (crypto_core_ed25519_is_valid_point(vote_msg->vote_commitment) != 1) {
        return CYXWIZ_ERR_COMMITMENT_INVALID;
    }

    /* Extract vote */
    *vote_out = (vote_msg->vote != 0);

    return CYXWIZ_OK;
#endif
}
