/*
 * CyxWiz Protocol - Crypto Context Management
 *
 * Manages crypto state including:
 * - MAC keys for SPDZ verification
 * - Threshold and party configuration
 * - Context creation and destruction
 */

#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <sodium.h>
#include <string.h>

/*
 * Crypto context structure
 */
struct cyxwiz_crypto_ctx {
    uint8_t mac_key[CYXWIZ_MAC_KEY_SIZE];   /* Global MAC key (alpha in SPDZ) */
    uint8_t threshold;                       /* K - minimum shares needed */
    uint8_t num_parties;                     /* N - total parties */
    uint8_t my_party_id;                     /* This node's ID (1..N) */
    bool initialized;
};

/*
 * Get MAC key from context (used by mac.c)
 */
const uint8_t *cyxwiz_crypto_get_mac_key(const cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return NULL;
    }
    return ctx->mac_key;
}

/*
 * Create a new crypto context
 */
cyxwiz_error_t cyxwiz_crypto_create(
    cyxwiz_crypto_ctx_t **ctx,
    uint8_t threshold,
    uint8_t num_parties,
    uint8_t my_party_id)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Validate parameters (upper bound check is implicit since uint8_t max = 255 = CYXWIZ_MAX_PARTIES) */
    if (num_parties < 2) {
        CYXWIZ_ERROR("Invalid num_parties: %d (must be 2-%d)", num_parties, CYXWIZ_MAX_PARTIES);
        return CYXWIZ_ERR_INVALID;
    }

    if (threshold < 1 || threshold > num_parties) {
        CYXWIZ_ERROR("Invalid threshold: %d (must be 1-%d)", threshold, num_parties);
        return CYXWIZ_ERR_INVALID;
    }

    if (my_party_id < 1 || my_party_id > num_parties) {
        CYXWIZ_ERROR("Invalid party_id: %d (must be 1-%d)", my_party_id, num_parties);
        return CYXWIZ_ERR_INVALID;
    }

    /* Allocate context */
    cyxwiz_crypto_ctx_t *new_ctx = cyxwiz_calloc(1, sizeof(cyxwiz_crypto_ctx_t));
    if (new_ctx == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* Generate random MAC key */
    cyxwiz_crypto_random(new_ctx->mac_key, CYXWIZ_MAC_KEY_SIZE);

    new_ctx->threshold = threshold;
    new_ctx->num_parties = num_parties;
    new_ctx->my_party_id = my_party_id;
    new_ctx->initialized = true;

    *ctx = new_ctx;

    CYXWIZ_INFO("Created crypto context: %d-of-%d, party %d",
               threshold, num_parties, my_party_id);

    return CYXWIZ_OK;
}

/*
 * Destroy crypto context
 */
void cyxwiz_crypto_destroy(cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Securely zero all sensitive data */
    cyxwiz_secure_zero(ctx->mac_key, CYXWIZ_MAC_KEY_SIZE);
    ctx->initialized = false;

    cyxwiz_free(ctx, sizeof(cyxwiz_crypto_ctx_t));

    CYXWIZ_DEBUG("Destroyed crypto context");
}

/*
 * Get threshold
 */
uint8_t cyxwiz_crypto_get_threshold(const cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->threshold;
}

/*
 * Get number of parties
 */
uint8_t cyxwiz_crypto_get_num_parties(const cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->num_parties;
}

/*
 * Get this node's party ID
 */
uint8_t cyxwiz_crypto_get_party_id(const cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->my_party_id;
}

/*
 * Refresh the MAC key for forward secrecy
 */
cyxwiz_error_t cyxwiz_crypto_refresh_key(cyxwiz_crypto_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!ctx->initialized) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Securely zero old key before generating new one */
    cyxwiz_secure_zero(ctx->mac_key, CYXWIZ_MAC_KEY_SIZE);

    /* Generate new random MAC key */
    cyxwiz_crypto_random(ctx->mac_key, CYXWIZ_MAC_KEY_SIZE);

    CYXWIZ_INFO("Refreshed MPC MAC key");

    return CYXWIZ_OK;
}

/*
 * Verify a share's MAC
 */
cyxwiz_error_t cyxwiz_crypto_verify_share(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *share)
{
    if (ctx == NULL || share == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!ctx->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Compute expected MAC */
    uint8_t computed_mac[CYXWIZ_MAC_SIZE];
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, share->value, computed_mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Constant-time comparison */
    if (cyxwiz_secure_compare(computed_mac, share->mac, CYXWIZ_MAC_SIZE) != 0) {
        CYXWIZ_WARN("MAC verification failed for party %d share", share->party_id);
        cyxwiz_secure_zero(computed_mac, sizeof(computed_mac));
        return CYXWIZ_ERR_CRYPTO;
    }

    cyxwiz_secure_zero(computed_mac, sizeof(computed_mac));
    return CYXWIZ_OK;
}
