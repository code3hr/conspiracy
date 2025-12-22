/*
 * CyxWiz Protocol - Crypto Layer (SPDZ-based MPC)
 *
 * Implements multi-party computation with:
 * - Additive secret sharing with MACs
 * - Threshold reconstruction (default 3-of-5)
 * - libsodium for cryptographic primitives
 */

#ifndef CYXWIZ_CRYPTO_H
#define CYXWIZ_CRYPTO_H

#include "types.h"

/* Key and share sizes */
#define CYXWIZ_KEY_SIZE 32              /* 256-bit keys */
#define CYXWIZ_MAC_KEY_SIZE 32          /* MAC key size */
#define CYXWIZ_MAC_SIZE 16              /* MAC tag size */
#define CYXWIZ_NONCE_SIZE 24            /* Nonce for secretbox */
#define CYXWIZ_AUTH_TAG_SIZE 16         /* Auth tag for secretbox */

/* Encryption overhead: nonce + auth tag */
#define CYXWIZ_CRYPTO_OVERHEAD (CYXWIZ_NONCE_SIZE + CYXWIZ_AUTH_TAG_SIZE)

/* Default MPC parameters */
#define CYXWIZ_DEFAULT_THRESHOLD 3
#define CYXWIZ_DEFAULT_PARTIES 5
#define CYXWIZ_MAX_PARTIES 255

/*
 * Secret share with MAC for integrity verification
 * Total size: 49 bytes (fits comfortably in 250-byte LoRa packets)
 */
typedef struct {
    uint8_t value[CYXWIZ_KEY_SIZE];     /* Additive share value */
    uint8_t mac[CYXWIZ_MAC_SIZE];       /* SPDZ-style MAC */
    uint8_t party_id;                    /* Owning party (1-indexed) */
} cyxwiz_share_t;

/*
 * Crypto context - opaque structure
 * Holds MAC keys, threshold config, party identity
 */
typedef struct cyxwiz_crypto_ctx cyxwiz_crypto_ctx_t;

/*
 * Global initialization - call once at startup
 * Initializes libsodium
 */
cyxwiz_error_t cyxwiz_crypto_init(void);

/*
 * Create a crypto context for MPC operations
 *
 * @param ctx           Output context pointer
 * @param threshold     Minimum shares needed to reconstruct (K)
 * @param num_parties   Total number of parties (N)
 * @param my_party_id   This node's party ID (1-indexed, 1..N)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_crypto_create(
    cyxwiz_crypto_ctx_t **ctx,
    uint8_t threshold,
    uint8_t num_parties,
    uint8_t my_party_id
);

/*
 * Destroy a crypto context, securely zeroing all keys
 */
void cyxwiz_crypto_destroy(cyxwiz_crypto_ctx_t *ctx);

/*
 * Get context parameters
 */
uint8_t cyxwiz_crypto_get_threshold(const cyxwiz_crypto_ctx_t *ctx);
uint8_t cyxwiz_crypto_get_num_parties(const cyxwiz_crypto_ctx_t *ctx);
uint8_t cyxwiz_crypto_get_party_id(const cyxwiz_crypto_ctx_t *ctx);

/* ============ Secret Sharing ============ */

/*
 * Split a secret into shares using additive sharing
 * Each share gets a MAC for integrity verification
 *
 * @param ctx           Crypto context
 * @param secret        Secret to share (must be CYXWIZ_KEY_SIZE bytes)
 * @param secret_len    Length of secret (must be CYXWIZ_KEY_SIZE)
 * @param shares_out    Output array (must have num_parties elements)
 * @param num_shares    Output: number of shares created
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_crypto_share_secret(
    cyxwiz_crypto_ctx_t *ctx,
    const uint8_t *secret,
    size_t secret_len,
    cyxwiz_share_t *shares_out,
    size_t *num_shares
);

/*
 * Reconstruct a secret from threshold shares
 * Uses Lagrange interpolation for threshold reconstruction
 *
 * @param ctx           Crypto context
 * @param shares        Array of shares (need at least threshold shares)
 * @param num_shares    Number of shares provided
 * @param secret_out    Output buffer (must be CYXWIZ_KEY_SIZE bytes)
 * @param secret_len    Size of output buffer
 * @return              CYXWIZ_OK on success, CYXWIZ_ERR_CRYPTO if invalid
 */
cyxwiz_error_t cyxwiz_crypto_reconstruct_secret(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *shares,
    size_t num_shares,
    uint8_t *secret_out,
    size_t secret_len
);

/* ============ Share Operations (Local) ============ */

/*
 * Add two shares (result = a + b)
 * This is a local operation - no communication needed
 * Context is needed to recompute the MAC for the result
 */
cyxwiz_error_t cyxwiz_crypto_share_add(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *a,
    const cyxwiz_share_t *b,
    cyxwiz_share_t *result
);

/*
 * Subtract shares (result = a - b)
 * Context is needed to recompute the MAC for the result
 */
cyxwiz_error_t cyxwiz_crypto_share_sub(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *a,
    const cyxwiz_share_t *b,
    cyxwiz_share_t *result
);

/*
 * Multiply share by a public scalar (result = share * scalar)
 * Scalar must be CYXWIZ_KEY_SIZE bytes
 */
cyxwiz_error_t cyxwiz_crypto_share_scalar_mul(
    const cyxwiz_share_t *share,
    const uint8_t *scalar,
    cyxwiz_share_t *result
);

/* ============ MAC Operations ============ */

/*
 * Verify a share's MAC is valid
 * Returns CYXWIZ_OK if valid, CYXWIZ_ERR_CRYPTO if invalid
 */
cyxwiz_error_t cyxwiz_crypto_verify_share(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *share
);

/*
 * Compute MAC for a share value using context's MAC key
 */
cyxwiz_error_t cyxwiz_crypto_compute_mac(
    cyxwiz_crypto_ctx_t *ctx,
    const uint8_t *value,
    uint8_t *mac_out
);

/* ============ Symmetric Encryption ============ */

/*
 * Encrypt data using authenticated encryption (XChaCha20-Poly1305)
 *
 * @param plaintext         Data to encrypt
 * @param plaintext_len     Length of plaintext
 * @param key               Encryption key (CYXWIZ_KEY_SIZE bytes)
 * @param ciphertext_out    Output buffer (must be plaintext_len + CYXWIZ_CRYPTO_OVERHEAD)
 * @param ciphertext_len    Output: actual ciphertext length
 * @return                  CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_crypto_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *key,
    uint8_t *ciphertext_out,
    size_t *ciphertext_len
);

/*
 * Decrypt data
 *
 * @param ciphertext        Data to decrypt
 * @param ciphertext_len    Length of ciphertext
 * @param key               Decryption key (CYXWIZ_KEY_SIZE bytes)
 * @param plaintext_out     Output buffer (must be ciphertext_len - CYXWIZ_CRYPTO_OVERHEAD)
 * @param plaintext_len     Output: actual plaintext length
 * @return                  CYXWIZ_OK on success, CYXWIZ_ERR_CRYPTO if auth fails
 */
cyxwiz_error_t cyxwiz_crypto_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *key,
    uint8_t *plaintext_out,
    size_t *plaintext_len
);

/* ============ Key Derivation ============ */

/*
 * Derive a key from input material using BLAKE2b
 *
 * @param input         Input key material
 * @param input_len     Length of input
 * @param context       Context string (domain separation)
 * @param context_len   Length of context
 * @param key_out       Output key (CYXWIZ_KEY_SIZE bytes)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_crypto_derive_key(
    const uint8_t *input,
    size_t input_len,
    const uint8_t *context,
    size_t context_len,
    uint8_t *key_out
);

/*
 * Hash data using BLAKE2b
 */
cyxwiz_error_t cyxwiz_crypto_hash(
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash_out,
    size_t hash_len
);

/* ============ Random ============ */

/*
 * Generate cryptographically secure random bytes
 */
void cyxwiz_crypto_random(uint8_t *buf, size_t len);

/*
 * Generate a random key
 */
void cyxwiz_crypto_random_key(uint8_t *key_out);

#endif /* CYXWIZ_CRYPTO_H */
