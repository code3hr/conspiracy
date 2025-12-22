/*
 * CyxWiz Protocol - Cryptographic Primitives
 *
 * Wrappers around libsodium for:
 * - Authenticated encryption (XChaCha20-Poly1305)
 * - Hashing (BLAKE2b)
 * - Key derivation
 * - Secure random
 */

#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <sodium.h>
#include <string.h>

/* Static initialization flag */
static int g_sodium_initialized = 0;

cyxwiz_error_t cyxwiz_crypto_init(void)
{
    if (g_sodium_initialized) {
        return CYXWIZ_OK;
    }

    if (sodium_init() < 0) {
        CYXWIZ_ERROR("Failed to initialize libsodium");
        return CYXWIZ_ERR_CRYPTO;
    }

    g_sodium_initialized = 1;
    CYXWIZ_INFO("Crypto subsystem initialized (libsodium %s)", sodium_version_string());
    return CYXWIZ_OK;
}

/*
 * Encrypt using XChaCha20-Poly1305
 * Output format: [nonce (24 bytes)][ciphertext + auth tag]
 */
cyxwiz_error_t cyxwiz_crypto_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *key,
    uint8_t *ciphertext_out,
    size_t *ciphertext_len)
{
    if (plaintext == NULL || key == NULL || ciphertext_out == NULL || ciphertext_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Generate random nonce */
    uint8_t nonce[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    /* Copy nonce to output */
    memcpy(ciphertext_out, nonce, sizeof(nonce));

    /* Encrypt */
    if (crypto_secretbox_xchacha20poly1305_easy(
            ciphertext_out + sizeof(nonce),
            plaintext,
            plaintext_len,
            nonce,
            key) != 0) {
        CYXWIZ_ERROR("Encryption failed");
        return CYXWIZ_ERR_CRYPTO;
    }

    *ciphertext_len = sizeof(nonce) + plaintext_len + crypto_secretbox_xchacha20poly1305_MACBYTES;
    return CYXWIZ_OK;
}

/*
 * Decrypt XChaCha20-Poly1305
 * Input format: [nonce (24 bytes)][ciphertext + auth tag]
 */
cyxwiz_error_t cyxwiz_crypto_decrypt(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *key,
    uint8_t *plaintext_out,
    size_t *plaintext_len)
{
    if (ciphertext == NULL || key == NULL || plaintext_out == NULL || plaintext_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    size_t nonce_size = crypto_secretbox_xchacha20poly1305_NONCEBYTES;
    size_t mac_size = crypto_secretbox_xchacha20poly1305_MACBYTES;

    if (ciphertext_len < nonce_size + mac_size) {
        CYXWIZ_ERROR("Ciphertext too short");
        return CYXWIZ_ERR_INVALID;
    }

    /* Extract nonce */
    const uint8_t *nonce = ciphertext;
    const uint8_t *encrypted = ciphertext + nonce_size;
    size_t encrypted_len = ciphertext_len - nonce_size;

    /* Decrypt and verify */
    if (crypto_secretbox_xchacha20poly1305_open_easy(
            plaintext_out,
            encrypted,
            encrypted_len,
            nonce,
            key) != 0) {
        CYXWIZ_ERROR("Decryption failed (authentication error)");
        return CYXWIZ_ERR_CRYPTO;
    }

    *plaintext_len = encrypted_len - mac_size;
    return CYXWIZ_OK;
}

/*
 * Key derivation using BLAKE2b
 */
cyxwiz_error_t cyxwiz_crypto_derive_key(
    const uint8_t *input,
    size_t input_len,
    const uint8_t *context,
    size_t context_len,
    uint8_t *key_out)
{
    if (input == NULL || key_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Use BLAKE2b with key=input, message=context */
    crypto_generichash_state state;

    if (crypto_generichash_init(&state, input, input_len, CYXWIZ_KEY_SIZE) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    if (context != NULL && context_len > 0) {
        if (crypto_generichash_update(&state, context, context_len) != 0) {
            return CYXWIZ_ERR_CRYPTO;
        }
    }

    if (crypto_generichash_final(&state, key_out, CYXWIZ_KEY_SIZE) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Zero state */
    cyxwiz_secure_zero(&state, sizeof(state));

    return CYXWIZ_OK;
}

/*
 * Hash data using BLAKE2b
 */
cyxwiz_error_t cyxwiz_crypto_hash(
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash_out,
    size_t hash_len)
{
    if (data == NULL || hash_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (hash_len > crypto_generichash_BYTES_MAX) {
        return CYXWIZ_ERR_INVALID;
    }

    if (crypto_generichash(hash_out, hash_len, data, data_len, NULL, 0) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
}

/*
 * Generate secure random bytes
 */
void cyxwiz_crypto_random(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return;
    }
    randombytes_buf(buf, len);
}

/*
 * Generate a random key
 */
void cyxwiz_crypto_random_key(uint8_t *key_out)
{
    if (key_out == NULL) {
        return;
    }
    randombytes_buf(key_out, CYXWIZ_KEY_SIZE);
}
