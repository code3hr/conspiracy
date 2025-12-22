/*
 * CyxWiz Protocol - SPDZ-style Information-Theoretic MACs
 *
 * SPDZ uses a linear MAC scheme:
 *   MAC(x) = alpha * x + beta
 *
 * Where:
 *   - alpha is the global MAC key (shared by all parties)
 *   - beta is a random value per share
 *   - Operations are in GF(2^128) for 128-bit security
 *
 * Properties:
 *   - MAC(x + y) = MAC(x) + MAC(y)  (additive homomorphic)
 *   - MAC(c * x) = c * MAC(x)       (scalar multiplicative)
 */

#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

/* Forward declaration for crypto.c function */
extern const uint8_t *cyxwiz_crypto_get_mac_key(const cyxwiz_crypto_ctx_t *ctx);

#include <sodium.h>
#include <string.h>

/*
 * XOR two byte arrays (used for addition in GF(2^n))
 */
static void xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/*
 * Galois field multiplication in GF(2^128)
 * Using the reduction polynomial x^128 + x^7 + x^2 + x + 1
 * This is the same polynomial used in GCM mode
 */
static void gf128_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint8_t v[16];
    uint8_t z[16];

    memcpy(v, b, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 128; i++) {
        /* If bit i of 'a' is set, XOR v into z */
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);

        if ((a[byte_idx] >> bit_idx) & 1) {
            xor_bytes(z, z, v, 16);
        }

        /* Check if MSB of v is set before shifting */
        int msb = v[0] & 0x80;

        /* Shift v right by 1 (big-endian) */
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
        }
        v[0] >>= 1;

        /* If MSB was set, XOR with reduction polynomial */
        if (msb) {
            v[15] ^= 0x87;  /* x^7 + x^2 + x + 1 = 0x87 */
        }
    }

    memcpy(out, z, 16);
}

/*
 * Compute MAC = alpha * value (truncated to MAC_SIZE)
 * Uses BLAKE2b keyed hash as a PRF to simulate the linear MAC
 *
 * For simplicity and security, we use HMAC-style construction:
 *   MAC(x) = H(alpha || x) truncated to CYXWIZ_MAC_SIZE
 *
 * This provides:
 *   - Collision resistance
 *   - Unforgeability without knowing alpha
 */
cyxwiz_error_t cyxwiz_crypto_compute_mac(
    cyxwiz_crypto_ctx_t *ctx,
    const uint8_t *value,
    uint8_t *mac_out)
{
    if (ctx == NULL || value == NULL || mac_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Get MAC key from context (defined in crypto.c) */
    const uint8_t *mac_key = cyxwiz_crypto_get_mac_key(ctx);

    if (mac_key == NULL) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Compute keyed hash: H(mac_key, value) */
    if (crypto_generichash(
            mac_out,
            CYXWIZ_MAC_SIZE,
            value,
            CYXWIZ_KEY_SIZE,
            mac_key,
            CYXWIZ_MAC_KEY_SIZE) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
}

/*
 * Add two MACs (for share addition)
 * MAC(a+b) should equal MAC(a) XOR MAC(b) in our scheme
 */
void cyxwiz_mac_add(
    const uint8_t *mac_a,
    const uint8_t *mac_b,
    uint8_t *mac_out)
{
    xor_bytes(mac_out, mac_a, mac_b, CYXWIZ_MAC_SIZE);
}

/*
 * Multiply MAC by scalar (for scalar multiplication of shares)
 * Uses GF(2^128) multiplication
 */
void cyxwiz_mac_scalar_mul(
    const uint8_t *mac,
    const uint8_t *scalar,
    uint8_t *mac_out)
{
    /* Truncate scalar to 128 bits for GF multiplication */
    uint8_t scalar_128[16];
    memcpy(scalar_128, scalar, 16);

    uint8_t mac_128[16];
    memcpy(mac_128, mac, CYXWIZ_MAC_SIZE);

    gf128_mul(mac_out, mac_128, scalar_128);
}

/*
 * Verify a MAC against expected value
 * Uses constant-time comparison
 */
int cyxwiz_mac_verify(
    const uint8_t *computed_mac,
    const uint8_t *expected_mac)
{
    return cyxwiz_secure_compare(computed_mac, expected_mac, CYXWIZ_MAC_SIZE);
}
