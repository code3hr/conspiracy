/*
 * CyxWiz Protocol - Crypto Layer Tests
 */

#include "cyxwiz/types.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("  Testing: %s... ", #name); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while (0)

/* Test crypto initialization */
static int test_crypto_init(void)
{
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Second init should also succeed (idempotent) */
    err = cyxwiz_crypto_init();
    return (err == CYXWIZ_OK);
}

/* Test context creation */
static int test_context_create(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    /* Valid parameters */
    err = cyxwiz_crypto_create(&ctx, 3, 5, 1);
    if (err != CYXWIZ_OK || ctx == NULL) {
        return 0;
    }

    if (cyxwiz_crypto_get_threshold(ctx) != 3) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    if (cyxwiz_crypto_get_num_parties(ctx) != 5) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    if (cyxwiz_crypto_get_party_id(ctx) != 1) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test invalid context parameters */
static int test_context_invalid(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    /* NULL output */
    err = cyxwiz_crypto_create(NULL, 3, 5, 1);
    if (err == CYXWIZ_OK) {
        return 0;
    }

    /* Threshold > num_parties */
    err = cyxwiz_crypto_create(&ctx, 6, 5, 1);
    if (err == CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Party ID > num_parties */
    err = cyxwiz_crypto_create(&ctx, 3, 5, 6);
    if (err == CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Party ID = 0 */
    err = cyxwiz_crypto_create(&ctx, 3, 5, 0);
    if (err == CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    return 1;
}

/* Test encrypt/decrypt */
static int test_encrypt_decrypt(void)
{
    uint8_t key[CYXWIZ_KEY_SIZE];
    uint8_t plaintext[] = "Hello, CyxWiz Protocol!";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[256];
    size_t ciphertext_len;

    uint8_t decrypted[256];
    size_t decrypted_len;

    /* Generate random key */
    cyxwiz_crypto_random_key(key);

    /* Encrypt */
    cyxwiz_error_t err = cyxwiz_crypto_encrypt(
        plaintext, plaintext_len,
        key,
        ciphertext, &ciphertext_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Ciphertext should be larger (nonce + auth tag) */
    if (ciphertext_len != plaintext_len + CYXWIZ_CRYPTO_OVERHEAD) {
        return 0;
    }

    /* Decrypt */
    err = cyxwiz_crypto_decrypt(
        ciphertext, ciphertext_len,
        key,
        decrypted, &decrypted_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Verify */
    if (decrypted_len != plaintext_len) {
        return 0;
    }

    if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
        return 0;
    }

    return 1;
}

/* Test decrypt with wrong key fails */
static int test_decrypt_wrong_key(void)
{
    uint8_t key1[CYXWIZ_KEY_SIZE];
    uint8_t key2[CYXWIZ_KEY_SIZE];
    uint8_t plaintext[] = "Secret message";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[256];
    size_t ciphertext_len;

    uint8_t decrypted[256];
    size_t decrypted_len;

    /* Generate two different keys */
    cyxwiz_crypto_random_key(key1);
    cyxwiz_crypto_random_key(key2);

    /* Encrypt with key1 */
    cyxwiz_error_t err = cyxwiz_crypto_encrypt(
        plaintext, plaintext_len,
        key1,
        ciphertext, &ciphertext_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Decrypt with key2 should fail */
    err = cyxwiz_crypto_decrypt(
        ciphertext, ciphertext_len,
        key2,
        decrypted, &decrypted_len
    );

    /* Should fail with crypto error */
    return (err == CYXWIZ_ERR_CRYPTO);
}

/* Test secret sharing and reconstruction */
static int test_share_reconstruct(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    /* Create 3-of-5 context */
    err = cyxwiz_crypto_create(&ctx, 3, 5, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create a secret */
    uint8_t secret[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random(secret, CYXWIZ_KEY_SIZE);

    /* Split into shares */
    cyxwiz_share_t shares[5];
    size_t num_shares;

    err = cyxwiz_crypto_share_secret(ctx, secret, CYXWIZ_KEY_SIZE, shares, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    if (num_shares != 5) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify each share has a valid party ID */
    for (size_t i = 0; i < num_shares; i++) {
        if (shares[i].party_id != i + 1) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
    }

    /* Reconstruct with all shares */
    uint8_t reconstructed[CYXWIZ_KEY_SIZE];
    err = cyxwiz_crypto_reconstruct_secret(ctx, shares, num_shares, reconstructed, CYXWIZ_KEY_SIZE);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify reconstruction */
    if (memcmp(secret, reconstructed, CYXWIZ_KEY_SIZE) != 0) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test share addition */
static int test_share_add(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 2, 3, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create two secrets */
    uint8_t secret_a[CYXWIZ_KEY_SIZE];
    uint8_t secret_b[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random(secret_a, CYXWIZ_KEY_SIZE);
    cyxwiz_crypto_random(secret_b, CYXWIZ_KEY_SIZE);

    /* Split both */
    cyxwiz_share_t shares_a[3];
    cyxwiz_share_t shares_b[3];
    size_t num_shares;

    err = cyxwiz_crypto_share_secret(ctx, secret_a, CYXWIZ_KEY_SIZE, shares_a, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    err = cyxwiz_crypto_share_secret(ctx, secret_b, CYXWIZ_KEY_SIZE, shares_b, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Add shares locally */
    cyxwiz_share_t shares_sum[3];
    for (size_t i = 0; i < 3; i++) {
        err = cyxwiz_crypto_share_add(&shares_a[i], &shares_b[i], &shares_sum[i]);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
    }

    /* Reconstruct sum */
    uint8_t reconstructed_sum[CYXWIZ_KEY_SIZE];
    err = cyxwiz_crypto_reconstruct_secret(ctx, shares_sum, 3, reconstructed_sum, CYXWIZ_KEY_SIZE);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Compute expected sum (XOR in GF(2^n)) */
    uint8_t expected_sum[CYXWIZ_KEY_SIZE];
    for (size_t i = 0; i < CYXWIZ_KEY_SIZE; i++) {
        expected_sum[i] = secret_a[i] ^ secret_b[i];
    }

    /* Verify */
    if (memcmp(expected_sum, reconstructed_sum, CYXWIZ_KEY_SIZE) != 0) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test MAC verification */
static int test_mac_verify(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 2, 3, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create secret and shares */
    uint8_t secret[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random(secret, CYXWIZ_KEY_SIZE);

    cyxwiz_share_t shares[3];
    size_t num_shares;

    err = cyxwiz_crypto_share_secret(ctx, secret, CYXWIZ_KEY_SIZE, shares, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify valid shares */
    for (size_t i = 0; i < num_shares; i++) {
        err = cyxwiz_crypto_verify_share(ctx, &shares[i]);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
    }

    /* Corrupt a share and verify it fails */
    shares[0].value[0] ^= 0xFF;
    err = cyxwiz_crypto_verify_share(ctx, &shares[0]);
    if (err == CYXWIZ_OK) {
        /* Should have failed! */
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test key derivation */
static int test_derive_key(void)
{
    uint8_t input[] = "master key material";
    uint8_t context[] = "encryption key v1";
    uint8_t key1[CYXWIZ_KEY_SIZE];
    uint8_t key2[CYXWIZ_KEY_SIZE];

    /* Derive same key twice */
    cyxwiz_error_t err;
    err = cyxwiz_crypto_derive_key(input, sizeof(input), context, sizeof(context), key1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_crypto_derive_key(input, sizeof(input), context, sizeof(context), key2);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Should be identical */
    if (memcmp(key1, key2, CYXWIZ_KEY_SIZE) != 0) {
        return 0;
    }

    /* Different context should give different key */
    uint8_t context2[] = "different context";
    err = cyxwiz_crypto_derive_key(input, sizeof(input), context2, sizeof(context2), key2);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Should be different */
    if (memcmp(key1, key2, CYXWIZ_KEY_SIZE) == 0) {
        return 0;
    }

    return 1;
}

/* Test random generation */
static int test_random(void)
{
    uint8_t buf1[32];
    uint8_t buf2[32];

    cyxwiz_crypto_random(buf1, sizeof(buf1));
    cyxwiz_crypto_random(buf2, sizeof(buf2));

    /* Very unlikely to be equal */
    if (memcmp(buf1, buf2, sizeof(buf1)) == 0) {
        return 0;
    }

    /* Check not all zeros */
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf1); i++) {
        if (buf1[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        return 0;
    }

    return 1;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Crypto Tests\n");
    printf("===================\n\n");

    TEST(crypto_init);
    TEST(context_create);
    TEST(context_invalid);
    TEST(encrypt_decrypt);
    TEST(decrypt_wrong_key);
    TEST(share_reconstruct);
    TEST(share_add);
    TEST(mac_verify);
    TEST(derive_key);
    TEST(random);

    printf("\n===================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
