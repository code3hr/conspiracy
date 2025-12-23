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

/* Test simple 2-of-2 threshold reconstruction */
static int test_threshold_2of2(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    /* Create 2-of-2 context - simplest threshold case */
    err = cyxwiz_crypto_create(&ctx, 2, 2, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create a simple secret (all zeros except first byte = 42) */
    uint8_t secret[CYXWIZ_KEY_SIZE];
    memset(secret, 0, CYXWIZ_KEY_SIZE);
    secret[CYXWIZ_KEY_SIZE - 1] = 42;

    /* Split into 2 shares */
    cyxwiz_share_t shares[2];
    size_t num_shares;

    err = cyxwiz_crypto_share_secret(ctx, secret, CYXWIZ_KEY_SIZE, shares, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Reconstruct with both shares */
    uint8_t reconstructed[CYXWIZ_KEY_SIZE];
    err = cyxwiz_crypto_reconstruct_secret(ctx, shares, 2, reconstructed, CYXWIZ_KEY_SIZE);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify */
    if (memcmp(secret, reconstructed, CYXWIZ_KEY_SIZE) != 0) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_crypto_destroy(ctx);
    return 1;
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

    /* Reconstruct with threshold shares (3 of 5) */
    uint8_t reconstructed[CYXWIZ_KEY_SIZE];
    err = cyxwiz_crypto_reconstruct_secret(ctx, shares, 3, reconstructed, CYXWIZ_KEY_SIZE);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify reconstruction */
    if (memcmp(secret, reconstructed, CYXWIZ_KEY_SIZE) != 0) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Also test with all shares */
    err = cyxwiz_crypto_reconstruct_secret(ctx, shares, num_shares, reconstructed, CYXWIZ_KEY_SIZE);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

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
        err = cyxwiz_crypto_share_add(ctx, &shares_a[i], &shares_b[i], &shares_sum[i]);
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

/* ============ Beaver Triple Tests ============ */

/* Test triple pool initialization */
static int test_triple_pool_init(void)
{
    cyxwiz_triple_pool_t pool;

    cyxwiz_error_t err = cyxwiz_triple_pool_init(&pool);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    if (pool.count != 0) {
        return 0;
    }

    if (pool.next_index != 0) {
        return 0;
    }

    if (cyxwiz_triple_pool_available(&pool) != 0) {
        return 0;
    }

    return 1;
}

/* Test triple generation */
static int test_triple_generation(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 3, 5, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_triple_pool_t pool;
    err = cyxwiz_triple_pool_init(&pool);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Generate some triples */
    err = cyxwiz_triple_pool_generate(ctx, &pool, 5);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    if (pool.count != 5) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    if (cyxwiz_triple_pool_available(&pool) != 5) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify each triple has valid MACs */
    for (size_t i = 0; i < pool.count; i++) {
        cyxwiz_beaver_triple_t *t = &pool.triples[i];

        err = cyxwiz_crypto_verify_share(ctx, &t->a);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }

        err = cyxwiz_crypto_verify_share(ctx, &t->b);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }

        err = cyxwiz_crypto_verify_share(ctx, &t->c);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }

        if (t->used != false) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
    }

    cyxwiz_triple_pool_clear(&pool);
    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test triple consumption */
static int test_triple_consume(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 3, 5, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_triple_pool_t pool;
    cyxwiz_triple_pool_init(&pool);

    /* Generate 3 triples */
    err = cyxwiz_triple_pool_generate(ctx, &pool, 3);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Consume all 3 */
    cyxwiz_beaver_triple_t triple;
    for (int i = 0; i < 3; i++) {
        err = cyxwiz_triple_pool_consume(&pool, &triple);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
    }

    /* Fourth consume should fail */
    err = cyxwiz_triple_pool_consume(&pool, &triple);
    if (err != CYXWIZ_ERR_EXHAUSTED) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Available should be 0 */
    if (cyxwiz_triple_pool_available(&pool) != 0) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_triple_pool_clear(&pool);
    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test share multiplication using Beaver triples */
static int test_share_mul(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    /* Create 2-of-2 context for testing (simulate party 1's view) */
    err = cyxwiz_crypto_create(&ctx, 2, 2, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create triple pool and generate triples */
    cyxwiz_triple_pool_t pool;
    cyxwiz_triple_pool_init(&pool);
    err = cyxwiz_triple_pool_generate(ctx, &pool, 10);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Create two secrets */
    uint8_t secret_x[CYXWIZ_KEY_SIZE];
    uint8_t secret_y[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random(secret_x, CYXWIZ_KEY_SIZE);
    cyxwiz_crypto_random(secret_y, CYXWIZ_KEY_SIZE);

    /* Split into shares */
    cyxwiz_share_t shares_x[2];
    cyxwiz_share_t shares_y[2];
    size_t num_shares;

    err = cyxwiz_crypto_share_secret(ctx, secret_x, CYXWIZ_KEY_SIZE, shares_x, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    err = cyxwiz_crypto_share_secret(ctx, secret_y, CYXWIZ_KEY_SIZE, shares_y, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Multiply shares (party 1's shares only, simulating local computation) */
    cyxwiz_share_t result_share;
    err = cyxwiz_crypto_share_mul(ctx, &pool, &shares_x[0], &shares_y[0], &result_share);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify result has valid MAC */
    err = cyxwiz_crypto_verify_share(ctx, &result_share);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify one triple was consumed */
    if (cyxwiz_triple_pool_available(&pool) != 9) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_triple_pool_clear(&pool);
    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test multiple share multiplications */
static int test_share_mul_multiple(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 2, 2, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_triple_pool_t pool;
    cyxwiz_triple_pool_init(&pool);
    err = cyxwiz_triple_pool_generate(ctx, &pool, 16);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Create multiple secrets */
    uint8_t secrets[4][CYXWIZ_KEY_SIZE];
    cyxwiz_share_t shares[4];
    size_t num_shares;

    for (int i = 0; i < 4; i++) {
        cyxwiz_crypto_random(secrets[i], CYXWIZ_KEY_SIZE);
        cyxwiz_share_t temp_shares[2];
        err = cyxwiz_crypto_share_secret(ctx, secrets[i], CYXWIZ_KEY_SIZE, temp_shares, &num_shares);
        if (err != CYXWIZ_OK) {
            cyxwiz_crypto_destroy(ctx);
            return 0;
        }
        /* Use party 1's share */
        memcpy(&shares[i], &temp_shares[0], sizeof(cyxwiz_share_t));
    }

    /* Perform 3 multiplications: (s0 * s1) * (s2 * s3) */
    cyxwiz_share_t result1, result2, final_result;

    err = cyxwiz_crypto_share_mul(ctx, &pool, &shares[0], &shares[1], &result1);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    err = cyxwiz_crypto_share_mul(ctx, &pool, &shares[2], &shares[3], &result2);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    err = cyxwiz_crypto_share_mul(ctx, &pool, &result1, &result2, &final_result);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify 3 triples were consumed */
    if (cyxwiz_triple_pool_available(&pool) != 13) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Verify final result has valid MAC */
    err = cyxwiz_crypto_verify_share(ctx, &final_result);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_triple_pool_clear(&pool);
    cyxwiz_crypto_destroy(ctx);
    return 1;
}

/* Test exhausted pool error */
static int test_share_mul_exhausted(void)
{
    cyxwiz_crypto_ctx_t *ctx = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_crypto_create(&ctx, 2, 2, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_triple_pool_t pool;
    cyxwiz_triple_pool_init(&pool);

    /* Generate only 1 triple */
    err = cyxwiz_triple_pool_generate(ctx, &pool, 1);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Create secrets and shares */
    uint8_t secret[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random(secret, CYXWIZ_KEY_SIZE);

    cyxwiz_share_t shares[2];
    size_t num_shares;
    err = cyxwiz_crypto_share_secret(ctx, secret, CYXWIZ_KEY_SIZE, shares, &num_shares);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* First multiplication should succeed */
    cyxwiz_share_t result;
    err = cyxwiz_crypto_share_mul(ctx, &pool, &shares[0], &shares[0], &result);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    /* Second multiplication should fail with exhausted */
    err = cyxwiz_crypto_share_mul(ctx, &pool, &shares[0], &shares[0], &result);
    if (err != CYXWIZ_ERR_EXHAUSTED) {
        cyxwiz_crypto_destroy(ctx);
        return 0;
    }

    cyxwiz_triple_pool_clear(&pool);
    cyxwiz_crypto_destroy(ctx);
    return 1;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_DEBUG); /* Enable debug for debugging */

    printf("\nCyxWiz Crypto Tests\n");
    printf("===================\n\n");

    TEST(crypto_init);
    TEST(context_create);
    TEST(context_invalid);
    TEST(encrypt_decrypt);
    TEST(decrypt_wrong_key);
    TEST(threshold_2of2);
    TEST(share_reconstruct);
    TEST(share_add);
    TEST(mac_verify);
    TEST(derive_key);
    TEST(random);

    printf("\n  Beaver Triple Tests:\n");
    TEST(triple_pool_init);
    TEST(triple_generation);
    TEST(triple_consume);
    TEST(share_mul);
    TEST(share_mul_multiple);
    TEST(share_mul_exhausted);

    printf("\n===================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
