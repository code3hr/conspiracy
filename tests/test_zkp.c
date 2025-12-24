/*
 * CyxWiz Protocol - Zero-Knowledge Proof Tests
 *
 * Tests for Schnorr identity proofs using Ed25519 primitives.
 */

#include "cyxwiz/types.h"
#include "cyxwiz/zkp.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        fflush(stdout); \
        printf("  Testing: %s... ", #name); \
        fflush(stdout); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            fflush(stdout); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
            fflush(stdout); \
        } \
    } while (0)

/* ============================================================================
 * Identity Keypair Tests
 * ============================================================================ */

/* Test identity keypair generation */
static int test_identity_keygen(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        printf("keygen failed: %d ", err);
        return 0;
    }

    /* Verify public key is not all zeros */
    uint8_t zeros[32] = {0};
    if (memcmp(keypair.public_key, zeros, 32) == 0) {
        printf("public key is all zeros ");
        return 0;
    }

    /* Clean up */
    cyxwiz_identity_destroy(&keypair);

    /* NULL should fail */
    err = cyxwiz_identity_keygen(NULL);
    if (err == CYXWIZ_OK) {
        printf("NULL should fail ");
        return 0;
    }

    return 1;
}

/* Test Ed25519 to X25519 public key derivation */
static int test_identity_to_x25519_pk(void)
{
    cyxwiz_identity_keypair_t keypair;
    uint8_t x25519_pk[32];
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_identity_to_x25519_pk(&keypair, x25519_pk);
    if (err != CYXWIZ_OK) {
        printf("x25519_pk derivation failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* X25519 key should be different from Ed25519 key */
    if (memcmp(keypair.public_key, x25519_pk, 32) == 0) {
        printf("x25519_pk same as ed25519_pk ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test Ed25519 to X25519 secret key derivation */
static int test_identity_to_x25519_sk(void)
{
    cyxwiz_identity_keypair_t keypair;
    uint8_t x25519_sk[32];
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_identity_to_x25519_sk(&keypair, x25519_sk);
    if (err != CYXWIZ_OK) {
        printf("x25519_sk derivation failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* X25519 secret key should not be all zeros */
    uint8_t zeros[32] = {0};
    if (memcmp(x25519_sk, zeros, 32) == 0) {
        printf("x25519_sk is all zeros ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Clean up sensitive data */
    cyxwiz_secure_zero(x25519_sk, sizeof(x25519_sk));
    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test node ID derivation from identity */
static int test_identity_to_node_id(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_node_id_t node_id;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_identity_to_node_id(&keypair, &node_id);
    if (err != CYXWIZ_OK) {
        printf("node_id derivation failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Node ID should be deterministic - derive again and compare */
    cyxwiz_node_id_t node_id2;
    err = cyxwiz_identity_to_node_id(&keypair, &node_id2);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    if (memcmp(node_id.bytes, node_id2.bytes, CYXWIZ_NODE_ID_LEN) != 0) {
        printf("node_id not deterministic ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test node ID verification */
static int test_identity_verify_node_id(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_node_id_t node_id;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_identity_to_node_id(&keypair, &node_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Valid node ID should verify */
    if (!cyxwiz_identity_verify_node_id(keypair.public_key, &node_id)) {
        printf("valid node_id failed to verify ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Tampered node ID should fail */
    cyxwiz_node_id_t bad_node_id;
    memcpy(bad_node_id.bytes, node_id.bytes, CYXWIZ_NODE_ID_LEN);
    bad_node_id.bytes[0] ^= 0xFF;
    if (cyxwiz_identity_verify_node_id(keypair.public_key, &bad_node_id)) {
        printf("tampered node_id should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* ============================================================================
 * Schnorr Proof Tests
 * ============================================================================ */

/* Test basic Schnorr proof generation and verification */
static int test_schnorr_proof_basic(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Generate proof without context */
    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof);
    if (err != CYXWIZ_OK) {
        printf("prove failed: %d ", err);
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify proof */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, NULL);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test Schnorr proof with context */
static int test_schnorr_proof_with_context(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_proof_context_t ctx;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Set up context */
    const char *ctx_str = "cyxwiz_test_context";
    cyxwiz_proof_context_init(&ctx, (const uint8_t *)ctx_str, strlen(ctx_str));

    /* Generate proof with context */
    err = cyxwiz_schnorr_prove(&keypair, &ctx, &proof);
    if (err != CYXWIZ_OK) {
        printf("prove with context failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify proof with same context */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, &ctx);
    if (err != CYXWIZ_OK) {
        printf("verify with context failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test proof fails with wrong public key */
static int test_schnorr_verify_wrong_pubkey(void)
{
    cyxwiz_identity_keypair_t keypair1, keypair2;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_identity_keygen(&keypair2);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair1);
        return 0;
    }

    /* Generate proof with keypair1 */
    err = cyxwiz_schnorr_prove(&keypair1, NULL, &proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair1);
        cyxwiz_identity_destroy(&keypair2);
        return 0;
    }

    /* Verify with keypair2's public key should fail */
    err = cyxwiz_schnorr_verify(keypair2.public_key, &proof, NULL);
    if (err == CYXWIZ_OK) {
        printf("verify with wrong pubkey should fail ");
        cyxwiz_identity_destroy(&keypair1);
        cyxwiz_identity_destroy(&keypair2);
        return 0;
    }

    if (err != CYXWIZ_ERR_PROOF_INVALID) {
        printf("expected PROOF_INVALID error, got %d ", err);
        cyxwiz_identity_destroy(&keypair1);
        cyxwiz_identity_destroy(&keypair2);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair1);
    cyxwiz_identity_destroy(&keypair2);
    return 1;
}

/* Test proof fails with tampered commitment */
static int test_schnorr_verify_tampered_commitment(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Tamper with commitment */
    proof.commitment[0] ^= 0xFF;

    /* Verification should fail */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, NULL);
    if (err == CYXWIZ_OK) {
        printf("tampered commitment should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test proof fails with tampered response */
static int test_schnorr_verify_tampered_response(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Tamper with response */
    proof.response[0] ^= 0xFF;

    /* Verification should fail */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, NULL);
    if (err == CYXWIZ_OK) {
        printf("tampered response should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test proof fails with wrong context */
static int test_schnorr_verify_wrong_context(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_proof_context_t ctx1, ctx2;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Set up two different contexts */
    const char *ctx_str1 = "context_one";
    const char *ctx_str2 = "context_two";
    cyxwiz_proof_context_init(&ctx1, (const uint8_t *)ctx_str1, strlen(ctx_str1));
    cyxwiz_proof_context_init(&ctx2, (const uint8_t *)ctx_str2, strlen(ctx_str2));

    /* Generate proof with ctx1 */
    err = cyxwiz_schnorr_prove(&keypair, &ctx1, &proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify with ctx2 should fail */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, &ctx2);
    if (err == CYXWIZ_OK) {
        printf("wrong context should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify with no context should also fail */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, NULL);
    if (err == CYXWIZ_OK) {
        printf("no context should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify with correct context should succeed */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof, &ctx1);
    if (err != CYXWIZ_OK) {
        printf("correct context should succeed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test message-bound proofs */
static int test_schnorr_prove_message(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Generate message-bound proof */
    const char *message = "Hello, this is a test message!";
    err = cyxwiz_schnorr_prove_message(&keypair, (const uint8_t *)message,
                                        strlen(message), &proof);
    if (err != CYXWIZ_OK) {
        printf("prove_message failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify with same message */
    err = cyxwiz_schnorr_verify_message(keypair.public_key,
                                         (const uint8_t *)message,
                                         strlen(message), &proof);
    if (err != CYXWIZ_OK) {
        printf("verify_message failed ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Verify with different message should fail */
    const char *other_message = "Different message";
    err = cyxwiz_schnorr_verify_message(keypair.public_key,
                                         (const uint8_t *)other_message,
                                         strlen(other_message), &proof);
    if (err == CYXWIZ_OK) {
        printf("different message should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test proof size is exactly 64 bytes */
static int test_proof_size(void)
{
    if (sizeof(cyxwiz_schnorr_proof_t) != CYXWIZ_SCHNORR_PROOF_SIZE) {
        printf("proof size is %zu, expected %d ",
               sizeof(cyxwiz_schnorr_proof_t), CYXWIZ_SCHNORR_PROOF_SIZE);
        return 0;
    }

    if (CYXWIZ_SCHNORR_PROOF_SIZE != 64) {
        printf("SCHNORR_PROOF_SIZE is %d, expected 64 ",
               CYXWIZ_SCHNORR_PROOF_SIZE);
        return 0;
    }

    return 1;
}

/* Test proofs are randomized (different each time) */
static int test_proof_randomization(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof1, proof2;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Generate two proofs */
    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof1);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof2);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Proofs should be different (commitment uses random k) */
    if (memcmp(proof1.commitment, proof2.commitment, 32) == 0) {
        printf("proofs have same commitment (should be randomized) ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Both proofs should still verify */
    err = cyxwiz_schnorr_verify(keypair.public_key, &proof1, NULL);
    if (err != CYXWIZ_OK) {
        printf("proof1 failed to verify ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    err = cyxwiz_schnorr_verify(keypair.public_key, &proof2, NULL);
    if (err != CYXWIZ_OK) {
        printf("proof2 failed to verify ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test NULL parameter handling */
static int test_null_parameters(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_schnorr_proof_t proof;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* NULL keypair for prove */
    err = cyxwiz_schnorr_prove(NULL, NULL, &proof);
    if (err == CYXWIZ_OK) {
        printf("NULL keypair should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* NULL proof output for prove */
    err = cyxwiz_schnorr_prove(&keypair, NULL, NULL);
    if (err == CYXWIZ_OK) {
        printf("NULL proof output should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* Generate valid proof for verify tests */
    err = cyxwiz_schnorr_prove(&keypair, NULL, &proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* NULL public key for verify */
    err = cyxwiz_schnorr_verify(NULL, &proof, NULL);
    if (err == CYXWIZ_OK) {
        printf("NULL public key should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    /* NULL proof for verify */
    err = cyxwiz_schnorr_verify(keypair.public_key, NULL, NULL);
    if (err == CYXWIZ_OK) {
        printf("NULL proof should fail ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test identity destroy zeros secret key */
static int test_identity_destroy(void)
{
    cyxwiz_identity_keypair_t keypair;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Save a copy of the public key to verify it gets zeroed */
    uint8_t pk_copy[32];
    memcpy(pk_copy, keypair.public_key, 32);

    /* Destroy keypair */
    cyxwiz_identity_destroy(&keypair);

    /* Public key should be zeroed */
    uint8_t zeros[32] = {0};
    if (memcmp(keypair.public_key, zeros, 32) != 0) {
        printf("public key not zeroed ");
        return 0;
    }

    /* Secret key should be zeroed */
    uint8_t zeros_sk[64] = {0};
    if (memcmp(keypair.secret_key, zeros_sk, 64) != 0) {
        printf("secret key not zeroed ");
        return 0;
    }

    /* NULL should be safe */
    cyxwiz_identity_destroy(NULL);

    return 1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("CyxWiz ZKP Tests\n");
    printf("================\n\n");

    /* Initialize crypto subsystem */
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        printf("Failed to initialize crypto: %s\n", cyxwiz_strerror(err));
        return 1;
    }

    printf("Identity Keypair Tests:\n");
    TEST(identity_keygen);
    TEST(identity_to_x25519_pk);
    TEST(identity_to_x25519_sk);
    TEST(identity_to_node_id);
    TEST(identity_verify_node_id);
    TEST(identity_destroy);

    printf("\nSchnorr Proof Tests:\n");
    TEST(schnorr_proof_basic);
    TEST(schnorr_proof_with_context);
    TEST(schnorr_verify_wrong_pubkey);
    TEST(schnorr_verify_tampered_commitment);
    TEST(schnorr_verify_tampered_response);
    TEST(schnorr_verify_wrong_context);
    TEST(schnorr_prove_message);
    TEST(proof_size);
    TEST(proof_randomization);
    TEST(null_parameters);

    printf("\n================\n");
    printf("Tests: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
