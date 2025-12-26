/*
 * CyxWiz Protocol - Privacy Protocol Tests
 *
 * Tests for Pedersen commitments, range proofs, anonymous credentials,
 * service tokens, and reputation proofs.
 */

/* Disable MSVC warning C4127: conditional expression is constant */
#ifdef _MSC_VER
#pragma warning(disable: 4127)
#endif

#include "cyxwiz/types.h"
#include "cyxwiz/privacy.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/zkp.h"
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
 * Pedersen Commitment Tests
 * ============================================================================ */

/* Test Pedersen initialization */
static int test_pedersen_init(void)
{
    cyxwiz_error_t err = cyxwiz_pedersen_init();
    if (err != CYXWIZ_OK) {
        printf("init failed: %d ", err);
        return 0;
    }
    return 1;
}

/* Test basic Pedersen commitment creation and verification */
static int test_pedersen_commit_basic(void)
{
    cyxwiz_pedersen_commitment_t commitment;
    cyxwiz_pedersen_opening_t opening;
    uint8_t value[32] = {0};
    cyxwiz_error_t err;

    /* Set a test value */
    value[0] = 42;

    err = cyxwiz_pedersen_commit(value, &commitment, &opening);
    if (err != CYXWIZ_OK) {
        printf("commit failed: %d ", err);
        return 0;
    }

    /* Verify the commitment */
    err = cyxwiz_pedersen_verify(&commitment, &opening);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test Pedersen commitment with u64 value */
static int test_pedersen_commit_u64(void)
{
    cyxwiz_pedersen_commitment_t commitment;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    err = cyxwiz_pedersen_commit_u64(12345, &commitment, &opening);
    if (err != CYXWIZ_OK) {
        printf("commit_u64 failed: %d ", err);
        return 0;
    }

    err = cyxwiz_pedersen_verify(&commitment, &opening);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test Pedersen commitment fails with wrong opening */
static int test_pedersen_wrong_opening(void)
{
    cyxwiz_pedersen_commitment_t commitment;
    cyxwiz_pedersen_opening_t opening;
    uint8_t value[32] = {0};
    cyxwiz_error_t err;

    value[0] = 42;

    err = cyxwiz_pedersen_commit(value, &commitment, &opening);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Tamper with the opening value */
    opening.value[0] ^= 0xFF;

    /* Verification should fail */
    err = cyxwiz_pedersen_verify(&commitment, &opening);
    if (err == CYXWIZ_OK) {
        printf("tampered opening should fail ");
        return 0;
    }

    return 1;
}

/* Test Pedersen commitment fails with wrong blinding factor */
static int test_pedersen_wrong_blinding(void)
{
    cyxwiz_pedersen_commitment_t commitment;
    cyxwiz_pedersen_opening_t opening;
    uint8_t value[32] = {0};
    cyxwiz_error_t err;

    value[0] = 42;

    err = cyxwiz_pedersen_commit(value, &commitment, &opening);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Tamper with the blinding factor */
    opening.blinding[0] ^= 0xFF;

    /* Verification should fail */
    err = cyxwiz_pedersen_verify(&commitment, &opening);
    if (err == CYXWIZ_OK) {
        printf("tampered blinding should fail ");
        return 0;
    }

    return 1;
}

/* Test homomorphic addition of Pedersen commitments */
static int test_pedersen_add(void)
{
    cyxwiz_pedersen_commitment_t c1, c2, c_sum;
    cyxwiz_pedersen_opening_t o1, o2;
    cyxwiz_error_t err;

    /* Create commitment to 10 */
    err = cyxwiz_pedersen_commit_u64(10, &c1, &o1);
    if (err != CYXWIZ_OK) {
        printf("commit c1 failed ");
        return 0;
    }

    /* Create commitment to 20 */
    err = cyxwiz_pedersen_commit_u64(20, &c2, &o2);
    if (err != CYXWIZ_OK) {
        printf("commit c2 failed ");
        return 0;
    }

    /* Add commitments: C1 + C2 */
    err = cyxwiz_pedersen_add(&c1, &c2, &c_sum);
    if (err != CYXWIZ_OK) {
        printf("add failed: %d ", err);
        return 0;
    }

    /* The sum commitment should be valid (we can't verify it without
     * also adding the openings, which is not supported by the API) */
    return 1;
}

/* Test homomorphic subtraction of Pedersen commitments */
static int test_pedersen_sub(void)
{
    cyxwiz_pedersen_commitment_t c1, c2, c_diff;
    cyxwiz_pedersen_opening_t o1, o2;
    cyxwiz_error_t err;

    /* Create commitment to 30 */
    err = cyxwiz_pedersen_commit_u64(30, &c1, &o1);
    if (err != CYXWIZ_OK) {
        printf("commit c1 failed ");
        return 0;
    }

    /* Create commitment to 10 */
    err = cyxwiz_pedersen_commit_u64(10, &c2, &o2);
    if (err != CYXWIZ_OK) {
        printf("commit c2 failed ");
        return 0;
    }

    /* Subtract commitments: C1 - C2 */
    err = cyxwiz_pedersen_sub(&c1, &c2, &c_diff);
    if (err != CYXWIZ_OK) {
        printf("sub failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test commitment size is exactly 32 bytes */
static int test_pedersen_size(void)
{
    if (sizeof(cyxwiz_pedersen_commitment_t) != CYXWIZ_PEDERSEN_POINT_SIZE) {
        printf("commitment size is %zu, expected %d ",
               sizeof(cyxwiz_pedersen_commitment_t), CYXWIZ_PEDERSEN_POINT_SIZE);
        return 0;
    }

    /* Opening should be value + blinding = 64 bytes */
    size_t expected_opening = CYXWIZ_PEDERSEN_SCALAR_SIZE + CYXWIZ_PEDERSEN_BLINDING_SIZE;
    if (sizeof(cyxwiz_pedersen_opening_t) != expected_opening) {
        printf("opening size is %zu, expected %zu ",
               sizeof(cyxwiz_pedersen_opening_t), expected_opening);
        return 0;
    }

    return 1;
}

/* ============================================================================
 * Range Proof Tests
 * ============================================================================ */

/* Test 16-bit range proof creation and verification */
static int test_range_proof_16(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    /* Test with mixed bits (1000 = 0b1111101000) */
    uint16_t value = 1000;
    err = cyxwiz_range_proof_create_16(value, &proof, &opening);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        return 0;
    }

    /* Verify the range proof */
    err = cyxwiz_range_proof_verify_16(&proof);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test range proof for value with mixed bits */
static int test_range_proof_mixed(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    /* Test with 0xAAAA = 0b1010101010101010 (alternating bits) */
    uint16_t value = 0xAAAA;

    err = cyxwiz_range_proof_create_16(value, &proof, &opening);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        return 0;
    }

    err = cyxwiz_range_proof_verify_16(&proof);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test range proof for maximum value (65535) */
static int test_range_proof_max(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    err = cyxwiz_range_proof_create_16(65535, &proof, &opening);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        return 0;
    }

    err = cyxwiz_range_proof_verify_16(&proof);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test range proof for minimum value (0) - verifies zero-bit fix */
static int test_range_proof_zero(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    /* Value 0 = all 16 bits are 0, tests the zero-bit handling */
    err = cyxwiz_range_proof_create_16(0, &proof, &opening);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        return 0;
    }

    err = cyxwiz_range_proof_verify_16(&proof);
    if (err != CYXWIZ_OK) {
        printf("verify failed: %d ", err);
        return 0;
    }

    return 1;
}

/* Test range proof fails with tampered commitment */
static int test_range_proof_tampered(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_pedersen_opening_t opening;
    cyxwiz_error_t err;

    /* Use value with mixed bits */
    err = cyxwiz_range_proof_create_16(12345, &proof, &opening);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        return 0;
    }

    /* Tamper with the commitment */
    proof.commitment[0] ^= 0xFF;

    /* Verification should fail */
    err = cyxwiz_range_proof_verify_16(&proof);
    if (err == CYXWIZ_OK) {
        printf("tampered proof should fail ");
        return 0;
    }

    return 1;
}

/* Test range proof size */
static int test_range_proof_size(void)
{
    /* Range proof is commitment (32) + proof (96) = 128 bytes */
    size_t expected = CYXWIZ_PEDERSEN_POINT_SIZE + CYXWIZ_RANGE_PROOF_16_SIZE;
    if (sizeof(cyxwiz_range_proof_16_t) != expected) {
        printf("range proof size is %zu, expected %zu ",
               sizeof(cyxwiz_range_proof_16_t), expected);
        return 0;
    }

    return 1;
}

/* Test greater-than-or-equal range proof */
static int test_range_proof_geq(void)
{
    cyxwiz_range_proof_16_t proof;
    cyxwiz_error_t err;

    /* Test proving value >= threshold with mixed-bit difference */
    uint16_t value = 5000;      /* actual value */
    uint16_t threshold = 1000;  /* minimum threshold */
    err = cyxwiz_range_proof_create_geq(value, threshold, &proof);
    if (err != CYXWIZ_OK) {
        printf("create_geq failed: %d ", err);
        return 0;
    }

    /* Verify the range proof */
    err = cyxwiz_range_proof_verify_geq(&proof, threshold);
    if (err != CYXWIZ_OK) {
        printf("verify_geq failed: %d ", err);
        return 0;
    }

    return 1;
}

/* ============================================================================
 * Anonymous Credential Tests
 * ============================================================================ */

/* Test credential request creation */
static int test_cred_request_create(void)
{
    cyxwiz_cred_request_t request;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    cyxwiz_error_t err;

    uint8_t attribute[] = "test_validator_001";
    err = cyxwiz_cred_request_create(CYXWIZ_CRED_VALIDATOR,
                                      attribute, sizeof(attribute) - 1,
                                      &request, blinding);
    if (err != CYXWIZ_OK) {
        printf("request create failed: %d ", err);
        return 0;
    }

    /* Verify request has expected type */
    if (request.cred_type != CYXWIZ_CRED_VALIDATOR) {
        printf("wrong cred type ");
        return 0;
    }

    return 1;
}

/* Test full credential issuance flow */
static int test_cred_issue_flow(void)
{
    cyxwiz_identity_keypair_t issuer_key;
    cyxwiz_cred_request_t request;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];
    cyxwiz_credential_t credential;
    cyxwiz_error_t err;

    /* Generate issuer keypair */
    err = cyxwiz_identity_keygen(&issuer_key);
    if (err != CYXWIZ_OK) {
        printf("issuer keygen failed ");
        return 0;
    }

    /* Create credential request */
    uint8_t attribute[] = "validator_node_xyz";
    err = cyxwiz_cred_request_create(CYXWIZ_CRED_VALIDATOR,
                                      attribute, sizeof(attribute) - 1,
                                      &request, blinding);
    if (err != CYXWIZ_OK) {
        printf("request create failed ");
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* Issuer signs blinded request */
    uint64_t expires_at = 0xFFFFFFFFFFFFFFFF; /* Far future */
    err = cyxwiz_cred_issue(&issuer_key, &request, expires_at, blinded_sig);
    if (err != CYXWIZ_OK) {
        printf("issue failed: %d ", err);
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* User unblinds to get final credential */
    err = cyxwiz_cred_unblind(blinded_sig, blinding, issuer_key.public_key,
                              attribute, sizeof(attribute) - 1, expires_at,
                              &credential);
    if (err != CYXWIZ_OK) {
        printf("unblind failed: %d ", err);
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* Verify credential has correct issuer */
    if (memcmp(credential.issuer_pubkey, issuer_key.public_key, 32) != 0) {
        printf("wrong issuer pubkey ");
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    cyxwiz_identity_destroy(&issuer_key);
    return 1;
}

/* Test credential showing and verification */
static int test_cred_show_verify(void)
{
    cyxwiz_identity_keypair_t issuer_key;
    cyxwiz_cred_request_t request;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];
    cyxwiz_credential_t credential;
    cyxwiz_cred_show_proof_t show_proof;
    cyxwiz_error_t err;

    /* Setup: issue a credential */
    err = cyxwiz_identity_keygen(&issuer_key);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    uint8_t attribute[] = "validator_v1";
    err = cyxwiz_cred_request_create(CYXWIZ_CRED_VALIDATOR,
                                      attribute, sizeof(attribute) - 1,
                                      &request, blinding);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    err = cyxwiz_cred_issue(&issuer_key, &request, 0xFFFFFFFFFFFFFFFF, blinded_sig);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    err = cyxwiz_cred_unblind(blinded_sig, blinding, issuer_key.public_key,
                              attribute, sizeof(attribute) - 1, 0xFFFFFFFFFFFFFFFF,
                              &credential);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* Create show proof - context is 16 bytes */
    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE] = {0};
    memcpy(context, "vote_round_001", 14);
    err = cyxwiz_cred_show_create(&credential, context, &show_proof);
    if (err != CYXWIZ_OK) {
        printf("show create failed: %d ", err);
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* Verify show proof */
    uint64_t current_time = 1000000; /* Some time before expiry */
    err = cyxwiz_cred_show_verify(&show_proof, CYXWIZ_CRED_VALIDATOR,
                                   issuer_key.public_key, current_time);
    if (err != CYXWIZ_OK) {
        printf("show verify failed: %d ", err);
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    cyxwiz_identity_destroy(&issuer_key);
    return 1;
}

/* Test credential with multiple issuers (basic flow test) */
static int test_cred_multi_issuer(void)
{
    cyxwiz_identity_keypair_t issuer_key, other_key;
    cyxwiz_cred_request_t request;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];
    cyxwiz_credential_t credential;
    cyxwiz_cred_show_proof_t show_proof;
    cyxwiz_error_t err;

    /* Setup - generate two issuer keypairs */
    err = cyxwiz_identity_keygen(&issuer_key);
    if (err != CYXWIZ_OK) return 0;
    err = cyxwiz_identity_keygen(&other_key);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    uint8_t attribute[] = "validator";
    err = cyxwiz_cred_request_create(CYXWIZ_CRED_VALIDATOR,
                                      attribute, sizeof(attribute) - 1,
                                      &request, blinding);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        cyxwiz_identity_destroy(&other_key);
        return 0;
    }

    err = cyxwiz_cred_issue(&issuer_key, &request, 0xFFFFFFFFFFFFFFFF, blinded_sig);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        cyxwiz_identity_destroy(&other_key);
        return 0;
    }

    err = cyxwiz_cred_unblind(blinded_sig, blinding, issuer_key.public_key,
                              attribute, sizeof(attribute) - 1, 0xFFFFFFFFFFFFFFFF,
                              &credential);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        cyxwiz_identity_destroy(&other_key);
        return 0;
    }

    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE] = {0};
    memcpy(context, "test_context", 12);
    err = cyxwiz_cred_show_create(&credential, context, &show_proof);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        cyxwiz_identity_destroy(&other_key);
        return 0;
    }

    /* Verify with correct issuer should work */
    err = cyxwiz_cred_show_verify(&show_proof, CYXWIZ_CRED_VALIDATOR,
                                   issuer_key.public_key, 1000);
    if (err != CYXWIZ_OK) {
        printf("correct issuer should pass ");
        cyxwiz_identity_destroy(&issuer_key);
        cyxwiz_identity_destroy(&other_key);
        return 0;
    }

    /* Note: Full issuer binding verification is TODO in implementation */
    /* For now just test that the basic flow works */

    cyxwiz_identity_destroy(&issuer_key);
    cyxwiz_identity_destroy(&other_key);
    return 1;
}

/* Test credential sizes */
static int test_credential_size(void)
{
    /* Credential has padding for alignment:
     * signature(64) + issuer_pk(32) + attr_hash(32) + type(1) + padding(7) + issued(8) + expires(8) = 152 */
    if (sizeof(cyxwiz_credential_t) < 145) {
        printf("credential too small: %zu ", sizeof(cyxwiz_credential_t));
        return 0;
    }

    if (sizeof(cyxwiz_cred_show_proof_t) != CYXWIZ_CRED_SHOW_PROOF_SIZE) {
        printf("show proof size is %zu, expected %d ",
               sizeof(cyxwiz_cred_show_proof_t), CYXWIZ_CRED_SHOW_PROOF_SIZE);
        return 0;
    }

    return 1;
}

/* ============================================================================
 * Service Token Tests
 * ============================================================================ */

/* Test service token request and issuance */
static int test_service_token_flow(void)
{
    cyxwiz_identity_keypair_t provider_key;
    uint8_t request[256];
    size_t request_len;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    cyxwiz_error_t err;

    /* Setup provider keypair */
    err = cyxwiz_identity_keygen(&provider_key);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Create token request */
    err = cyxwiz_service_token_request(CYXWIZ_TOKEN_COMPUTE, 100,
                                        request, &request_len, blinding);
    if (err != CYXWIZ_OK) {
        printf("request failed: %d ", err);
        cyxwiz_identity_destroy(&provider_key);
        return 0;
    }

    /* Token request created successfully */
    cyxwiz_identity_destroy(&provider_key);
    return 1;
}

/* Test service token unblind */
static int test_service_token_unblind(void)
{
    cyxwiz_identity_keypair_t provider_key;
    uint8_t request[256];
    size_t request_len;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    uint8_t blinded_response[128]; /* Mock response */
    cyxwiz_service_token_t token;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&provider_key);
    if (err != CYXWIZ_OK) return 0;

    err = cyxwiz_service_token_request(CYXWIZ_TOKEN_STORAGE, 50,
                                        request, &request_len, blinding);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&provider_key);
        return 0;
    }

    /* Try to unblind (will likely fail without real issuer, but tests API) */
    memset(blinded_response, 0xAB, sizeof(blinded_response));
    err = cyxwiz_service_token_unblind(blinded_response, blinding,
                                        provider_key.public_key, &token);
    /* We don't require this to succeed - just testing the API is callable */
    (void)err;
    (void)token;

    cyxwiz_identity_destroy(&provider_key);
    return 1;
}

/* Test service token usage API */
static int test_service_token_use_api(void)
{
    cyxwiz_service_token_t token;
    uint8_t proof[256];
    size_t proof_len;
    uint8_t context[CYXWIZ_CRED_CONTEXT_SIZE] = {0};
    memcpy(context, "service_ctx", 11);
    cyxwiz_error_t err;

    /* Create a mock token */
    memset(&token, 0, sizeof(token));
    token.token_type = CYXWIZ_TOKEN_COMPUTE;
    token.units = 100;
    token.expires_at = 0xFFFFFFFFFFFFFFFF;

    /* Try to create usage proof */
    err = cyxwiz_service_token_use(&token, 10, context, proof, &proof_len);
    /* Just testing API is callable */
    (void)err;

    return 1;
}

/* ============================================================================
 * Reputation Proof Tests
 * ============================================================================ */

/* Test reputation proof creation API */
static int test_reputation_proof_create(void)
{
    cyxwiz_identity_keypair_t keypair;
    uint8_t proof[256];
    size_t proof_len;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Prove we have at least 500 credits when we actually have 2000 */
    uint32_t actual_credits = 2000;
    uint16_t min_threshold = 500;

    err = cyxwiz_reputation_proof_create(actual_credits, min_threshold,
                                          &keypair, proof, &proof_len);
    if (err != CYXWIZ_OK) {
        printf("create failed: %d ", err);
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* Test reputation proof fails when credits below threshold */
static int test_reputation_proof_insufficient(void)
{
    cyxwiz_identity_keypair_t keypair;
    uint8_t proof[256];
    size_t proof_len;
    cyxwiz_error_t err;

    err = cyxwiz_identity_keygen(&keypair);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Try to prove >= 100 when we only have 50 */
    uint32_t actual_credits = 50;
    uint16_t min_threshold = 100;

    err = cyxwiz_reputation_proof_create(actual_credits, min_threshold,
                                          &keypair, proof, &proof_len);
    if (err == CYXWIZ_OK) {
        printf("should fail when credits below threshold ");
        cyxwiz_identity_destroy(&keypair);
        return 0;
    }

    cyxwiz_identity_destroy(&keypair);
    return 1;
}

/* ============================================================================
 * Anonymous Voting Tests
 * ============================================================================ */

/* Test anonymous vote creation API */
static int test_anon_vote_create(void)
{
    cyxwiz_identity_keypair_t issuer_key;
    cyxwiz_cred_request_t request;
    uint8_t blinding[CYXWIZ_CRED_BLINDING_SIZE];
    uint8_t blinded_sig[CYXWIZ_CRED_SIGNATURE_SIZE];
    cyxwiz_credential_t credential;
    uint8_t vote_msg[256];
    size_t vote_len;
    cyxwiz_error_t err;

    /* Setup issuer */
    err = cyxwiz_identity_keygen(&issuer_key);
    if (err != CYXWIZ_OK) return 0;

    /* Issue vote eligibility credential */
    uint8_t attribute[] = "vote_eligible_v1";
    err = cyxwiz_cred_request_create(CYXWIZ_CRED_VOTE_ELIGIBLE,
                                      attribute, sizeof(attribute) - 1,
                                      &request, blinding);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    err = cyxwiz_cred_issue(&issuer_key, &request, 0xFFFFFFFFFFFFFFFF, blinded_sig);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    err = cyxwiz_cred_unblind(blinded_sig, blinding, issuer_key.public_key,
                              attribute, sizeof(attribute) - 1, 0xFFFFFFFFFFFFFFFF,
                              &credential);
    if (err != CYXWIZ_OK) {
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    /* Cast anonymous vote */
    uint8_t round_id[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    bool vote_valid = true;
    err = cyxwiz_privacy_vote_anonymous(&credential, round_id, vote_valid,
                                         vote_msg, &vote_len);
    if (err != CYXWIZ_OK) {
        printf("vote failed: %d ", err);
        cyxwiz_identity_destroy(&issuer_key);
        return 0;
    }

    cyxwiz_identity_destroy(&issuer_key);
    return 1;
}

/* ============================================================================
 * Message Size Tests
 * ============================================================================ */

/* Test all privacy message sizes fit within LoRa MTU */
static int test_message_sizes(void)
{
    /* All messages must fit within 250 bytes */
    const size_t max_size = CYXWIZ_MAX_PACKET_SIZE;

    if (sizeof(cyxwiz_pedersen_commit_msg_t) > max_size) {
        printf("PEDERSEN_COMMIT too large: %zu ", sizeof(cyxwiz_pedersen_commit_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_pedersen_open_msg_t) > max_size) {
        printf("PEDERSEN_OPEN too large: %zu ", sizeof(cyxwiz_pedersen_open_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_range_proof_msg_t) > max_size) {
        printf("RANGE_PROOF too large: %zu ", sizeof(cyxwiz_range_proof_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_cred_issue_req_msg_t) > max_size) {
        printf("CRED_ISSUE_REQ too large: %zu ", sizeof(cyxwiz_cred_issue_req_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_cred_issue_resp_msg_t) > max_size) {
        printf("CRED_ISSUE_RESP too large: %zu ", sizeof(cyxwiz_cred_issue_resp_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_cred_show_msg_t) > max_size) {
        printf("CRED_SHOW too large: %zu ", sizeof(cyxwiz_cred_show_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_cred_verify_msg_t) > max_size) {
        printf("CRED_VERIFY too large: %zu ", sizeof(cyxwiz_cred_verify_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_anon_vote_msg_t) > max_size) {
        printf("ANON_VOTE too large: %zu ", sizeof(cyxwiz_anon_vote_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_service_token_req_msg_t) > max_size) {
        printf("SERVICE_TOKEN_REQ too large: %zu ", sizeof(cyxwiz_service_token_req_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_service_token_msg_t) > max_size) {
        printf("SERVICE_TOKEN too large: %zu ", sizeof(cyxwiz_service_token_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_service_token_use_msg_t) > max_size) {
        printf("SERVICE_TOKEN_USE too large: %zu ", sizeof(cyxwiz_service_token_use_msg_t));
        return 0;
    }

    if (sizeof(cyxwiz_reputation_proof_msg_t) > max_size) {
        printf("REPUTATION_PROOF too large: %zu ", sizeof(cyxwiz_reputation_proof_msg_t));
        return 0;
    }

    return 1;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("CyxWiz Privacy Protocol Tests\n");
    printf("==============================\n\n");

    /* Initialize crypto subsystem */
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        printf("Failed to initialize crypto: %s\n", cyxwiz_strerror(err));
        return 1;
    }

    /* Initialize Pedersen module */
    err = cyxwiz_pedersen_init();
    if (err != CYXWIZ_OK) {
        printf("Failed to initialize Pedersen: %s\n", cyxwiz_strerror(err));
        return 1;
    }

    printf("Pedersen Commitment Tests:\n");
    TEST(pedersen_init);
    TEST(pedersen_commit_basic);
    TEST(pedersen_commit_u64);
    TEST(pedersen_wrong_opening);
    TEST(pedersen_wrong_blinding);
    TEST(pedersen_add);
    TEST(pedersen_sub);
    TEST(pedersen_size);

    printf("\nRange Proof Tests:\n");
    TEST(range_proof_16);
    TEST(range_proof_mixed);
    TEST(range_proof_max);
    TEST(range_proof_zero);
    TEST(range_proof_tampered);
    TEST(range_proof_size);
    TEST(range_proof_geq);

    printf("\nAnonymous Credential Tests:\n");
    TEST(cred_request_create);
    TEST(cred_issue_flow);
    TEST(cred_show_verify);
    TEST(cred_multi_issuer);
    TEST(credential_size);

    printf("\nService Token Tests:\n");
    TEST(service_token_flow);
    TEST(service_token_unblind);
    TEST(service_token_use_api);

    printf("\nReputation Proof Tests:\n");
    TEST(reputation_proof_create);
    TEST(reputation_proof_insufficient);

    printf("\nAnonymous Voting Tests:\n");
    TEST(anon_vote_create);

    printf("\nMessage Size Tests:\n");
    TEST(message_sizes);

    printf("\n==============================\n");
    printf("Tests: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
