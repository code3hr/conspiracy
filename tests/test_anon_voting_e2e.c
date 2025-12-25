/*
 * CyxWiz Protocol - Anonymous Voting End-to-End Test
 *
 * Tests the complete anonymous voting flow:
 * 1. Initialize multiple validators
 * 2. Obtain validator credentials
 * 3. Start a validation round
 * 4. Cast anonymous votes
 * 5. Verify quorum is reached
 */

#include "cyxwiz/consensus.h"
#include "cyxwiz/privacy.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

/* Test configuration */
#define NUM_VALIDATORS 5
#define QUORUM_THRESHOLD 3  /* Need 3 of 5 for consensus */

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAILED: %s\n", msg); \
        tests_failed++; \
        return 0; \
    } \
} while(0)

#define TEST_OK(err, msg) TEST_ASSERT((err) == CYXWIZ_OK, msg)

/* Validator state for test */
typedef struct {
    cyxwiz_identity_keypair_t identity;
    cyxwiz_node_id_t node_id;
    cyxwiz_credential_t credential;
    bool has_credential;
} test_validator_t;

static test_validator_t validators[NUM_VALIDATORS];

/* Issuer keypair (for credential issuance) */
static cyxwiz_identity_keypair_t issuer_identity;

/*
 * Test 1: Initialize validators and obtain credentials
 */
static int test_credential_issuance(void)
{
    cyxwiz_error_t err;

    printf("  Initializing %d validators...\n", NUM_VALIDATORS);

    /* Generate issuer identity */
    err = cyxwiz_identity_keygen(&issuer_identity);
    TEST_OK(err, "Failed to generate issuer identity");

    /* Initialize each validator */
    for (int i = 0; i < NUM_VALIDATORS; i++) {
        /* Generate validator identity */
        err = cyxwiz_identity_keygen(&validators[i].identity);
        TEST_OK(err, "Failed to generate validator identity");

        /* Derive node ID */
        err = cyxwiz_identity_to_node_id(&validators[i].identity, &validators[i].node_id);
        TEST_OK(err, "Failed to derive node ID");

        /* Create credential request (blinded) */
        cyxwiz_cred_request_t request;
        uint8_t blinding[32];
        err = cyxwiz_cred_request_create(
            CYXWIZ_CRED_VOTE_ELIGIBLE,
            validators[i].identity.public_key,
            CYXWIZ_ED25519_PK_SIZE,
            &request,
            blinding
        );
        TEST_OK(err, "Failed to create credential request");

        /* Issuer signs the blinded request */
        uint8_t blinded_sig[64];
        uint64_t expires_at = 0; /* Never expires for test */
        err = cyxwiz_cred_issue(&issuer_identity, &request, expires_at, blinded_sig);
        TEST_OK(err, "Failed to issue credential");

        /* Validator unblinds to get usable credential */
        err = cyxwiz_cred_unblind(
            blinded_sig,
            blinding,
            issuer_identity.public_key,
            validators[i].identity.public_key,
            CYXWIZ_ED25519_PK_SIZE,
            expires_at,
            &validators[i].credential
        );
        TEST_OK(err, "Failed to unblind credential");

        validators[i].has_credential = true;
        printf("    Validator %d: credential obtained\n", i + 1);
    }

    printf("  All validators have credentials\n");
    return 1;
}

/*
 * Test 2: Create and verify credential show proofs
 */
static int test_credential_showing(void)
{
    cyxwiz_error_t err;

    printf("  Testing credential show proofs...\n");

    for (int i = 0; i < NUM_VALIDATORS; i++) {
        TEST_ASSERT(validators[i].has_credential, "Validator missing credential");

        /* Create a context for this showing */
        uint8_t context[16];
        memset(context, 0, sizeof(context));
        snprintf((char *)context, sizeof(context), "round_%d", i);

        /* Create show proof */
        cyxwiz_cred_show_proof_t proof;
        err = cyxwiz_cred_show_create(&validators[i].credential, context, &proof);
        TEST_OK(err, "Failed to create show proof");

        /* Verify the proof */
        err = cyxwiz_cred_show_verify(
            &proof,
            CYXWIZ_CRED_VOTE_ELIGIBLE,
            issuer_identity.public_key,
            0  /* current_time - 0 means no expiry check */
        );
        TEST_OK(err, "Failed to verify show proof");

        printf("    Validator %d: show proof verified\n", i + 1);
    }

    printf("  All show proofs verified\n");
    return 1;
}

/*
 * Test 3: Simulate anonymous voting round
 */
static int test_anonymous_voting_round(void)
{
    cyxwiz_error_t err;

    printf("  Simulating anonymous voting round...\n");

    /* Round ID for this validation */
    uint8_t round_id[8];
#ifdef CYXWIZ_HAS_CRYPTO
    randombytes_buf(round_id, sizeof(round_id));
#else
    memset(round_id, 0x42, sizeof(round_id));
#endif

    printf("    Round ID: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", round_id[i]);
    }
    printf("\n");

    /* Each validator creates an anonymous vote message */
    int votes_valid = 0;
    int votes_invalid = 0;

    for (int i = 0; i < NUM_VALIDATORS; i++) {
        /* Decide how to vote (first 3 vote valid, last 2 vote invalid) */
        bool vote = (i < 3);

        /* Create anonymous vote message */
        uint8_t vote_msg[256];
        size_t vote_len;
        err = cyxwiz_privacy_vote_anonymous(
            &validators[i].credential,
            round_id,
            vote,
            vote_msg,
            &vote_len
        );
        if (err != CYXWIZ_OK) {
            printf("    Validator %d: vote creation failed with error %d\n", i + 1, err);
            TEST_OK(err, "Failed to create anonymous vote");
        }

        /* Verify the vote message structure */
        TEST_ASSERT(vote_len == sizeof(cyxwiz_anon_vote_msg_t),
                    "Vote message wrong size");
        TEST_ASSERT(vote_msg[0] == CYXWIZ_MSG_ANON_VOTE,
                    "Vote message wrong type");

        /* Parse vote message */
        cyxwiz_anon_vote_msg_t *msg = (cyxwiz_anon_vote_msg_t *)vote_msg;
        TEST_ASSERT(memcmp(msg->round_id, round_id, 8) == 0,
                    "Round ID mismatch in vote message");

        /* Verify credential proof in vote */
        err = cyxwiz_cred_show_verify(
            &msg->cred_proof,
            CYXWIZ_CRED_VOTE_ELIGIBLE,
            issuer_identity.public_key,
            0
        );
        TEST_OK(err, "Failed to verify vote credential");

        /* Count votes */
        if (msg->vote) {
            votes_valid++;
        } else {
            votes_invalid++;
        }

        printf("    Validator %d: anonymous vote %s (credential verified)\n",
               i + 1, vote ? "VALID" : "INVALID");
    }

    printf("    Vote tally: %d valid, %d invalid\n", votes_valid, votes_invalid);

    /* Check quorum */
    TEST_ASSERT(votes_valid >= QUORUM_THRESHOLD,
                "Quorum not reached for valid votes");

    printf("  Quorum reached: %d/%d validators voted VALID\n",
           votes_valid, QUORUM_THRESHOLD);

    return 1;
}

/*
 * Test 4: Test vote unlinkability (same credential, different showings)
 */
static int test_vote_unlinkability(void)
{
    cyxwiz_error_t err;

    printf("  Testing vote unlinkability...\n");

    /* Use first validator */
    test_validator_t *v = &validators[0];

    /* Create two different vote messages with different round IDs */
    uint8_t round1[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t round2[8] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

    uint8_t vote1[256], vote2[256];
    size_t len1, len2;

    err = cyxwiz_privacy_vote_anonymous(&v->credential, round1, true, vote1, &len1);
    TEST_OK(err, "Failed to create vote 1");

    err = cyxwiz_privacy_vote_anonymous(&v->credential, round2, true, vote2, &len2);
    TEST_OK(err, "Failed to create vote 2");

    /* Both votes should be valid */
    cyxwiz_anon_vote_msg_t *msg1 = (cyxwiz_anon_vote_msg_t *)vote1;
    cyxwiz_anon_vote_msg_t *msg2 = (cyxwiz_anon_vote_msg_t *)vote2;

    err = cyxwiz_cred_show_verify(&msg1->cred_proof, CYXWIZ_CRED_VOTE_ELIGIBLE,
                                   issuer_identity.public_key, 0);
    TEST_OK(err, "Vote 1 credential invalid");

    err = cyxwiz_cred_show_verify(&msg2->cred_proof, CYXWIZ_CRED_VOTE_ELIGIBLE,
                                   issuer_identity.public_key, 0);
    TEST_OK(err, "Vote 2 credential invalid");

    /* The credential proofs should be different (unlinkable) */
    int proofs_identical = (memcmp(&msg1->cred_proof, &msg2->cred_proof,
                                    sizeof(cyxwiz_cred_show_proof_t)) == 0);
    TEST_ASSERT(!proofs_identical, "Credential proofs should be unlinkable");

    printf("    Two votes from same validator are unlinkable\n");
    printf("  Unlinkability verified\n");

    return 1;
}

/*
 * Test 5: Test message sizes fit LoRa MTU
 */
static int test_message_sizes(void)
{
    printf("  Checking message sizes...\n");

    size_t anon_vote_size = sizeof(cyxwiz_anon_vote_msg_t);
    printf("    ANON_VOTE message: %zu bytes\n", anon_vote_size);

    TEST_ASSERT(anon_vote_size <= 250, "ANON_VOTE exceeds LoRa MTU");

    printf("  All messages fit within 250-byte LoRa MTU\n");
    return 1;
}

/*
 * Test 6: Full consensus integration test
 */
static int test_consensus_integration(void)
{
    cyxwiz_error_t err;

    printf("  Testing consensus integration...\n");

    /* Create minimal infrastructure */
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_peer_table_t *peer_table = NULL;
    cyxwiz_router_t *router = NULL;
    cyxwiz_consensus_ctx_t *consensus = NULL;

    /* Create transport */
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    TEST_OK(err, "Failed to create transport");

    /* Create peer table */
    err = cyxwiz_peer_table_create(&peer_table);
    TEST_OK(err, "Failed to create peer table");

    /* Create router */
    err = cyxwiz_router_create(&router, peer_table, transport, &validators[0].node_id);
    TEST_OK(err, "Failed to create router");

    /* Create consensus context */
    err = cyxwiz_consensus_create(&consensus, router, peer_table, &validators[0].identity);
    TEST_OK(err, "Failed to create consensus context");

    /* Test anonymous voting API */
    uint8_t round_id[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    /* Check if round allows anonymous voting (unknown round defaults to yes) */
    bool allows = cyxwiz_consensus_round_allows_anonymous(consensus, round_id);
    TEST_ASSERT(allows, "Unknown round should allow anonymous voting");

    printf("    Consensus context created\n");
    printf("    Anonymous voting enabled for rounds\n");

    /* Cleanup */
    cyxwiz_consensus_destroy(consensus);
    cyxwiz_router_destroy(router);
    cyxwiz_peer_table_destroy(peer_table);
    cyxwiz_transport_destroy(transport);

    printf("  Consensus integration verified\n");
    return 1;
}

/*
 * Cleanup
 */
static void cleanup(void)
{
    for (int i = 0; i < NUM_VALIDATORS; i++) {
        cyxwiz_identity_destroy(&validators[i].identity);
    }
    cyxwiz_identity_destroy(&issuer_identity);
}

/*
 * Main
 */
int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  Anonymous Voting End-to-End Test\n");
    printf("========================================\n\n");

#ifdef CYXWIZ_HAS_CRYPTO
    /* Initialize crypto */
    if (cyxwiz_crypto_init() != CYXWIZ_OK) {
        printf("Failed to initialize crypto\n");
        return 1;
    }

    /* Initialize Pedersen parameters */
    if (cyxwiz_pedersen_init() != CYXWIZ_OK) {
        printf("Failed to initialize Pedersen parameters\n");
        return 1;
    }

    printf("Test 1: Credential Issuance\n");
    if (test_credential_issuance()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    printf("Test 2: Credential Showing\n");
    if (test_credential_showing()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    printf("Test 3: Anonymous Voting Round\n");
    if (test_anonymous_voting_round()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    printf("Test 4: Vote Unlinkability\n");
    if (test_vote_unlinkability()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    printf("Test 5: Message Sizes\n");
    if (test_message_sizes()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    printf("Test 6: Consensus Integration\n");
    if (test_consensus_integration()) {
        tests_passed++;
        printf("  PASSED\n\n");
    } else {
        printf("\n");
    }

    cleanup();

    printf("========================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n\n");

    return tests_failed > 0 ? 1 : 0;

#else
    printf("Skipped: requires CYXWIZ_HAS_CRYPTO\n");
    return 0;
#endif
}
