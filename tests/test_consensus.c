/*
 * CyxWiz Protocol - Consensus Tests
 *
 * Tests for the Proof of Useful Work consensus mechanism.
 */

/* Disable MSVC warning C4127: conditional expression is constant */
#ifdef _MSC_VER
#pragma warning(disable: 4127)
#endif

#include "cyxwiz/consensus.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_OK(err) ASSERT((err) == CYXWIZ_OK)

/* ============ Test Fixtures ============ */

static cyxwiz_transport_t *transport = NULL;
static cyxwiz_peer_table_t *peer_table = NULL;
static cyxwiz_router_t *router = NULL;
static cyxwiz_identity_keypair_t identity;
static cyxwiz_node_id_t node_id;

static void setup(void)
{
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_crypto_init();
#endif

    /* Create transport */
    cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);

    /* Create peer table */
    cyxwiz_peer_table_create(&peer_table);

    /* Generate identity */
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_identity_keygen(&identity);
    cyxwiz_identity_to_node_id(&identity, &node_id);
#else
    memset(&identity, 0, sizeof(identity));
    cyxwiz_node_id_random(&node_id);
#endif

    /* Create router */
    cyxwiz_router_create(&router, peer_table, transport, &node_id);
}

static void teardown(void)
{
    if (router) {
        cyxwiz_router_destroy(router);
        router = NULL;
    }
    if (peer_table) {
        cyxwiz_peer_table_destroy(peer_table);
        peer_table = NULL;
    }
    if (transport) {
        cyxwiz_transport_destroy(transport);
        transport = NULL;
    }
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_identity_destroy(&identity);
#endif
}

/* ============ Lifecycle Tests ============ */

TEST(test_consensus_create_destroy)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);
    ASSERT_NE(ctx, NULL);

    /* Check initial state */
    ASSERT_EQ(cyxwiz_consensus_is_registered(ctx), false);
    ASSERT_EQ(cyxwiz_consensus_get_state(ctx), CYXWIZ_VALIDATOR_INACTIVE);
    ASSERT_EQ(cyxwiz_consensus_get_credits(ctx), 0);
    ASSERT_EQ(cyxwiz_consensus_validator_count(ctx), 0);
    ASSERT_EQ(cyxwiz_consensus_active_rounds(ctx), 0);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_consensus_create_null_params)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;

    /* All NULL */
    cyxwiz_error_t err = cyxwiz_consensus_create(NULL, NULL, NULL, NULL);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* Missing router */
    err = cyxwiz_consensus_create(&ctx, NULL, peer_table, &identity);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* Missing peer_table */
    err = cyxwiz_consensus_create(&ctx, router, NULL, &identity);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* Missing identity */
    err = cyxwiz_consensus_create(&ctx, router, peer_table, NULL);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    teardown();
}

/* ============ Validator Registration Tests ============ */

#ifdef CYXWIZ_HAS_CRYPTO
TEST(test_validator_registration)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Register as validator */
    err = cyxwiz_consensus_register_validator(ctx);
    ASSERT_OK(err);

    /* Should be pending (waiting for ACK) */
    ASSERT_EQ(cyxwiz_consensus_get_state(ctx), CYXWIZ_VALIDATOR_PENDING);
    ASSERT_EQ(cyxwiz_consensus_is_registered(ctx), false);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}
#endif

/* ============ Work Credit Tests ============ */

TEST(test_work_credits_basic)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Initial credits should be 0 */
    ASSERT_EQ(cyxwiz_consensus_get_credits(ctx), 0);

    /* Report some work */
    uint8_t job_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    err = cyxwiz_consensus_report_work(ctx, CYXWIZ_WORK_COMPUTE, job_id, 10);
    ASSERT_OK(err);

    /* Credits should be updated */
    ASSERT_EQ(cyxwiz_consensus_get_credits(ctx), 10);

    /* Report more work */
    uint8_t job_id2[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    err = cyxwiz_consensus_report_work(ctx, CYXWIZ_WORK_STORAGE, job_id2, 5);
    ASSERT_OK(err);

    /* Credits should accumulate */
    ASSERT_EQ(cyxwiz_consensus_get_credits(ctx), 15);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_work_credits_null_params)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* NULL context */
    err = cyxwiz_consensus_report_work(NULL, CYXWIZ_WORK_COMPUTE, NULL, 10);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* NULL work_id */
    err = cyxwiz_consensus_report_work(ctx, CYXWIZ_WORK_COMPUTE, NULL, 10);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

/* ============ Polling Tests ============ */

TEST(test_consensus_poll)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Poll should work */
    err = cyxwiz_consensus_poll(ctx, 1000);
    ASSERT_OK(err);

    /* Poll again with later time */
    err = cyxwiz_consensus_poll(ctx, 2000);
    ASSERT_OK(err);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

/* ============ Committee Selection Tests ============ */

#ifdef CYXWIZ_HAS_CRYPTO
TEST(test_committee_selection_empty)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* With no registered validators, committee selection should fail */
    uint8_t seed[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    cyxwiz_node_id_t committee[CYXWIZ_MAX_VALIDATORS];
    uint8_t committee_size = 0;

    err = cyxwiz_consensus_select_committee(ctx, seed, committee, &committee_size);
    ASSERT_EQ(err, CYXWIZ_ERR_CONSENSUS_NO_QUORUM);
    ASSERT_EQ(committee_size, 0);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}
#endif

/* ============ Message Structure Tests ============ */

TEST(test_message_sizes)
{
    /* Verify all message structures fit within LoRa MTU */
    ASSERT(sizeof(cyxwiz_validator_register_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_validator_reg_ack_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_work_credit_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_validation_req_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_validation_vote_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_validation_result_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_job_validate_req_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_storage_validate_req_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_slash_report_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_credit_query_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_credit_response_msg_t) <= 250);
    ASSERT(sizeof(cyxwiz_validator_heartbeat_msg_t) <= 250);

    /* Print actual sizes for debugging */
    printf("\n    Message sizes:\n");
    printf("      VALIDATOR_REGISTER: %zu bytes\n", sizeof(cyxwiz_validator_register_msg_t));
    printf("      VALIDATOR_REG_ACK:  %zu bytes\n", sizeof(cyxwiz_validator_reg_ack_msg_t));
    printf("      WORK_CREDIT:        %zu bytes\n", sizeof(cyxwiz_work_credit_msg_t));
    printf("      VALIDATION_REQ:     %zu bytes\n", sizeof(cyxwiz_validation_req_msg_t));
    printf("      VALIDATION_VOTE:    %zu bytes\n", sizeof(cyxwiz_validation_vote_msg_t));
    printf("      VALIDATION_RESULT:  %zu bytes\n", sizeof(cyxwiz_validation_result_msg_t));
    printf("      JOB_VALIDATE_REQ:   %zu bytes\n", sizeof(cyxwiz_job_validate_req_msg_t));
    printf("      STORAGE_VALIDATE:   %zu bytes\n", sizeof(cyxwiz_storage_validate_req_msg_t));
    printf("      SLASH_REPORT:       %zu bytes\n", sizeof(cyxwiz_slash_report_msg_t));
    printf("      CREDIT_QUERY:       %zu bytes\n", sizeof(cyxwiz_credit_query_msg_t));
    printf("      CREDIT_RESPONSE:    %zu bytes\n", sizeof(cyxwiz_credit_response_msg_t));
    printf("      VALIDATOR_HEARTBEAT:%zu bytes\n", sizeof(cyxwiz_validator_heartbeat_msg_t));
    printf("    ");
}

/* ============ Utility Function Tests ============ */

TEST(test_utility_functions)
{
    /* Test state name functions */
    ASSERT(strcmp(cyxwiz_validator_state_name(CYXWIZ_VALIDATOR_INACTIVE), "inactive") == 0);
    ASSERT(strcmp(cyxwiz_validator_state_name(CYXWIZ_VALIDATOR_PENDING), "pending") == 0);
    ASSERT(strcmp(cyxwiz_validator_state_name(CYXWIZ_VALIDATOR_ACTIVE), "active") == 0);
    ASSERT(strcmp(cyxwiz_validator_state_name(CYXWIZ_VALIDATOR_SLASHED), "slashed") == 0);

    /* Test result name functions */
    ASSERT(strcmp(cyxwiz_validation_result_name(CYXWIZ_VALIDATION_PENDING), "pending") == 0);
    ASSERT(strcmp(cyxwiz_validation_result_name(CYXWIZ_VALIDATION_VALID), "valid") == 0);
    ASSERT(strcmp(cyxwiz_validation_result_name(CYXWIZ_VALIDATION_INVALID), "invalid") == 0);
    ASSERT(strcmp(cyxwiz_validation_result_name(CYXWIZ_VALIDATION_INCONCLUSIVE), "inconclusive") == 0);
    ASSERT(strcmp(cyxwiz_validation_result_name(CYXWIZ_VALIDATION_TIMEOUT), "timeout") == 0);

    /* Test slash reason names */
    ASSERT(strcmp(cyxwiz_slash_reason_name(CYXWIZ_SLASH_FALSE_POSITIVE), "false_positive") == 0);
    ASSERT(strcmp(cyxwiz_slash_reason_name(CYXWIZ_SLASH_FALSE_NEGATIVE), "false_negative") == 0);
    ASSERT(strcmp(cyxwiz_slash_reason_name(CYXWIZ_SLASH_OFFLINE), "offline") == 0);
    ASSERT(strcmp(cyxwiz_slash_reason_name(CYXWIZ_SLASH_EQUIVOCATION), "equivocation") == 0);
}

/* ============ Get Validator Tests ============ */

TEST(test_get_validator_self)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Get self validator */
    const cyxwiz_validator_t *v = cyxwiz_consensus_get_validator(ctx, &node_id);
    ASSERT_NE(v, NULL);
    ASSERT_EQ(memcmp(&v->node_id, &node_id, sizeof(cyxwiz_node_id_t)), 0);
    ASSERT(v->identity_verified);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_get_validator_unknown)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Get unknown validator */
    cyxwiz_node_id_t unknown;
    memset(&unknown, 0xAB, sizeof(unknown));

    const cyxwiz_validator_t *v = cyxwiz_consensus_get_validator(ctx, &unknown);
    ASSERT_EQ(v, NULL);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

/* ============ Message Handling Tests ============ */

TEST(test_handle_message_null)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* NULL context */
    err = cyxwiz_consensus_handle_message(NULL, &node_id, NULL, 0);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* NULL from */
    uint8_t data[10] = {0};
    err = cyxwiz_consensus_handle_message(ctx, NULL, data, sizeof(data));
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* NULL data */
    err = cyxwiz_consensus_handle_message(ctx, &node_id, NULL, 10);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* Zero length */
    err = cyxwiz_consensus_handle_message(ctx, &node_id, data, 0);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_handle_unknown_message)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Unknown message type should be handled gracefully */
    uint8_t data[10] = {0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    err = cyxwiz_consensus_handle_message(ctx, &node_id, data, sizeof(data));
    ASSERT_OK(err); /* Should not error, just ignore */

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

/* ============ Callback Tests ============ */

static int validation_callback_called = 0;
static int credits_callback_called = 0;
static int state_callback_called = 0;

static void test_validation_cb(const cyxwiz_consensus_round_t *round,
                                cyxwiz_validation_result_t result,
                                void *user_data)
{
    (void)round;
    (void)result;
    (void)user_data;
    validation_callback_called++;
}

static void test_credits_cb(const cyxwiz_node_id_t *validator_id,
                            uint32_t old_credits,
                            uint32_t new_credits,
                            void *user_data)
{
    (void)validator_id;
    (void)old_credits;
    (void)new_credits;
    (void)user_data;
    credits_callback_called++;
}

static void test_state_cb(const cyxwiz_validator_t *validator,
                          cyxwiz_validator_state_t old_state,
                          void *user_data)
{
    (void)validator;
    (void)old_state;
    (void)user_data;
    state_callback_called++;
}

TEST(test_callbacks)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Reset counters */
    validation_callback_called = 0;
    credits_callback_called = 0;
    state_callback_called = 0;

    /* Set callbacks */
    cyxwiz_consensus_set_validation_callback(ctx, test_validation_cb, NULL);
    cyxwiz_consensus_set_credits_callback(ctx, test_credits_cb, NULL);
    cyxwiz_consensus_set_state_callback(ctx, test_state_cb, NULL);

    /* Report work should trigger credits callback */
    uint8_t job_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    err = cyxwiz_consensus_report_work(ctx, CYXWIZ_WORK_COMPUTE, job_id, 10);
    ASSERT_OK(err);
    ASSERT_EQ(credits_callback_called, 1);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

/* ============ Anonymous Voting Tests ============ */

#ifdef CYXWIZ_HAS_CRYPTO
TEST(test_anon_vote_null_params)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    uint8_t round_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    cyxwiz_credential_t cred;
    memset(&cred, 0, sizeof(cred));
    cred.cred_type = CYXWIZ_CRED_VOTE_ELIGIBLE;

    /* NULL context */
    err = cyxwiz_consensus_vote_anonymous(NULL, round_id, true, &cred);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* NULL round_id */
    err = cyxwiz_consensus_vote_anonymous(ctx, NULL, true, &cred);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    /* NULL credential */
    err = cyxwiz_consensus_vote_anonymous(ctx, round_id, true, NULL);
    ASSERT_EQ(err, CYXWIZ_ERR_INVALID);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_anon_vote_wrong_cred_type)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    uint8_t round_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    cyxwiz_credential_t cred;
    memset(&cred, 0, sizeof(cred));
    cred.cred_type = CYXWIZ_CRED_SERVICE_ACCESS; /* Wrong type */

    /* Should reject wrong credential type */
    err = cyxwiz_consensus_vote_anonymous(ctx, round_id, true, &cred);
    ASSERT_EQ(err, CYXWIZ_ERR_CREDENTIAL_INVALID);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_round_allows_anonymous)
{
    setup();

    cyxwiz_consensus_ctx_t *ctx = NULL;
    cyxwiz_error_t err = cyxwiz_consensus_create(&ctx, router, peer_table, &identity);
    ASSERT_OK(err);

    /* Unknown round should allow anonymous by default */
    uint8_t unknown_round[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool allows = cyxwiz_consensus_round_allows_anonymous(ctx, unknown_round);
    ASSERT(allows);

    /* NULL context should return false */
    allows = cyxwiz_consensus_round_allows_anonymous(NULL, unknown_round);
    ASSERT(!allows);

    /* NULL round_id should return false */
    allows = cyxwiz_consensus_round_allows_anonymous(ctx, NULL);
    ASSERT(!allows);

    cyxwiz_consensus_destroy(ctx);
    teardown();
}

TEST(test_consensus_round_anon_fields)
{
    /* Verify consensus round structure has anonymous voting fields */
    cyxwiz_consensus_round_t round;
    memset(&round, 0, sizeof(round));

    /* Set anonymous vote counts */
    round.anon_votes_valid = 5;
    round.anon_votes_invalid = 3;
    round.allows_anonymous = true;

    ASSERT_EQ(round.anon_votes_valid, 5);
    ASSERT_EQ(round.anon_votes_invalid, 3);
    ASSERT(round.allows_anonymous);
}
#endif

/* ============ Main ============ */

int main(void)
{
    printf("CyxWiz Consensus Tests\n");
    printf("======================\n\n");

    printf("Lifecycle Tests:\n");
    RUN_TEST(test_consensus_create_destroy);
    RUN_TEST(test_consensus_create_null_params);

    printf("\nValidator Registration Tests:\n");
#ifdef CYXWIZ_HAS_CRYPTO
    RUN_TEST(test_validator_registration);
#else
    printf("  (skipped - requires crypto)\n");
#endif

    printf("\nWork Credit Tests:\n");
    RUN_TEST(test_work_credits_basic);
    RUN_TEST(test_work_credits_null_params);

    printf("\nPolling Tests:\n");
    RUN_TEST(test_consensus_poll);

    printf("\nCommittee Selection Tests:\n");
#ifdef CYXWIZ_HAS_CRYPTO
    RUN_TEST(test_committee_selection_empty);
#else
    printf("  (skipped - requires crypto)\n");
#endif

    printf("\nMessage Structure Tests:\n");
    RUN_TEST(test_message_sizes);

    printf("\nUtility Function Tests:\n");
    RUN_TEST(test_utility_functions);

    printf("\nGet Validator Tests:\n");
    RUN_TEST(test_get_validator_self);
    RUN_TEST(test_get_validator_unknown);

    printf("\nMessage Handling Tests:\n");
    RUN_TEST(test_handle_message_null);
    RUN_TEST(test_handle_unknown_message);

    printf("\nCallback Tests:\n");
    RUN_TEST(test_callbacks);

    printf("\nAnonymous Voting Tests:\n");
#ifdef CYXWIZ_HAS_CRYPTO
    RUN_TEST(test_anon_vote_null_params);
    RUN_TEST(test_anon_vote_wrong_cred_type);
    RUN_TEST(test_round_allows_anonymous);
    RUN_TEST(test_consensus_round_anon_fields);
#else
    printf("  (skipped - requires crypto)\n");
#endif

    printf("\n======================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
