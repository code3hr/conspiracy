/*
 * CyxWiz Protocol - Compute Layer Tests
 */

#include "cyxwiz/types.h"
#include "cyxwiz/compute.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/peer.h"
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

/* Mock router for testing */
static cyxwiz_node_id_t g_last_send_to;
static uint8_t g_last_send_data[256];
static size_t g_last_send_len;
static int g_send_count = 0;

/* Minimal router mock - we just need to track sends */
typedef struct {
    cyxwiz_node_id_t local_id;
} mock_router_t;

static mock_router_t g_mock_router;

/* Override router_send for testing */
cyxwiz_error_t cyxwiz_router_send(
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(router);
    memcpy(&g_last_send_to, to, sizeof(cyxwiz_node_id_t));
    if (len <= sizeof(g_last_send_data)) {
        memcpy(g_last_send_data, data, len);
    }
    g_last_send_len = len;
    g_send_count++;
    return CYXWIZ_OK;
}

/* Test context creation */
static int test_context_create(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id;
    memset(&local_id, 0x42, sizeof(local_id));

    /* Create with NULL args should fail */
    cyxwiz_error_t err = cyxwiz_compute_create(NULL, NULL, NULL, NULL, NULL);
    if (err == CYXWIZ_OK) {
        return 0;
    }

    /* Create valid context */
    err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    if (ctx == NULL) {
        return 0;
    }

    /* Check initial state */
    if (cyxwiz_compute_is_worker(ctx)) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    if (cyxwiz_compute_job_count(ctx) != 0) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

/* Test worker mode enable/disable */
static int test_worker_mode(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id;
    memset(&local_id, 0x42, sizeof(local_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Initially not a worker */
    if (cyxwiz_compute_is_worker(ctx)) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Enable worker mode */
    err = cyxwiz_compute_enable_worker(ctx, 4);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    if (!cyxwiz_compute_is_worker(ctx)) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Disable worker mode */
    cyxwiz_compute_disable_worker(ctx);
    if (cyxwiz_compute_is_worker(ctx)) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

/* Test job ID utilities */
static int test_job_id_utils(void)
{
    cyxwiz_job_id_t id1, id2;
    memset(id1.bytes, 0x11, CYXWIZ_JOB_ID_SIZE);
    memset(id2.bytes, 0x22, CYXWIZ_JOB_ID_SIZE);

    /* Compare different */
    if (cyxwiz_job_id_compare(&id1, &id2) == 0) {
        return 0;
    }

    /* Compare same */
    if (cyxwiz_job_id_compare(&id1, &id1) != 0) {
        return 0;
    }

    /* To hex */
    char hex[17];
    cyxwiz_job_id_to_hex(&id1, hex);
    if (strlen(hex) != 16) {
        return 0;
    }
    if (strcmp(hex, "1111111111111111") != 0) {
        return 0;
    }

    return 1;
}

/* Test state and type names */
static int test_name_functions(void)
{
    const char *name;

    /* State names */
    name = cyxwiz_job_state_name(CYXWIZ_JOB_STATE_PENDING);
    if (strcmp(name, "PENDING") != 0) {
        return 0;
    }

    name = cyxwiz_job_state_name(CYXWIZ_JOB_STATE_COMPLETED);
    if (strcmp(name, "COMPLETED") != 0) {
        return 0;
    }

    /* Type names */
    name = cyxwiz_job_type_name(CYXWIZ_JOB_TYPE_HASH);
    if (strcmp(name, "HASH") != 0) {
        return 0;
    }

    name = cyxwiz_job_type_name(CYXWIZ_JOB_TYPE_CUSTOM);
    if (strcmp(name, "CUSTOM") != 0) {
        return 0;
    }

    return 1;
}

/* Test job submission */
static int test_job_submit(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id, worker_id;
    memset(&local_id, 0x42, sizeof(local_id));
    memset(&worker_id, 0xAB, sizeof(worker_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    g_send_count = 0;

    /* Submit a job */
    uint8_t payload[] = "test payload data";
    cyxwiz_job_id_t job_id;

    err = cyxwiz_compute_submit(ctx, &worker_id, CYXWIZ_JOB_TYPE_HASH,
                                payload, sizeof(payload) - 1, &job_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Should have sent a message */
    if (g_send_count == 0) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Check message type */
    if (g_last_send_data[0] != CYXWIZ_MSG_JOB_SUBMIT) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Check destination */
    if (memcmp(&g_last_send_to, &worker_id, sizeof(cyxwiz_node_id_t)) != 0) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Should have 1 active job */
    if (cyxwiz_compute_job_count(ctx) != 1) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Can find the job */
    const cyxwiz_job_t *job = cyxwiz_compute_get_job(ctx, &job_id);
    if (job == NULL) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    if (job->state != CYXWIZ_JOB_STATE_PENDING) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

/* Test job cancel */
static int test_job_cancel(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id, worker_id;
    memset(&local_id, 0x42, sizeof(local_id));
    memset(&worker_id, 0xAB, sizeof(worker_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Submit a job */
    uint8_t payload[] = "test";
    cyxwiz_job_id_t job_id;
    err = cyxwiz_compute_submit(ctx, &worker_id, CYXWIZ_JOB_TYPE_HASH,
                                payload, sizeof(payload), &job_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    if (cyxwiz_compute_job_count(ctx) != 1) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Cancel job */
    err = cyxwiz_compute_cancel(ctx, &job_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Should have 0 jobs now */
    if (cyxwiz_compute_job_count(ctx) != 0) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Cancel non-existent job should fail */
    err = cyxwiz_compute_cancel(ctx, &job_id);
    if (err != CYXWIZ_ERR_JOB_NOT_FOUND) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

/* Test MAC computation and verification */
static int test_result_mac(void)
{
    /* Initialize crypto */
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_crypto_ctx_t *crypto_ctx = NULL;
    err = cyxwiz_crypto_create(&crypto_ctx, 2, 3, 1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id;
    memset(&local_id, 0x42, sizeof(local_id));

    err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, crypto_ctx, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    /* Compute MAC */
    cyxwiz_job_id_t job_id;
    memset(job_id.bytes, 0xAA, CYXWIZ_JOB_ID_SIZE);

    uint8_t result[] = "computation result";
    uint8_t mac[CYXWIZ_MAC_SIZE];

    err = cyxwiz_compute_result_mac(ctx, &job_id, result, sizeof(result), mac);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    /* Verify MAC */
    err = cyxwiz_compute_verify_result(ctx, &job_id, result, sizeof(result), mac);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    /* Modify result - verification should fail */
    result[0] ^= 0xFF;
    err = cyxwiz_compute_verify_result(ctx, &job_id, result, sizeof(result), mac);
    if (err != CYXWIZ_ERR_MAC_INVALID) {
        cyxwiz_compute_destroy(ctx);
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    cyxwiz_crypto_destroy(crypto_ctx);
    return 1;
}

/* Test message handling - job submit as worker */
static int test_handle_job_submit(void)
{
    cyxwiz_crypto_init();

    cyxwiz_crypto_ctx_t *crypto_ctx = NULL;
    cyxwiz_crypto_create(&crypto_ctx, 2, 3, 1);

    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id, submitter_id;
    memset(&local_id, 0x42, sizeof(local_id));
    memset(&submitter_id, 0xBB, sizeof(submitter_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, crypto_ctx, &local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    /* Enable worker mode */
    cyxwiz_compute_enable_worker(ctx, 4);

    g_send_count = 0;

    /* Create a JOB_SUBMIT message */
    uint8_t msg[64];
    cyxwiz_job_submit_msg_t *submit = (cyxwiz_job_submit_msg_t *)msg;
    submit->type = CYXWIZ_MSG_JOB_SUBMIT;
    memset(submit->job_id, 0x11, CYXWIZ_JOB_ID_SIZE);
    submit->job_type = CYXWIZ_JOB_TYPE_HASH;
    submit->total_chunks = 0;  /* Single packet */
    submit->payload_len = 4;

    /* Add payload */
    memcpy(msg + sizeof(cyxwiz_job_submit_msg_t), "test", 4);

    /* Handle the message */
    err = cyxwiz_compute_handle_message(ctx, &submitter_id, msg,
                                        sizeof(cyxwiz_job_submit_msg_t) + 4);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    /* Should have sent JOB_ACCEPT and JOB_RESULT */
    if (g_send_count < 2) {
        cyxwiz_compute_destroy(ctx);
        cyxwiz_crypto_destroy(crypto_ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    cyxwiz_crypto_destroy(crypto_ctx);
    return 1;
}

/* Test job rejection when not in worker mode */
static int test_reject_not_worker(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id, submitter_id;
    memset(&local_id, 0x42, sizeof(local_id));
    memset(&submitter_id, 0xBB, sizeof(submitter_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* NOT enabling worker mode */
    g_send_count = 0;

    /* Create a JOB_SUBMIT message */
    uint8_t msg[64];
    cyxwiz_job_submit_msg_t *submit = (cyxwiz_job_submit_msg_t *)msg;
    submit->type = CYXWIZ_MSG_JOB_SUBMIT;
    memset(submit->job_id, 0x11, CYXWIZ_JOB_ID_SIZE);
    submit->job_type = CYXWIZ_JOB_TYPE_HASH;
    submit->total_chunks = 0;
    submit->payload_len = 4;
    memcpy(msg + sizeof(cyxwiz_job_submit_msg_t), "test", 4);

    /* Handle the message */
    err = cyxwiz_compute_handle_message(ctx, &submitter_id, msg,
                                        sizeof(cyxwiz_job_submit_msg_t) + 4);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Should have sent JOB_REJECT */
    if (g_send_count != 1) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    if (g_last_send_data[0] != CYXWIZ_MSG_JOB_REJECT) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

/* Test polling with timeouts */
static int test_poll_timeout(void)
{
    cyxwiz_compute_ctx_t *ctx = NULL;
    cyxwiz_node_id_t local_id, worker_id;
    memset(&local_id, 0x42, sizeof(local_id));
    memset(&worker_id, 0xAB, sizeof(worker_id));

    cyxwiz_error_t err = cyxwiz_compute_create(&ctx, (cyxwiz_router_t *)&g_mock_router, NULL, NULL, &local_id);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Submit a job */
    uint8_t payload[] = "test";
    cyxwiz_job_id_t job_id;
    err = cyxwiz_compute_submit(ctx, &worker_id, CYXWIZ_JOB_TYPE_HASH,
                                payload, sizeof(payload), &job_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Poll at current time - no timeout */
    uint64_t now = cyxwiz_time_ms();
    cyxwiz_compute_poll(ctx, now);

    if (cyxwiz_compute_job_count(ctx) != 1) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    /* Poll way in the future - should timeout */
    cyxwiz_compute_poll(ctx, now + CYXWIZ_JOB_TIMEOUT_MS + 1000);

    if (cyxwiz_compute_job_count(ctx) != 0) {
        cyxwiz_compute_destroy(ctx);
        return 0;
    }

    cyxwiz_compute_destroy(ctx);
    return 1;
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_WARN);

    printf("\nCyxWiz Compute Tests\n");
    printf("====================\n\n");

    TEST(context_create);
    TEST(worker_mode);
    TEST(job_id_utils);
    TEST(name_functions);
    TEST(job_submit);
    TEST(job_cancel);
    TEST(result_mac);
    TEST(handle_job_submit);
    TEST(reject_not_worker);
    TEST(poll_timeout);

    printf("\n====================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
