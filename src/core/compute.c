/*
 * CyxWiz Protocol - Compute Layer Implementation
 *
 * Implements job marketplace for distributed computation:
 * - Job submission and tracking
 * - Worker execution
 * - Result delivery with MAC verification
 * - Payload chunking for large jobs
 */

#include "cyxwiz/compute.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>

/* ============ Internal Context ============ */

struct cyxwiz_compute_ctx {
    /* Dependencies */
    cyxwiz_router_t *router;
    cyxwiz_peer_table_t *peer_table;
    cyxwiz_crypto_ctx_t *crypto_ctx;
    cyxwiz_node_id_t local_id;

    /* Job storage */
    cyxwiz_job_t jobs[CYXWIZ_MAX_ACTIVE_JOBS];
    size_t job_count;

    /* Worker state */
    bool is_worker;
    size_t max_concurrent;
    size_t active_worker_jobs;

    /* Callbacks */
    cyxwiz_job_complete_cb_t on_complete;
    void *complete_user_data;
    cyxwiz_job_execute_cb_t on_execute;
    void *execute_user_data;

    /* State */
    bool running;
    uint64_t last_poll;
};

/* ============ Forward Declarations ============ */

static cyxwiz_job_t *find_job(cyxwiz_compute_ctx_t *ctx, const cyxwiz_job_id_t *job_id);
static cyxwiz_job_t *alloc_job(cyxwiz_compute_ctx_t *ctx);
static void free_job(cyxwiz_job_t *job);
static cyxwiz_error_t send_job_submit(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);
static cyxwiz_error_t send_job_chunk(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *to,
                                      const cyxwiz_job_id_t *job_id, uint8_t chunk_index,
                                      const uint8_t *data, size_t len);
static cyxwiz_error_t send_job_accept(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *to,
                                       const cyxwiz_job_id_t *job_id);
static cyxwiz_error_t send_job_reject(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *to,
                                       const cyxwiz_job_id_t *job_id, cyxwiz_reject_reason_t reason);
static cyxwiz_error_t send_job_result(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);
static cyxwiz_error_t send_job_ack(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *to,
                                    const cyxwiz_job_id_t *job_id);
static cyxwiz_error_t send_job_accept_via_surb(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);
static cyxwiz_error_t send_job_result_via_surb(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);

static cyxwiz_error_t handle_job_submit(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len, bool is_anonymous);
static cyxwiz_error_t handle_job_chunk(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                        const uint8_t *data, size_t len);
static cyxwiz_error_t handle_job_accept(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);
static cyxwiz_error_t handle_job_reject(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);
static cyxwiz_error_t handle_job_result(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);
static cyxwiz_error_t handle_job_ack(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                      const uint8_t *data, size_t len);
static cyxwiz_error_t handle_job_cancel(cyxwiz_compute_ctx_t *ctx, const cyxwiz_node_id_t *from,
                                         const uint8_t *data, size_t len);

static cyxwiz_error_t execute_job(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);
static cyxwiz_error_t execute_builtin_job(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);

/* ============ Context Lifecycle ============ */

cyxwiz_error_t cyxwiz_compute_create(
    cyxwiz_compute_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_crypto_ctx_t *crypto_ctx,
    const cyxwiz_node_id_t *local_id)
{
    if (ctx == NULL || router == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_compute_ctx_t *c = cyxwiz_calloc(1, sizeof(cyxwiz_compute_ctx_t));
    if (c == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    c->router = router;
    c->peer_table = peer_table;
    c->crypto_ctx = crypto_ctx;
    memcpy(&c->local_id, local_id, sizeof(cyxwiz_node_id_t));

    c->job_count = 0;
    c->is_worker = false;
    c->max_concurrent = 0;
    c->active_worker_jobs = 0;

    c->on_complete = NULL;
    c->on_execute = NULL;
    c->running = true;
    c->last_poll = 0;

    /* Initialize all job slots as invalid */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        c->jobs[i].valid = false;
    }

    CYXWIZ_INFO("Created compute context");
    *ctx = c;
    return CYXWIZ_OK;
}

void cyxwiz_compute_destroy(cyxwiz_compute_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Clear all jobs */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        if (ctx->jobs[i].valid) {
            cyxwiz_secure_zero(&ctx->jobs[i], sizeof(cyxwiz_job_t));
        }
    }

    CYXWIZ_INFO("Destroyed compute context");
    cyxwiz_free(ctx, sizeof(cyxwiz_compute_ctx_t));
}

cyxwiz_error_t cyxwiz_compute_enable_worker(
    cyxwiz_compute_ctx_t *ctx,
    size_t max_concurrent)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (max_concurrent == 0) {
        max_concurrent = CYXWIZ_DEFAULT_WORKER_CAPACITY;
    }

    ctx->is_worker = true;
    ctx->max_concurrent = max_concurrent;
    ctx->active_worker_jobs = 0;

    CYXWIZ_INFO("Enabled worker mode (capacity: %zu)", max_concurrent);
    return CYXWIZ_OK;
}

void cyxwiz_compute_disable_worker(cyxwiz_compute_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->is_worker = false;
    ctx->max_concurrent = 0;
    CYXWIZ_INFO("Disabled worker mode");
}

bool cyxwiz_compute_is_worker(const cyxwiz_compute_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return ctx->is_worker;
}

/* ============ Callbacks ============ */

void cyxwiz_compute_set_complete_callback(
    cyxwiz_compute_ctx_t *ctx,
    cyxwiz_job_complete_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->on_complete = callback;
    ctx->complete_user_data = user_data;
}

void cyxwiz_compute_set_execute_callback(
    cyxwiz_compute_ctx_t *ctx,
    cyxwiz_job_execute_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->on_execute = callback;
    ctx->execute_user_data = user_data;
}

/* ============ Job Management ============ */

static cyxwiz_job_t *find_job(cyxwiz_compute_ctx_t *ctx, const cyxwiz_job_id_t *job_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        if (ctx->jobs[i].valid &&
            memcmp(ctx->jobs[i].id.bytes, job_id->bytes, CYXWIZ_JOB_ID_SIZE) == 0) {
            return &ctx->jobs[i];
        }
    }
    return NULL;
}

static cyxwiz_job_t *alloc_job(cyxwiz_compute_ctx_t *ctx)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        if (!ctx->jobs[i].valid) {
            memset(&ctx->jobs[i], 0, sizeof(cyxwiz_job_t));
            ctx->jobs[i].valid = true;
            ctx->job_count++;
            return &ctx->jobs[i];
        }
    }
    return NULL;
}

static void free_job(cyxwiz_job_t *job)
{
    if (job != NULL && job->valid) {
        cyxwiz_secure_zero(job, sizeof(cyxwiz_job_t));
        job->valid = false;
    }
}

const cyxwiz_job_t *cyxwiz_compute_get_job(
    const cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id)
{
    if (ctx == NULL || job_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        if (ctx->jobs[i].valid &&
            memcmp(ctx->jobs[i].id.bytes, job_id->bytes, CYXWIZ_JOB_ID_SIZE) == 0) {
            return &ctx->jobs[i];
        }
    }
    return NULL;
}

size_t cyxwiz_compute_job_count(const cyxwiz_compute_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        if (ctx->jobs[i].valid) {
            count++;
        }
    }
    return count;
}

/* ============ Job Submission ============ */

cyxwiz_error_t cyxwiz_compute_submit(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *worker,
    cyxwiz_job_type_t type,
    const uint8_t *payload,
    size_t payload_len,
    cyxwiz_job_id_t *job_id_out)
{
    if (ctx == NULL || worker == NULL || job_id_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (payload_len > 0 && payload == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (payload_len > CYXWIZ_JOB_MAX_TOTAL_PAYLOAD) {
        CYXWIZ_ERROR("Payload too large: %zu > %d", payload_len, CYXWIZ_JOB_MAX_TOTAL_PAYLOAD);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Allocate job slot */
    cyxwiz_job_t *job = alloc_job(ctx);
    if (job == NULL) {
        CYXWIZ_ERROR("Job table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Generate job ID */
    cyxwiz_crypto_random(job->id.bytes, CYXWIZ_JOB_ID_SIZE);

    /* Initialize job */
    job->type = type;
    job->state = CYXWIZ_JOB_STATE_PENDING;
    job->is_anonymous = false;
    memcpy(&job->submitter.direct_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(&job->worker, worker, sizeof(cyxwiz_node_id_t));
    job->is_submitter = true;

    /* Copy payload */
    if (payload_len > 0) {
        memcpy(job->payload, payload, payload_len);
    }
    job->payload_len = payload_len;

    /* Calculate chunks needed */
    if (payload_len <= CYXWIZ_JOB_MAX_PAYLOAD) {
        job->total_chunks = 0;  /* Single packet */
    } else {
        job->total_chunks = (uint8_t)((payload_len + CYXWIZ_JOB_CHUNK_SIZE - 1) / CYXWIZ_JOB_CHUNK_SIZE);
    }

    job->submitted_at = cyxwiz_time_ms();

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);
    CYXWIZ_DEBUG("Submitting job %s (type=%d, payload=%zu bytes, chunks=%d)",
                 hex_id, type, payload_len, job->total_chunks);

    /* Send job submission */
    cyxwiz_error_t err = send_job_submit(ctx, job);
    if (err != CYXWIZ_OK) {
        free_job(job);
        ctx->job_count--;
        return err;
    }

    /* Output job ID */
    memcpy(job_id_out, &job->id, sizeof(cyxwiz_job_id_t));

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_compute_cancel(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id)
{
    if (ctx == NULL || job_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_job_t *job = find_job(ctx, job_id);
    if (job == NULL) {
        return CYXWIZ_ERR_JOB_NOT_FOUND;
    }

    /* Send cancel message if we're the submitter */
    if (job->is_submitter) {
        cyxwiz_job_cancel_msg_t msg;
        msg.type = CYXWIZ_MSG_JOB_CANCEL;
        memcpy(msg.job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);

        cyxwiz_router_send(ctx->router, &job->worker,
                          (uint8_t *)&msg, sizeof(msg));
    }

    free_job(job);
    ctx->job_count--;

    return CYXWIZ_OK;
}

/* Forward declaration for anonymous submit helper */
static cyxwiz_error_t send_job_submit_anonymous(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job);

/*
 * Submit a job anonymously - worker cannot identify submitter
 */
cyxwiz_error_t cyxwiz_compute_submit_anonymous(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *worker,
    cyxwiz_job_type_t type,
    const uint8_t *payload,
    size_t payload_len,
    cyxwiz_job_id_t *job_id_out)
{
    if (ctx == NULL || worker == NULL || job_id_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (payload_len > 0 && payload == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check payload fits within anonymous job limits */
    if (payload_len > CYXWIZ_JOB_ANON_MAX_PAYLOAD) {
        CYXWIZ_ERROR("Payload too large for anonymous job: %zu > %d",
                     payload_len, CYXWIZ_JOB_ANON_MAX_PAYLOAD);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Verify SURB creation is possible */
    if (!cyxwiz_router_can_create_surb(ctx->router)) {
        CYXWIZ_ERROR("Cannot create SURB - insufficient relay peers");
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Allocate job slot */
    cyxwiz_job_t *job = alloc_job(ctx);
    if (job == NULL) {
        CYXWIZ_ERROR("Job table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Generate job ID */
    cyxwiz_crypto_random(job->id.bytes, CYXWIZ_JOB_ID_SIZE);

    /* Initialize job as anonymous */
    job->type = type;
    job->state = CYXWIZ_JOB_STATE_PENDING;
    job->is_anonymous = true;
    memcpy(&job->worker, worker, sizeof(cyxwiz_node_id_t));
    job->is_submitter = true;

    /* Create SURB for anonymous reply */
    cyxwiz_error_t err = cyxwiz_router_create_surb(ctx->router, &job->submitter.reply_surb);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to create SURB: %s", cyxwiz_strerror(err));
        free_job(job);
        ctx->job_count--;
        return err;
    }

    /* Copy payload */
    if (payload_len > 0) {
        memcpy(job->payload, payload, payload_len);
    }
    job->payload_len = payload_len;

    /* Anonymous jobs are single-packet only (due to SURB overhead) */
    job->total_chunks = 0;

    job->submitted_at = cyxwiz_time_ms();

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);
    CYXWIZ_DEBUG("Submitting anonymous job %s (type=%d, payload=%zu bytes)",
                 hex_id, type, payload_len);

    /* Send anonymous job submission */
    err = send_job_submit_anonymous(ctx, job);
    if (err != CYXWIZ_OK) {
        free_job(job);
        ctx->job_count--;
        return err;
    }

    /* Output job ID */
    memcpy(job_id_out, &job->id, sizeof(cyxwiz_job_id_t));

    return CYXWIZ_OK;
}

/*
 * Check if context supports anonymous job submission
 */
bool cyxwiz_compute_can_submit_anonymous(const cyxwiz_compute_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }

    return cyxwiz_router_can_create_surb(ctx->router);
}

/* ============ Send Functions ============ */

static cyxwiz_error_t send_job_submit(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    uint8_t buf[CYXWIZ_MAX_PACKET_SIZE];
    cyxwiz_job_submit_msg_t *msg = (cyxwiz_job_submit_msg_t *)buf;

    msg->type = CYXWIZ_MSG_JOB_SUBMIT;
    memcpy(msg->job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);
    msg->job_type = (uint8_t)job->type;
    msg->total_chunks = job->total_chunks;

    size_t msg_len;

    if (job->total_chunks == 0) {
        /* Single packet - include payload */
        msg->payload_len = (uint8_t)job->payload_len;
        if (job->payload_len > 0) {
            memcpy(buf + sizeof(cyxwiz_job_submit_msg_t), job->payload, job->payload_len);
        }
        msg_len = sizeof(cyxwiz_job_submit_msg_t) + job->payload_len;
    } else {
        /* Chunked - just send header, chunks follow */
        msg->payload_len = (uint8_t)job->payload_len;  /* Total payload length */
        msg_len = sizeof(cyxwiz_job_submit_msg_t);
    }

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    /* Send submit message */
    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, &job->worker, buf, CYXWIZ_PADDED_SIZE);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to send JOB_SUBMIT: %s", cyxwiz_strerror(err));
        return err;
    }

    /* Send chunks if needed */
    if (job->total_chunks > 0) {
        for (uint8_t i = 0; i < job->total_chunks; i++) {
            size_t offset = i * CYXWIZ_JOB_CHUNK_SIZE;
            size_t chunk_len = job->payload_len - offset;
            if (chunk_len > CYXWIZ_JOB_CHUNK_SIZE) {
                chunk_len = CYXWIZ_JOB_CHUNK_SIZE;
            }

            err = send_job_chunk(ctx, &job->worker, &job->id, i,
                                job->payload + offset, chunk_len);
            if (err != CYXWIZ_OK) {
                CYXWIZ_WARN("Failed to send chunk %d: %s", i, cyxwiz_strerror(err));
                /* Continue trying other chunks */
            }
        }
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t send_job_submit_anonymous(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    uint8_t buf[CYXWIZ_MAX_PACKET_SIZE];
    cyxwiz_job_submit_anon_msg_t *msg = (cyxwiz_job_submit_anon_msg_t *)buf;

    msg->type = CYXWIZ_MSG_JOB_SUBMIT_ANON;
    memcpy(msg->job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);
    msg->job_type = (uint8_t)job->type;
    msg->total_chunks = 0;  /* Anonymous jobs are always single-packet */
    msg->payload_len = (uint8_t)job->payload_len;

    /* Copy the SURB for anonymous reply */
    memcpy(&msg->reply_surb, &job->submitter.reply_surb, sizeof(cyxwiz_surb_t));

    /* Copy payload after header */
    size_t msg_len = sizeof(cyxwiz_job_submit_anon_msg_t);
    if (job->payload_len > 0) {
        memcpy(buf + sizeof(cyxwiz_job_submit_anon_msg_t), job->payload, job->payload_len);
        msg_len += job->payload_len;
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);
    CYXWIZ_DEBUG("Sending anonymous JOB_SUBMIT %s (%zu bytes)", hex_id, msg_len);

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    /* Send to worker */
    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, &job->worker, buf, CYXWIZ_PADDED_SIZE);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to send anonymous JOB_SUBMIT: %s", cyxwiz_strerror(err));
    }

    return err;
}

static cyxwiz_error_t send_job_chunk(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_job_id_t *job_id,
    uint8_t chunk_index,
    const uint8_t *data,
    size_t len)
{
    uint8_t buf[CYXWIZ_MAX_PACKET_SIZE];
    cyxwiz_job_chunk_msg_t *msg = (cyxwiz_job_chunk_msg_t *)buf;

    msg->type = CYXWIZ_MSG_JOB_CHUNK;
    memcpy(msg->job_id, job_id->bytes, CYXWIZ_JOB_ID_SIZE);
    msg->chunk_index = chunk_index;
    msg->chunk_len = (uint8_t)len;
    memcpy(buf + sizeof(cyxwiz_job_chunk_msg_t), data, len);

    size_t msg_len = sizeof(cyxwiz_job_chunk_msg_t) + len;

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, to, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_job_accept(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_job_id_t *job_id)
{
    cyxwiz_job_accept_msg_t msg;
    msg.type = CYXWIZ_MSG_JOB_ACCEPT;
    memcpy(msg.job_id, job_id->bytes, CYXWIZ_JOB_ID_SIZE);

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_job_reject(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_job_id_t *job_id,
    cyxwiz_reject_reason_t reason)
{
    cyxwiz_job_reject_msg_t msg;
    msg.type = CYXWIZ_MSG_JOB_REJECT;
    memcpy(msg.job_id, job_id->bytes, CYXWIZ_JOB_ID_SIZE);
    msg.reason = (uint8_t)reason;

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

static cyxwiz_error_t send_job_result(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    /* Use SURB for anonymous jobs */
    if (job->is_anonymous) {
        return send_job_result_via_surb(ctx, job);
    }

    uint8_t buf[CYXWIZ_MAX_PACKET_SIZE];
    cyxwiz_job_result_msg_t *msg = (cyxwiz_job_result_msg_t *)buf;

    msg->type = CYXWIZ_MSG_JOB_RESULT;
    memcpy(msg->job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);
    msg->state = (uint8_t)job->state;
    msg->total_chunks = 0;  /* TODO: chunked results */
    msg->result_len = (uint8_t)job->result_len;

    /* Compute MAC over job_id || result */
    cyxwiz_compute_result_mac(ctx, &job->id, job->result, job->result_len, msg->mac);

    /* Copy result */
    if (job->result_len > 0) {
        memcpy(buf + sizeof(cyxwiz_job_result_msg_t), job->result, job->result_len);
    }

    size_t msg_len = sizeof(cyxwiz_job_result_msg_t) + job->result_len;

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send(ctx->router, &job->submitter.direct_id, buf, CYXWIZ_PADDED_SIZE);
}

static cyxwiz_error_t send_job_ack(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *to,
    const cyxwiz_job_id_t *job_id)
{
    cyxwiz_job_ack_msg_t msg;
    msg.type = CYXWIZ_MSG_JOB_ACK;
    memcpy(msg.job_id, job_id->bytes, CYXWIZ_JOB_ID_SIZE);

    return cyxwiz_router_send(ctx->router, to, (uint8_t *)&msg, sizeof(msg));
}

/*
 * Send job accept via SURB for anonymous jobs
 */
static cyxwiz_error_t send_job_accept_via_surb(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    cyxwiz_job_accept_msg_t msg;
    msg.type = CYXWIZ_MSG_JOB_ACCEPT;
    memcpy(msg.job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);
    CYXWIZ_DEBUG("Sending anonymous JOB_ACCEPT for %s via SURB", hex_id);

    return cyxwiz_router_send_via_surb(ctx->router, &job->submitter.reply_surb,
                                       (uint8_t *)&msg, sizeof(msg));
}

/*
 * Send job result via SURB for anonymous jobs
 */
static cyxwiz_error_t send_job_result_via_surb(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    uint8_t buf[CYXWIZ_MAX_PACKET_SIZE];
    cyxwiz_job_result_msg_t *msg = (cyxwiz_job_result_msg_t *)buf;

    msg->type = CYXWIZ_MSG_JOB_RESULT;
    memcpy(msg->job_id, job->id.bytes, CYXWIZ_JOB_ID_SIZE);
    msg->state = (uint8_t)job->state;
    msg->total_chunks = 0;
    msg->result_len = (uint8_t)job->result_len;

    /* Compute MAC over job_id || result */
    cyxwiz_compute_result_mac(ctx, &job->id, job->result, job->result_len, msg->mac);

    /* Copy result */
    if (job->result_len > 0) {
        memcpy(buf + sizeof(cyxwiz_job_result_msg_t), job->result, job->result_len);
    }

    size_t msg_len = sizeof(cyxwiz_job_result_msg_t) + job->result_len;

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);
    CYXWIZ_DEBUG("Sending anonymous JOB_RESULT for %s via SURB (%zu bytes)", hex_id, msg_len);

    /* Pad to MTU for traffic analysis prevention */
    cyxwiz_pad_message(buf, msg_len, CYXWIZ_PADDED_SIZE);

    return cyxwiz_router_send_via_surb(ctx->router, &job->submitter.reply_surb, buf, CYXWIZ_PADDED_SIZE);
}

/* ============ Message Handling ============ */

cyxwiz_error_t cyxwiz_compute_handle_message(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (ctx == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case CYXWIZ_MSG_JOB_SUBMIT:
            return handle_job_submit(ctx, from, data, len, false);
        case CYXWIZ_MSG_JOB_SUBMIT_ANON:
            return handle_job_submit(ctx, from, data, len, true);
        case CYXWIZ_MSG_JOB_CHUNK:
            return handle_job_chunk(ctx, from, data, len);
        case CYXWIZ_MSG_JOB_ACCEPT:
            return handle_job_accept(ctx, from, data, len);
        case CYXWIZ_MSG_JOB_REJECT:
            return handle_job_reject(ctx, from, data, len);
        case CYXWIZ_MSG_JOB_RESULT:
            return handle_job_result(ctx, from, data, len);
        case CYXWIZ_MSG_JOB_ACK:
            return handle_job_ack(ctx, from, data, len);
        case CYXWIZ_MSG_JOB_CANCEL:
            return handle_job_cancel(ctx, from, data, len);
        default:
            CYXWIZ_DEBUG("Unknown compute message type: 0x%02X", msg_type);
            return CYXWIZ_ERR_INVALID;
    }
}

static cyxwiz_error_t handle_job_submit(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    bool is_anonymous)
{
    /* Validate minimum message length */
    size_t min_len = is_anonymous ? sizeof(cyxwiz_job_submit_anon_msg_t)
                                  : sizeof(cyxwiz_job_submit_msg_t);
    if (len < min_len) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Extract job ID and type from appropriate message format */
    cyxwiz_job_id_t job_id;
    cyxwiz_job_type_t job_type;
    uint8_t total_chunks;
    const cyxwiz_surb_t *reply_surb = NULL;
    const uint8_t *payload_data;
    size_t payload_len;

    if (is_anonymous) {
        const cyxwiz_job_submit_anon_msg_t *msg = (const cyxwiz_job_submit_anon_msg_t *)data;
        memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);
        job_type = (cyxwiz_job_type_t)msg->job_type;
        total_chunks = msg->total_chunks;  /* Always 0 for anonymous */
        reply_surb = &msg->reply_surb;
        payload_data = data + sizeof(cyxwiz_job_submit_anon_msg_t);
        payload_len = len - sizeof(cyxwiz_job_submit_anon_msg_t);
    } else {
        const cyxwiz_job_submit_msg_t *msg = (const cyxwiz_job_submit_msg_t *)data;
        memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);
        job_type = (cyxwiz_job_type_t)msg->job_type;
        total_chunks = msg->total_chunks;
        payload_data = data + sizeof(cyxwiz_job_submit_msg_t);
        payload_len = len - sizeof(cyxwiz_job_submit_msg_t);
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);

    /* Check if we're a worker */
    if (!ctx->is_worker) {
        CYXWIZ_DEBUG("Received job %s but not in worker mode", hex_id);
        /* Note: For anonymous jobs, we can't send reject back easily */
        if (!is_anonymous) {
            send_job_reject(ctx, from, &job_id, CYXWIZ_REJECT_UNSUPPORTED);
        }
        return CYXWIZ_OK;
    }

    /* Check capacity */
    if (ctx->active_worker_jobs >= ctx->max_concurrent) {
        CYXWIZ_DEBUG("Rejecting job %s - at capacity", hex_id);
        if (!is_anonymous) {
            send_job_reject(ctx, from, &job_id, CYXWIZ_REJECT_BUSY);
        }
        return CYXWIZ_OK;
    }

    /* Check if we already have this job */
    cyxwiz_job_t *existing = find_job(ctx, &job_id);
    if (existing != NULL) {
        CYXWIZ_DEBUG("Duplicate job %s", hex_id);
        return CYXWIZ_OK;
    }

    /* Allocate job slot */
    cyxwiz_job_t *job = alloc_job(ctx);
    if (job == NULL) {
        if (!is_anonymous) {
            send_job_reject(ctx, from, &job_id, CYXWIZ_REJECT_BUSY);
        }
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize job */
    memcpy(&job->id, &job_id, sizeof(cyxwiz_job_id_t));
    job->type = job_type;
    job->state = CYXWIZ_JOB_STATE_PENDING;
    job->is_anonymous = is_anonymous;

    /* Store submitter identity or SURB */
    if (is_anonymous) {
        memcpy(&job->submitter.reply_surb, reply_surb, sizeof(cyxwiz_surb_t));
        CYXWIZ_DEBUG("Received anonymous job %s (type=%d, payload=%zu)",
                     hex_id, job->type, payload_len);
    } else {
        memcpy(&job->submitter.direct_id, from, sizeof(cyxwiz_node_id_t));
    }

    memcpy(&job->worker, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    job->is_submitter = false;
    job->total_chunks = total_chunks;

    if (total_chunks == 0) {
        /* Single packet - payload is inline */
        if (payload_len > CYXWIZ_JOB_MAX_PAYLOAD) {
            payload_len = CYXWIZ_JOB_MAX_PAYLOAD;
        }
        if (payload_len > 0) {
            memcpy(job->payload, payload_data, payload_len);
        }
        job->payload_len = payload_len;
        job->received_chunks = 0;
        job->chunk_bitmap = 0;

        if (!is_anonymous) {
            CYXWIZ_DEBUG("Received single-packet job %s (type=%d, payload=%zu)",
                         hex_id, job->type, job->payload_len);
        }

        /* Accept and execute immediately */
        /* For anonymous jobs, accept goes via SURB */
        if (is_anonymous) {
            send_job_accept_via_surb(ctx, job);
        } else {
            send_job_accept(ctx, from, &job_id);
        }
        ctx->active_worker_jobs++;
        return execute_job(ctx, job);
    } else {
        /* Chunked job - wait for chunks */
        /* Note: Anonymous jobs don't support chunking */
        if (is_anonymous) {
            CYXWIZ_WARN("Anonymous job %s uses chunking - not supported", hex_id);
            free_job(job);
            ctx->job_count--;
            return CYXWIZ_ERR_INVALID;
        }

        const cyxwiz_job_submit_msg_t *msg = (const cyxwiz_job_submit_msg_t *)data;
        job->payload_len = msg->payload_len;  /* Expected total length */
        job->received_chunks = 0;
        job->chunk_bitmap = 0;
        job->submitted_at = cyxwiz_time_ms();

        CYXWIZ_DEBUG("Received chunked job %s (type=%d, chunks=%d, total=%zu)",
                     hex_id, job->type, total_chunks, job->payload_len);

        /* Don't accept yet - wait for all chunks */
        return CYXWIZ_OK;
    }
}

static cyxwiz_error_t handle_job_chunk(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_chunk_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_chunk_msg_t *msg = (const cyxwiz_job_chunk_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        /* Job not found - maybe we rejected it */
        return CYXWIZ_ERR_JOB_NOT_FOUND;
    }

    /* Validate chunk */
    if (msg->chunk_index >= job->total_chunks) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if already received */
    if (job->chunk_bitmap & (1 << msg->chunk_index)) {
        return CYXWIZ_OK;  /* Duplicate, ignore */
    }

    /* Copy chunk data */
    size_t chunk_data_len = len - sizeof(cyxwiz_job_chunk_msg_t);
    if (chunk_data_len > msg->chunk_len) {
        chunk_data_len = msg->chunk_len;
    }

    size_t offset = msg->chunk_index * CYXWIZ_JOB_CHUNK_SIZE;
    if (offset + chunk_data_len > CYXWIZ_JOB_MAX_TOTAL_PAYLOAD) {
        return CYXWIZ_ERR_INVALID;
    }

    memcpy(job->payload + offset, data + sizeof(cyxwiz_job_chunk_msg_t), chunk_data_len);

    /* Mark received */
    job->chunk_bitmap |= (1 << msg->chunk_index);
    job->received_chunks++;

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);
    CYXWIZ_DEBUG("Received chunk %d/%d for job %s",
                 msg->chunk_index + 1, job->total_chunks, hex_id);

    /* Check if complete */
    if (job->received_chunks == job->total_chunks) {
        CYXWIZ_DEBUG("All chunks received for job %s", hex_id);

        /* Accept and execute (chunked jobs are never anonymous) */
        send_job_accept(ctx, &job->submitter.direct_id, &job->id);
        ctx->active_worker_jobs++;
        return execute_job(ctx, job);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_job_accept(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_accept_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_accept_msg_t *msg = (const cyxwiz_job_accept_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        return CYXWIZ_ERR_JOB_NOT_FOUND;
    }

    if (!job->is_submitter) {
        return CYXWIZ_ERR_INVALID;
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);
    CYXWIZ_DEBUG("Job %s accepted by worker", hex_id);

    job->state = CYXWIZ_JOB_STATE_RUNNING;
    job->started_at = cyxwiz_time_ms();

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_job_reject(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_reject_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_reject_msg_t *msg = (const cyxwiz_job_reject_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        return CYXWIZ_ERR_JOB_NOT_FOUND;
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);
    CYXWIZ_WARN("Job %s rejected (reason=%d)", hex_id, msg->reason);

    job->state = CYXWIZ_JOB_STATE_FAILED;
    job->completed_at = cyxwiz_time_ms();

    /* Notify submitter */
    if (ctx->on_complete != NULL && job->is_submitter) {
        ctx->on_complete(ctx, job, NULL, 0, false, ctx->complete_user_data);
    }

    free_job(job);
    ctx->job_count--;

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_job_result(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_result_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_result_msg_t *msg = (const cyxwiz_job_result_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        return CYXWIZ_ERR_JOB_NOT_FOUND;
    }

    if (!job->is_submitter) {
        return CYXWIZ_ERR_INVALID;
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);

    /* Copy result */
    size_t result_len = len - sizeof(cyxwiz_job_result_msg_t);
    if (result_len > msg->result_len) {
        result_len = msg->result_len;
    }
    if (result_len > CYXWIZ_JOB_MAX_PAYLOAD) {
        result_len = CYXWIZ_JOB_MAX_PAYLOAD;
    }

    if (result_len > 0) {
        memcpy(job->result, data + sizeof(cyxwiz_job_result_msg_t), result_len);
    }
    job->result_len = result_len;
    memcpy(job->result_mac, msg->mac, CYXWIZ_MAC_SIZE);

    /* Verify MAC */
    job->mac_valid = (cyxwiz_compute_verify_result(ctx, &job->id,
                      job->result, job->result_len, job->result_mac) == CYXWIZ_OK);

    job->state = (cyxwiz_job_state_t)msg->state;
    job->completed_at = cyxwiz_time_ms();

    CYXWIZ_INFO("Received result for job %s (state=%d, len=%zu, mac_valid=%d)",
                hex_id, job->state, job->result_len, job->mac_valid);

    /* Send acknowledgment */
    send_job_ack(ctx, &job->worker, &job->id);

    /* Notify submitter */
    if (ctx->on_complete != NULL) {
        ctx->on_complete(ctx, job, job->result, job->result_len,
                        job->mac_valid, ctx->complete_user_data);
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_job_ack(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_ack_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_ack_msg_t *msg = (const cyxwiz_job_ack_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        return CYXWIZ_OK;  /* Already cleaned up */
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);
    CYXWIZ_DEBUG("Job %s acknowledged by submitter", hex_id);

    /* Worker can now clean up */
    if (!job->is_submitter) {
        ctx->active_worker_jobs--;
    }

    free_job(job);
    ctx->job_count--;

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_job_cancel(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_job_cancel_msg_t)) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_job_cancel_msg_t *msg = (const cyxwiz_job_cancel_msg_t *)data;
    cyxwiz_job_id_t job_id;
    memcpy(job_id.bytes, msg->job_id, CYXWIZ_JOB_ID_SIZE);

    cyxwiz_job_t *job = find_job(ctx, &job_id);
    if (job == NULL) {
        return CYXWIZ_OK;
    }

    char hex_id[17];
    cyxwiz_job_id_to_hex(&job_id, hex_id);
    CYXWIZ_INFO("Job %s cancelled", hex_id);

    if (!job->is_submitter) {
        ctx->active_worker_jobs--;
    }

    free_job(job);
    ctx->job_count--;

    return CYXWIZ_OK;
}

/* ============ Job Execution ============ */

static cyxwiz_error_t execute_job(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    char hex_id[17];
    cyxwiz_job_id_to_hex(&job->id, hex_id);

    CYXWIZ_INFO("Executing job %s (type=%s, payload=%zu bytes)",
                hex_id, cyxwiz_job_type_name(job->type), job->payload_len);

    job->state = CYXWIZ_JOB_STATE_RUNNING;
    job->started_at = cyxwiz_time_ms();

    cyxwiz_error_t err;

    /* Try custom callback first */
    if (ctx->on_execute != NULL) {
        err = ctx->on_execute(ctx, job, job->result, &job->result_len,
                             ctx->execute_user_data);
    } else {
        /* Use builtin handlers */
        err = execute_builtin_job(ctx, job);
    }

    if (err == CYXWIZ_OK) {
        job->state = CYXWIZ_JOB_STATE_COMPLETED;
    } else {
        job->state = CYXWIZ_JOB_STATE_FAILED;
        job->result_len = 0;
    }

    job->completed_at = cyxwiz_time_ms();

    CYXWIZ_INFO("Job %s completed (state=%s, result=%zu bytes)",
                hex_id, cyxwiz_job_state_name(job->state), job->result_len);

    /* Send result back to submitter */
    return send_job_result(ctx, job);
}

static cyxwiz_error_t execute_builtin_job(cyxwiz_compute_ctx_t *ctx, cyxwiz_job_t *job)
{
    switch (job->type) {
        case CYXWIZ_JOB_TYPE_HASH:
            /* Compute BLAKE2b hash of payload */
            job->result_len = CYXWIZ_KEY_SIZE;
            return cyxwiz_crypto_hash(job->payload, job->payload_len,
                                      job->result, job->result_len);

        case CYXWIZ_JOB_TYPE_ENCRYPT:
        case CYXWIZ_JOB_TYPE_DECRYPT:
        case CYXWIZ_JOB_TYPE_VERIFY:
            /* These require additional context/keys - not implemented yet */
            CYXWIZ_WARN("Job type %d not implemented", job->type);
            return CYXWIZ_ERR_INVALID;

        case CYXWIZ_JOB_TYPE_CUSTOM:
        default:
            /* Custom jobs require a callback */
            if (ctx->on_execute == NULL) {
                CYXWIZ_WARN("No execute callback for custom job");
                return CYXWIZ_ERR_INVALID;
            }
            return ctx->on_execute(ctx, job, job->result, &job->result_len,
                                  ctx->execute_user_data);
    }
}

/* ============ Polling ============ */

cyxwiz_error_t cyxwiz_compute_poll(cyxwiz_compute_ctx_t *ctx, uint64_t now_ms)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    ctx->last_poll = now_ms;

    /* Check for timed out jobs */
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_JOBS; i++) {
        cyxwiz_job_t *job = &ctx->jobs[i];
        if (!job->valid) {
            continue;
        }

        /* Check job timeout */
        if (job->state == CYXWIZ_JOB_STATE_PENDING ||
            job->state == CYXWIZ_JOB_STATE_ASSIGNED ||
            job->state == CYXWIZ_JOB_STATE_RUNNING) {

            uint64_t elapsed = now_ms - job->submitted_at;
            if (elapsed > CYXWIZ_JOB_TIMEOUT_MS) {
                char hex_id[17];
                cyxwiz_job_id_to_hex(&job->id, hex_id);
                CYXWIZ_WARN("Job %s timed out", hex_id);

                job->state = CYXWIZ_JOB_STATE_TIMEOUT;
                job->completed_at = now_ms;

                /* Notify if we're the submitter */
                if (job->is_submitter && ctx->on_complete != NULL) {
                    ctx->on_complete(ctx, job, NULL, 0, false, ctx->complete_user_data);
                }

                if (!job->is_submitter) {
                    ctx->active_worker_jobs--;
                }

                free_job(job);
                ctx->job_count--;
            }
        }
    }

    return CYXWIZ_OK;
}

/* ============ MAC Functions ============ */

cyxwiz_error_t cyxwiz_compute_result_mac(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id,
    const uint8_t *result,
    size_t result_len,
    uint8_t *mac_out)
{
    if (ctx == NULL || job_id == NULL || mac_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (ctx->crypto_ctx == NULL) {
        /* No crypto context - generate deterministic MAC from hash */
        uint8_t buf[CYXWIZ_JOB_ID_SIZE + CYXWIZ_JOB_MAX_PAYLOAD];
        memcpy(buf, job_id->bytes, CYXWIZ_JOB_ID_SIZE);
        if (result_len > 0 && result != NULL) {
            memcpy(buf + CYXWIZ_JOB_ID_SIZE, result, result_len);
        }

        uint8_t hash[CYXWIZ_KEY_SIZE];
        cyxwiz_error_t err = cyxwiz_crypto_hash(buf, CYXWIZ_JOB_ID_SIZE + result_len,
                                                hash, CYXWIZ_KEY_SIZE);
        if (err != CYXWIZ_OK) {
            return err;
        }

        /* Use first 16 bytes of hash as MAC */
        memcpy(mac_out, hash, CYXWIZ_MAC_SIZE);
        return CYXWIZ_OK;
    }

    /* Use crypto context's MAC function */
    uint8_t buf[CYXWIZ_JOB_ID_SIZE + CYXWIZ_JOB_MAX_PAYLOAD];
    memcpy(buf, job_id->bytes, CYXWIZ_JOB_ID_SIZE);
    if (result_len > 0 && result != NULL) {
        memcpy(buf + CYXWIZ_JOB_ID_SIZE, result, result_len);
    }

    return cyxwiz_crypto_compute_mac(ctx->crypto_ctx, buf, mac_out);
}

cyxwiz_error_t cyxwiz_compute_verify_result(
    cyxwiz_compute_ctx_t *ctx,
    const cyxwiz_job_id_t *job_id,
    const uint8_t *result,
    size_t result_len,
    const uint8_t *mac)
{
    if (ctx == NULL || job_id == NULL || mac == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t computed_mac[CYXWIZ_MAC_SIZE];
    cyxwiz_error_t err = cyxwiz_compute_result_mac(ctx, job_id, result, result_len, computed_mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (size_t i = 0; i < CYXWIZ_MAC_SIZE; i++) {
        diff |= computed_mac[i] ^ mac[i];
    }

    if (diff != 0) {
        return CYXWIZ_ERR_MAC_INVALID;
    }

    return CYXWIZ_OK;
}

/* ============ Utilities ============ */

const char *cyxwiz_job_state_name(cyxwiz_job_state_t state)
{
    switch (state) {
        case CYXWIZ_JOB_STATE_PENDING:   return "PENDING";
        case CYXWIZ_JOB_STATE_ASSIGNED:  return "ASSIGNED";
        case CYXWIZ_JOB_STATE_RUNNING:   return "RUNNING";
        case CYXWIZ_JOB_STATE_COMPLETED: return "COMPLETED";
        case CYXWIZ_JOB_STATE_FAILED:    return "FAILED";
        case CYXWIZ_JOB_STATE_TIMEOUT:   return "TIMEOUT";
        default:                         return "UNKNOWN";
    }
}

const char *cyxwiz_job_type_name(cyxwiz_job_type_t type)
{
    switch (type) {
        case CYXWIZ_JOB_TYPE_HASH:    return "HASH";
        case CYXWIZ_JOB_TYPE_ENCRYPT: return "ENCRYPT";
        case CYXWIZ_JOB_TYPE_DECRYPT: return "DECRYPT";
        case CYXWIZ_JOB_TYPE_VERIFY:  return "VERIFY";
        case CYXWIZ_JOB_TYPE_CUSTOM:  return "CUSTOM";
        default:                      return "UNKNOWN";
    }
}

int cyxwiz_job_id_compare(const cyxwiz_job_id_t *a, const cyxwiz_job_id_t *b)
{
    if (a == NULL || b == NULL) {
        return (a == b) ? 0 : 1;
    }
    return memcmp(a->bytes, b->bytes, CYXWIZ_JOB_ID_SIZE);
}

void cyxwiz_job_id_to_hex(const cyxwiz_job_id_t *id, char *hex_out)
{
    if (id == NULL || hex_out == NULL) {
        if (hex_out != NULL) {
            hex_out[0] = '\0';
        }
        return;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < CYXWIZ_JOB_ID_SIZE; i++) {
        hex_out[i * 2] = hex_chars[(id->bytes[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[id->bytes[i] & 0x0F];
    }
    hex_out[CYXWIZ_JOB_ID_SIZE * 2] = '\0';
}
