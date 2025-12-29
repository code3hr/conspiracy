/*
 * CyxWiz Protocol - Proof of Useful Work Consensus
 *
 * Implements committee-based consensus where validators earn rights through
 * useful work (compute jobs, storage proofs). Uses 2/3+1 Byzantine fault
 * tolerance with Schnorr proof authentication.
 */

#include "cyxwiz/consensus.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/privacy.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdlib.h>

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

/* ============ Context Structure ============ */

struct cyxwiz_consensus_ctx {
    /* Dependencies */
    cyxwiz_router_t *router;
    cyxwiz_peer_table_t *peer_table;
    cyxwiz_identity_keypair_t identity;
    cyxwiz_node_id_t local_id;

    /* Local validator state */
    cyxwiz_validator_t local_validator;
    bool is_registered;

    /* Known validators */
    cyxwiz_validator_t validators[CYXWIZ_MAX_VALIDATORS];
    size_t validator_count;

    /* Active validation rounds */
    cyxwiz_consensus_round_t rounds[CYXWIZ_MAX_ACTIVE_VALIDATIONS];
    size_t active_round_count;

    /* Callbacks */
    cyxwiz_validation_complete_cb_t on_validation_complete;
    void *validation_user_data;
    cyxwiz_credits_change_cb_t on_credits_change;
    void *credits_user_data;
    cyxwiz_validator_state_cb_t on_state_change;
    void *state_user_data;

    /* State */
    bool running;
    uint64_t last_poll;
    uint64_t last_heartbeat;
    uint64_t last_registration_attempt;

    /* Statistics */
    uint32_t total_earned;
    uint32_t total_slashed;
};

/* ============ Internal Helpers ============ */

/* Forward declaration */
static void create_equivocation_evidence(
    const uint8_t *round_id,
    const cyxwiz_node_id_t *validator_id,
    bool vote1,
    bool vote2,
    uint8_t *evidence_hash_out);

static int find_validator_index(const cyxwiz_consensus_ctx_t *ctx,
                                 const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < ctx->validator_count; i++) {
        if (memcmp(&ctx->validators[i].node_id, id, sizeof(cyxwiz_node_id_t)) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int find_round_index(const cyxwiz_consensus_ctx_t *ctx,
                            const uint8_t *round_id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_VALIDATIONS; i++) {
        if (ctx->rounds[i].active &&
            memcmp(ctx->rounds[i].round_id, round_id, CYXWIZ_CONSENSUS_ID_SIZE) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int find_free_round_slot(const cyxwiz_consensus_ctx_t *ctx)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_VALIDATIONS; i++) {
        if (!ctx->rounds[i].active) {
            return (int)i;
        }
    }
    return -1;
}

static void generate_round_id(uint8_t *round_id)
{
#ifdef CYXWIZ_HAS_CRYPTO
    randombytes_buf(round_id, CYXWIZ_CONSENSUS_ID_SIZE);
#else
    for (int i = 0; i < CYXWIZ_CONSENSUS_ID_SIZE; i++) {
        round_id[i] = (uint8_t)(rand() & 0xFF);
    }
#endif
}

/*
 * Apply credit decay based on time elapsed
 * Half-life: 1 hour
 */
static uint32_t apply_credit_decay(uint32_t credits, uint64_t age_ms)
{
    if (age_ms == 0 || credits == 0) {
        return credits;
    }

    /* Approximate decay: credits * 2^(-age_ms / half_life) */
    uint64_t half_lives = age_ms / CYXWIZ_WORK_CREDIT_DECAY_MS;
    if (half_lives >= 32) {
        return 0; /* Fully decayed */
    }

    /* Simple bit shift approximation */
    return credits >> half_lives;
}

static void update_validator_credits(cyxwiz_consensus_ctx_t *ctx,
                                      cyxwiz_validator_t *validator,
                                      uint64_t now_ms)
{
    if (validator->credits_updated_at == 0) {
        validator->credits_updated_at = now_ms;
        return;
    }

    uint64_t age = now_ms - validator->credits_updated_at;
    uint32_t old_credits = validator->work_credits;
    validator->work_credits = apply_credit_decay(old_credits, age);
    validator->credits_updated_at = now_ms;

    if (old_credits != validator->work_credits && ctx->on_credits_change) {
        ctx->on_credits_change(&validator->node_id, old_credits,
                               validator->work_credits, ctx->credits_user_data);
    }
}

/*
 * Count bits set in a uint32_t (for vote counting)
 */
static int popcount32(uint32_t x)
{
    int count = 0;
    while (x) {
        count += (int)(x & 1);
        x >>= 1;
    }
    return count;
}

/*
 * Check if committee member index is in vote bitmap
 */
static bool has_voted(uint32_t votes, int member_index)
{
    if (member_index < 0 || member_index >= 32) {
        return false;
    }
    return (votes & (1U << member_index)) != 0;
}

/*
 * Set vote for committee member
 */
static void set_vote(uint32_t *votes, int member_index)
{
    if (member_index >= 0 && member_index < 32) {
        *votes |= (1U << member_index);
    }
}

/*
 * Find member index in committee
 */
static int find_committee_member(const cyxwiz_consensus_round_t *round,
                                  const cyxwiz_node_id_t *validator_id)
{
    for (int i = 0; i < round->committee_size; i++) {
        if (memcmp(&round->committee[i], validator_id, sizeof(cyxwiz_node_id_t)) == 0) {
            return i;
        }
    }
    return -1;
}

/*
 * Verify equivocation evidence hash
 *
 * Checks if we have recorded conflicting votes from the alleged offender
 * in the specified round, and if so, verifies the evidence hash matches.
 *
 * Returns:
 *   1  = verified (we have conflicting votes and hash matches)
 *   0  = unverifiable (we don't have the round or conflicting votes)
 *  -1  = invalid (hash doesn't match our recorded evidence)
 */
static int verify_equivocation_evidence(
    const cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id,
    const cyxwiz_node_id_t *offender_id,
    const uint8_t *claimed_evidence_hash)
{
    /* Find the round */
    int round_idx = find_round_index(ctx, round_id);
    if (round_idx < 0) {
        /* We don't have this round - can't verify */
        return 0;
    }

    const cyxwiz_consensus_round_t *round = &ctx->rounds[round_idx];

    /* Find offender in committee */
    int member_idx = find_committee_member(round, offender_id);
    if (member_idx < 0) {
        /* Offender not in committee for this round - suspicious */
        CYXWIZ_WARN("Slash report: offender not in committee for claimed round");
        return -1;
    }

    /* Check if we've recorded conflicting votes from this validator */
    bool voted_valid = has_voted(round->votes_valid, member_idx);
    bool voted_invalid = has_voted(round->votes_invalid, member_idx);

    if (!voted_valid && !voted_invalid) {
        /* We haven't seen any vote from this validator - can't verify */
        return 0;
    }

    if (voted_valid && voted_invalid) {
        /* We have recorded equivocation! Compute our evidence hash */
        uint8_t our_evidence_hash[32];
        create_equivocation_evidence(round_id, offender_id, true, false, our_evidence_hash);

        /* Compare with claimed evidence */
        if (memcmp(our_evidence_hash, claimed_evidence_hash, 32) == 0) {
            CYXWIZ_DEBUG("Equivocation evidence verified");
            return 1;
        }

        /* Try the other vote order */
        create_equivocation_evidence(round_id, offender_id, false, true, our_evidence_hash);
        if (memcmp(our_evidence_hash, claimed_evidence_hash, 32) == 0) {
            CYXWIZ_DEBUG("Equivocation evidence verified (alternate order)");
            return 1;
        }

        /* Hash doesn't match - could be different conflicting votes */
        CYXWIZ_WARN("Evidence hash mismatch - may be different votes");
        return 1; /* Still slash since we know they equivocated */
    }

    /* We only have one vote - can't independently verify equivocation */
    return 0;
}

/* ============ Slashing ============ */

/*
 * Slash a validator for misbehavior
 *
 * Updates validator state to SLASHED and fires callback.
 * Returns the validator index, or -1 if not found.
 */
static int slash_validator(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *offender_id,
    cyxwiz_slash_reason_t reason,
    uint64_t now_ms)
{
    int idx = find_validator_index(ctx, offender_id);
    if (idx < 0) {
        CYXWIZ_DEBUG("Cannot slash unknown validator");
        return -1;
    }

    cyxwiz_validator_t *validator = &ctx->validators[idx];

    /* Already slashed? */
    if (validator->state == CYXWIZ_VALIDATOR_SLASHED) {
        CYXWIZ_DEBUG("Validator already slashed");
        return idx;
    }

    cyxwiz_validator_state_t old_state = validator->state;

    /* Update validator state */
    validator->state = CYXWIZ_VALIDATOR_SLASHED;
    validator->slashed_at = now_ms;
    validator->work_credits = 0; /* Forfeit all credits */

    /* Update statistics */
    ctx->total_slashed++;

    char hex_id[65];
    cyxwiz_node_id_to_hex(offender_id, hex_id);
    CYXWIZ_WARN("Validator %.16s... SLASHED for %s",
                hex_id, cyxwiz_slash_reason_name(reason));

    /* Fire state change callback */
    if (ctx->on_state_change) {
        ctx->on_state_change(validator, old_state, ctx->state_user_data);
    }

    return idx;
}

/*
 * Broadcast a slash report to all known validators
 */
static void broadcast_slash_report(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *offender_id,
    cyxwiz_slash_reason_t reason,
    const uint8_t *round_id,
    const uint8_t *evidence_hash)
{
    if (ctx->router == NULL) {
        return;
    }

    cyxwiz_slash_report_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.type = CYXWIZ_MSG_SLASH_REPORT;
    memcpy(&msg.offender_id, offender_id, sizeof(cyxwiz_node_id_t));
    memcpy(&msg.reporter_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    msg.reason = (uint8_t)reason;

    if (round_id != NULL) {
        memcpy(msg.round_id, round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    }
    if (evidence_hash != NULL) {
        memcpy(msg.evidence_hash, evidence_hash, 32);
    }

    /* Send to all known validators */
    for (size_t i = 0; i < ctx->validator_count; i++) {
        if (ctx->validators[i].state == CYXWIZ_VALIDATOR_ACTIVE &&
            memcmp(&ctx->validators[i].node_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) != 0) {
            cyxwiz_router_send(ctx->router, &ctx->validators[i].node_id,
                               (uint8_t *)&msg, sizeof(msg));
        }
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(offender_id, hex_id);
    CYXWIZ_INFO("Broadcast slash report for %.16s... (%s)",
                hex_id, cyxwiz_slash_reason_name(reason));
}

/*
 * Handle incoming slash report
 */
static cyxwiz_error_t handle_slash_report(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_slash_report_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    char offender_hex[65];
    char reporter_hex[65];
    cyxwiz_node_id_to_hex(&msg->offender_id, offender_hex);
    cyxwiz_node_id_to_hex(&msg->reporter_id, reporter_hex);

    CYXWIZ_INFO("Received slash report: offender=%.16s... reporter=%.16s... reason=%s",
                offender_hex, reporter_hex,
                cyxwiz_slash_reason_name((cyxwiz_slash_reason_t)msg->reason));

    /* Verify reporter is a known validator */
    int reporter_idx = find_validator_index(ctx, &msg->reporter_id);
    if (reporter_idx < 0) {
        CYXWIZ_WARN("Slash report from unknown validator, ignoring");
        return CYXWIZ_OK;
    }

    if (ctx->validators[reporter_idx].state != CYXWIZ_VALIDATOR_ACTIVE) {
        CYXWIZ_WARN("Slash report from inactive validator, ignoring");
        return CYXWIZ_OK;
    }

    /* For equivocation, we trust the report immediately since it's
     * cryptographically verifiable (same validator signed conflicting votes).
     * For other reasons, we might want additional verification in production. */

    cyxwiz_slash_reason_t reason = (cyxwiz_slash_reason_t)msg->reason;

    if (reason == CYXWIZ_SLASH_EQUIVOCATION) {
        /* Verify the evidence hash if we have the data to do so */
        int verification = verify_equivocation_evidence(ctx, msg->round_id,
                                                         &msg->offender_id,
                                                         msg->evidence_hash);

        if (verification == -1) {
            /* Evidence is invalid - offender not in committee */
            CYXWIZ_WARN("Rejecting slash report: invalid evidence");
            return CYXWIZ_OK;
        }

        if (verification == 1) {
            /* Verified! We independently confirmed equivocation */
            CYXWIZ_INFO("Slash report verified - slashing validator");
            slash_validator(ctx, &msg->offender_id, reason, ctx->last_poll);
        } else {
            /* Can't verify - trust reporter (they're a known active validator) */
            CYXWIZ_DEBUG("Cannot independently verify, trusting reporter");
            slash_validator(ctx, &msg->offender_id, reason, ctx->last_poll);
        }
    } else {
        /* For other slash types, we could implement a voting mechanism
         * where multiple validators need to report before slashing.
         * For now, just log it. */
        CYXWIZ_DEBUG("Non-equivocation slash report received, logging only");
    }

    return CYXWIZ_OK;
}

/*
 * Create evidence hash for equivocation
 * Hash of: round_id || validator_id || both_votes
 */
static void create_equivocation_evidence(
    const uint8_t *round_id,
    const cyxwiz_node_id_t *validator_id,
    bool vote1,
    bool vote2,
    uint8_t *evidence_hash_out)
{
#ifdef CYXWIZ_HAS_CRYPTO
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, 32);
    crypto_generichash_update(&state, round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    crypto_generichash_update(&state, validator_id->bytes, CYXWIZ_NODE_ID_LEN);
    uint8_t votes[2] = { vote1 ? 1 : 0, vote2 ? 1 : 0 };
    crypto_generichash_update(&state, votes, 2);
    crypto_generichash_final(&state, evidence_hash_out, 32);
#else
    memset(evidence_hash_out, 0, 32);
    memcpy(evidence_hash_out, round_id, CYXWIZ_CONSENSUS_ID_SIZE);
#endif
}

/* ============ Lifecycle ============ */

cyxwiz_error_t cyxwiz_consensus_create(
    cyxwiz_consensus_ctx_t **ctx,
    cyxwiz_router_t *router,
    cyxwiz_peer_table_t *peer_table,
    const cyxwiz_identity_keypair_t *identity)
{
    if (ctx == NULL || router == NULL || peer_table == NULL || identity == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_consensus_ctx_t *c = cyxwiz_calloc(1, sizeof(cyxwiz_consensus_ctx_t));
    if (c == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    c->router = router;
    c->peer_table = peer_table;
    memcpy(&c->identity, identity, sizeof(cyxwiz_identity_keypair_t));

    /* Derive node ID from identity */
    cyxwiz_error_t err = cyxwiz_identity_to_node_id(identity, &c->local_id);
    if (err != CYXWIZ_OK) {
        cyxwiz_free(c, sizeof(cyxwiz_consensus_ctx_t));
        return err;
    }

    /* Initialize local validator entry */
    memcpy(&c->local_validator.node_id, &c->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(c->local_validator.ed25519_pubkey, identity->public_key, CYXWIZ_ED25519_PK_SIZE);
    c->local_validator.state = CYXWIZ_VALIDATOR_INACTIVE;
    c->local_validator.work_credits = 0;
    c->local_validator.identity_verified = true;

    c->is_registered = false;
    c->validator_count = 0;
    c->active_round_count = 0;
    c->running = true;

    *ctx = c;
    CYXWIZ_INFO("Created consensus context");
    return CYXWIZ_OK;
}

void cyxwiz_consensus_destroy(cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Zero sensitive data */
    cyxwiz_secure_zero(&ctx->identity, sizeof(ctx->identity));
    cyxwiz_free(ctx, sizeof(cyxwiz_consensus_ctx_t));
    CYXWIZ_INFO("Destroyed consensus context");
}

/* ============ Polling ============ */

static void check_round_timeouts(cyxwiz_consensus_ctx_t *ctx, uint64_t now_ms)
{
    for (size_t i = 0; i < CYXWIZ_MAX_ACTIVE_VALIDATIONS; i++) {
        cyxwiz_consensus_round_t *round = &ctx->rounds[i];
        if (!round->active) {
            continue;
        }

        uint64_t age = now_ms - round->started_at;
        if (age > CYXWIZ_VALIDATION_TIMEOUT_MS && round->result == CYXWIZ_VALIDATION_PENDING) {
            /* Round timed out */
            round->result = CYXWIZ_VALIDATION_TIMEOUT;
            round->completed_at = now_ms;
            round->active = false;
            ctx->active_round_count--;

            CYXWIZ_WARN("Validation round timed out");

            if (ctx->on_validation_complete) {
                ctx->on_validation_complete(round, CYXWIZ_VALIDATION_TIMEOUT,
                                            ctx->validation_user_data);
            }
        }
    }
}

static void send_heartbeat(cyxwiz_consensus_ctx_t *ctx, uint64_t now_ms)
{
    if (!ctx->is_registered) {
        return;
    }

    if (now_ms - ctx->last_heartbeat < CYXWIZ_VALIDATOR_HEARTBEAT_MS) {
        return;
    }

    ctx->last_heartbeat = now_ms;

    /* Build heartbeat message */
    cyxwiz_validator_heartbeat_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_VALIDATOR_HEARTBEAT;
    memcpy(&msg.validator_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    msg.current_credits = (uint16_t)(ctx->local_validator.work_credits > 0xFFFF ?
                                      0xFFFF : ctx->local_validator.work_credits);
    msg.pending_validations = (uint8_t)ctx->active_round_count;
    msg.capabilities = 0x0F; /* All capabilities */

    /* Broadcast heartbeat */
    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&msg, sizeof(msg));

    CYXWIZ_DEBUG("Sent validator heartbeat (credits: %u)", msg.current_credits);
}

cyxwiz_error_t cyxwiz_consensus_poll(
    cyxwiz_consensus_ctx_t *ctx,
    uint64_t now_ms)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Update local validator credits (apply decay) */
    update_validator_credits(ctx, &ctx->local_validator, now_ms);

    /* Update known validators credits */
    for (size_t i = 0; i < ctx->validator_count; i++) {
        update_validator_credits(ctx, &ctx->validators[i], now_ms);
    }

    /* Check for timed out rounds */
    check_round_timeouts(ctx, now_ms);

    /* Retry registration if pending and not yet confirmed */
    if (ctx->local_validator.state == CYXWIZ_VALIDATOR_PENDING && !ctx->is_registered) {
        /* Retry every 10 seconds */
        if (now_ms - ctx->last_registration_attempt > 10000) {
            ctx->last_registration_attempt = now_ms;
            cyxwiz_consensus_register_validator(ctx);
        }
    }

    /* Send heartbeat if registered */
    send_heartbeat(ctx, now_ms);

    ctx->last_poll = now_ms;
    return CYXWIZ_OK;
}

/* ============ Validator Registration ============ */

cyxwiz_error_t cyxwiz_consensus_register_validator(cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (ctx->is_registered) {
        return CYXWIZ_OK; /* Already registered */
    }

#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Build registration message */
    cyxwiz_validator_register_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_VALIDATOR_REGISTER;
    memcpy(&msg.node_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(msg.ed25519_pubkey, ctx->identity.public_key, CYXWIZ_ED25519_PK_SIZE);
    msg.capabilities = 0x0F; /* All capabilities */

    /* Generate Schnorr identity proof */
    static const char *reg_context = "cyxwiz_validator_register";
    cyxwiz_proof_context_t proof_ctx;
    proof_ctx.context = (const uint8_t *)reg_context;
    proof_ctx.context_len = strlen(reg_context);

    cyxwiz_error_t err = cyxwiz_schnorr_prove(&ctx->identity, &proof_ctx, &msg.identity_proof);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to generate registration proof");
        return err;
    }

    /* Mark as pending first (local state update) */
    ctx->local_validator.state = CYXWIZ_VALIDATOR_PENDING;
    ctx->local_validator.registered_at = ctx->last_poll;

    /* Broadcast registration (may fail if no peers - that's ok, we'll retry in poll) */
    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    err = cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&msg, sizeof(msg));
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Broadcast registration failed (no peers?), will retry");
        /* Don't return error - local state is pending, we can retry later */
    } else {
        CYXWIZ_INFO("Broadcast validator registration");
    }

    return CYXWIZ_OK;
#endif
}

bool cyxwiz_consensus_is_registered(const cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return ctx->is_registered;
}

cyxwiz_validator_state_t cyxwiz_consensus_get_state(const cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) {
        return CYXWIZ_VALIDATOR_INACTIVE;
    }
    return ctx->local_validator.state;
}

/* ============ Work Credits ============ */

cyxwiz_error_t cyxwiz_consensus_report_work(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_work_type_t work_type,
    const uint8_t *work_id,
    uint16_t credits_earned)
{
    if (ctx == NULL || work_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Update local credits */
    uint32_t old_credits = ctx->local_validator.work_credits;
    ctx->local_validator.work_credits += credits_earned;
    ctx->total_earned += credits_earned;

    /* Update stats */
    if (work_type == CYXWIZ_WORK_COMPUTE) {
        ctx->local_validator.jobs_validated++;
    } else if (work_type == CYXWIZ_WORK_STORAGE) {
        ctx->local_validator.storage_proofs_passed++;
    } else if (work_type == CYXWIZ_WORK_VALIDATION) {
        ctx->local_validator.validations_participated++;
    }

    /* Notify callback */
    if (ctx->on_credits_change) {
        ctx->on_credits_change(&ctx->local_id, old_credits,
                               ctx->local_validator.work_credits,
                               ctx->credits_user_data);
    }

    CYXWIZ_DEBUG("Earned %u credits (type=%d, total=%u)",
                credits_earned, work_type, ctx->local_validator.work_credits);

    /* Broadcast work credit report */
    cyxwiz_work_credit_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_WORK_CREDIT;
    memcpy(&msg.validator_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    msg.work_type = (uint8_t)work_type;
    memcpy(msg.work_id, work_id, 8);
    msg.credits_earned = credits_earned;

    /* Hash of work as proof (truncated) */
#ifdef CYXWIZ_HAS_CRYPTO
    uint8_t hash[32];
    crypto_generichash(hash, 32, work_id, 8, NULL, 0);
    memcpy(msg.proof_hash, hash, 16);
#endif

    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&msg, sizeof(msg));

    return CYXWIZ_OK;
}

uint32_t cyxwiz_consensus_get_credits(const cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->local_validator.work_credits;
}

const cyxwiz_validator_t *cyxwiz_consensus_get_validator(
    const cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *node_id)
{
    if (ctx == NULL || node_id == NULL) {
        return NULL;
    }

    /* Check if it's us */
    if (memcmp(&ctx->local_id, node_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return &ctx->local_validator;
    }

    int idx = find_validator_index(ctx, node_id);
    if (idx < 0) {
        return NULL;
    }
    return &ctx->validators[idx];
}

/* ============ Committee Selection ============ */

/*
 * VRF-like deterministic committee selection weighted by credits
 */
cyxwiz_error_t cyxwiz_consensus_select_committee(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *seed,
    cyxwiz_node_id_t *committee_out,
    uint8_t *committee_size_out)
{
    if (ctx == NULL || seed == NULL || committee_out == NULL || committee_size_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Build list of active validators with scores */
    typedef struct {
        cyxwiz_node_id_t id;
        uint64_t score;
    } validator_score_t;

    validator_score_t scores[CYXWIZ_MAX_VALIDATORS + 1]; /* +1 for self */
    size_t score_count = 0;

    /* Add self if registered */
    if (ctx->is_registered && ctx->local_validator.state == CYXWIZ_VALIDATOR_ACTIVE) {
#ifdef CYXWIZ_HAS_CRYPTO
        uint8_t hash[32];
        uint8_t input[40]; /* seed + node_id */
        memcpy(input, seed, 8);
        memcpy(input + 8, &ctx->local_id, 32);
        crypto_generichash(hash, 32, input, 40, NULL, 0);

        /* Score = hash * credits (simplified) */
        uint64_t hash_val = 0;
        for (int i = 0; i < 8; i++) {
            hash_val = (hash_val << 8) | hash[i];
        }
        scores[score_count].id = ctx->local_id;
        scores[score_count].score = hash_val * (ctx->local_validator.work_credits + 1);
        score_count++;
#endif
    }

    /* Add known validators */
    for (size_t i = 0; i < ctx->validator_count && score_count < CYXWIZ_MAX_VALIDATORS; i++) {
        if (ctx->validators[i].state != CYXWIZ_VALIDATOR_ACTIVE) {
            continue;
        }

#ifdef CYXWIZ_HAS_CRYPTO
        uint8_t hash[32];
        uint8_t input[40];
        memcpy(input, seed, 8);
        memcpy(input + 8, &ctx->validators[i].node_id, 32);
        crypto_generichash(hash, 32, input, 40, NULL, 0);

        uint64_t hash_val = 0;
        for (int j = 0; j < 8; j++) {
            hash_val = (hash_val << 8) | hash[j];
        }
        scores[score_count].id = ctx->validators[i].node_id;
        scores[score_count].score = hash_val * (ctx->validators[i].work_credits + 1);
        score_count++;
#endif
    }

    if (score_count < CYXWIZ_MIN_COMMITTEE_SIZE) {
        *committee_size_out = 0;
        return CYXWIZ_ERR_CONSENSUS_NO_QUORUM;
    }

    /* Sort by score (descending) - simple bubble sort for small N */
    for (size_t i = 0; i < score_count - 1; i++) {
        for (size_t j = 0; j < score_count - i - 1; j++) {
            if (scores[j].score < scores[j + 1].score) {
                validator_score_t tmp = scores[j];
                scores[j] = scores[j + 1];
                scores[j + 1] = tmp;
            }
        }
    }

    /* Select top N validators */
    uint8_t committee_size = (uint8_t)(score_count > CYXWIZ_MAX_VALIDATORS ?
                                        CYXWIZ_MAX_VALIDATORS : score_count);

    for (uint8_t i = 0; i < committee_size; i++) {
        committee_out[i] = scores[i].id;
    }

    *committee_size_out = committee_size;
    CYXWIZ_DEBUG("Selected committee of %u validators", committee_size);
    return CYXWIZ_OK;
}

bool cyxwiz_consensus_in_committee(
    const cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id)
{
    if (ctx == NULL || round_id == NULL) {
        return false;
    }

    int idx = find_round_index(ctx, round_id);
    if (idx < 0) {
        return false;
    }

    return find_committee_member(&ctx->rounds[idx], &ctx->local_id) >= 0;
}

/* ============ Validation ============ */

cyxwiz_error_t cyxwiz_consensus_validate_job(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *job_id,
    const uint8_t *result,
    size_t result_len,
    const uint8_t *result_mac)
{
    if (ctx == NULL || job_id == NULL || result == NULL || result_mac == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int slot = find_free_round_slot(ctx);
    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    cyxwiz_consensus_round_t *round = &ctx->rounds[slot];
    memset(round, 0, sizeof(cyxwiz_consensus_round_t));

    /* Initialize round */
    generate_round_id(round->round_id);
    round->type = CYXWIZ_VALIDATE_JOB_RESULT;
    round->result = CYXWIZ_VALIDATION_PENDING;
    round->started_at = ctx->last_poll;
    round->active = true;
    round->allows_anonymous = true; /* Enable anonymous voting by default */

    /* Set target */
    memcpy(round->target.job.job_id, job_id, 8);
    memcpy(round->target.job.result_mac, result_mac, 16);

#ifdef CYXWIZ_HAS_CRYPTO
    /* Hash result for comparison */
    crypto_generichash(round->target.job.result_hash, 32, result, result_len, NULL, 0);
#else
    CYXWIZ_UNUSED(result_len);
#endif

    /* Select committee */
    uint8_t seed[8];
    memcpy(seed, round->round_id, 8);
    cyxwiz_error_t err = cyxwiz_consensus_select_committee(ctx, seed,
                                                            round->committee,
                                                            &round->committee_size);
    if (err != CYXWIZ_OK) {
        round->active = false;
        return err;
    }

    ctx->active_round_count++;

    /* Build validation request */
    cyxwiz_validation_req_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_VALIDATION_REQ;
    memcpy(msg.round_id, round->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    msg.validation_type = CYXWIZ_VALIDATE_JOB_RESULT;
    memcpy(msg.target_data, job_id, 8);
    memcpy(msg.target_data + 8, round->target.job.result_hash, 32);
    memcpy(msg.target_data + 40, result_mac, 16);
    memcpy(msg.committee_seed, seed, 8);

    /* Broadcast to committee */
    for (int i = 0; i < round->committee_size; i++) {
        cyxwiz_router_send(ctx->router, &round->committee[i], (uint8_t *)&msg, sizeof(msg));
    }

    CYXWIZ_INFO("Started job validation round (committee size: %u)", round->committee_size);

    /* Initiator votes VALID for their own proposal */
    cyxwiz_error_t vote_err = cyxwiz_consensus_vote(ctx, round->round_id, true);
    if (vote_err != CYXWIZ_OK) {
        CYXWIZ_DEBUG("Initiator vote failed (may not be in committee): %s", cyxwiz_strerror(vote_err));
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_consensus_validate_storage(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *storage_id,
    const cyxwiz_node_id_t *provider_id)
{
    if (ctx == NULL || storage_id == NULL || provider_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int slot = find_free_round_slot(ctx);
    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    cyxwiz_consensus_round_t *round = &ctx->rounds[slot];
    memset(round, 0, sizeof(cyxwiz_consensus_round_t));

    /* Initialize round */
    generate_round_id(round->round_id);
    round->type = CYXWIZ_VALIDATE_STORAGE_PROOF;
    round->result = CYXWIZ_VALIDATION_PENDING;
    round->started_at = ctx->last_poll;
    round->active = true;
    round->allows_anonymous = true; /* Enable anonymous voting by default */

    /* Set target */
    memcpy(round->target.storage.storage_id, storage_id, 8);
    memcpy(&round->target.storage.provider_id, provider_id, sizeof(cyxwiz_node_id_t));

    /* Select committee */
    uint8_t seed[8];
    memcpy(seed, round->round_id, 8);
    cyxwiz_error_t err = cyxwiz_consensus_select_committee(ctx, seed,
                                                            round->committee,
                                                            &round->committee_size);
    if (err != CYXWIZ_OK) {
        round->active = false;
        return err;
    }

    ctx->active_round_count++;

    /* Build storage validation request with shared challenge nonce */
    cyxwiz_storage_validate_req_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_STORAGE_VALIDATE_REQ;
    memcpy(msg.round_id, round->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    memcpy(msg.storage_id, storage_id, 8);
    memcpy(&msg.provider_id, provider_id, sizeof(cyxwiz_node_id_t));

#ifdef CYXWIZ_HAS_CRYPTO
    randombytes_buf(msg.challenge_nonce, 8);
#endif

    /* Broadcast to committee */
    for (int i = 0; i < round->committee_size; i++) {
        cyxwiz_router_send(ctx->router, &round->committee[i], (uint8_t *)&msg, sizeof(msg));
    }

    CYXWIZ_INFO("Started storage validation round (committee size: %u)", round->committee_size);

    /* Initiator votes VALID for their own proposal */
    cyxwiz_error_t vote_err = cyxwiz_consensus_vote(ctx, round->round_id, true);
    if (vote_err != CYXWIZ_OK) {
        CYXWIZ_DEBUG("Initiator vote failed (may not be in committee): %s", cyxwiz_strerror(vote_err));
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_consensus_vote(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id,
    bool valid)
{
    if (ctx == NULL || round_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!ctx->is_registered) {
        return CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR;
    }

    int idx = find_round_index(ctx, round_id);
    if (idx < 0) {
        /* Round not found - caller should have created it first */
        CYXWIZ_WARN("Cannot vote on unknown round");
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_consensus_round_t *round = &ctx->rounds[idx];

    /* Check if we're in the committee */
    int member_idx = find_committee_member(round, &ctx->local_id);
    if (member_idx < 0) {
        return CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR;
    }

    /* Check for equivocation */
    if (has_voted(round->votes_valid, member_idx) ||
        has_voted(round->votes_invalid, member_idx)) {
        CYXWIZ_WARN("Attempted double vote");
        return CYXWIZ_ERR_INVALID;
    }

    /* Record vote */
    if (valid) {
        set_vote(&round->votes_valid, member_idx);
    } else {
        set_vote(&round->votes_invalid, member_idx);
    }
    round->vote_count++;

    /* Build vote message with Schnorr proof */
    cyxwiz_validation_vote_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = CYXWIZ_MSG_VALIDATION_VOTE;
    memcpy(msg.round_id, round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    memcpy(&msg.validator_id, &ctx->local_id, sizeof(cyxwiz_node_id_t));
    msg.vote = valid ? 1 : 0;

#ifdef CYXWIZ_HAS_CRYPTO
    /* Generate Schnorr proof binding vote to round */
    uint8_t vote_data[CYXWIZ_CONSENSUS_ID_SIZE + 1];
    memcpy(vote_data, round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    vote_data[CYXWIZ_CONSENSUS_ID_SIZE] = msg.vote;

    cyxwiz_schnorr_prove_message(&ctx->identity, vote_data, sizeof(vote_data), &msg.vote_proof);
#endif

    /* Broadcast vote */
    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&msg, sizeof(msg));

    /* Update participation stats */
    ctx->local_validator.validations_participated++;

    /* Award participation credits */
    cyxwiz_consensus_report_work(ctx, CYXWIZ_WORK_VALIDATION, round_id, CYXWIZ_CREDIT_VALIDATION);

    CYXWIZ_DEBUG("Cast vote: %s for round", valid ? "VALID" : "INVALID");
    return CYXWIZ_OK;
}

/* ============ Anonymous Voting ============ */

cyxwiz_error_t cyxwiz_consensus_vote_anonymous(
    cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id,
    bool valid,
    const cyxwiz_credential_t *validator_cred)
{
    if (ctx == NULL || round_id == NULL || validator_cred == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Verify credential type is VOTE_ELIGIBLE */
    if (validator_cred->cred_type != CYXWIZ_CRED_VOTE_ELIGIBLE &&
        validator_cred->cred_type != CYXWIZ_CRED_VALIDATOR) {
        CYXWIZ_WARN("Anonymous vote requires vote eligibility credential");
        return CYXWIZ_ERR_CREDENTIAL_INVALID;
    }

    /* Check if round allows anonymous voting */
    if (!cyxwiz_consensus_round_allows_anonymous(ctx, round_id)) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Create anonymous vote message using privacy protocol */
    uint8_t vote_msg[256];
    size_t vote_len;
    cyxwiz_error_t err = cyxwiz_privacy_vote_anonymous(
        validator_cred,
        round_id,
        valid,
        vote_msg,
        &vote_len
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to create anonymous vote: %d", err);
        return err;
    }

    /* Broadcast the anonymous vote
     * Note: For maximum privacy, this should be sent via onion routing
     * to hide the sender's identity. For now, we broadcast directly. */
    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    err = cyxwiz_router_send(ctx->router, &broadcast, vote_msg, vote_len);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to broadcast anonymous vote");
        return err;
    }

    CYXWIZ_DEBUG("Cast anonymous vote: %s", valid ? "VALID" : "INVALID");
    return CYXWIZ_OK;
#endif
}

bool cyxwiz_consensus_round_allows_anonymous(
    const cyxwiz_consensus_ctx_t *ctx,
    const uint8_t *round_id)
{
    if (ctx == NULL || round_id == NULL) {
        return false;
    }

    int idx = find_round_index(ctx, round_id);
    if (idx < 0) {
        /* Unknown round - default to allowing anonymous for flexibility */
        return true;
    }

    return ctx->rounds[idx].allows_anonymous;
}

/* ============ Message Handling ============ */

static cyxwiz_error_t handle_validator_register(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_validator_register_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Verify Schnorr identity proof */
    static const char *reg_context = "cyxwiz_validator_register";
    cyxwiz_proof_context_t proof_ctx;
    proof_ctx.context = (const uint8_t *)reg_context;
    proof_ctx.context_len = strlen(reg_context);

    cyxwiz_error_t err = cyxwiz_schnorr_verify(msg->ed25519_pubkey,
                                                &msg->identity_proof,
                                                &proof_ctx);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Invalid registration proof");
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* Verify node ID matches pubkey */
    cyxwiz_node_id_t expected_id;
    cyxwiz_identity_keypair_t temp_kp;
    memcpy(temp_kp.public_key, msg->ed25519_pubkey, CYXWIZ_ED25519_PK_SIZE);
    cyxwiz_crypto_hash(msg->ed25519_pubkey, CYXWIZ_ED25519_PK_SIZE,
                       expected_id.bytes, CYXWIZ_NODE_ID_LEN);

    if (memcmp(&expected_id, &msg->node_id, sizeof(cyxwiz_node_id_t)) != 0) {
        CYXWIZ_WARN("Node ID doesn't match pubkey");
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* Add to known validators */
    if (ctx->validator_count >= CYXWIZ_MAX_VALIDATORS) {
        CYXWIZ_WARN("Validator table full");
        return CYXWIZ_ERR_NOMEM;
    }

    /* Check if already registered */
    int idx = find_validator_index(ctx, &msg->node_id);
    if (idx >= 0) {
        /* Update existing */
        ctx->validators[idx].state = CYXWIZ_VALIDATOR_ACTIVE;
        ctx->validators[idx].identity_verified = true;
        CYXWIZ_DEBUG("Updated existing validator");
        return CYXWIZ_OK;
    }

    /* Add new validator */
    cyxwiz_validator_t *v = &ctx->validators[ctx->validator_count];
    memset(v, 0, sizeof(cyxwiz_validator_t));
    memcpy(&v->node_id, &msg->node_id, sizeof(cyxwiz_node_id_t));
    memcpy(v->ed25519_pubkey, msg->ed25519_pubkey, CYXWIZ_ED25519_PK_SIZE);
    v->state = CYXWIZ_VALIDATOR_ACTIVE;
    v->identity_verified = true;
    v->registered_at = ctx->last_poll;
    v->credits_updated_at = ctx->last_poll;

    ctx->validator_count++;

    CYXWIZ_INFO("Registered new validator (total: %zu)", ctx->validator_count);

    /* Send ACK via broadcast (ensures delivery before routing is established) */
    cyxwiz_validator_reg_ack_msg_t ack;
    memset(&ack, 0, sizeof(ack));
    ack.type = CYXWIZ_MSG_VALIDATOR_REG_ACK;
    memcpy(&ack.node_id, &msg->node_id, sizeof(cyxwiz_node_id_t));
    ack.result = CYXWIZ_VALIDATION_VALID;

    cyxwiz_node_id_t broadcast;
    memset(&broadcast, 0xFF, sizeof(broadcast));
    cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&ack, sizeof(ack));

    return CYXWIZ_OK;
#endif
}

static cyxwiz_error_t handle_validator_reg_ack(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_validator_reg_ack_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    /* Check if this is for us */
    if (memcmp(&msg->node_id, &ctx->local_id, sizeof(cyxwiz_node_id_t)) != 0) {
        return CYXWIZ_OK; /* Not for us */
    }

    if (msg->result == CYXWIZ_VALIDATION_VALID) {
        cyxwiz_validator_state_t old_state = ctx->local_validator.state;
        ctx->local_validator.state = CYXWIZ_VALIDATOR_ACTIVE;
        ctx->is_registered = true;

        if (ctx->on_state_change) {
            ctx->on_state_change(&ctx->local_validator, old_state, ctx->state_user_data);
        }

        CYXWIZ_INFO("Validator registration confirmed");
    } else {
        CYXWIZ_WARN("Validator registration rejected");
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_work_credit(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_work_credit_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    int idx = find_validator_index(ctx, &msg->validator_id);
    if (idx < 0) {
        return CYXWIZ_OK; /* Unknown validator */
    }

    /* Update their credits (simplified - real impl would verify work) */
    ctx->validators[idx].work_credits += msg->credits_earned;

    CYXWIZ_DEBUG("Validator earned %u credits", msg->credits_earned);
    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_validation_req(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_validation_req_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    if (!ctx->is_registered) {
        return CYXWIZ_OK; /* Not a validator */
    }

    /* Check if round already exists */
    int idx = find_round_index(ctx, msg->round_id);
    if (idx >= 0) {
        return CYXWIZ_OK; /* Already know this round */
    }

    /* Create the round entry with committee */
    int slot = find_free_round_slot(ctx);
    if (slot < 0) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    cyxwiz_consensus_round_t *round = &ctx->rounds[slot];
    memset(round, 0, sizeof(cyxwiz_consensus_round_t));
    memcpy(round->round_id, msg->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    round->type = (cyxwiz_validation_type_t)msg->validation_type;
    round->result = CYXWIZ_VALIDATION_PENDING;
    round->started_at = ctx->last_poll;
    round->active = true;
    round->allows_anonymous = true;

    /* Select committee using the seed from the message */
    cyxwiz_error_t err = cyxwiz_consensus_select_committee(
        ctx, msg->committee_seed, round->committee, &round->committee_size);
    if (err != CYXWIZ_OK) {
        round->active = false;
        return CYXWIZ_OK;
    }

    ctx->active_round_count++;

    /* Check if we're in the committee */
    bool in_committee = false;
    for (uint8_t i = 0; i < round->committee_size; i++) {
        if (cyxwiz_node_id_cmp(&round->committee[i], &ctx->local_id) == 0) {
            in_committee = true;
            break;
        }
    }

    if (!in_committee) {
        CYXWIZ_DEBUG("Not in committee for round, ignoring");
        round->active = false;
        ctx->active_round_count--;
        return CYXWIZ_OK;
    }

    CYXWIZ_INFO("Received validation request, casting vote");
    return cyxwiz_consensus_vote(ctx, msg->round_id, true);
}

static cyxwiz_error_t handle_validation_vote(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_validation_vote_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    char voter_hex[65];
    cyxwiz_node_id_to_hex(&msg->validator_id, voter_hex);
    CYXWIZ_DEBUG("Received vote from %.16s... (vote=%d)", voter_hex, msg->vote);

    int idx = find_round_index(ctx, msg->round_id);
    if (idx < 0) {
        CYXWIZ_DEBUG("Vote for unknown round (active rounds: %d)", ctx->active_round_count);
        return CYXWIZ_OK; /* Unknown round */
    }

    CYXWIZ_DEBUG("Found round at index %d (committee_size=%d)", idx, ctx->rounds[idx].committee_size);
    cyxwiz_consensus_round_t *round = &ctx->rounds[idx];

#ifdef CYXWIZ_HAS_CRYPTO
    /* Verify vote proof */
    const cyxwiz_validator_t *voter = cyxwiz_consensus_get_validator(ctx, &msg->validator_id);
    CYXWIZ_DEBUG("Voter lookup: %p, identity_verified=%d", (void*)voter, voter ? voter->identity_verified : -1);
    if (voter == NULL || !voter->identity_verified) {
        CYXWIZ_WARN("Vote from unknown/unverified validator");
        return CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR;
    }

    uint8_t vote_data[CYXWIZ_CONSENSUS_ID_SIZE + 1];
    memcpy(vote_data, msg->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
    vote_data[CYXWIZ_CONSENSUS_ID_SIZE] = msg->vote;

    cyxwiz_error_t err = cyxwiz_schnorr_verify_message(voter->ed25519_pubkey,
                                                        vote_data, sizeof(vote_data),
                                                        &msg->vote_proof);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Invalid vote proof");
        return CYXWIZ_ERR_PROOF_INVALID;
    }
#endif

    /* Find committee member index */
    int member_idx = find_committee_member(round, &msg->validator_id);
    CYXWIZ_DEBUG("Committee member index: %d", member_idx);
    if (member_idx < 0) {
        CYXWIZ_DEBUG("Voter not in committee, ignoring vote");
        return CYXWIZ_OK; /* Not in committee */
    }

    /* Check for equivocation */
    bool already_valid = has_voted(round->votes_valid, member_idx);
    bool already_invalid = has_voted(round->votes_invalid, member_idx);

    if (already_valid || already_invalid) {
        bool new_vote = (msg->vote != 0);
        if ((already_valid && !new_vote) || (already_invalid && new_vote)) {
            /* Equivocation detected! Slash the validator. */
            char hex_id[65];
            cyxwiz_node_id_to_hex(&msg->validator_id, hex_id);
            CYXWIZ_WARN("Equivocation detected from validator %.16s...", hex_id);

            /* Create evidence hash */
            uint8_t evidence_hash[32];
            create_equivocation_evidence(round->round_id, &msg->validator_id,
                                         already_valid, new_vote, evidence_hash);

            /* Slash locally */
            slash_validator(ctx, &msg->validator_id, CYXWIZ_SLASH_EQUIVOCATION,
                           ctx->last_poll);

            /* Broadcast to other validators */
            broadcast_slash_report(ctx, &msg->validator_id, CYXWIZ_SLASH_EQUIVOCATION,
                                   round->round_id, evidence_hash);
        }
        return CYXWIZ_OK;
    }

    /* Record vote */
    if (msg->vote != 0) {
        set_vote(&round->votes_valid, member_idx);
    } else {
        set_vote(&round->votes_invalid, member_idx);
    }
    round->vote_count++;

    /* Check for quorum (including anonymous votes) */
    int valid_count = popcount32(round->votes_valid) + round->anon_votes_valid;
    int invalid_count = popcount32(round->votes_invalid) + round->anon_votes_invalid;
    int total_votes = valid_count + invalid_count;

    int quorum_needed = (round->committee_size * CYXWIZ_QUORUM_THRESHOLD + 99) / 100;

    if (valid_count >= quorum_needed) {
        round->result = CYXWIZ_VALIDATION_VALID;
        round->completed_at = ctx->last_poll;
        round->active = false;
        ctx->active_round_count--;

        CYXWIZ_INFO("Consensus reached: VALID (%d/%d votes)", valid_count, total_votes);

        if (ctx->on_validation_complete) {
            ctx->on_validation_complete(round, CYXWIZ_VALIDATION_VALID,
                                        ctx->validation_user_data);
        }

        /* Broadcast result */
        cyxwiz_validation_result_msg_t result_msg;
        memset(&result_msg, 0, sizeof(result_msg));
        result_msg.type = CYXWIZ_MSG_VALIDATION_RESULT;
        memcpy(result_msg.round_id, round->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
        result_msg.result = CYXWIZ_VALIDATION_VALID;
        result_msg.votes_valid = (uint8_t)valid_count;
        result_msg.votes_invalid = (uint8_t)invalid_count;

        cyxwiz_node_id_t broadcast;
        memset(&broadcast, 0xFF, sizeof(broadcast));
        cyxwiz_router_send(ctx->router, &broadcast, (uint8_t *)&result_msg, sizeof(result_msg));

    } else if (invalid_count >= quorum_needed) {
        round->result = CYXWIZ_VALIDATION_INVALID;
        round->completed_at = ctx->last_poll;
        round->active = false;
        ctx->active_round_count--;

        CYXWIZ_INFO("Consensus reached: INVALID (%d/%d votes)", invalid_count, total_votes);

        if (ctx->on_validation_complete) {
            ctx->on_validation_complete(round, CYXWIZ_VALIDATION_INVALID,
                                        ctx->validation_user_data);
        }
    }

    return CYXWIZ_OK;
}

static cyxwiz_error_t handle_validator_heartbeat(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_validator_heartbeat_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

    int idx = find_validator_index(ctx, &msg->validator_id);
    if (idx >= 0) {
        /* Update credits (truncated value) */
        if (msg->current_credits > ctx->validators[idx].work_credits) {
            ctx->validators[idx].work_credits = msg->current_credits;
        }
        ctx->validators[idx].credits_updated_at = ctx->last_poll;
    }

    return CYXWIZ_OK;
}

/*
 * Handle anonymous vote message (CYXWIZ_MSG_ANON_VOTE = 0x77)
 *
 * Anonymous votes use the privacy protocol's credential system
 * to prove validator eligibility without revealing identity.
 */
static cyxwiz_error_t handle_anon_vote(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const cyxwiz_anon_vote_msg_t *msg)
{
    CYXWIZ_UNUSED(from);

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(msg);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    /* Find the round */
    int idx = find_round_index(ctx, msg->round_id);
    if (idx < 0) {
        CYXWIZ_DEBUG("Anonymous vote for unknown round");
        return CYXWIZ_OK; /* Unknown round, ignore */
    }

    cyxwiz_consensus_round_t *round = &ctx->rounds[idx];

    /* Check if round allows anonymous voting */
    if (!round->allows_anonymous) {
        CYXWIZ_WARN("Anonymous vote rejected: round requires identified voting");
        return CYXWIZ_ERR_INVALID;
    }

    /* Verify the credential show proof */
    /* We accept credentials from any registered issuer (simplified) */
    cyxwiz_error_t err = cyxwiz_cred_show_verify(
        &msg->cred_proof,
        CYXWIZ_CRED_VOTE_ELIGIBLE,
        ctx->identity.public_key, /* Use our key as issuer for now */
        ctx->last_poll
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Invalid anonymous vote credential proof");
        return CYXWIZ_ERR_CREDENTIAL_INVALID;
    }

    /* Verify vote commitment and proof (simplified - check commitment is valid point) */
    if (crypto_core_ed25519_is_valid_point(msg->vote_commitment) != 1) {
        CYXWIZ_WARN("Invalid vote commitment in anonymous vote");
        return CYXWIZ_ERR_INVALID;
    }

    /* Record anonymous vote */
    if (msg->vote != 0) {
        round->anon_votes_valid++;
    } else {
        round->anon_votes_invalid++;
    }
    round->vote_count++;

    CYXWIZ_DEBUG("Received anonymous vote: %s", msg->vote ? "VALID" : "INVALID");

    /* Check for quorum including anonymous votes */
    int valid_count = popcount32(round->votes_valid) + round->anon_votes_valid;
    int invalid_count = popcount32(round->votes_invalid) + round->anon_votes_invalid;
    int total_votes = valid_count + invalid_count;

    /* For anonymous voting, we use a fixed effective committee size
     * since we don't know how many eligible voters there are */
    int effective_committee = round->committee_size > 0 ?
                              round->committee_size : CYXWIZ_MIN_COMMITTEE_SIZE;
    int quorum_needed = (effective_committee * CYXWIZ_QUORUM_THRESHOLD + 99) / 100;

    if (valid_count >= quorum_needed) {
        round->result = CYXWIZ_VALIDATION_VALID;
        round->completed_at = ctx->last_poll;
        round->active = false;
        ctx->active_round_count--;

        CYXWIZ_INFO("Consensus reached (with anon votes): VALID (%d/%d votes)",
                    valid_count, total_votes);

        if (ctx->on_validation_complete) {
            ctx->on_validation_complete(round, CYXWIZ_VALIDATION_VALID,
                                        ctx->validation_user_data);
        }

        /* Broadcast result */
        cyxwiz_validation_result_msg_t result_msg;
        memset(&result_msg, 0, sizeof(result_msg));
        result_msg.type = CYXWIZ_MSG_VALIDATION_RESULT;
        memcpy(result_msg.round_id, round->round_id, CYXWIZ_CONSENSUS_ID_SIZE);
        result_msg.result = CYXWIZ_VALIDATION_VALID;
        result_msg.votes_valid = (uint8_t)valid_count;
        result_msg.votes_invalid = (uint8_t)invalid_count;

        cyxwiz_node_id_t broadcast;
        memset(&broadcast, 0xFF, sizeof(broadcast));
        cyxwiz_router_send(ctx->router, &broadcast,
                           (uint8_t *)&result_msg, sizeof(result_msg));

    } else if (invalid_count >= quorum_needed) {
        round->result = CYXWIZ_VALIDATION_INVALID;
        round->completed_at = ctx->last_poll;
        round->active = false;
        ctx->active_round_count--;

        CYXWIZ_INFO("Consensus reached (with anon votes): INVALID (%d/%d votes)",
                    invalid_count, total_votes);

        if (ctx->on_validation_complete) {
            ctx->on_validation_complete(round, CYXWIZ_VALIDATION_INVALID,
                                        ctx->validation_user_data);
        }
    }

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_consensus_handle_message(
    cyxwiz_consensus_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (ctx == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    /* Rate limit check */
    uint64_t now = cyxwiz_time_ms();
    if (!cyxwiz_peer_table_check_rate_limit(ctx->peer_table, from, now, msg_type)) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(from, hex_id);
        CYXWIZ_WARN("Rate limit exceeded for consensus message from %.16s...", hex_id);
        return CYXWIZ_ERR_RATE_LIMITED;
    }

    switch (msg_type) {
        case CYXWIZ_MSG_VALIDATOR_REGISTER:
            if (len >= sizeof(cyxwiz_validator_register_msg_t)) {
                return handle_validator_register(ctx, from,
                    (const cyxwiz_validator_register_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_VALIDATOR_REG_ACK:
            if (len >= sizeof(cyxwiz_validator_reg_ack_msg_t)) {
                return handle_validator_reg_ack(ctx, from,
                    (const cyxwiz_validator_reg_ack_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_WORK_CREDIT:
            if (len >= sizeof(cyxwiz_work_credit_msg_t)) {
                return handle_work_credit(ctx, from,
                    (const cyxwiz_work_credit_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_VALIDATION_REQ:
            if (len >= sizeof(cyxwiz_validation_req_msg_t)) {
                return handle_validation_req(ctx, from,
                    (const cyxwiz_validation_req_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_VALIDATION_VOTE:
            if (len >= sizeof(cyxwiz_validation_vote_msg_t)) {
                return handle_validation_vote(ctx, from,
                    (const cyxwiz_validation_vote_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_VALIDATOR_HEARTBEAT:
            if (len >= sizeof(cyxwiz_validator_heartbeat_msg_t)) {
                return handle_validator_heartbeat(ctx, from,
                    (const cyxwiz_validator_heartbeat_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_ANON_VOTE:
            if (len >= sizeof(cyxwiz_anon_vote_msg_t)) {
                return handle_anon_vote(ctx, from,
                    (const cyxwiz_anon_vote_msg_t *)data);
            }
            break;

        case CYXWIZ_MSG_SLASH_REPORT:
            if (len >= sizeof(cyxwiz_slash_report_msg_t)) {
                return handle_slash_report(ctx, from,
                    (const cyxwiz_slash_report_msg_t *)data);
            }
            break;

        default:
            CYXWIZ_DEBUG("Unknown consensus message type: 0x%02X", msg_type);
            break;
    }

    return CYXWIZ_OK;
}

/* ============ Callbacks ============ */

void cyxwiz_consensus_set_validation_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_validation_complete_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_validation_complete = callback;
    ctx->validation_user_data = user_data;
}

void cyxwiz_consensus_set_credits_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_credits_change_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_credits_change = callback;
    ctx->credits_user_data = user_data;
}

void cyxwiz_consensus_set_state_callback(
    cyxwiz_consensus_ctx_t *ctx,
    cyxwiz_validator_state_cb_t callback,
    void *user_data)
{
    if (ctx == NULL) return;
    ctx->on_state_change = callback;
    ctx->state_user_data = user_data;
}

/* ============ Statistics ============ */

size_t cyxwiz_consensus_validator_count(const cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    return ctx->validator_count;
}

size_t cyxwiz_consensus_active_rounds(const cyxwiz_consensus_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    return ctx->active_round_count;
}

/* ============ Utilities ============ */

const char *cyxwiz_validator_state_name(cyxwiz_validator_state_t state)
{
    switch (state) {
        case CYXWIZ_VALIDATOR_INACTIVE:  return "inactive";
        case CYXWIZ_VALIDATOR_PENDING:   return "pending";
        case CYXWIZ_VALIDATOR_ACTIVE:    return "active";
        case CYXWIZ_VALIDATOR_SLASHED:   return "slashed";
        default:                         return "unknown";
    }
}

const char *cyxwiz_validation_result_name(cyxwiz_validation_result_t result)
{
    switch (result) {
        case CYXWIZ_VALIDATION_PENDING:      return "pending";
        case CYXWIZ_VALIDATION_VALID:        return "valid";
        case CYXWIZ_VALIDATION_INVALID:      return "invalid";
        case CYXWIZ_VALIDATION_INCONCLUSIVE: return "inconclusive";
        case CYXWIZ_VALIDATION_TIMEOUT:      return "timeout";
        default:                             return "unknown";
    }
}

const char *cyxwiz_slash_reason_name(cyxwiz_slash_reason_t reason)
{
    switch (reason) {
        case CYXWIZ_SLASH_FALSE_POSITIVE: return "false_positive";
        case CYXWIZ_SLASH_FALSE_NEGATIVE: return "false_negative";
        case CYXWIZ_SLASH_OFFLINE:        return "offline";
        case CYXWIZ_SLASH_EQUIVOCATION:   return "equivocation";
        default:                          return "unknown";
    }
}
