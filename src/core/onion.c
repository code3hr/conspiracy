/*
 * CyxWiz Protocol - Onion Routing Implementation
 *
 * Implements layered encryption for anonymous routing:
 * - X25519 key exchange for shared secrets
 * - XChaCha20-Poly1305 for each layer
 * - Circuit management for multi-hop paths
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/onion.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

#include <string.h>
#include <stdio.h>

/* Onion context structure */
struct cyxwiz_onion_ctx {
    cyxwiz_router_t *router;
    cyxwiz_node_id_t local_id;

    /* X25519 keypair */
    uint8_t secret_key[CYXWIZ_KEY_SIZE];
    uint8_t public_key[CYXWIZ_PUBKEY_SIZE];

    /* Active circuits */
    cyxwiz_circuit_t circuits[CYXWIZ_MAX_CIRCUITS];
    size_t circuit_count;

    /* Shared secrets with peers */
    cyxwiz_peer_key_t peer_keys[CYXWIZ_MAX_PEERS];
    size_t peer_key_count;

    /* Guard nodes for consistent entry points */
    cyxwiz_guard_t guards[CYXWIZ_NUM_GUARDS];

    /* Cover traffic state */
    bool cover_traffic_enabled;
    uint64_t last_cover_traffic_ms;
    uint64_t next_cover_traffic_ms;   /* Jittered next cover time */

    /* Circuit prebuilding state */
    uint64_t last_prebuild_ms;
    uint64_t next_prebuild_ms;        /* Jittered next prebuild time */

    /* Path diversity: track relays in active circuits */
    cyxwiz_node_id_t active_relays[CYXWIZ_MAX_CIRCUITS * CYXWIZ_MAX_ONION_HOPS];
    size_t active_relay_count;

    /* Replay protection: track seen onion packets */
    struct {
        uint8_t hash[CYXWIZ_ONION_HASH_SIZE];
        uint64_t seen_at;
    } seen_onions[CYXWIZ_MAX_SEEN_ONIONS];
    size_t seen_onion_count;

    /* Delivery callback */
    cyxwiz_delivery_callback_t callback;
    void *user_data;

    /* Stream callback (for multiplexed stream events) */
    cyxwiz_stream_callback_t stream_callback;
    void *stream_user_data;

    /* Next circuit ID */
    uint32_t next_circuit_id;

    /* Hidden services (hosted by this node) */
    cyxwiz_hidden_service_t services[CYXWIZ_MAX_HIDDEN_SERVICES];
    size_t service_count;

    /* Client-side hidden service connections (rendezvous-based) */
    cyxwiz_service_conn_t service_connections[CYXWIZ_MAX_SERVICE_CONNECTIONS];
    size_t connection_count;

    /* Rendezvous points (this node acting as RP) */
    cyxwiz_rendezvous_t rendezvous_points[CYXWIZ_MAX_RENDEZVOUS];
    size_t rendezvous_count;
};

/* Forward declarations */
static void send_cover_traffic(cyxwiz_onion_ctx_t *ctx);
static void prebuild_circuits(cyxwiz_onion_ctx_t *ctx, uint64_t now);
static void expire_seen_onions(cyxwiz_onion_ctx_t *ctx, uint64_t now);

/* Circuit health monitoring */
static void check_circuit_health(cyxwiz_onion_ctx_t *ctx, uint64_t now);

/* Rendezvous point management */
static cyxwiz_rendezvous_t *find_rendezvous_by_cookie(cyxwiz_onion_ctx_t *ctx, const uint8_t *cookie);
static void handle_rendezvous1(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *from, uint32_t circuit_id, const uint8_t *data, size_t len);
static void handle_rendezvous2(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *from, uint32_t circuit_id, const uint8_t *data, size_t len);
static void handle_rendezvous_data(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *from, uint32_t circuit_id, const uint8_t *data, size_t len);
static void handle_introduce1(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *from, const uint8_t *data, size_t len);
static void handle_introduce_ack(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *from, const uint8_t *data, size_t len);
static void expire_rendezvous_points(cyxwiz_onion_ctx_t *ctx, uint64_t now);
static void send_circuit_health_probe(cyxwiz_onion_ctx_t *ctx, cyxwiz_circuit_t *circuit, uint64_t now);
static uint8_t circuit_success_rate(const cyxwiz_circuit_t *circuit);

/* ============ Traffic Analysis Resistance ============ */

/*
 * Apply timing jitter to an interval
 * Returns base_ms ± (percent% of base_ms)
 */
static uint64_t apply_jitter(uint64_t base_ms, uint8_t percent)
{
#ifdef CYXWIZ_HAS_CRYPTO
    if (percent == 0 || base_ms == 0) {
        return base_ms;
    }

    /* Calculate jitter range: ±percent% of base */
    uint64_t jitter_range = (base_ms * percent) / 100;
    if (jitter_range == 0) {
        return base_ms;
    }

    /* Get random value in range [0, 2*jitter_range] */
    uint32_t rand_val;
    randombytes_buf(&rand_val, sizeof(rand_val));
    uint64_t jitter = rand_val % (2 * jitter_range + 1);

    /* Apply jitter: base - range + random(0, 2*range) = base ± range */
    return base_ms - jitter_range + jitter;
#else
    return base_ms;
#endif
}

/* ============ Circuit Health Monitoring ============ */

/*
 * Calculate circuit success rate (0-100%)
 */
static uint8_t circuit_success_rate(const cyxwiz_circuit_t *circuit)
{
    if (circuit == NULL || circuit->messages_sent == 0) {
        return 100;  /* No data yet, assume healthy */
    }

    uint32_t successful = circuit->messages_sent - circuit->messages_failed;
    return (uint8_t)((successful * 100) / circuit->messages_sent);
}

/*
 * Send a health probe through a circuit
 */
static void send_circuit_health_probe(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    uint64_t now)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(circuit);
    CYXWIZ_UNUSED(now);
#else
    if (ctx == NULL || circuit == NULL || !circuit->active) {
        return;
    }

    /* Already have a probe pending */
    if (circuit->health_probe_pending) {
        return;
    }

    /* Build probe payload: magic marker (4 bytes) + circuit_id (4 bytes) */
    uint8_t probe[8];
    probe[0] = (CYXWIZ_CIRCUIT_PROBE_MAGIC >> 24) & 0xFF;
    probe[1] = (CYXWIZ_CIRCUIT_PROBE_MAGIC >> 16) & 0xFF;
    probe[2] = (CYXWIZ_CIRCUIT_PROBE_MAGIC >> 8) & 0xFF;
    probe[3] = CYXWIZ_CIRCUIT_PROBE_MAGIC & 0xFF;
    probe[4] = (circuit->circuit_id >> 24) & 0xFF;
    probe[5] = (circuit->circuit_id >> 16) & 0xFF;
    probe[6] = (circuit->circuit_id >> 8) & 0xFF;
    probe[7] = circuit->circuit_id & 0xFF;

    /* Send probe through circuit */
    cyxwiz_error_t err = cyxwiz_onion_send(ctx, circuit, probe, sizeof(probe));
    if (err == CYXWIZ_OK) {
        circuit->health_probe_pending = true;
        circuit->health_probe_sent_ms = now;
        CYXWIZ_DEBUG("Sent health probe for circuit %u", circuit->circuit_id);
    } else {
        CYXWIZ_WARN("Failed to send health probe for circuit %u: %s",
                   circuit->circuit_id, cyxwiz_strerror(err));
    }
#endif
}

/*
 * Check health of all active circuits
 * - Sends probes to circuits without recent activity
 * - Checks for probe timeouts
 * - Rotates unhealthy circuits early
 */
static void check_circuit_health(cyxwiz_onion_ctx_t *ctx, uint64_t now)
{
    if (ctx == NULL) {
        return;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        cyxwiz_circuit_t *circuit = &ctx->circuits[i];
        if (!circuit->active) {
            continue;
        }

        uint64_t age = now - circuit->created_at;

        /* Check for probe timeout */
        if (circuit->health_probe_pending) {
            uint64_t probe_age = now - circuit->health_probe_sent_ms;
            if (probe_age > CYXWIZ_CIRCUIT_HEALTH_TIMEOUT_MS) {
                /* Probe timed out - count as failure */
                circuit->messages_failed++;
                circuit->health_probe_pending = false;
                CYXWIZ_WARN("Health probe timeout for circuit %u", circuit->circuit_id);
            }
        }

        /* Check success rate - rotate early if unhealthy */
        uint8_t success_rate = circuit_success_rate(circuit);
        if (circuit->messages_sent >= 3 && success_rate < CYXWIZ_CIRCUIT_MIN_SUCCESS_RATE) {
            CYXWIZ_WARN("Circuit %u unhealthy (success rate %u%%), forcing rotation",
                       circuit->circuit_id, success_rate);
            cyxwiz_secure_zero(circuit->keys, sizeof(circuit->keys));
            circuit->active = false;
            ctx->circuit_count--;
            continue;
        }

        /* Send health probe if circuit is old enough and no recent activity */
        if (age >= CYXWIZ_CIRCUIT_HEALTH_INTERVAL_MS &&
            !circuit->health_probe_pending &&
            (circuit->last_success_ms == 0 ||
             (now - circuit->last_success_ms) >= CYXWIZ_CIRCUIT_HEALTH_INTERVAL_MS)) {
            send_circuit_health_probe(ctx, circuit, now);
        }
    }
}

/* ============ Helper Functions ============ */

bool cyxwiz_node_id_is_zero(const cyxwiz_node_id_t *id)
{
    if (id == NULL) {
        return true;
    }
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        if (id->bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static cyxwiz_peer_key_t *find_peer_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id)
{
    for (size_t i = 0; i < ctx->peer_key_count; i++) {
        if (ctx->peer_keys[i].valid &&
            memcmp(&ctx->peer_keys[i].peer_id, peer_id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &ctx->peer_keys[i];
        }
    }
    return NULL;
}

/* ============ Onion Context Lifecycle ============ */

cyxwiz_error_t cyxwiz_onion_create(
    cyxwiz_onion_ctx_t **ctx,
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *local_id)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_ERROR("Onion routing requires crypto module");
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || router == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_onion_ctx_t *c = cyxwiz_calloc(1, sizeof(cyxwiz_onion_ctx_t));
    if (c == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    c->router = router;
    memcpy(&c->local_id, local_id, sizeof(cyxwiz_node_id_t));

    /* Generate X25519 keypair */
    crypto_box_keypair(c->public_key, c->secret_key);

    c->circuit_count = 0;
    c->peer_key_count = 0;
    c->next_circuit_id = 1;
    c->callback = NULL;
    c->user_data = NULL;

    CYXWIZ_INFO("Onion routing context created");
    *ctx = c;
    return CYXWIZ_OK;
#endif
}

void cyxwiz_onion_destroy(cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Zero sensitive data */
    cyxwiz_secure_zero(ctx->secret_key, sizeof(ctx->secret_key));
    for (size_t i = 0; i < ctx->peer_key_count; i++) {
        cyxwiz_secure_zero(ctx->peer_keys[i].shared_secret,
                          sizeof(ctx->peer_keys[i].shared_secret));
    }
    for (size_t i = 0; i < ctx->circuit_count; i++) {
        cyxwiz_secure_zero(ctx->circuits[i].keys,
                          sizeof(ctx->circuits[i].keys));
    }

    cyxwiz_free(ctx, sizeof(cyxwiz_onion_ctx_t));
    CYXWIZ_INFO("Onion routing context destroyed");
}

void cyxwiz_onion_set_callback(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_delivery_callback_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->callback = callback;
    ctx->user_data = user_data;
}

void cyxwiz_onion_set_stream_callback(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_stream_callback_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->stream_callback = callback;
    ctx->stream_user_data = user_data;
}

cyxwiz_error_t cyxwiz_onion_poll(
    cyxwiz_onion_ctx_t *ctx,
    uint64_t current_time_ms)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Expire old circuits */
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active) {
            uint64_t age = current_time_ms - ctx->circuits[i].created_at;
            if (age > CYXWIZ_CIRCUIT_TIMEOUT_MS) {
                CYXWIZ_DEBUG("Circuit %u expired", ctx->circuits[i].circuit_id);
                cyxwiz_secure_zero(ctx->circuits[i].keys,
                                  sizeof(ctx->circuits[i].keys));
                ctx->circuits[i].active = false;
                ctx->circuit_count--;
            }
        }
    }

    /* Expire old seen onion entries */
    expire_seen_onions(ctx, current_time_ms);

    /* Send cover traffic periodically (with jitter for traffic analysis resistance) */
    if (ctx->cover_traffic_enabled) {
        /* Initialize next_cover_traffic_ms on first poll */
        if (ctx->next_cover_traffic_ms == 0) {
            ctx->next_cover_traffic_ms = current_time_ms +
                apply_jitter(CYXWIZ_COVER_TRAFFIC_INTERVAL_MS, CYXWIZ_TIMING_JITTER_PERCENT);
        }

        if (current_time_ms >= ctx->next_cover_traffic_ms) {
            ctx->last_cover_traffic_ms = current_time_ms;
            /* Schedule next with jitter */
            ctx->next_cover_traffic_ms = current_time_ms +
                apply_jitter(CYXWIZ_COVER_TRAFFIC_INTERVAL_MS, CYXWIZ_TIMING_JITTER_PERCENT);
            send_cover_traffic(ctx);
        }
    }

    /* Prebuild circuits periodically (with jitter for traffic analysis resistance) */
    /* Initialize next_prebuild_ms on first poll */
    if (ctx->next_prebuild_ms == 0) {
        ctx->next_prebuild_ms = current_time_ms +
            apply_jitter(CYXWIZ_PREBUILD_INTERVAL_MS, CYXWIZ_TIMING_JITTER_PERCENT);
    }

    if (current_time_ms >= ctx->next_prebuild_ms) {
        ctx->last_prebuild_ms = current_time_ms;
        /* Schedule next with jitter */
        ctx->next_prebuild_ms = current_time_ms +
            apply_jitter(CYXWIZ_PREBUILD_INTERVAL_MS, CYXWIZ_TIMING_JITTER_PERCENT);
        prebuild_circuits(ctx, current_time_ms);
    }

    /* Check circuit health periodically */
    check_circuit_health(ctx, current_time_ms);

    /* Expire old rendezvous points */
    expire_rendezvous_points(ctx, current_time_ms);

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_onion_refresh_keypair(cyxwiz_onion_ctx_t *ctx)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Securely zero old secret key before generating new one */
    cyxwiz_secure_zero(ctx->secret_key, sizeof(ctx->secret_key));

    /* Generate new X25519 keypair */
    crypto_box_keypair(ctx->public_key, ctx->secret_key);

    /* Clear all peer shared secrets (they were computed with old keypair) */
    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (ctx->peer_keys[i].valid) {
            cyxwiz_secure_zero(ctx->peer_keys[i].shared_secret,
                              sizeof(ctx->peer_keys[i].shared_secret));
            ctx->peer_keys[i].valid = false;
        }
    }
    ctx->peer_key_count = 0;

    /* Invalidate all active circuits (keys derived from old shared secrets) */
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active) {
            cyxwiz_secure_zero(ctx->circuits[i].keys,
                              sizeof(ctx->circuits[i].keys));
            cyxwiz_secure_zero(ctx->circuits[i].ephemeral_pubs,
                              sizeof(ctx->circuits[i].ephemeral_pubs));
            ctx->circuits[i].active = false;
        }
    }
    ctx->circuit_count = 0;

    CYXWIZ_INFO("Refreshed X25519 keypair - all peer keys and circuits cleared");

    return CYXWIZ_OK;
#endif
}

/* ============ Key Management ============ */

cyxwiz_error_t cyxwiz_onion_get_pubkey(
    cyxwiz_onion_ctx_t *ctx,
    uint8_t *pubkey_out)
{
    if (ctx == NULL || pubkey_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }
    memcpy(pubkey_out, ctx->public_key, CYXWIZ_PUBKEY_SIZE);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_onion_add_peer_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id,
    const uint8_t *peer_pubkey)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || peer_id == NULL || peer_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if already exists */
    cyxwiz_peer_key_t *existing = find_peer_key(ctx, peer_id);
    if (existing != NULL) {
        /* Key pinning: check for key changes (potential MITM) */
        if (existing->key_pinned) {
            if (memcmp(existing->pinned_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE) != 0) {
                char hex_id[65];
                cyxwiz_node_id_to_hex(peer_id, hex_id);
                CYXWIZ_WARN("KEY CHANGE DETECTED for peer %.16s... - possible MITM!", hex_id);
                existing->key_changed = true;
            }
        } else {
            /* First time seeing this peer with a valid key - pin it */
            memcpy(existing->pinned_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);
            existing->key_pinned = true;
            existing->pinned_at = cyxwiz_time_ms();
            existing->key_changed = false;
        }

        /* Update existing */
        memcpy(existing->peer_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);

        /* Recompute shared secret */
        if (crypto_scalarmult(existing->shared_secret,
                             ctx->secret_key,
                             peer_pubkey) != 0) {
            CYXWIZ_ERROR("Failed to compute shared secret");
            return CYXWIZ_ERR_CRYPTO;
        }

        existing->established_at = cyxwiz_time_ms();
        CYXWIZ_DEBUG("Updated shared key with peer");
        return CYXWIZ_OK;
    }

    /* Find free slot */
    cyxwiz_peer_key_t *slot = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            slot = &ctx->peer_keys[i];
            break;
        }
    }

    if (slot == NULL) {
        CYXWIZ_WARN("Peer key table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Compute X25519 shared secret */
    if (crypto_scalarmult(slot->shared_secret,
                         ctx->secret_key,
                         peer_pubkey) != 0) {
        CYXWIZ_ERROR("Failed to compute shared secret");
        return CYXWIZ_ERR_CRYPTO;
    }

    memcpy(&slot->peer_id, peer_id, sizeof(cyxwiz_node_id_t));
    memcpy(slot->peer_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);
    slot->established_at = cyxwiz_time_ms();
    slot->valid = true;

    /* Pin the key on first contact */
    memcpy(slot->pinned_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);
    slot->key_pinned = true;
    slot->pinned_at = cyxwiz_time_ms();
    slot->key_changed = false;

    ctx->peer_key_count++;

    CYXWIZ_DEBUG("Added shared key with peer (key pinned)");
    return CYXWIZ_OK;
#endif
}

bool cyxwiz_onion_has_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id)
{
    if (ctx == NULL || peer_id == NULL) {
        return false;
    }
    return find_peer_key(ctx, peer_id) != NULL;
}

cyxwiz_error_t cyxwiz_onion_derive_hop_key(
    const uint8_t *shared_secret,
    const cyxwiz_node_id_t *sender,
    const cyxwiz_node_id_t *receiver,
    uint8_t *key_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (shared_secret == NULL || sender == NULL ||
        receiver == NULL || key_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Context: "cyxwiz_onion_v1" || sender_id || receiver_id */
    uint8_t context[15 + 32 + 32];
    memcpy(context, "cyxwiz_onion_v1", 15);  /* NOLINT(bugprone-not-null-terminated-result) */
    memcpy(context + 15, sender->bytes, 32);
    memcpy(context + 47, receiver->bytes, 32);

    return cyxwiz_crypto_derive_key(shared_secret, CYXWIZ_KEY_SIZE,
                                    context, sizeof(context), key_out);
#endif
}

cyxwiz_error_t cyxwiz_onion_compute_ecdh(
    cyxwiz_onion_ctx_t *ctx,
    const uint8_t *peer_pubkey,
    uint8_t *secret_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || peer_pubkey == NULL || secret_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* X25519 scalar multiplication: shared = our_sk * peer_pk */
    if (crypto_scalarmult(secret_out, ctx->secret_key, peer_pubkey) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

/* ============ Circuit Management ============ */

cyxwiz_error_t cyxwiz_onion_build_circuit(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *hops,
    uint8_t hop_count,
    cyxwiz_circuit_t **circuit_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(hops);
    CYXWIZ_UNUSED(hop_count);
    CYXWIZ_UNUSED(circuit_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || hops == NULL || circuit_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        CYXWIZ_ERROR("Invalid hop count: %u (max %u)", hop_count, CYXWIZ_MAX_ONION_HOPS);
        return CYXWIZ_ERR_INVALID;
    }

    /* Check we have peer pubkeys for all hops (needed for ephemeral ECDH) */
    for (uint8_t i = 0; i < hop_count; i++) {
        if (!cyxwiz_onion_has_key(ctx, &hops[i])) {
            CYXWIZ_ERROR("No shared key with hop %u", i);
            return CYXWIZ_ERR_NO_KEY;
        }
    }

    /* Find free circuit slot */
    cyxwiz_circuit_t *circuit = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (!ctx->circuits[i].active) {
            circuit = &ctx->circuits[i];
            break;
        }
    }

    if (circuit == NULL) {
        CYXWIZ_ERROR("Circuit table full");
        return CYXWIZ_ERR_CIRCUIT_FULL;
    }

    /* Initialize circuit */
    circuit->circuit_id = ctx->next_circuit_id++;
    circuit->hop_count = hop_count;
    circuit->created_at = cyxwiz_time_ms();
    circuit->active = true;

    /* Initialize health monitoring fields */
    circuit->messages_sent = 0;
    circuit->messages_failed = 0;
    circuit->last_success_ms = 0;
    circuit->avg_latency_ms = 0;
    circuit->health_probe_pending = false;
    circuit->health_probe_sent_ms = 0;

    /*
     * Generate ephemeral keypairs for each hop and derive per-hop keys.
     * Each hop will use ECDH between the ephemeral pubkey and their private key
     * to derive the layer key. This allows multi-hop routing since each hop
     * can independently derive the correct key without knowing the sender.
     */
    for (uint8_t i = 0; i < hop_count; i++) {
        memcpy(&circuit->hops[i], &hops[i], sizeof(cyxwiz_node_id_t));

        /* Get peer's public key for ECDH */
        cyxwiz_peer_key_t *peer_key = find_peer_key(ctx, &hops[i]);
        if (peer_key == NULL) {
            circuit->active = false;
            return CYXWIZ_ERR_NO_KEY;
        }

        /* Generate ephemeral X25519 keypair for this hop */
        uint8_t ephemeral_sk[CYXWIZ_KEY_SIZE];
        crypto_box_keypair(circuit->ephemeral_pubs[i], ephemeral_sk);

        /* Compute ephemeral shared secret: ephemeral_sk * peer_pubkey */
        uint8_t ephemeral_shared[CYXWIZ_KEY_SIZE];
        if (crypto_scalarmult(ephemeral_shared, ephemeral_sk, peer_key->peer_pubkey) != 0) {
            cyxwiz_secure_zero(ephemeral_sk, sizeof(ephemeral_sk));
            circuit->active = false;
            CYXWIZ_ERROR("Failed to compute ephemeral shared secret");
            return CYXWIZ_ERR_CRYPTO;
        }

        /* Derive hop key from ephemeral shared secret */
        /* Use a simple context for key derivation */
        uint8_t context[32];
        memcpy(context, "cyxwiz_eph_layer", 16);  /* NOLINT(bugprone-not-null-terminated-result) */
        memcpy(context + 16, circuit->ephemeral_pubs[i], 16);

        cyxwiz_error_t err = cyxwiz_crypto_derive_key(
            ephemeral_shared, CYXWIZ_KEY_SIZE,
            context, sizeof(context),
            circuit->keys[i]);

        /* Zero sensitive ephemeral data */
        cyxwiz_secure_zero(ephemeral_sk, sizeof(ephemeral_sk));
        cyxwiz_secure_zero(ephemeral_shared, sizeof(ephemeral_shared));

        if (err != CYXWIZ_OK) {
            circuit->active = false;
            return err;
        }
    }

    ctx->circuit_count++;
    CYXWIZ_INFO("Built circuit %u with %u hops (ephemeral keys)", circuit->circuit_id, hop_count);

    *circuit_out = circuit;
    return CYXWIZ_OK;
#endif
}

void cyxwiz_onion_destroy_circuit(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit)
{
    if (ctx == NULL || circuit == NULL) {
        return;
    }

    if (circuit->active) {
        cyxwiz_secure_zero(circuit->keys, sizeof(circuit->keys));
        cyxwiz_secure_zero(circuit->ephemeral_pubs, sizeof(circuit->ephemeral_pubs));
        circuit->active = false;
        ctx->circuit_count--;
        CYXWIZ_DEBUG("Destroyed circuit %u", circuit->circuit_id);
    }
}

cyxwiz_circuit_t *cyxwiz_onion_get_circuit(
    cyxwiz_onion_ctx_t *ctx,
    uint32_t circuit_id)
{
    if (ctx == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active &&
            ctx->circuits[i].circuit_id == circuit_id) {
            return &ctx->circuits[i];
        }
    }
    return NULL;
}

/* ============ Stream Multiplexing ============ */

cyxwiz_error_t cyxwiz_circuit_open_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t *stream_id_out)
{
    if (circuit == NULL || stream_id_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!circuit->active) {
        return CYXWIZ_ERR_INVALID;
    }

    if (circuit->stream_count >= CYXWIZ_MAX_STREAMS_PER_CIRCUIT) {
        CYXWIZ_ERROR("Max streams per circuit reached");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Find free slot */
    for (size_t i = 0; i < CYXWIZ_MAX_STREAMS_PER_CIRCUIT; i++) {
        if (circuit->streams[i].state == CYXWIZ_STREAM_STATE_CLOSED) {
            /* Allocate new stream ID (avoid 0 which is default/legacy) */
            circuit->next_stream_id++;
            if (circuit->next_stream_id == 0) {
                circuit->next_stream_id = 1;  /* Wrap around, skip 0 */
            }

            circuit->streams[i].stream_id = circuit->next_stream_id;
            circuit->streams[i].state = CYXWIZ_STREAM_STATE_OPEN;
            circuit->streams[i].opened_at = cyxwiz_time_ms();
            circuit->streams[i].last_activity_ms = circuit->streams[i].opened_at;
            circuit->stream_count++;

            *stream_id_out = circuit->streams[i].stream_id;
            CYXWIZ_DEBUG("Opened stream %u on circuit %u", circuit->streams[i].stream_id, circuit->circuit_id);
            return CYXWIZ_OK;
        }
    }

    return CYXWIZ_ERR_QUEUE_FULL;
}

void cyxwiz_circuit_close_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id)
{
    if (circuit == NULL) {
        return;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_STREAMS_PER_CIRCUIT; i++) {
        if (circuit->streams[i].stream_id == stream_id &&
            circuit->streams[i].state != CYXWIZ_STREAM_STATE_CLOSED) {
            circuit->streams[i].state = CYXWIZ_STREAM_STATE_CLOSED;
            circuit->stream_count--;
            CYXWIZ_DEBUG("Closed stream %u on circuit %u", stream_id, circuit->circuit_id);
            return;
        }
    }
}

cyxwiz_stream_t *cyxwiz_circuit_get_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id)
{
    if (circuit == NULL) {
        return NULL;
    }

    /* Stream ID 0 is the default/legacy stream - return NULL (use legacy callback) */
    if (stream_id == CYXWIZ_STREAM_ID_DEFAULT) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_STREAMS_PER_CIRCUIT; i++) {
        if (circuit->streams[i].stream_id == stream_id &&
            circuit->streams[i].state != CYXWIZ_STREAM_STATE_CLOSED) {
            return &circuit->streams[i];
        }
    }
    return NULL;
}

/* ============ Payload Size ============ */

size_t cyxwiz_onion_max_payload(uint8_t hop_count)
{
    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        return 0;
    }

    /*
     * With ephemeral keys, the packet structure is:
     * Header: type(1) + circuit_id(4) + ephemeral(32) = 37 bytes
     * Then encrypted layers, each containing:
     *   - next_hop (32)
     *   - next_ephemeral (32) for non-final layers
     *   - AEAD overhead (40)
     *   - inner data
     * Final layer: zero_hop (32) + payload
     */
    size_t size = CYXWIZ_ONION_MAX_ENCRYPTED;

    /*
     * Each intermediate layer adds: AEAD overhead (40) + next_hop (32) + next_ephemeral (32)
     * Final layer adds: AEAD overhead (40) + zero_hop (32)
     */
    for (uint8_t i = 0; i < hop_count; i++) {
        size_t layer_overhead = CYXWIZ_ONION_OVERHEAD + CYXWIZ_NODE_ID_LEN;

        /* Non-final layers also include next_ephemeral */
        if (i < hop_count - 1) {
            layer_overhead += CYXWIZ_EPHEMERAL_SIZE;
        }

        if (size <= layer_overhead) {
            return 0;
        }
        size -= layer_overhead;
    }

    return size;
}

/* ============ Low-Level Operations ============ */

cyxwiz_error_t cyxwiz_onion_wrap(
    const uint8_t *payload,
    size_t payload_len,
    const cyxwiz_node_id_t *hops,
    const uint8_t (*keys)[CYXWIZ_KEY_SIZE],
    const uint8_t (*ephemeral_pubs)[CYXWIZ_EPHEMERAL_SIZE],
    uint8_t hop_count,
    uint8_t *onion_out,
    size_t *onion_len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(payload);
    CYXWIZ_UNUSED(payload_len);
    CYXWIZ_UNUSED(hops);
    CYXWIZ_UNUSED(keys);
    CYXWIZ_UNUSED(ephemeral_pubs);
    CYXWIZ_UNUSED(hop_count);
    CYXWIZ_UNUSED(onion_out);
    CYXWIZ_UNUSED(onion_len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (payload == NULL || hops == NULL || keys == NULL ||
        ephemeral_pubs == NULL || onion_out == NULL || onion_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        return CYXWIZ_ERR_INVALID;
    }

    size_t max_payload = cyxwiz_onion_max_payload(hop_count);
    if (payload_len > max_payload) {
        CYXWIZ_ERROR("Payload too large: %zu > %zu", payload_len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Use temporary buffers for building layers */
    uint8_t buffer1[CYXWIZ_ONION_MAX_ENCRYPTED];
    uint8_t buffer2[CYXWIZ_ONION_MAX_ENCRYPTED];
    uint8_t *current = buffer1;
    uint8_t *next = buffer2;
    size_t current_len;

    /*
     * Build onion from inside out.
     * Final layer: zero_hop (32) + payload
     * Each intermediate layer decrypts to: next_hop (32) + next_ephemeral (32) + inner
     */
    cyxwiz_node_id_t zero_hop;
    memset(&zero_hop, 0, sizeof(zero_hop));

    /* Innermost layer: zeros for next_hop (final destination marker) + payload */
    memcpy(current, &zero_hop, sizeof(cyxwiz_node_id_t));
    memcpy(current + sizeof(cyxwiz_node_id_t), payload, payload_len);
    current_len = sizeof(cyxwiz_node_id_t) + payload_len;

    /* Wrap from inside out (last hop first) */
    for (int i = hop_count - 1; i >= 0; i--) {
        /* Encrypt current data with this hop's key */
        size_t encrypted_len;
        cyxwiz_error_t err = cyxwiz_crypto_encrypt(
            current, current_len,
            keys[i],
            next, &encrypted_len);

        if (err != CYXWIZ_OK) {
            return err;
        }

        /* For non-outermost layers, prepend next_hop + next_ephemeral */
        if (i > 0) {
            /* Make room for next_hop + next_ephemeral */
            size_t header_size = sizeof(cyxwiz_node_id_t) + CYXWIZ_EPHEMERAL_SIZE;
            memmove(next + header_size, next, encrypted_len);

            /* next_hop: where to forward after decryption at hop i-1 */
            memcpy(next, &hops[i], sizeof(cyxwiz_node_id_t));

            /* next_ephemeral: the ephemeral key for hop i */
            memcpy(next + sizeof(cyxwiz_node_id_t), ephemeral_pubs[i], CYXWIZ_EPHEMERAL_SIZE);

            encrypted_len += header_size;
        }

        /* Swap buffers */
        uint8_t *tmp = current;
        current = next;
        next = tmp;
        current_len = encrypted_len;
    }

    memcpy(onion_out, current, current_len);
    *onion_len = current_len;

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_onion_unwrap(
    const uint8_t *onion,
    size_t onion_len,
    const uint8_t *key,
    cyxwiz_node_id_t *next_hop_out,
    uint8_t *next_ephemeral_out,
    uint8_t *inner_out,
    size_t *inner_len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(onion);
    CYXWIZ_UNUSED(onion_len);
    CYXWIZ_UNUSED(key);
    CYXWIZ_UNUSED(next_hop_out);
    CYXWIZ_UNUSED(next_ephemeral_out);
    CYXWIZ_UNUSED(inner_out);
    CYXWIZ_UNUSED(inner_len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (onion == NULL || key == NULL || next_hop_out == NULL ||
        inner_out == NULL || inner_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (onion_len < CYXWIZ_ONION_OVERHEAD + sizeof(cyxwiz_node_id_t)) {
        CYXWIZ_ERROR("Onion too short: %zu bytes", onion_len);
        return CYXWIZ_ERR_INVALID;
    }

    /* Decrypt the layer */
    uint8_t decrypted[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t decrypted_len;

    cyxwiz_error_t err = cyxwiz_crypto_decrypt(
        onion, onion_len,
        key,
        decrypted, &decrypted_len);

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to decrypt onion layer");
        return CYXWIZ_ERR_CRYPTO;
    }

    if (decrypted_len < sizeof(cyxwiz_node_id_t)) {
        CYXWIZ_ERROR("Decrypted data too short");
        return CYXWIZ_ERR_INVALID;
    }

    /* Extract next_hop */
    memcpy(next_hop_out, decrypted, sizeof(cyxwiz_node_id_t));

    /*
     * If next_hop is non-zero (relay), the next 32 bytes are the ephemeral key
     * for the next hop. If next_hop is zero (final destination), the remaining
     * data is the payload with no ephemeral key.
     */
    size_t offset = sizeof(cyxwiz_node_id_t);

    if (!cyxwiz_node_id_is_zero(next_hop_out)) {
        /* Non-final: extract next_ephemeral */
        if (decrypted_len < sizeof(cyxwiz_node_id_t) + CYXWIZ_EPHEMERAL_SIZE) {
            CYXWIZ_ERROR("Decrypted layer missing ephemeral key");
            return CYXWIZ_ERR_INVALID;
        }

        if (next_ephemeral_out != NULL) {
            memcpy(next_ephemeral_out, decrypted + offset, CYXWIZ_EPHEMERAL_SIZE);
        }
        offset += CYXWIZ_EPHEMERAL_SIZE;
    } else {
        /* Final destination: no ephemeral key */
        if (next_ephemeral_out != NULL) {
            memset(next_ephemeral_out, 0, CYXWIZ_EPHEMERAL_SIZE);
        }
    }

    /* Rest is inner data */
    size_t inner_data_len = decrypted_len - offset;
    memcpy(inner_out, decrypted + offset, inner_data_len);
    *inner_len = inner_data_len;

    return CYXWIZ_OK;
#endif
}

/* ============ Sending Messages ============ */

cyxwiz_error_t cyxwiz_onion_send_stream(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(circuit);
    CYXWIZ_UNUSED(stream_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || circuit == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!circuit->active) {
        CYXWIZ_ERROR("Circuit not active");
        return CYXWIZ_ERR_INVALID;
    }

    size_t max_payload = cyxwiz_onion_max_payload(circuit->hop_count);
    if (len > max_payload) {
        CYXWIZ_ERROR("Payload too large for circuit: %zu > %zu", len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Update stream activity if using a specific stream */
    if (stream_id != CYXWIZ_STREAM_ID_DEFAULT) {
        cyxwiz_stream_t *stream = cyxwiz_circuit_get_stream(circuit, stream_id);
        if (stream != NULL) {
            stream->last_activity_ms = cyxwiz_time_ms();
        }
    }

    /* Build onion with ephemeral keys */
    uint8_t onion[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t onion_len;

    cyxwiz_error_t err = cyxwiz_onion_wrap(
        data, len,
        circuit->hops,
        (const uint8_t (*)[CYXWIZ_KEY_SIZE])circuit->keys,
        (const uint8_t (*)[CYXWIZ_EPHEMERAL_SIZE])circuit->ephemeral_pubs,
        circuit->hop_count,
        onion, &onion_len);

    if (err != CYXWIZ_OK) {
        return err;
    }

    /*
     * Build packet: type (1) + circuit_id (4) + stream_id (2) + ephemeral_pub (32) + onion
     * The ephemeral_pub for the first hop is included in the header so the
     * first relay can derive the decryption key via ECDH.
     */
    uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
    size_t packet_len = 0;

    packet[0] = CYXWIZ_MSG_ONION_DATA;
    packet_len = 1;

    /* Circuit ID (big-endian) */
    packet[packet_len++] = (circuit->circuit_id >> 24) & 0xFF;
    packet[packet_len++] = (circuit->circuit_id >> 16) & 0xFF;
    packet[packet_len++] = (circuit->circuit_id >> 8) & 0xFF;
    packet[packet_len++] = circuit->circuit_id & 0xFF;

    /* Stream ID (big-endian) */
    packet[packet_len++] = (stream_id >> 8) & 0xFF;
    packet[packet_len++] = stream_id & 0xFF;

    /* Ephemeral public key for first hop */
    memcpy(packet + packet_len, circuit->ephemeral_pubs[0], CYXWIZ_EPHEMERAL_SIZE);
    packet_len += CYXWIZ_EPHEMERAL_SIZE;

    /* Encrypted onion data */
    memcpy(packet + packet_len, onion, onion_len);
    packet_len += onion_len;

    /* Send to first hop */
    cyxwiz_error_t send_err = cyxwiz_router_send(ctx->router, &circuit->hops[0], packet, packet_len);

    /* Track circuit health metrics */
    circuit->messages_sent++;
    if (send_err != CYXWIZ_OK) {
        circuit->messages_failed++;
    }

    return send_err;
#endif
}

cyxwiz_error_t cyxwiz_onion_send(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    const uint8_t *data,
    size_t len)
{
    /* Use default stream ID (backward compatible) */
    return cyxwiz_onion_send_stream(ctx, circuit, CYXWIZ_STREAM_ID_DEFAULT, data, len);
}

/* ============ Replay Protection ============ */

/*
 * Compute truncated blake2b hash of onion packet for replay detection
 */
static void compute_onion_hash(const uint8_t *data, size_t len, uint8_t *hash_out)
{
#ifdef CYXWIZ_HAS_CRYPTO
    crypto_generichash(hash_out, CYXWIZ_ONION_HASH_SIZE,
                       data, len, NULL, 0);
#else
    /* Simple fallback hash (not secure, but better than nothing) */
    memset(hash_out, 0, CYXWIZ_ONION_HASH_SIZE);
    for (size_t i = 0; i < len; i++) {
        hash_out[i % CYXWIZ_ONION_HASH_SIZE] ^= data[i];
    }
#endif
}

/*
 * Check if onion packet has been seen before
 */
static bool is_onion_seen(cyxwiz_onion_ctx_t *ctx, const uint8_t *data, size_t len)
{
    uint8_t hash[CYXWIZ_ONION_HASH_SIZE];
    compute_onion_hash(data, len, hash);

    for (size_t i = 0; i < ctx->seen_onion_count; i++) {
        if (memcmp(ctx->seen_onions[i].hash, hash, CYXWIZ_ONION_HASH_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Mark onion packet as seen
 */
static void mark_onion_seen(cyxwiz_onion_ctx_t *ctx, const uint8_t *data, size_t len, uint64_t now)
{
    uint8_t hash[CYXWIZ_ONION_HASH_SIZE];
    compute_onion_hash(data, len, hash);

    /* Find free slot or reuse oldest */
    size_t slot = ctx->seen_onion_count;
    if (slot >= CYXWIZ_MAX_SEEN_ONIONS) {
        /* Find oldest entry to evict */
        slot = 0;
        uint64_t oldest = ctx->seen_onions[0].seen_at;
        for (size_t i = 1; i < CYXWIZ_MAX_SEEN_ONIONS; i++) {
            if (ctx->seen_onions[i].seen_at < oldest) {
                oldest = ctx->seen_onions[i].seen_at;
                slot = i;
            }
        }
    } else {
        ctx->seen_onion_count++;
    }

    memcpy(ctx->seen_onions[slot].hash, hash, CYXWIZ_ONION_HASH_SIZE);
    ctx->seen_onions[slot].seen_at = now;
}

/*
 * Expire old seen onion entries
 */
static void expire_seen_onions(cyxwiz_onion_ctx_t *ctx, uint64_t now)
{
    size_t write_idx = 0;
    for (size_t i = 0; i < ctx->seen_onion_count; i++) {
        if (now - ctx->seen_onions[i].seen_at < CYXWIZ_ONION_SEEN_TIMEOUT_MS) {
            if (write_idx != i) {
                memcpy(&ctx->seen_onions[write_idx], &ctx->seen_onions[i],
                       sizeof(ctx->seen_onions[0]));
            }
            write_idx++;
        }
    }
    ctx->seen_onion_count = write_idx;
}

/* ============ Message Handling ============ */

cyxwiz_error_t cyxwiz_onion_handle_message(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || from == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Header: type (1) + circuit_id (4) + stream_id (2) + ephemeral_pub (32) = 39 bytes */
    if (len < CYXWIZ_ONION_HEADER_SIZE) {
        CYXWIZ_ERROR("Onion packet too short: %zu < %d", len, CYXWIZ_ONION_HEADER_SIZE);
        return CYXWIZ_ERR_INVALID;
    }

    /* Parse header */
    if (data[0] != CYXWIZ_MSG_ONION_DATA) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Rate limit check */
    uint64_t now = cyxwiz_time_ms();
    cyxwiz_peer_table_t *peer_table = cyxwiz_router_get_peer_table(ctx->router);
    if (peer_table != NULL &&
        !cyxwiz_peer_table_check_rate_limit(peer_table, from, now, data[0])) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(from, hex_id);
        CYXWIZ_WARN("Rate limit exceeded for onion message from %.16s...", hex_id);
        return CYXWIZ_ERR_RATE_LIMITED;
    }

    /* Replay protection: check if we've seen this packet before */
    if (is_onion_seen(ctx, data, len)) {
        CYXWIZ_DEBUG("Dropped replayed onion packet");
        return CYXWIZ_OK;  /* Silently drop replayed packets */
    }
    mark_onion_seen(ctx, data, len, now);

    uint32_t circuit_id = ((uint32_t)data[1] << 24) |
                          ((uint32_t)data[2] << 16) |
                          ((uint32_t)data[3] << 8) |
                          (uint32_t)data[4];

    /* Extract stream ID from header */
    uint16_t stream_id = ((uint16_t)data[5] << 8) | (uint16_t)data[6];

    /* Extract ephemeral public key from header */
    const uint8_t *ephemeral_pub = data + 7;

    const uint8_t *onion = data + CYXWIZ_ONION_HEADER_SIZE;
    size_t onion_len = len - CYXWIZ_ONION_HEADER_SIZE;

    /*
     * Derive layer key using ECDH with the ephemeral public key.
     * shared_secret = my_private_key * ephemeral_pub
     * This allows any hop to decrypt without knowing the original sender.
     */
    uint8_t ephemeral_shared[CYXWIZ_KEY_SIZE];
    if (crypto_scalarmult(ephemeral_shared, ctx->secret_key, ephemeral_pub) != 0) {
        CYXWIZ_ERROR("Failed to compute ECDH with ephemeral key");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Derive hop key from ephemeral shared secret */
    uint8_t hop_key[CYXWIZ_KEY_SIZE];
    uint8_t context[32];
    memcpy(context, "cyxwiz_eph_layer", 16);  /* NOLINT(bugprone-not-null-terminated-result) */
    memcpy(context + 16, ephemeral_pub, 16);

    cyxwiz_error_t err = cyxwiz_crypto_derive_key(
        ephemeral_shared, CYXWIZ_KEY_SIZE,
        context, sizeof(context),
        hop_key);

    cyxwiz_secure_zero(ephemeral_shared, sizeof(ephemeral_shared));

    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Unwrap one layer */
    cyxwiz_node_id_t next_hop;
    uint8_t next_ephemeral[CYXWIZ_EPHEMERAL_SIZE];
    uint8_t inner[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(onion, onion_len, hop_key,
                              &next_hop, next_ephemeral, inner, &inner_len);

    cyxwiz_secure_zero(hop_key, sizeof(hop_key));

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to unwrap onion layer");
        return err;
    }

    /* Check if this is the final destination */
    if (cyxwiz_node_id_is_zero(&next_hop)) {
        /* Check for cover traffic magic marker */
        if (inner_len >= sizeof(uint32_t)) {
            uint32_t magic = ((uint32_t)inner[0] << 24) |
                             ((uint32_t)inner[1] << 16) |
                             ((uint32_t)inner[2] << 8) |
                             (uint32_t)inner[3];
            if (magic == CYXWIZ_COVER_MAGIC) {
                /* Silently discard cover traffic */
                CYXWIZ_DEBUG("Discarded cover traffic");
                return CYXWIZ_OK;
            }

            /* Check for health probe response */
            if (magic == CYXWIZ_CIRCUIT_PROBE_MAGIC && inner_len >= 8) {
                uint32_t probe_circuit_id = ((uint32_t)inner[4] << 24) |
                                            ((uint32_t)inner[5] << 16) |
                                            ((uint32_t)inner[6] << 8) |
                                            (uint32_t)inner[7];

                /* Find the circuit and update health metrics */
                for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
                    cyxwiz_circuit_t *circuit = &ctx->circuits[i];
                    if (circuit->active && circuit->circuit_id == probe_circuit_id &&
                        circuit->health_probe_pending) {
                        /* Calculate round-trip latency */
                        uint64_t rtt = now - circuit->health_probe_sent_ms;

                        /* Update running average (exponential moving average) */
                        if (circuit->avg_latency_ms == 0) {
                            circuit->avg_latency_ms = (uint16_t)rtt;
                        } else {
                            /* avg = 0.7 * old + 0.3 * new */
                            circuit->avg_latency_ms = (uint16_t)(
                                (circuit->avg_latency_ms * 7 + rtt * 3) / 10);
                        }

                        circuit->last_success_ms = now;
                        circuit->health_probe_pending = false;
                        CYXWIZ_DEBUG("Health probe response for circuit %u: RTT=%llu ms, avg=%u ms",
                                    probe_circuit_id, (unsigned long long)rtt, circuit->avg_latency_ms);
                        break;
                    }
                }
                return CYXWIZ_OK;
            }
        }

        /* Check for hidden service messages */
        if (inner_len >= 1) {
            uint8_t msg_type = inner[0];

            /* SERVICE_INTRO: Introduction point registration */
            if (msg_type == CYXWIZ_MSG_SERVICE_INTRO && inner_len >= 65) {
                /* Parse: type(1) + service_id(32) + service_pubkey(32) */
                cyxwiz_node_id_t service_id;
                memcpy(service_id.bytes, inner + 1, CYXWIZ_NODE_ID_LEN);

                uint8_t service_pubkey[CYXWIZ_PUBKEY_SIZE];
                memcpy(service_pubkey, inner + 1 + CYXWIZ_NODE_ID_LEN, CYXWIZ_PUBKEY_SIZE);

                /* Store as peer key for future communication */
                cyxwiz_onion_add_peer_key(ctx, &service_id, service_pubkey);

                char hex_id[65];
                cyxwiz_node_id_to_hex(&service_id, hex_id);
                CYXWIZ_INFO("Registered as introduction point for service %.16s...", hex_id);

                return CYXWIZ_OK;
            }

            /* SERVICE_DATA: Data for a hosted hidden service */
            if (msg_type == CYXWIZ_MSG_SERVICE_DATA && inner_len > 1) {
                /* Find matching hosted service and deliver */
                for (size_t i = 0; i < CYXWIZ_MAX_HIDDEN_SERVICES; i++) {
                    if (ctx->services[i].active && ctx->services[i].callback != NULL) {
                        /* Deliver data (skip message type byte) */
                        ctx->services[i].callback(from, inner + 1, inner_len - 1,
                                                  ctx->services[i].user_data);
                        return CYXWIZ_OK;
                    }
                }
            }
        }

        /* Deliver to application */
        CYXWIZ_DEBUG("Onion reached destination, delivering %zu bytes (stream %u)", inner_len, stream_id);

        /* Use stream callback for non-default streams, legacy callback otherwise */
        if (stream_id != CYXWIZ_STREAM_ID_DEFAULT && ctx->stream_callback != NULL) {
            /* Note: 'from' is the immediate sender, not the original sender
             * (which is hidden by the onion routing) */
            ctx->stream_callback(from, stream_id, CYXWIZ_STREAM_EVENT_DATA,
                                 inner, inner_len, ctx->stream_user_data);
        } else if (ctx->callback != NULL) {
            /* Legacy callback for default stream or when no stream callback set */
            ctx->callback(from, inner, inner_len, ctx->user_data);
        }
    } else {
        /* Forward to next hop */
        CYXWIZ_DEBUG("Forwarding onion to next hop");

        /*
         * Build new packet with the next_ephemeral in the header
         * and the inner data as the encrypted payload.
         */
        uint8_t forward_packet[CYXWIZ_MAX_PACKET_SIZE];
        size_t forward_len = 0;

        forward_packet[0] = CYXWIZ_MSG_ONION_DATA;
        forward_len = 1;

        /* Keep same circuit ID */
        forward_packet[forward_len++] = (circuit_id >> 24) & 0xFF;
        forward_packet[forward_len++] = (circuit_id >> 16) & 0xFF;
        forward_packet[forward_len++] = (circuit_id >> 8) & 0xFF;
        forward_packet[forward_len++] = circuit_id & 0xFF;

        /* Keep same stream ID */
        forward_packet[forward_len++] = (stream_id >> 8) & 0xFF;
        forward_packet[forward_len++] = stream_id & 0xFF;

        /* Include the next_ephemeral in the forwarded packet header */
        memcpy(forward_packet + forward_len, next_ephemeral, CYXWIZ_EPHEMERAL_SIZE);
        forward_len += CYXWIZ_EPHEMERAL_SIZE;

        /* Inner encrypted data */
        memcpy(forward_packet + forward_len, inner, inner_len);
        forward_len += inner_len;

        return cyxwiz_router_send(ctx->router, &next_hop, forward_packet, forward_len);
    }

    return CYXWIZ_OK;
#endif
}

/* ============ Send To Destination ============ */

/*
 * Find circuit that routes to destination
 */
cyxwiz_circuit_t *cyxwiz_onion_find_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    if (ctx == NULL || destination == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active && ctx->circuits[i].hop_count > 0) {
            /* Last hop is the destination */
            const cyxwiz_node_id_t *last_hop =
                &ctx->circuits[i].hops[ctx->circuits[i].hop_count - 1];
            if (memcmp(last_hop, destination, sizeof(cyxwiz_node_id_t)) == 0) {
                return &ctx->circuits[i];
            }
        }
    }
    return NULL;
}

/*
 * Check if circuit exists to destination
 */
bool cyxwiz_onion_has_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    return cyxwiz_onion_find_circuit_to(ctx, destination) != NULL;
}

/*
 * Path diversity: Update active relay list from all active circuits
 */
static void update_active_relays(cyxwiz_onion_ctx_t *ctx)
{
    ctx->active_relay_count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (!ctx->circuits[i].active) {
            continue;
        }

        /* Add all hops except the destination (last hop) to active relays */
        size_t relay_hops = ctx->circuits[i].hop_count > 1 ?
                            ctx->circuits[i].hop_count - 1 : 0;

        for (size_t h = 0; h < relay_hops; h++) {
            if (ctx->active_relay_count >= CYXWIZ_MAX_CIRCUITS * CYXWIZ_MAX_ONION_HOPS) {
                break;
            }
            memcpy(&ctx->active_relays[ctx->active_relay_count],
                   &ctx->circuits[i].hops[h], sizeof(cyxwiz_node_id_t));
            ctx->active_relay_count++;
        }
    }
}

/*
 * Path diversity: Check if relay is already in use by another circuit
 */
static bool is_relay_in_use(cyxwiz_onion_ctx_t *ctx, const cyxwiz_node_id_t *relay)
{
    for (size_t i = 0; i < ctx->active_relay_count; i++) {
        if (memcmp(&ctx->active_relays[i], relay, sizeof(cyxwiz_node_id_t)) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Relay candidate with reputation weight
 */
typedef struct {
    cyxwiz_node_id_t id;
    uint16_t weight;
} relay_candidate_t;

/*
 * Select relay nodes weighted by reputation
 * Higher reputation peers are more likely to be selected
 * Excludes destination from relay selection
 */
static size_t select_random_relays(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    cyxwiz_node_id_t *relays_out,
    size_t max_relays)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(destination);
    CYXWIZ_UNUSED(relays_out);
    CYXWIZ_UNUSED(max_relays);
    return 0;
#else
    /* Get peer table for reputation lookup */
    cyxwiz_peer_table_t *peer_table = cyxwiz_router_get_peer_table(ctx->router);

    /* Path diversity: refresh active relay list */
    update_active_relays(ctx);

    /* Collect candidates with reputation weights */
    relay_candidate_t candidates[CYXWIZ_MAX_PEERS];
    size_t candidate_count = 0;
    uint32_t total_weight = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS && candidate_count < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            continue;
        }

        /* Don't use destination as relay */
        if (memcmp(&ctx->peer_keys[i].peer_id, destination,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Don't use self as relay */
        if (memcmp(&ctx->peer_keys[i].peer_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Path diversity: skip relays already in use by other circuits */
        if (is_relay_in_use(ctx, &ctx->peer_keys[i].peer_id)) {
            continue;
        }

        /* Get peer and reputation score (0-100), default 50 if not in peer table */
        uint16_t rep = 50;
        const cyxwiz_peer_t *peer = NULL;
        if (peer_table != NULL) {
            peer = cyxwiz_peer_table_find(
                peer_table, &ctx->peer_keys[i].peer_id);
            if (peer != NULL) {
                rep = cyxwiz_peer_reputation(peer);
            }
        }

        /* Skip blacklisted peers */
        if (rep < CYXWIZ_MIN_RELAY_REPUTATION) {
            continue;
        }

        /* Base weight = reputation + 10 */
        uint16_t weight = rep + 10;

        /* Bandwidth bonus: +1 per 10 kbit/s (max +20) */
        if (peer != NULL) {
            uint32_t bw_bonus = cyxwiz_peer_bandwidth(peer) / 10;
            if (bw_bonus > 20) bw_bonus = 20;
            weight += (uint16_t)bw_bonus;

            /* Connection warmth bonus: +20 if recently active */
            if (cyxwiz_peer_is_warmed(peer, cyxwiz_time_ms())) {
                weight += 20;
            }

            /* Latency bonus: +15 for low latency peers */
            if (peer->latency_ms > 0) {
                if (peer->latency_ms < 50) {
                    weight += 15;  /* Excellent: < 50ms */
                } else if (peer->latency_ms < 100) {
                    weight += 10;  /* Good: 50-100ms */
                } else if (peer->latency_ms < 200) {
                    weight += 5;   /* Acceptable: 100-200ms */
                }
                /* No bonus for > 200ms */
            }
        }

        memcpy(&candidates[candidate_count].id, &ctx->peer_keys[i].peer_id,
               sizeof(cyxwiz_node_id_t));
        candidates[candidate_count].weight = weight;
        total_weight += weight;
        candidate_count++;
    }

    if (candidate_count == 0) {
        return 0;
    }

    /* Weighted random selection without replacement */
    size_t selected = 0;
    while (selected < max_relays && candidate_count > 0) {
        /* Pick random point in total weight */
        uint32_t r;
        randombytes_buf(&r, sizeof(r));
        r = r % total_weight;

        /* Find candidate at cumulative weight r */
        uint32_t cumulative = 0;
        for (size_t j = 0; j < candidate_count; j++) {
            cumulative += candidates[j].weight;
            if (r < cumulative) {
                /* Select this candidate */
                memcpy(&relays_out[selected], &candidates[j].id,
                       sizeof(cyxwiz_node_id_t));
                selected++;

                /* Remove from candidates */
                total_weight -= candidates[j].weight;
                candidates[j] = candidates[candidate_count - 1];
                candidate_count--;
                break;
            }
        }
    }

    return selected;
#endif
}

/*
 * Calculate desired relay count based on network trust level
 * High trust (avg rep > 70): 0 relays (direct)
 * Medium trust (40-70): 1 relay
 * Low trust (< 40): 2 relays (max privacy)
 */
static size_t calculate_relay_count(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    cyxwiz_peer_table_t *peer_table = cyxwiz_router_get_peer_table(ctx->router);
    if (peer_table == NULL) {
        return 1;  /* Default: 1 relay */
    }

    /* Calculate average reputation of relay candidates */
    uint32_t total_rep = 0;
    size_t count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            continue;
        }

        /* Skip destination */
        if (memcmp(&ctx->peer_keys[i].peer_id, destination,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Skip self */
        if (memcmp(&ctx->peer_keys[i].peer_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(
            peer_table, &ctx->peer_keys[i].peer_id);
        if (peer != NULL) {
            uint8_t rep = cyxwiz_peer_reputation(peer);
            if (rep >= CYXWIZ_MIN_RELAY_REPUTATION) {
                total_rep += rep;
                count++;
            }
        }
    }

    if (count == 0) {
        return 0;  /* No relays available */
    }

    uint8_t avg_rep = (uint8_t)(total_rep / count);

    if (avg_rep > 70) {
        CYXWIZ_DEBUG("High trust network (avg rep %u), using direct connection", avg_rep);
        return 0;  /* High trust: direct connection */
    } else if (avg_rep >= 40) {
        CYXWIZ_DEBUG("Medium trust network (avg rep %u), using 1 relay", avg_rep);
        return 1;  /* Medium trust: 1 relay */
    } else {
        CYXWIZ_DEBUG("Low trust network (avg rep %u), using 2 relays", avg_rep);
        return 2;  /* Low trust: 2 relays (max privacy) */
    }
}

/*
 * Get available guard node (valid, has key, good reputation)
 */
static const cyxwiz_guard_t *get_available_guard(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    cyxwiz_peer_table_t *peer_table = cyxwiz_router_get_peer_table(ctx->router);
    uint64_t now = cyxwiz_time_ms();

    for (size_t i = 0; i < CYXWIZ_NUM_GUARDS; i++) {
        if (!ctx->guards[i].valid) {
            continue;
        }

        /* Check if guard is same as destination */
        if (memcmp(&ctx->guards[i].id, destination, sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Check if guard is expired */
        if (now - ctx->guards[i].selected_at > CYXWIZ_GUARD_ROTATION_MS) {
            ctx->guards[i].valid = false;
            continue;
        }

        /* Check if we have a key with the guard */
        if (!cyxwiz_onion_has_key(ctx, &ctx->guards[i].id)) {
            continue;
        }

        /* Check guard reputation */
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(peer_table, &ctx->guards[i].id);
        if (peer == NULL || cyxwiz_peer_reputation(peer) < CYXWIZ_GUARD_MIN_REPUTATION) {
            continue;
        }

        return &ctx->guards[i];
    }

    return NULL;
}

/*
 * Select a new guard node from available peers
 */
static void select_new_guard(cyxwiz_onion_ctx_t *ctx, size_t slot)
{
    cyxwiz_peer_table_t *peer_table = cyxwiz_router_get_peer_table(ctx->router);
    uint64_t now = cyxwiz_time_ms();

    /* Find highest reputation peer that we have a key with */
    const cyxwiz_peer_key_t *best = NULL;
    uint8_t best_rep = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            continue;
        }

        /* Skip if already a guard */
        bool is_guard = false;
        for (size_t j = 0; j < CYXWIZ_NUM_GUARDS; j++) {
            if (ctx->guards[j].valid &&
                memcmp(&ctx->guards[j].id, &ctx->peer_keys[i].peer_id, sizeof(cyxwiz_node_id_t)) == 0) {
                is_guard = true;
                break;
            }
        }
        if (is_guard) {
            continue;
        }

        const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(peer_table, &ctx->peer_keys[i].peer_id);
        if (peer == NULL) {
            continue;
        }

        uint8_t rep = cyxwiz_peer_reputation(peer);
        if (rep >= CYXWIZ_GUARD_MIN_REPUTATION && rep > best_rep) {
            best = &ctx->peer_keys[i];
            best_rep = rep;
        }
    }

    if (best != NULL) {
        memcpy(&ctx->guards[slot].id, &best->peer_id, sizeof(cyxwiz_node_id_t));
        ctx->guards[slot].selected_at = now;
        ctx->guards[slot].valid = true;

        char hex_id[65];
        cyxwiz_node_id_to_hex(&best->peer_id, hex_id);
        CYXWIZ_INFO("Selected new guard node: %.16s... (reputation %u)", hex_id, best_rep);
    }
}

/*
 * Build circuit to destination with automatic relay selection
 */
static cyxwiz_error_t build_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    cyxwiz_circuit_t **circuit_out)
{
    /* Check if we have a key with the destination */
    if (!cyxwiz_onion_has_key(ctx, destination)) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(destination, hex_id);
        CYXWIZ_WARN("No shared key with destination %.16s...", hex_id);
        return CYXWIZ_ERR_NO_KEY;
    }

    /* Calculate desired relay count based on network trust */
    size_t desired_relays = calculate_relay_count(ctx, destination);

    /* Build path: [guard/relay(s)...] + destination */
    cyxwiz_node_id_t path[CYXWIZ_MAX_ONION_HOPS];
    uint8_t hop_count = 0;

    /* Try to use a guard as first hop if we need relays */
    if (desired_relays > 0) {
        const cyxwiz_guard_t *guard = get_available_guard(ctx, destination);

        if (guard != NULL) {
            memcpy(&path[hop_count++], &guard->id, sizeof(cyxwiz_node_id_t));
            desired_relays--;
            CYXWIZ_DEBUG("Using guard node as first hop");
        } else {
            /* No guard available - try to select one for next time */
            for (size_t i = 0; i < CYXWIZ_NUM_GUARDS; i++) {
                if (!ctx->guards[i].valid) {
                    select_new_guard(ctx, i);
                    break;
                }
            }
        }
    }

    /* Select remaining relay nodes randomly */
    if (desired_relays > 0) {
        cyxwiz_node_id_t relays[CYXWIZ_MAX_ONION_HOPS - 1];
        size_t relay_count = select_random_relays(ctx, destination, relays, desired_relays);

        for (size_t i = 0; i < relay_count; i++) {
            /* Skip if already in path (guard) */
            bool skip = false;
            for (uint8_t j = 0; j < hop_count; j++) {
                if (memcmp(&path[j], &relays[i], sizeof(cyxwiz_node_id_t)) == 0) {
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                memcpy(&path[hop_count++], &relays[i], sizeof(cyxwiz_node_id_t));
            }
        }
    }

    /* Add destination as final hop */
    memcpy(&path[hop_count++], destination, sizeof(cyxwiz_node_id_t));

    CYXWIZ_DEBUG("Building %u-hop circuit to destination", hop_count);

    return cyxwiz_onion_build_circuit(ctx, path, hop_count, circuit_out);
}

/*
 * Send data to destination via onion routing
 * Automatically builds circuit if needed
 */
cyxwiz_error_t cyxwiz_onion_send_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(destination);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || destination == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find existing circuit to destination */
    cyxwiz_circuit_t *circuit = cyxwiz_onion_find_circuit_to(ctx, destination);

    /* Check if circuit needs rotation */
    if (circuit != NULL) {
        uint64_t now = cyxwiz_time_ms();
        uint64_t age = now - circuit->created_at;

        if (age > CYXWIZ_CIRCUIT_ROTATION_MS) {
            CYXWIZ_DEBUG("Rotating circuit %u (age %llu ms)",
                        circuit->circuit_id, (unsigned long long)age);
            cyxwiz_onion_destroy_circuit(ctx, circuit);
            circuit = NULL;
        }
    }

    /* Build new circuit if none exists or was rotated */
    if (circuit == NULL) {
        cyxwiz_error_t err = build_circuit_to(ctx, destination, &circuit);
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    /* Check payload size */
    size_t max_payload = cyxwiz_onion_max_payload(circuit->hop_count);
    if (len > max_payload) {
        CYXWIZ_WARN("Payload too large for %u-hop circuit: %zu > %zu",
                    circuit->hop_count, len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Send via the circuit */
    return cyxwiz_onion_send(ctx, circuit, data, len);
#endif
}

/* ============ Statistics ============ */

size_t cyxwiz_onion_circuit_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->circuit_count;
}

size_t cyxwiz_onion_peer_key_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->peer_key_count;
}

/* ============ Guard Node Management ============ */

/*
 * Convert node ID to hex string
 * Buffer must be at least 65 bytes (32*2 + 1)
 */
static void node_id_to_hex(const cyxwiz_node_id_t *id, char *hex, size_t hex_size)
{
    static const char hex_chars[] = "0123456789abcdef";
    if (hex_size < CYXWIZ_NODE_ID_LEN * 2 + 1) {
        if (hex_size > 0) hex[0] = '\0';
        return;
    }
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        hex[i * 2]     = hex_chars[(id->bytes[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[id->bytes[i] & 0xF];
    }
    hex[CYXWIZ_NODE_ID_LEN * 2] = '\0';
}

/*
 * Convert hex string to node ID
 */
static int hex_to_node_id(const char *hex, cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        id->bytes[i] = (uint8_t)byte;
    }
    return 0;
}

cyxwiz_error_t cyxwiz_onion_save_guards(
    const cyxwiz_onion_ctx_t *ctx,
    const char *path)
{
    if (ctx == NULL || path == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        CYXWIZ_WARN("Failed to open %s for writing guards", path);
        return CYXWIZ_ERR_TRANSPORT;
    }

    fprintf(f, "# CyxWiz Guard Nodes\n");
    fprintf(f, "# Format: node_id selected_at\n");

    for (size_t i = 0; i < CYXWIZ_NUM_GUARDS; i++) {
        if (ctx->guards[i].valid) {
            char hex_id[65];
            node_id_to_hex(&ctx->guards[i].id, hex_id, sizeof(hex_id));
            fprintf(f, "%s %llu\n", hex_id, (unsigned long long)ctx->guards[i].selected_at);
        }
    }

    fclose(f);
    CYXWIZ_DEBUG("Saved %zu guards to %s", CYXWIZ_NUM_GUARDS, path);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_onion_load_guards(
    cyxwiz_onion_ctx_t *ctx,
    const char *path)
{
    if (ctx == NULL || path == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        /* File doesn't exist - that's OK for first run */
        return CYXWIZ_OK;
    }

    char line[256];
    size_t loaded = 0;

    while (fgets(line, sizeof(line), f) != NULL && loaded < CYXWIZ_NUM_GUARDS) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        char hex_id[65];
        unsigned long long selected_at;

        if (sscanf(line, "%64s %llu", hex_id, &selected_at) != 2) {
            continue;
        }

        cyxwiz_node_id_t id;
        if (hex_to_node_id(hex_id, &id) != 0) {
            continue;
        }

        ctx->guards[loaded].id = id;
        ctx->guards[loaded].selected_at = (uint64_t)selected_at;
        ctx->guards[loaded].valid = true;
        loaded++;
    }

    fclose(f);
    CYXWIZ_INFO("Loaded %zu guards from %s", loaded, path);
    return CYXWIZ_OK;
}

/* ============ Key Pinning ============ */

/*
 * Convert bytes to hex string
 * Buffer must be at least len*2 + 1 bytes
 */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex, size_t hex_size)
{
    static const char hex_chars[] = "0123456789abcdef";
    if (hex_size < len * 2 + 1) {
        if (hex_size > 0) hex[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len * 2] = '\0';
}

/*
 * Convert hex string to bytes
 */
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

cyxwiz_error_t cyxwiz_onion_save_pinned_keys(
    const cyxwiz_onion_ctx_t *ctx,
    const char *path)
{
    if (ctx == NULL || path == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        CYXWIZ_WARN("Failed to open %s for writing pinned keys", path);
        return CYXWIZ_ERR_TRANSPORT;
    }

    fprintf(f, "# CyxWiz Pinned Keys (MITM Detection)\n");
    fprintf(f, "# Format: node_id pubkey pinned_at key_changed\n");

    size_t saved = 0;
    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (ctx->peer_keys[i].valid && ctx->peer_keys[i].key_pinned) {
            char hex_id[65];
            char hex_pubkey[65];
            node_id_to_hex(&ctx->peer_keys[i].peer_id, hex_id, sizeof(hex_id));
            bytes_to_hex(ctx->peer_keys[i].pinned_pubkey, CYXWIZ_PUBKEY_SIZE, hex_pubkey, sizeof(hex_pubkey));
            fprintf(f, "%s %s %llu %d\n",
                    hex_id, hex_pubkey,
                    (unsigned long long)ctx->peer_keys[i].pinned_at,
                    ctx->peer_keys[i].key_changed ? 1 : 0);
            saved++;
        }
    }

    fclose(f);
    CYXWIZ_DEBUG("Saved %zu pinned keys to %s", saved, path);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_onion_load_pinned_keys(
    cyxwiz_onion_ctx_t *ctx,
    const char *path)
{
    if (ctx == NULL || path == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        /* File doesn't exist - that's OK for first run */
        return CYXWIZ_OK;
    }

    char line[256];
    size_t loaded = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        char hex_id[65];
        char hex_pubkey[65];
        unsigned long long pinned_at;
        int key_changed;

        if (sscanf(line, "%64s %64s %llu %d", hex_id, hex_pubkey, &pinned_at, &key_changed) != 4) {
            continue;
        }

        cyxwiz_node_id_t id;
        if (hex_to_node_id(hex_id, &id) != 0) {
            continue;
        }

        uint8_t pubkey[CYXWIZ_PUBKEY_SIZE];
        if (hex_to_bytes(hex_pubkey, pubkey, CYXWIZ_PUBKEY_SIZE) != 0) {
            continue;
        }

        /* Find or create peer key entry */
        cyxwiz_peer_key_t *entry = find_peer_key(ctx, &id);
        if (entry == NULL) {
            /* Find free slot to store pinned key info for future use */
            for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
                if (!ctx->peer_keys[i].valid) {
                    entry = &ctx->peer_keys[i];
                    memcpy(&entry->peer_id, &id, sizeof(cyxwiz_node_id_t));
                    entry->valid = false;  /* Not valid until we get their current key */
                    break;
                }
            }
        }

        if (entry != NULL) {
            memcpy(entry->pinned_pubkey, pubkey, CYXWIZ_PUBKEY_SIZE);
            entry->key_pinned = true;
            entry->pinned_at = (uint64_t)pinned_at;
            entry->key_changed = (key_changed != 0);
            loaded++;
        }
    }

    fclose(f);
    CYXWIZ_INFO("Loaded %zu pinned keys from %s", loaded, path);
    return CYXWIZ_OK;
}

/* ============ Cover Traffic ============ */

void cyxwiz_onion_enable_cover_traffic(cyxwiz_onion_ctx_t *ctx, bool enable)
{
    if (ctx == NULL) {
        return;
    }
    ctx->cover_traffic_enabled = enable;
    if (enable) {
        ctx->last_cover_traffic_ms = cyxwiz_time_ms();
        CYXWIZ_INFO("Cover traffic enabled");
    } else {
        CYXWIZ_INFO("Cover traffic disabled");
    }
}

bool cyxwiz_onion_cover_traffic_enabled(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return ctx->cover_traffic_enabled;
}

/*
 * Send cover traffic to a random peer via onion route
 * Cover traffic is indistinguishable from real traffic:
 * - Same encryption
 * - Same packet structure
 * - Identified by magic marker at destination (silently discarded)
 */
static void send_cover_traffic(cyxwiz_onion_ctx_t *ctx)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    return;
#else
    /* Pick a random peer with valid key */
    size_t valid_peers[CYXWIZ_MAX_PEERS];
    size_t valid_count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (ctx->peer_keys[i].valid &&
            memcmp(&ctx->peer_keys[i].peer_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) != 0) {
            valid_peers[valid_count++] = i;
        }
    }

    if (valid_count == 0) {
        CYXWIZ_DEBUG("No peers available for cover traffic");
        return;
    }

    /* Select random peer */
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    size_t idx = valid_peers[r % valid_count];
    const cyxwiz_node_id_t *peer_id = &ctx->peer_keys[idx].peer_id;

    /* Build dummy payload with magic marker
     * Use small fixed size (32 bytes) to fit any hop count configuration */
    uint8_t dummy[32];
    uint32_t magic = CYXWIZ_COVER_MAGIC;
    memcpy(dummy, &magic, sizeof(magic));

    /* Fill rest with random data */
    randombytes_buf(dummy + sizeof(magic), sizeof(dummy) - sizeof(magic));

    /* Send via onion routing */
    cyxwiz_error_t err = cyxwiz_onion_send_to(ctx, peer_id, dummy, sizeof(dummy));
    if (err == CYXWIZ_OK) {
        CYXWIZ_DEBUG("Sent cover traffic");
    } else {
        CYXWIZ_DEBUG("Cover traffic send failed: %d", err);
    }
#endif
}

/*
 * Prebuild circuits to random peers for faster first-message latency
 * Called periodically from poll. Builds at most one circuit per call
 * to avoid traffic bursts.
 */
static void prebuild_circuits(cyxwiz_onion_ctx_t *ctx, uint64_t now)
{
    CYXWIZ_UNUSED(now);  /* Reserved for future use (e.g., rate limiting) */

#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    return;
#else
    /* Count active circuits */
    size_t active_count = 0;
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active) {
            active_count++;
        }
    }

    /* Check if we need more circuits */
    if (active_count >= CYXWIZ_PREBUILD_TARGET) {
        return;  /* Already at target */
    }

    /* Collect peers that don't already have circuits */
    cyxwiz_node_id_t candidates[CYXWIZ_MAX_PEERS];
    size_t candidate_count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS && candidate_count < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            continue;
        }

        /* Skip self */
        if (memcmp(&ctx->peer_keys[i].peer_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Skip if already have circuit to this destination */
        if (cyxwiz_onion_has_circuit_to(ctx, &ctx->peer_keys[i].peer_id)) {
            continue;
        }

        memcpy(&candidates[candidate_count++], &ctx->peer_keys[i].peer_id,
               sizeof(cyxwiz_node_id_t));
    }

    if (candidate_count == 0) {
        CYXWIZ_DEBUG("No candidates for circuit prebuilding");
        return;
    }

    /* Pick a random candidate */
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    size_t idx = r % candidate_count;

    /* Build circuit to this peer */
    cyxwiz_circuit_t *circuit = NULL;
    cyxwiz_error_t err = build_circuit_to(ctx, &candidates[idx], &circuit);

    if (err == CYXWIZ_OK && circuit != NULL) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(&candidates[idx], hex_id);
        CYXWIZ_DEBUG("Prebuilt circuit to %.16s... (%zu/%d active)",
                     hex_id, active_count + 1, CYXWIZ_PREBUILD_TARGET);
    } else {
        char hex_id[65];
        cyxwiz_node_id_to_hex(&candidates[idx], hex_id);
        CYXWIZ_DEBUG("Failed to prebuild circuit to %.16s...: %s",
                     hex_id, cyxwiz_strerror(err));
    }
#endif
}

/* ============ Hidden Services ============ */

cyxwiz_error_t cyxwiz_hidden_service_create(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t **service_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find free service slot */
    cyxwiz_hidden_service_t *service = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_HIDDEN_SERVICES; i++) {
        if (!ctx->services[i].active) {
            service = &ctx->services[i];
            break;
        }
    }

    if (service == NULL) {
        CYXWIZ_ERROR("Hidden service table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Generate X25519 keypair for the service */
    crypto_box_keypair(service->public_key, service->secret_key);

    /* Derive service ID from public key (first 32 bytes of hash) */
    crypto_generichash(service->service_id.bytes, CYXWIZ_NODE_ID_LEN,
                       service->public_key, CYXWIZ_PUBKEY_SIZE,
                       NULL, 0);

    /* Initialize other fields */
    memset(service->intro_points, 0, sizeof(service->intro_points));
    service->last_publish_ms = 0;
    service->active = true;
    service->callback = NULL;
    service->user_data = NULL;

    ctx->service_count++;
    *service_out = service;

    char hex_id[65];
    cyxwiz_node_id_to_hex(&service->service_id, hex_id);
    CYXWIZ_INFO("Created hidden service: %.16s...", hex_id);

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_hidden_service_publish(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t *service)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service == NULL || !service->active) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Select introduction points from available peers */
    size_t intro_count = 0;
    for (size_t i = 0; i < ctx->peer_key_count && intro_count < CYXWIZ_SERVICE_INTRO_POINTS; i++) {
        if (ctx->peer_keys[i].valid) {
            /* Check this peer isn't the local node */
            if (cyxwiz_node_id_cmp(&ctx->peer_keys[i].peer_id, &ctx->local_id) == 0) {
                continue;
            }

            /* Use this peer as introduction point */
            memcpy(&service->intro_points[intro_count],
                   &ctx->peer_keys[i].peer_id,
                   sizeof(cyxwiz_node_id_t));
            intro_count++;
        }
    }

    if (intro_count == 0) {
        CYXWIZ_ERROR("No peers available for introduction points");
        return CYXWIZ_ERR_NO_ROUTE;
    }

    /* Build service descriptor */
    uint8_t descriptor[128];
    size_t desc_len = 0;

    descriptor[desc_len++] = CYXWIZ_MSG_SERVICE_INTRO;

    /* Service ID (32 bytes) */
    memcpy(descriptor + desc_len, service->service_id.bytes, CYXWIZ_NODE_ID_LEN);
    desc_len += CYXWIZ_NODE_ID_LEN;

    /* Service public key (32 bytes) */
    memcpy(descriptor + desc_len, service->public_key, CYXWIZ_PUBKEY_SIZE);
    desc_len += CYXWIZ_PUBKEY_SIZE;

    /* Publish to each introduction point */
    size_t published = 0;
    for (size_t i = 0; i < intro_count; i++) {
        cyxwiz_error_t err = cyxwiz_onion_send_to(ctx, &service->intro_points[i],
                                                  descriptor, desc_len);
        if (err == CYXWIZ_OK) {
            char hex_id[65];
            cyxwiz_node_id_to_hex(&service->intro_points[i], hex_id);
            CYXWIZ_DEBUG("Published service descriptor to intro point %.16s...", hex_id);
            published++;
        } else {
            CYXWIZ_WARN("Failed to publish to intro point: %s", cyxwiz_strerror(err));
        }
    }

    if (published == 0) {
        return CYXWIZ_ERR_NO_ROUTE;
    }

    service->last_publish_ms = cyxwiz_time_ms();

    char hex_id[65];
    cyxwiz_node_id_to_hex(&service->service_id, hex_id);
    CYXWIZ_INFO("Published hidden service %.16s... to %zu intro points",
                hex_id, published);

    return CYXWIZ_OK;
#endif
}

void cyxwiz_hidden_service_set_callback(
    cyxwiz_hidden_service_t *service,
    cyxwiz_delivery_callback_t callback,
    void *user_data)
{
    if (service == NULL) {
        return;
    }
    service->callback = callback;
    service->user_data = user_data;
}

cyxwiz_error_t cyxwiz_hidden_service_connect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *service_pubkey)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service_id);
    CYXWIZ_UNUSED(service_pubkey);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service_id == NULL || service_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if already connected */
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (ctx->service_connections[i].connected &&
            cyxwiz_node_id_cmp(&ctx->service_connections[i].service_id, service_id) == 0) {
            return CYXWIZ_OK;  /* Already connected */
        }
    }

    /* Find free connection slot */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (!ctx->service_connections[i].connected) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        CYXWIZ_ERROR("Service connection table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Store the service info */
    memcpy(&ctx->service_connections[slot].service_id, service_id, sizeof(cyxwiz_node_id_t));
    memcpy(ctx->service_connections[slot].service_pubkey, service_pubkey, CYXWIZ_PUBKEY_SIZE);
    ctx->service_connections[slot].connected = true;
    ctx->connection_count++;

    /* Send connection request via onion routing
     * The service_id is used as the "destination" - in practice, this would
     * go through an introduction point, but we simplify here by treating
     * the service ID as if we have a route to it.
     *
     * For a full implementation, we would:
     * 1. Query DHT/introduction points for the service descriptor
     * 2. Connect via the introduction point
     * 3. Do a rendezvous handshake
     *
     * For now, we simulate the connection by adding the service pubkey
     * as a peer key, allowing future sends to be encrypted correctly.
     */
    cyxwiz_onion_add_peer_key(ctx, service_id, service_pubkey);

    char hex_id[65];
    cyxwiz_node_id_to_hex(service_id, hex_id);
    CYXWIZ_INFO("Connected to hidden service %.16s...", hex_id);

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_hidden_service_send(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service_id == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find connection */
    int slot = -1;
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (ctx->service_connections[i].connected &&
            cyxwiz_node_id_cmp(&ctx->service_connections[i].service_id, service_id) == 0) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(service_id, hex_id);
        CYXWIZ_ERROR("Not connected to service %.16s...", hex_id);
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    /* Build service data message */
    uint8_t msg[CYXWIZ_ONION_PAYLOAD_2HOP];
    size_t msg_len = 0;

    if (len > CYXWIZ_ONION_PAYLOAD_2HOP - 1) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    msg[msg_len++] = CYXWIZ_MSG_SERVICE_DATA;
    memcpy(msg + msg_len, data, len);
    msg_len += len;

    /* Send via onion routing */
    return cyxwiz_onion_send_to(ctx, service_id, msg, msg_len);
#endif
}

void cyxwiz_hidden_service_destroy(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t *service)
{
    if (ctx == NULL || service == NULL) {
        return;
    }

    /* Securely zero the secret key */
    cyxwiz_secure_zero(service->secret_key, sizeof(service->secret_key));
    cyxwiz_secure_zero(service->public_key, sizeof(service->public_key));

    service->active = false;
    service->callback = NULL;
    service->user_data = NULL;

    if (ctx->service_count > 0) {
        ctx->service_count--;
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(&service->service_id, hex_id);
    CYXWIZ_INFO("Destroyed hidden service %.16s...", hex_id);

    memset(&service->service_id, 0, sizeof(service->service_id));
}

size_t cyxwiz_hidden_service_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->service_count;
}

/* ============ Rendezvous Point Implementation ============ */

/*
 * Find rendezvous point by cookie
 */
static cyxwiz_rendezvous_t *find_rendezvous_by_cookie(
    cyxwiz_onion_ctx_t *ctx,
    const uint8_t *cookie)
{
    if (ctx == NULL || cookie == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_RENDEZVOUS; i++) {
        if (ctx->rendezvous_points[i].client_ready || ctx->rendezvous_points[i].service_ready) {
            if (memcmp(ctx->rendezvous_points[i].cookie, cookie,
                      CYXWIZ_RENDEZVOUS_COOKIE_SIZE) == 0) {
                return &ctx->rendezvous_points[i];
            }
        }
    }
    return NULL;
}

/*
 * Handle RENDEZVOUS1: Client establishes at RP
 * Format: cookie(20)
 */
static void handle_rendezvous1(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    uint32_t circuit_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(circuit_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
#else
    if (len < CYXWIZ_RENDEZVOUS_COOKIE_SIZE) {
        CYXWIZ_WARN("RENDEZVOUS1 too short");
        return;
    }

    const uint8_t *cookie = data;

    /* Check if this cookie already exists */
    cyxwiz_rendezvous_t *existing = find_rendezvous_by_cookie(ctx, cookie);
    if (existing != NULL) {
        CYXWIZ_WARN("RENDEZVOUS1: Cookie already in use");
        return;
    }

    /* Find free slot */
    cyxwiz_rendezvous_t *rp = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_RENDEZVOUS; i++) {
        if (!ctx->rendezvous_points[i].client_ready && !ctx->rendezvous_points[i].service_ready) {
            rp = &ctx->rendezvous_points[i];
            break;
        }
    }

    if (rp == NULL) {
        CYXWIZ_WARN("RENDEZVOUS1: No free slots");
        return;
    }

    /* Set up client side of rendezvous */
    memcpy(rp->cookie, cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);
    rp->client_circuit_id = circuit_id;
    memcpy(&rp->client_id, from, sizeof(cyxwiz_node_id_t));
    rp->established_at = cyxwiz_time_ms();
    rp->client_ready = true;
    rp->service_ready = false;
    rp->bridged = false;
    ctx->rendezvous_count++;

    CYXWIZ_DEBUG("RENDEZVOUS1: Client waiting at RP");
#endif
}

/*
 * Handle RENDEZVOUS2: Service joins at RP
 * Format: cookie(20)
 */
static void handle_rendezvous2(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    uint32_t circuit_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(circuit_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
#else
    if (len < CYXWIZ_RENDEZVOUS_COOKIE_SIZE) {
        CYXWIZ_WARN("RENDEZVOUS2 too short");
        return;
    }

    const uint8_t *cookie = data;

    /* Find matching rendezvous point */
    cyxwiz_rendezvous_t *rp = find_rendezvous_by_cookie(ctx, cookie);
    if (rp == NULL) {
        CYXWIZ_WARN("RENDEZVOUS2: No matching cookie");
        return;
    }

    if (!rp->client_ready) {
        CYXWIZ_WARN("RENDEZVOUS2: Client not ready");
        return;
    }

    if (rp->service_ready) {
        CYXWIZ_WARN("RENDEZVOUS2: Service already connected");
        return;
    }

    /* Set up service side of rendezvous */
    rp->service_circuit_id = circuit_id;
    memcpy(&rp->service_id, from, sizeof(cyxwiz_node_id_t));
    rp->service_ready = true;
    rp->bridged = true;

    CYXWIZ_INFO("RENDEZVOUS: Bridge established!");

    /* Send acknowledgment to both sides (SERVICE_CONNECTED) */
    uint8_t ack[1];
    ack[0] = CYXWIZ_MSG_SERVICE_CONNECTED;

    /* Notify client */
    cyxwiz_router_send(ctx->router, &rp->client_id, ack, sizeof(ack));

    /* Notify service */
    cyxwiz_router_send(ctx->router, &rp->service_id, ack, sizeof(ack));
#endif
}

/*
 * Handle RENDEZVOUS_DATA: Forward data through the bridge
 * Format: cookie(20) + payload
 */
static void handle_rendezvous_data(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    uint32_t circuit_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(circuit_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
#else
    CYXWIZ_UNUSED(circuit_id);  /* Currently unused - reserved for future */

    if (len < CYXWIZ_RENDEZVOUS_COOKIE_SIZE + 1) {
        return;
    }

    const uint8_t *cookie = data;
    const uint8_t *payload = data + CYXWIZ_RENDEZVOUS_COOKIE_SIZE;
    size_t payload_len = len - CYXWIZ_RENDEZVOUS_COOKIE_SIZE;

    /* Find matching rendezvous point */
    cyxwiz_rendezvous_t *rp = find_rendezvous_by_cookie(ctx, cookie);
    if (rp == NULL || !rp->bridged) {
        return;
    }

    /* Forward to the other side */
    uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
    packet[0] = CYXWIZ_MSG_SERVICE_DATA;
    memcpy(packet + 1, payload, payload_len);

    if (memcmp(from, &rp->client_id, sizeof(cyxwiz_node_id_t)) == 0) {
        /* From client, forward to service */
        cyxwiz_router_send(ctx->router, &rp->service_id, packet, payload_len + 1);
    } else if (memcmp(from, &rp->service_id, sizeof(cyxwiz_node_id_t)) == 0) {
        /* From service, forward to client */
        cyxwiz_router_send(ctx->router, &rp->client_id, packet, payload_len + 1);
    }
#endif
}

/*
 * Handle INTRODUCE1: Introduction request from client to service
 * Format: service_id(32) + rp_id(32) + cookie(20) + client_ephemeral_pub(32)
 * This is forwarded by the introduction point to the service.
 */
static void handle_introduce1(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
#else
    /* Expected: service_id(32) + rp_id(32) + cookie(20) + client_eph_pub(32) = 116 */
    if (len < 32 + 32 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE + 32) {
        CYXWIZ_WARN("INTRODUCE1 too short");
        return;
    }

    cyxwiz_node_id_t service_id;
    memcpy(service_id.bytes, data, CYXWIZ_NODE_ID_LEN);

    /* Check if we are hosting this service */
    for (size_t i = 0; i < CYXWIZ_MAX_HIDDEN_SERVICES; i++) {
        if (ctx->services[i].active &&
            memcmp(&ctx->services[i].service_id, &service_id, sizeof(cyxwiz_node_id_t)) == 0) {
            /* We are the service - extract connection info */
            cyxwiz_node_id_t rp_id;
            memcpy(rp_id.bytes, data + 32, CYXWIZ_NODE_ID_LEN);

            uint8_t cookie[CYXWIZ_RENDEZVOUS_COOKIE_SIZE];
            memcpy(cookie, data + 64, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);

            uint8_t client_eph_pub[CYXWIZ_PUBKEY_SIZE];
            memcpy(client_eph_pub, data + 64 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE, CYXWIZ_PUBKEY_SIZE);

            CYXWIZ_INFO("INTRODUCE1: Received introduction request");

            /* Build circuit to RP and send RENDEZVOUS2 */
            /* For now, send directly (simplified) - real impl would build circuit first */
            uint8_t response[1 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE];
            response[0] = CYXWIZ_MSG_RENDEZVOUS2;
            memcpy(response + 1, cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);

            cyxwiz_router_send(ctx->router, &rp_id, response, sizeof(response));

            /* Send acknowledgment back through intro point */
            uint8_t ack[1];
            ack[0] = CYXWIZ_MSG_INTRODUCE_ACK;
            cyxwiz_router_send(ctx->router, from, ack, sizeof(ack));

            return;
        }
    }

    /* Not our service - we might be the introduction point, forward to service */
    /* Look up service_id in our peer keys to find the service */
    cyxwiz_peer_key_t *peer_key = find_peer_key(ctx, &service_id);
    if (peer_key != NULL) {
        /* Forward the INTRODUCE1 to the service */
        uint8_t forward[1 + 116];
        forward[0] = CYXWIZ_MSG_INTRODUCE1;
        memcpy(forward + 1, data, len > 116 ? 116 : len);
        cyxwiz_router_send(ctx->router, &service_id, forward, 1 + (len > 116 ? 116 : len));
        CYXWIZ_DEBUG("INTRODUCE1: Forwarded to service");
    }
#endif
}

/*
 * Handle INTRODUCE_ACK: Service acknowledged introduction
 */
static void handle_introduce_ack(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    CYXWIZ_UNUSED(from);

    if (ctx == NULL) {
        return;
    }

    CYXWIZ_DEBUG("INTRODUCE_ACK: Introduction acknowledged");
    /* Client can now expect RENDEZVOUS2 at the RP */
}

/*
 * Expire old rendezvous points
 */
static void expire_rendezvous_points(cyxwiz_onion_ctx_t *ctx, uint64_t now)
{
    for (size_t i = 0; i < CYXWIZ_MAX_RENDEZVOUS; i++) {
        cyxwiz_rendezvous_t *rp = &ctx->rendezvous_points[i];
        if (rp->client_ready || rp->service_ready) {
            if (now - rp->established_at > CYXWIZ_RENDEZVOUS_TIMEOUT_MS) {
                CYXWIZ_DEBUG("Rendezvous point expired");
                memset(rp, 0, sizeof(*rp));
                ctx->rendezvous_count--;
            }
        }
    }
}

/* ============ Rendezvous API ============ */

cyxwiz_error_t cyxwiz_rendezvous_connect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *service_pubkey,
    const cyxwiz_node_id_t *intro_point)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service_id);
    CYXWIZ_UNUSED(service_pubkey);
    CYXWIZ_UNUSED(intro_point);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service_id == NULL || service_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if already connected */
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (ctx->service_connections[i].connected &&
            memcmp(&ctx->service_connections[i].service_id, service_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            return CYXWIZ_OK;  /* Already connected */
        }
    }

    /* Find free connection slot */
    cyxwiz_service_conn_t *conn = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (!ctx->service_connections[i].connected &&
            ctx->service_connections[i].started_at == 0) {
            conn = &ctx->service_connections[i];
            break;
        }
    }

    if (conn == NULL) {
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize connection state */
    memset(conn, 0, sizeof(*conn));
    memcpy(&conn->service_id, service_id, sizeof(cyxwiz_node_id_t));
    memcpy(conn->service_pubkey, service_pubkey, CYXWIZ_PUBKEY_SIZE);
    conn->started_at = cyxwiz_time_ms();

    /* Generate random rendezvous cookie */
    randombytes_buf(conn->rendezvous_cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);

    /* Generate ephemeral keypair for this connection */
    crypto_box_keypair(conn->client_ephemeral_pub, conn->client_ephemeral_sk);

    /* Select a rendezvous point (any peer that's not the service or intro point) */
    cyxwiz_node_id_t rp_id;
    bool found_rp = false;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS && !found_rp; i++) {
        if (ctx->peer_keys[i].valid) {
            /* Skip service and intro point */
            if (memcmp(&ctx->peer_keys[i].peer_id, service_id, sizeof(cyxwiz_node_id_t)) == 0) {
                continue;
            }
            if (intro_point != NULL &&
                memcmp(&ctx->peer_keys[i].peer_id, intro_point, sizeof(cyxwiz_node_id_t)) == 0) {
                continue;
            }
            memcpy(&rp_id, &ctx->peer_keys[i].peer_id, sizeof(cyxwiz_node_id_t));
            memcpy(&conn->rendezvous_point, &rp_id, sizeof(cyxwiz_node_id_t));
            found_rp = true;
        }
    }

    if (!found_rp) {
        CYXWIZ_ERROR("No suitable rendezvous point found");
        memset(conn, 0, sizeof(*conn));
        return CYXWIZ_ERR_INSUFFICIENT_RELAYS;
    }

    /* Step 1: Send RENDEZVOUS1 to RP */
    uint8_t rend1[1 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE];
    rend1[0] = CYXWIZ_MSG_RENDEZVOUS1;
    memcpy(rend1 + 1, conn->rendezvous_cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);

    cyxwiz_error_t err = cyxwiz_router_send(ctx->router, &rp_id, rend1, sizeof(rend1));
    if (err != CYXWIZ_OK) {
        memset(conn, 0, sizeof(*conn));
        return err;
    }
    conn->rp_ready = true;

    /* Step 2: Send INTRODUCE1 to service via intro point */
    /* Format: service_id(32) + rp_id(32) + cookie(20) + client_eph_pub(32) */
    uint8_t intro1[1 + 32 + 32 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE + 32];
    intro1[0] = CYXWIZ_MSG_INTRODUCE1;
    memcpy(intro1 + 1, service_id->bytes, 32);
    memcpy(intro1 + 33, rp_id.bytes, 32);
    memcpy(intro1 + 65, conn->rendezvous_cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);
    memcpy(intro1 + 85, conn->client_ephemeral_pub, 32);

    /* Send to intro point (or service directly if no intro point specified) */
    const cyxwiz_node_id_t *target = intro_point != NULL ? intro_point : service_id;
    err = cyxwiz_router_send(ctx->router, target, intro1, sizeof(intro1));
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to send INTRODUCE1");
        /* Don't clean up - we might still receive RENDEZVOUS2 */
    }

    ctx->connection_count++;
    CYXWIZ_INFO("Rendezvous connection initiated");

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_rendezvous_send(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(service_id);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || service_id == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find connection */
    cyxwiz_service_conn_t *conn = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (ctx->service_connections[i].rp_ready &&
            memcmp(&ctx->service_connections[i].service_id, service_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            conn = &ctx->service_connections[i];
            break;
        }
    }

    if (conn == NULL) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    /* Build RENDEZVOUS_DATA packet */
    if (len + CYXWIZ_RENDEZVOUS_COOKIE_SIZE + 1 > CYXWIZ_MAX_PACKET_SIZE) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
    packet[0] = CYXWIZ_MSG_RENDEZVOUS_DATA;
    memcpy(packet + 1, conn->rendezvous_cookie, CYXWIZ_RENDEZVOUS_COOKIE_SIZE);
    memcpy(packet + 1 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE, data, len);

    return cyxwiz_router_send(ctx->router, &conn->rendezvous_point,
                              packet, 1 + CYXWIZ_RENDEZVOUS_COOKIE_SIZE + len);
#endif
}

bool cyxwiz_rendezvous_is_connected(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id)
{
    if (ctx == NULL || service_id == NULL) {
        return false;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (ctx->service_connections[i].connected &&
            memcmp(&ctx->service_connections[i].service_id, service_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            return true;
        }
    }
    return false;
}

void cyxwiz_rendezvous_disconnect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id)
{
    if (ctx == NULL || service_id == NULL) {
        return;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
        if (memcmp(&ctx->service_connections[i].service_id, service_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            /* Clear sensitive data */
            cyxwiz_secure_zero(ctx->service_connections[i].client_ephemeral_sk,
                              sizeof(ctx->service_connections[i].client_ephemeral_sk));
            cyxwiz_secure_zero(ctx->service_connections[i].shared_secret,
                              sizeof(ctx->service_connections[i].shared_secret));
            memset(&ctx->service_connections[i], 0, sizeof(ctx->service_connections[i]));
            ctx->connection_count--;
            return;
        }
    }
}

size_t cyxwiz_rendezvous_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->rendezvous_count;
}

cyxwiz_error_t cyxwiz_onion_handle_direct_message(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (ctx == NULL || from == NULL || data == NULL || len < 1) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = len - 1;

    switch (msg_type) {
        case CYXWIZ_MSG_INTRODUCE1:
            handle_introduce1(ctx, from, payload, payload_len);
            return CYXWIZ_OK;

        case CYXWIZ_MSG_INTRODUCE_ACK:
            handle_introduce_ack(ctx, from, payload, payload_len);
            return CYXWIZ_OK;

        case CYXWIZ_MSG_RENDEZVOUS1:
            handle_rendezvous1(ctx, from, 0, payload, payload_len);
            return CYXWIZ_OK;

        case CYXWIZ_MSG_RENDEZVOUS2:
            handle_rendezvous2(ctx, from, 0, payload, payload_len);
            return CYXWIZ_OK;

        case CYXWIZ_MSG_RENDEZVOUS_DATA:
            handle_rendezvous_data(ctx, from, 0, payload, payload_len);
            return CYXWIZ_OK;

        case CYXWIZ_MSG_SERVICE_CONNECTED:
            /* Update client connection state */
            for (size_t i = 0; i < CYXWIZ_MAX_SERVICE_CONNECTIONS; i++) {
                if (ctx->service_connections[i].rp_ready &&
                    !ctx->service_connections[i].connected) {
                    ctx->service_connections[i].connected = true;
                    CYXWIZ_INFO("Rendezvous connection established!");
                    break;
                }
            }
            return CYXWIZ_OK;

        default:
            return CYXWIZ_ERR_INVALID;
    }
}
