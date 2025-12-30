/*
 * CyxWiz Protocol - Peer Table Management
 *
 * Maintains a table of known peers with their state and metadata.
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/peer.h"
#include "cyxwiz/zkp.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef CYXWIZ_HAS_CRYPTO
extern void cyxwiz_crypto_random(uint8_t *buf, size_t len);
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

/*
 * Peer table structure
 */
struct cyxwiz_peer_table {
    cyxwiz_peer_t peers[CYXWIZ_MAX_PEERS];
    size_t count;
    cyxwiz_peer_event_cb_t on_change;
    void *user_data;
};

/* ============ Utility Functions ============ */

uint64_t cyxwiz_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

const char *cyxwiz_peer_state_name(cyxwiz_peer_state_t state)
{
    switch (state) {
        case CYXWIZ_PEER_STATE_UNKNOWN:      return "unknown";
        case CYXWIZ_PEER_STATE_DISCOVERED:   return "discovered";
        case CYXWIZ_PEER_STATE_CONNECTING:   return "connecting";
        case CYXWIZ_PEER_STATE_CONNECTED:    return "connected";
        case CYXWIZ_PEER_STATE_DISCONNECTING:return "disconnecting";
        case CYXWIZ_PEER_STATE_FAILED:       return "failed";
        default:                             return "invalid";
    }
}

void cyxwiz_node_id_to_hex(const cyxwiz_node_id_t *id, char *buf)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        buf[i * 2]     = hex[(id->bytes[i] >> 4) & 0xF];
        buf[i * 2 + 1] = hex[id->bytes[i] & 0xF];
    }
    buf[CYXWIZ_NODE_ID_LEN * 2] = '\0';
}

int cyxwiz_node_id_cmp(const cyxwiz_node_id_t *a, const cyxwiz_node_id_t *b)
{
    return memcmp(a->bytes, b->bytes, CYXWIZ_NODE_ID_LEN);
}

void cyxwiz_node_id_random(cyxwiz_node_id_t *id)
{
    /* Use crypto random if available, otherwise fall back */
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_crypto_random(id->bytes, CYXWIZ_NODE_ID_LEN);
#else
    /* Simple fallback - not cryptographically secure */
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        id->bytes[i] = (uint8_t)(rand() & 0xFF);
    }
#endif
}

/* ============ Peer Table ============ */

cyxwiz_error_t cyxwiz_peer_table_create(cyxwiz_peer_table_t **table)
{
    if (table == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_peer_table_t *t = cyxwiz_calloc(1, sizeof(cyxwiz_peer_table_t));
    if (t == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    t->count = 0;
    t->on_change = NULL;
    t->user_data = NULL;

    *table = t;
    CYXWIZ_DEBUG("Created peer table (max %d peers)", CYXWIZ_MAX_PEERS);
    return CYXWIZ_OK;
}

void cyxwiz_peer_table_destroy(cyxwiz_peer_table_t *table)
{
    if (table == NULL) {
        return;
    }

    cyxwiz_free(table, sizeof(cyxwiz_peer_table_t));
    CYXWIZ_DEBUG("Destroyed peer table");
}

void cyxwiz_peer_table_set_callback(
    cyxwiz_peer_table_t *table,
    cyxwiz_peer_event_cb_t callback,
    void *user_data)
{
    if (table == NULL) {
        return;
    }
    table->on_change = callback;
    table->user_data = user_data;
}

/*
 * Find peer index by ID, returns -1 if not found
 */
static int find_peer_index(const cyxwiz_peer_table_t *table, const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < table->count; i++) {
        if (cyxwiz_node_id_cmp(&table->peers[i].id, id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

cyxwiz_error_t cyxwiz_peer_table_add(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    cyxwiz_transport_type_t transport,
    int8_t rssi)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    uint64_t now = cyxwiz_time_ms();

    /* Check if peer already exists */
    int idx = find_peer_index(table, id);
    if (idx >= 0) {
        /* Update existing peer */
        table->peers[idx].last_seen = now;
        table->peers[idx].rssi = rssi;
        table->peers[idx].transport = transport;
        return CYXWIZ_OK;
    }

    /* Add new peer */
    if (table->count >= CYXWIZ_MAX_PEERS) {
        CYXWIZ_WARN("Peer table full (%d peers)", CYXWIZ_MAX_PEERS);
        return CYXWIZ_ERR_NOMEM;
    }

    cyxwiz_peer_t *peer = &table->peers[table->count];

    /* Zero all fields first to avoid uninitialized data */
    cyxwiz_secure_zero(peer, sizeof(cyxwiz_peer_t));

    /* Set specific values */
    memcpy(&peer->id, id, sizeof(cyxwiz_node_id_t));
    peer->state = CYXWIZ_PEER_STATE_DISCOVERED;
    peer->transport = transport;
    peer->rssi = rssi;
    peer->last_seen = now;
    peer->discovered_at = now;

    table->count++;

    char hex_id[65];
    cyxwiz_node_id_to_hex(id, hex_id);
    CYXWIZ_INFO("Added peer %.16s... via %s (RSSI: %d)",
               hex_id,
               cyxwiz_transport_type_name(transport),
               rssi);

    /* Notify callback */
    if (table->on_change) {
        table->on_change(table, peer, CYXWIZ_PEER_STATE_UNKNOWN, table->user_data);
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_remove(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(id, hex_id);
    CYXWIZ_INFO("Removed peer %.16s...", hex_id);

    /* Shift remaining peers down */
    for (size_t i = idx; i < table->count - 1; i++) {
        table->peers[i] = table->peers[i + 1];
    }
    table->count--;

    /* Zero the removed slot */
    cyxwiz_secure_zero(&table->peers[table->count], sizeof(cyxwiz_peer_t));

    return CYXWIZ_OK;
}

const cyxwiz_peer_t *cyxwiz_peer_table_find(
    const cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return NULL;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return NULL;
    }

    return &table->peers[idx];
}

cyxwiz_peer_t *cyxwiz_peer_table_find_mutable(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return NULL;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return NULL;
    }

    return &table->peers[idx];
}

cyxwiz_error_t cyxwiz_peer_table_set_state(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    cyxwiz_peer_state_t state)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    cyxwiz_peer_state_t old_state = table->peers[idx].state;
    table->peers[idx].state = state;
    table->peers[idx].last_seen = cyxwiz_time_ms();

    if (old_state != state) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(id, hex_id);
        CYXWIZ_DEBUG("Peer %.16s... state: %s -> %s",
                    hex_id,
                    cyxwiz_peer_state_name(old_state),
                    cyxwiz_peer_state_name(state));

        if (table->on_change) {
            table->on_change(table, &table->peers[idx], old_state, table->user_data);
        }
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_set_capabilities(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    uint8_t capabilities)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    table->peers[idx].capabilities = capabilities;
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_update_latency(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    uint16_t latency_ms)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    cyxwiz_peer_update_latency(&table->peers[idx], latency_ms);
    table->peers[idx].pongs_received++;
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_increment_pings(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    table->peers[idx].pings_sent++;
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_relay_success(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    table->peers[idx].relay_successes++;
    table->peers[idx].last_relay_activity = cyxwiz_time_ms();
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_relay_failure(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    table->peers[idx].relay_failures++;
    table->peers[idx].last_relay_activity = cyxwiz_time_ms();
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_set_identity_verified(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    const uint8_t *ed25519_pubkey)
{
    if (table == NULL || id == NULL || ed25519_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    table->peers[idx].identity_verified = true;
    memcpy(table->peers[idx].ed25519_pubkey, ed25519_pubkey, CYXWIZ_ED25519_PK_SIZE);

    char hex_id[65];
    cyxwiz_node_id_to_hex(id, hex_id);
    CYXWIZ_DEBUG("Peer %.16s... identity verified", hex_id);

    return CYXWIZ_OK;
}

size_t cyxwiz_peer_table_count(const cyxwiz_peer_table_t *table)
{
    if (table == NULL) {
        return 0;
    }
    return table->count;
}

size_t cyxwiz_peer_table_connected_count(const cyxwiz_peer_table_t *table)
{
    if (table == NULL) {
        return 0;
    }

    size_t count = 0;
    for (size_t i = 0; i < table->count; i++) {
        if (table->peers[i].state == CYXWIZ_PEER_STATE_CONNECTED) {
            count++;
        }
    }
    return count;
}

void cyxwiz_peer_table_iterate(
    const cyxwiz_peer_table_t *table,
    cyxwiz_peer_iter_cb_t callback,
    void *user_data)
{
    if (table == NULL || callback == NULL) {
        return;
    }

    for (size_t i = 0; i < table->count; i++) {
        if (callback(&table->peers[i], user_data) != 0) {
            break;
        }
    }
}

const cyxwiz_peer_t *cyxwiz_peer_table_get_peer(
    const cyxwiz_peer_table_t *table,
    size_t index)
{
    if (table == NULL || index >= CYXWIZ_MAX_PEERS || index >= table->count) {
        return NULL;
    }
    return &table->peers[index];
}

size_t cyxwiz_peer_table_cleanup(
    cyxwiz_peer_table_t *table,
    uint64_t timeout_ms)
{
    if (table == NULL) {
        return 0;
    }

    uint64_t now = cyxwiz_time_ms();
    size_t removed = 0;

    /* Iterate backwards to safely remove */
    for (int i = (int)table->count - 1; i >= 0; i--) {
        uint64_t age = now - table->peers[i].last_seen;
        if (age > timeout_ms) {
            char hex_id[65];
            cyxwiz_node_id_to_hex(&table->peers[i].id, hex_id);
            CYXWIZ_DEBUG("Peer %.16s... timed out (%llu ms)", hex_id, (unsigned long long)age);

            cyxwiz_peer_table_remove(table, &table->peers[i].id);
            removed++;
        }
    }

    if (removed > 0) {
        CYXWIZ_INFO("Cleaned up %zu stale peers", removed);
    }

    return removed;
}

/* ============ Connection Quality Metrics ============ */

uint8_t cyxwiz_peer_packet_loss(const cyxwiz_peer_t *peer)
{
    if (peer == NULL || peer->pings_sent == 0) {
        return 0;
    }

    uint32_t lost = peer->pings_sent - peer->pongs_received;
    return (uint8_t)((lost * 100) / peer->pings_sent);
}

uint8_t cyxwiz_peer_quality_score(const cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return 0;
    }

    int score = 100;

    /* Latency penalty: -30 max for high latency (300ms+) */
    if (peer->latency_ms > 0) {
        int latency_penalty = peer->latency_ms / 10;
        if (latency_penalty > 30) latency_penalty = 30;
        score -= latency_penalty;
    }

    /* Jitter penalty: -20 max for high jitter (100ms+) */
    if (peer->jitter_ms > 0) {
        int jitter_penalty = peer->jitter_ms / 5;
        if (jitter_penalty > 20) jitter_penalty = 20;
        score -= jitter_penalty;
    }

    /* Packet loss penalty: -40 max for 20%+ loss */
    uint8_t loss = cyxwiz_peer_packet_loss(peer);
    if (loss > 0) {
        int loss_penalty = loss * 2;
        if (loss_penalty > 40) loss_penalty = 40;
        score -= loss_penalty;
    }

    /* RSSI penalty: -10 max for weak signal (-80 dBm or worse) */
    if (peer->rssi < -50) {
        int rssi_penalty = (-peer->rssi - 50) / 3;
        if (rssi_penalty > 10) rssi_penalty = 10;
        score -= rssi_penalty;
    }

    if (score < 0) score = 0;
    return (uint8_t)score;
}

void cyxwiz_peer_update_latency(cyxwiz_peer_t *peer, uint16_t latency_ms)
{
    if (peer == NULL) {
        return;
    }

    /* Update current latency */
    peer->latency_ms = latency_ms;

    /* Add to ring buffer */
    peer->latency_samples[peer->latency_idx] = latency_ms;
    peer->latency_idx = (peer->latency_idx + 1) % CYXWIZ_LATENCY_SAMPLES;
    if (peer->latency_count < CYXWIZ_LATENCY_SAMPLES) {
        peer->latency_count++;
    }

    /* Calculate jitter (RFC 3550 style simplified) */
    if (peer->latency_count >= 2) {
        /* Calculate average */
        uint32_t sum = 0;
        for (uint8_t i = 0; i < peer->latency_count; i++) {
            sum += peer->latency_samples[i];
        }
        uint16_t avg = (uint16_t)(sum / peer->latency_count);

        /* Calculate mean deviation (simplified jitter) */
        uint32_t deviation_sum = 0;
        for (uint8_t i = 0; i < peer->latency_count; i++) {
            int diff = (int)peer->latency_samples[i] - (int)avg;
            deviation_sum += (uint32_t)(diff < 0 ? -diff : diff);
        }
        peer->jitter_ms = (uint16_t)(deviation_sum / peer->latency_count);
    }
}

uint8_t cyxwiz_peer_reputation(const cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return 0;
    }

    /* Start with connection quality score */
    int score = cyxwiz_peer_quality_score(peer);

    /* Blend with relay reliability if we have data */
    uint32_t total_relays = peer->relay_successes + peer->relay_failures;
    if (total_relays > 0) {
        int relay_rate = (int)((peer->relay_successes * 100) / total_relays);

        /* Apply decay based on time since last relay activity */
        if (peer->last_relay_activity > 0) {
            uint64_t now = cyxwiz_time_ms();
            uint64_t idle_time = now - peer->last_relay_activity;

            if (idle_time > CYXWIZ_REPUTATION_DECAY_START_MS) {
                /* Decay relay_rate toward 50 (neutral) */
                uint64_t decay_time = idle_time - CYXWIZ_REPUTATION_DECAY_START_MS;
                uint64_t decay_range = CYXWIZ_REPUTATION_DECAY_FULL_MS -
                                       CYXWIZ_REPUTATION_DECAY_START_MS;

                if (decay_time >= decay_range) {
                    relay_rate = 50;  /* Fully decayed to neutral */
                } else {
                    /* Linear interpolation toward 50 */
                    int diff = relay_rate - 50;
                    relay_rate = 50 + (int)((diff * (int64_t)(decay_range - decay_time)) /
                                            (int64_t)decay_range);
                }
            }
        }

        /* 50/50 blend of quality and reliability */
        score = (score + relay_rate) / 2;
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return (uint8_t)score;
}

void cyxwiz_peer_relay_success(cyxwiz_peer_t *peer)
{
    if (peer != NULL) {
        peer->relay_successes++;
    }
}

void cyxwiz_peer_relay_failure(cyxwiz_peer_t *peer)
{
    if (peer != NULL) {
        peer->relay_failures++;
    }
}

/* ============ Bandwidth Tracking ============ */

void cyxwiz_peer_record_transfer(cyxwiz_peer_t *peer, size_t bytes, bool is_send)
{
    if (peer == NULL || bytes == 0) {
        return;
    }

    uint64_t now = cyxwiz_time_ms();

    /* Reset window if expired */
    if (peer->window_start_ms == 0 ||
        now - peer->window_start_ms > CYXWIZ_BANDWIDTH_WINDOW_MS) {
        peer->bytes_sent_window = 0;
        peer->bytes_recv_window = 0;
        peer->window_start_ms = now;
    }

    if (is_send) {
        peer->bytes_sent_window += bytes;
        peer->last_send_ms = now;
    } else {
        peer->bytes_recv_window += bytes;
    }
}

void cyxwiz_peer_update_bandwidth(cyxwiz_peer_t *peer, uint64_t now)
{
    if (peer == NULL || peer->window_start_ms == 0) {
        return;
    }

    uint64_t window_duration = now - peer->window_start_ms;
    if (window_duration == 0) {
        return;
    }

    /* Calculate total bytes and convert to kbit/s */
    uint64_t total_bytes = peer->bytes_sent_window + peer->bytes_recv_window;
    /* kbit/s = (bytes * 8) / (ms) = (bytes * 8000) / (ms * 1000) */
    peer->bandwidth_kbps = (uint32_t)((total_bytes * 8) / window_duration);
}

uint32_t cyxwiz_peer_bandwidth(const cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return 0;
    }
    return peer->bandwidth_kbps;
}

bool cyxwiz_peer_is_warmed(const cyxwiz_peer_t *peer, uint64_t now)
{
    if (peer == NULL || peer->last_send_ms == 0) {
        return false;
    }
    return (now - peer->last_send_ms) < CYXWIZ_CONNECTION_WARM_MS;
}

/* ============ Rate Limiting ============ */

bool cyxwiz_peer_check_rate_limit(cyxwiz_peer_t *peer, uint64_t now)
{
    if (peer == NULL) {
        return false;
    }

    /* Reset window if expired */
    if (peer->rate_window_start == 0 ||
        now - peer->rate_window_start >= CYXWIZ_RATE_WINDOW_MS) {
        peer->msgs_this_window = 0;
        peer->rate_window_start = now;
    }

    /* Check against limit */
    return peer->msgs_this_window < CYXWIZ_RATE_LIMIT_MSGS;
}

void cyxwiz_peer_record_message(cyxwiz_peer_t *peer, uint64_t now)
{
    if (peer == NULL) {
        return;
    }

    /* Reset window if expired */
    if (peer->rate_window_start == 0 ||
        now - peer->rate_window_start >= CYXWIZ_RATE_WINDOW_MS) {
        peer->msgs_this_window = 0;
        peer->rate_window_start = now;
    }

    peer->msgs_this_window++;
}

void cyxwiz_peer_record_rate_violation(cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return;
    }

    peer->rate_violations++;

    /* Impact reputation: each violation counts as a relay failure */
    peer->relay_failures++;
    peer->last_relay_activity = cyxwiz_time_ms();

    char hex_id[65];
    cyxwiz_node_id_to_hex(&peer->id, hex_id);
    CYXWIZ_WARN("Rate limit violation from peer %.16s... (count: %u)",
                hex_id, peer->rate_violations);
}

bool cyxwiz_peer_check_rate_limit_type(cyxwiz_peer_t *peer, uint64_t now, uint8_t msg_type)
{
    if (peer == NULL) {
        return false;
    }

    /* First check overall rate limit */
    if (!cyxwiz_peer_check_rate_limit(peer, now)) {
        return false;
    }

    /* Check type-specific limits based on message type ranges from types.h */
    /* Discovery messages (0x01-0x0F) */
    if (msg_type >= 0x01 && msg_type <= 0x0F) {
        /* Count discovery messages in current window */
        /* We track overall messages, so we use a stricter threshold */
        if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_DISCOVERY) {
            return false;
        }
    }

    /* Route request messages (0x20-0x21) */
    if (msg_type == 0x20 || msg_type == 0x25) {  /* ROUTE_REQ or ANON_ROUTE_REQ */
        if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_ROUTE_REQ) {
            return false;
        }
    }

    /* Onion relay messages (0x24) */
    if (msg_type == 0x24) {  /* ONION_DATA */
        if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_ONION) {
            return false;
        }
    }

    /* Compute messages (0x30-0x3F) */
    if (msg_type >= 0x30 && msg_type <= 0x3F) {
        /* Job submission has stricter limit */
        if (msg_type == 0x30 || msg_type == 0x3B) {  /* JOB_SUBMIT or JOB_SUBMIT_ANON */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_JOB_SUBMIT) {
                return false;
            }
        } else {
            /* General compute messages */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_COMPUTE) {
                return false;
            }
        }
    }

    /* Storage messages (0x40-0x5F, includes Proof of Storage) */
    if (msg_type >= 0x40 && msg_type <= 0x5F) {
        /* Store requests have stricter limit */
        if (msg_type == 0x40 || msg_type == 0x4B) {  /* STORE_REQ or STORE_REQ_ANON */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_STORE_REQ) {
                return false;
            }
        } else {
            /* General storage messages */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_STORAGE) {
                return false;
            }
        }
    }

    /* Consensus messages (0x60-0x6F) */
    if (msg_type >= 0x60 && msg_type <= 0x6F) {
        /* Validator registration has stricter limit */
        if (msg_type == 0x60) {  /* VALIDATOR_REGISTER */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_VALIDATOR_REG) {
                return false;
            }
        } else {
            /* General consensus messages */
            if (peer->msgs_this_window >= CYXWIZ_RATE_LIMIT_CONSENSUS) {
                return false;
            }
        }
    }

    return true;
}

bool cyxwiz_peer_table_check_rate_limit(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    uint64_t now,
    uint8_t msg_type)
{
    if (id == NULL) {
        return false;
    }

    /* No peer table - skip rate limiting */
    if (table == NULL) {
        return true;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        /* Unknown peer - allow message but don't track */
        return true;
    }

    cyxwiz_peer_t *peer = &table->peers[idx];

    /* Check rate limit */
    if (!cyxwiz_peer_check_rate_limit_type(peer, now, msg_type)) {
        /* Rate limit exceeded */
        cyxwiz_peer_record_rate_violation(peer);
        return false;
    }

    /* Record this message */
    cyxwiz_peer_record_message(peer, now);
    return true;
}

/* ============ Dead Peer Detection ============ */

void cyxwiz_peer_record_failure(cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return;
    }

    peer->consecutive_failures++;

    if (peer->consecutive_failures >= CYXWIZ_PEER_MAX_FAILURES) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(&peer->id, hex_id);
        CYXWIZ_WARN("Peer %.16s... unresponsive after %u consecutive failures",
                    hex_id, peer->consecutive_failures);
    }
}

void cyxwiz_peer_record_success(cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return;
    }

    /* Reset failures on any success */
    if (peer->consecutive_failures > 0) {
        peer->consecutive_failures = 0;
    }

    /* Clear ping pending flag */
    peer->ping_pending = false;
}

bool cyxwiz_peer_is_responsive(const cyxwiz_peer_t *peer)
{
    if (peer == NULL) {
        return false;
    }
    return peer->consecutive_failures < CYXWIZ_PEER_MAX_FAILURES;
}

cyxwiz_error_t cyxwiz_peer_table_record_failure(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    cyxwiz_peer_record_failure(&table->peers[idx]);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_peer_table_record_success(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id)
{
    if (table == NULL || id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    int idx = find_peer_index(table, id);
    if (idx < 0) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    cyxwiz_peer_record_success(&table->peers[idx]);
    return CYXWIZ_OK;
}

/* ============ Reputation Persistence ============ */

cyxwiz_error_t cyxwiz_peer_table_save(const cyxwiz_peer_table_t *table, const char *path)
{
    if (table == NULL || path == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        CYXWIZ_WARN("Failed to open %s for writing", path);
        return CYXWIZ_ERR_TRANSPORT;
    }

    bool write_error = false;

    if (fprintf(f, "# CyxWiz Peer Reputation Data\n") < 0 ||
        fprintf(f, "# Format: node_id relay_successes relay_failures latency_ms pings_sent pongs_received\n") < 0) {
        write_error = true;
    }

    for (size_t i = 0; i < table->count && !write_error; i++) {
        const cyxwiz_peer_t *peer = &table->peers[i];

        /* Only save peers with reputation data */
        if (peer->relay_successes == 0 && peer->relay_failures == 0 &&
            peer->pings_sent == 0) {
            continue;
        }

        char hex_id[65];
        cyxwiz_node_id_to_hex(&peer->id, hex_id);

        if (fprintf(f, "%s %u %u %u %u %u\n",
                    hex_id,
                    peer->relay_successes,
                    peer->relay_failures,
                    peer->latency_ms,
                    peer->pings_sent,
                    peer->pongs_received) < 0) {
            write_error = true;
        }
    }

    if (fclose(f) != 0 || write_error) {
        CYXWIZ_WARN("Failed to save peer reputation to %s", path);
        return CYXWIZ_ERR_TRANSPORT;
    }

    CYXWIZ_INFO("Saved peer reputation to %s", path);
    return CYXWIZ_OK;
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len)
{
    if (hex == NULL || bytes == NULL) {
        return -1;
    }

    /* Validate input string length before reading */
    size_t hex_len = strlen(hex);
    if (hex_len < len * 2) {
        return -1;  /* Input too short */
    }

    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }
    return 0;
}

cyxwiz_error_t cyxwiz_peer_table_load(cyxwiz_peer_table_t *table, const char *path)
{
    if (table == NULL || path == NULL) {
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
        uint32_t relay_successes, relay_failures, latency_ms, pings_sent, pongs_received;

        if (sscanf(line, "%64s %u %u %u %u %u",
                   hex_id, &relay_successes, &relay_failures,
                   &latency_ms, &pings_sent, &pongs_received) != 6) {
            continue;
        }

        /* Convert hex to node ID */
        cyxwiz_node_id_t id;
        if (hex_to_bytes(hex_id, id.bytes, CYXWIZ_NODE_ID_LEN) != 0) {
            continue;
        }

        /* Find or add peer */
        int idx = -1;
        for (size_t i = 0; i < table->count; i++) {
            if (cyxwiz_node_id_cmp(&table->peers[i].id, &id) == 0) {
                idx = (int)i;
                break;
            }
        }

        if (idx >= 0) {
            /* Update existing peer with loaded reputation */
            table->peers[idx].relay_successes = relay_successes;
            table->peers[idx].relay_failures = relay_failures;
            table->peers[idx].latency_ms = (uint16_t)latency_ms;
            table->peers[idx].pings_sent = pings_sent;
            table->peers[idx].pongs_received = pongs_received;
            loaded++;
        }
        /* Don't add unknown peers - wait for discovery */
    }

    if (fclose(f) != 0) {
        CYXWIZ_WARN("Error closing %s after reading", path);
        /* Non-fatal for read - data already loaded */
    }

    if (loaded > 0) {
        CYXWIZ_INFO("Loaded reputation for %zu peers from %s", loaded, path);
    }
    return CYXWIZ_OK;
}
