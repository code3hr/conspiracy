/*
 * CyxWiz Protocol - Peer Table Management
 *
 * Maintains a table of known peers with their state and metadata.
 */

#include "cyxwiz/peer.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdio.h>

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
    extern void cyxwiz_crypto_random(uint8_t *buf, size_t len);
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
    memcpy(&peer->id, id, sizeof(cyxwiz_node_id_t));
    peer->state = CYXWIZ_PEER_STATE_DISCOVERED;
    peer->transport = transport;
    peer->capabilities = 0;
    peer->rssi = rssi;
    peer->last_seen = now;
    peer->discovered_at = now;
    peer->latency_ms = 0;
    peer->bytes_sent = 0;
    peer->bytes_recv = 0;

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
