/*
 * CyxWiz Protocol - Distributed Hash Table
 *
 * Kademlia-style DHT implementation for decentralized peer discovery.
 */

#include "cyxwiz/dht.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Lookup state for iterative node finding */
typedef struct {
    cyxwiz_node_id_t target;
    cyxwiz_node_id_t closest[CYXWIZ_DHT_K * 2];  /* Best nodes found so far */
    size_t closest_count;
    cyxwiz_node_id_t queried[CYXWIZ_DHT_K * 3];  /* Nodes already queried */
    size_t queried_count;
    uint32_t request_id;
    uint64_t started_at;
    cyxwiz_dht_find_cb_t callback;
    void *user_data;
    bool active;
    bool found;
} cyxwiz_dht_lookup_t;

/* Pending ping for bucket maintenance */
typedef struct {
    uint32_t request_id;
    int bucket_idx;
    size_t node_idx;
    uint64_t sent_at;
    bool active;
} cyxwiz_dht_pending_ping_t;

/*
 * DHT context
 */
struct cyxwiz_dht {
    cyxwiz_router_t *router;
    cyxwiz_node_id_t local_id;

    /* Routing table: 256 k-buckets */
    cyxwiz_dht_bucket_t buckets[CYXWIZ_DHT_BUCKET_COUNT];

    /* Active lookups */
    cyxwiz_dht_lookup_t lookups[CYXWIZ_DHT_MAX_LOOKUPS];

    /* Pending pings */
    cyxwiz_dht_pending_ping_t pending_pings[CYXWIZ_DHT_K];
    size_t pending_ping_count;

    /* Callbacks */
    cyxwiz_dht_node_cb_t node_callback;
    void *node_callback_data;

    /* State */
    uint64_t current_time;
    uint32_t next_request_id;
    bool running;

    /* Statistics */
    uint64_t messages_sent;
    uint64_t messages_received;
};

/* Forward declarations */
static void handle_ping(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                        const cyxwiz_dht_ping_t *msg);
static void handle_pong(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                        const cyxwiz_dht_pong_t *msg);
static void handle_find_node(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                             const cyxwiz_dht_find_node_t *msg);
static void handle_find_node_resp(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                                  const uint8_t *data, size_t len);
static void send_find_node(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *to,
                           const cyxwiz_node_id_t *target, uint32_t request_id);
static void send_ping(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *to, uint32_t request_id);
static void add_to_bucket(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *node_id);
static void refresh_buckets(cyxwiz_dht_t *dht);
static void check_lookup_timeouts(cyxwiz_dht_t *dht);
static void check_ping_timeouts(cyxwiz_dht_t *dht);
static void continue_lookup(cyxwiz_dht_t *dht, cyxwiz_dht_lookup_t *lookup);
static bool is_node_queried(cyxwiz_dht_lookup_t *lookup, const cyxwiz_node_id_t *node_id);
static void add_to_closest(cyxwiz_dht_lookup_t *lookup, const cyxwiz_node_id_t *node_id,
                           const cyxwiz_node_id_t *target);

/* ============ Utility Functions ============ */

void cyxwiz_dht_xor_distance(
    const cyxwiz_node_id_t *a,
    const cyxwiz_node_id_t *b,
    uint8_t *distance)
{
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        distance[i] = a->bytes[i] ^ b->bytes[i];
    }
}

int cyxwiz_dht_distance_cmp(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, CYXWIZ_NODE_ID_LEN);
}

int cyxwiz_dht_bucket_index(
    const cyxwiz_node_id_t *local,
    const cyxwiz_node_id_t *remote)
{
    uint8_t dist[CYXWIZ_NODE_ID_LEN];
    cyxwiz_dht_xor_distance(local, remote, dist);

    /* Find first non-zero bit (most significant differing bit) */
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        if (dist[i] != 0) {
            /* Count leading zeros in this byte */
            int lz = 0;
            uint8_t b = dist[i];
            while ((b & 0x80) == 0) {
                lz++;
                b <<= 1;
            }
            return (int)(i * 8 + lz);
        }
    }

    /* Same node */
    return -1;
}

/* Compare nodes by distance to target (for sorting) */
static int compare_by_distance(const void *a, const void *b, void *target)
{
    const cyxwiz_node_id_t *node_a = (const cyxwiz_node_id_t *)a;
    const cyxwiz_node_id_t *node_b = (const cyxwiz_node_id_t *)b;
    const cyxwiz_node_id_t *tgt = (const cyxwiz_node_id_t *)target;

    uint8_t dist_a[CYXWIZ_NODE_ID_LEN];
    uint8_t dist_b[CYXWIZ_NODE_ID_LEN];

    cyxwiz_dht_xor_distance(node_a, tgt, dist_a);
    cyxwiz_dht_xor_distance(node_b, tgt, dist_b);

    return cyxwiz_dht_distance_cmp(dist_a, dist_b);
}

/* Simple insertion sort by distance (small arrays) */
static void sort_by_distance(cyxwiz_node_id_t *nodes, size_t count,
                             const cyxwiz_node_id_t *target)
{
    for (size_t i = 1; i < count; i++) {
        cyxwiz_node_id_t key = nodes[i];
        size_t j = i;
        while (j > 0 && compare_by_distance(&nodes[j-1], &key, (void *)target) > 0) {
            nodes[j] = nodes[j-1];
            j--;
        }
        nodes[j] = key;
    }
}

/* ============ DHT API Implementation ============ */

cyxwiz_error_t cyxwiz_dht_create(
    cyxwiz_dht_t **dht,
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *local_id)
{
    /* Router can be NULL for basic DHT operations (routing table only) */
    if (dht == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_dht_t *d = cyxwiz_calloc(1, sizeof(cyxwiz_dht_t));
    if (d == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    d->router = router;
    memcpy(&d->local_id, local_id, sizeof(cyxwiz_node_id_t));
    d->next_request_id = 1;
    d->running = true;

    /* Initialize buckets */
    for (size_t i = 0; i < CYXWIZ_DHT_BUCKET_COUNT; i++) {
        d->buckets[i].count = 0;
        d->buckets[i].last_refresh = 0;
    }

    char id_hex[17];
    for (int i = 0; i < 8; i++) {
        snprintf(id_hex + i*2, 3, "%02x", local_id->bytes[i]);
    }
    CYXWIZ_INFO("Created DHT context for node %s...", id_hex);

    *dht = d;
    return CYXWIZ_OK;
}

void cyxwiz_dht_destroy(cyxwiz_dht_t *dht)
{
    if (dht == NULL) {
        return;
    }

    dht->running = false;
    cyxwiz_free(dht, sizeof(cyxwiz_dht_t));
    CYXWIZ_INFO("Destroyed DHT context");
}

cyxwiz_error_t cyxwiz_dht_bootstrap(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *seed_nodes,
    size_t count)
{
    if (dht == NULL || (seed_nodes == NULL && count > 0)) {
        return CYXWIZ_ERR_INVALID;
    }

    CYXWIZ_INFO("Bootstrapping DHT with %zu seed nodes", count);

    /* Add seed nodes to routing table */
    for (size_t i = 0; i < count; i++) {
        add_to_bucket(dht, &seed_nodes[i]);
    }

    /* Perform lookup for our own ID to populate buckets */
    if (count > 0) {
        cyxwiz_dht_find_node(dht, &dht->local_id, NULL, NULL);
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_dht_add_node(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *node_id)
{
    if (dht == NULL || node_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    add_to_bucket(dht, node_id);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_dht_find_node(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *target,
    cyxwiz_dht_find_cb_t callback,
    void *user_data)
{
    if (dht == NULL || target == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find free lookup slot */
    cyxwiz_dht_lookup_t *lookup = NULL;
    for (size_t i = 0; i < CYXWIZ_DHT_MAX_LOOKUPS; i++) {
        if (!dht->lookups[i].active) {
            lookup = &dht->lookups[i];
            break;
        }
    }

    if (lookup == NULL) {
        CYXWIZ_WARN("DHT lookup slots exhausted");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Initialize lookup */
    memset(lookup, 0, sizeof(*lookup));
    memcpy(&lookup->target, target, sizeof(cyxwiz_node_id_t));
    lookup->request_id = dht->next_request_id++;
    lookup->started_at = dht->current_time;
    lookup->callback = callback;
    lookup->user_data = user_data;
    lookup->active = true;
    lookup->found = false;

    /* Seed with closest known nodes */
    lookup->closest_count = cyxwiz_dht_get_closest(dht, target,
                                                    lookup->closest,
                                                    CYXWIZ_DHT_K);

    if (lookup->closest_count == 0) {
        CYXWIZ_WARN("No nodes in routing table for lookup");
        lookup->active = false;
        if (callback) {
            callback(target, false, NULL, user_data);
        }
        return CYXWIZ_OK;
    }

    char hex[17];
    for (int i = 0; i < 8; i++) {
        snprintf(hex + i*2, 3, "%02x", target->bytes[i]);
    }
    CYXWIZ_DEBUG("Starting DHT lookup for %s... with %zu initial nodes",
                 hex, lookup->closest_count);

    /* Start parallel queries */
    continue_lookup(dht, lookup);

    return CYXWIZ_OK;
}

size_t cyxwiz_dht_get_closest(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *target,
    cyxwiz_node_id_t *out_nodes,
    size_t max_nodes)
{
    if (dht == NULL || target == NULL || out_nodes == NULL || max_nodes == 0) {
        return 0;
    }

    /* Collect all nodes from all buckets */
    cyxwiz_node_id_t all_nodes[CYXWIZ_DHT_BUCKET_COUNT * CYXWIZ_DHT_K];
    size_t total = 0;

    for (size_t i = 0; i < CYXWIZ_DHT_BUCKET_COUNT; i++) {
        cyxwiz_dht_bucket_t *bucket = &dht->buckets[i];
        for (size_t j = 0; j < bucket->count; j++) {
            if (bucket->nodes[j].active) {
                all_nodes[total++] = bucket->nodes[j].id;
            }
        }
    }

    if (total == 0) {
        return 0;
    }

    /* Sort by distance to target */
    sort_by_distance(all_nodes, total, target);

    /* Return closest */
    size_t count = (total < max_nodes) ? total : max_nodes;
    memcpy(out_nodes, all_nodes, count * sizeof(cyxwiz_node_id_t));

    return count;
}

void cyxwiz_dht_set_node_callback(
    cyxwiz_dht_t *dht,
    cyxwiz_dht_node_cb_t callback,
    void *user_data)
{
    if (dht != NULL) {
        dht->node_callback = callback;
        dht->node_callback_data = user_data;
    }
}

cyxwiz_error_t cyxwiz_dht_poll(
    cyxwiz_dht_t *dht,
    uint64_t current_time_ms)
{
    if (dht == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    dht->current_time = current_time_ms;

    /* Check lookup timeouts */
    check_lookup_timeouts(dht);

    /* Check ping timeouts */
    check_ping_timeouts(dht);

    /* Periodically refresh buckets */
    static uint64_t last_refresh = 0;
    if (current_time_ms - last_refresh > CYXWIZ_DHT_REFRESH_MS) {
        refresh_buckets(dht);
        last_refresh = current_time_ms;
    }

    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_dht_handle_message(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (dht == NULL || from == NULL || data == NULL || len < 1) {
        return CYXWIZ_ERR_INVALID;
    }

    dht->messages_received++;

    uint8_t type = data[0];

    switch (type) {
        case CYXWIZ_MSG_DHT_PING:
            if (len >= sizeof(cyxwiz_dht_ping_t)) {
                handle_ping(dht, from, (const cyxwiz_dht_ping_t *)data);
            }
            break;

        case CYXWIZ_MSG_DHT_PONG:
            if (len >= sizeof(cyxwiz_dht_pong_t)) {
                handle_pong(dht, from, (const cyxwiz_dht_pong_t *)data);
            }
            break;

        case CYXWIZ_MSG_DHT_FIND_NODE:
            if (len >= sizeof(cyxwiz_dht_find_node_t)) {
                handle_find_node(dht, from, (const cyxwiz_dht_find_node_t *)data);
            }
            break;

        case CYXWIZ_MSG_DHT_FIND_NODE_RESP:
            if (len >= sizeof(cyxwiz_dht_find_node_resp_t)) {
                handle_find_node_resp(dht, from, data, len);
            }
            break;

        default:
            return CYXWIZ_ERR_INVALID;
    }

    /* Update routing table with sender */
    add_to_bucket(dht, from);

    return CYXWIZ_OK;
}

void cyxwiz_dht_get_stats(
    cyxwiz_dht_t *dht,
    cyxwiz_dht_stats_t *stats)
{
    if (dht == NULL || stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(*stats));

    for (size_t i = 0; i < CYXWIZ_DHT_BUCKET_COUNT; i++) {
        if (dht->buckets[i].count > 0) {
            stats->active_buckets++;
            stats->total_nodes += dht->buckets[i].count;
        }
    }

    for (size_t i = 0; i < CYXWIZ_DHT_MAX_LOOKUPS; i++) {
        if (dht->lookups[i].active) {
            stats->pending_lookups++;
        }
    }

    stats->messages_sent = dht->messages_sent;
    stats->messages_received = dht->messages_received;
}

/* ============ Message Handlers ============ */

static void handle_ping(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                        const cyxwiz_dht_ping_t *msg)
{
    CYXWIZ_DEBUG("Received DHT PING from peer");

    if (dht->router == NULL) {
        return;  /* No router, can't send response */
    }

    /* Send PONG response */
    cyxwiz_dht_pong_t pong;
    pong.type = CYXWIZ_MSG_DHT_PONG;
    pong.request_id = msg->request_id;
    memcpy(&pong.sender, &dht->local_id, sizeof(cyxwiz_node_id_t));

    cyxwiz_router_send(dht->router, from, (uint8_t *)&pong, sizeof(pong));
    dht->messages_sent++;
}

static void handle_pong(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                        const cyxwiz_dht_pong_t *msg)
{
    CYXWIZ_UNUSED(from);
    CYXWIZ_DEBUG("Received DHT PONG from peer");

    /* Find matching pending ping */
    for (size_t i = 0; i < dht->pending_ping_count; i++) {
        if (dht->pending_pings[i].active &&
            dht->pending_pings[i].request_id == msg->request_id) {
            /* Node is alive - update last_seen */
            int bucket_idx = dht->pending_pings[i].bucket_idx;
            size_t node_idx = dht->pending_pings[i].node_idx;

            if (bucket_idx >= 0 && bucket_idx < CYXWIZ_DHT_BUCKET_COUNT &&
                node_idx < dht->buckets[bucket_idx].count) {
                dht->buckets[bucket_idx].nodes[node_idx].last_seen = dht->current_time;
                dht->buckets[bucket_idx].nodes[node_idx].failures = 0;
            }

            dht->pending_pings[i].active = false;
            break;
        }
    }
}

static void handle_find_node(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                             const cyxwiz_dht_find_node_t *msg)
{
    CYXWIZ_DEBUG("Received DHT FIND_NODE request");

    if (dht->router == NULL) {
        return;  /* No router, can't send response */
    }

    /* Get closest nodes to target */
    cyxwiz_node_id_t closest[CYXWIZ_DHT_MAX_PEERS_RESP];
    size_t count = cyxwiz_dht_get_closest(dht, &msg->target, closest,
                                          CYXWIZ_DHT_MAX_PEERS_RESP);

    /* Build response */
    uint8_t response[250];
    cyxwiz_dht_find_node_resp_t *resp = (cyxwiz_dht_find_node_resp_t *)response;
    resp->type = CYXWIZ_MSG_DHT_FIND_NODE_RESP;
    resp->request_id = msg->request_id;
    resp->node_count = (uint8_t)count;

    /* Add node entries */
    cyxwiz_dht_node_entry_t *entries = (cyxwiz_dht_node_entry_t *)(response + sizeof(*resp));
    for (size_t i = 0; i < count; i++) {
        memcpy(&entries[i].id, &closest[i], sizeof(cyxwiz_node_id_t));
        entries[i].latency_ms = 0;  /* Unknown */
        entries[i].capabilities = 0;
        entries[i].reputation = 50;  /* Default */
    }

    size_t resp_len = sizeof(*resp) + count * sizeof(cyxwiz_dht_node_entry_t);
    cyxwiz_router_send(dht->router, from, response, resp_len);
    dht->messages_sent++;
}

static void handle_find_node_resp(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *from,
                                  const uint8_t *data, size_t len)
{
    const cyxwiz_dht_find_node_resp_t *resp = (const cyxwiz_dht_find_node_resp_t *)data;

    CYXWIZ_DEBUG("Received DHT FIND_NODE response with %u nodes", resp->node_count);

    /* Find matching lookup */
    cyxwiz_dht_lookup_t *lookup = NULL;
    for (size_t i = 0; i < CYXWIZ_DHT_MAX_LOOKUPS; i++) {
        if (dht->lookups[i].active &&
            dht->lookups[i].request_id == resp->request_id) {
            lookup = &dht->lookups[i];
            break;
        }
    }

    if (lookup == NULL) {
        /* Stale response */
        return;
    }

    /* Parse node entries */
    const cyxwiz_dht_node_entry_t *entries =
        (const cyxwiz_dht_node_entry_t *)(data + sizeof(*resp));

    size_t expected_len = sizeof(*resp) + resp->node_count * sizeof(*entries);
    if (len < expected_len) {
        return;
    }

    /* Add nodes to routing table and lookup's closest list */
    for (size_t i = 0; i < resp->node_count; i++) {
        /* Skip self */
        if (cyxwiz_node_id_cmp(&entries[i].id, &dht->local_id) == 0) {
            continue;
        }

        /* Add to routing table */
        add_to_bucket(dht, &entries[i].id);

        /* Check if this is the target */
        if (cyxwiz_node_id_cmp(&entries[i].id, &lookup->target) == 0) {
            lookup->found = true;
        }

        /* Add to closest list */
        add_to_closest(lookup, &entries[i].id, &lookup->target);
    }

    /* Mark sender as queried */
    if (lookup->queried_count < CYXWIZ_DHT_K * 3) {
        memcpy(&lookup->queried[lookup->queried_count++], from, sizeof(cyxwiz_node_id_t));
    }

    /* Continue lookup or finish */
    if (lookup->found) {
        /* Found target! */
        lookup->active = false;
        if (lookup->callback) {
            lookup->callback(&lookup->target, true, &lookup->target, lookup->user_data);
        }
    } else {
        continue_lookup(dht, lookup);
    }
}

/* ============ Message Sending ============ */

static void send_find_node(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *to,
                           const cyxwiz_node_id_t *target, uint32_t request_id)
{
    if (dht->router == NULL) {
        return;  /* No router, can't send messages */
    }

    cyxwiz_dht_find_node_t msg;
    msg.type = CYXWIZ_MSG_DHT_FIND_NODE;
    msg.request_id = request_id;
    memcpy(&msg.target, target, sizeof(cyxwiz_node_id_t));

    cyxwiz_router_send(dht->router, to, (uint8_t *)&msg, sizeof(msg));
    dht->messages_sent++;
}

static void send_ping(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *to, uint32_t request_id)
{
    if (dht->router == NULL) {
        return;  /* No router, can't send messages */
    }

    cyxwiz_dht_ping_t msg;
    msg.type = CYXWIZ_MSG_DHT_PING;
    msg.request_id = request_id;
    memcpy(&msg.sender, &dht->local_id, sizeof(cyxwiz_node_id_t));

    cyxwiz_router_send(dht->router, to, (uint8_t *)&msg, sizeof(msg));
    dht->messages_sent++;
}

/* ============ Bucket Management ============ */

static void add_to_bucket(cyxwiz_dht_t *dht, const cyxwiz_node_id_t *node_id)
{
    /* Don't add self */
    if (cyxwiz_node_id_cmp(node_id, &dht->local_id) == 0) {
        return;
    }

    int idx = cyxwiz_dht_bucket_index(&dht->local_id, node_id);
    if (idx < 0 || idx >= CYXWIZ_DHT_BUCKET_COUNT) {
        return;
    }

    cyxwiz_dht_bucket_t *bucket = &dht->buckets[idx];

    /* Check if already exists */
    for (size_t i = 0; i < bucket->count; i++) {
        if (cyxwiz_node_id_cmp(&bucket->nodes[i].id, node_id) == 0) {
            /* Update last_seen and move to end (most recently seen) */
            bucket->nodes[i].last_seen = dht->current_time;
            return;
        }
    }

    /* Bucket not full - add directly */
    if (bucket->count < CYXWIZ_DHT_K) {
        cyxwiz_dht_node_t *node = &bucket->nodes[bucket->count];
        memcpy(&node->id, node_id, sizeof(cyxwiz_node_id_t));
        node->last_seen = dht->current_time;
        node->latency_ms = 0;
        node->failures = 0;
        node->active = true;
        bucket->count++;

        /* Notify callback */
        if (dht->node_callback) {
            dht->node_callback(node_id, dht->node_callback_data);
        }

        return;
    }

    /* Bucket full - find oldest node and ping it */
    size_t oldest_idx = 0;
    uint64_t oldest_time = bucket->nodes[0].last_seen;
    for (size_t i = 1; i < bucket->count; i++) {
        if (bucket->nodes[i].last_seen < oldest_time) {
            oldest_time = bucket->nodes[i].last_seen;
            oldest_idx = i;
        }
    }

    /* If oldest has failed before, replace it */
    if (bucket->nodes[oldest_idx].failures > 0) {
        memcpy(&bucket->nodes[oldest_idx].id, node_id, sizeof(cyxwiz_node_id_t));
        bucket->nodes[oldest_idx].last_seen = dht->current_time;
        bucket->nodes[oldest_idx].failures = 0;

        if (dht->node_callback) {
            dht->node_callback(node_id, dht->node_callback_data);
        }
    }
    /* Otherwise, ping the oldest to see if it's still alive */
    /* (new node is discarded if oldest responds) */
}

static void refresh_buckets(cyxwiz_dht_t *dht)
{
    /* For each bucket that hasn't been refreshed recently,
       pick a random ID in that bucket's range and do a lookup */
    for (size_t i = 0; i < CYXWIZ_DHT_BUCKET_COUNT; i++) {
        cyxwiz_dht_bucket_t *bucket = &dht->buckets[i];

        if (bucket->count == 0) {
            continue;
        }

        if (dht->current_time - bucket->last_refresh < CYXWIZ_DHT_REFRESH_MS) {
            continue;
        }

        bucket->last_refresh = dht->current_time;

        /* Ping a random node in this bucket to check liveness */
        if (bucket->count > 0) {
            size_t random_idx = (size_t)(dht->current_time % bucket->count);
            uint32_t req_id = dht->next_request_id++;

            /* Track pending ping */
            if (dht->pending_ping_count < CYXWIZ_DHT_K) {
                cyxwiz_dht_pending_ping_t *pending =
                    &dht->pending_pings[dht->pending_ping_count++];
                pending->request_id = req_id;
                pending->bucket_idx = (int)i;
                pending->node_idx = random_idx;
                pending->sent_at = dht->current_time;
                pending->active = true;

                send_ping(dht, &bucket->nodes[random_idx].id, req_id);
            }
        }
    }
}

static void check_lookup_timeouts(cyxwiz_dht_t *dht)
{
    for (size_t i = 0; i < CYXWIZ_DHT_MAX_LOOKUPS; i++) {
        cyxwiz_dht_lookup_t *lookup = &dht->lookups[i];
        if (!lookup->active) {
            continue;
        }

        if (dht->current_time - lookup->started_at > CYXWIZ_DHT_LOOKUP_TIMEOUT_MS) {
            CYXWIZ_DEBUG("DHT lookup timed out");
            lookup->active = false;
            if (lookup->callback) {
                lookup->callback(&lookup->target, false, NULL, lookup->user_data);
            }
        }
    }
}

static void check_ping_timeouts(cyxwiz_dht_t *dht)
{
    for (size_t i = 0; i < dht->pending_ping_count; i++) {
        cyxwiz_dht_pending_ping_t *pending = &dht->pending_pings[i];
        if (!pending->active) {
            continue;
        }

        if (dht->current_time - pending->sent_at > CYXWIZ_DHT_PING_TIMEOUT_MS) {
            /* Mark node as failed */
            int bucket_idx = pending->bucket_idx;
            size_t node_idx = pending->node_idx;

            if (bucket_idx >= 0 && bucket_idx < CYXWIZ_DHT_BUCKET_COUNT &&
                node_idx < dht->buckets[bucket_idx].count) {
                dht->buckets[bucket_idx].nodes[node_idx].failures++;
            }

            pending->active = false;
        }
    }

    /* Compact pending pings array */
    size_t write_idx = 0;
    for (size_t i = 0; i < dht->pending_ping_count; i++) {
        if (dht->pending_pings[i].active) {
            if (write_idx != i) {
                dht->pending_pings[write_idx] = dht->pending_pings[i];
            }
            write_idx++;
        }
    }
    dht->pending_ping_count = write_idx;
}

/* ============ Lookup Helpers ============ */

static void continue_lookup(cyxwiz_dht_t *dht, cyxwiz_dht_lookup_t *lookup)
{
    if (!lookup->active) {
        return;
    }

    /* Find unqueried nodes from closest list */
    int queries_sent = 0;
    for (size_t i = 0; i < lookup->closest_count && queries_sent < CYXWIZ_DHT_ALPHA; i++) {
        if (!is_node_queried(lookup, &lookup->closest[i])) {
            send_find_node(dht, &lookup->closest[i], &lookup->target, lookup->request_id);

            /* Mark as queried */
            if (lookup->queried_count < CYXWIZ_DHT_K * 3) {
                memcpy(&lookup->queried[lookup->queried_count++],
                       &lookup->closest[i], sizeof(cyxwiz_node_id_t));
            }
            queries_sent++;
        }
    }

    /* If no more nodes to query, lookup is complete */
    if (queries_sent == 0) {
        lookup->active = false;
        if (lookup->callback) {
            /* Return closest node as result */
            const cyxwiz_node_id_t *result = lookup->closest_count > 0 ?
                                              &lookup->closest[0] : NULL;
            lookup->callback(&lookup->target, false, result, lookup->user_data);
        }
    }
}

static bool is_node_queried(cyxwiz_dht_lookup_t *lookup, const cyxwiz_node_id_t *node_id)
{
    for (size_t i = 0; i < lookup->queried_count; i++) {
        if (cyxwiz_node_id_cmp(&lookup->queried[i], node_id) == 0) {
            return true;
        }
    }
    return false;
}

static void add_to_closest(cyxwiz_dht_lookup_t *lookup, const cyxwiz_node_id_t *node_id,
                           const cyxwiz_node_id_t *target)
{
    /* Check if already in list */
    for (size_t i = 0; i < lookup->closest_count; i++) {
        if (cyxwiz_node_id_cmp(&lookup->closest[i], node_id) == 0) {
            return;
        }
    }

    /* Add to list */
    if (lookup->closest_count < CYXWIZ_DHT_K * 2) {
        memcpy(&lookup->closest[lookup->closest_count++], node_id, sizeof(cyxwiz_node_id_t));
    } else {
        /* Check if this node is closer than the farthest in list */
        uint8_t new_dist[CYXWIZ_NODE_ID_LEN];
        uint8_t farthest_dist[CYXWIZ_NODE_ID_LEN];

        cyxwiz_dht_xor_distance(node_id, target, new_dist);
        cyxwiz_dht_xor_distance(&lookup->closest[lookup->closest_count - 1],
                                target, farthest_dist);

        if (cyxwiz_dht_distance_cmp(new_dist, farthest_dist) < 0) {
            /* Replace farthest */
            memcpy(&lookup->closest[lookup->closest_count - 1], node_id,
                   sizeof(cyxwiz_node_id_t));
        }
    }

    /* Keep sorted by distance */
    sort_by_distance(lookup->closest, lookup->closest_count, target);
}
