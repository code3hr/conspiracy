/*
 * CyxWiz Protocol - Distributed Hash Table
 *
 * Kademlia-style DHT for decentralized peer discovery.
 * Enables global node discovery without centralized bootstrap servers.
 *
 * Key features:
 * - 256-bit node ID keyspace (matches CYXWIZ_NODE_ID_LEN)
 * - XOR distance metric for routing
 * - K-buckets for routing table organization
 * - Iterative lookup with parallel queries
 * - All messages fit 250-byte LoRa constraint
 */

#ifndef CYXWIZ_DHT_H
#define CYXWIZ_DHT_H

#include "types.h"
#include "routing.h"

/* DHT constants */
#define CYXWIZ_DHT_K                 8       /* Bucket size (replication factor) */
#define CYXWIZ_DHT_ALPHA             3       /* Parallel lookup concurrency */
#define CYXWIZ_DHT_BUCKET_COUNT      256     /* One bucket per bit of node ID */
#define CYXWIZ_DHT_MAX_PEERS_RESP    6       /* Max peers per response (fits LoRa) */
#define CYXWIZ_DHT_REFRESH_MS        600000  /* Bucket refresh interval (10 min) */
#define CYXWIZ_DHT_PING_TIMEOUT_MS   5000    /* Ping timeout (5 sec) */
#define CYXWIZ_DHT_LOOKUP_TIMEOUT_MS 10000   /* Lookup timeout (10 sec) */
#define CYXWIZ_DHT_MAX_LOOKUPS       4       /* Max concurrent lookups */
#define CYXWIZ_DHT_NODE_TIMEOUT_MS   900000  /* Node considered stale after 15 min */

/* DHT node entry in routing table */
typedef struct {
    cyxwiz_node_id_t id;
    uint64_t last_seen;
    uint16_t latency_ms;
    uint8_t failures;
    bool active;
} cyxwiz_dht_node_t;

/* K-bucket (stores K nodes at similar XOR distance) */
typedef struct {
    cyxwiz_dht_node_t nodes[CYXWIZ_DHT_K];
    size_t count;
    uint64_t last_refresh;
} cyxwiz_dht_bucket_t;

/* DHT context (opaque) */
typedef struct cyxwiz_dht cyxwiz_dht_t;

/* Callback for node lookup completion */
typedef void (*cyxwiz_dht_find_cb_t)(
    const cyxwiz_node_id_t *target,
    bool found,
    const cyxwiz_node_id_t *result,  /* If found, the actual node */
    void *user_data
);

/* Callback when new node discovered via DHT */
typedef void (*cyxwiz_dht_node_cb_t)(
    const cyxwiz_node_id_t *node_id,
    void *user_data
);

/* ============ DHT Message Structures ============ */

/*
 * DHT PING (37 bytes) - Check if node is alive
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_PING (0x05) */
    uint32_t request_id;             /* For response correlation */
    cyxwiz_node_id_t sender;         /* Sender's node ID */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_ping_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * DHT PONG (37 bytes) - Response to PING
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_PONG (0x06) */
    uint32_t request_id;             /* Echo request ID */
    cyxwiz_node_id_t sender;         /* Responder's node ID */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_pong_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * FIND_NODE request (37 bytes) - Find nodes close to target
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_FIND_NODE (0x07) */
    uint32_t request_id;             /* For response correlation */
    cyxwiz_node_id_t target;         /* Target node ID to find */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_find_node_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * Node entry in FIND_NODE response (36 bytes per entry)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    cyxwiz_node_id_t id;             /* Node ID (32 bytes) */
    uint16_t latency_ms;             /* RTT hint */
    uint8_t capabilities;            /* RELAY, COMPUTE, STORAGE, etc */
    uint8_t reputation;              /* 0-100 quality score */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_node_entry_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * FIND_NODE response header (6 bytes + N * 36 bytes)
 * Max N=6 for 222 bytes total (fits 250-byte LoRa)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_FIND_NODE_RESP (0x08) */
    uint32_t request_id;             /* Echo request ID */
    uint8_t node_count;              /* Number of nodes (0-6) */
    /* Followed by node_count cyxwiz_dht_node_entry_t entries */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_find_node_resp_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * DHT STORE request (variable, max ~100 bytes for small values)
 * Used for storing service announcements, etc.
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_STORE (0x09) */
    uint32_t request_id;
    cyxwiz_node_id_t key;            /* Storage key (32 bytes) */
    cyxwiz_node_id_t publisher;      /* Original publisher */
    uint32_t ttl_seconds;            /* Time-to-live */
    uint8_t value_len;               /* Value length */
    /* Followed by value bytes */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_store_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * DHT STORE response (6 bytes)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_STORE_RESP (0x0A) */
    uint32_t request_id;
    uint8_t success;                 /* 1 = stored, 0 = rejected */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_store_resp_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * FIND_VALUE request (37 bytes) - Get value by key
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_FIND_VALUE (0x0B) */
    uint32_t request_id;
    cyxwiz_node_id_t key;            /* Key to find (32 bytes) */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_find_value_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * FIND_VALUE response (variable)
 * If found: type + request_id + found=1 + ttl + value_len + value
 * If not found: type + request_id + found=0 + node_count + nodes[]
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_MSG_DHT_FIND_VALUE_RESP (0x0C) */
    uint32_t request_id;
    uint8_t found;                   /* 1 = value included, 0 = nodes included */
    /* If found=1: uint32_t ttl_remaining, uint8_t value_len, uint8_t value[] */
    /* If found=0: uint8_t node_count, cyxwiz_dht_node_entry_t nodes[] */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_dht_find_value_resp_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ DHT Value Storage Constants ============ */

#define CYXWIZ_DHT_MAX_VALUE_SIZE    160     /* Max value size (fits LoRa with headers) */
#define CYXWIZ_DHT_MAX_VALUES        64      /* Max stored values per node */
#define CYXWIZ_DHT_VALUE_REPLICATION 3       /* Store to K closest nodes */
#define CYXWIZ_DHT_GET_TIMEOUT_MS    5000    /* Get operation timeout */

/* ============ DHT API ============ */

/*
 * Create DHT context
 *
 * @param dht       Output: DHT context
 * @param router    Router for sending messages
 * @param local_id  This node's ID
 * @return CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_dht_create(
    cyxwiz_dht_t **dht,
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy DHT context
 */
void cyxwiz_dht_destroy(cyxwiz_dht_t *dht);

/*
 * Bootstrap DHT with seed nodes
 *
 * @param dht         DHT context
 * @param seed_nodes  Array of seed node IDs
 * @param count       Number of seed nodes
 * @return CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_dht_bootstrap(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *seed_nodes,
    size_t count
);

/*
 * Add a known node to DHT routing table
 *
 * @param dht      DHT context
 * @param node_id  Node to add
 * @return CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_dht_add_node(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *node_id
);

/*
 * Find a node in the DHT (iterative lookup)
 *
 * @param dht        DHT context
 * @param target     Target node ID to find
 * @param callback   Called when lookup completes
 * @param user_data  Passed to callback
 * @return CYXWIZ_OK if lookup started
 */
cyxwiz_error_t cyxwiz_dht_find_node(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *target,
    cyxwiz_dht_find_cb_t callback,
    void *user_data
);

/*
 * Get closest known nodes to target (synchronous)
 *
 * @param dht        DHT context
 * @param target     Target node ID
 * @param out_nodes  Output: array of closest nodes
 * @param max_nodes  Maximum nodes to return
 * @return Number of nodes returned
 */
size_t cyxwiz_dht_get_closest(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *target,
    cyxwiz_node_id_t *out_nodes,
    size_t max_nodes
);

/*
 * Set callback for newly discovered nodes
 *
 * @param dht        DHT context
 * @param callback   Called when new node discovered
 * @param user_data  Passed to callback
 */
void cyxwiz_dht_set_node_callback(
    cyxwiz_dht_t *dht,
    cyxwiz_dht_node_cb_t callback,
    void *user_data
);

/*
 * Poll DHT (call periodically from main loop)
 *
 * @param dht             DHT context
 * @param current_time_ms Current timestamp
 * @return CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_dht_poll(
    cyxwiz_dht_t *dht,
    uint64_t current_time_ms
);

/*
 * Handle incoming DHT message
 *
 * @param dht   DHT context
 * @param from  Sender node ID
 * @param data  Message data
 * @param len   Message length
 * @return CYXWIZ_OK if handled
 */
cyxwiz_error_t cyxwiz_dht_handle_message(
    cyxwiz_dht_t *dht,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/*
 * Get DHT statistics
 */
typedef struct {
    size_t total_nodes;              /* Total nodes in routing table */
    size_t active_buckets;           /* Non-empty buckets */
    size_t pending_lookups;          /* Active lookups */
    uint64_t messages_sent;
    uint64_t messages_received;
} cyxwiz_dht_stats_t;

void cyxwiz_dht_get_stats(
    cyxwiz_dht_t *dht,
    cyxwiz_dht_stats_t *stats
);

/* ============ Simple Key-Value API ============ */

/*
 * Callback for DHT get completion
 *
 * @param key        The key that was looked up
 * @param found      true if value was found
 * @param value      Value data (NULL if not found)
 * @param value_len  Length of value
 * @param user_data  User-provided context
 */
typedef void (*cyxwiz_dht_get_cb_t)(
    const uint8_t *key,
    bool found,
    const uint8_t *value,
    size_t value_len,
    void *user_data
);

/*
 * Store a key-value pair in the DHT
 *
 * Stores the value to the K closest nodes to the key.
 * Key is a 32-byte hash (e.g., BLAKE2b of logical key).
 *
 * @param dht         DHT context
 * @param key         32-byte key (usually a hash)
 * @param value       Value to store
 * @param value_len   Length of value (max CYXWIZ_DHT_MAX_VALUE_SIZE)
 * @param ttl_seconds Time-to-live in seconds (max 86400 = 24h)
 * @return            CYXWIZ_OK on success, error otherwise
 */
cyxwiz_error_t cyxwiz_dht_put(
    cyxwiz_dht_t *dht,
    const uint8_t *key,
    const uint8_t *value,
    size_t value_len,
    uint32_t ttl_seconds
);

/*
 * Retrieve a value from the DHT by key
 *
 * Performs iterative lookup to find nodes closest to key,
 * queries them for the value. Callback is invoked when complete.
 *
 * @param dht         DHT context
 * @param key         32-byte key to look up
 * @param callback    Called when lookup completes
 * @param user_data   Passed to callback
 * @return            CYXWIZ_OK if lookup started
 */
cyxwiz_error_t cyxwiz_dht_get(
    cyxwiz_dht_t *dht,
    const uint8_t *key,
    cyxwiz_dht_get_cb_t callback,
    void *user_data
);

/*
 * Delete a key from the DHT
 *
 * Sends delete requests to nodes storing this key.
 * Note: DHT deletes are best-effort (nodes may still have cached copies).
 *
 * @param dht   DHT context
 * @param key   32-byte key to delete
 * @return      CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_dht_delete(
    cyxwiz_dht_t *dht,
    const uint8_t *key
);

/*
 * Check if a key exists locally (without network lookup)
 *
 * @param dht   DHT context
 * @param key   32-byte key to check
 * @return      true if stored locally
 */
bool cyxwiz_dht_has_local(
    cyxwiz_dht_t *dht,
    const uint8_t *key
);

/*
 * Get a value stored locally (without network lookup)
 *
 * @param dht         DHT context
 * @param key         32-byte key
 * @param value_out   Output buffer for value
 * @param value_size  Size of output buffer
 * @param value_len   Output: actual value length
 * @return            CYXWIZ_OK if found, CYXWIZ_ERR_STORAGE_NOT_FOUND otherwise
 */
cyxwiz_error_t cyxwiz_dht_get_local(
    cyxwiz_dht_t *dht,
    const uint8_t *key,
    uint8_t *value_out,
    size_t value_size,
    size_t *value_len
);

/*
 * Get count of locally stored values
 */
size_t cyxwiz_dht_local_count(const cyxwiz_dht_t *dht);

/*
 * Get total bytes used by local value storage
 */
size_t cyxwiz_dht_local_bytes(const cyxwiz_dht_t *dht);

/* ============ Utility Functions ============ */

/*
 * Calculate XOR distance between two node IDs
 *
 * @param a         First node ID
 * @param b         Second node ID
 * @param distance  Output: XOR distance (32 bytes)
 */
void cyxwiz_dht_xor_distance(
    const cyxwiz_node_id_t *a,
    const cyxwiz_node_id_t *b,
    uint8_t *distance
);

/*
 * Compare XOR distances (for sorting)
 *
 * @param a  First distance
 * @param b  Second distance
 * @return <0 if a<b, 0 if equal, >0 if a>b
 */
int cyxwiz_dht_distance_cmp(
    const uint8_t *a,
    const uint8_t *b
);

/*
 * Get bucket index for a node relative to local ID
 *
 * @param local   Local node ID
 * @param remote  Remote node ID
 * @return Bucket index (0-255), or -1 if same node
 */
int cyxwiz_dht_bucket_index(
    const cyxwiz_node_id_t *local,
    const cyxwiz_node_id_t *remote
);

#endif /* CYXWIZ_DHT_H */
