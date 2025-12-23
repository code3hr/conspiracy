/*
 * CyxWiz Protocol - Peer Discovery and Management
 *
 * Handles:
 * - Peer table (known peers and their state)
 * - Discovery protocol (finding new peers)
 * - Peer lifecycle (connect, heartbeat, disconnect)
 */

#ifndef CYXWIZ_PEER_H
#define CYXWIZ_PEER_H

#include "types.h"
#include "transport.h"

/* Peer table limits */
#define CYXWIZ_MAX_PEERS 64
#define CYXWIZ_PEER_TIMEOUT_MS 30000      /* 30 seconds */
#define CYXWIZ_DISCOVERY_INTERVAL_MS 5000  /* 5 seconds */
#define CYXWIZ_HEARTBEAT_INTERVAL_MS 10000 /* 10 seconds */

/* Peer states */
typedef enum {
    CYXWIZ_PEER_STATE_UNKNOWN = 0,
    CYXWIZ_PEER_STATE_DISCOVERED,    /* Just discovered, not connected */
    CYXWIZ_PEER_STATE_CONNECTING,    /* Handshake in progress */
    CYXWIZ_PEER_STATE_CONNECTED,     /* Active connection */
    CYXWIZ_PEER_STATE_DISCONNECTING, /* Graceful disconnect */
    CYXWIZ_PEER_STATE_FAILED         /* Connection failed */
} cyxwiz_peer_state_t;

/* Peer capabilities (bitflags) */
typedef enum {
    CYXWIZ_PEER_CAP_RELAY   = 0x01,  /* Can relay traffic */
    CYXWIZ_PEER_CAP_COMPUTE = 0x02,  /* Can execute compute */
    CYXWIZ_PEER_CAP_STORAGE = 0x04,  /* Can store data */
    CYXWIZ_PEER_CAP_VALIDATE = 0x08  /* Can validate */
} cyxwiz_peer_cap_t;

/*
 * Peer information
 */
typedef struct {
    cyxwiz_node_id_t id;              /* Peer's node ID */
    cyxwiz_peer_state_t state;        /* Connection state */
    cyxwiz_transport_type_t transport; /* How we're connected */
    uint8_t capabilities;              /* What this peer can do */
    int8_t rssi;                       /* Signal strength (dBm) */
    uint64_t last_seen;                /* Timestamp of last activity */
    uint64_t discovered_at;            /* When we first found them */
    uint16_t latency_ms;               /* Round-trip latency */
    uint32_t bytes_sent;               /* Traffic stats */
    uint32_t bytes_recv;
} cyxwiz_peer_t;

/*
 * Peer table - manages all known peers
 */
typedef struct cyxwiz_peer_table cyxwiz_peer_table_t;

/*
 * Callbacks for peer events
 */
typedef void (*cyxwiz_peer_event_cb_t)(
    cyxwiz_peer_table_t *table,
    const cyxwiz_peer_t *peer,
    cyxwiz_peer_state_t old_state,
    void *user_data
);

/* ============ Peer Table Management ============ */

/*
 * Create a peer table
 */
cyxwiz_error_t cyxwiz_peer_table_create(cyxwiz_peer_table_t **table);

/*
 * Destroy peer table
 */
void cyxwiz_peer_table_destroy(cyxwiz_peer_table_t *table);

/*
 * Set callback for peer state changes
 */
void cyxwiz_peer_table_set_callback(
    cyxwiz_peer_table_t *table,
    cyxwiz_peer_event_cb_t callback,
    void *user_data
);

/*
 * Add or update a peer
 * If peer exists, updates last_seen and state
 */
cyxwiz_error_t cyxwiz_peer_table_add(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    cyxwiz_transport_type_t transport,
    int8_t rssi
);

/*
 * Remove a peer from the table
 */
cyxwiz_error_t cyxwiz_peer_table_remove(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id
);

/*
 * Find a peer by ID
 * Returns NULL if not found
 */
const cyxwiz_peer_t *cyxwiz_peer_table_find(
    const cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id
);

/*
 * Update peer state
 */
cyxwiz_error_t cyxwiz_peer_table_set_state(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    cyxwiz_peer_state_t state
);

/*
 * Update peer capabilities
 */
cyxwiz_error_t cyxwiz_peer_table_set_capabilities(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *id,
    uint8_t capabilities
);

/*
 * Get number of peers in table
 */
size_t cyxwiz_peer_table_count(const cyxwiz_peer_table_t *table);

/*
 * Get number of connected peers
 */
size_t cyxwiz_peer_table_connected_count(const cyxwiz_peer_table_t *table);

/*
 * Iterate over all peers
 * Callback returns 0 to continue, non-zero to stop
 */
typedef int (*cyxwiz_peer_iter_cb_t)(const cyxwiz_peer_t *peer, void *user_data);

void cyxwiz_peer_table_iterate(
    const cyxwiz_peer_table_t *table,
    cyxwiz_peer_iter_cb_t callback,
    void *user_data
);

/*
 * Get peer by index (for random selection/iteration)
 * Returns NULL if index out of range or slot empty
 */
const cyxwiz_peer_t *cyxwiz_peer_table_get_peer(
    const cyxwiz_peer_table_t *table,
    size_t index
);

/*
 * Clean up stale peers (not seen within timeout)
 * Returns number of peers removed
 */
size_t cyxwiz_peer_table_cleanup(
    cyxwiz_peer_table_t *table,
    uint64_t timeout_ms
);

/* ============ Discovery Protocol ============ */

/*
 * Discovery context
 */
typedef struct cyxwiz_discovery cyxwiz_discovery_t;

/*
 * Key exchange callback - called when a peer's public key is received
 */
typedef void (*cyxwiz_key_exchange_cb_t)(
    const cyxwiz_node_id_t *peer_id,
    const uint8_t *peer_pubkey,
    void *user_data
);

/*
 * Set key exchange callback for discovery
 * Called when peer's X25519 public key is received via ANNOUNCE
 */
void cyxwiz_discovery_set_key_callback(
    cyxwiz_discovery_t *discovery,
    cyxwiz_key_exchange_cb_t callback,
    void *user_data
);

/*
 * Set this node's X25519 public key for announcements
 */
void cyxwiz_discovery_set_pubkey(
    cyxwiz_discovery_t *discovery,
    const uint8_t *pubkey
);

/*
 * Create discovery context
 * Attaches to a peer table and transport
 */
cyxwiz_error_t cyxwiz_discovery_create(
    cyxwiz_discovery_t **discovery,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy discovery context
 */
void cyxwiz_discovery_destroy(cyxwiz_discovery_t *discovery);

/*
 * Start discovery (begins broadcasting announcements)
 */
cyxwiz_error_t cyxwiz_discovery_start(cyxwiz_discovery_t *discovery);

/*
 * Stop discovery
 */
cyxwiz_error_t cyxwiz_discovery_stop(cyxwiz_discovery_t *discovery);

/*
 * Process discovery events (call periodically)
 * - Sends announcements
 * - Processes incoming announcements
 * - Cleans up stale peers
 */
cyxwiz_error_t cyxwiz_discovery_poll(
    cyxwiz_discovery_t *discovery,
    uint64_t current_time_ms
);

/*
 * Handle incoming discovery message
 */
cyxwiz_error_t cyxwiz_discovery_handle_message(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ Discovery Messages ============ */

/*
 * Discovery message types
 */
typedef enum {
    CYXWIZ_DISC_ANNOUNCE = 0x01,   /* "I'm here" broadcast */
    CYXWIZ_DISC_ANNOUNCE_ACK = 0x02, /* Response to announce */
    CYXWIZ_DISC_PING = 0x03,       /* Keepalive */
    CYXWIZ_DISC_PONG = 0x04,       /* Keepalive response */
    CYXWIZ_DISC_GOODBYE = 0x05     /* Graceful disconnect */
} cyxwiz_disc_msg_type_t;

/* X25519 public key size */
#define CYXWIZ_PUBKEY_SIZE 32

/*
 * Announcement message (broadcast to find peers)
 * Total: 69 bytes (fits easily in LoRa)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_DISC_ANNOUNCE */
    uint8_t version;                 /* Protocol version */
    cyxwiz_node_id_t node_id;        /* Our node ID (32 bytes) */
    uint8_t capabilities;            /* What we can do */
    uint16_t port;                   /* Optional port (0 if N/A) */
    uint8_t pubkey[CYXWIZ_PUBKEY_SIZE]; /* X25519 public key for onion routing */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_disc_announce_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * Ping message (keepalive)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_DISC_PING */
    uint64_t timestamp;              /* For latency measurement */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_disc_ping_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * Pong message (keepalive response)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                    /* CYXWIZ_DISC_PONG */
    uint64_t echo_timestamp;         /* Echo back sender's timestamp */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_disc_pong_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Utility ============ */

/*
 * Get current timestamp in milliseconds
 */
uint64_t cyxwiz_time_ms(void);

/*
 * Get peer state name
 */
const char *cyxwiz_peer_state_name(cyxwiz_peer_state_t state);

/*
 * Format node ID as hex string (for logging)
 * Buffer must be at least 65 bytes (32*2 + 1)
 */
void cyxwiz_node_id_to_hex(const cyxwiz_node_id_t *id, char *buf);

/*
 * Compare two node IDs
 * Returns 0 if equal
 */
int cyxwiz_node_id_cmp(const cyxwiz_node_id_t *a, const cyxwiz_node_id_t *b);

/*
 * Generate random node ID
 */
void cyxwiz_node_id_random(cyxwiz_node_id_t *id);

#endif /* CYXWIZ_PEER_H */
