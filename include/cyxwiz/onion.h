/*
 * CyxWiz Protocol - Onion Routing
 *
 * Implements layered encryption for anonymous routing:
 * - True onion routing with up to 3 hops
 * - XChaCha20-Poly1305 for each layer (40 bytes overhead)
 * - Per-hop key derivation from shared secrets
 * - Circuit management for tracking paths
 */

#ifndef CYXWIZ_ONION_H
#define CYXWIZ_ONION_H

#include "types.h"
#include "routing.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include "crypto.h"
#endif

/* Onion routing constants */
#define CYXWIZ_MAX_ONION_HOPS 3         /* Max hops (due to encryption overhead) */
#define CYXWIZ_ONION_OVERHEAD 40        /* XChaCha20-Poly1305 per layer */
#define CYXWIZ_CIRCUIT_ID_SIZE 4        /* Circuit identifier size */
#define CYXWIZ_MAX_CIRCUITS 16          /* Max active circuits */
#define CYXWIZ_CIRCUIT_TIMEOUT_MS 60000 /* Circuit expires after 60s */
#define CYXWIZ_CIRCUIT_ROTATION_MS 30000 /* Rotate circuit after 30s */
#define CYXWIZ_PUBKEY_SIZE 32           /* X25519 public key size */
#define CYXWIZ_EPHEMERAL_SIZE 32        /* Ephemeral public key per layer */

/* Guard node constants */
#define CYXWIZ_NUM_GUARDS 3             /* Number of guard nodes to maintain */
#define CYXWIZ_GUARD_ROTATION_MS (30ULL * 24 * 60 * 60 * 1000) /* 30 days */
#define CYXWIZ_GUARD_MIN_REPUTATION 70  /* Minimum reputation for guard */

/* Cover traffic constants */
#define CYXWIZ_COVER_TRAFFIC_INTERVAL_MS 30000  /* Send cover traffic every 30s */
#define CYXWIZ_COVER_MAGIC 0xDEADBEEF           /* Magic marker for cover traffic */

/* Circuit prebuilding constants */
#define CYXWIZ_PREBUILD_TARGET 4              /* Target number of prebuilt circuits */
#define CYXWIZ_PREBUILD_INTERVAL_MS 5000      /* Check for prebuilding every 5s */

/* Traffic analysis resistance - timing jitter */
#define CYXWIZ_TIMING_JITTER_PERCENT 30       /* ±30% jitter on intervals */
#define CYXWIZ_SEND_DELAY_MAX_MS 500          /* Max random send delay */

/* Circuit health monitoring */
#define CYXWIZ_CIRCUIT_HEALTH_INTERVAL_MS 15000  /* Health check every 15s */
#define CYXWIZ_CIRCUIT_HEALTH_TIMEOUT_MS 5000    /* Probe timeout */
#define CYXWIZ_CIRCUIT_MIN_SUCCESS_RATE 70       /* Min % for healthy circuit */
#define CYXWIZ_CIRCUIT_PROBE_MAGIC 0xCAFEBABE    /* Health probe marker */

/* Stream multiplexing constants */
#define CYXWIZ_MAX_STREAMS_PER_CIRCUIT 16       /* Max concurrent streams per circuit */
#define CYXWIZ_STREAM_ID_SIZE 2                 /* Stream ID field size in bytes */
#define CYXWIZ_STREAM_ID_DEFAULT 0              /* Default stream (backward compat) */

/* Replay protection constants */
#define CYXWIZ_MAX_SEEN_ONIONS 128            /* Max tracked onion packets */
#define CYXWIZ_ONION_SEEN_TIMEOUT_MS 90000    /* 90 second expiry (circuit lifetime + buffer) */
#define CYXWIZ_ONION_HASH_SIZE 16             /* Blake2b truncated hash */

/*
 * Maximum payload per hop count (with ephemeral keys and stream_id)
 * Header: type(1) + circuit_id(4) + stream_id(2) + ephemeral(32) = 39 bytes
 * Each layer adds: encryption overhead (40) + ephemeral key (32) = 72 bytes
 * Plus next_hop (32) for non-final layers
 * Final layer: zero_hop (32) + payload
 *
 * 1-hop: 250 - 7(hdr) - 32(eph) - 40(enc) - 32(zero_hop) = 139 bytes
 * 2-hop: 139 - 32(eph) - 40(enc) - 32(next_hop) = 35 bytes
 * 3-hop: would be negative, so we limit to 2 hops with ephemeral keys
 */
#define CYXWIZ_ONION_PAYLOAD_1HOP 139   /* 1-hop onion payload */
#define CYXWIZ_ONION_PAYLOAD_2HOP 35    /* 2-hop onion payload */
#define CYXWIZ_ONION_PAYLOAD_3HOP 0     /* 3-hop not supported with ephemeral */

/* Onion message header size: type (1) + circuit_id (4) + stream_id (2) + ephemeral (32) = 39 bytes */
#define CYXWIZ_ONION_HEADER_SIZE 39

/* Maximum encrypted payload in onion packet */
#define CYXWIZ_ONION_MAX_ENCRYPTED (CYXWIZ_MAX_PACKET_SIZE - CYXWIZ_ONION_HEADER_SIZE)

/* ============ Onion Data Message ============ */

/*
 * Onion-routed data message (0x24)
 * Total packet fits in 250 bytes
 *
 * Format: type (1) + circuit_id (4) + stream_id (2) + ephemeral_pub (32) + encrypted_data
 * The ephemeral_pub is used by the receiver to derive the layer key via ECDH.
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_MSG_ONION_DATA */
    uint32_t circuit_id;                 /* Circuit ID for replies */
    uint16_t stream_id;                  /* Stream ID for multiplexing */
    uint8_t ephemeral_pub[CYXWIZ_EPHEMERAL_SIZE]; /* Ephemeral public key for this hop */
    /* encrypted data follows (up to 211 bytes) */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_onion_data_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/*
 * Decrypted onion layer structure
 * Non-final layer: next_hop (32) + next_ephemeral (32) + inner_encrypted
 * Final layer: zero_hop (32) + payload
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    cyxwiz_node_id_t next_hop;           /* Next hop (0x00...00 = final destination) */
    uint8_t next_ephemeral[CYXWIZ_EPHEMERAL_SIZE]; /* Ephemeral key for next hop (if not final) */
    /* inner data follows */
}
#ifdef __GNUC__
__attribute__((packed))
#endif
cyxwiz_onion_layer_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============ Stream Multiplexing ============ */

/*
 * Stream state
 */
typedef enum {
    CYXWIZ_STREAM_STATE_CLOSED = 0,
    CYXWIZ_STREAM_STATE_OPEN = 1,
    CYXWIZ_STREAM_STATE_HALF_CLOSED = 2
} cyxwiz_stream_state_t;

/*
 * Stream event types for callback
 */
typedef enum {
    CYXWIZ_STREAM_EVENT_OPEN = 1,
    CYXWIZ_STREAM_EVENT_DATA = 2,
    CYXWIZ_STREAM_EVENT_CLOSE = 3,
    CYXWIZ_STREAM_EVENT_ERROR = 4
} cyxwiz_stream_event_t;

/*
 * Stream state (per circuit)
 */
typedef struct {
    uint16_t stream_id;
    cyxwiz_stream_state_t state;
    uint64_t opened_at;
    uint64_t last_activity_ms;
} cyxwiz_stream_t;

/*
 * Onion circuit (for building/tracking onion paths)
 */
typedef struct {
    uint32_t circuit_id;
    uint8_t hop_count;
    cyxwiz_node_id_t hops[CYXWIZ_MAX_ONION_HOPS];
    uint8_t keys[CYXWIZ_MAX_ONION_HOPS][CYXWIZ_KEY_SIZE];  /* Per-hop derived keys */
    uint8_t ephemeral_pubs[CYXWIZ_MAX_ONION_HOPS][CYXWIZ_EPHEMERAL_SIZE]; /* Per-hop ephemeral pubkeys */
    uint64_t created_at;
    bool active;

    /* Health monitoring */
    uint32_t messages_sent;           /* Total messages sent via this circuit */
    uint32_t messages_failed;         /* Failed deliveries (timeout/error) */
    uint64_t last_success_ms;         /* Last successful send timestamp */
    uint16_t avg_latency_ms;          /* Running average RTT */
    bool health_probe_pending;        /* Awaiting probe response */
    uint64_t health_probe_sent_ms;    /* When probe was sent */

    /* Stream multiplexing */
    cyxwiz_stream_t streams[CYXWIZ_MAX_STREAMS_PER_CIRCUIT];
    uint16_t next_stream_id;          /* Next stream ID to allocate */
    size_t stream_count;              /* Active stream count */
} cyxwiz_circuit_t;

/*
 * Peer key entry (shared secret with a peer)
 */
typedef struct {
    cyxwiz_node_id_t peer_id;
    uint8_t shared_secret[CYXWIZ_KEY_SIZE];
    uint8_t peer_pubkey[CYXWIZ_PUBKEY_SIZE];
    uint64_t established_at;
    bool valid;

    /* Key pinning (MITM detection) */
    uint8_t pinned_pubkey[CYXWIZ_PUBKEY_SIZE];  /* First-seen public key */
    bool key_pinned;                             /* Whether key is pinned */
    uint64_t pinned_at;                          /* When key was pinned */
    bool key_changed;                            /* Key changed since pin */
} cyxwiz_peer_key_t;

/*
 * Onion context - opaque structure
 */
typedef struct cyxwiz_onion_ctx cyxwiz_onion_ctx_t;

/* ============ Onion Context Lifecycle ============ */

/*
 * Create onion context
 *
 * @param ctx           Output context pointer
 * @param router        Router for sending/receiving
 * @param local_id      This node's ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_create(
    cyxwiz_onion_ctx_t **ctx,
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *local_id
);

/*
 * Destroy onion context
 */
void cyxwiz_onion_destroy(cyxwiz_onion_ctx_t *ctx);

/*
 * Refresh X25519 keypair for forward secrecy
 *
 * Generates a new keypair and clears all existing peer shared secrets.
 * Should be called periodically (e.g., every hour) to limit exposure
 * if the private key is compromised. Existing circuits will be invalidated.
 *
 * After calling this, you must re-announce your public key and peers
 * must re-compute shared secrets.
 *
 * @param ctx           Onion context
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_refresh_keypair(cyxwiz_onion_ctx_t *ctx);

/*
 * Set delivery callback for received onion data
 */
void cyxwiz_onion_set_callback(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_delivery_callback_t callback,
    void *user_data
);

/*
 * Stream callback type (receives stream events with stream ID)
 */
typedef void (*cyxwiz_stream_callback_t)(
    const cyxwiz_node_id_t *from,
    uint16_t stream_id,
    cyxwiz_stream_event_t event,
    const uint8_t *data,
    size_t len,
    void *user_data
);

/*
 * Set stream callback for multiplexed stream events
 */
void cyxwiz_onion_set_stream_callback(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_stream_callback_t callback,
    void *user_data
);

/*
 * Poll onion context (call in main loop)
 * - Expires old circuits
 * - Processes pending operations
 */
cyxwiz_error_t cyxwiz_onion_poll(
    cyxwiz_onion_ctx_t *ctx,
    uint64_t current_time_ms
);

/* ============ Key Management ============ */

/*
 * Get this node's X25519 public key
 */
cyxwiz_error_t cyxwiz_onion_get_pubkey(
    cyxwiz_onion_ctx_t *ctx,
    uint8_t *pubkey_out
);

/*
 * Add a peer's public key (from ANNOUNCE message)
 * Computes and stores shared secret via X25519 DH
 */
cyxwiz_error_t cyxwiz_onion_add_peer_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id,
    const uint8_t *peer_pubkey
);

/*
 * Check if we have a shared key with peer
 */
bool cyxwiz_onion_has_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id
);

/*
 * Derive per-hop key from shared secret
 *
 * @param shared_secret  The DH shared secret
 * @param sender         Sender's node ID
 * @param receiver       Receiver's node ID
 * @param key_out        Output derived key (32 bytes)
 */
cyxwiz_error_t cyxwiz_onion_derive_hop_key(
    const uint8_t *shared_secret,
    const cyxwiz_node_id_t *sender,
    const cyxwiz_node_id_t *receiver,
    uint8_t *key_out
);

/*
 * Compute ECDH shared secret with an ephemeral public key
 * Uses this node's private key with the provided public key
 *
 * @param ctx           Onion context
 * @param peer_pubkey   Peer's X25519 public key (32 bytes)
 * @param secret_out    Output shared secret (32 bytes)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_compute_ecdh(
    cyxwiz_onion_ctx_t *ctx,
    const uint8_t *peer_pubkey,
    uint8_t *secret_out
);

/* ============ Circuit Management ============ */

/*
 * Build an onion circuit through specified hops
 *
 * @param ctx           Onion context
 * @param hops          Array of intermediate hops (last is destination)
 * @param hop_count     Number of hops (1-3)
 * @param circuit_out   Output circuit pointer
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_build_circuit(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *hops,
    uint8_t hop_count,
    cyxwiz_circuit_t **circuit_out
);

/*
 * Destroy a circuit
 */
void cyxwiz_onion_destroy_circuit(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit
);

/*
 * Get circuit by ID
 */
cyxwiz_circuit_t *cyxwiz_onion_get_circuit(
    cyxwiz_onion_ctx_t *ctx,
    uint32_t circuit_id
);

/* ============ Sending Messages ============ */

/*
 * Send data through onion circuit
 *
 * @param ctx           Onion context
 * @param circuit       The circuit to use
 * @param data          Data to send
 * @param len           Data length (must fit in circuit's max payload)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_send(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    const uint8_t *data,
    size_t len
);

/*
 * Get maximum payload size for hop count
 */
size_t cyxwiz_onion_max_payload(uint8_t hop_count);

/*
 * Send data to destination via onion routing
 * Automatically builds circuit if needed
 *
 * @param ctx           Onion context
 * @param destination   Destination node ID
 * @param data          Data to send
 * @param len           Data length
 * @return              CYXWIZ_OK on success
 *                      CYXWIZ_ERR_NO_ROUTE if insufficient peers for circuit
 *                      CYXWIZ_ERR_PACKET_TOO_LARGE if data exceeds max payload
 */
cyxwiz_error_t cyxwiz_onion_send_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len
);

/*
 * Check if circuit exists to destination
 */
bool cyxwiz_onion_has_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination
);

/*
 * Find circuit to destination (returns NULL if none)
 */
cyxwiz_circuit_t *cyxwiz_onion_find_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination
);

/* ============ Stream Multiplexing API ============ */

/*
 * Open a new stream on a circuit
 *
 * @param circuit       The circuit to open stream on
 * @param stream_id_out Output: allocated stream ID
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_circuit_open_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t *stream_id_out
);

/*
 * Send data on a specific stream
 *
 * @param ctx           Onion context
 * @param circuit       The circuit
 * @param stream_id     Stream ID (0 = default stream)
 * @param data          Data to send
 * @param len           Data length
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_send_stream(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id,
    const uint8_t *data,
    size_t len
);

/*
 * Close a stream
 *
 * @param circuit       The circuit
 * @param stream_id     Stream ID to close
 */
void cyxwiz_circuit_close_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id
);

/*
 * Get stream by ID on a circuit
 */
cyxwiz_stream_t *cyxwiz_circuit_get_stream(
    cyxwiz_circuit_t *circuit,
    uint16_t stream_id
);

/* ============ Message Handling ============ */

/*
 * Handle incoming onion message
 * Called by router when CYXWIZ_MSG_ONION_DATA received
 *
 * @param ctx           Onion context
 * @param from          Immediate sender (previous hop)
 * @param data          Raw packet data
 * @param len           Packet length
 * @return              CYXWIZ_OK if handled
 */
cyxwiz_error_t cyxwiz_onion_handle_message(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

/* ============ Low-Level Operations ============ */

/*
 * Wrap payload in onion layers (build onion from inside out)
 *
 * @param payload        The payload to wrap
 * @param payload_len    Payload length
 * @param hops           Array of hop node IDs
 * @param keys           Array of per-hop keys (one per hop)
 * @param ephemeral_pubs Array of ephemeral public keys (one per hop)
 * @param hop_count      Number of hops
 * @param onion_out      Output buffer (must be large enough)
 * @param onion_len      Output: actual onion length
 * @return               CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_wrap(
    const uint8_t *payload,
    size_t payload_len,
    const cyxwiz_node_id_t *hops,
    const uint8_t (*keys)[CYXWIZ_KEY_SIZE],
    const uint8_t (*ephemeral_pubs)[CYXWIZ_EPHEMERAL_SIZE],
    uint8_t hop_count,
    uint8_t *onion_out,
    size_t *onion_len
);

/*
 * Unwrap one onion layer (peel outer encryption)
 *
 * @param onion             The onion data
 * @param onion_len         Onion length
 * @param key               Key for this layer
 * @param next_hop_out      Output: next hop (zeros if final destination)
 * @param next_ephemeral_out Output: ephemeral key for next hop (NULL if not needed)
 * @param inner_out         Output: inner data
 * @param inner_len         Output: inner data length
 * @return                  CYXWIZ_OK on success, CYXWIZ_ERR_CRYPTO if tampered
 */
cyxwiz_error_t cyxwiz_onion_unwrap(
    const uint8_t *onion,
    size_t onion_len,
    const uint8_t *key,
    cyxwiz_node_id_t *next_hop_out,
    uint8_t *next_ephemeral_out,
    uint8_t *inner_out,
    size_t *inner_len
);

/*
 * Check if node ID is all zeros (final destination marker)
 */
bool cyxwiz_node_id_is_zero(const cyxwiz_node_id_t *id);

/* ============ Statistics ============ */

/*
 * Get onion routing statistics
 */
size_t cyxwiz_onion_circuit_count(const cyxwiz_onion_ctx_t *ctx);
size_t cyxwiz_onion_peer_key_count(const cyxwiz_onion_ctx_t *ctx);

/* ============ Guard Node Management ============ */

/*
 * Guard node entry
 */
typedef struct {
    cyxwiz_node_id_t id;                     /* Guard node ID */
    uint64_t selected_at;                    /* When guard was selected */
    bool valid;
} cyxwiz_guard_t;

/*
 * Save guard nodes to file
 *
 * @param ctx   Onion context
 * @param path  File path
 * @return      CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_save_guards(
    const cyxwiz_onion_ctx_t *ctx,
    const char *path
);

/*
 * Load guard nodes from file
 *
 * @param ctx   Onion context
 * @param path  File path
 * @return      CYXWIZ_OK on success (or if file doesn't exist)
 */
cyxwiz_error_t cyxwiz_onion_load_guards(
    cyxwiz_onion_ctx_t *ctx,
    const char *path
);

/* ============ Key Pinning ============ */

/*
 * Save pinned keys to file for MITM detection persistence
 *
 * @param ctx   Onion context
 * @param path  File path
 * @return      CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_onion_save_pinned_keys(
    const cyxwiz_onion_ctx_t *ctx,
    const char *path
);

/*
 * Load pinned keys from file
 *
 * @param ctx   Onion context
 * @param path  File path
 * @return      CYXWIZ_OK on success (or if file doesn't exist)
 */
cyxwiz_error_t cyxwiz_onion_load_pinned_keys(
    cyxwiz_onion_ctx_t *ctx,
    const char *path
);

/* ============ Cover Traffic ============ */

/*
 * Enable or disable cover traffic generation
 *
 * @param ctx     Onion context
 * @param enable  true to enable, false to disable
 */
void cyxwiz_onion_enable_cover_traffic(
    cyxwiz_onion_ctx_t *ctx,
    bool enable
);

/*
 * Check if cover traffic is enabled
 */
bool cyxwiz_onion_cover_traffic_enabled(const cyxwiz_onion_ctx_t *ctx);

/* ============ Hidden Services ============ */

/* Hidden service constants */
#define CYXWIZ_MAX_HIDDEN_SERVICES 4        /* Max hosted services */
#define CYXWIZ_SERVICE_INTRO_POINTS 3       /* Introduction points per service */
#define CYXWIZ_SERVICE_SURBS_PER_INTRO 2    /* SURBs per introduction point */
#define CYXWIZ_SERVICE_DESCRIPTOR_TTL_MS 300000  /* Descriptor valid for 5 minutes */
#define CYXWIZ_MAX_SERVICE_CONNECTIONS 8    /* Max client-side connections */

/* Rendezvous point constants */
#define CYXWIZ_MAX_RENDEZVOUS 8             /* Max concurrent rendezvous points */
#define CYXWIZ_RENDEZVOUS_COOKIE_SIZE 20    /* Rendezvous cookie size */
#define CYXWIZ_RENDEZVOUS_TIMEOUT_MS 60000  /* Rendezvous expires after 60s */

/*
 * Rendezvous point context
 * Manages a rendezvous point that bridges client and service circuits.
 */
typedef struct {
    uint8_t cookie[CYXWIZ_RENDEZVOUS_COOKIE_SIZE]; /* Rendezvous cookie (random) */
    uint32_t client_circuit_id;           /* Circuit from client */
    uint32_t service_circuit_id;          /* Circuit from service */
    cyxwiz_node_id_t client_id;           /* Client node ID */
    cyxwiz_node_id_t service_id;          /* Service node ID */
    uint64_t established_at;              /* When first party arrived */
    bool client_ready;                    /* Client has connected */
    bool service_ready;                   /* Service has connected */
    bool bridged;                         /* Both sides connected, bridge active */
} cyxwiz_rendezvous_t;

/*
 * Client-side rendezvous state
 * Tracks a pending or active connection to a hidden service.
 */
typedef struct {
    cyxwiz_node_id_t service_id;          /* Target service ID */
    uint8_t service_pubkey[CYXWIZ_PUBKEY_SIZE]; /* Service's X25519 public key */
    cyxwiz_node_id_t rendezvous_point;    /* Selected RP node */
    uint8_t rendezvous_cookie[CYXWIZ_RENDEZVOUS_COOKIE_SIZE]; /* Cookie for this connection */
    uint32_t rp_circuit_id;               /* Circuit to RP */
    uint8_t client_ephemeral_pub[CYXWIZ_PUBKEY_SIZE]; /* Client's ephemeral key for this connection */
    uint8_t client_ephemeral_sk[CYXWIZ_KEY_SIZE]; /* Client's ephemeral secret key */
    uint8_t shared_secret[CYXWIZ_KEY_SIZE]; /* Derived shared secret with service */
    bool rp_ready;                        /* RENDEZVOUS1 acknowledged */
    bool connected;                       /* INTRODUCE_ACK received, service connected */
    uint64_t started_at;                  /* Connection start time */
} cyxwiz_service_conn_t;

/*
 * Service descriptor (published to introduction points)
 * Contains everything needed for a client to connect to the service.
 */
typedef struct {
    cyxwiz_node_id_t service_id;              /* Derived from service pubkey */
    uint8_t service_pubkey[CYXWIZ_PUBKEY_SIZE]; /* X25519 public key for encryption */
    uint64_t created_at;                      /* Descriptor creation timestamp */
    uint16_t version;                         /* Protocol version */
} cyxwiz_service_descriptor_t;

/*
 * Hidden service context
 * Represents a hosted anonymous service.
 */
typedef struct {
    cyxwiz_node_id_t service_id;              /* Service identifier (derived from pubkey) */
    uint8_t secret_key[CYXWIZ_KEY_SIZE];      /* X25519 secret key */
    uint8_t public_key[CYXWIZ_PUBKEY_SIZE];   /* X25519 public key */
    cyxwiz_node_id_t intro_points[CYXWIZ_SERVICE_INTRO_POINTS]; /* Introduction point nodes */
    uint64_t last_publish_ms;                 /* Last descriptor publish time */
    bool active;                              /* Service is running */
    cyxwiz_delivery_callback_t callback;      /* Callback for incoming data */
    void *user_data;                          /* User callback context */
} cyxwiz_hidden_service_t;

/*
 * Create a new hidden service
 *
 * Generates a new X25519 keypair and derives the service ID.
 *
 * @param ctx           Onion context
 * @param service_out   Output service pointer
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_hidden_service_create(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t **service_out
);

/*
 * Publish service to introduction points
 *
 * Selects introduction points and publishes the service descriptor.
 * Must be called after cyxwiz_hidden_service_create to make the
 * service reachable.
 *
 * @param ctx       Onion context
 * @param service   The service to publish
 * @return          CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_hidden_service_publish(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t *service
);

/*
 * Set callback for incoming service connections
 *
 * @param service   The hidden service
 * @param callback  Function to call when data arrives
 * @param user_data User context passed to callback
 */
void cyxwiz_hidden_service_set_callback(
    cyxwiz_hidden_service_t *service,
    cyxwiz_delivery_callback_t callback,
    void *user_data
);

/*
 * Connect to a hidden service as a client
 *
 * Fetches the service descriptor from introduction points and
 * establishes a connection.
 *
 * @param ctx           Onion context
 * @param service_id    Target service ID
 * @param service_pubkey Service's X25519 public key (32 bytes)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_hidden_service_connect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *service_pubkey
);

/*
 * Send data to a hidden service
 *
 * @param ctx           Onion context
 * @param service_id    Target service ID
 * @param data          Data to send
 * @param len           Data length
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_hidden_service_send(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *data,
    size_t len
);

/*
 * Destroy a hidden service
 *
 * Stops the service and clears all keys.
 *
 * @param ctx       Onion context
 * @param service   Service to destroy
 */
void cyxwiz_hidden_service_destroy(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_hidden_service_t *service
);

/*
 * Get number of active hidden services
 */
size_t cyxwiz_hidden_service_count(const cyxwiz_onion_ctx_t *ctx);

/* ============ Rendezvous Point API ============ */

/*
 * Connect to a hidden service via rendezvous point
 *
 * Full Tor-style connection:
 * 1. Client selects random node as RP
 * 2. Client builds circuit to RP and sends RENDEZVOUS1
 * 3. Client sends INTRODUCE1 via intro point to service
 * 4. Service builds circuit to RP and sends RENDEZVOUS2
 * 5. RP bridges the two circuits
 *
 * @param ctx           Onion context
 * @param service_id    Target service ID
 * @param service_pubkey Service's X25519 public key (32 bytes)
 * @param intro_point   Introduction point to use (NULL to auto-select)
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_rendezvous_connect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *service_pubkey,
    const cyxwiz_node_id_t *intro_point
);

/*
 * Send data to a hidden service via rendezvous
 *
 * @param ctx           Onion context
 * @param service_id    Target service ID
 * @param data          Data to send
 * @param len           Data length
 * @return              CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_rendezvous_send(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id,
    const uint8_t *data,
    size_t len
);

/*
 * Check if connected to a hidden service via rendezvous
 */
bool cyxwiz_rendezvous_is_connected(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id
);

/*
 * Disconnect from a hidden service
 */
void cyxwiz_rendezvous_disconnect(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *service_id
);

/*
 * Get number of active rendezvous points (this node as RP)
 */
size_t cyxwiz_rendezvous_count(const cyxwiz_onion_ctx_t *ctx);

/*
 * Handle direct rendezvous messages (not onion-wrapped)
 * Called by router when receiving message types 0x85-0x89
 *
 * @param ctx   Onion context
 * @param from  Sender node ID
 * @param data  Raw message data (includes type byte)
 * @param len   Message length
 * @return      CYXWIZ_OK if handled
 */
cyxwiz_error_t cyxwiz_onion_handle_direct_message(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len
);

#endif /* CYXWIZ_ONION_H */
