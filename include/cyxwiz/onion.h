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

/*
 * Maximum payload per hop count (with ephemeral keys)
 * Each layer adds: encryption overhead (40) + ephemeral key (32) = 72 bytes
 * Plus next_hop (32) for non-final layers
 * Final layer: zero_hop (32) + payload
 *
 * 1-hop: 250 - 5(hdr) - 32(eph) - 40(enc) - 32(zero_hop) = 141 bytes
 * 2-hop: 141 - 32(eph) - 40(enc) - 32(next_hop) = 37 bytes
 * 3-hop: would be negative, so we limit to 2 hops with ephemeral keys
 *
 * Revised payload sizes:
 */
#define CYXWIZ_ONION_PAYLOAD_1HOP 141   /* 1-hop onion payload */
#define CYXWIZ_ONION_PAYLOAD_2HOP 37    /* 2-hop onion payload */
#define CYXWIZ_ONION_PAYLOAD_3HOP 0     /* 3-hop not supported with ephemeral */

/* Onion message header size: type (1) + circuit_id (4) + ephemeral (32) = 37 bytes */
#define CYXWIZ_ONION_HEADER_SIZE 37

/* Maximum encrypted payload in onion packet */
#define CYXWIZ_ONION_MAX_ENCRYPTED (CYXWIZ_MAX_PACKET_SIZE - CYXWIZ_ONION_HEADER_SIZE)

/* ============ Onion Data Message ============ */

/*
 * Onion-routed data message (0x24)
 * Total packet fits in 250 bytes
 *
 * Format: type (1) + circuit_id (4) + ephemeral_pub (32) + encrypted_data
 * The ephemeral_pub is used by the receiver to derive the layer key via ECDH.
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint8_t type;                        /* CYXWIZ_MSG_ONION_DATA */
    uint32_t circuit_id;                 /* Circuit ID for replies */
    uint8_t ephemeral_pub[CYXWIZ_EPHEMERAL_SIZE]; /* Ephemeral public key for this hop */
    /* encrypted data follows (up to 213 bytes) */
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

#endif /* CYXWIZ_ONION_H */
