/*
 * CyxWiz Protocol - Peer Discovery
 *
 * Implements the discovery protocol:
 * - Broadcasts announcements to find peers
 * - Responds to announcements from others
 * - Maintains keepalives with connected peers
 */

#include "cyxwiz/peer.h"
#include "cyxwiz/zkp.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>

/* Protocol versions */
#define CYXWIZ_PROTOCOL_VERSION_V1 1   /* Original, no identity proof */
#define CYXWIZ_PROTOCOL_VERSION_V2 2   /* With Schnorr identity proof */

/* Default to v2 when identity is set, v1 otherwise */
#define CYXWIZ_PROTOCOL_VERSION CYXWIZ_PROTOCOL_VERSION_V1

/* Context string for announce proofs */
static const char *ANNOUNCE_PROOF_CONTEXT = "cyxwiz_announce_v2";

/*
 * Discovery context
 */
struct cyxwiz_discovery {
    cyxwiz_peer_table_t *peer_table;
    cyxwiz_transport_t *transport;
    cyxwiz_node_id_t local_id;
    uint8_t capabilities;
    bool running;
    uint64_t last_announce;
    uint64_t last_cleanup;

    /* X25519 public key for onion routing (v1 mode) */
    uint8_t pubkey[CYXWIZ_PUBKEY_SIZE];
    bool has_pubkey;

    /* Ed25519 identity keypair for authenticated announcements (v2 mode) */
    cyxwiz_identity_keypair_t identity;
    bool has_identity;

    /* Key exchange callback */
    cyxwiz_key_exchange_cb_t key_callback;
    void *key_user_data;
};

/*
 * Create discovery context
 */
cyxwiz_error_t cyxwiz_discovery_create(
    cyxwiz_discovery_t **discovery,
    cyxwiz_peer_table_t *peer_table,
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id)
{
    if (discovery == NULL || peer_table == NULL || transport == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_discovery_t *d = cyxwiz_calloc(1, sizeof(cyxwiz_discovery_t));
    if (d == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    d->peer_table = peer_table;
    d->transport = transport;
    memcpy(&d->local_id, local_id, sizeof(cyxwiz_node_id_t));
    d->capabilities = CYXWIZ_PEER_CAP_RELAY;  /* Default: relay only */
    d->running = false;
    d->last_announce = 0;
    d->last_cleanup = 0;

    /* Initialize key exchange fields */
    memset(d->pubkey, 0, sizeof(d->pubkey));
    d->has_pubkey = false;
    memset(&d->identity, 0, sizeof(d->identity));
    d->has_identity = false;
    d->key_callback = NULL;
    d->key_user_data = NULL;

    *discovery = d;

    char hex_id[65];
    cyxwiz_node_id_to_hex(local_id, hex_id);
    CYXWIZ_INFO("Created discovery context for node %.16s...", hex_id);

    return CYXWIZ_OK;
}

/*
 * Destroy discovery context
 */
void cyxwiz_discovery_destroy(cyxwiz_discovery_t *discovery)
{
    if (discovery == NULL) {
        return;
    }

    if (discovery->running) {
        cyxwiz_discovery_stop(discovery);
    }

    cyxwiz_free(discovery, sizeof(cyxwiz_discovery_t));
    CYXWIZ_DEBUG("Destroyed discovery context");
}

/*
 * Set key exchange callback
 */
void cyxwiz_discovery_set_key_callback(
    cyxwiz_discovery_t *discovery,
    cyxwiz_key_exchange_cb_t callback,
    void *user_data)
{
    if (discovery == NULL) {
        return;
    }
    discovery->key_callback = callback;
    discovery->key_user_data = user_data;
}

/*
 * Set public key for announcements (v1 mode)
 */
void cyxwiz_discovery_set_pubkey(
    cyxwiz_discovery_t *discovery,
    const uint8_t *pubkey)
{
    if (discovery == NULL || pubkey == NULL) {
        return;
    }
    memcpy(discovery->pubkey, pubkey, CYXWIZ_PUBKEY_SIZE);
    discovery->has_pubkey = true;
    CYXWIZ_DEBUG("Set X25519 public key for discovery (v1 mode)");
}

/*
 * Set identity keypair for authenticated announcements (v2 mode)
 */
void cyxwiz_discovery_set_identity(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_identity_keypair_t *identity)
{
    if (discovery == NULL || identity == NULL) {
        return;
    }
    memcpy(&discovery->identity, identity, sizeof(cyxwiz_identity_keypair_t));
    discovery->has_identity = true;

    /* Also derive and set X25519 pubkey for backwards compatibility */
    cyxwiz_identity_to_x25519_pk(identity, discovery->pubkey);
    discovery->has_pubkey = true;

    CYXWIZ_DEBUG("Set Ed25519 identity for discovery (v2 mode)");
}

/*
 * Send announcement message
 */
static cyxwiz_error_t send_announce(cyxwiz_discovery_t *discovery)
{
    /* Broadcast to all (use 0xFF ID for broadcast) */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    cyxwiz_error_t err;

    /* Use v2 format if we have an identity keypair */
    if (discovery->has_identity) {
        cyxwiz_disc_announce_v2_t msg;
        memset(&msg, 0, sizeof(msg));

        msg.type = CYXWIZ_DISC_ANNOUNCE;
        msg.version = CYXWIZ_PROTOCOL_VERSION_V2;
        memcpy(&msg.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
        msg.capabilities = discovery->capabilities;
        msg.port = 0;

        /* Include Ed25519 public key */
        memcpy(msg.ed25519_pubkey, discovery->identity.public_key,
               CYXWIZ_ED25519_PK_SIZE);

        /* Generate Schnorr identity proof */
        cyxwiz_proof_context_t ctx;
        cyxwiz_proof_context_init(&ctx, (const uint8_t *)ANNOUNCE_PROOF_CONTEXT,
                                   strlen(ANNOUNCE_PROOF_CONTEXT));

        err = cyxwiz_schnorr_prove(&discovery->identity, &ctx, &msg.identity_proof);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to generate identity proof for announce");
            return err;
        }

        err = discovery->transport->ops->send(
            discovery->transport,
            &broadcast_id,
            (uint8_t *)&msg,
            sizeof(msg)
        );

        if (err == CYXWIZ_OK) {
            CYXWIZ_DEBUG("Sent discovery announcement (v2 with identity proof)");
        }
    } else {
        /* Fall back to v1 format */
        cyxwiz_disc_announce_t msg;
        memset(&msg, 0, sizeof(msg));

        msg.type = CYXWIZ_DISC_ANNOUNCE;
        msg.version = CYXWIZ_PROTOCOL_VERSION_V1;
        memcpy(&msg.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
        msg.capabilities = discovery->capabilities;
        msg.port = 0;

        /* Include X25519 public key if available */
        if (discovery->has_pubkey) {
            memcpy(msg.pubkey, discovery->pubkey, CYXWIZ_PUBKEY_SIZE);
        }

        err = discovery->transport->ops->send(
            discovery->transport,
            &broadcast_id,
            (uint8_t *)&msg,
            sizeof(msg)
        );

        if (err == CYXWIZ_OK) {
            CYXWIZ_DEBUG("Sent discovery announcement (v1)");
        }
    }

    return err;
}

/*
 * Send pong in response to ping
 */
static cyxwiz_error_t send_pong(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *peer_id,
    uint64_t echo_timestamp)
{
    cyxwiz_disc_pong_t msg;
    msg.type = CYXWIZ_DISC_PONG;
    msg.echo_timestamp = echo_timestamp;

    return discovery->transport->ops->send(
        discovery->transport,
        peer_id,
        (uint8_t *)&msg,
        sizeof(msg)
    );
}

/*
 * Send announcement ACK (can be v1 or v2 depending on identity)
 */
static cyxwiz_error_t send_announce_ack(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *to)
{
    cyxwiz_error_t err;

    /* Use v2 format if we have an identity keypair */
    if (discovery->has_identity) {
        cyxwiz_disc_announce_v2_t ack;
        memset(&ack, 0, sizeof(ack));

        ack.type = CYXWIZ_DISC_ANNOUNCE_ACK;
        ack.version = CYXWIZ_PROTOCOL_VERSION_V2;
        memcpy(&ack.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
        ack.capabilities = discovery->capabilities;
        ack.port = 0;

        /* Include Ed25519 public key */
        memcpy(ack.ed25519_pubkey, discovery->identity.public_key,
               CYXWIZ_ED25519_PK_SIZE);

        /* Generate Schnorr identity proof */
        cyxwiz_proof_context_t ctx;
        cyxwiz_proof_context_init(&ctx, (const uint8_t *)ANNOUNCE_PROOF_CONTEXT,
                                   strlen(ANNOUNCE_PROOF_CONTEXT));

        err = cyxwiz_schnorr_prove(&discovery->identity, &ctx, &ack.identity_proof);
        if (err != CYXWIZ_OK) {
            return err;
        }

        return discovery->transport->ops->send(
            discovery->transport,
            to,
            (uint8_t *)&ack,
            sizeof(ack)
        );
    } else {
        /* Fall back to v1 format */
        cyxwiz_disc_announce_t ack;
        memset(&ack, 0, sizeof(ack));

        ack.type = CYXWIZ_DISC_ANNOUNCE_ACK;
        ack.version = CYXWIZ_PROTOCOL_VERSION_V1;
        memcpy(&ack.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
        ack.capabilities = discovery->capabilities;
        ack.port = 0;

        if (discovery->has_pubkey) {
            memcpy(ack.pubkey, discovery->pubkey, CYXWIZ_PUBKEY_SIZE);
        }

        return discovery->transport->ops->send(
            discovery->transport,
            to,
            (uint8_t *)&ack,
            sizeof(ack)
        );
    }
}

/*
 * Handle v1 announcement (no identity proof)
 */
static cyxwiz_error_t handle_announce_v1(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_disc_announce_t *msg,
    bool is_ack)
{
    /* Add peer to table */
    cyxwiz_error_t err = cyxwiz_peer_table_add(
        discovery->peer_table,
        &msg->node_id,
        discovery->transport->type,
        0
    );

    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Update capabilities */
    cyxwiz_peer_table_set_capabilities(
        discovery->peer_table,
        &msg->node_id,
        msg->capabilities
    );

    /* Notify key exchange callback if pubkey present */
    if (discovery->key_callback != NULL) {
        bool has_pubkey = false;
        for (size_t i = 0; i < CYXWIZ_PUBKEY_SIZE; i++) {
            if (msg->pubkey[i] != 0) {
                has_pubkey = true;
                break;
            }
        }
        if (has_pubkey) {
            discovery->key_callback(&msg->node_id, msg->pubkey,
                                   discovery->key_user_data);
        }
    }

    /* If it's an ACK, mark peer as connected */
    if (is_ack) {
        cyxwiz_peer_table_set_state(
            discovery->peer_table,
            &msg->node_id,
            CYXWIZ_PEER_STATE_CONNECTED
        );
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(&msg->node_id, hex_id);
    CYXWIZ_DEBUG("Processed v1 %s from %.16s... (unverified identity)",
                 is_ack ? "ACK" : "ANNOUNCE", hex_id);

    return CYXWIZ_OK;
}

/*
 * Handle v2 announcement (with identity proof)
 */
static cyxwiz_error_t handle_announce_v2(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_disc_announce_v2_t *msg,
    bool is_ack)
{
    char hex_id[65];
    cyxwiz_node_id_to_hex(&msg->node_id, hex_id);

    /* Verify the node ID matches the Ed25519 public key */
    if (!cyxwiz_identity_verify_node_id(msg->ed25519_pubkey, &msg->node_id)) {
        CYXWIZ_WARN("v2 announce from %.16s...: node ID doesn't match pubkey",
                    hex_id);
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* Verify the Schnorr identity proof */
    cyxwiz_proof_context_t ctx;
    cyxwiz_proof_context_init(&ctx, (const uint8_t *)ANNOUNCE_PROOF_CONTEXT,
                               strlen(ANNOUNCE_PROOF_CONTEXT));

    cyxwiz_error_t err = cyxwiz_schnorr_verify(
        msg->ed25519_pubkey,
        &msg->identity_proof,
        &ctx
    );

    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("v2 announce from %.16s...: identity proof invalid", hex_id);
        return CYXWIZ_ERR_PROOF_INVALID;
    }

    /* Proof is valid! Add peer to table */
    err = cyxwiz_peer_table_add(
        discovery->peer_table,
        &msg->node_id,
        discovery->transport->type,
        0
    );

    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Update capabilities */
    cyxwiz_peer_table_set_capabilities(
        discovery->peer_table,
        &msg->node_id,
        msg->capabilities
    );

    /* Mark identity as verified */
    cyxwiz_peer_table_set_identity_verified(
        discovery->peer_table,
        &msg->node_id,
        msg->ed25519_pubkey
    );

    /* Derive X25519 public key from Ed25519 and notify callback */
    if (discovery->key_callback != NULL) {
        uint8_t x25519_pubkey[CYXWIZ_PUBKEY_SIZE];
        /* Create a temporary keypair just for conversion */
        cyxwiz_identity_keypair_t temp_kp;
        memcpy(temp_kp.public_key, msg->ed25519_pubkey, CYXWIZ_ED25519_PK_SIZE);
        memset(temp_kp.secret_key, 0, sizeof(temp_kp.secret_key));

        if (cyxwiz_identity_to_x25519_pk(&temp_kp, x25519_pubkey) == CYXWIZ_OK) {
            discovery->key_callback(&msg->node_id, x25519_pubkey,
                                   discovery->key_user_data);
        }
    }

    /* If it's an ACK, mark peer as connected */
    if (is_ack) {
        cyxwiz_peer_table_set_state(
            discovery->peer_table,
            &msg->node_id,
            CYXWIZ_PEER_STATE_CONNECTED
        );
    }

    CYXWIZ_DEBUG("Processed v2 %s from %.16s... (identity VERIFIED)",
                 is_ack ? "ACK" : "ANNOUNCE", hex_id);

    return CYXWIZ_OK;
}

/*
 * Handle announcement message (dispatches to v1 or v2 handler)
 */
static cyxwiz_error_t handle_announce(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    bool is_ack)
{
    CYXWIZ_UNUSED(from);

    if (len < 2) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t version = data[1];

    /* Check for own announcements by peeking at node_id field */
    if (len >= sizeof(cyxwiz_disc_announce_t)) {
        const cyxwiz_disc_announce_t *base = (const cyxwiz_disc_announce_t *)data;
        if (cyxwiz_node_id_cmp(&base->node_id, &discovery->local_id) == 0) {
            return CYXWIZ_OK;  /* Ignore our own */
        }
    }

    cyxwiz_error_t err;

    if (version == CYXWIZ_PROTOCOL_VERSION_V2) {
        if (len < sizeof(cyxwiz_disc_announce_v2_t)) {
            CYXWIZ_WARN("v2 announce too short: %zu < %zu",
                        len, sizeof(cyxwiz_disc_announce_v2_t));
            return CYXWIZ_ERR_INVALID;
        }
        err = handle_announce_v2(discovery, (const cyxwiz_disc_announce_v2_t *)data, is_ack);
    } else if (version == CYXWIZ_PROTOCOL_VERSION_V1) {
        if (len < sizeof(cyxwiz_disc_announce_t)) {
            return CYXWIZ_ERR_INVALID;
        }
        err = handle_announce_v1(discovery, (const cyxwiz_disc_announce_t *)data, is_ack);
    } else {
        CYXWIZ_WARN("Unknown announce version: %d", version);
        return CYXWIZ_OK;  /* Ignore unknown versions */
    }

    /* Send ACK if this was an announce (not an ACK) */
    if (!is_ack && err == CYXWIZ_OK) {
        const cyxwiz_disc_announce_t *base = (const cyxwiz_disc_announce_t *)data;
        send_announce_ack(discovery, &base->node_id);
    }

    return err;
}

/*
 * Handle ping message
 */
static cyxwiz_error_t handle_ping(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const cyxwiz_disc_ping_t *msg)
{
    /* Update last seen */
    const cyxwiz_peer_t *peer = cyxwiz_peer_table_find(discovery->peer_table, from);
    if (peer != NULL) {
        cyxwiz_peer_table_set_state(discovery->peer_table, from, peer->state);
    }

    /* Send pong */
    return send_pong(discovery, from, msg->timestamp);
}

/*
 * Handle pong message
 */
static cyxwiz_error_t handle_pong(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const cyxwiz_disc_pong_t *msg)
{
    uint64_t now = cyxwiz_time_ms();
    uint64_t latency = now - msg->echo_timestamp;

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);
    CYXWIZ_DEBUG("Pong from %.16s..., latency: %llu ms", hex_id, (unsigned long long)latency);

    /* Update peer state */
    cyxwiz_peer_table_set_state(discovery->peer_table, from, CYXWIZ_PEER_STATE_CONNECTED);

    return CYXWIZ_OK;
}

/*
 * Start discovery
 */
cyxwiz_error_t cyxwiz_discovery_start(cyxwiz_discovery_t *discovery)
{
    if (discovery == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (discovery->running) {
        return CYXWIZ_OK;
    }

    /* Start transport discovery */
    cyxwiz_error_t err = discovery->transport->ops->discover(discovery->transport);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to start transport discovery");
        return err;
    }

    discovery->running = true;
    discovery->last_announce = 0;  /* Force immediate announce */
    discovery->last_cleanup = cyxwiz_time_ms();

    CYXWIZ_INFO("Discovery started");
    return CYXWIZ_OK;
}

/*
 * Stop discovery
 */
cyxwiz_error_t cyxwiz_discovery_stop(cyxwiz_discovery_t *discovery)
{
    if (discovery == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!discovery->running) {
        return CYXWIZ_OK;
    }

    /* Send goodbye to all connected peers */
    /* TODO: Implement goodbye message */

    discovery->transport->ops->stop_discover(discovery->transport);
    discovery->running = false;

    CYXWIZ_INFO("Discovery stopped");
    return CYXWIZ_OK;
}

/*
 * Poll discovery (call periodically)
 */
cyxwiz_error_t cyxwiz_discovery_poll(
    cyxwiz_discovery_t *discovery,
    uint64_t current_time_ms)
{
    if (discovery == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!discovery->running) {
        return CYXWIZ_OK;
    }

    /* Send periodic announcements */
    if (current_time_ms - discovery->last_announce >= CYXWIZ_DISCOVERY_INTERVAL_MS) {
        send_announce(discovery);
        discovery->last_announce = current_time_ms;
    }

    /* Cleanup stale peers periodically */
    if (current_time_ms - discovery->last_cleanup >= CYXWIZ_PEER_TIMEOUT_MS / 2) {
        cyxwiz_peer_table_cleanup(discovery->peer_table, CYXWIZ_PEER_TIMEOUT_MS);
        discovery->last_cleanup = current_time_ms;
    }

    /* Poll transport for incoming messages */
    discovery->transport->ops->poll(discovery->transport, 0);

    return CYXWIZ_OK;
}

/*
 * Handle incoming discovery message
 */
cyxwiz_error_t cyxwiz_discovery_handle_message(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
    if (discovery == NULL || from == NULL || data == NULL || len == 0) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case CYXWIZ_DISC_ANNOUNCE:
            /* Minimum size is v1, handle_announce will check version */
            if (len >= sizeof(cyxwiz_disc_announce_t)) {
                return handle_announce(discovery, from, data, len, false);
            }
            break;

        case CYXWIZ_DISC_ANNOUNCE_ACK:
            if (len >= sizeof(cyxwiz_disc_announce_t)) {
                return handle_announce(discovery, from, data, len, true);
            }
            break;

        case CYXWIZ_DISC_PING:
            if (len >= sizeof(cyxwiz_disc_ping_t)) {
                return handle_ping(discovery, from, (const cyxwiz_disc_ping_t *)data);
            }
            break;

        case CYXWIZ_DISC_PONG:
            if (len >= sizeof(cyxwiz_disc_pong_t)) {
                return handle_pong(discovery, from, (const cyxwiz_disc_pong_t *)data);
            }
            break;

        case CYXWIZ_DISC_GOODBYE:
            /* Remove peer from table */
            cyxwiz_peer_table_remove(discovery->peer_table, from);
            break;

        default:
            CYXWIZ_WARN("Unknown discovery message type: 0x%02x", msg_type);
            break;
    }

    return CYXWIZ_OK;
}
