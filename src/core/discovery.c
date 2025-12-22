/*
 * CyxWiz Protocol - Peer Discovery
 *
 * Implements the discovery protocol:
 * - Broadcasts announcements to find peers
 * - Responds to announcements from others
 * - Maintains keepalives with connected peers
 */

#include "cyxwiz/peer.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>

/* Protocol version */
#define CYXWIZ_PROTOCOL_VERSION 1

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

    /* X25519 public key for onion routing */
    uint8_t pubkey[CYXWIZ_PUBKEY_SIZE];
    bool has_pubkey;

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
 * Set public key for announcements
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
    CYXWIZ_DEBUG("Set X25519 public key for discovery");
}

/*
 * Send announcement message
 */
static cyxwiz_error_t send_announce(cyxwiz_discovery_t *discovery)
{
    cyxwiz_disc_announce_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.type = CYXWIZ_DISC_ANNOUNCE;
    msg.version = CYXWIZ_PROTOCOL_VERSION;
    memcpy(&msg.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
    msg.capabilities = discovery->capabilities;
    msg.port = 0;  /* Not used for mesh transports */

    /* Include X25519 public key if available */
    if (discovery->has_pubkey) {
        memcpy(msg.pubkey, discovery->pubkey, CYXWIZ_PUBKEY_SIZE);
    }

    /* Broadcast to all (use zero ID for broadcast) */
    cyxwiz_node_id_t broadcast_id;
    memset(&broadcast_id, 0xFF, sizeof(cyxwiz_node_id_t));

    cyxwiz_error_t err = discovery->transport->ops->send(
        discovery->transport,
        &broadcast_id,
        (uint8_t *)&msg,
        sizeof(msg)
    );

    if (err == CYXWIZ_OK) {
        CYXWIZ_DEBUG("Sent discovery announcement");
    }

    return err;
}

/*
 * Send ping to a peer
 */
static cyxwiz_error_t send_ping(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *peer_id)
{
    cyxwiz_disc_ping_t msg;
    msg.type = CYXWIZ_DISC_PING;
    msg.timestamp = cyxwiz_time_ms();

    return discovery->transport->ops->send(
        discovery->transport,
        peer_id,
        (uint8_t *)&msg,
        sizeof(msg)
    );
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
 * Handle announcement message
 */
static cyxwiz_error_t handle_announce(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const cyxwiz_disc_announce_t *msg)
{
    CYXWIZ_UNUSED(from);

    /* Ignore our own announcements */
    if (cyxwiz_node_id_cmp(&msg->node_id, &discovery->local_id) == 0) {
        return CYXWIZ_OK;
    }

    /* Check protocol version */
    if (msg->version != CYXWIZ_PROTOCOL_VERSION) {
        CYXWIZ_WARN("Ignoring announcement with version %d (expected %d)",
                   msg->version, CYXWIZ_PROTOCOL_VERSION);
        return CYXWIZ_OK;
    }

    /* Add peer to table */
    cyxwiz_error_t err = cyxwiz_peer_table_add(
        discovery->peer_table,
        &msg->node_id,
        discovery->transport->type,
        0  /* RSSI not available from message */
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
        /* Check if pubkey is not all zeros */
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

    /* Send acknowledgment (our own announcement) */
    cyxwiz_disc_announce_t ack;
    memset(&ack, 0, sizeof(ack));
    ack.type = CYXWIZ_DISC_ANNOUNCE_ACK;
    ack.version = CYXWIZ_PROTOCOL_VERSION;
    memcpy(&ack.node_id, &discovery->local_id, sizeof(cyxwiz_node_id_t));
    ack.capabilities = discovery->capabilities;
    ack.port = 0;

    /* Include our X25519 public key if available */
    if (discovery->has_pubkey) {
        memcpy(ack.pubkey, discovery->pubkey, CYXWIZ_PUBKEY_SIZE);
    }

    discovery->transport->ops->send(
        discovery->transport,
        &msg->node_id,
        (uint8_t *)&ack,
        sizeof(ack)
    );

    return CYXWIZ_OK;
}

/*
 * Handle announcement acknowledgment
 */
static cyxwiz_error_t handle_announce_ack(
    cyxwiz_discovery_t *discovery,
    const cyxwiz_node_id_t *from,
    const cyxwiz_disc_announce_t *msg)
{
    CYXWIZ_UNUSED(from);

    /* Ignore our own */
    if (cyxwiz_node_id_cmp(&msg->node_id, &discovery->local_id) == 0) {
        return CYXWIZ_OK;
    }

    /* Add/update peer */
    cyxwiz_error_t err = cyxwiz_peer_table_add(
        discovery->peer_table,
        &msg->node_id,
        discovery->transport->type,
        0
    );

    if (err == CYXWIZ_OK) {
        cyxwiz_peer_table_set_capabilities(
            discovery->peer_table,
            &msg->node_id,
            msg->capabilities
        );

        /* Mark as connected since they responded */
        cyxwiz_peer_table_set_state(
            discovery->peer_table,
            &msg->node_id,
            CYXWIZ_PEER_STATE_CONNECTED
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
            if (len >= sizeof(cyxwiz_disc_announce_t)) {
                return handle_announce(discovery, from, (const cyxwiz_disc_announce_t *)data);
            }
            break;

        case CYXWIZ_DISC_ANNOUNCE_ACK:
            if (len >= sizeof(cyxwiz_disc_announce_t)) {
                return handle_announce_ack(discovery, from, (const cyxwiz_disc_announce_t *)data);
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
