/*
 * CyxWiz Protocol - Transport Manager
 *
 * Creates and manages transport instances.
 */

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"
#include <string.h>

/* Forward declarations for transport drivers */
extern const cyxwiz_transport_ops_t cyxwiz_udp_ops;

const char *cyxwiz_transport_type_name(cyxwiz_transport_type_t type)
{
    switch (type) {
        case CYXWIZ_TRANSPORT_UDP:         return "UDP/Internet";
        default:                           return "Unknown";
    }
}

cyxwiz_error_t cyxwiz_transport_create(
    cyxwiz_transport_type_t type,
    cyxwiz_transport_t **out)
{
    if (out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    const cyxwiz_transport_ops_t *ops = NULL;

    switch (type) {
        case CYXWIZ_TRANSPORT_UDP:
            ops = &cyxwiz_udp_ops;
            break;
        default:
            CYXWIZ_ERROR("Transport type %d not supported", type);
            return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_transport_t *transport = cyxwiz_calloc(1, sizeof(cyxwiz_transport_t));
    if (transport == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    transport->type = type;
    transport->ops = ops;
    transport->driver_data = NULL;
    transport->on_recv = NULL;
    transport->on_peer = NULL;

    /* Initialize the driver */
    cyxwiz_error_t err = ops->init(transport);
    if (err != CYXWIZ_OK) {
        cyxwiz_free(transport, sizeof(cyxwiz_transport_t));
        return err;
    }

    CYXWIZ_INFO("Created %s transport", cyxwiz_transport_type_name(type));
    *out = transport;
    return CYXWIZ_OK;
}

void cyxwiz_transport_destroy(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return;
    }

    if (transport->ops && transport->ops->shutdown) {
        transport->ops->shutdown(transport);
    }

    CYXWIZ_INFO("Destroyed %s transport", cyxwiz_transport_type_name(transport->type));
    cyxwiz_free(transport, sizeof(cyxwiz_transport_t));
}

void cyxwiz_transport_set_recv_callback(
    cyxwiz_transport_t *transport,
    cyxwiz_recv_callback_t callback,
    void *user_data)
{
    if (transport == NULL) {
        return;
    }
    transport->on_recv = callback;
    transport->recv_user_data = user_data;
}

void cyxwiz_transport_set_peer_callback(
    cyxwiz_transport_t *transport,
    cyxwiz_peer_callback_t callback,
    void *user_data)
{
    if (transport == NULL) {
        return;
    }
    transport->on_peer = callback;
    transport->peer_user_data = user_data;
}

void cyxwiz_transport_set_local_id(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id)
{
    if (transport == NULL || local_id == NULL) {
        return;
    }
    memcpy(&transport->local_id, local_id, sizeof(cyxwiz_node_id_t));
}

/* Error strings */
const char *cyxwiz_strerror(cyxwiz_error_t err)
{
    switch (err) {
        case CYXWIZ_OK:                  return "Success";
        case CYXWIZ_ERR_NOMEM:           return "Out of memory";
        case CYXWIZ_ERR_INVALID:         return "Invalid argument";
        case CYXWIZ_ERR_TRANSPORT:       return "Transport error";
        case CYXWIZ_ERR_CRYPTO:          return "Cryptographic error";
        case CYXWIZ_ERR_TIMEOUT:         return "Operation timed out";
        case CYXWIZ_ERR_PEER_NOT_FOUND:  return "Peer not found";
        case CYXWIZ_ERR_BUFFER_TOO_SMALL:return "Buffer too small";
        case CYXWIZ_ERR_NOT_INITIALIZED: return "Not initialized";
        case CYXWIZ_ERR_ALREADY_INIT:    return "Already initialized";
        case CYXWIZ_ERR_PACKET_TOO_LARGE:return "Packet exceeds transport MTU";
        case CYXWIZ_ERR_NO_ROUTE:        return "No route to destination";
        case CYXWIZ_ERR_QUEUE_FULL:      return "Pending queue full";
        case CYXWIZ_ERR_TTL_EXPIRED:     return "TTL expired";
        case CYXWIZ_ERR_NO_KEY:          return "No shared key with peer";
        case CYXWIZ_ERR_CIRCUIT_FULL:    return "Circuit table full";
        case CYXWIZ_ERR_EXHAUSTED:       return "Resource exhausted";
        default:                         return "Unknown error";
    }
}

const char *cyxwiz_nat_type_name(cyxwiz_nat_type_t type)
{
    switch (type) {
        case CYXWIZ_NAT_UNKNOWN:   return "Unknown";
        case CYXWIZ_NAT_OPEN:      return "Open";
        case CYXWIZ_NAT_CONE:      return "Cone";
        case CYXWIZ_NAT_SYMMETRIC: return "Symmetric";
        case CYXWIZ_NAT_BLOCKED:   return "Blocked";
        default:                   return "Unknown";
    }
}

/* Internal: Get NAT type from UDP driver state */
extern cyxwiz_nat_type_t cyxwiz_udp_get_nat_type(void *driver_data);
/* Internal: Check if bootstrap ACK received from UDP driver state */
extern bool cyxwiz_udp_is_bootstrap_connected(void *driver_data);
/* Internal: Check if peer has direct UDP connection */
extern bool cyxwiz_udp_is_peer_direct(void *driver_data, const cyxwiz_node_id_t *peer_id);

cyxwiz_nat_type_t cyxwiz_transport_get_nat_type(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return CYXWIZ_NAT_UNKNOWN;
    }

    if (transport->type == CYXWIZ_TRANSPORT_UDP && transport->driver_data != NULL) {
        return cyxwiz_udp_get_nat_type(transport->driver_data);
    }

    return CYXWIZ_NAT_UNKNOWN;
}

bool cyxwiz_transport_is_bootstrap_connected(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return false;
    }

    if (transport->type == CYXWIZ_TRANSPORT_UDP && transport->driver_data != NULL) {
        return cyxwiz_udp_is_bootstrap_connected(transport->driver_data);
    }

    return false;
}

bool cyxwiz_transport_is_peer_direct(cyxwiz_transport_t *transport,
                                      const cyxwiz_node_id_t *peer_id)
{
    if (transport == NULL || peer_id == NULL) {
        return false;
    }

    if (transport->type == CYXWIZ_TRANSPORT_UDP && transport->driver_data != NULL) {
        return cyxwiz_udp_is_peer_direct(transport->driver_data, peer_id);
    }

    return false;
}
