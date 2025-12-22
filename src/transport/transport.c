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
#ifdef CYXWIZ_HAS_WIFI
extern const cyxwiz_transport_ops_t cyxwiz_wifi_direct_ops;
#endif

#ifdef CYXWIZ_HAS_BLUETOOTH
extern const cyxwiz_transport_ops_t cyxwiz_bluetooth_ops;
#endif

#ifdef CYXWIZ_HAS_LORA
extern const cyxwiz_transport_ops_t cyxwiz_lora_ops;
#endif

const char *cyxwiz_transport_type_name(cyxwiz_transport_type_t type)
{
    switch (type) {
        case CYXWIZ_TRANSPORT_WIFI_DIRECT: return "WiFi Direct";
        case CYXWIZ_TRANSPORT_BLUETOOTH:   return "Bluetooth";
        case CYXWIZ_TRANSPORT_LORA:        return "LoRa";
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
#ifdef CYXWIZ_HAS_WIFI
        case CYXWIZ_TRANSPORT_WIFI_DIRECT:
            ops = &cyxwiz_wifi_direct_ops;
            break;
#endif
#ifdef CYXWIZ_HAS_BLUETOOTH
        case CYXWIZ_TRANSPORT_BLUETOOTH:
            ops = &cyxwiz_bluetooth_ops;
            break;
#endif
#ifdef CYXWIZ_HAS_LORA
        case CYXWIZ_TRANSPORT_LORA:
            ops = &cyxwiz_lora_ops;
            break;
#endif
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
        default:                         return "Unknown error";
    }
}
