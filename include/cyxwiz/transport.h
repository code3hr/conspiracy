/*
 * CyxWiz Protocol - Transport Abstraction Layer
 *
 * Defines the interface that all transport drivers must implement.
 * This allows the protocol layer to work over WiFi Direct, Bluetooth, LoRa,
 * or any future transport without modification.
 */

#ifndef CYXWIZ_TRANSPORT_H
#define CYXWIZ_TRANSPORT_H

#include "types.h"

/* Transport types */
typedef enum {
    CYXWIZ_TRANSPORT_WIFI_DIRECT,
    CYXWIZ_TRANSPORT_BLUETOOTH,
    CYXWIZ_TRANSPORT_LORA,
    CYXWIZ_TRANSPORT_UDP           /* Internet P2P via UDP */
} cyxwiz_transport_type_t;

/* Forward declaration */
typedef struct cyxwiz_transport cyxwiz_transport_t;

/* Peer info returned by discovery */
typedef struct {
    cyxwiz_node_id_t id;
    int8_t rssi;                    /* Signal strength (dBm) */
    cyxwiz_transport_type_t via;    /* Transport used to reach peer */
} cyxwiz_peer_info_t;

/* Callback for received data */
typedef void (*cyxwiz_recv_callback_t)(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data
);

/* Callback for peer discovery */
typedef void (*cyxwiz_peer_callback_t)(
    cyxwiz_transport_t *transport,
    const cyxwiz_peer_info_t *peer,
    void *user_data
);

/*
 * Transport operations - every driver must implement these
 */
typedef struct {
    /* Initialize the transport driver */
    cyxwiz_error_t (*init)(cyxwiz_transport_t *transport);

    /* Shutdown the transport driver */
    cyxwiz_error_t (*shutdown)(cyxwiz_transport_t *transport);

    /* Send data to a specific peer */
    cyxwiz_error_t (*send)(
        cyxwiz_transport_t *transport,
        const cyxwiz_node_id_t *to,
        const uint8_t *data,
        size_t len
    );

    /* Start peer discovery */
    cyxwiz_error_t (*discover)(cyxwiz_transport_t *transport);

    /* Stop peer discovery */
    cyxwiz_error_t (*stop_discover)(cyxwiz_transport_t *transport);

    /* Get maximum packet size for this transport */
    size_t (*max_packet_size)(cyxwiz_transport_t *transport);

    /* Process events (call periodically) */
    cyxwiz_error_t (*poll)(cyxwiz_transport_t *transport, uint32_t timeout_ms);

} cyxwiz_transport_ops_t;

/*
 * Transport instance
 */
struct cyxwiz_transport {
    cyxwiz_transport_type_t type;
    const cyxwiz_transport_ops_t *ops;
    void *driver_data;              /* Driver-specific state */

    /* Callbacks */
    cyxwiz_recv_callback_t on_recv;
    void *recv_user_data;
    cyxwiz_peer_callback_t on_peer;
    void *peer_user_data;

    /* Our node ID */
    cyxwiz_node_id_t local_id;
};

/*
 * Transport manager API
 */

/* Create a transport instance */
cyxwiz_error_t cyxwiz_transport_create(
    cyxwiz_transport_type_t type,
    cyxwiz_transport_t **out
);

/* Destroy a transport instance */
void cyxwiz_transport_destroy(cyxwiz_transport_t *transport);

/* Set receive callback */
void cyxwiz_transport_set_recv_callback(
    cyxwiz_transport_t *transport,
    cyxwiz_recv_callback_t callback,
    void *user_data
);

/* Set peer discovery callback */
void cyxwiz_transport_set_peer_callback(
    cyxwiz_transport_t *transport,
    cyxwiz_peer_callback_t callback,
    void *user_data
);

/* Set local node ID (required before using transport for peer discovery) */
void cyxwiz_transport_set_local_id(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *local_id
);

/* Get transport type name */
const char *cyxwiz_transport_type_name(cyxwiz_transport_type_t type);

#endif /* CYXWIZ_TRANSPORT_H */
