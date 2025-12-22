/*
 * CyxWiz Protocol - Common Types
 *
 * Core type definitions and error codes used throughout the protocol.
 */

#ifndef CYXWIZ_TYPES_H
#define CYXWIZ_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Version */
#define CYXWIZ_VERSION_MAJOR 0
#define CYXWIZ_VERSION_MINOR 1
#define CYXWIZ_VERSION_PATCH 0

/* Error codes */
typedef enum {
    CYXWIZ_OK = 0,
    CYXWIZ_ERR_NOMEM = -1,          /* Out of memory */
    CYXWIZ_ERR_INVALID = -2,         /* Invalid argument */
    CYXWIZ_ERR_TRANSPORT = -3,       /* Transport error */
    CYXWIZ_ERR_CRYPTO = -4,          /* Cryptographic error */
    CYXWIZ_ERR_TIMEOUT = -5,         /* Operation timed out */
    CYXWIZ_ERR_PEER_NOT_FOUND = -6,  /* Peer not found */
    CYXWIZ_ERR_BUFFER_TOO_SMALL = -7,/* Buffer too small */
    CYXWIZ_ERR_NOT_INITIALIZED = -8, /* Not initialized */
    CYXWIZ_ERR_ALREADY_INIT = -9,    /* Already initialized */
    CYXWIZ_ERR_PACKET_TOO_LARGE = -10,/* Packet exceeds transport MTU */
    CYXWIZ_ERR_NO_ROUTE = -11,        /* No route to destination */
    CYXWIZ_ERR_QUEUE_FULL = -12,      /* Pending queue full */
    CYXWIZ_ERR_TTL_EXPIRED = -13,     /* TTL reached zero */
    CYXWIZ_ERR_NO_KEY = -14,          /* No shared key with peer */
    CYXWIZ_ERR_CIRCUIT_FULL = -15,    /* Circuit table full */
    CYXWIZ_ERR_UNKNOWN = -99
} cyxwiz_error_t;

/* Node ID - 32 bytes (256-bit) */
#define CYXWIZ_NODE_ID_LEN 32
typedef struct {
    uint8_t bytes[CYXWIZ_NODE_ID_LEN];
} cyxwiz_node_id_t;

/* Maximum packet size (constrained by LoRa) */
#define CYXWIZ_MAX_PACKET_SIZE 250

/* Message types */
typedef enum {
    /* Discovery messages (0x01-0x0F) */
    CYXWIZ_MSG_PING = 0x01,
    CYXWIZ_MSG_PONG = 0x02,
    CYXWIZ_MSG_DISCOVER = 0x03,
    CYXWIZ_MSG_ANNOUNCE = 0x04,

    /* Data messages (0x10-0x1F) */
    CYXWIZ_MSG_DATA = 0x10,
    CYXWIZ_MSG_DATA_ACK = 0x11,

    /* Routing messages (0x20-0x2F) */
    CYXWIZ_MSG_ROUTE_REQ = 0x20,      /* Route request (broadcast) */
    CYXWIZ_MSG_ROUTE_REPLY = 0x21,    /* Route reply (unicast) */
    CYXWIZ_MSG_ROUTE_DATA = 0x22,     /* Routed data packet */
    CYXWIZ_MSG_ROUTE_ERROR = 0x23,    /* Route error notification */
    CYXWIZ_MSG_ONION_DATA = 0x24      /* Onion-encrypted data packet */
} cyxwiz_msg_type_t;

/* Utility macros */
#define CYXWIZ_UNUSED(x) (void)(x)
#define CYXWIZ_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Return error string */
const char *cyxwiz_strerror(cyxwiz_error_t err);

#endif /* CYXWIZ_TYPES_H */
