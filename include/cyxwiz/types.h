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
    CYXWIZ_ERR_EXHAUSTED = -16,       /* Resource exhausted (e.g., triple pool) */
    CYXWIZ_ERR_JOB_NOT_FOUND = -17,   /* Job not found */
    CYXWIZ_ERR_JOB_INVALID = -18,     /* Invalid job format */
    CYXWIZ_ERR_WORKER_BUSY = -19,     /* Worker at capacity */
    CYXWIZ_ERR_MAC_INVALID = -20,     /* MAC verification failed */
    CYXWIZ_ERR_STORAGE_NOT_FOUND = -21, /* Storage ID not found */
    CYXWIZ_ERR_STORAGE_EXPIRED = -22,   /* Data has expired */
    CYXWIZ_ERR_STORAGE_FULL = -23,      /* Provider storage is full */
    CYXWIZ_ERR_STORAGE_UNAUTHORIZED = -24, /* Not authorized to access */
    CYXWIZ_ERR_INSUFFICIENT_SHARES = -25, /* Not enough shares for reconstruction */
    CYXWIZ_ERR_STORAGE_CORRUPTED = -26, /* Share verification failed */
    CYXWIZ_ERR_POS_NO_COMMITMENT = -27, /* No PoS commitment stored */
    CYXWIZ_ERR_POS_INVALID_PROOF = -28, /* Proof verification failed */
    CYXWIZ_ERR_POS_CHALLENGE_PENDING = -29, /* Challenge already in progress */
    CYXWIZ_ERR_POS_INVALID_BLOCK = -30, /* Block index out of range */
    CYXWIZ_ERR_INSUFFICIENT_RELAYS = -31, /* Not enough relay nodes for SURB */
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
    CYXWIZ_MSG_ONION_DATA = 0x24,     /* Onion-encrypted data packet */
    CYXWIZ_MSG_ANON_ROUTE_REQ = 0x25, /* Anonymous route request */
    CYXWIZ_MSG_ANON_ROUTE_REPLY = 0x26, /* Anonymous route reply */

    /* Compute messages (0x30-0x3F) */
    CYXWIZ_MSG_JOB_SUBMIT = 0x30,     /* Submit job to worker */
    CYXWIZ_MSG_JOB_CHUNK = 0x31,      /* Job payload chunk */
    CYXWIZ_MSG_JOB_ACCEPT = 0x32,     /* Worker accepts job */
    CYXWIZ_MSG_JOB_REJECT = 0x33,     /* Worker rejects job */
    CYXWIZ_MSG_JOB_STATUS = 0x34,     /* Status update */
    CYXWIZ_MSG_JOB_RESULT = 0x35,     /* Result with MAC */
    CYXWIZ_MSG_JOB_RESULT_CHUNK = 0x36, /* Large result chunk */
    CYXWIZ_MSG_JOB_ACK = 0x37,        /* Acknowledge result */
    CYXWIZ_MSG_JOB_CANCEL = 0x38,     /* Cancel job */
    CYXWIZ_MSG_JOB_QUERY = 0x39,      /* Query workers */
    CYXWIZ_MSG_JOB_ANNOUNCE = 0x3A,   /* Worker availability */

    /* Storage messages (0x40-0x4F) */
    CYXWIZ_MSG_STORE_REQ = 0x40,      /* Store share on provider */
    CYXWIZ_MSG_STORE_CHUNK = 0x41,    /* Encrypted data chunk */
    CYXWIZ_MSG_STORE_ACK = 0x42,      /* Provider confirms storage */
    CYXWIZ_MSG_STORE_REJECT = 0x43,   /* Provider rejects storage */
    CYXWIZ_MSG_RETRIEVE_REQ = 0x44,   /* Request share retrieval */
    CYXWIZ_MSG_RETRIEVE_RESP = 0x45,  /* Provider returns share */
    CYXWIZ_MSG_RETRIEVE_CHUNK = 0x46, /* Retrieved data chunk */
    CYXWIZ_MSG_DELETE_REQ = 0x47,     /* Delete stored data */
    CYXWIZ_MSG_DELETE_ACK = 0x48,     /* Deletion confirmed */
    CYXWIZ_MSG_STORAGE_QUERY = 0x49,  /* Query for providers */
    CYXWIZ_MSG_STORAGE_ANNOUNCE = 0x4A, /* Provider availability */

    /* Proof of Storage messages (0x50-0x5F) */
    CYXWIZ_MSG_POS_COMMITMENT = 0x50,     /* Provider sends commitment after store */
    CYXWIZ_MSG_POS_CHALLENGE = 0x51,      /* Owner challenges provider */
    CYXWIZ_MSG_POS_PROOF = 0x52,          /* Provider responds with proof */
    CYXWIZ_MSG_POS_VERIFY_OK = 0x53,      /* Owner confirms proof valid */
    CYXWIZ_MSG_POS_VERIFY_FAIL = 0x54,    /* Owner reports proof invalid */
    CYXWIZ_MSG_POS_REQUEST_COMMIT = 0x55  /* Owner requests commitment (retry) */
} cyxwiz_msg_type_t;

/* Utility macros */
#define CYXWIZ_UNUSED(x) (void)(x)
#define CYXWIZ_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Return error string */
const char *cyxwiz_strerror(cyxwiz_error_t err);

#endif /* CYXWIZ_TYPES_H */
