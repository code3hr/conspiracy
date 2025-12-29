/*
 * CyxWiz Protocol - Pluggable Transports (Traffic Obfuscation)
 *
 * Implements transport wrappers that obfuscate traffic to evade detection:
 * - TLS obfuscation: Makes traffic look like HTTPS
 * - Wraps underlying transports transparently
 */

#ifndef CYXWIZ_OBFUSCATION_H
#define CYXWIZ_OBFUSCATION_H

#include "types.h"
#include "transport.h"

/* Obfuscation overhead constants */
#define CYXWIZ_TLS_RECORD_HEADER_SIZE 5      /* TLS record header: type(1) + version(2) + length(2) */
#define CYXWIZ_OBFS_TLS_OVERHEAD CYXWIZ_TLS_RECORD_HEADER_SIZE

/* TLS record type for application data */
#define CYXWIZ_TLS_APPLICATION_DATA 0x17
#define CYXWIZ_TLS_VERSION_MAJOR 0x03
#define CYXWIZ_TLS_VERSION_MINOR 0x03  /* TLS 1.2 */

/*
 * Obfuscation types
 */
typedef enum {
    CYXWIZ_OBFS_NONE = 0,       /* No obfuscation (passthrough) */
    CYXWIZ_OBFS_TLS = 1,        /* TLS 1.2/1.3 record format */
    CYXWIZ_OBFS_HTTP = 2,       /* HTTP POST/response (future) */
    CYXWIZ_OBFS_DNS = 3         /* DNS query/response (future) */
} cyxwiz_obfuscation_type_t;

/*
 * Obfuscated transport structure
 * Wraps an inner transport and transforms packets.
 */
typedef struct {
    cyxwiz_transport_t base;                /* Base transport interface */
    cyxwiz_transport_t *inner;              /* Wrapped transport */
    cyxwiz_obfuscation_type_t obfs_type;    /* Obfuscation type */

    /* TLS-specific state */
    uint8_t tls_session_id[32];             /* Fake session ID */
    uint16_t tls_seq;                       /* Sequence number for ordering */
} cyxwiz_obfs_transport_t;

/*
 * Create an obfuscated transport wrapping another
 *
 * @param inner     The underlying transport to wrap
 * @param type      Obfuscation type (CYXWIZ_OBFS_TLS recommended)
 * @param out       Output: created obfuscation transport
 * @return          CYXWIZ_OK on success
 */
cyxwiz_error_t cyxwiz_obfs_transport_create(
    cyxwiz_transport_t *inner,
    cyxwiz_obfuscation_type_t type,
    cyxwiz_transport_t **out
);

/*
 * Destroy an obfuscated transport
 * Note: Does NOT destroy the inner transport
 *
 * @param transport The obfuscation transport to destroy
 */
void cyxwiz_obfs_transport_destroy(cyxwiz_transport_t *transport);

/*
 * Get the inner transport
 *
 * @param transport The obfuscation transport
 * @return          The wrapped inner transport
 */
cyxwiz_transport_t *cyxwiz_obfs_transport_get_inner(cyxwiz_transport_t *transport);

/*
 * Get the obfuscation type
 */
cyxwiz_obfuscation_type_t cyxwiz_obfs_transport_get_type(cyxwiz_transport_t *transport);

#endif /* CYXWIZ_OBFUSCATION_H */
