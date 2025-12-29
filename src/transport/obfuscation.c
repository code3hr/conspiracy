/*
 * CyxWiz Protocol - Pluggable Transports Implementation
 *
 * Implements TLS obfuscation to make protocol traffic appear as HTTPS.
 */

#include "cyxwiz/obfuscation.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

/* Forward declarations for transport ops */
static cyxwiz_error_t obfs_init(cyxwiz_transport_t *transport);
static cyxwiz_error_t obfs_shutdown(cyxwiz_transport_t *transport);
static cyxwiz_error_t obfs_send(cyxwiz_transport_t *transport,
                                 const cyxwiz_node_id_t *dest,
                                 const uint8_t *data,
                                 size_t len);
static cyxwiz_error_t obfs_discover(cyxwiz_transport_t *transport);
static cyxwiz_error_t obfs_stop_discover(cyxwiz_transport_t *transport);
static size_t obfs_max_packet_size(cyxwiz_transport_t *transport);
static cyxwiz_error_t obfs_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms);

/* Internal callback to unwrap received packets */
static void obfs_receive_callback(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data);

/* Transport ops vtable */
static const cyxwiz_transport_ops_t obfs_ops = {
    .init = obfs_init,
    .shutdown = obfs_shutdown,
    .send = obfs_send,
    .discover = obfs_discover,
    .stop_discover = obfs_stop_discover,
    .max_packet_size = obfs_max_packet_size,
    .poll = obfs_poll
};

/* ============ TLS Obfuscation Helpers ============ */

/*
 * Wrap data in TLS Application Data record
 * Format: type(1) + version(2) + length(2) + data
 */
static size_t tls_wrap(const uint8_t *data, size_t len, uint8_t *out)
{
    out[0] = CYXWIZ_TLS_APPLICATION_DATA;  /* Content type: Application Data */
    out[1] = CYXWIZ_TLS_VERSION_MAJOR;     /* TLS 1.2 */
    out[2] = CYXWIZ_TLS_VERSION_MINOR;
    out[3] = (uint8_t)((len >> 8) & 0xFF); /* Length (big-endian) */
    out[4] = (uint8_t)(len & 0xFF);
    memcpy(out + CYXWIZ_TLS_RECORD_HEADER_SIZE, data, len);
    return CYXWIZ_TLS_RECORD_HEADER_SIZE + len;
}

/*
 * Unwrap TLS Application Data record
 * Returns true if valid TLS record, false otherwise
 */
static bool tls_unwrap(const uint8_t *data, size_t len,
                       const uint8_t **payload, size_t *payload_len)
{
    if (len < CYXWIZ_TLS_RECORD_HEADER_SIZE) {
        return false;
    }

    /* Verify content type */
    if (data[0] != CYXWIZ_TLS_APPLICATION_DATA) {
        return false;
    }

    /* Extract length */
    size_t record_len = ((size_t)data[3] << 8) | data[4];

    if (len < CYXWIZ_TLS_RECORD_HEADER_SIZE + record_len) {
        return false;
    }

    *payload = data + CYXWIZ_TLS_RECORD_HEADER_SIZE;
    *payload_len = record_len;
    return true;
}

/* ============ Transport Operations ============ */

static cyxwiz_error_t obfs_init(cyxwiz_transport_t *transport)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Generate random session ID for TLS */
#ifdef CYXWIZ_HAS_CRYPTO
    randombytes_buf(obfs->tls_session_id, sizeof(obfs->tls_session_id));
#else
    memset(obfs->tls_session_id, 0x42, sizeof(obfs->tls_session_id));
#endif

    obfs->tls_seq = 0;

    /* Initialize inner transport */
    cyxwiz_error_t err = CYXWIZ_OK;
    if (obfs->inner->ops->init != NULL) {
        err = obfs->inner->ops->init(obfs->inner);
    }

    /* Set up receive callback interception on inner transport */
    cyxwiz_transport_set_recv_callback(obfs->inner, obfs_receive_callback, obfs);

    CYXWIZ_INFO("Obfuscation transport initialized (type=%d)", obfs->obfs_type);
    return err;
}

static cyxwiz_error_t obfs_shutdown(cyxwiz_transport_t *transport)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Don't shut down inner transport - we don't own it */
    CYXWIZ_INFO("Obfuscation transport shutdown");
    return CYXWIZ_OK;
}

static cyxwiz_error_t obfs_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *dest,
    const uint8_t *data,
    size_t len)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL || dest == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if packet will fit after obfuscation */
    size_t inner_max = obfs->inner->ops->max_packet_size(obfs->inner);
    size_t overhead = 0;

    switch (obfs->obfs_type) {
        case CYXWIZ_OBFS_TLS:
            overhead = CYXWIZ_OBFS_TLS_OVERHEAD;
            break;
        case CYXWIZ_OBFS_NONE:
        default:
            overhead = 0;
            break;
    }

    if (len + overhead > inner_max) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Apply obfuscation */
    uint8_t wrapped[CYXWIZ_MAX_PACKET_SIZE + 16];
    size_t wrapped_len;

    switch (obfs->obfs_type) {
        case CYXWIZ_OBFS_TLS:
            wrapped_len = tls_wrap(data, len, wrapped);
            break;

        case CYXWIZ_OBFS_NONE:
        default:
            memcpy(wrapped, data, len);
            wrapped_len = len;
            break;
    }

    /* Forward to inner transport */
    return obfs->inner->ops->send(obfs->inner, dest, wrapped, wrapped_len);
}

static cyxwiz_error_t obfs_discover(cyxwiz_transport_t *transport)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Forward to inner transport */
    return obfs->inner->ops->discover(obfs->inner);
}

static cyxwiz_error_t obfs_stop_discover(cyxwiz_transport_t *transport)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    return obfs->inner->ops->stop_discover(obfs->inner);
}

static size_t obfs_max_packet_size(cyxwiz_transport_t *transport)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL) {
        return 0;
    }

    size_t inner_max = obfs->inner->ops->max_packet_size(obfs->inner);
    size_t overhead = 0;

    switch (obfs->obfs_type) {
        case CYXWIZ_OBFS_TLS:
            overhead = CYXWIZ_OBFS_TLS_OVERHEAD;
            break;
        case CYXWIZ_OBFS_NONE:
        default:
            overhead = 0;
            break;
    }

    if (inner_max <= overhead) {
        return 0;
    }

    return inner_max - overhead;
}

static cyxwiz_error_t obfs_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    if (obfs == NULL || obfs->inner == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Poll inner transport - received packets will be unwrapped in callback */
    return obfs->inner->ops->poll(obfs->inner, timeout_ms);
}

/* Internal callback to unwrap received packets */
static void obfs_receive_callback(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    CYXWIZ_UNUSED(transport);

    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)user_data;
    if (obfs == NULL) {
        return;
    }

    const uint8_t *payload = data;
    size_t payload_len = len;

    /* Remove obfuscation */
    switch (obfs->obfs_type) {
        case CYXWIZ_OBFS_TLS:
            if (!tls_unwrap(data, len, &payload, &payload_len)) {
                /* Not a valid TLS record - might be unobfuscated or corrupted */
                /* Pass through anyway for backwards compatibility */
                payload = data;
                payload_len = len;
            }
            break;

        case CYXWIZ_OBFS_NONE:
        default:
            /* No unwrapping needed */
            break;
    }

    /* Forward to user callback on the base transport */
    if (obfs->base.on_recv != NULL) {
        obfs->base.on_recv(&obfs->base, from, payload, payload_len, obfs->base.recv_user_data);
    }
}

/* ============ Public API ============ */

cyxwiz_error_t cyxwiz_obfs_transport_create(
    cyxwiz_transport_t *inner,
    cyxwiz_obfuscation_type_t type,
    cyxwiz_transport_t **out)
{
    if (inner == NULL || out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_obfs_transport_t *obfs = cyxwiz_calloc(1, sizeof(cyxwiz_obfs_transport_t));
    if (obfs == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    obfs->base.ops = &obfs_ops;
    obfs->base.on_recv = NULL;
    obfs->base.recv_user_data = NULL;
    obfs->base.on_peer = NULL;
    obfs->base.peer_user_data = NULL;
    obfs->inner = inner;
    obfs->obfs_type = type;

    *out = &obfs->base;
    return CYXWIZ_OK;
}

void cyxwiz_obfs_transport_destroy(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return;
    }

    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;

    /* Clear sensitive data */
    cyxwiz_secure_zero(obfs->tls_session_id, sizeof(obfs->tls_session_id));

    cyxwiz_free(obfs, sizeof(cyxwiz_obfs_transport_t));
}

cyxwiz_transport_t *cyxwiz_obfs_transport_get_inner(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return NULL;
    }

    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    return obfs->inner;
}

cyxwiz_obfuscation_type_t cyxwiz_obfs_transport_get_type(cyxwiz_transport_t *transport)
{
    if (transport == NULL) {
        return CYXWIZ_OBFS_NONE;
    }

    cyxwiz_obfs_transport_t *obfs = (cyxwiz_obfs_transport_t *)transport;
    return obfs->obfs_type;
}
