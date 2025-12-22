/*
 * CyxWiz Protocol - WiFi Direct Transport Driver
 *
 * Stub implementation - platform-specific code to be added.
 */

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_WIFI

/* WiFi Direct specific state */
typedef struct {
    bool initialized;
    /* TODO: Platform-specific handles */
} wifi_direct_state_t;

static cyxwiz_error_t wifi_direct_init(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = cyxwiz_calloc(1, sizeof(wifi_direct_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* TODO: Initialize WiFi Direct
     * - Linux: wpa_supplicant P2P
     * - Windows: WiFi Direct API
     * - Android: WifiP2pManager
     */

    state->initialized = true;
    transport->driver_data = state;

    CYXWIZ_DEBUG("WiFi Direct driver initialized (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_shutdown(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* TODO: Cleanup WiFi Direct resources */

    cyxwiz_free(state, sizeof(wifi_direct_state_t));
    transport->driver_data = NULL;

    CYXWIZ_DEBUG("WiFi Direct driver shutdown");
    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(to);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);

    /* TODO: Send over WiFi Direct */
    CYXWIZ_DEBUG("WiFi Direct send (stub): %zu bytes", len);
    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    /* TODO: Start P2P discovery */
    CYXWIZ_DEBUG("WiFi Direct discover started (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_stop_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    /* TODO: Stop P2P discovery */
    CYXWIZ_DEBUG("WiFi Direct discover stopped (stub)");
    return CYXWIZ_OK;
}

static size_t wifi_direct_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* WiFi can handle larger packets, but we stay compatible with LoRa */
    return CYXWIZ_MAX_PACKET_SIZE;
}

static cyxwiz_error_t wifi_direct_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(timeout_ms);

    /* TODO: Poll for incoming data and events */
    return CYXWIZ_OK;
}

const cyxwiz_transport_ops_t cyxwiz_wifi_direct_ops = {
    .init = wifi_direct_init,
    .shutdown = wifi_direct_shutdown,
    .send = wifi_direct_send,
    .discover = wifi_direct_discover,
    .stop_discover = wifi_direct_stop_discover,
    .max_packet_size = wifi_direct_max_packet_size,
    .poll = wifi_direct_poll
};

#endif /* CYXWIZ_HAS_WIFI */
