/*
 * CyxWiz Protocol - Bluetooth Mesh Transport Driver
 *
 * Stub implementation - platform-specific code to be added.
 */

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_BLUETOOTH

/* Bluetooth specific state */
typedef struct {
    bool initialized;
    /* TODO: Platform-specific handles */
} bluetooth_state_t;

static cyxwiz_error_t bluetooth_init(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = cyxwiz_calloc(1, sizeof(bluetooth_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* TODO: Initialize Bluetooth
     * - Linux: BlueZ D-Bus API
     * - Windows: Windows.Devices.Bluetooth
     * - Android: BluetoothAdapter
     */

    state->initialized = true;
    transport->driver_data = state;

    CYXWIZ_DEBUG("Bluetooth driver initialized (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_shutdown(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* TODO: Cleanup Bluetooth resources */

    cyxwiz_free(state, sizeof(bluetooth_state_t));
    transport->driver_data = NULL;

    CYXWIZ_DEBUG("Bluetooth driver shutdown");
    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(to);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);

    /* TODO: Send over Bluetooth */
    CYXWIZ_DEBUG("Bluetooth send (stub): %zu bytes", len);
    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    /* TODO: Start Bluetooth discovery */
    CYXWIZ_DEBUG("Bluetooth discover started (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_stop_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    /* TODO: Stop Bluetooth discovery */
    CYXWIZ_DEBUG("Bluetooth discover stopped (stub)");
    return CYXWIZ_OK;
}

static size_t bluetooth_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* BLE has limited MTU, stay compatible with LoRa */
    return CYXWIZ_MAX_PACKET_SIZE;
}

static cyxwiz_error_t bluetooth_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(timeout_ms);

    /* TODO: Poll for incoming data and events */
    return CYXWIZ_OK;
}

const cyxwiz_transport_ops_t cyxwiz_bluetooth_ops = {
    .init = bluetooth_init,
    .shutdown = bluetooth_shutdown,
    .send = bluetooth_send,
    .discover = bluetooth_discover,
    .stop_discover = bluetooth_stop_discover,
    .max_packet_size = bluetooth_max_packet_size,
    .poll = bluetooth_poll
};

#endif /* CYXWIZ_HAS_BLUETOOTH */
