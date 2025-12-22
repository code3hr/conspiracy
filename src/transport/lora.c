/*
 * CyxWiz Protocol - LoRa Transport Driver
 *
 * Stub implementation - hardware-specific code to be added.
 * LoRa is critical for long-range, low-power mesh networking.
 */

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_LORA

/* LoRa-specific constraints */
#define LORA_MAX_PACKET_SIZE 250  /* LoRa packet size limit */

/* LoRa specific state */
typedef struct {
    bool initialized;
    /* TODO: Hardware-specific handles
     * - SX1276/SX1278 SPI interface
     * - LoRa frequency, spreading factor, bandwidth
     */
} lora_state_t;

static cyxwiz_error_t lora_init(cyxwiz_transport_t *transport)
{
    lora_state_t *state = cyxwiz_calloc(1, sizeof(lora_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* TODO: Initialize LoRa hardware
     * - Configure SPI
     * - Set frequency (e.g., 915MHz US, 868MHz EU)
     * - Set spreading factor (SF7-SF12)
     * - Set bandwidth
     */

    state->initialized = true;
    transport->driver_data = state;

    CYXWIZ_DEBUG("LoRa driver initialized (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_shutdown(cyxwiz_transport_t *transport)
{
    lora_state_t *state = (lora_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* TODO: Put LoRa radio in sleep mode */

    cyxwiz_free(state, sizeof(lora_state_t));
    transport->driver_data = NULL;

    CYXWIZ_DEBUG("LoRa driver shutdown");
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_send(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *to,
    const uint8_t *data,
    size_t len)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(to);
    CYXWIZ_UNUSED(data);

    if (len > LORA_MAX_PACKET_SIZE) {
        CYXWIZ_ERROR("LoRa packet too large: %zu > %d", len, LORA_MAX_PACKET_SIZE);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* TODO: Transmit via LoRa
     * - Check channel busy (CAD)
     * - Send packet
     * - Wait for TX complete
     */
    CYXWIZ_DEBUG("LoRa send (stub): %zu bytes", len);
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    /* TODO: LoRa discovery
     * - Broadcast beacon
     * - Listen for responses
     * Note: LoRa is half-duplex, need time-slotting
     */
    CYXWIZ_DEBUG("LoRa discover started (stub)");
    return CYXWIZ_OK;
}

static cyxwiz_error_t lora_stop_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);

    CYXWIZ_DEBUG("LoRa discover stopped (stub)");
    return CYXWIZ_OK;
}

static size_t lora_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    return LORA_MAX_PACKET_SIZE;
}

static cyxwiz_error_t lora_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(timeout_ms);

    /* TODO: Check for incoming LoRa packets
     * - Check RX interrupt
     * - Read packet if available
     */
    return CYXWIZ_OK;
}

const cyxwiz_transport_ops_t cyxwiz_lora_ops = {
    .init = lora_init,
    .shutdown = lora_shutdown,
    .send = lora_send,
    .discover = lora_discover,
    .stop_discover = lora_stop_discover,
    .max_packet_size = lora_max_packet_size,
    .poll = lora_poll
};

#endif /* CYXWIZ_HAS_LORA */
