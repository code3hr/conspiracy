/*
 * CyxWiz Protocol - Windows Bluetooth Wrapper
 *
 * C API for Windows Bluetooth functionality.
 * Implementation is in bluetooth_win.cpp.
 */

#ifndef CYXWIZ_BLUETOOTH_WIN_H
#define CYXWIZ_BLUETOOTH_WIN_H

#ifdef _WIN32

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum data size for events */
#define BLUETOOTH_WIN_MAX_DATA 256

/* Event types from Windows Bluetooth */
typedef enum {
    BLUETOOTH_WIN_DEVICE_FOUND = 0,
    BLUETOOTH_WIN_DEVICE_LOST,
    BLUETOOTH_WIN_CONNECTED,
    BLUETOOTH_WIN_DISCONNECTED,
    BLUETOOTH_WIN_CONNECTION_FAILED,
    BLUETOOTH_WIN_DATA
} bluetooth_win_event_type_t;

/* Event structure */
typedef struct {
    bluetooth_win_event_type_t type;
    uint8_t addr[6];                    /* Bluetooth device address */
    int8_t rssi;                        /* Signal strength */
    uint8_t data[BLUETOOTH_WIN_MAX_DATA];
    size_t data_len;
    char device_name[64];               /* Friendly name if available */
} bluetooth_win_event_t;

/*
 * Initialize Windows Bluetooth
 *
 * @param ctx Output: Opaque context pointer
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_init(void **ctx);

/*
 * Shutdown Windows Bluetooth
 *
 * @param ctx Context from bluetooth_win_init
 */
void bluetooth_win_shutdown(void *ctx);

/*
 * Start device discovery
 *
 * @param ctx Context from bluetooth_win_init
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_discover(void *ctx);

/*
 * Stop device discovery
 *
 * @param ctx Context from bluetooth_win_init
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_stop_discover(void *ctx);

/*
 * Poll for events
 *
 * @param ctx Context from bluetooth_win_init
 * @param events Output array for events
 * @param max_events Maximum number of events to return
 * @return Number of events returned
 */
int bluetooth_win_poll(void *ctx, bluetooth_win_event_t *events, int max_events);

/*
 * Connect to a discovered device
 *
 * @param ctx Context from bluetooth_win_init
 * @param addr Bluetooth address (6 bytes)
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_connect(void *ctx, const uint8_t *addr);

/*
 * Disconnect from a device
 *
 * @param ctx Context from bluetooth_win_init
 * @param addr Bluetooth address (6 bytes)
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_disconnect(void *ctx, const uint8_t *addr);

/*
 * Send data to a connected device
 *
 * @param ctx Context from bluetooth_win_init
 * @param addr Bluetooth address (6 bytes)
 * @param data Data to send
 * @param len Length of data
 * @return 0 on success, -1 on failure
 */
int bluetooth_win_send(void *ctx, const uint8_t *addr,
                       const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* CYXWIZ_BLUETOOTH_WIN_H */
