/*
 * CyxWiz Protocol - Windows WiFi Direct Wrapper
 *
 * C API for Windows WinRT WiFi Direct functionality.
 * Implementation is in wifi_direct_win.cpp (C++/WinRT).
 */

#ifndef CYXWIZ_WIFI_DIRECT_WIN_H
#define CYXWIZ_WIFI_DIRECT_WIN_H

#ifdef _WIN32

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Event types from Windows WiFi Direct */
typedef enum {
    WIFI_DIRECT_WIN_DEVICE_FOUND = 0,
    WIFI_DIRECT_WIN_DEVICE_LOST,
    WIFI_DIRECT_WIN_CONNECTED,
    WIFI_DIRECT_WIN_DISCONNECTED,
    WIFI_DIRECT_WIN_CONNECTION_FAILED
} wifi_direct_win_event_type_t;

/* Event structure */
typedef struct {
    wifi_direct_win_event_type_t type;
    uint8_t mac[6];         /* Device MAC address */
    uint32_t ip;            /* IP address (for connected events) */
    char device_id[256];    /* Windows device ID string */
} wifi_direct_win_event_t;

/*
 * Initialize Windows WiFi Direct
 *
 * @param ctx Output: Opaque context pointer
 * @return 0 on success, -1 on failure
 */
int wifi_direct_win_init(void **ctx);

/*
 * Shutdown Windows WiFi Direct
 *
 * @param ctx Context from wifi_direct_win_init
 */
void wifi_direct_win_shutdown(void *ctx);

/*
 * Start device discovery
 *
 * @param ctx Context from wifi_direct_win_init
 * @return 0 on success, -1 on failure
 */
int wifi_direct_win_discover(void *ctx);

/*
 * Stop device discovery
 *
 * @param ctx Context from wifi_direct_win_init
 * @return 0 on success, -1 on failure
 */
int wifi_direct_win_stop_discover(void *ctx);

/*
 * Poll for events
 *
 * @param ctx Context from wifi_direct_win_init
 * @param events Output array for events
 * @param max_events Maximum number of events to return
 * @return Number of events returned
 */
int wifi_direct_win_poll(void *ctx, wifi_direct_win_event_t *events, int max_events);

/*
 * Connect to a discovered device
 *
 * @param ctx Context from wifi_direct_win_init
 * @param device_id Windows device ID string
 * @return 0 on success, -1 on failure
 */
int wifi_direct_win_connect(void *ctx, const char *device_id);

/*
 * Disconnect from current group
 *
 * @param ctx Context from wifi_direct_win_init
 * @return 0 on success, -1 on failure
 */
int wifi_direct_win_disconnect(void *ctx);

/*
 * Check if connected to a group
 *
 * @param ctx Context from wifi_direct_win_init
 * @return 1 if connected, 0 if not
 */
int wifi_direct_win_is_connected(void *ctx);

/*
 * Get local IP address in the group
 *
 * @param ctx Context from wifi_direct_win_init
 * @return IP address in network byte order, 0 if not connected
 */
uint32_t wifi_direct_win_get_local_ip(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* CYXWIZ_WIFI_DIRECT_WIN_H */
