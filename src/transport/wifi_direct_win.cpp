/*
 * CyxWiz Protocol - Windows WiFi Direct Implementation
 *
 * Uses Windows Runtime (WinRT) APIs for WiFi Direct functionality.
 * Requires Windows 10+ and C++17.
 *
 * NOTE: Full WinRT implementation requires C++/WinRT NuGet package.
 * This provides a stub that compiles cleanly and can be extended
 * when the full WinRT SDK is available.
 */

#ifdef _WIN32

// Disable MSVC warnings for standard C functions
#define _CRT_SECURE_NO_WARNINGS

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

#include "wifi_direct_win.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <queue>
#include <mutex>
#include <string>

/* Maximum queued events */
#define MAX_EVENTS 64

/* Internal context structure */
struct wifi_direct_win_context {
    bool initialized;
    bool discovering;
    bool connected;
    uint32_t local_ip;

    std::mutex event_mutex;
    std::queue<wifi_direct_win_event_t> events;

    /* For future WinRT integration */
    void *winrt_publisher;
    void *winrt_watcher;
    void *winrt_device;

    wifi_direct_win_context() :
        initialized(false),
        discovering(false),
        connected(false),
        local_ip(0),
        winrt_publisher(nullptr),
        winrt_watcher(nullptr),
        winrt_device(nullptr) {}
};

/* Get local IP address of WiFi Direct adapter */
static uint32_t get_wifi_direct_ip(void)
{
    PIP_ADAPTER_ADDRESSES addresses = NULL;
    ULONG size = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    /* First call to get required size */
    GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size);
    if (size == 0) return 0;

    addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (!addresses) return 0;

    if (GetAdaptersAddresses(AF_INET, flags, NULL, addresses, &size) != NO_ERROR) {
        free(addresses);
        return 0;
    }

    uint32_t result = 0;

    for (PIP_ADAPTER_ADDRESSES addr = addresses; addr != NULL; addr = addr->Next) {
        /* Look for WiFi Direct adapter (contains "Wi-Fi Direct" or similar) */
        if (addr->FriendlyName &&
            (wcsstr(addr->FriendlyName, L"Wi-Fi Direct") != NULL ||
             wcsstr(addr->FriendlyName, L"WiFi Direct") != NULL ||
             wcsstr(addr->FriendlyName, L"Local Area Connection") != NULL)) {
            if (addr->FirstUnicastAddress) {
                struct sockaddr_in *sa = (struct sockaddr_in *)addr->FirstUnicastAddress->Address.lpSockaddr;
                if (sa->sin_family == AF_INET) {
                    result = sa->sin_addr.s_addr;
                    break;
                }
            }
        }
    }

    free(addresses);
    return result;
}

/* Queue an event (thread-safe) */
static void queue_event(wifi_direct_win_context *ctx, const wifi_direct_win_event_t &event)
{
    std::lock_guard<std::mutex> lock(ctx->event_mutex);
    if (ctx->events.size() < MAX_EVENTS) {
        ctx->events.push(event);
    }
}

extern "C" {

int wifi_direct_win_init(void **ctx)
{
    if (!ctx) return -1;

    auto *context = new (std::nothrow) wifi_direct_win_context();
    if (!context) return -1;

    /*
     * NOTE: Full WinRT WiFi Direct implementation would initialize here:
     * - WiFiDirectAdvertisementPublisher for making ourselves discoverable
     * - DeviceWatcher for discovering other WiFi Direct devices
     *
     * For now, this is a stub that allows compilation.
     * To enable full WiFi Direct:
     * 1. Add C++/WinRT NuGet package
     * 2. Include <winrt/Windows.Devices.WiFiDirect.h>
     * 3. Implement device discovery and connection
     */

    context->initialized = true;
    *ctx = context;

    return 0;
}

void wifi_direct_win_shutdown(void *ctx)
{
    if (!ctx) return;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);

    /* Cleanup would go here for WinRT objects */

    delete context;
}

int wifi_direct_win_discover(void *ctx)
{
    if (!ctx) return -1;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->initialized) return -1;

    /*
     * Full implementation would:
     * 1. Start WiFiDirectAdvertisementPublisher
     * 2. Start DeviceWatcher with WiFiDirect selector
     * 3. Queue DEVICE_FOUND events as devices are discovered
     */

    context->discovering = true;
    return 0;
}

int wifi_direct_win_stop_discover(void *ctx)
{
    if (!ctx) return -1;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->initialized) return -1;

    context->discovering = false;
    return 0;
}

int wifi_direct_win_poll(void *ctx, wifi_direct_win_event_t *events, int max_events)
{
    if (!ctx || !events || max_events <= 0) return 0;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->initialized) return 0;

    std::lock_guard<std::mutex> lock(context->event_mutex);

    int count = 0;
    while (!context->events.empty() && count < max_events) {
        events[count++] = context->events.front();
        context->events.pop();
    }

    return count;
}

int wifi_direct_win_connect(void *ctx, const char *device_id)
{
    if (!ctx || !device_id) return -1;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->initialized) return -1;

    /*
     * Full implementation would:
     * 1. Call WiFiDirectDevice::FromIdAsync(device_id)
     * 2. Wait for connection
     * 3. Get endpoint information
     * 4. Queue CONNECTED or CONNECTION_FAILED event
     */

    /* For now, just simulate failure since WinRT is not initialized */
    wifi_direct_win_event_t event = {};
    event.type = WIFI_DIRECT_WIN_CONNECTION_FAILED;
    strncpy(event.device_id, device_id, sizeof(event.device_id) - 1);
    queue_event(context, event);

    return -1;
}

int wifi_direct_win_disconnect(void *ctx)
{
    if (!ctx) return -1;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->initialized) return -1;

    if (context->connected) {
        context->connected = false;
        context->local_ip = 0;

        wifi_direct_win_event_t event = {};
        event.type = WIFI_DIRECT_WIN_DISCONNECTED;
        queue_event(context, event);
    }

    return 0;
}

int wifi_direct_win_is_connected(void *ctx)
{
    if (!ctx) return 0;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    return context->connected ? 1 : 0;
}

uint32_t wifi_direct_win_get_local_ip(void *ctx)
{
    if (!ctx) return 0;

    auto *context = static_cast<wifi_direct_win_context*>(ctx);
    if (!context->connected) return 0;

    /* Try to get IP from WiFi Direct adapter */
    if (context->local_ip == 0) {
        context->local_ip = get_wifi_direct_ip();
    }

    return context->local_ip;
}

} /* extern "C" */

#endif /* _WIN32 */
