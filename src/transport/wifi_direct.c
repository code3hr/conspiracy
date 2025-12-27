/*
 * CyxWiz Protocol - WiFi Direct Transport Driver
 *
 * Implements WiFi Direct (P2P) transport for mesh networking.
 * - Linux: Uses wpa_supplicant P2P control interface
 * - Windows: Uses WinRT WiFiDirect APIs via C++ wrapper
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef CYXWIZ_HAS_WIFI

/* ============================================================================
 * Platform-specific includes
 * ========================================================================= */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
typedef SOCKET socket_t;
typedef int ssize_t;
#define SOCKET_INVALID INVALID_SOCKET
#define SOCKET_ERROR_CODE WSAGetLastError()
#define close_socket closesocket
/* Windows WinRT wrapper declarations */
#include "wifi_direct_win.h"
#else
/* Linux/Unix */
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <net/if.h>
#include <sys/ioctl.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define SOCKET_ERROR_CODE errno
#define close_socket close
#endif

/* ============================================================================
 * Constants
 * ========================================================================= */

#define CYXWIZ_MAX_WIFI_PEERS           32
#define CYXWIZ_MAX_WIFI_PENDING         8
#define CYXWIZ_WIFI_DATA_PORT           19850
#define CYXWIZ_WIFI_KEEPALIVE_MS        30000
#define CYXWIZ_WIFI_PEER_TIMEOUT_MS     60000
#define CYXWIZ_WIFI_DISCOVERY_POLL_MS   1000
#define CYXWIZ_WIFI_CONNECT_TIMEOUT_MS  15000
#define CYXWIZ_WIFI_CMD_TIMEOUT_MS      5000
#define CYXWIZ_WIFI_MAX_CMD_LEN         256
#define CYXWIZ_WIFI_MAX_REPLY_LEN       4096

/* P2P group default subnet (192.168.49.0/24) */
#define CYXWIZ_WIFI_GROUP_SUBNET        0xC0A83100  /* 192.168.49.0 */
#define CYXWIZ_WIFI_GROUP_BROADCAST     0xC0A831FF  /* 192.168.49.255 */

/* ============================================================================
 * WiFi Direct Internal Message Types (0xE0-0xEF)
 * ========================================================================= */

#define CYXWIZ_WIFI_ANNOUNCE            0xE0    /* Node ID announcement */
#define CYXWIZ_WIFI_ANNOUNCE_ACK        0xE1    /* Acknowledge announce */
#define CYXWIZ_WIFI_DATA                0xE2    /* Application data wrapper */
#define CYXWIZ_WIFI_KEEPALIVE           0xE3    /* Keep connection alive */
#define CYXWIZ_WIFI_GOODBYE             0xE4    /* Graceful disconnect */

/* ============================================================================
 * Message Structures (packed for network transmission)
 * ========================================================================= */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/* Node announcement (sent after joining group) */
typedef struct {
    uint8_t type;                   /* CYXWIZ_WIFI_ANNOUNCE */
    cyxwiz_node_id_t node_id;       /* Our 32-byte node ID */
    uint16_t data_port;             /* Port we're listening on (network order) */
} cyxwiz_wifi_announce_t;           /* 35 bytes */

/* Announce acknowledgement */
typedef struct {
    uint8_t type;                   /* CYXWIZ_WIFI_ANNOUNCE_ACK */
    cyxwiz_node_id_t node_id;       /* Responder's node ID */
} cyxwiz_wifi_announce_ack_t;       /* 33 bytes */

/* Data wrapper */
typedef struct {
    uint8_t type;                   /* CYXWIZ_WIFI_DATA */
    cyxwiz_node_id_t from;          /* Sender's node ID */
    uint8_t data[1];                /* Payload (flexible array workaround) */
} cyxwiz_wifi_data_t;

#define CYXWIZ_WIFI_DATA_HDR_SIZE (1 + sizeof(cyxwiz_node_id_t))

/* Keepalive */
typedef struct {
    uint8_t type;                   /* CYXWIZ_WIFI_KEEPALIVE */
    cyxwiz_node_id_t sender_id;
} cyxwiz_wifi_keepalive_t;          /* 33 bytes */

/* Goodbye */
typedef struct {
    uint8_t type;                   /* CYXWIZ_WIFI_GOODBYE */
    cyxwiz_node_id_t sender_id;
} cyxwiz_wifi_goodbye_t;            /* 33 bytes */

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============================================================================
 * Peer and State Structures
 * ========================================================================= */

/* WiFi Direct peer */
typedef struct {
    cyxwiz_node_id_t    node_id;        /* CyxWiz node ID */
    uint8_t             mac[6];         /* WiFi Direct device MAC */
    char                p2p_addr[18];   /* "XX:XX:XX:XX:XX:XX" for wpa_cli */
    uint32_t            ip;             /* IP address (network byte order) */
    uint16_t            port;           /* Data port (network byte order) */
    uint64_t            last_seen;      /* Timestamp for timeout */
    uint64_t            last_keepalive; /* Last keepalive sent */
    bool                connected;      /* In active P2P group */
    bool                has_node_id;    /* Node ID received via ANNOUNCE */
    bool                active;         /* Slot in use */
} wifi_direct_peer_t;

/* Pending connection request */
typedef struct {
    uint8_t             mac[6];
    char                p2p_addr[18];
    uint64_t            request_time;
    uint8_t             attempts;
    bool                active;
} wifi_direct_pending_t;

/* WiFi Direct driver state */
typedef struct {
    bool initialized;
    bool discovering;

#ifndef _WIN32
    /* Linux: wpa_supplicant control interface */
    int ctrl_fd;                        /* Control socket fd */
    int mon_fd;                         /* Monitor socket fd (async events) */
    char ctrl_path[256];                /* /var/run/wpa_supplicant/<iface> */
    char local_ctrl_path[256];          /* Our local socket path */
    char local_mon_path[256];           /* Monitor local socket path */
    char iface[32];                     /* e.g., "wlan0" */
    char p2p_iface[32];                 /* e.g., "p2p-wlan0-0" after group */
#else
    /* Windows: WinRT wrapper context */
    void *win_context;
#endif

    /* Group state */
    bool is_group_owner;                /* Are we the GO? */
    bool in_group;                      /* Currently in a P2P group */
    uint32_t group_ip;                  /* Our IP in the group */

    /* Data socket (after group formation) */
    socket_t data_socket;
    uint16_t data_port;

    /* Peer management */
    wifi_direct_peer_t peers[CYXWIZ_MAX_WIFI_PEERS];
    size_t peer_count;

    /* Pending connections */
    wifi_direct_pending_t pending[CYXWIZ_MAX_WIFI_PENDING];
    size_t pending_count;

    /* Receive buffer */
    uint8_t recv_buf[CYXWIZ_MAX_PACKET_SIZE + 64];

    /* Timers */
    uint64_t last_discovery_poll;
    uint64_t last_announce;

} wifi_direct_state_t;

/* ============================================================================
 * Utility Functions
 * ========================================================================= */

/* Get current time in milliseconds */
static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

/* Parse MAC address from string "XX:XX:XX:XX:XX:XX" */
static bool parse_mac(const char *str, uint8_t *mac)
{
    unsigned int m[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)m[i];
    }
    return true;
}

/* Format MAC address to string */
static void format_mac(const uint8_t *mac, char *str)
{
    snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Check if node ID is broadcast (all 0xFF) */
static bool is_broadcast_id(const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < sizeof(cyxwiz_node_id_t); i++) {
        if (id->bytes[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

/* Find peer by node ID */
static wifi_direct_peer_t *find_peer_by_id(wifi_direct_state_t *state,
                                            const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_WIFI_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].has_node_id &&
            memcmp(&state->peers[i].node_id, id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Find peer by MAC address */
static wifi_direct_peer_t *find_peer_by_mac(wifi_direct_state_t *state,
                                             const uint8_t *mac)
{
    for (size_t i = 0; i < CYXWIZ_MAX_WIFI_PEERS; i++) {
        if (state->peers[i].active &&
            memcmp(state->peers[i].mac, mac, 6) == 0) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Find peer by IP address */
static wifi_direct_peer_t *find_peer_by_ip(wifi_direct_state_t *state,
                                            uint32_t ip)
{
    for (size_t i = 0; i < CYXWIZ_MAX_WIFI_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].ip == ip) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Add or update peer by MAC */
static wifi_direct_peer_t *add_peer_by_mac(wifi_direct_state_t *state,
                                            const uint8_t *mac,
                                            const char *p2p_addr)
{
    wifi_direct_peer_t *peer = find_peer_by_mac(state, mac);
    if (peer != NULL) {
        peer->last_seen = get_time_ms();
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < CYXWIZ_MAX_WIFI_PEERS; i++) {
        if (!state->peers[i].active) {
            memset(&state->peers[i], 0, sizeof(wifi_direct_peer_t));
            memcpy(state->peers[i].mac, mac, 6);
            if (p2p_addr) {
                strncpy(state->peers[i].p2p_addr, p2p_addr, 17);
            } else {
                format_mac(mac, state->peers[i].p2p_addr);
            }
            state->peers[i].last_seen = get_time_ms();
            state->peers[i].active = true;
            state->peer_count++;
            return &state->peers[i];
        }
    }

    CYXWIZ_WARN("WiFi Direct peer table full");
    return NULL;
}

/* Remove peer */
static void remove_peer(wifi_direct_state_t *state, wifi_direct_peer_t *peer)
{
    if (peer && peer->active) {
        peer->active = false;
        state->peer_count--;
    }
}

/* ============================================================================
 * Linux: wpa_supplicant Control Interface
 * ========================================================================= */

#ifndef _WIN32

/* Open connection to wpa_supplicant control interface */
static int wpa_ctrl_open(wifi_direct_state_t *state, const char *ctrl_path)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        CYXWIZ_ERROR("Failed to create wpa_ctrl socket: %d", errno);
        return -1;
    }

    /* Bind local address for replies */
    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path),
             "/tmp/cyxwiz_wpa_ctrl_%d", getpid());
    strncpy(state->local_ctrl_path, local.sun_path, sizeof(state->local_ctrl_path) - 1);

    unlink(local.sun_path);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        CYXWIZ_ERROR("Failed to bind wpa_ctrl socket: %d", errno);
        close(fd);
        return -1;
    }

    /* Connect to wpa_supplicant */
    struct sockaddr_un dest;
    memset(&dest, 0, sizeof(dest));
    dest.sun_family = AF_UNIX;
    strncpy(dest.sun_path, ctrl_path, sizeof(dest.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        CYXWIZ_ERROR("Failed to connect to wpa_supplicant at %s: %d", ctrl_path, errno);
        close(fd);
        unlink(local.sun_path);
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

/* Open monitor connection for async events */
static int wpa_ctrl_open_monitor(wifi_direct_state_t *state, const char *ctrl_path)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    /* Bind local address */
    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    snprintf(local.sun_path, sizeof(local.sun_path),
             "/tmp/cyxwiz_wpa_mon_%d", getpid());
    strncpy(state->local_mon_path, local.sun_path, sizeof(state->local_mon_path) - 1);

    unlink(local.sun_path);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return -1;
    }

    /* Connect to wpa_supplicant */
    struct sockaddr_un dest;
    memset(&dest, 0, sizeof(dest));
    dest.sun_family = AF_UNIX;
    strncpy(dest.sun_path, ctrl_path, sizeof(dest.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(fd);
        unlink(local.sun_path);
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

/* Send command and receive reply */
static int wpa_ctrl_command(int fd, const char *cmd, char *reply, size_t reply_len)
{
    if (send(fd, cmd, strlen(cmd), 0) < 0) {
        CYXWIZ_DEBUG("wpa_ctrl send failed: %d", errno);
        return -1;
    }

    /* Wait for reply with timeout */
    struct timeval tv;
    tv.tv_sec = CYXWIZ_WIFI_CMD_TIMEOUT_MS / 1000;
    tv.tv_usec = (CYXWIZ_WIFI_CMD_TIMEOUT_MS % 1000) * 1000;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
        CYXWIZ_DEBUG("wpa_ctrl command timeout");
        return -1;
    }

    ssize_t len = recv(fd, reply, reply_len - 1, 0);
    if (len < 0) {
        return -1;
    }
    reply[len] = '\0';

    /* Skip unsolicited event messages (start with '<') */
    while (len > 0 && reply[0] == '<') {
        /* This is an event, try to get actual reply */
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
            break;
        }
        len = recv(fd, reply, reply_len - 1, 0);
        if (len > 0) {
            reply[len] = '\0';
        }
    }

    return (int)len;
}

/* Attach to receive unsolicited events */
static int wpa_ctrl_attach(int fd)
{
    char reply[64];
    if (wpa_ctrl_command(fd, "ATTACH", reply, sizeof(reply)) < 0) {
        return -1;
    }
    return (strncmp(reply, "OK", 2) == 0) ? 0 : -1;
}

/* Detach from events */
static int wpa_ctrl_detach(int fd)
{
    char reply[64];
    wpa_ctrl_command(fd, "DETACH", reply, sizeof(reply));
    return 0;
}

/* Close wpa_supplicant connection */
static void wpa_ctrl_close(wifi_direct_state_t *state)
{
    if (state->mon_fd >= 0) {
        wpa_ctrl_detach(state->mon_fd);
        close(state->mon_fd);
        state->mon_fd = -1;
        if (state->local_mon_path[0]) {
            unlink(state->local_mon_path);
        }
    }

    if (state->ctrl_fd >= 0) {
        close(state->ctrl_fd);
        state->ctrl_fd = -1;
        if (state->local_ctrl_path[0]) {
            unlink(state->local_ctrl_path);
        }
    }
}

/* Parse P2P-DEVICE-FOUND event */
static bool parse_p2p_device_found(const char *event, uint8_t *mac, char *p2p_addr)
{
    /* Format: <3>P2P-DEVICE-FOUND 02:00:00:00:01:00 p2p_dev_addr=... */
    const char *ptr = strstr(event, "P2P-DEVICE-FOUND");
    if (!ptr) return false;

    ptr += 17; /* Skip "P2P-DEVICE-FOUND " */
    while (*ptr == ' ') ptr++;

    /* Parse MAC address */
    if (!parse_mac(ptr, mac)) return false;

    /* Copy as p2p_addr string */
    strncpy(p2p_addr, ptr, 17);
    p2p_addr[17] = '\0';

    return true;
}

/* Parse P2P-GROUP-STARTED event */
static bool parse_p2p_group_started(const char *event, char *iface, bool *is_go)
{
    /* Format: <3>P2P-GROUP-STARTED p2p-wlan0-0 GO ssid="DIRECT-xx" ... */
    const char *ptr = strstr(event, "P2P-GROUP-STARTED");
    if (!ptr) return false;

    ptr += 18; /* Skip "P2P-GROUP-STARTED " */
    while (*ptr == ' ') ptr++;

    /* Parse interface name */
    const char *end = strchr(ptr, ' ');
    if (!end) return false;

    size_t len = (size_t)(end - ptr);
    if (len >= 32) len = 31;
    strncpy(iface, ptr, len);
    iface[len] = '\0';

    /* Check if GO or client */
    ptr = end + 1;
    *is_go = (strncmp(ptr, "GO", 2) == 0);

    return true;
}

/* Get IP address of interface */
static uint32_t get_interface_ip(const char *iface)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }

    close(fd);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    return addr->sin_addr.s_addr;
}

#endif /* !_WIN32 */

/* ============================================================================
 * Data Socket Management
 * ========================================================================= */

/* Setup data socket on P2P interface */
static cyxwiz_error_t setup_data_socket(wifi_direct_state_t *state)
{
    state->data_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (state->data_socket == SOCKET_INVALID) {
        CYXWIZ_ERROR("Failed to create data socket: %d", SOCKET_ERROR_CODE);
        return CYXWIZ_ERR_TRANSPORT;
    }

#ifndef _WIN32
    /* Bind to P2P interface (Linux only) */
    if (state->p2p_iface[0]) {
        if (setsockopt(state->data_socket, SOL_SOCKET, SO_BINDTODEVICE,
                       state->p2p_iface, strlen(state->p2p_iface) + 1) < 0) {
            CYXWIZ_WARN("Failed to bind to P2P interface %s: %d",
                       state->p2p_iface, errno);
            /* Continue anyway - may work on some systems */
        }
    }

    /* Set non-blocking */
    int flags = fcntl(state->data_socket, F_GETFL, 0);
    fcntl(state->data_socket, F_SETFL, flags | O_NONBLOCK);
#else
    /* Windows non-blocking */
    u_long mode = 1;
    ioctlsocket(state->data_socket, FIONBIO, &mode);
#endif

    /* Bind to port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(CYXWIZ_WIFI_DATA_PORT);

    if (bind(state->data_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CYXWIZ_ERROR("Failed to bind data socket to port %d: %d",
                    CYXWIZ_WIFI_DATA_PORT, SOCKET_ERROR_CODE);
        close_socket(state->data_socket);
        state->data_socket = SOCKET_INVALID;
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Enable broadcast */
    int broadcast = 1;
    setsockopt(state->data_socket, SOL_SOCKET, SO_BROADCAST,
               (const char *)&broadcast, sizeof(broadcast));

    state->data_port = CYXWIZ_WIFI_DATA_PORT;

#ifndef _WIN32
    /* Get our IP address in the group */
    if (state->p2p_iface[0]) {
        state->group_ip = get_interface_ip(state->p2p_iface);
        if (state->group_ip) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &state->group_ip, ip_str, sizeof(ip_str));
            CYXWIZ_INFO("WiFi Direct data socket on %s:%d (IP: %s)",
                       state->p2p_iface, CYXWIZ_WIFI_DATA_PORT, ip_str);
        }
    }
#endif

    return CYXWIZ_OK;
}

/* Close data socket */
static void close_data_socket(wifi_direct_state_t *state)
{
    if (state->data_socket != SOCKET_INVALID) {
        close_socket(state->data_socket);
        state->data_socket = SOCKET_INVALID;
    }
}

/* Send to endpoint */
static cyxwiz_error_t send_to_ip(wifi_direct_state_t *state,
                                  uint32_t ip, uint16_t port,
                                  const uint8_t *data, size_t len)
{
    if (state->data_socket == SOCKET_INVALID) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = port;

    ssize_t sent = sendto(state->data_socket, (const char *)data, (int)len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));

    if (sent < 0) {
        CYXWIZ_DEBUG("WiFi Direct sendto failed: %d", SOCKET_ERROR_CODE);
        return CYXWIZ_ERR_TRANSPORT;
    }

    return CYXWIZ_OK;
}

/* Broadcast to group */
static cyxwiz_error_t broadcast_to_group(wifi_direct_state_t *state,
                                          const uint8_t *data, size_t len)
{
    return send_to_ip(state, htonl(CYXWIZ_WIFI_GROUP_BROADCAST),
                      htons(CYXWIZ_WIFI_DATA_PORT), data, len);
}

/* ============================================================================
 * Announce Protocol
 * ========================================================================= */

/* Send node announcement */
static void send_announce(wifi_direct_state_t *state, cyxwiz_transport_t *transport)
{
    if (!state->in_group || state->data_socket == SOCKET_INVALID) {
        return;
    }

    cyxwiz_wifi_announce_t announce;
    announce.type = CYXWIZ_WIFI_ANNOUNCE;
    memcpy(&announce.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    announce.data_port = htons(state->data_port);

    broadcast_to_group(state, (uint8_t *)&announce, sizeof(announce));
    state->last_announce = get_time_ms();

    CYXWIZ_DEBUG("Sent WiFi Direct announce");
}

/* Send announce acknowledgement to specific peer */
static void send_announce_ack(wifi_direct_state_t *state,
                               cyxwiz_transport_t *transport,
                               wifi_direct_peer_t *peer)
{
    if (!peer || !peer->ip) return;

    cyxwiz_wifi_announce_ack_t ack;
    ack.type = CYXWIZ_WIFI_ANNOUNCE_ACK;
    memcpy(&ack.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

    send_to_ip(state, peer->ip, peer->port, (uint8_t *)&ack, sizeof(ack));
}

/* Handle received announce */
static void handle_announce(wifi_direct_state_t *state,
                            cyxwiz_transport_t *transport,
                            const cyxwiz_wifi_announce_t *announce,
                            uint32_t from_ip)
{
    /* Skip our own announcements */
    if (memcmp(&announce->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    /* Find or create peer by IP */
    wifi_direct_peer_t *peer = find_peer_by_ip(state, from_ip);
    if (!peer) {
        /* Create new peer entry */
        uint8_t dummy_mac[6] = {0};
        peer = add_peer_by_mac(state, dummy_mac, NULL);
        if (!peer) return;
        peer->ip = from_ip;
    }

    /* Update peer info */
    memcpy(&peer->node_id, &announce->node_id, sizeof(cyxwiz_node_id_t));
    peer->port = announce->data_port;
    peer->has_node_id = true;
    peer->connected = true;
    peer->last_seen = get_time_ms();

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from_ip, ip_str, sizeof(ip_str));
    CYXWIZ_INFO("WiFi Direct peer announced: %s", ip_str);

    /* Send ACK */
    send_announce_ack(state, transport, peer);

    /* Notify discovery callback */
    if (transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = announce->node_id;
        info.rssi = -50;  /* Estimate for WiFi Direct */
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }
}

/* Handle received announce ACK */
static void handle_announce_ack(wifi_direct_state_t *state,
                                 cyxwiz_transport_t *transport,
                                 const cyxwiz_wifi_announce_ack_t *ack,
                                 uint32_t from_ip)
{
    /* Skip our own */
    if (memcmp(&ack->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    wifi_direct_peer_t *peer = find_peer_by_ip(state, from_ip);
    if (!peer) {
        uint8_t dummy_mac[6] = {0};
        peer = add_peer_by_mac(state, dummy_mac, NULL);
        if (!peer) return;
        peer->ip = from_ip;
    }

    memcpy(&peer->node_id, &ack->node_id, sizeof(cyxwiz_node_id_t));
    peer->has_node_id = true;
    peer->connected = true;
    peer->last_seen = get_time_ms();

    /* Notify if this is a new peer */
    if (transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = ack->node_id;
        info.rssi = -50;
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }
}

/* ============================================================================
 * Message Handling
 * ========================================================================= */

/* Handle received data packet */
static void handle_data(wifi_direct_state_t *state,
                        cyxwiz_transport_t *transport,
                        const cyxwiz_wifi_data_t *pkt,
                        size_t total_len)
{
    if (total_len <= CYXWIZ_WIFI_DATA_HDR_SIZE) {
        return;
    }

    size_t payload_len = total_len - CYXWIZ_WIFI_DATA_HDR_SIZE;

    /* Update peer last seen */
    wifi_direct_peer_t *peer = find_peer_by_id(state, &pkt->from);
    if (peer) {
        peer->last_seen = get_time_ms();
    }

    /* Pass to application callback */
    if (transport->on_recv) {
        transport->on_recv(transport, &pkt->from, pkt->data, payload_len,
                          transport->recv_user_data);
    }
}

/* Handle keepalive */
static void handle_keepalive(wifi_direct_state_t *state,
                              const cyxwiz_wifi_keepalive_t *ka)
{
    wifi_direct_peer_t *peer = find_peer_by_id(state, &ka->sender_id);
    if (peer) {
        peer->last_seen = get_time_ms();
    }
}

/* Handle goodbye */
static void handle_goodbye(wifi_direct_state_t *state,
                           const cyxwiz_wifi_goodbye_t *goodbye)
{
    wifi_direct_peer_t *peer = find_peer_by_id(state, &goodbye->sender_id);
    if (peer) {
        CYXWIZ_DEBUG("Peer sent goodbye");
        remove_peer(state, peer);
    }
}

/* Process received packet */
static void handle_received_packet(wifi_direct_state_t *state,
                                    cyxwiz_transport_t *transport,
                                    uint32_t from_ip,
                                    const uint8_t *data, size_t len)
{
    if (len < 1) return;

    uint8_t type = data[0];

    switch (type) {
        case CYXWIZ_WIFI_ANNOUNCE:
            if (len >= sizeof(cyxwiz_wifi_announce_t)) {
                handle_announce(state, transport,
                               (const cyxwiz_wifi_announce_t *)data, from_ip);
            }
            break;

        case CYXWIZ_WIFI_ANNOUNCE_ACK:
            if (len >= sizeof(cyxwiz_wifi_announce_ack_t)) {
                handle_announce_ack(state, transport,
                                   (const cyxwiz_wifi_announce_ack_t *)data, from_ip);
            }
            break;

        case CYXWIZ_WIFI_DATA:
            handle_data(state, transport, (const cyxwiz_wifi_data_t *)data, len);
            break;

        case CYXWIZ_WIFI_KEEPALIVE:
            if (len >= sizeof(cyxwiz_wifi_keepalive_t)) {
                handle_keepalive(state, (const cyxwiz_wifi_keepalive_t *)data);
            }
            break;

        case CYXWIZ_WIFI_GOODBYE:
            if (len >= sizeof(cyxwiz_wifi_goodbye_t)) {
                handle_goodbye(state, (const cyxwiz_wifi_goodbye_t *)data);
            }
            break;

        default:
            CYXWIZ_DEBUG("Unknown WiFi Direct message type: 0x%02X", type);
            break;
    }
}

/* ============================================================================
 * Linux: wpa_supplicant Event Processing
 * ========================================================================= */

#ifndef _WIN32

/* Handle wpa_supplicant event */
static void handle_wpa_event(wifi_direct_state_t *state,
                              cyxwiz_transport_t *transport,
                              const char *event)
{
    CYXWIZ_DEBUG("wpa_supplicant event: %s", event);

    if (strstr(event, "P2P-DEVICE-FOUND")) {
        uint8_t mac[6];
        char p2p_addr[18];
        if (parse_p2p_device_found(event, mac, p2p_addr)) {
            wifi_direct_peer_t *peer = add_peer_by_mac(state, mac, p2p_addr);
            if (peer) {
                CYXWIZ_INFO("P2P device found: %s", p2p_addr);
            }
        }
    }
    else if (strstr(event, "P2P-DEVICE-LOST")) {
        /* Device no longer visible */
        uint8_t mac[6];
        char p2p_addr[18];
        if (parse_p2p_device_found(event, mac, p2p_addr)) {
            wifi_direct_peer_t *peer = find_peer_by_mac(state, mac);
            if (peer && !peer->connected) {
                remove_peer(state, peer);
            }
        }
    }
    else if (strstr(event, "P2P-GROUP-STARTED")) {
        char iface[32];
        bool is_go;
        if (parse_p2p_group_started(event, iface, &is_go)) {
            strncpy(state->p2p_iface, iface, sizeof(state->p2p_iface) - 1);
            state->is_group_owner = is_go;
            state->in_group = true;

            CYXWIZ_INFO("P2P group started: %s (role: %s)",
                       iface, is_go ? "GO" : "client");

            /* Setup data socket on P2P interface */
            if (setup_data_socket(state) == CYXWIZ_OK) {
                /* Send initial announce */
                send_announce(state, transport);
            }
        }
    }
    else if (strstr(event, "P2P-GROUP-REMOVED")) {
        CYXWIZ_INFO("P2P group removed");
        state->in_group = false;
        state->is_group_owner = false;
        state->p2p_iface[0] = '\0';
        close_data_socket(state);
    }
    else if (strstr(event, "P2P-GO-NEG-SUCCESS")) {
        CYXWIZ_DEBUG("GO negotiation succeeded");
    }
    else if (strstr(event, "P2P-GO-NEG-FAILURE")) {
        CYXWIZ_WARN("GO negotiation failed");
    }
    else if (strstr(event, "AP-STA-CONNECTED")) {
        /* Client connected to us (if we're GO) */
        CYXWIZ_DEBUG("Station connected to our group");
    }
    else if (strstr(event, "AP-STA-DISCONNECTED")) {
        CYXWIZ_DEBUG("Station disconnected from our group");
    }
}

/* Poll wpa_supplicant for events */
static void poll_wpa_events(wifi_direct_state_t *state,
                            cyxwiz_transport_t *transport)
{
    if (state->mon_fd < 0) return;

    char buf[1024];
    ssize_t len;

    /* Read all pending events */
    while ((len = recv(state->mon_fd, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[len] = '\0';
        handle_wpa_event(state, transport, buf);
    }
}

#endif /* !_WIN32 */

/* ============================================================================
 * Housekeeping
 * ========================================================================= */

/* Send keepalives to connected peers */
static void send_keepalives(wifi_direct_state_t *state,
                            cyxwiz_transport_t *transport)
{
    if (!state->in_group) return;

    uint64_t now = get_time_ms();

    for (size_t i = 0; i < CYXWIZ_MAX_WIFI_PEERS; i++) {
        if (!state->peers[i].active || !state->peers[i].connected) {
            continue;
        }

        wifi_direct_peer_t *peer = &state->peers[i];

        /* Check timeout */
        if (now - peer->last_seen > CYXWIZ_WIFI_PEER_TIMEOUT_MS) {
            CYXWIZ_DEBUG("WiFi Direct peer timed out");
            remove_peer(state, peer);
            continue;
        }

        /* Send keepalive if needed */
        if (now - peer->last_keepalive > CYXWIZ_WIFI_KEEPALIVE_MS) {
            cyxwiz_wifi_keepalive_t ka;
            ka.type = CYXWIZ_WIFI_KEEPALIVE;
            memcpy(&ka.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

            if (peer->ip && peer->port) {
                send_to_ip(state, peer->ip, peer->port, (uint8_t *)&ka, sizeof(ka));
            }
            peer->last_keepalive = now;
        }
    }
}

/* ============================================================================
 * Transport Interface Implementation
 * ========================================================================= */

static cyxwiz_error_t wifi_direct_init(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = cyxwiz_calloc(1, sizeof(wifi_direct_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    state->data_socket = SOCKET_INVALID;

#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        CYXWIZ_ERROR("WSAStartup failed: %d", WSAGetLastError());
        cyxwiz_free(state, sizeof(wifi_direct_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Initialize Windows WiFi Direct */
    if (wifi_direct_win_init(&state->win_context) != 0) {
        CYXWIZ_ERROR("Failed to initialize Windows WiFi Direct");
        WSACleanup();
        cyxwiz_free(state, sizeof(wifi_direct_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }
#else
    state->ctrl_fd = -1;
    state->mon_fd = -1;

    /* Get WiFi interface name */
    const char *iface = getenv("CYXWIZ_WIFI_IFACE");
    if (iface == NULL) {
        iface = "wlan0";
    }
    strncpy(state->iface, iface, sizeof(state->iface) - 1);

    /* Build control path */
    snprintf(state->ctrl_path, sizeof(state->ctrl_path),
             "/var/run/wpa_supplicant/%s", state->iface);

    /* Check for alternative path */
    const char *alt_path = getenv("CYXWIZ_WPA_CTRL");
    if (alt_path) {
        strncpy(state->ctrl_path, alt_path, sizeof(state->ctrl_path) - 1);
    }

    /* Open control connection */
    state->ctrl_fd = wpa_ctrl_open(state, state->ctrl_path);
    if (state->ctrl_fd < 0) {
        CYXWIZ_ERROR("Failed to connect to wpa_supplicant at %s", state->ctrl_path);
        CYXWIZ_ERROR("Make sure wpa_supplicant is running with P2P support");
        cyxwiz_free(state, sizeof(wifi_direct_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Open monitor connection for events */
    state->mon_fd = wpa_ctrl_open_monitor(state, state->ctrl_path);
    if (state->mon_fd < 0) {
        CYXWIZ_WARN("Failed to open wpa_supplicant monitor connection");
        /* Continue without monitor - will poll for status */
    } else {
        if (wpa_ctrl_attach(state->mon_fd) < 0) {
            CYXWIZ_WARN("Failed to attach to wpa_supplicant events");
        }
    }

    /* Verify P2P support */
    char reply[256];
    if (wpa_ctrl_command(state->ctrl_fd, "P2P_FIND 1", reply, sizeof(reply)) < 0) {
        CYXWIZ_WARN("P2P_FIND test failed - P2P may not be supported");
    } else {
        /* Stop the brief discovery */
        wpa_ctrl_command(state->ctrl_fd, "P2P_STOP_FIND", reply, sizeof(reply));
    }

    CYXWIZ_INFO("WiFi Direct driver initialized (interface: %s)", state->iface);
#endif

    transport->driver_data = state;
    state->initialized = true;

    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_shutdown(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* Send goodbye to all peers */
    if (state->in_group) {
        cyxwiz_wifi_goodbye_t goodbye;
        goodbye.type = CYXWIZ_WIFI_GOODBYE;
        memcpy(&goodbye.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
        broadcast_to_group(state, (uint8_t *)&goodbye, sizeof(goodbye));
    }

#ifdef _WIN32
    if (state->win_context) {
        wifi_direct_win_shutdown(state->win_context);
    }
    WSACleanup();
#else
    /* Leave group */
    if (state->in_group && state->ctrl_fd >= 0) {
        char reply[256];
        wpa_ctrl_command(state->ctrl_fd, "P2P_GROUP_REMOVE *", reply, sizeof(reply));
    }

    /* Close data socket */
    close_data_socket(state);

    /* Close wpa_supplicant connections */
    wpa_ctrl_close(state);
#endif

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
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    if (!state->in_group || state->data_socket == SOCKET_INVALID) {
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Check size */
    if (len + CYXWIZ_WIFI_DATA_HDR_SIZE > CYXWIZ_MAX_PACKET_SIZE) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Build data packet */
    uint8_t msg[CYXWIZ_MAX_PACKET_SIZE + 64];
    cyxwiz_wifi_data_t *pkt = (cyxwiz_wifi_data_t *)msg;
    pkt->type = CYXWIZ_WIFI_DATA;
    memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(pkt->data, data, len);

    size_t msg_len = CYXWIZ_WIFI_DATA_HDR_SIZE + len;

    /* Check for broadcast */
    if (is_broadcast_id(to)) {
        return broadcast_to_group(state, msg, msg_len);
    }

    /* Unicast: find peer */
    wifi_direct_peer_t *peer = find_peer_by_id(state, to);
    if (peer == NULL || !peer->connected || !peer->ip) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    return send_to_ip(state, peer->ip, peer->port, msg, msg_len);
}

static cyxwiz_error_t wifi_direct_discover(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

#ifdef _WIN32
    if (wifi_direct_win_discover(state->win_context) != 0) {
        return CYXWIZ_ERR_TRANSPORT;
    }
#else
    char reply[256];

    /* Start P2P discovery */
    if (wpa_ctrl_command(state->ctrl_fd, "P2P_FIND", reply, sizeof(reply)) < 0) {
        CYXWIZ_ERROR("P2P_FIND failed");
        return CYXWIZ_ERR_TRANSPORT;
    }

    if (strncmp(reply, "OK", 2) != 0 && strncmp(reply, "FAIL", 4) == 0) {
        CYXWIZ_ERROR("P2P_FIND returned: %s", reply);
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Also make ourselves discoverable */
    wpa_ctrl_command(state->ctrl_fd, "P2P_LISTEN", reply, sizeof(reply));
#endif

    state->discovering = true;
    CYXWIZ_DEBUG("WiFi Direct discovery started");
    return CYXWIZ_OK;
}

static cyxwiz_error_t wifi_direct_stop_discover(cyxwiz_transport_t *transport)
{
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

#ifdef _WIN32
    wifi_direct_win_stop_discover(state->win_context);
#else
    char reply[256];
    wpa_ctrl_command(state->ctrl_fd, "P2P_STOP_FIND", reply, sizeof(reply));
#endif

    state->discovering = false;
    CYXWIZ_DEBUG("WiFi Direct discovery stopped");
    return CYXWIZ_OK;
}

static size_t wifi_direct_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* Account for data header */
    return CYXWIZ_MAX_PACKET_SIZE - CYXWIZ_WIFI_DATA_HDR_SIZE;
}

static cyxwiz_error_t wifi_direct_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    wifi_direct_state_t *state = (wifi_direct_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    uint64_t now = get_time_ms();

#ifdef _WIN32
    /* Poll Windows events */
    wifi_direct_win_event_t events[16];
    int count = wifi_direct_win_poll(state->win_context, events, 16);
    for (int i = 0; i < count; i++) {
        /* Handle Windows events - similar to wpa_supplicant events */
        switch (events[i].type) {
            case WIFI_DIRECT_WIN_DEVICE_FOUND:
                /* Add peer */
                break;
            case WIFI_DIRECT_WIN_CONNECTED:
                state->in_group = true;
                setup_data_socket(state);
                send_announce(state, transport);
                break;
            case WIFI_DIRECT_WIN_DISCONNECTED:
                state->in_group = false;
                close_data_socket(state);
                break;
        }
    }
#else
    /* Poll wpa_supplicant events */
    poll_wpa_events(state, transport);
#endif

    /* Poll data socket for incoming messages */
    if (state->data_socket != SOCKET_INVALID) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(state->data_socket, &read_fds);

#ifndef _WIN32
        int max_fd = state->data_socket;
        if (state->mon_fd >= 0) {
            FD_SET(state->mon_fd, &read_fds);
            if (state->mon_fd > max_fd) max_fd = state->mon_fd;
        }
#else
        int max_fd = (int)state->data_socket;
#endif

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (ready > 0) {
#ifndef _WIN32
            /* Check monitor socket */
            if (state->mon_fd >= 0 && FD_ISSET(state->mon_fd, &read_fds)) {
                poll_wpa_events(state, transport);
            }
#endif

            /* Check data socket */
            if (FD_ISSET(state->data_socket, &read_fds)) {
                struct sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);

                ssize_t len = recvfrom(state->data_socket, (char *)state->recv_buf,
                                       sizeof(state->recv_buf), 0,
                                       (struct sockaddr *)&from_addr, &from_len);

                if (len > 0) {
                    handle_received_packet(state, transport,
                                          from_addr.sin_addr.s_addr,
                                          state->recv_buf, (size_t)len);
                }
            }
        }
    }

    /* Periodic tasks */

    /* Re-announce periodically if in group */
    if (state->in_group && now - state->last_announce > 10000) {
        send_announce(state, transport);
    }

    /* Send keepalives */
    send_keepalives(state, transport);

    return CYXWIZ_OK;
}

/* ============================================================================
 * Operations Table
 * ========================================================================= */

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
