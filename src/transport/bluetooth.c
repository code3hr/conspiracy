/*
 * CyxWiz Protocol - Bluetooth Transport Driver
 *
 * Implements Bluetooth transport for mesh networking.
 * - Linux: Uses BlueZ with L2CAP sockets
 * - Windows: Uses Windows Bluetooth APIs via C++ wrapper
 *
 * Uses L2CAP (Logical Link Control and Adaptation Protocol) for
 * connection-oriented packet communication between peers.
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

#ifdef CYXWIZ_HAS_BLUETOOTH

/* ============================================================================
 * Platform-specific includes
 * ========================================================================= */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2bth.h>
#include <bluetoothapis.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bthprops.lib")
typedef int socklen_t;
typedef SOCKET socket_t;
typedef int ssize_t;
#define SOCKET_INVALID INVALID_SOCKET
#define SOCKET_ERROR_CODE WSAGetLastError()
#define close_socket closesocket
/* Windows Bluetooth wrapper declarations */
#include "bluetooth_win.h"
#else
/* Linux/Unix with BlueZ */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>

/* BlueZ headers */
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

typedef int socket_t;
#define SOCKET_INVALID (-1)
#define SOCKET_ERROR_CODE errno
#define close_socket close
#endif

/* ============================================================================
 * Constants
 * ========================================================================= */

#define CYXWIZ_MAX_BT_PEERS             16
#define CYXWIZ_MAX_BT_PENDING           8
#define CYXWIZ_BT_L2CAP_PSM             0x1001      /* Custom PSM for CyxWiz */
#define CYXWIZ_BT_KEEPALIVE_MS          30000
#define CYXWIZ_BT_PEER_TIMEOUT_MS       60000
#define CYXWIZ_BT_DISCOVERY_TIMEOUT_MS  10000
#define CYXWIZ_BT_CONNECT_TIMEOUT_MS    15000
#define CYXWIZ_BT_MTU                   672         /* Standard L2CAP MTU */

/* ============================================================================
 * Bluetooth Internal Message Types (0xD0-0xDF)
 * ========================================================================= */

#define CYXWIZ_BT_ANNOUNCE              0xD0    /* Node ID announcement */
#define CYXWIZ_BT_ANNOUNCE_ACK          0xD1    /* Acknowledge announce */
#define CYXWIZ_BT_DATA                  0xD2    /* Application data wrapper */
#define CYXWIZ_BT_KEEPALIVE             0xD3    /* Keep connection alive */
#define CYXWIZ_BT_GOODBYE               0xD4    /* Graceful disconnect */

/* ============================================================================
 * Message Structures (packed for network transmission)
 * ========================================================================= */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/* Node announcement */
typedef struct {
    uint8_t type;                   /* CYXWIZ_BT_ANNOUNCE */
    cyxwiz_node_id_t node_id;       /* Our 32-byte node ID */
} cyxwiz_bt_announce_t;             /* 33 bytes */

/* Announce acknowledgement */
typedef struct {
    uint8_t type;                   /* CYXWIZ_BT_ANNOUNCE_ACK */
    cyxwiz_node_id_t node_id;       /* Responder's node ID */
} cyxwiz_bt_announce_ack_t;         /* 33 bytes */

/* Data wrapper */
typedef struct {
    uint8_t type;                   /* CYXWIZ_BT_DATA */
    cyxwiz_node_id_t from;          /* Sender's node ID */
    uint8_t data[1];                /* Payload (flexible array workaround) */
} cyxwiz_bt_data_t;

#define CYXWIZ_BT_DATA_HDR_SIZE (1 + sizeof(cyxwiz_node_id_t))

/* Keepalive */
typedef struct {
    uint8_t type;                   /* CYXWIZ_BT_KEEPALIVE */
    cyxwiz_node_id_t sender_id;
} cyxwiz_bt_keepalive_t;            /* 33 bytes */

/* Goodbye */
typedef struct {
    uint8_t type;                   /* CYXWIZ_BT_GOODBYE */
    cyxwiz_node_id_t sender_id;
} cyxwiz_bt_goodbye_t;              /* 33 bytes */

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* ============================================================================
 * Peer and State Structures
 * ========================================================================= */

/* Bluetooth address (platform-independent) */
typedef struct {
    uint8_t b[6];
} bt_addr_t;

/* Bluetooth peer */
typedef struct {
    cyxwiz_node_id_t    node_id;        /* CyxWiz node ID */
    bt_addr_t           addr;           /* Bluetooth device address */
    char                addr_str[18];   /* "XX:XX:XX:XX:XX:XX" */
    socket_t            socket;         /* L2CAP connection socket */
    uint64_t            last_seen;      /* Timestamp for timeout */
    uint64_t            last_keepalive; /* Last keepalive sent */
    bool                connected;      /* L2CAP connection established */
    bool                has_node_id;    /* Node ID received via ANNOUNCE */
    bool                active;         /* Slot in use */
    int8_t              rssi;           /* Signal strength */
} bluetooth_peer_t;

/* Pending connection request */
typedef struct {
    bt_addr_t           addr;
    char                addr_str[18];
    uint64_t            request_time;
    uint8_t             attempts;
    bool                active;
} bluetooth_pending_t;

/* Bluetooth driver state */
typedef struct {
    bool initialized;
    bool discovering;

#ifndef _WIN32
    /* Linux: BlueZ */
    int hci_dev_id;                     /* HCI device ID (usually 0) */
    int hci_socket;                     /* HCI socket for discovery */
    socket_t listen_socket;             /* L2CAP listening socket */
    bt_addr_t local_addr;               /* Our Bluetooth address */
#else
    /* Windows: Bluetooth wrapper context */
    void *win_context;
    socket_t listen_socket;             /* RFCOMM/L2CAP listening socket */
#endif

    /* Peer management */
    bluetooth_peer_t peers[CYXWIZ_MAX_BT_PEERS];
    size_t peer_count;

    /* Pending connections */
    bluetooth_pending_t pending[CYXWIZ_MAX_BT_PENDING];
    size_t pending_count;

    /* Receive buffer */
    uint8_t recv_buf[CYXWIZ_MAX_PACKET_SIZE + 64];

    /* Timers */
    uint64_t last_discovery_time;
    uint64_t discovery_end_time;

} bluetooth_state_t;

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

/* Format Bluetooth address to string */
static void format_bt_addr(const bt_addr_t *addr, char *str)
{
    snprintf(str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr->b[5], addr->b[4], addr->b[3],
             addr->b[2], addr->b[1], addr->b[0]);
}

/* Parse Bluetooth address from string */
static bool parse_bt_addr(const char *str, bt_addr_t *addr)
{
    unsigned int b[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[5], &b[4], &b[3], &b[2], &b[1], &b[0]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        addr->b[i] = (uint8_t)b[i];
    }
    return true;
}

/* Compare Bluetooth addresses */
static bool bt_addr_equal(const bt_addr_t *a, const bt_addr_t *b)
{
    return memcmp(a->b, b->b, 6) == 0;
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
static bluetooth_peer_t *find_peer_by_id(bluetooth_state_t *state,
                                          const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].has_node_id &&
            memcmp(&state->peers[i].node_id, id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Find peer by Bluetooth address */
static bluetooth_peer_t *find_peer_by_addr(bluetooth_state_t *state,
                                            const bt_addr_t *addr)
{
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].active && bt_addr_equal(&state->peers[i].addr, addr)) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Find peer by socket */
static bluetooth_peer_t *find_peer_by_socket(bluetooth_state_t *state,
                                              socket_t sock)
{
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].socket == sock) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Add or update peer by address */
static bluetooth_peer_t *add_peer_by_addr(bluetooth_state_t *state,
                                           const bt_addr_t *addr,
                                           int8_t rssi)
{
    bluetooth_peer_t *peer = find_peer_by_addr(state, addr);
    if (peer != NULL) {
        peer->last_seen = get_time_ms();
        peer->rssi = rssi;
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (!state->peers[i].active) {
            memset(&state->peers[i], 0, sizeof(bluetooth_peer_t));
            memcpy(&state->peers[i].addr, addr, sizeof(bt_addr_t));
            format_bt_addr(addr, state->peers[i].addr_str);
            state->peers[i].socket = SOCKET_INVALID;
            state->peers[i].last_seen = get_time_ms();
            state->peers[i].rssi = rssi;
            state->peers[i].active = true;
            state->peer_count++;
            return &state->peers[i];
        }
    }

    CYXWIZ_WARN("Bluetooth peer table full");
    return NULL;
}

/* Remove peer */
static void remove_peer(bluetooth_state_t *state, bluetooth_peer_t *peer)
{
    if (peer && peer->active) {
        if (peer->socket != SOCKET_INVALID) {
            close_socket(peer->socket);
            peer->socket = SOCKET_INVALID;
        }
        peer->active = false;
        state->peer_count--;
    }
}

/* ============================================================================
 * Linux: BlueZ L2CAP Implementation
 * ========================================================================= */

#ifndef _WIN32

/* Get local Bluetooth adapter address */
static bool get_local_bt_addr(int dev_id, bt_addr_t *addr)
{
    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        return false;
    }

    bdaddr_t bdaddr;
    if (hci_read_bd_addr(sock, &bdaddr, 1000) < 0) {
        hci_close_dev(sock);
        return false;
    }

    memcpy(addr->b, bdaddr.b, 6);
    hci_close_dev(sock);
    return true;
}

/* Create L2CAP listening socket */
static socket_t create_l2cap_listen_socket(uint16_t psm)
{
    socket_t sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        CYXWIZ_ERROR("Failed to create L2CAP socket: %d", errno);
        return SOCKET_INVALID;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to local address */
    struct sockaddr_l2 addr;
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(psm);
    bacpy(&addr.l2_bdaddr, BDADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CYXWIZ_ERROR("Failed to bind L2CAP socket: %d", errno);
        close(sock);
        return SOCKET_INVALID;
    }

    /* Set non-blocking */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    /* Listen for connections */
    if (listen(sock, CYXWIZ_MAX_BT_PEERS) < 0) {
        CYXWIZ_ERROR("Failed to listen on L2CAP socket: %d", errno);
        close(sock);
        return SOCKET_INVALID;
    }

    CYXWIZ_INFO("L2CAP listening on PSM 0x%04X", psm);
    return sock;
}

/* Connect to a peer via L2CAP */
static socket_t connect_l2cap(const bt_addr_t *addr, uint16_t psm)
{
    socket_t sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        return SOCKET_INVALID;
    }

    /* Set non-blocking for async connect */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_l2 remote;
    memset(&remote, 0, sizeof(remote));
    remote.l2_family = AF_BLUETOOTH;
    remote.l2_psm = htobs(psm);
    memcpy(&remote.l2_bdaddr, addr->b, 6);

    int ret = connect(sock, (struct sockaddr *)&remote, sizeof(remote));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return SOCKET_INVALID;
    }

    return sock;
}

/* Perform HCI device discovery */
static int perform_hci_discovery(bluetooth_state_t *state,
                                  cyxwiz_transport_t *transport)
{
    inquiry_info *info = NULL;
    int num_rsp;
    int flags = IREQ_CACHE_FLUSH;

    /* Perform inquiry (8 * 1.28s = ~10 seconds max) */
    num_rsp = hci_inquiry(state->hci_dev_id, 8, CYXWIZ_MAX_BT_PEERS,
                          NULL, &info, flags);

    if (num_rsp < 0) {
        CYXWIZ_DEBUG("HCI inquiry failed: %d", errno);
        return -1;
    }

    CYXWIZ_DEBUG("HCI inquiry found %d devices", num_rsp);

    for (int i = 0; i < num_rsp; i++) {
        bt_addr_t addr;
        memcpy(addr.b, info[i].bdaddr.b, 6);

        /* Skip devices we already know */
        bluetooth_peer_t *existing = find_peer_by_addr(state, &addr);
        if (existing && existing->connected) {
            continue;
        }

        /* Add to peer list */
        bluetooth_peer_t *peer = add_peer_by_addr(state, &addr, 0);
        if (peer) {
            CYXWIZ_INFO("Discovered Bluetooth device: %s", peer->addr_str);

            /* Notify discovery callback (without node ID yet) */
            if (transport->on_peer) {
                cyxwiz_peer_info_t pinfo;
                memset(&pinfo, 0, sizeof(pinfo));
                /* Node ID will be populated after ANNOUNCE exchange */
                pinfo.rssi = 0;
                pinfo.via = transport->type;
                /* Don't call callback until we have node_id */
            }
        }
    }

    if (info) {
        free(info);
    }

    return num_rsp;
}

#endif /* !_WIN32 */

/* ============================================================================
 * Send/Receive Helpers
 * ========================================================================= */

/* Send data to a peer */
static cyxwiz_error_t send_to_peer(bluetooth_peer_t *peer,
                                    const uint8_t *data, size_t len)
{
    if (!peer || peer->socket == SOCKET_INVALID || !peer->connected) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    ssize_t sent = send(peer->socket, (const char *)data, (int)len, 0);
    if (sent < 0) {
        CYXWIZ_DEBUG("Bluetooth send failed: %d", SOCKET_ERROR_CODE);
        return CYXWIZ_ERR_TRANSPORT;
    }

    return CYXWIZ_OK;
}

/* Broadcast to all connected peers */
static cyxwiz_error_t broadcast_to_peers(bluetooth_state_t *state,
                                          const uint8_t *data, size_t len)
{
    cyxwiz_error_t last_err = CYXWIZ_OK;
    size_t sent_count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].connected) {
            cyxwiz_error_t err = send_to_peer(&state->peers[i], data, len);
            if (err == CYXWIZ_OK) {
                sent_count++;
            } else {
                last_err = err;
            }
        }
    }

    CYXWIZ_DEBUG("Broadcast to %zu Bluetooth peers", sent_count);
    return (sent_count > 0) ? CYXWIZ_OK : last_err;
}

/* ============================================================================
 * Announce Protocol
 * ========================================================================= */

/* Send node announcement */
static void send_announce(bluetooth_state_t *state,
                          cyxwiz_transport_t *transport,
                          bluetooth_peer_t *peer)
{
    cyxwiz_bt_announce_t announce;
    announce.type = CYXWIZ_BT_ANNOUNCE;
    memcpy(&announce.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

    if (peer) {
        send_to_peer(peer, (uint8_t *)&announce, sizeof(announce));
    } else {
        broadcast_to_peers(state, (uint8_t *)&announce, sizeof(announce));
    }

    CYXWIZ_DEBUG("Sent Bluetooth announce");
}

/* Send announce acknowledgement */
static void send_announce_ack(cyxwiz_transport_t *transport,
                               bluetooth_peer_t *peer)
{
    if (!peer) return;

    cyxwiz_bt_announce_ack_t ack;
    ack.type = CYXWIZ_BT_ANNOUNCE_ACK;
    memcpy(&ack.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

    send_to_peer(peer, (uint8_t *)&ack, sizeof(ack));
}

/* Handle received announce */
static void handle_announce(bluetooth_state_t *state,
                            cyxwiz_transport_t *transport,
                            bluetooth_peer_t *peer,
                            const cyxwiz_bt_announce_t *announce)
{
    (void)state; /* Used for potential future state updates */
    if (!peer) return;

    /* Skip our own announcements */
    if (memcmp(&announce->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    /* Update peer info */
    memcpy(&peer->node_id, &announce->node_id, sizeof(cyxwiz_node_id_t));
    peer->has_node_id = true;
    peer->last_seen = get_time_ms();

    CYXWIZ_INFO("Bluetooth peer announced: %s", peer->addr_str);

    /* Send ACK */
    send_announce_ack(transport, peer);

    /* Notify discovery callback */
    if (transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = announce->node_id;
        info.rssi = peer->rssi;
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }
}

/* Handle received announce ACK */
static void handle_announce_ack(bluetooth_state_t *state,
                                 cyxwiz_transport_t *transport,
                                 bluetooth_peer_t *peer,
                                 const cyxwiz_bt_announce_ack_t *ack)
{
    CYXWIZ_UNUSED(state);

    if (!peer) return;

    /* Skip our own */
    if (memcmp(&ack->node_id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
        return;
    }

    memcpy(&peer->node_id, &ack->node_id, sizeof(cyxwiz_node_id_t));
    peer->has_node_id = true;
    peer->last_seen = get_time_ms();

    /* Notify if this is a new peer with node ID */
    if (transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = ack->node_id;
        info.rssi = peer->rssi;
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }
}

/* ============================================================================
 * Message Handling
 * ========================================================================= */

/* Handle received data packet */
static void handle_data(bluetooth_state_t *state,
                        cyxwiz_transport_t *transport,
                        bluetooth_peer_t *peer,
                        const cyxwiz_bt_data_t *pkt,
                        size_t total_len)
{
    CYXWIZ_UNUSED(state);

    if (total_len <= CYXWIZ_BT_DATA_HDR_SIZE) {
        return;
    }

    size_t payload_len = total_len - CYXWIZ_BT_DATA_HDR_SIZE;

    /* Update peer last seen */
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
static void handle_keepalive(bluetooth_state_t *state,
                              bluetooth_peer_t *peer,
                              const cyxwiz_bt_keepalive_t *ka)
{
    CYXWIZ_UNUSED(state);
    CYXWIZ_UNUSED(ka);

    if (peer) {
        peer->last_seen = get_time_ms();
    }
}

/* Handle goodbye */
static void handle_goodbye(bluetooth_state_t *state,
                           bluetooth_peer_t *peer,
                           const cyxwiz_bt_goodbye_t *goodbye)
{
    CYXWIZ_UNUSED(goodbye);

    if (peer) {
        CYXWIZ_DEBUG("Bluetooth peer sent goodbye: %s", peer->addr_str);
        remove_peer(state, peer);
    }
}

/* Process received packet */
static void handle_received_packet(bluetooth_state_t *state,
                                    cyxwiz_transport_t *transport,
                                    bluetooth_peer_t *peer,
                                    const uint8_t *data, size_t len)
{
    if (len < 1) return;

    uint8_t type = data[0];

    switch (type) {
        case CYXWIZ_BT_ANNOUNCE:
            if (len >= sizeof(cyxwiz_bt_announce_t)) {
                handle_announce(state, transport, peer,
                               (const cyxwiz_bt_announce_t *)data);
            }
            break;

        case CYXWIZ_BT_ANNOUNCE_ACK:
            if (len >= sizeof(cyxwiz_bt_announce_ack_t)) {
                handle_announce_ack(state, transport, peer,
                                   (const cyxwiz_bt_announce_ack_t *)data);
            }
            break;

        case CYXWIZ_BT_DATA:
            handle_data(state, transport, peer,
                       (const cyxwiz_bt_data_t *)data, len);
            break;

        case CYXWIZ_BT_KEEPALIVE:
            if (len >= sizeof(cyxwiz_bt_keepalive_t)) {
                handle_keepalive(state, peer,
                                (const cyxwiz_bt_keepalive_t *)data);
            }
            break;

        case CYXWIZ_BT_GOODBYE:
            if (len >= sizeof(cyxwiz_bt_goodbye_t)) {
                handle_goodbye(state, peer,
                              (const cyxwiz_bt_goodbye_t *)data);
            }
            break;

        default:
            CYXWIZ_DEBUG("Unknown Bluetooth message type: 0x%02X", type);
            break;
    }
}

/* ============================================================================
 * Connection Management
 * ========================================================================= */

#ifndef _WIN32

/* Accept incoming L2CAP connection */
static void accept_l2cap_connection(bluetooth_state_t *state,
                                     cyxwiz_transport_t *transport)
{
    struct sockaddr_l2 remote;
    socklen_t len = sizeof(remote);

    socket_t client = accept(state->listen_socket,
                             (struct sockaddr *)&remote, &len);
    if (client < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            CYXWIZ_DEBUG("L2CAP accept failed: %d", errno);
        }
        return;
    }

    /* Set non-blocking */
    int flags = fcntl(client, F_GETFL, 0);
    fcntl(client, F_SETFL, flags | O_NONBLOCK);

    /* Get peer address */
    bt_addr_t addr;
    memcpy(addr.b, remote.l2_bdaddr.b, 6);

    /* Find or create peer */
    bluetooth_peer_t *peer = find_peer_by_addr(state, &addr);
    if (!peer) {
        peer = add_peer_by_addr(state, &addr, 0);
    }

    if (peer) {
        if (peer->socket != SOCKET_INVALID && peer->socket != client) {
            close_socket(peer->socket);
        }
        peer->socket = client;
        peer->connected = true;
        peer->last_seen = get_time_ms();

        CYXWIZ_INFO("Accepted Bluetooth connection from %s", peer->addr_str);

        /* Send our announcement */
        send_announce(state, transport, peer);
    } else {
        close_socket(client);
    }
}

/* Process pending outgoing connections */
static void process_pending_connections(bluetooth_state_t *state,
                                         cyxwiz_transport_t *transport)
{
    uint64_t now = get_time_ms();

    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        bluetooth_peer_t *peer = &state->peers[i];

        if (!peer->active || peer->connected) {
            continue;
        }

        /* Check if we should try to connect */
        if (peer->socket == SOCKET_INVALID) {
            /* Initiate connection */
            peer->socket = connect_l2cap(&peer->addr, CYXWIZ_BT_L2CAP_PSM);
            if (peer->socket != SOCKET_INVALID) {
                CYXWIZ_DEBUG("Connecting to %s", peer->addr_str);
            }
        } else {
            /* Check connection status */
            struct pollfd pfd;
            pfd.fd = peer->socket;
            pfd.events = POLLOUT;
            pfd.revents = 0;

            int ret = poll(&pfd, 1, 0);
            if (ret > 0 && (pfd.revents & POLLOUT)) {
                /* Check for connect error */
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(peer->socket, SOL_SOCKET, SO_ERROR, &error, &len);

                if (error == 0) {
                    peer->connected = true;
                    peer->last_seen = now;
                    CYXWIZ_INFO("Connected to Bluetooth peer: %s", peer->addr_str);

                    /* Send announcement */
                    send_announce(state, transport, peer);
                } else {
                    CYXWIZ_DEBUG("Connection to %s failed: %d", peer->addr_str, error);
                    close_socket(peer->socket);
                    peer->socket = SOCKET_INVALID;
                }
            } else if (pfd.revents & (POLLERR | POLLHUP)) {
                close_socket(peer->socket);
                peer->socket = SOCKET_INVALID;
            }
        }
    }
}

/* Receive data from connected peers */
static void receive_from_peers(bluetooth_state_t *state,
                               cyxwiz_transport_t *transport)
{
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        bluetooth_peer_t *peer = &state->peers[i];

        if (!peer->active || !peer->connected || peer->socket == SOCKET_INVALID) {
            continue;
        }

        ssize_t len = recv(peer->socket, (char *)state->recv_buf,
                           sizeof(state->recv_buf), MSG_DONTWAIT);

        if (len > 0) {
            handle_received_packet(state, transport, peer,
                                  state->recv_buf, (size_t)len);
        } else if (len == 0) {
            /* Connection closed */
            CYXWIZ_DEBUG("Bluetooth peer disconnected: %s", peer->addr_str);
            close_socket(peer->socket);
            peer->socket = SOCKET_INVALID;
            peer->connected = false;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            CYXWIZ_DEBUG("Bluetooth recv error from %s: %d", peer->addr_str, errno);
            close_socket(peer->socket);
            peer->socket = SOCKET_INVALID;
            peer->connected = false;
        }
    }
}

#endif /* !_WIN32 */

/* ============================================================================
 * Housekeeping
 * ========================================================================= */

/* Send keepalives to connected peers */
static void send_keepalives(bluetooth_state_t *state,
                            cyxwiz_transport_t *transport)
{
    uint64_t now = get_time_ms();

    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (!state->peers[i].active || !state->peers[i].connected) {
            continue;
        }

        bluetooth_peer_t *peer = &state->peers[i];

        /* Check timeout */
        if (now - peer->last_seen > CYXWIZ_BT_PEER_TIMEOUT_MS) {
            CYXWIZ_DEBUG("Bluetooth peer timed out: %s", peer->addr_str);
            remove_peer(state, peer);
            continue;
        }

        /* Send keepalive if needed */
        if (now - peer->last_keepalive > CYXWIZ_BT_KEEPALIVE_MS) {
            cyxwiz_bt_keepalive_t ka;
            ka.type = CYXWIZ_BT_KEEPALIVE;
            memcpy(&ka.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

            send_to_peer(peer, (uint8_t *)&ka, sizeof(ka));
            peer->last_keepalive = now;
        }
    }
}

/* ============================================================================
 * Transport Interface Implementation
 * ========================================================================= */

static cyxwiz_error_t bluetooth_init(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = cyxwiz_calloc(1, sizeof(bluetooth_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    state->listen_socket = SOCKET_INVALID;

    /* Initialize all peer sockets to invalid */
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        state->peers[i].socket = SOCKET_INVALID;
    }

#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        CYXWIZ_ERROR("WSAStartup failed: %d", WSAGetLastError());
        cyxwiz_free(state, sizeof(bluetooth_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Initialize Windows Bluetooth */
    if (bluetooth_win_init(&state->win_context) != 0) {
        CYXWIZ_ERROR("Failed to initialize Windows Bluetooth");
        WSACleanup();
        cyxwiz_free(state, sizeof(bluetooth_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    CYXWIZ_INFO("Bluetooth driver initialized (Windows)");
#else
    /* Get HCI device */
    state->hci_dev_id = hci_get_route(NULL);
    if (state->hci_dev_id < 0) {
        CYXWIZ_ERROR("No Bluetooth adapter found");
        cyxwiz_free(state, sizeof(bluetooth_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Get local Bluetooth address */
    if (!get_local_bt_addr(state->hci_dev_id, &state->local_addr)) {
        CYXWIZ_ERROR("Failed to get local Bluetooth address");
        cyxwiz_free(state, sizeof(bluetooth_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    char addr_str[18];
    format_bt_addr(&state->local_addr, addr_str);
    CYXWIZ_INFO("Local Bluetooth address: %s", addr_str);

    /* Create L2CAP listening socket */
    state->listen_socket = create_l2cap_listen_socket(CYXWIZ_BT_L2CAP_PSM);
    if (state->listen_socket == SOCKET_INVALID) {
        CYXWIZ_ERROR("Failed to create L2CAP listening socket");
        cyxwiz_free(state, sizeof(bluetooth_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    CYXWIZ_INFO("Bluetooth driver initialized (Linux/BlueZ, dev hci%d)", state->hci_dev_id);
#endif

    transport->driver_data = state;
    state->initialized = true;

    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_shutdown(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    /* Send goodbye to all connected peers */
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].active && state->peers[i].connected) {
            cyxwiz_bt_goodbye_t goodbye;
            goodbye.type = CYXWIZ_BT_GOODBYE;
            memcpy(&goodbye.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
            send_to_peer(&state->peers[i], (uint8_t *)&goodbye, sizeof(goodbye));
        }
    }

    /* Close all peer sockets */
    for (size_t i = 0; i < CYXWIZ_MAX_BT_PEERS; i++) {
        if (state->peers[i].socket != SOCKET_INVALID) {
            close_socket(state->peers[i].socket);
        }
    }

    /* Close listen socket */
    if (state->listen_socket != SOCKET_INVALID) {
        close_socket(state->listen_socket);
    }

#ifdef _WIN32
    if (state->win_context) {
        bluetooth_win_shutdown(state->win_context);
    }
    WSACleanup();
#endif

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
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Check size */
    if (len + CYXWIZ_BT_DATA_HDR_SIZE > CYXWIZ_MAX_PACKET_SIZE) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Build data packet */
    uint8_t msg[CYXWIZ_MAX_PACKET_SIZE + 64];
    cyxwiz_bt_data_t *pkt = (cyxwiz_bt_data_t *)msg;
    pkt->type = CYXWIZ_BT_DATA;
    memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(pkt->data, data, len);

    size_t msg_len = CYXWIZ_BT_DATA_HDR_SIZE + len;

    /* Check for broadcast */
    if (is_broadcast_id(to)) {
        return broadcast_to_peers(state, msg, msg_len);
    }

    /* Unicast: find peer */
    bluetooth_peer_t *peer = find_peer_by_id(state, to);
    if (peer == NULL || !peer->connected) {
        return CYXWIZ_ERR_PEER_NOT_FOUND;
    }

    return send_to_peer(peer, msg, msg_len);
}

static cyxwiz_error_t bluetooth_discover(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

#ifdef _WIN32
    if (bluetooth_win_discover(state->win_context) != 0) {
        return CYXWIZ_ERR_TRANSPORT;
    }
#else
    /* Perform HCI inquiry */
    CYXWIZ_DEBUG("Starting Bluetooth discovery...");
    int found = perform_hci_discovery(state, transport);
    if (found < 0) {
        CYXWIZ_WARN("Bluetooth discovery failed");
    } else {
        CYXWIZ_INFO("Bluetooth discovery found %d devices", found);
    }
#endif

    state->discovering = true;
    state->last_discovery_time = get_time_ms();
    state->discovery_end_time = state->last_discovery_time + CYXWIZ_BT_DISCOVERY_TIMEOUT_MS;

    return CYXWIZ_OK;
}

static cyxwiz_error_t bluetooth_stop_discover(cyxwiz_transport_t *transport)
{
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

#ifdef _WIN32
    bluetooth_win_stop_discover(state->win_context);
#endif

    state->discovering = false;
    CYXWIZ_DEBUG("Bluetooth discovery stopped");
    return CYXWIZ_OK;
}

static size_t bluetooth_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* Account for data header */
    return CYXWIZ_MAX_PACKET_SIZE - CYXWIZ_BT_DATA_HDR_SIZE;
}

static cyxwiz_error_t bluetooth_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    bluetooth_state_t *state = (bluetooth_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    CYXWIZ_UNUSED(timeout_ms);

#ifdef _WIN32
    /* Poll Windows Bluetooth events */
    bluetooth_win_event_t events[16];
    int count = bluetooth_win_poll(state->win_context, events, 16);
    for (int i = 0; i < count; i++) {
        switch (events[i].type) {
            case BLUETOOTH_WIN_DEVICE_FOUND: {
                bt_addr_t addr;
                memcpy(addr.b, events[i].addr, 6);
                add_peer_by_addr(state, &addr, events[i].rssi);
                break;
            }
            case BLUETOOTH_WIN_CONNECTED: {
                bt_addr_t addr;
                memcpy(addr.b, events[i].addr, 6);
                bluetooth_peer_t *peer = find_peer_by_addr(state, &addr);
                if (peer) {
                    peer->connected = true;
                    send_announce(state, transport, peer);
                }
                break;
            }
            case BLUETOOTH_WIN_DISCONNECTED: {
                bt_addr_t addr;
                memcpy(addr.b, events[i].addr, 6);
                bluetooth_peer_t *peer = find_peer_by_addr(state, &addr);
                if (peer) {
                    peer->connected = false;
                }
                break;
            }
            case BLUETOOTH_WIN_DATA: {
                bt_addr_t addr;
                memcpy(addr.b, events[i].addr, 6);
                bluetooth_peer_t *peer = find_peer_by_addr(state, &addr);
                handle_received_packet(state, transport, peer,
                                       events[i].data, events[i].data_len);
                break;
            }
        }
    }
#else
    /* Accept incoming connections */
    accept_l2cap_connection(state, transport);

    /* Process pending outgoing connections */
    process_pending_connections(state, transport);

    /* Receive data from connected peers */
    receive_from_peers(state, transport);
#endif

    /* Send keepalives */
    send_keepalives(state, transport);

    return CYXWIZ_OK;
}

/* ============================================================================
 * Operations Table
 * ========================================================================= */

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
