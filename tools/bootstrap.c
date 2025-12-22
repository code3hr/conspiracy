/*
 * CyxWiz Protocol - Bootstrap Server
 *
 * A simple bootstrap/rendezvous server for the UDP transport.
 * Nodes register with this server to discover other nodes.
 *
 * Usage: cyxwiz-bootstrap [port]
 *        Default port: 7777
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
typedef SOCKET socket_t;
#define SOCKET_INVALID INVALID_SOCKET
#define close_socket closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define close_socket close
#endif

/* Configuration */
#define DEFAULT_PORT 7777
#define MAX_PEERS 256
#define NODE_ID_LEN 32
#define PEER_TIMEOUT_SEC 120
#define MAX_PEERS_PER_LIST 10

/* Protocol message types (must match udp.c) */
#define CYXWIZ_UDP_REGISTER         0xF0
#define CYXWIZ_UDP_REGISTER_ACK     0xF1
#define CYXWIZ_UDP_PEER_LIST        0xF2
#define CYXWIZ_UDP_CONNECT_REQ      0xF3

/* Node ID */
typedef struct {
    uint8_t bytes[NODE_ID_LEN];
} node_id_t;

/* Endpoint (IP:port) */
typedef struct {
    uint32_t ip;
    uint16_t port;
} endpoint_t;

/* Registered peer */
typedef struct {
    node_id_t id;
    endpoint_t addr;
    time_t registered_at;
    int active;
} peer_t;

/* Protocol structures - must match udp.c */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

typedef struct {
    uint8_t type;
    node_id_t node_id;
    uint16_t local_port;
} register_msg_t;

typedef struct {
    uint8_t type;
} register_ack_t;

typedef struct {
    uint8_t type;
    uint8_t peer_count;
} peer_list_header_t;

typedef struct {
    node_id_t id;
    uint32_t ip;
    uint16_t port;
} peer_entry_t;

typedef struct {
    uint8_t type;
    node_id_t requester_id;
    uint32_t requester_ip;
    uint16_t requester_port;
} connect_req_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Global state */
static peer_t g_peers[MAX_PEERS];
static size_t g_peer_count = 0;
static volatile int g_running = 1;
static socket_t g_socket = SOCKET_INVALID;

static void signal_handler(int sig)
{
    (void)sig;
    printf("\nShutting down...\n");
    g_running = 0;
}

/* Find peer by node ID */
static peer_t *find_peer(const node_id_t *id)
{
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active &&
            memcmp(&g_peers[i].id, id, sizeof(node_id_t)) == 0) {
            return &g_peers[i];
        }
    }
    return NULL;
}

/* Add or update peer */
static peer_t *add_or_update_peer(const node_id_t *id, const endpoint_t *addr)
{
    peer_t *peer = find_peer(id);
    if (peer != NULL) {
        peer->addr = *addr;
        peer->registered_at = time(NULL);
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (!g_peers[i].active) {
            g_peers[i].id = *id;
            g_peers[i].addr = *addr;
            g_peers[i].registered_at = time(NULL);
            g_peers[i].active = 1;
            g_peer_count++;
            return &g_peers[i];
        }
    }

    /* Table full - find oldest and replace */
    peer_t *oldest = NULL;
    time_t oldest_time = time(NULL);
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active && g_peers[i].registered_at < oldest_time) {
            oldest = &g_peers[i];
            oldest_time = g_peers[i].registered_at;
        }
    }

    if (oldest != NULL) {
        oldest->id = *id;
        oldest->addr = *addr;
        oldest->registered_at = time(NULL);
        return oldest;
    }

    return NULL;
}

/* Clean up expired peers */
static void cleanup_expired_peers(void)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active &&
            (now - g_peers[i].registered_at) > PEER_TIMEOUT_SEC) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_peers[i].addr.ip, ip_str, sizeof(ip_str));
            printf("Expired peer %s:%d\n", ip_str, ntohs(g_peers[i].addr.port));
            g_peers[i].active = 0;
            g_peer_count--;
        }
    }
}

/* Convert node ID to hex string (first 16 chars) */
static void node_id_to_hex(const node_id_t *id, char *out)
{
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2] = hex[(id->bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[id->bytes[i] & 0x0F];
    }
    out[16] = '\0';
}

/* Handle registration */
static void handle_register(const struct sockaddr_in *from, const uint8_t *data, size_t len)
{
    if (len < sizeof(register_msg_t)) {
        return;
    }

    const register_msg_t *msg = (const register_msg_t *)data;

    endpoint_t addr = {
        .ip = from->sin_addr.s_addr,
        .port = from->sin_port
    };

    char hex_id[17];
    node_id_to_hex(&msg->node_id, hex_id);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.ip, ip_str, sizeof(ip_str));

    peer_t *peer = add_or_update_peer(&msg->node_id, &addr);
    if (peer != NULL) {
        printf("Registered: %s... from %s:%d (total: %zu)\n",
               hex_id, ip_str, ntohs(addr.port), g_peer_count);
    }

    /* Send ACK */
    register_ack_t ack = { .type = CYXWIZ_UDP_REGISTER_ACK };
    sendto(g_socket, (const char *)&ack, sizeof(ack), 0,
           (const struct sockaddr *)from, sizeof(*from));

    /* Send peer list */
    uint8_t buf[1024];
    peer_list_header_t *hdr = (peer_list_header_t *)buf;
    hdr->type = CYXWIZ_UDP_PEER_LIST;
    hdr->peer_count = 0;

    peer_entry_t *entries = (peer_entry_t *)(buf + sizeof(peer_list_header_t));
    size_t entry_count = 0;

    for (size_t i = 0; i < MAX_PEERS && entry_count < MAX_PEERS_PER_LIST; i++) {
        if (!g_peers[i].active) {
            continue;
        }

        /* Skip the requesting peer */
        if (memcmp(&g_peers[i].id, &msg->node_id, sizeof(node_id_t)) == 0) {
            continue;
        }

        entries[entry_count].id = g_peers[i].id;
        entries[entry_count].ip = g_peers[i].addr.ip;
        entries[entry_count].port = g_peers[i].addr.port;
        entry_count++;
    }

    hdr->peer_count = (uint8_t)entry_count;
    size_t total_len = sizeof(peer_list_header_t) + entry_count * sizeof(peer_entry_t);

    if (entry_count > 0) {
        sendto(g_socket, (const char *)buf, (int)total_len, 0,
               (const struct sockaddr *)from, sizeof(*from));
        printf("Sent %zu peers to %s:%d\n", entry_count, ip_str, ntohs(addr.port));
    }
}

/* Handle connection request relay */
static void handle_connect_request(const struct sockaddr_in *from,
                                   const uint8_t *data, size_t len)
{
    if (len < sizeof(connect_req_t) + sizeof(node_id_t)) {
        return;
    }

    const connect_req_t *msg = (const connect_req_t *)data;
    const node_id_t *target_id = (const node_id_t *)(data + sizeof(connect_req_t));

    peer_t *target = find_peer(target_id);
    if (target == NULL) {
        printf("Connect request for unknown peer\n");
        return;
    }

    /* Build relay message with requester's observed address */
    connect_req_t relay;
    relay.type = CYXWIZ_UDP_CONNECT_REQ;
    relay.requester_id = msg->requester_id;
    relay.requester_ip = from->sin_addr.s_addr;
    relay.requester_port = from->sin_port;

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = target->addr.ip;
    target_addr.sin_port = target->addr.port;

    sendto(g_socket, (const char *)&relay, sizeof(relay), 0,
           (const struct sockaddr *)&target_addr, sizeof(target_addr));

    char req_ip[INET_ADDRSTRLEN];
    char tgt_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->sin_addr, req_ip, sizeof(req_ip));
    inet_ntop(AF_INET, &target->addr.ip, tgt_ip, sizeof(tgt_ip));

    printf("Relayed connect: %s:%d -> %s:%d\n",
           req_ip, ntohs(from->sin_port),
           tgt_ip, ntohs(target->addr.port));
}

/* Process received packet */
static void handle_packet(const struct sockaddr_in *from, const uint8_t *data, size_t len)
{
    if (len < 1) {
        return;
    }

    uint8_t type = data[0];

    switch (type) {
        case CYXWIZ_UDP_REGISTER:
            handle_register(from, data, len);
            break;

        case CYXWIZ_UDP_CONNECT_REQ:
            handle_connect_request(from, data, len);
            break;

        default:
            printf("Unknown message type: 0x%02X\n", type);
            break;
    }
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[1]);
            return 1;
        }
    }

    printf("\n");
    printf("CyxWiz Bootstrap Server\n");
    printf("=======================\n");
    printf("\n");

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    /* Create UDP socket */
    g_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_socket == SOCKET_INVALID) {
        fprintf(stderr, "socket() failed\n");
        return 1;
    }

    /* Allow address reuse */
    int reuse = 1;
    setsockopt(g_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind() failed\n");
        close_socket(g_socket);
        return 1;
    }

    printf("Listening on port %d\n", port);
    printf("Press Ctrl+C to stop\n\n");

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Initialize peer table */
    memset(g_peers, 0, sizeof(g_peers));

    /* Main loop */
    uint8_t buf[1024];
    time_t last_cleanup = time(NULL);

    while (g_running) {
        /* Use select for timeout */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(g_socket, &read_fds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int ready = select((int)(g_socket + 1), &read_fds, NULL, NULL, &tv);

        if (ready > 0 && FD_ISSET(g_socket, &read_fds)) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);

            int len = recvfrom(g_socket, (char *)buf, sizeof(buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (len > 0) {
                handle_packet(&from_addr, buf, (size_t)len);
            }
        }

        /* Periodic cleanup */
        time_t now = time(NULL);
        if (now - last_cleanup > 30) {
            cleanup_expired_peers();
            last_cleanup = now;
        }
    }

    /* Cleanup */
    close_socket(g_socket);

#ifdef _WIN32
    WSACleanup();
#endif

    printf("Goodbye.\n");
    return 0;
}
