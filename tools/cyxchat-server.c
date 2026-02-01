/*
 * CyxChat Server - Combined Bootstrap + Relay Server
 *
 * Handles:
 * 1. Peer registration and discovery (bootstrap)
 * 2. Data relay when hole punching fails
 *
 * Usage: cyxchat-server [port]
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
#include <sodium.h>

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
#include <sys/select.h>
#include <sys/time.h>
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
#define PEER_TIMEOUT_SEC 300  /* 5 minutes */
#define MAX_PEERS_PER_LIST 10
#define MAX_RELAY_DATA 1400

/* Bootstrap protocol message types (0xF0-0xF3) */
#define CYXWIZ_UDP_REGISTER         0xF0
#define CYXWIZ_UDP_REGISTER_ACK     0xF1
#define CYXWIZ_UDP_PEER_LIST        0xF2
#define CYXWIZ_UDP_CONNECT_REQ      0xF3
#define CYXWIZ_UDP_RELAY_PKT        0xF8    /* Relay any packet to peer */

/* Relay protocol message types (0xE0-0xE5) */
#define CYXCHAT_RELAY_CONNECT       0xE0
#define CYXCHAT_RELAY_CONNECT_ACK   0xE1
#define CYXCHAT_RELAY_DISCONNECT    0xE2
#define CYXCHAT_RELAY_DATA          0xE3
#define CYXCHAT_RELAY_KEEPALIVE     0xE4
#define CYXCHAT_RELAY_ERROR         0xE5

/* Server registry message types (0xF5-0xFA) */
#define CYXCHAT_MSG_SERVER_HEALTH_PING      0xA0
#define CYXCHAT_MSG_SERVER_HEALTH_PONG      0xA1
#define CYXCHAT_MSG_SERVER_CHALLENGE        0xA2
#define CYXCHAT_MSG_SERVER_CHALLENGE_RESP   0xA3

#define SERVER_KEY_FILE     "server_key.dat"
#define SERVER_PUBKEY_SIZE  32
#define SERVER_SECKEY_SIZE  64
#define SERVER_SIG_SIZE     64
#define SERVER_NONCE_SIZE   32

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
    time_t last_activity;
    int active;
} peer_t;

/* Protocol structures - packed for network transmission */
#ifdef _MSC_VER
#pragma pack(push, 1)
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif

typedef struct PACKED {
    uint8_t type;
    node_id_t node_id;
    uint16_t local_port;
} register_msg_t;

typedef struct {
    uint8_t type;
} PACKED register_ack_t;

typedef struct {
    uint8_t type;
    uint8_t peer_count;
} PACKED peer_list_header_t;

typedef struct {
    node_id_t id;
    uint32_t ip;
    uint16_t port;
} PACKED peer_entry_t;

typedef struct {
    uint8_t type;
    node_id_t requester_id;
    uint32_t requester_ip;
    uint16_t requester_port;
} PACKED connect_req_t;

/* Relay messages */
typedef struct {
    uint8_t type;
    node_id_t from_id;
    node_id_t to_id;
} relay_connect_t;

typedef struct {
    uint8_t type;
    node_id_t peer_id;
} relay_connect_ack_t;

typedef struct {
    uint8_t type;
    node_id_t from_id;
    node_id_t to_id;
    uint16_t data_len;
    /* data follows */
} relay_data_header_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Global state */
static peer_t g_peers[MAX_PEERS];
static size_t g_peer_count = 0;
static volatile int g_running = 1;
static socket_t g_socket = SOCKET_INVALID;

/* Stats */
static uint64_t g_bytes_relayed = 0;
static uint64_t g_messages_relayed = 0;

/* Server Ed25519 identity */
static uint8_t g_server_pubkey[SERVER_PUBKEY_SIZE];
static uint8_t g_server_seckey[SERVER_SECKEY_SIZE];
static int g_has_identity = 0;

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
        peer->last_activity = time(NULL);
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (!g_peers[i].active) {
            g_peers[i].id = *id;
            g_peers[i].addr = *addr;
            g_peers[i].registered_at = time(NULL);
            g_peers[i].last_activity = time(NULL);
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
        oldest->last_activity = time(NULL);
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
            (now - g_peers[i].last_activity) > PEER_TIMEOUT_SEC) {
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

/* Send to peer */
static void send_to_peer(peer_t *peer, const uint8_t *data, size_t len)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = peer->addr.ip;
    addr.sin_port = peer->addr.port;

    sendto(g_socket, (const char *)data, (int)len, 0,
           (const struct sockaddr *)&addr, sizeof(addr));

    peer->last_activity = time(NULL);
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
        fflush(stdout);
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
        fflush(stdout);
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

    send_to_peer(target, (uint8_t *)&relay, sizeof(relay));

    char req_ip[INET_ADDRSTRLEN];
    char tgt_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->sin_addr, req_ip, sizeof(req_ip));
    inet_ntop(AF_INET, &target->addr.ip, tgt_ip, sizeof(tgt_ip));

    printf("Relayed connect: %s:%d -> %s:%d\n",
           req_ip, ntohs(from->sin_port),
           tgt_ip, ntohs(target->addr.port));
}

/* Handle relay connect */
static void handle_relay_connect(const struct sockaddr_in *from,
                                 const uint8_t *data, size_t len)
{
    if (len < sizeof(relay_connect_t)) {
        return;
    }

    const relay_connect_t *msg = (const relay_connect_t *)data;

    /* Update sender's address */
    endpoint_t addr = {
        .ip = from->sin_addr.s_addr,
        .port = from->sin_port
    };
    add_or_update_peer(&msg->from_id, &addr);

    /* Find target peer */
    peer_t *target = find_peer(&msg->to_id);
    if (target == NULL) {
        /* Target not found - send error */
        uint8_t err = CYXCHAT_RELAY_ERROR;
        sendto(g_socket, (const char *)&err, 1, 0,
               (const struct sockaddr *)from, sizeof(*from));
        return;
    }

    /* Send ACK to requester */
    relay_connect_ack_t ack;
    ack.type = CYXCHAT_RELAY_CONNECT_ACK;
    ack.peer_id = msg->to_id;
    sendto(g_socket, (const char *)&ack, sizeof(ack), 0,
           (const struct sockaddr *)from, sizeof(*from));

    char from_hex[17], to_hex[17];
    node_id_to_hex(&msg->from_id, from_hex);
    node_id_to_hex(&msg->to_id, to_hex);
    printf("Relay connect: %s... -> %s...\n", from_hex, to_hex);
}

/* Handle relay data */
static void handle_relay_data(const struct sockaddr_in *from,
                              const uint8_t *data, size_t len)
{
    if (len < sizeof(relay_data_header_t)) {
        return;
    }

    const relay_data_header_t *hdr = (const relay_data_header_t *)data;
    uint16_t data_len = ntohs(hdr->data_len);

    if (len < sizeof(relay_data_header_t) + data_len) {
        return;
    }

    /* Update sender's address */
    endpoint_t addr = {
        .ip = from->sin_addr.s_addr,
        .port = from->sin_port
    };
    add_or_update_peer(&hdr->from_id, &addr);

    /* Find target peer */
    peer_t *target = find_peer(&hdr->to_id);
    if (target == NULL) {
        return;
    }

    /* Forward the entire message (preserving from_id so target knows sender) */
    send_to_peer(target, data, len);

    g_bytes_relayed += data_len;
    g_messages_relayed++;

    if (g_messages_relayed % 100 == 0) {
        printf("Relayed %llu messages, %llu KB\n",
               (unsigned long long)g_messages_relayed,
               (unsigned long long)(g_bytes_relayed / 1024));
    }
}

/* Handle relay keepalive */
static void handle_relay_keepalive(const struct sockaddr_in *from,
                                   const uint8_t *data, size_t len)
{
    if (len < 1 + sizeof(node_id_t)) {
        return;
    }

    const node_id_t *id = (const node_id_t *)(data + 1);

    /* Update peer's last activity */
    endpoint_t addr = {
        .ip = from->sin_addr.s_addr,
        .port = from->sin_port
    };
    add_or_update_peer(id, &addr);

    /* Echo back */
    sendto(g_socket, (const char *)data, (int)len, 0,
           (const struct sockaddr *)from, sizeof(*from));
}


/* ============================================================
 * Server Identity (Ed25519)
 * ============================================================ */

/* Convert bytes to hex string */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out)
{
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/* Load or generate Ed25519 keypair */
static int init_server_identity(void)
{
    FILE *f = fopen(SERVER_KEY_FILE, "rb");
    if (f) {
        /* Load existing keypair */
        size_t r1 = fread(g_server_pubkey, 1, SERVER_PUBKEY_SIZE, f);
        size_t r2 = fread(g_server_seckey, 1, SERVER_SECKEY_SIZE, f);
        fclose(f);

        if (r1 == SERVER_PUBKEY_SIZE && r2 == SERVER_SECKEY_SIZE) {
            g_has_identity = 1;
            char hex[65];
            bytes_to_hex(g_server_pubkey, SERVER_PUBKEY_SIZE, hex);
            printf("Loaded server identity from %s\n", SERVER_KEY_FILE);
            printf("Server pubkey: %s\n", hex);
            return 1;
        }
        printf("Warning: corrupt key file, regenerating\n");
    }

    /* Generate new keypair */
    if (crypto_sign_ed25519_keypair(g_server_pubkey, g_server_seckey) != 0) {
        fprintf(stderr, "Failed to generate Ed25519 keypair\n");
        return 0;
    }

    /* Save to file */
    f = fopen(SERVER_KEY_FILE, "wb");
    if (f) {
        fwrite(g_server_pubkey, 1, SERVER_PUBKEY_SIZE, f);
        fwrite(g_server_seckey, 1, SERVER_SECKEY_SIZE, f);
        fclose(f);
    } else {
        fprintf(stderr, "Warning: could not save key to %s\n", SERVER_KEY_FILE);
    }

    g_has_identity = 1;
    char hex[65];
    bytes_to_hex(g_server_pubkey, SERVER_PUBKEY_SIZE, hex);
    printf("Generated new server identity\n");
    printf("Server pubkey: %s\n", hex);
    printf("  (Add this to client seed list for verification)\n");
    return 1;
}

/* ============================================================
 * Health Ping/Pong Handler
 * ============================================================ */

static void handle_health_ping(const struct sockaddr_in *from,
                                const uint8_t *data, size_t len)
{
    /* Health ping: [type:1][timestamp:8] = 9 bytes */
    if (len < 9) return;

    /* Reply with pong (same format, different type) */
    uint8_t pong[9];
    pong[0] = CYXCHAT_MSG_SERVER_HEALTH_PONG;
    memcpy(pong + 1, data + 1, 8);  /* Echo timestamp */

    sendto(g_socket, (const char *)pong, 9, 0,
           (const struct sockaddr *)from, sizeof(*from));
}

/* ============================================================
 * Challenge/Response Handler
 * ============================================================ */

static void handle_challenge(const struct sockaddr_in *from,
                              const uint8_t *data, size_t len)
{
    /* Challenge: [type:1][nonce:32] = 33 bytes */
    if (len < 33) return;
    if (!g_has_identity) return;

    const uint8_t *nonce = data + 1;

    /* Sign the nonce with our Ed25519 secret key */
    uint8_t signature[SERVER_SIG_SIZE];
    if (crypto_sign_ed25519_detached(signature, NULL, nonce, SERVER_NONCE_SIZE,
                                      g_server_seckey) != 0) {
        fprintf(stderr, "Failed to sign challenge\n");
        return;
    }

    /* Build response: [type:1][nonce:32][pubkey:32][signature:64] = 129 bytes */
    uint8_t resp[129];
    resp[0] = CYXCHAT_MSG_SERVER_CHALLENGE_RESP;
    memcpy(resp + 1, nonce, SERVER_NONCE_SIZE);
    memcpy(resp + 1 + SERVER_NONCE_SIZE, g_server_pubkey, SERVER_PUBKEY_SIZE);
    memcpy(resp + 1 + SERVER_NONCE_SIZE + SERVER_PUBKEY_SIZE, signature, SERVER_SIG_SIZE);

    sendto(g_socket, (const char *)resp, sizeof(resp), 0,
           (const struct sockaddr *)from, sizeof(*from));

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->sin_addr, ip_str, sizeof(ip_str));
    printf("Responded to verification challenge from %s:%d\n",
           ip_str, ntohs(from->sin_port));
    fflush(stdout);
}

/* Handle relay packet (forward any packet to target peer) */
static void handle_relay_packet(const struct sockaddr_in *from,
                                const uint8_t *data, size_t len)
{
    /* Format: [0xF4][to_id:32][data_len:2][data...] */
    if (len < 1 + NODE_ID_LEN + 2) {
        return;
    }

    const node_id_t *to_id = (const node_id_t *)(data + 1);
    uint16_t data_len;
    memcpy(&data_len, data + 1 + NODE_ID_LEN, 2);
    data_len = ntohs(data_len);

    if (len < 1 + NODE_ID_LEN + 2 + data_len) {
        return;
    }

    /* Find target peer */
    peer_t *target = find_peer(to_id);
    if (target == NULL) {
        char hex_id[17];
        node_id_to_hex(to_id, hex_id);
        printf("Relay packet: target %s... not found\n", hex_id);
        return;
    }

    /* Forward the data portion to target peer */
    const uint8_t *payload = data + 1 + NODE_ID_LEN + 2;
    send_to_peer(target, payload, data_len);

    g_bytes_relayed += data_len;
    g_messages_relayed++;

    char hex_id[17];
    node_id_to_hex(to_id, hex_id);
    printf("Relayed %u bytes to %s...\n", data_len, hex_id);
    fflush(stdout);
}

/* Process received packet */
static void handle_packet(const struct sockaddr_in *from, const uint8_t *data, size_t len)
{
    if (len < 1) {
        return;
    }

    uint8_t type = data[0];

    switch (type) {
        /* Bootstrap protocol */
        case CYXWIZ_UDP_REGISTER:
            handle_register(from, data, len);
            break;

        case CYXWIZ_UDP_CONNECT_REQ:
            handle_connect_request(from, data, len);
            break;

        case CYXWIZ_UDP_RELAY_PKT:
            handle_relay_packet(from, data, len);
            break;

        /* Relay protocol */
        case CYXCHAT_RELAY_CONNECT:
            handle_relay_connect(from, data, len);
            break;

        case CYXCHAT_RELAY_DATA:
            handle_relay_data(from, data, len);
            break;

        case CYXCHAT_RELAY_KEEPALIVE:
            handle_relay_keepalive(from, data, len);
            break;

        case CYXCHAT_RELAY_DISCONNECT:
            /* Just ignore - peer will timeout */
            break;

        /* Server registry protocol */
        case CYXCHAT_MSG_SERVER_HEALTH_PING:
            handle_health_ping(from, data, len);
            break;

        case CYXCHAT_MSG_SERVER_CHALLENGE:
            handle_challenge(from, data, len);
            break;

        default:
            /* 0xF6 (UDP_DATA) and 0xF7 (KEEPALIVE) are transport-layer
             * packets that clients send before hole punch completes.
             * Safe to ignore — data is delivered via relay (0xE3). */
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

    /* Initialize libsodium */
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    printf("\n");
    printf("CyxChat Server (Bootstrap + Relay)\n");
    printf("===================================\n");
    printf("\n");

    /* Load or generate server Ed25519 identity */
    if (!init_server_identity()) {
        fprintf(stderr, "Failed to initialize server identity\n");
        return 1;
    }
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

    printf("Listening on UDP port %d\n", port);
    printf("Press Ctrl+C to stop\n\n");
    printf("Environment variables for clients:\n");
    printf("  CYXWIZ_BOOTSTRAP=<this_server_ip>:%d\n", port);
    printf("  CYXCHAT_RELAY=<this_server_ip>:%d\n\n", port);

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    signal(SIGTERM, signal_handler);
#endif

    /* Initialize peer table */
    memset(g_peers, 0, sizeof(g_peers));

    /* Main loop */
    uint8_t buf[2048];
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

    printf("\nStats: Relayed %llu messages, %llu KB\n",
           (unsigned long long)g_messages_relayed,
           (unsigned long long)(g_bytes_relayed / 1024));
    printf("Goodbye.\n");
    return 0;
}
