/*
 * CyxWiz Protocol - UDP Transport Driver
 *
 * Internet P2P transport using UDP with:
 * - STUN for NAT traversal (public IP discovery)
 * - Bootstrap nodes for initial peer discovery
 * - UDP hole punching for direct P2P connections
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
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define SOCKET_ERROR_CODE errno
#define close_socket close
#endif

/* Configuration */
#define CYXWIZ_MAX_BOOTSTRAP 4
#define CYXWIZ_MAX_UDP_PEERS 64
#define CYXWIZ_MAX_PENDING 16
#define CYXWIZ_KEEPALIVE_INTERVAL_MS 30000
#define CYXWIZ_PEER_TIMEOUT_MS 90000
#define CYXWIZ_STUN_TIMEOUT_MS 3000
#define CYXWIZ_PUNCH_ATTEMPTS 5
#define CYXWIZ_PUNCH_INTERVAL_MS 50
#define CYXWIZ_BOOTSTRAP_REGISTER_INTERVAL_MS 60000

/* UDP-specific MTU (much larger than LoRa's 250 bytes) */
#define CYXWIZ_UDP_MAX_PACKET_SIZE 1400

/* STUN magic cookie (RFC 5389) */
#define STUN_MAGIC_COOKIE 0x2112A442

/* UDP transport message types (internal to transport) */
#define CYXWIZ_UDP_REGISTER         0xF0    /* Register with bootstrap */
#define CYXWIZ_UDP_REGISTER_ACK     0xF1
#define CYXWIZ_UDP_PEER_LIST        0xF2    /* Peer list from bootstrap */
#define CYXWIZ_UDP_CONNECT_REQ      0xF3    /* Connection request relay */
#define CYXWIZ_UDP_PUNCH            0xF4    /* Hole punch packet */
#define CYXWIZ_UDP_PUNCH_ACK        0xF5    /* Hole punch acknowledgement */
#define CYXWIZ_UDP_DATA             0xF6    /* Application data wrapper */
#define CYXWIZ_UDP_KEEPALIVE        0xF7    /* Keep connection alive */
#define CYXWIZ_UDP_RELAY_PKT        0xF8    /* Relay packet via bootstrap */

/* Peer endpoint (IP:port) */
typedef struct {
    uint32_t ip;            /* IPv4 address (network byte order) */
    uint16_t port;          /* Port (network byte order) */
} cyxwiz_endpoint_t;

/* Known peer with network address */
typedef struct {
    cyxwiz_node_id_t id;
    cyxwiz_endpoint_t public_addr;
    uint64_t last_seen;
    uint64_t last_keepalive_sent;
    bool connected;
    bool active;
} cyxwiz_udp_peer_t;

/* Pending connection request */
typedef struct {
    cyxwiz_node_id_t peer_id;
    cyxwiz_endpoint_t addr;
    uint64_t request_time;
    uint8_t attempts;
    bool active;
    bool direct_failed;      /* Direct send didn't work, use relay */
    uint64_t last_relay;     /* Last relay attempt time (rate limiting) */
} cyxwiz_pending_t;

/* STUN header - packed for network */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct {
    uint16_t type;
    uint16_t length;
    uint32_t magic;
    uint8_t transaction_id[12];
} stun_header_t;
#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* UDP transport state */
typedef struct {
    bool initialized;

    /* Socket */
    socket_t socket_fd;
    uint16_t local_port;

    /* NAT info (from STUN) */
    cyxwiz_endpoint_t public_addr;
    bool has_public_addr;
    uint64_t last_stun_attempt;

    /* NAT type detection */
    cyxwiz_nat_type_t nat_type;
    cyxwiz_endpoint_t stun_results[3];  /* Results from each STUN server */
    uint8_t stun_result_count;
    bool nat_detection_complete;

    /* Bootstrap servers */
    cyxwiz_endpoint_t bootstrap_servers[CYXWIZ_MAX_BOOTSTRAP];
    size_t bootstrap_count;
    uint64_t last_bootstrap_register;

    /* Connected peers */
    cyxwiz_udp_peer_t peers[CYXWIZ_MAX_UDP_PEERS];
    size_t peer_count;

    /* Pending connection requests */
    cyxwiz_pending_t pending[CYXWIZ_MAX_PENDING];
    size_t pending_count;

    /* Receive buffer */
    uint8_t recv_buf[CYXWIZ_UDP_MAX_PACKET_SIZE + 64];

    /* STUN transaction tracking */
    uint8_t stun_transaction_id[12];
    bool stun_pending;

    /* Bootstrap status */
    bool bootstrap_ack_received;
} cyxwiz_udp_state_t;

/* Protocol message structures - ALL packed for network wire format.
 * Without packing, compiler alignment padding causes sizeof() mismatches
 * between platforms, silently dropping packets in size checks. */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

#ifdef __GNUC__
#define PACKED_ATTR __attribute__((packed))
#else
#define PACKED_ATTR
#endif

typedef struct PACKED_ATTR {
    uint8_t type;
    cyxwiz_node_id_t from;
    uint8_t data[1];  /* Flexible array workaround for MSVC */
} cyxwiz_udp_data_t;

/* Header size without the data array */
#define CYXWIZ_UDP_DATA_HDR_SIZE (1 + sizeof(cyxwiz_node_id_t))

typedef struct PACKED_ATTR {
    uint8_t type;
    cyxwiz_node_id_t node_id;
    uint16_t local_port;
} cyxwiz_udp_register_t;

typedef struct PACKED_ATTR {
    uint8_t type;
} cyxwiz_udp_register_ack_t;

typedef struct PACKED_ATTR {
    uint8_t type;
    uint8_t peer_count;
    /* Followed by peer entries */
} cyxwiz_udp_peer_list_header_t;

typedef struct PACKED_ATTR {
    cyxwiz_node_id_t id;
    uint32_t ip;
    uint16_t port;
} cyxwiz_udp_peer_entry_t;

typedef struct PACKED_ATTR {
    uint8_t type;
    cyxwiz_node_id_t requester_id;
    uint32_t requester_ip;
    uint16_t requester_port;
} cyxwiz_udp_connect_req_t;

typedef struct PACKED_ATTR {
    uint8_t type;
    cyxwiz_node_id_t sender_id;
    uint32_t punch_id;
} cyxwiz_udp_punch_t;

typedef struct PACKED_ATTR {
    uint8_t type;
    cyxwiz_node_id_t sender_id;
} cyxwiz_udp_keepalive_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Forward declarations */
static cyxwiz_error_t send_to_endpoint(cyxwiz_udp_state_t *state,
                                       const cyxwiz_endpoint_t *endpoint,
                                       const uint8_t *data, size_t len);

#ifdef CYXWIZ_HAS_CRYPTO
extern void cyxwiz_crypto_random(uint8_t *buf, size_t len);
#endif
static void handle_received_packet(cyxwiz_transport_t *transport,
                                   cyxwiz_udp_state_t *state,
                                   const cyxwiz_endpoint_t *from,
                                   const uint8_t *data, size_t len);
static uint64_t get_time_ms(void);

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

/* Parse hostname:port string to endpoint */
static bool parse_endpoint(const char *str, cyxwiz_endpoint_t *out)
{
    char host[256];
    int port;

    const char *colon = strchr(str, ':');
    if (colon == NULL) {
        return false;
    }

    size_t host_len = (size_t)(colon - str);
    if (host_len >= sizeof(host)) {
        return false;
    }

    memcpy(host, str, host_len);
    host[host_len] = '\0';
    port = atoi(colon + 1);

    if (port <= 0 || port > 65535) {
        return false;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) {
        /* Try DNS resolution */
        struct addrinfo hints = {0};
        struct addrinfo *result = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(host, NULL, &hints, &result) != 0 || result == NULL) {
            return false;
        }

        struct sockaddr_in *sin = (struct sockaddr_in *)result->ai_addr;
        out->ip = sin->sin_addr.s_addr;
        freeaddrinfo(result);
    } else {
        out->ip = addr.s_addr;
    }

    out->port = htons((uint16_t)port);
    return true;
}

/* Load bootstrap servers */
static void load_bootstrap_servers(cyxwiz_udp_state_t *state)
{
    state->bootstrap_count = 0;

    /* Check environment variable first */
    const char *env = getenv("CYXWIZ_BOOTSTRAP");
    if (env != NULL && strlen(env) > 0) {
        char *copy = strdup(env);
        char *token = strtok(copy, ",");
        while (token != NULL && state->bootstrap_count < CYXWIZ_MAX_BOOTSTRAP) {
            cyxwiz_endpoint_t ep;
            if (parse_endpoint(token, &ep)) {
                state->bootstrap_servers[state->bootstrap_count++] = ep;
                CYXWIZ_DEBUG("Added bootstrap server: %s", token);
            }
            token = strtok(NULL, ",");
        }
        free(copy);
    }

    /* Fallback to hardcoded defaults if none configured */
    if (state->bootstrap_count == 0) {
        CYXWIZ_WARN("No bootstrap servers configured (set CYXWIZ_BOOTSTRAP env var)");
    } else {
        CYXWIZ_INFO("Loaded %zu bootstrap server(s)", state->bootstrap_count);
    }
}

/* Find a peer by node ID */
static cyxwiz_udp_peer_t *find_peer(cyxwiz_udp_state_t *state, const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < CYXWIZ_MAX_UDP_PEERS; i++) {
        if (state->peers[i].active &&
            memcmp(&state->peers[i].id, id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &state->peers[i];
        }
    }
    return NULL;
}

/* Add or update a peer */
static cyxwiz_udp_peer_t *add_or_update_peer(cyxwiz_udp_state_t *state,
                                              const cyxwiz_node_id_t *id,
                                              const cyxwiz_endpoint_t *addr,
                                              bool connected)
{
    cyxwiz_udp_peer_t *peer = find_peer(state, id);
    if (peer != NULL) {
        peer->public_addr = *addr;
        peer->last_seen = get_time_ms();
        peer->connected = connected;
        return peer;
    }

    /* Find empty slot */
    for (size_t i = 0; i < CYXWIZ_MAX_UDP_PEERS; i++) {
        if (!state->peers[i].active) {
            state->peers[i].id = *id;
            state->peers[i].public_addr = *addr;
            state->peers[i].last_seen = get_time_ms();
            state->peers[i].last_keepalive_sent = 0;
            state->peers[i].connected = connected;
            state->peers[i].active = true;
            state->peer_count++;
            return &state->peers[i];
        }
    }

    CYXWIZ_WARN("Peer table full");
    return NULL;
}

/* Send data to an endpoint */
static cyxwiz_error_t send_to_endpoint(cyxwiz_udp_state_t *state,
                                       const cyxwiz_endpoint_t *endpoint,
                                       const uint8_t *data, size_t len)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = endpoint->ip;
    addr.sin_port = endpoint->port;

    ssize_t sent = sendto(state->socket_fd, (const char *)data, (int)len, 0,
                          (struct sockaddr *)&addr, sizeof(addr));

    if (sent < 0) {
        CYXWIZ_DEBUG("sendto failed: %d", SOCKET_ERROR_CODE);
        return CYXWIZ_ERR_TRANSPORT;
    }

    return CYXWIZ_OK;
}

/* Send STUN binding request */
static cyxwiz_error_t stun_send_request(cyxwiz_udp_state_t *state)
{
    /* Public STUN servers */
    static const char *stun_servers[] = {
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.cloudflare.com:3478"
    };

    stun_header_t request;
    memset(&request, 0, sizeof(request));
    request.type = htons(0x0001);  /* Binding Request */
    request.length = 0;
    request.magic = htonl(STUN_MAGIC_COOKIE);

    /* Generate random transaction ID */
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_crypto_random(request.transaction_id, 12);
#else
    for (int i = 0; i < 12; i++) {
        request.transaction_id[i] = (uint8_t)rand();
    }
#endif

    memcpy(state->stun_transaction_id, request.transaction_id, 12);

    /* Try each STUN server */
    for (size_t i = 0; i < sizeof(stun_servers) / sizeof(stun_servers[0]); i++) {
        cyxwiz_endpoint_t ep;
        if (parse_endpoint(stun_servers[i], &ep)) {
            send_to_endpoint(state, &ep, (uint8_t *)&request, sizeof(request));
            CYXWIZ_DEBUG("Sent STUN request to %s", stun_servers[i]);
        }
    }

    state->stun_pending = true;
    state->last_stun_attempt = get_time_ms();
    return CYXWIZ_OK;
}

/* Determine NAT type from collected STUN results */
static void determine_nat_type(cyxwiz_udp_state_t *state)
{
    if (state->stun_result_count == 0) {
        state->nat_type = CYXWIZ_NAT_BLOCKED;
        state->nat_detection_complete = true;
        CYXWIZ_INFO("NAT type: Blocked (no STUN responses)");
        return;
    }

    if (state->stun_result_count == 1) {
        /* Only got one response - assume Cone (best case) */
        state->nat_type = CYXWIZ_NAT_CONE;
        state->nat_detection_complete = true;
        CYXWIZ_INFO("NAT type: Cone (single response, assumed)");
        return;
    }

    /* Compare mapped ports from different servers */
    bool ports_match = true;
    uint16_t first_port = state->stun_results[0].port;

    for (uint8_t i = 1; i < state->stun_result_count; i++) {
        if (state->stun_results[i].port != first_port) {
            ports_match = false;
            break;
        }
    }

    if (ports_match) {
        /* Check if public IP matches local IP (no NAT) */
        /* For simplicity, just report Cone - proper open detection needs more */
        state->nat_type = CYXWIZ_NAT_CONE;
        CYXWIZ_INFO("NAT type: Cone (same port from %d servers)", state->stun_result_count);
    } else {
        state->nat_type = CYXWIZ_NAT_SYMMETRIC;
        CYXWIZ_INFO("NAT type: Symmetric (different ports from servers)");
    }

    state->nat_detection_complete = true;
}

/* Handle STUN binding response */
static void handle_stun_response(cyxwiz_udp_state_t *state,
                                  const uint8_t *data, size_t len)
{
    if (len < sizeof(stun_header_t)) {
        return;
    }

    const stun_header_t *hdr = (const stun_header_t *)data;

    /* Verify it's a Binding Response */
    if (ntohs(hdr->type) != 0x0101) {
        return;
    }

    /* Verify magic cookie */
    if (ntohl(hdr->magic) != STUN_MAGIC_COOKIE) {
        return;
    }

    /* Verify transaction ID */
    if (memcmp(hdr->transaction_id, state->stun_transaction_id, 12) != 0) {
        return;
    }

    /* Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) */
    const uint8_t *attrs = data + sizeof(stun_header_t);
    size_t attrs_len = ntohs(hdr->length);
    size_t offset = 0;

    while (offset + 4 <= attrs_len) {
        uint16_t attr_type = (attrs[offset] << 8) | attrs[offset + 1];
        uint16_t attr_len = (attrs[offset + 2] << 8) | attrs[offset + 3];
        offset += 4;

        if (attr_type == 0x0020 && attr_len >= 8) {  /* XOR-MAPPED-ADDRESS */
            /* uint8_t family = attrs[offset + 1]; */
            uint16_t xor_port = (attrs[offset + 2] << 8) | attrs[offset + 3];
            uint32_t xor_addr;
            memcpy(&xor_addr, &attrs[offset + 4], 4);

            /* XOR with magic cookie */
            uint16_t mapped_port = htons(xor_port ^ (STUN_MAGIC_COOKIE >> 16));
            uint32_t mapped_ip = xor_addr ^ htonl(STUN_MAGIC_COOKIE);

            /* Store first result as public address */
            if (!state->has_public_addr) {
                state->public_addr.port = mapped_port;
                state->public_addr.ip = mapped_ip;
                state->has_public_addr = true;
            }

            /* Store result for NAT type detection (up to 3 servers) */
            if (state->stun_result_count < 3) {
                state->stun_results[state->stun_result_count].ip = mapped_ip;
                state->stun_results[state->stun_result_count].port = mapped_port;
                state->stun_result_count++;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &mapped_ip, ip_str, sizeof(ip_str));
                CYXWIZ_DEBUG("STUN result %d: %s:%d",
                            state->stun_result_count, ip_str, ntohs(mapped_port));
            }

            /* After 2+ responses, determine NAT type */
            if (state->stun_result_count >= 2 && !state->nat_detection_complete) {
                determine_nat_type(state);
            }

            state->stun_pending = false;

            if (state->stun_result_count == 1) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &state->public_addr.ip, ip_str, sizeof(ip_str));
                CYXWIZ_INFO("STUN discovered public address: %s:%d",
                           ip_str, ntohs(state->public_addr.port));
            }
            return;
        }

        /* Align to 4 bytes */
        offset += attr_len;
        offset = (offset + 3) & ~3;
    }
}

/* Register with bootstrap server */
static cyxwiz_error_t bootstrap_register(cyxwiz_transport_t *transport,
                                         cyxwiz_udp_state_t *state)
{
    if (state->bootstrap_count == 0) {
        return CYXWIZ_OK;
    }

    cyxwiz_udp_register_t reg;
    memset(&reg, 0, sizeof(reg));
    reg.type = CYXWIZ_UDP_REGISTER;
    memcpy(&reg.node_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    reg.local_port = htons(state->local_port);

    for (size_t i = 0; i < state->bootstrap_count; i++) {
        send_to_endpoint(state, &state->bootstrap_servers[i],
                        (uint8_t *)&reg, sizeof(reg));
    }

    state->last_bootstrap_register = get_time_ms();
    CYXWIZ_INFO("Bootstrap: Sent register to %zu server(s)", state->bootstrap_count);
    return CYXWIZ_OK;
}

/* Handle peer list from bootstrap */
static void handle_peer_list(cyxwiz_transport_t *transport,
                             cyxwiz_udp_state_t *state,
                             const uint8_t *data, size_t len)
{
    if (len < sizeof(cyxwiz_udp_peer_list_header_t)) {
        return;
    }

    const cyxwiz_udp_peer_list_header_t *hdr = (const cyxwiz_udp_peer_list_header_t *)data;
    size_t expected_len = sizeof(cyxwiz_udp_peer_list_header_t) +
                          hdr->peer_count * sizeof(cyxwiz_udp_peer_entry_t);

    if (len < expected_len) {
        return;
    }

    const cyxwiz_udp_peer_entry_t *entries =
        (const cyxwiz_udp_peer_entry_t *)(data + sizeof(cyxwiz_udp_peer_list_header_t));

    CYXWIZ_INFO("Received peer list with %d peers from bootstrap", hdr->peer_count);

    for (uint8_t i = 0; i < hdr->peer_count; i++) {
        /* Skip self */
        if (memcmp(&entries[i].id, &transport->local_id, sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Check if we already know this peer */
        cyxwiz_udp_peer_t *existing = find_peer(state, &entries[i].id);
        if (existing != NULL && existing->connected) {
            continue;
        }

        /* Check if already pending (avoid duplicate entries from repeated 0xF2) */
        bool already_pending = false;
        for (size_t j = 0; j < CYXWIZ_MAX_PENDING; j++) {
            if (state->pending[j].active &&
                memcmp(&state->pending[j].peer_id, &entries[i].id,
                       sizeof(cyxwiz_node_id_t)) == 0) {
                /* Update address in case it changed */
                state->pending[j].addr.ip = entries[i].ip;
                state->pending[j].addr.port = entries[i].port;
                already_pending = true;
                break;
            }
        }
        if (already_pending) {
            continue;
        }

        /* Add as pending connection */
        cyxwiz_endpoint_t ep = {
            .ip = entries[i].ip,
            .port = entries[i].port
        };

        /* Find empty pending slot */
        bool found = false;
        for (size_t j = 0; j < CYXWIZ_MAX_PENDING; j++) {
            if (!state->pending[j].active) {
                state->pending[j].peer_id = entries[i].id;
                state->pending[j].addr = ep;
                state->pending[j].request_time = get_time_ms();
                state->pending[j].attempts = 0;
                state->pending[j].active = true;
                state->pending[j].direct_failed = false;
                state->pending[j].last_relay = 0;
                state->pending_count++;
                found = true;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ep.ip, ip_str, sizeof(ip_str));
                CYXWIZ_INFO("Added pending connection to %s:%d", ip_str, ntohs(ep.port));

                /* Send connect request (0xF3) via bootstrap to coordinate hole punch.
                 * Format: [connect_req_t][target_node_id] */
                if (state->bootstrap_count > 0) {
                    uint8_t req_buf[sizeof(cyxwiz_udp_connect_req_t) + sizeof(cyxwiz_node_id_t)];
                    cyxwiz_udp_connect_req_t *req = (cyxwiz_udp_connect_req_t *)req_buf;
                    req->type = CYXWIZ_UDP_CONNECT_REQ;
                    memcpy(&req->requester_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
                    req->requester_ip = ep.ip;
                    req->requester_port = ep.port;
                    /* Append target node ID after the connect request */
                    memcpy(req_buf + sizeof(cyxwiz_udp_connect_req_t),
                           &entries[i].id, sizeof(cyxwiz_node_id_t));
                    send_to_endpoint(state, &state->bootstrap_servers[0],
                                     req_buf, sizeof(req_buf));
                    CYXWIZ_INFO("Sent connect request (0xF3) to bootstrap for %s:%d",
                               ip_str, ntohs(ep.port));
                }

                /* Notify discovery callback to trigger key exchange ANNOUNCE */
                if (transport->on_peer) {
                    cyxwiz_peer_info_t info;
                    memset(&info, 0, sizeof(info));
                    info.id = entries[i].id;
                    info.rssi = 0;
                    info.via = transport->type;
                    transport->on_peer(transport, &info, transport->peer_user_data);
                    CYXWIZ_INFO("Triggered on_peer callback for bootstrap peer");
                }
                break;
            }
        }

        if (!found) {
            CYXWIZ_DEBUG("Pending queue full, skipping peer");
        }
    }
}

/* Handle connection request (relayed from bootstrap or direct) */
static void handle_connect_request(cyxwiz_transport_t *transport,
                                   cyxwiz_udp_state_t *state,
                                   const cyxwiz_endpoint_t *from,
                                   const uint8_t *data, size_t len)
{
    CYXWIZ_UNUSED(from);

    if (len < sizeof(cyxwiz_udp_connect_req_t)) {
        return;
    }

    const cyxwiz_udp_connect_req_t *req = (const cyxwiz_udp_connect_req_t *)data;

    /* Build endpoint from request */
    cyxwiz_endpoint_t requester_ep = {
        .ip = req->requester_ip,
        .port = req->requester_port
    };

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &requester_ep.ip, ip_str, sizeof(ip_str));
    CYXWIZ_DEBUG("Received connect request from %s:%d", ip_str, ntohs(requester_ep.port));

    /* Send punch packets to initiate hole punching */
    cyxwiz_udp_punch_t punch;
    punch.type = CYXWIZ_UDP_PUNCH;
    memcpy(&punch.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    punch.punch_id = (uint32_t)get_time_ms();  /* Simple punch ID */

    for (int i = 0; i < CYXWIZ_PUNCH_ATTEMPTS; i++) {
        send_to_endpoint(state, &requester_ep, (uint8_t *)&punch, sizeof(punch));
    }

    /* Add to pending */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (!state->pending[i].active) {
            state->pending[i].peer_id = req->requester_id;
            state->pending[i].addr = requester_ep;
            state->pending[i].request_time = get_time_ms();
            state->pending[i].attempts = 1;
            state->pending[i].active = true;
            state->pending_count++;
            break;
        }
    }
}

/* Handle hole punch packet */
static void handle_punch(cyxwiz_transport_t *transport,
                         cyxwiz_udp_state_t *state,
                         const cyxwiz_endpoint_t *from,
                         const uint8_t *data, size_t len)
{
    if (len < sizeof(cyxwiz_udp_punch_t)) {
        return;
    }

    const cyxwiz_udp_punch_t *punch = (const cyxwiz_udp_punch_t *)data;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->ip, ip_str, sizeof(ip_str));
    CYXWIZ_DEBUG("Received punch from %s:%d", ip_str, ntohs(from->port));

    /* Send ACK back */
    cyxwiz_udp_punch_t ack;
    ack.type = CYXWIZ_UDP_PUNCH_ACK;
    memcpy(&ack.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
    ack.punch_id = punch->punch_id;
    send_to_endpoint(state, from, (uint8_t *)&ack, sizeof(ack));

    /* Mark peer as connected */
    cyxwiz_udp_peer_t *peer = add_or_update_peer(state, &punch->sender_id, from, true);

    /* Notify discovery callback */
    if (peer != NULL && transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = punch->sender_id;
        info.rssi = 0;  /* N/A for Internet */
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }

    /* Remove from pending if present */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (state->pending[i].active &&
            memcmp(&state->pending[i].peer_id, &punch->sender_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            state->pending[i].active = false;
            state->pending_count--;
            break;
        }
    }
}

/* Handle punch ACK */
static void handle_punch_ack(cyxwiz_transport_t *transport,
                             cyxwiz_udp_state_t *state,
                             const cyxwiz_endpoint_t *from,
                             const uint8_t *data, size_t len)
{
    if (len < sizeof(cyxwiz_udp_punch_t)) {
        return;
    }

    const cyxwiz_udp_punch_t *ack = (const cyxwiz_udp_punch_t *)data;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from->ip, ip_str, sizeof(ip_str));
    CYXWIZ_DEBUG("Received punch ACK from %s:%d", ip_str, ntohs(from->port));

    /* Mark peer as connected */
    cyxwiz_udp_peer_t *peer = add_or_update_peer(state, &ack->sender_id, from, true);

    /* Notify discovery callback */
    if (peer != NULL && transport->on_peer) {
        cyxwiz_peer_info_t info;
        memset(&info, 0, sizeof(info));
        info.id = ack->sender_id;
        info.rssi = 0;
        info.via = transport->type;
        transport->on_peer(transport, &info, transport->peer_user_data);
    }

    /* Remove from pending */
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (state->pending[i].active &&
            memcmp(&state->pending[i].peer_id, &ack->sender_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            state->pending[i].active = false;
            state->pending_count--;
            break;
        }
    }
}

/* Handle keepalive */
static void handle_keepalive(cyxwiz_udp_state_t *state,
                             const cyxwiz_endpoint_t *from,
                             const uint8_t *data, size_t len)
{
    if (len < sizeof(cyxwiz_udp_keepalive_t)) {
        return;
    }

    const cyxwiz_udp_keepalive_t *ka = (const cyxwiz_udp_keepalive_t *)data;
    cyxwiz_udp_peer_t *peer = find_peer(state, &ka->sender_id);

    if (peer != NULL) {
        peer->last_seen = get_time_ms();
    } else {
        /* Unknown peer, add them */
        add_or_update_peer(state, &ka->sender_id, from, true);
    }
}

/* Handle application data */
static void handle_data(cyxwiz_transport_t *transport,
                        cyxwiz_udp_state_t *state,
                        const cyxwiz_endpoint_t *from,
                        const uint8_t *data, size_t len)
{
    if (len <= CYXWIZ_UDP_DATA_HDR_SIZE) {
        return;
    }

    const cyxwiz_udp_data_t *pkt = (const cyxwiz_udp_data_t *)data;
    size_t payload_len = len - CYXWIZ_UDP_DATA_HDR_SIZE;

    /* Update peer last seen */
    cyxwiz_udp_peer_t *peer = find_peer(state, &pkt->from);
    if (peer != NULL) {
        peer->last_seen = get_time_ms();
    } else {
        /* Unknown peer sent us data, add them */
        add_or_update_peer(state, &pkt->from, from, true);
    }

    /* Pass to application callback */
    if (transport->on_recv) {
        transport->on_recv(transport, &pkt->from, pkt->data, payload_len,
                          transport->recv_user_data);
    }
}

/* Handle received packet */
static void handle_received_packet(cyxwiz_transport_t *transport,
                                   cyxwiz_udp_state_t *state,
                                   const cyxwiz_endpoint_t *from,
                                   const uint8_t *data, size_t len)
{
    if (len < 1) {
        return;
    }

    uint8_t type = data[0];

    /* Check if it looks like a STUN response */
    if (len >= sizeof(stun_header_t)) {
        const stun_header_t *hdr = (const stun_header_t *)data;
        if (ntohl(hdr->magic) == STUN_MAGIC_COOKIE) {
            handle_stun_response(state, data, len);
            return;
        }
    }

    CYXWIZ_INFO("Received UDP packet type 0x%02X, len=%zu", type, len);

    switch (type) {
        case CYXWIZ_UDP_REGISTER_ACK:
            CYXWIZ_INFO("Received register ACK from bootstrap");
            state->bootstrap_ack_received = true;
            break;

        case CYXWIZ_UDP_PEER_LIST:
            handle_peer_list(transport, state, data, len);
            break;

        case CYXWIZ_UDP_CONNECT_REQ:
            handle_connect_request(transport, state, from, data, len);
            break;

        case CYXWIZ_UDP_PUNCH:
            handle_punch(transport, state, from, data, len);
            break;

        case CYXWIZ_UDP_PUNCH_ACK:
            handle_punch_ack(transport, state, from, data, len);
            break;

        case CYXWIZ_UDP_KEEPALIVE:
            handle_keepalive(state, from, data, len);
            break;

        case CYXWIZ_UDP_DATA:
            handle_data(transport, state, from, data, len);
            break;

        default:
            /* Forward unrecognized types (server registry, relay, etc.)
             * to application callback so higher layers can handle them */
            if (transport->on_recv) {
                cyxwiz_node_id_t from_id;
                memset(&from_id, 0, sizeof(from_id));
                memcpy(from_id.bytes, &from->ip, 4);
                memcpy(from_id.bytes + 4, &from->port, 2);
                from_id.bytes[6] = 0xFF;
                transport->on_recv(transport, &from_id, data, len,
                                  transport->recv_user_data);
            } else {
                CYXWIZ_DEBUG("Unknown UDP transport message type: 0x%02X", type);
            }
            break;
    }
}

/* Process pending connections (retries) */
static void process_pending_connections(cyxwiz_transport_t *transport,
                                        cyxwiz_udp_state_t *state)
{
    uint64_t now = get_time_ms();

    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (!state->pending[i].active) {
            continue;
        }

        /* Check if we should retry */
        uint64_t elapsed = now - state->pending[i].request_time;
        if (elapsed > (uint64_t)(state->pending[i].attempts * CYXWIZ_PUNCH_INTERVAL_MS * 10)) {
            if (state->pending[i].attempts >= CYXWIZ_PUNCH_ATTEMPTS) {
                /* Give up */
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &state->pending[i].addr.ip, ip_str, sizeof(ip_str));
                CYXWIZ_DEBUG("Giving up on punch to %s:%d",
                            ip_str, ntohs(state->pending[i].addr.port));
                state->pending[i].active = false;
                state->pending_count--;
                continue;
            }

            /* Send punch */
            cyxwiz_udp_punch_t punch;
            punch.type = CYXWIZ_UDP_PUNCH;
            memcpy(&punch.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));
            punch.punch_id = (uint32_t)now;

            send_to_endpoint(state, &state->pending[i].addr,
                           (uint8_t *)&punch, sizeof(punch));
            state->pending[i].attempts++;
        }
    }
}

/* Send keepalives to connected peers */
static void send_keepalives(cyxwiz_transport_t *transport,
                            cyxwiz_udp_state_t *state)
{
    uint64_t now = get_time_ms();

    for (size_t i = 0; i < CYXWIZ_MAX_UDP_PEERS; i++) {
        if (!state->peers[i].active || !state->peers[i].connected) {
            continue;
        }

        /* Check if peer timed out */
        if (now - state->peers[i].last_seen > CYXWIZ_PEER_TIMEOUT_MS) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &state->peers[i].public_addr.ip, ip_str, sizeof(ip_str));
            CYXWIZ_DEBUG("Peer %s:%d timed out",
                        ip_str, ntohs(state->peers[i].public_addr.port));
            state->peers[i].active = false;
            state->peer_count--;
            continue;
        }

        /* Send keepalive if needed */
        if (now - state->peers[i].last_keepalive_sent > CYXWIZ_KEEPALIVE_INTERVAL_MS) {
            cyxwiz_udp_keepalive_t ka;
            ka.type = CYXWIZ_UDP_KEEPALIVE;
            memcpy(&ka.sender_id, &transport->local_id, sizeof(cyxwiz_node_id_t));

            send_to_endpoint(state, &state->peers[i].public_addr,
                           (uint8_t *)&ka, sizeof(ka));
            state->peers[i].last_keepalive_sent = now;
        }
    }
}

/* ============ Transport Interface Implementation ============ */

static cyxwiz_error_t udp_init(cyxwiz_transport_t *transport)
{
    cyxwiz_udp_state_t *state = cyxwiz_calloc(1, sizeof(cyxwiz_udp_state_t));
    if (state == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        CYXWIZ_ERROR("WSAStartup failed: %d", WSAGetLastError());
        cyxwiz_free(state, sizeof(cyxwiz_udp_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }
#endif

    /* Create UDP socket */
    state->socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (state->socket_fd == SOCKET_INVALID) {
        CYXWIZ_ERROR("socket() failed: %d", SOCKET_ERROR_CODE);
#ifdef _WIN32
        WSACleanup();
#endif
        cyxwiz_free(state, sizeof(cyxwiz_udp_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Set non-blocking */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(state->socket_fd, FIONBIO, &mode);
#else
    int flags = fcntl(state->socket_fd, F_GETFL, 0);
    fcntl(state->socket_fd, F_SETFL, flags | O_NONBLOCK);
#endif

    /* Bind to any available port */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;  /* OS assigns port */

    if (bind(state->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CYXWIZ_ERROR("bind() failed: %d", SOCKET_ERROR_CODE);
        close_socket(state->socket_fd);
#ifdef _WIN32
        WSACleanup();
#endif
        cyxwiz_free(state, sizeof(cyxwiz_udp_state_t));
        return CYXWIZ_ERR_TRANSPORT;
    }

    /* Get assigned port */
    socklen_t len = sizeof(addr);
    getsockname(state->socket_fd, (struct sockaddr *)&addr, &len);
    state->local_port = ntohs(addr.sin_port);

    CYXWIZ_INFO("UDP transport bound to port %d", state->local_port);

    /* Load bootstrap servers */
    load_bootstrap_servers(state);

    transport->driver_data = state;
    state->initialized = true;

    /* Start STUN discovery */
    stun_send_request(state);

    return CYXWIZ_OK;
}

static cyxwiz_error_t udp_shutdown(cyxwiz_transport_t *transport)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)transport->driver_data;
    if (state == NULL) {
        return CYXWIZ_OK;
    }

    if (state->socket_fd != SOCKET_INVALID) {
        close_socket(state->socket_fd);
    }

#ifdef _WIN32
    WSACleanup();
#endif

    cyxwiz_free(state, sizeof(cyxwiz_udp_state_t));
    transport->driver_data = NULL;

    CYXWIZ_DEBUG("UDP transport shutdown");
    return CYXWIZ_OK;
}

/* Check if node ID is broadcast address (all 0xFF) */
static bool is_broadcast_id(const cyxwiz_node_id_t *id)
{
    for (size_t i = 0; i < sizeof(cyxwiz_node_id_t); i++) {
        if (id->bytes[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

/* Send wrapped data packet to a specific peer */
static cyxwiz_error_t send_data_to_peer(cyxwiz_transport_t *transport,
                                        cyxwiz_udp_state_t *state,
                                        cyxwiz_udp_peer_t *peer,
                                        const uint8_t *data,
                                        size_t len)
{
    /* Build data packet */
    size_t msg_len = CYXWIZ_UDP_DATA_HDR_SIZE + len;
    uint8_t msg[CYXWIZ_UDP_MAX_PACKET_SIZE + 64];

    cyxwiz_udp_data_t *pkt = (cyxwiz_udp_data_t *)msg;
    pkt->type = CYXWIZ_UDP_DATA;
    memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
    memcpy(pkt->data, data, len);

    return send_to_endpoint(state, &peer->public_addr, msg, msg_len);
}

/* Send packet via bootstrap relay */
static cyxwiz_error_t send_via_relay(cyxwiz_udp_state_t *state,
                                     const cyxwiz_node_id_t *to,
                                     const uint8_t *data, size_t len)
{
    if (state->bootstrap_count == 0) {
        return CYXWIZ_ERR_NO_ROUTE;
    }

    /* Build relay packet: [0xF8][to_id:32][len:2][data...] */
    uint8_t relay_buf[CYXWIZ_UDP_MAX_PACKET_SIZE];
    size_t relay_len = 1 + sizeof(cyxwiz_node_id_t) + 2 + len;

    if (relay_len > sizeof(relay_buf)) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    relay_buf[0] = CYXWIZ_UDP_RELAY_PKT;
    memcpy(&relay_buf[1], to, sizeof(cyxwiz_node_id_t));
    uint16_t net_len = htons((uint16_t)len);
    memcpy(&relay_buf[1 + sizeof(cyxwiz_node_id_t)], &net_len, 2);
    memcpy(&relay_buf[1 + sizeof(cyxwiz_node_id_t) + 2], data, len);

    /* Send to first bootstrap server */
    CYXWIZ_INFO("Sending %zu bytes via relay to bootstrap", len);
    return send_to_endpoint(state, &state->bootstrap_servers[0],
                           relay_buf, relay_len);
}

static cyxwiz_error_t udp_send(cyxwiz_transport_t *transport,
                               const cyxwiz_node_id_t *to,
                               const uint8_t *data,
                               size_t len)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Check size */
    if (len + CYXWIZ_UDP_DATA_HDR_SIZE > CYXWIZ_UDP_MAX_PACKET_SIZE) {
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Check for broadcast destination (all 0xFF) */
    if (is_broadcast_id(to)) {
        /* Send to ALL connected peers */
        cyxwiz_error_t last_err = CYXWIZ_OK;
        size_t sent_count = 0;

        for (size_t i = 0; i < CYXWIZ_MAX_UDP_PEERS; i++) {
            if (state->peers[i].active && state->peers[i].connected) {
                cyxwiz_error_t err = send_data_to_peer(
                    transport, state, &state->peers[i], data, len);
                if (err == CYXWIZ_OK) {
                    sent_count++;
                } else {
                    last_err = err;
                }
            }
        }

        CYXWIZ_DEBUG("Broadcast to %zu peers", sent_count);
        return (sent_count > 0) ? CYXWIZ_OK : last_err;
    }

    /* Check for server/relay direct address (bytes[6] == 0xFF marker) */
    if (to->bytes[6] == 0xFF) {
        cyxwiz_endpoint_t ep;
        memcpy(&ep.ip, &to->bytes[0], 4);
        memcpy(&ep.port, &to->bytes[4], 2);
        return send_to_endpoint(state, &ep, data, len);
    }

    /* Unicast: Find peer endpoint */
    cyxwiz_udp_peer_t *peer = find_peer(state, to);
    if (peer != NULL && peer->connected) {
        /* Send direct to connected peer */
        cyxwiz_error_t err = send_data_to_peer(transport, state, peer, data, len);

        /* Also send via relay as backup — direct path may not actually work
         * (NAT hairpinning, asymmetric NAT, stale connection state).
         * Receiver deduplicates via msg_id. */
        if (state->bootstrap_count > 0) {
            size_t msg_len = CYXWIZ_UDP_DATA_HDR_SIZE + len;
            uint8_t msg[CYXWIZ_UDP_MAX_PACKET_SIZE + 64];
            cyxwiz_udp_data_t *pkt = (cyxwiz_udp_data_t *)msg;
            pkt->type = CYXWIZ_UDP_DATA;
            memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
            memcpy(pkt->data, data, len);
            send_via_relay(state, to, msg, msg_len);
        }
        return err;
    }

    /* Peer not connected - check pending connections and send directly */
    CYXWIZ_INFO("Looking for peer in %zu pending connections", state->pending_count);
    for (size_t i = 0; i < CYXWIZ_MAX_PENDING; i++) {
        if (state->pending[i].active) {
            char hex_pending[17], hex_to[17];
            for (int j = 0; j < 8; j++) {
                snprintf(hex_pending + j*2, 3, "%02x", state->pending[i].peer_id.bytes[j]);
                snprintf(hex_to + j*2, 3, "%02x", to->bytes[j]);
            }
            CYXWIZ_INFO("Pending[%zu]: %s, looking for: %s", i, hex_pending, hex_to);
        }
        if (state->pending[i].active &&
            memcmp(&state->pending[i].peer_id, to, sizeof(cyxwiz_node_id_t)) == 0) {
            /* Build data packet */
            size_t msg_len = CYXWIZ_UDP_DATA_HDR_SIZE + len;
            uint8_t msg[CYXWIZ_UDP_MAX_PACKET_SIZE + 64];

            cyxwiz_udp_data_t *pkt = (cyxwiz_udp_data_t *)msg;
            pkt->type = CYXWIZ_UDP_DATA;
            memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
            memcpy(pkt->data, data, len);

            /* Send via direct endpoint */
            CYXWIZ_INFO("Sending to pending peer via direct endpoint");
            cyxwiz_error_t err = send_to_endpoint(state, &state->pending[i].addr, msg, msg_len);

            /* Also send via relay as backup (parallel approach) */
            if (state->bootstrap_count > 0) {
                uint64_t now = get_time_ms();
                /* Rate limit: relay at most once per second per pending peer */
                if (now - state->pending[i].last_relay > 1000) {
                    CYXWIZ_INFO("Also sending via relay as backup");
                    send_via_relay(state, to, msg, msg_len);
                    state->pending[i].last_relay = now;
                }
            }

            return err;
        }
    }

    /* Last resort: send via relay even without pending entry */
    if (state->bootstrap_count > 0) {
        size_t msg_len = CYXWIZ_UDP_DATA_HDR_SIZE + len;
        uint8_t msg[CYXWIZ_UDP_MAX_PACKET_SIZE + 64];
        cyxwiz_udp_data_t *pkt = (cyxwiz_udp_data_t *)msg;
        pkt->type = CYXWIZ_UDP_DATA;
        memcpy(&pkt->from, &transport->local_id, sizeof(cyxwiz_node_id_t));
        memcpy(pkt->data, data, len);
        CYXWIZ_INFO("Sending via relay as last resort (no direct or pending path)");
        return send_via_relay(state, to, msg, msg_len);
    }

    return CYXWIZ_ERR_PEER_NOT_FOUND;
}

static cyxwiz_error_t udp_discover(cyxwiz_transport_t *transport)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    /* Register with bootstrap to get peer list */
    return bootstrap_register(transport, state);
}

static cyxwiz_error_t udp_stop_discover(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* Nothing to do - discovery is passive */
    return CYXWIZ_OK;
}

static size_t udp_max_packet_size(cyxwiz_transport_t *transport)
{
    CYXWIZ_UNUSED(transport);
    /* Account for UDP_DATA header */
    return CYXWIZ_UDP_MAX_PACKET_SIZE - CYXWIZ_UDP_DATA_HDR_SIZE;
}

static cyxwiz_error_t udp_poll(cyxwiz_transport_t *transport, uint32_t timeout_ms)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)transport->driver_data;

    if (state == NULL || !state->initialized) {
        return CYXWIZ_ERR_NOT_INITIALIZED;
    }

    uint64_t now = get_time_ms();

    /* Retry STUN if needed */
    if (!state->has_public_addr && !state->stun_pending) {
        if (now - state->last_stun_attempt > CYXWIZ_STUN_TIMEOUT_MS) {
            stun_send_request(state);
        }
    }

    /* Re-register with bootstrap periodically */
    if (now - state->last_bootstrap_register > CYXWIZ_BOOTSTRAP_REGISTER_INTERVAL_MS) {
        bootstrap_register(transport, state);
    }

    /* Use select() for timeout */
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(state->socket_fd, &read_fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = select((int)(state->socket_fd + 1), &read_fds, NULL, NULL, &tv);

    if (ready > 0 && FD_ISSET(state->socket_fd, &read_fds)) {
        /* Drain all available packets (e.g. 0xF1 + 0xF2 arrive back-to-back) */
        for (int pkt_idx = 0; pkt_idx < 16; pkt_idx++) {
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t len = recvfrom(state->socket_fd, (char *)state->recv_buf,
                                   sizeof(state->recv_buf), 0,
                                   (struct sockaddr *)&from_addr, &from_len);

            if (len <= 0) {
                break;  /* No more packets */
            }

            cyxwiz_endpoint_t from = {
                .ip = from_addr.sin_addr.s_addr,
                .port = from_addr.sin_port
            };
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, sizeof(ip_str));
            CYXWIZ_INFO("Received %zd bytes from %s:%d (first byte: 0x%02X)",
                       len, ip_str, ntohs(from_addr.sin_port), state->recv_buf[0]);
            handle_received_packet(transport, state, &from,
                                  state->recv_buf, (size_t)len);
        }
    }

    /* Process pending connections */
    process_pending_connections(transport, state);

    /* Send keepalives */
    send_keepalives(transport, state);

    return CYXWIZ_OK;
}

/* Transport operations table */
const cyxwiz_transport_ops_t cyxwiz_udp_ops = {
    .init = udp_init,
    .shutdown = udp_shutdown,
    .send = udp_send,
    .discover = udp_discover,
    .stop_discover = udp_stop_discover,
    .max_packet_size = udp_max_packet_size,
    .poll = udp_poll
};

/* Get NAT type from driver state (called from transport.c) */
cyxwiz_nat_type_t cyxwiz_udp_get_nat_type(void *driver_data)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)driver_data;
    if (state == NULL) {
        return CYXWIZ_NAT_UNKNOWN;
    }
    return state->nat_type;
}

/* Check if bootstrap ACK has been received */
bool cyxwiz_udp_is_bootstrap_connected(void *driver_data)
{
    cyxwiz_udp_state_t *state = (cyxwiz_udp_state_t *)driver_data;
    if (state == NULL) {
        return false;
    }
    return state->bootstrap_ack_received;
}
