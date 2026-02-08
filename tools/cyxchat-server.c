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
#include <direct.h>    /* _mkdir */
#include <io.h>        /* _access, _unlink */
#include <sys/stat.h>  /* _stat */
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
typedef SOCKET socket_t;
#define SOCKET_INVALID INVALID_SOCKET
#define close_socket closesocket
#define mkdir(path, mode) _mkdir(path)
#define stat _stat
#define unlink _unlink
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
typedef int socket_t;
#define SOCKET_INVALID (-1)
#define close_socket close
#endif

/* Configuration */
#define DEFAULT_PORT 7777
#define MAX_PEERS 256
#define NODE_ID_LEN 32
#define PEER_TIMEOUT_SEC 5   /* 5 seconds */
#define MAX_PEERS_PER_LIST 10
#define MAX_RELAY_DATA 1400

/* Offline message queue configuration */
#ifdef _WIN32
#define QUEUE_DIR "cyxchat_queue"  /* Relative to current directory on Windows */
#else
#define QUEUE_DIR "/var/lib/cyxchat/queue"
#endif
#define QUEUE_TTL_SEC (72 * 3600)        /* 72 hours */
#define QUEUE_MAX_SIZE (1 * 1024 * 1024) /* 1 MB per peer */
#define QUEUE_MSG_HEADER_SIZE 42         /* 32 + 2 + 8 */

/* Bootstrap protocol message types (0xF0-0xF3) */
#define CYXWIZ_UDP_REGISTER         0xF0
#define CYXWIZ_UDP_REGISTER_ACK     0xF1
#define CYXWIZ_UDP_PEER_LIST        0xF2
#define CYXWIZ_UDP_CONNECT_REQ      0xF3
#define CYXWIZ_UDP_RELAY_PKT        0xF8    /* Relay any packet to peer */
#define CYXWIZ_UDP_RELAY_ACK        0xF9    /* Client ACK for relayed packet */

/* Reliable delivery configuration */
#define DELIVERY_ACK_TIMEOUT_MS     10000   /* 10 seconds to wait for ACK */
#define MAX_DELIVERY_FAILURES       3       /* Failures before marking peer offline */
#define MAX_PENDING_DELIVERIES      256     /* Max concurrent pending deliveries */

/* Relay protocol message types (0xE0-0xE5) */
#define CYXCHAT_RELAY_CONNECT       0xE0
#define CYXCHAT_RELAY_CONNECT_ACK   0xE1
#define CYXCHAT_RELAY_DISCONNECT    0xE2
#define CYXCHAT_RELAY_DATA          0xE3
#define CYXCHAT_RELAY_KEEPALIVE     0xE4
#define CYXCHAT_RELAY_ERROR         0xE5

/* Server registry message types (0xA0-0xA3) */
#define CYXCHAT_MSG_SERVER_HEALTH_PING      0xA0
#define CYXCHAT_MSG_SERVER_HEALTH_PONG      0xA1
#define CYXCHAT_MSG_SERVER_CHALLENGE        0xA2
#define CYXCHAT_MSG_SERVER_CHALLENGE_RESP   0xA3

/* Presence query message types (0xB0-0xB1) */
#define CYXCHAT_PRESENCE_QUERY              0xB0    /* Query if peer is online */
#define CYXCHAT_PRESENCE_RESPONSE           0xB1    /* Response: online/offline */

#define SERVER_KEY_FILE     "server_key.dat"
#define SERVER_PUBKEY_SIZE  32
#define SERVER_SECKEY_SIZE  64
#define SERVER_SIG_SIZE     64
#define SERVER_NONCE_SIZE   32

/* Node ID */
typedef struct {
    uint8_t bytes[NODE_ID_LEN];
} node_id_t;

/* Forward declarations */
static void clear_pending_for_peer(const node_id_t *peer_id);

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
    time_t queue_deliver_at;    /* When to deliver queued messages (0 = none pending) */
    int delivery_failures;      /* Consecutive failed deliveries */
    int active;
} peer_t;

/* Delay before delivering queued messages (allow key exchange to complete) */
#define QUEUE_DELIVERY_DELAY_SEC 5

/* Pending delivery (waiting for ACK) */
typedef struct {
    uint8_t msg_hash[16];       /* Hash for matching ACK (128-bit) */
    node_id_t to_id;            /* Recipient */
    node_id_t from_id;          /* Sender (for queuing if failed) */
    uint8_t *data;              /* Message data (allocated) */
    uint16_t data_len;          /* Data length */
    uint64_t sent_at_ms;        /* When we sent it (milliseconds) */
    int active;                 /* Slot in use */
} pending_delivery_t;

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

/* Presence query: client asks if peer is online */
typedef struct {
    uint8_t type;           /* CYXCHAT_PRESENCE_QUERY */
    node_id_t requester_id; /* Who is asking */
    node_id_t peer_id;      /* Who to check */
} PACKED presence_query_t;

/* Presence response: server tells if peer is online */
typedef struct {
    uint8_t type;           /* CYXCHAT_PRESENCE_RESPONSE */
    node_id_t peer_id;      /* The peer queried */
    uint8_t online;         /* 1 = online, 0 = offline */
} PACKED presence_response_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

/* Global state */
static peer_t g_peers[MAX_PEERS];
static size_t g_peer_count = 0;
static volatile int g_running = 1;
static socket_t g_socket = SOCKET_INVALID;

/* Pending deliveries (waiting for ACK) */
static pending_delivery_t g_pending[MAX_PENDING_DELIVERIES];
static size_t g_pending_count = 0;

/* Stats */
static uint64_t g_bytes_relayed = 0;
static uint64_t g_messages_relayed = 0;
static uint64_t g_messages_queued_on_timeout = 0;

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

static peer_t *find_peer_by_addr(const struct sockaddr_in *addr)
{
    for (size_t i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].active &&
            g_peers[i].addr.ip == addr->sin_addr.s_addr &&
            g_peers[i].addr.port == addr->sin_port) {
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

/* Convert full node ID to hex string (64 chars + null) */
static void node_id_to_hex_full(const node_id_t *id, char *out)
{
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < NODE_ID_LEN; i++) {
        out[i * 2] = hex[(id->bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[id->bytes[i] & 0x0F];
    }
    out[NODE_ID_LEN * 2] = '\0';
}

/* ============ Reliable Delivery (ACK-based) ============ */

/* Get current time in milliseconds */
static uint64_t get_time_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

/* Compute hash for message matching (128-bit) */
static void compute_msg_hash(const uint8_t *data, uint16_t len,
                             const node_id_t *to_id, uint8_t *hash_out)
{
    /* BLAKE2b hash of data + to_id */
    uint8_t full_hash[32];
    crypto_generichash(full_hash, sizeof(full_hash),
                       data, len,
                       to_id->bytes, NODE_ID_LEN);
    memcpy(hash_out, full_hash, 16);  /* 128-bit hash */
}

/* Add a pending delivery */
static int add_pending_delivery(const node_id_t *to_id, const node_id_t *from_id,
                                 const uint8_t *data, uint16_t data_len,
                                 const uint8_t *msg_hash)
{
    /* Find free slot */
    int slot = -1;
    for (size_t i = 0; i < MAX_PENDING_DELIVERIES; i++) {
        if (!g_pending[i].active) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        printf("Pending delivery queue full!\n");
        return -1;
    }

    pending_delivery_t *pd = &g_pending[slot];
    memcpy(pd->msg_hash, msg_hash, 16);
    memcpy(&pd->to_id, to_id, sizeof(node_id_t));
    memcpy(&pd->from_id, from_id, sizeof(node_id_t));

    pd->data = malloc(data_len);
    if (!pd->data) {
        return -1;
    }
    memcpy(pd->data, data, data_len);
    pd->data_len = data_len;
    pd->sent_at_ms = get_time_ms();
    pd->active = 1;
    g_pending_count++;

    return slot;
}

/* Find pending delivery by hash */
static pending_delivery_t *find_pending_by_hash(const uint8_t *hash)
{
    for (size_t i = 0; i < MAX_PENDING_DELIVERIES; i++) {
        if (g_pending[i].active &&
            memcmp(g_pending[i].msg_hash, hash, 16) == 0) {
            return &g_pending[i];
        }
    }
    return NULL;
}

/* Remove a pending delivery */
static void remove_pending(pending_delivery_t *pd)
{
    if (pd && pd->active) {
        if (pd->data) {
            free(pd->data);
            pd->data = NULL;
        }
        pd->active = 0;
        if (g_pending_count > 0) {
            g_pending_count--;
        }
    }
}

/* Forward declaration for queue_message */
static void queue_message(const node_id_t *to_id, const node_id_t *from_id,
                          const uint8_t *data, uint16_t len);

/* Process pending deliveries - check for timeouts */
static void process_pending_deliveries(void)
{
    uint64_t now = get_time_ms();

    for (size_t i = 0; i < MAX_PENDING_DELIVERIES; i++) {
        pending_delivery_t *pd = &g_pending[i];
        if (!pd->active) continue;

        uint64_t elapsed = now - pd->sent_at_ms;
        if (elapsed >= DELIVERY_ACK_TIMEOUT_MS) {
            /* Timeout - no ACK received */
            char hex_id[17];
            node_id_to_hex(&pd->to_id, hex_id);

            peer_t *peer = find_peer(&pd->to_id);
            if (peer && peer->active) {
                /* Peer registered but not responding - track failures */
                peer->delivery_failures++;
                if (peer->delivery_failures >= MAX_DELIVERY_FAILURES) {
                    /* Too many failures - mark offline */
                    printf("Peer %s... offline after %d failures\n",
                           hex_id, peer->delivery_failures);
                    peer->active = 0;
                    if (g_peer_count > 0) g_peer_count--;

                    /* Queue ALL pending messages for this peer */
                    int queued = 0;
                    for (size_t j = 0; j < MAX_PENDING_DELIVERIES; j++) {
                        pending_delivery_t *pj = &g_pending[j];
                        if (pj->active && memcmp(&pj->to_id, &pd->to_id, sizeof(node_id_t)) == 0) {
                            queue_message(&pj->to_id, &pj->from_id, pj->data, pj->data_len);
                            g_messages_queued_on_timeout++;
                            remove_pending(pj);
                            queued++;
                        }
                    }
                    printf("Queued %d pending messages for %s...\n", queued, hex_id);
                    continue;  /* Already handled, skip to next */
                }
                remove_pending(pd);
            } else {
                /* Peer not registered - queue immediately */
                printf("Timeout for %s... (not registered) - queuing\n", hex_id);
                queue_message(&pd->to_id, &pd->from_id, pd->data, pd->data_len);
                g_messages_queued_on_timeout++;
                remove_pending(pd);
            }
        }
    }
}

/* ============ Offline Message Queue ============ */

/* Initialize queue directory */
static void init_queue_dir(void)
{
    mkdir(QUEUE_DIR, 0755);  /* On Windows, mode is ignored by _mkdir */
}

/* Queue a message for an offline peer */
static void queue_message(const node_id_t *to_id,
                          const node_id_t *from_id,
                          const uint8_t *data, uint16_t len)
{
    char hex[65];
    node_id_to_hex_full(to_id, hex);

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.queue", QUEUE_DIR, hex);

    /* Check file size limit */
    struct stat st;
    if (stat(path, &st) == 0 && (size_t)(st.st_size + len + QUEUE_MSG_HEADER_SIZE) > QUEUE_MAX_SIZE) {
        char hex_short[17];
        node_id_to_hex(to_id, hex_short);
        printf("Queue full for peer %s..., dropping message\n", hex_short);
        return;
    }

    FILE *f = fopen(path, "ab");
    if (!f) {
        printf("Failed to open queue file: %s\n", path);
        return;
    }

    /* Write header: from_id(32) + len(2) + timestamp(8) */
    time_t now = time(NULL);
    uint16_t len_net = htons(len);

    /* Check all fwrite return values */
    if (fwrite(from_id->bytes, NODE_ID_LEN, 1, f) != 1 ||
        fwrite(&len_net, sizeof(len_net), 1, f) != 1 ||
        fwrite(&now, sizeof(now), 1, f) != 1 ||
        fwrite(data, len, 1, f) != 1) {
        printf("Failed to write queue entry (disk full?)\n");
        fclose(f);
        return;
    }
    fclose(f);

    char to_hex[17], from_hex[17];
    node_id_to_hex(to_id, to_hex);
    node_id_to_hex(from_id, from_hex);
    printf("Queued %d bytes for offline peer %s... (from %s...)\n",
           len, to_hex, from_hex);
}

/* Deliver queued messages to a peer that just came online */
static void deliver_queued_messages(const node_id_t *peer_id,
                                     const endpoint_t *addr)
{
    char hex[65];
    node_id_to_hex_full(peer_id, hex);

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.queue", QUEUE_DIR, hex);

    FILE *f = fopen(path, "rb");
    if (!f) return;  /* No queue */

    time_t now = time(NULL);
    int delivered = 0, expired = 0;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = addr->ip;
    dest.sin_port = addr->port;

    while (!feof(f)) {
        /* Read header */
        node_id_t from_id;
        uint16_t len_net;
        time_t queued_at;

        if (fread(&from_id, NODE_ID_LEN, 1, f) != 1) break;
        if (fread(&len_net, sizeof(len_net), 1, f) != 1) break;
        if (fread(&queued_at, sizeof(queued_at), 1, f) != 1) break;

        uint16_t len = ntohs(len_net);
        if (len > MAX_RELAY_DATA) {
            /* Corrupted entry, abort */
            break;
        }

        uint8_t *data = malloc(len);
        if (!data) break;

        if (fread(data, len, 1, f) != 1) {
            free(data);
            break;
        }

        /* Check TTL */
        if (now - queued_at > QUEUE_TTL_SEC) {
            expired++;
            free(data);
            continue;
        }

        /* Deliver */
        sendto(g_socket, (char *)data, len, 0,
               (struct sockaddr *)&dest, sizeof(dest));

        delivered++;
        free(data);
    }

    fclose(f);

    /* Delete queue file after delivery */
    unlink(path);

    if (delivered > 0 || expired > 0) {
        char hex_short[17];
        node_id_to_hex(peer_id, hex_short);
        printf("Delivered %d queued messages to %s... (%d expired)\n",
               delivered, hex_short, expired);
    }
}

/* Cleanup expired queue files */
/* Validate queue filename: must be 64 hex chars + ".queue" */
static int is_valid_queue_filename(const char *name)
{
    size_t len = strlen(name);
    if (len != 70) return 0;  /* 64 hex + 6 for ".queue" */
    if (strcmp(name + 64, ".queue") != 0) return 0;
    for (int i = 0; i < 64; i++) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

static void cleanup_expired_queues(void)
{
    time_t now = time(NULL);

#ifdef _WIN32
    /* Windows: Use FindFirstFile/FindNextFile */
    char search_path[256];
    snprintf(search_path, sizeof(search_path), "%s\\*.queue", QUEUE_DIR);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        /* Validate filename to prevent path traversal */
        if (!is_valid_queue_filename(ffd.cFileName)) {
            continue;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s\\%s", QUEUE_DIR, ffd.cFileName);

        struct stat st;
        if (stat(path, &st) == 0) {
            /* Delete if file older than TTL */
            if (now - st.st_mtime > QUEUE_TTL_SEC) {
                unlink(path);
                printf("Expired queue file: %s\n", ffd.cFileName);
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
#else
    /* POSIX: Use opendir/readdir */
    DIR *dir = opendir(QUEUE_DIR);
    if (!dir) return;

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Validate filename to prevent path traversal */
        if (!is_valid_queue_filename(entry->d_name)) {
            continue;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s/%s", QUEUE_DIR, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0) {
            /* Delete if file older than TTL */
            if (now - st.st_mtime > QUEUE_TTL_SEC) {
                unlink(path);
                printf("Expired queue file: %s\n", entry->d_name);
            }
        }
    }
    closedir(dir);
#endif
}

/* Process scheduled queue deliveries */
static void process_scheduled_deliveries(void)
{
    time_t now = time(NULL);

    for (size_t i = 0; i < g_peer_count; i++) {
        peer_t *peer = &g_peers[i];
        if (!peer->active || peer->queue_deliver_at == 0) {
            continue;
        }

        if (now >= peer->queue_deliver_at) {
            /* Time to deliver */
            deliver_queued_messages(&peer->id, &peer->addr);
            peer->queue_deliver_at = 0;  /* Clear the schedule */
        }
    }
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
        /* Reset delivery failures - peer is clearly online */
        peer->delivery_failures = 0;

        /* Clear any pending deliveries for this peer (implicit ACK) */
        clear_pending_for_peer(&msg->node_id);

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

    /* Schedule delayed delivery of queued messages (allow key exchange to complete first) */
    if (peer != NULL) {
        char queue_path[256];
        char hex[65];
        node_id_to_hex_full(&msg->node_id, hex);
        snprintf(queue_path, sizeof(queue_path), "%s/%s.queue", QUEUE_DIR, hex);

        struct stat st;
        if (stat(queue_path, &st) == 0 && st.st_size > 0) {
            peer->queue_deliver_at = time(NULL) + QUEUE_DELIVERY_DELAY_SEC;
            printf("Scheduled queue delivery for %s... in %d seconds\n",
                   hex_id, QUEUE_DELIVERY_DELAY_SEC);
            fflush(stdout);
        }
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
        char from_hex[17], tgt_hex[17];
        for (int j = 0; j < 8; j++) {
            snprintf(from_hex + j*2, 3, "%02x", msg->requester_id.bytes[j]);
            snprintf(tgt_hex + j*2, 3, "%02x", target_id->bytes[j]);
        }
        printf("Connect request from %s... for unknown peer %s...\n", from_hex, tgt_hex);
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

/* Handle relay ACK (client confirms receipt of relayed message) */
static void handle_relay_ack(const struct sockaddr_in *from,
                             const uint8_t *data, size_t len)
{
    /* Format: [0xF9][msg_hash:16][node_id:32] = 49 bytes */
    if (len < 1 + 16 + NODE_ID_LEN) {
        return;
    }

    const uint8_t *msg_hash = data + 1;
    const node_id_t *peer_id = (const node_id_t *)(data + 1 + 16);

    /* Validate: ACK must come from a registered peer matching the claimed ID */
    peer_t *sender = find_peer_by_addr(from);
    if (sender == NULL) {
        /* ACK from unknown address - ignore */
        return;
    }

    /* Verify the peer_id in the ACK matches the sender's registered ID */
    if (memcmp(&sender->id, peer_id, sizeof(node_id_t)) != 0) {
        /* Spoofed ACK - peer_id doesn't match sender's address */
        char claimed_hex[17], actual_hex[17];
        node_id_to_hex(peer_id, claimed_hex);
        node_id_to_hex(&sender->id, actual_hex);
        printf("WARNING: Spoofed ACK detected! Claimed=%s... Actual=%s...\n",
               claimed_hex, actual_hex);
        return;
    }

    /* Find pending delivery by hash */
    pending_delivery_t *pd = find_pending_by_hash(msg_hash);
    if (pd == NULL) {
        /* No matching pending delivery - stale or duplicate ACK */
        return;
    }

    /* Verify the pending delivery was actually for this peer */
    if (memcmp(&pd->to_id, peer_id, sizeof(node_id_t)) != 0) {
        /* Hash collision or spoofing attempt */
        char pending_hex[17], ack_hex[17];
        node_id_to_hex(&pd->to_id, pending_hex);
        node_id_to_hex(peer_id, ack_hex);
        printf("WARNING: ACK hash collision! Pending for=%s... ACK from=%s...\n",
               pending_hex, ack_hex);
        return;
    }

    /* Valid ACK - update peer activity and remove pending */
    sender->last_activity = time(NULL);
    sender->delivery_failures = 0;

    char hex_id[17];
    node_id_to_hex(peer_id, hex_id);
    printf("ACK received for message to %s...\n", hex_id);
    remove_pending(pd);
}

/* Clear pending deliveries for a peer (implicit ACK via activity) */
static void clear_pending_for_peer(const node_id_t *peer_id)
{
    int cleared = 0;
    for (size_t i = 0; i < MAX_PENDING_DELIVERIES; i++) {
        pending_delivery_t *pd = &g_pending[i];
        if (pd->active &&
            memcmp(&pd->to_id, peer_id, sizeof(node_id_t)) == 0) {
            /* Peer is responsive - no need to track this anymore */
            remove_pending(pd);
            cleared++;
        }
    }
    if (cleared > 0) {
        char hex_id[17];
        node_id_to_hex(peer_id, hex_id);
        printf("Cleared %d pending deliveries for %s... (implicit ACK)\n",
               cleared, hex_id);
    }
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
    /* Format: [0xF8][to_id:32][data_len:2][data...] */
    if (len < 1 + NODE_ID_LEN + 2) {
        return;
    }

    const node_id_t *to_id = (const node_id_t *)(data + 1);
    uint16_t data_len;
    memcpy(&data_len, data + 1 + NODE_ID_LEN, 2);
    data_len = ntohs(data_len);

    /* Validate data_len against max allowed */
    if (data_len > MAX_RELAY_DATA) {
        printf("Relay packet data_len %u exceeds max %d\n", data_len, MAX_RELAY_DATA);
        return;
    }

    if (len < 1 + NODE_ID_LEN + 2 + data_len) {
        return;
    }

    /* Get sender info */
    peer_t *sender = find_peer_by_addr(from);
    node_id_t from_id;
    if (sender != NULL) {
        memcpy(&from_id, &sender->id, sizeof(node_id_t));
    } else {
        memset(&from_id, 0, sizeof(node_id_t));
    }

    const uint8_t *payload = data + 1 + NODE_ID_LEN + 2;

    /* Find target peer */
    peer_t *target = find_peer(to_id);

    char hex_id[17];
    node_id_to_hex(to_id, hex_id);

    if (target == NULL || !target->active) {
        /* Target offline — queue immediately */
        queue_message(to_id, &from_id, payload, data_len);
        return;
    }

    /* Target is online — relay instantly (no ACK overhead) */
    send_to_peer(target, payload, data_len);

    g_bytes_relayed += data_len;
    g_messages_relayed++;

    printf("Relayed %u bytes to %s...\n", data_len, hex_id);
    fflush(stdout);
}

/* Handle presence query - check if peer is online */
static void handle_presence_query(const struct sockaddr_in *from, const uint8_t *data, size_t len)
{
    if (len < sizeof(presence_query_t)) {
        return;
    }

    const presence_query_t *query = (const presence_query_t *)data;

    char hex_id[17];
    node_id_to_hex(&query->peer_id, hex_id);

    /* Check if peer is registered and active */
    peer_t *peer = find_peer(&query->peer_id);
    uint8_t online = (peer != NULL && peer->active) ? 1 : 0;

    /* Send response */
    presence_response_t resp;
    resp.type = CYXCHAT_PRESENCE_RESPONSE;
    memcpy(&resp.peer_id, &query->peer_id, sizeof(node_id_t));
    resp.online = online;

    sendto(g_socket, (const char *)&resp, sizeof(resp), 0,
           (const struct sockaddr *)from, sizeof(*from));

    printf("Presence query: %s... = %s\n", hex_id, online ? "online" : "offline"); fflush(stdout);
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

        case CYXWIZ_UDP_RELAY_ACK:
            handle_relay_ack(from, data, len);
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

        /* Presence protocol */
        case CYXCHAT_PRESENCE_QUERY:
            handle_presence_query(from, data, len);
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

    /* Initialize offline message queue directory */
    init_queue_dir();

    /* Main loop */
    uint8_t buf[2048];
    time_t last_cleanup = time(NULL);
    time_t last_queue_cleanup = time(NULL);

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

        /* Process scheduled queue deliveries */
        process_scheduled_deliveries();

        /* Note: Pending delivery tracking removed for simplicity.
         * Relay is now instant - queue only when peer not registered. */

        /* Hourly queue cleanup */
        if (now - last_queue_cleanup > 3600) {
            cleanup_expired_queues();
            last_queue_cleanup = now;
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
