/* Disable MSVC security warnings for standard C functions */
#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif

/*
 * CyxWiz Protocol - Node Daemon
 *
 * Main entry point for the CyxWiz node.
 * Runs as a background daemon, participating in the mesh network.
 */

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/log.h"
#include "cyxwiz/memory.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include "cyxwiz/crypto.h"
#include "cyxwiz/onion.h"
#endif

#ifdef CYXWIZ_HAS_COMPUTE
#include "cyxwiz/compute.h"
#endif

#ifdef CYXWIZ_HAS_STORAGE
#include "cyxwiz/storage.h"
#endif

#ifdef CYXWIZ_HAS_CONSENSUS
#include "cyxwiz/consensus.h"
#endif

#ifdef CYXWIZ_HAS_PRIVACY
#include "cyxwiz/privacy.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/select.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

static volatile bool g_running = true;
static bool g_batch_mode = false;

static void signal_handler(int sig)
{
    CYXWIZ_UNUSED(sig);
    CYXWIZ_INFO("Received shutdown signal");
    g_running = false;
}

/* Forward declarations */
static cyxwiz_discovery_t *g_discovery = NULL;
static cyxwiz_router_t *g_router = NULL;
#ifdef CYXWIZ_HAS_CRYPTO
static cyxwiz_onion_ctx_t *g_onion = NULL;
#endif
#ifdef CYXWIZ_HAS_COMPUTE
static cyxwiz_compute_ctx_t *g_compute = NULL;
#endif
#ifdef CYXWIZ_HAS_STORAGE
static cyxwiz_storage_ctx_t *g_storage = NULL;
#endif
#ifdef CYXWIZ_HAS_CONSENSUS
static cyxwiz_consensus_ctx_t *g_consensus = NULL;
static cyxwiz_identity_keypair_t g_identity;
#endif

static void on_peer_discovered(
    cyxwiz_transport_t *transport,
    const cyxwiz_peer_info_t *peer,
    void *user_data)
{
    CYXWIZ_UNUSED(user_data);
    CYXWIZ_INFO("Discovered peer via %s (RSSI: %d dBm)",
        cyxwiz_transport_type_name(transport->type),
        peer->rssi);
}

static void on_peer_state_change(
    cyxwiz_peer_table_t *table,
    const cyxwiz_peer_t *peer,
    cyxwiz_peer_state_t old_state,
    void *user_data)
{
    CYXWIZ_UNUSED(table);
    CYXWIZ_UNUSED(user_data);

    char hex_id[65];
    cyxwiz_node_id_to_hex(&peer->id, hex_id);

    CYXWIZ_INFO("Peer %.16s... state: %s -> %s",
        hex_id,
        cyxwiz_peer_state_name(old_state),
        cyxwiz_peer_state_name(peer->state));
}

static void on_data_received(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    CYXWIZ_UNUSED(transport);
    CYXWIZ_UNUSED(user_data);
    CYXWIZ_DEBUG("Received %zu bytes", len);

    if (len == 0) {
        return;
    }

    /* Dispatch by message type */
    uint8_t msg_type = data[0];

    if (msg_type >= 0x20 && msg_type <= 0x2F) {
        /* Routing messages (ROUTE_REQ, ROUTE_REPLY, ROUTE_DATA, ROUTE_ERROR) */
        if (g_router != NULL) {
            cyxwiz_router_handle_message(g_router, from, data, len);
        }
    } else if (msg_type >= 0x01 && msg_type <= 0x0F) {
        /* Discovery messages (ANNOUNCE, ANNOUNCE_ACK) */
        if (g_discovery != NULL) {
            cyxwiz_discovery_handle_message(g_discovery, from, data, len);
        }
#ifdef CYXWIZ_HAS_COMPUTE
    } else if (msg_type >= 0x30 && msg_type <= 0x3F) {
        /* Compute messages (JOB_SUBMIT, JOB_RESULT, etc.) */
        if (g_compute != NULL) {
            cyxwiz_compute_handle_message(g_compute, from, data, len);
        }
#endif
#ifdef CYXWIZ_HAS_STORAGE
    } else if (msg_type >= 0x40 && msg_type <= 0x4F) {
        /* Storage messages (STORE_REQ, RETRIEVE_REQ, etc.) */
        if (g_storage != NULL) {
            cyxwiz_storage_handle_message(g_storage, from, data, len);
        }
#endif
#ifdef CYXWIZ_HAS_CONSENSUS
    } else if (msg_type >= 0x60 && msg_type <= 0x6F) {
        /* Consensus messages (VALIDATOR_REGISTER, VOTE, etc.) */
        if (g_consensus != NULL) {
            cyxwiz_consensus_handle_message(g_consensus, from, data, len);
        }
    } else if (msg_type >= 0x70 && msg_type <= 0x7F) {
        /* Privacy messages (ANON_VOTE, CRED_SHOW, etc.) */
        if (g_consensus != NULL) {
            cyxwiz_consensus_handle_message(g_consensus, from, data, len);
        }
#endif
    } else {
        CYXWIZ_DEBUG("Unknown message type: 0x%02X", msg_type);
    }
}

static void on_routed_data(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    CYXWIZ_UNUSED(user_data);

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);
    CYXWIZ_INFO("Received %zu bytes via route from %.16s...", len, hex_id);

#ifdef CYXWIZ_HAS_COMPUTE
    /* Dispatch compute messages received via routing */
    if (len > 0 && data[0] >= 0x30 && data[0] <= 0x3F) {
        if (g_compute != NULL) {
            cyxwiz_compute_handle_message(g_compute, from, data, len);
        }
        return;
    }
#endif

#ifdef CYXWIZ_HAS_STORAGE
    /* Dispatch storage messages received via routing */
    if (len > 0 && data[0] >= 0x40 && data[0] <= 0x4F) {
        if (g_storage != NULL) {
            cyxwiz_storage_handle_message(g_storage, from, data, len);
        }
        return;
    }
#endif

#ifdef CYXWIZ_HAS_CONSENSUS
    /* Dispatch consensus messages received via routing */
    if (len > 0 && data[0] >= 0x60 && data[0] <= 0x7F) {
        if (g_consensus != NULL) {
            cyxwiz_consensus_handle_message(g_consensus, from, data, len);
        }
        return;
    }
#endif
}

#ifdef CYXWIZ_HAS_CRYPTO
/* Called when discovery receives a peer's public key */
static void on_peer_key_exchange(
    const cyxwiz_node_id_t *peer_id,
    const uint8_t *peer_pubkey,
    void *user_data)
{
    CYXWIZ_UNUSED(user_data);

    if (g_onion == NULL) {
        return;
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(peer_id, hex_id);
    CYXWIZ_DEBUG("Received public key from %.16s...", hex_id);

    /* Add peer's public key to onion context (computes shared secret) */
    cyxwiz_error_t err = cyxwiz_onion_add_peer_key(g_onion, peer_id, peer_pubkey);
    if (err != CYXWIZ_OK) {
        CYXWIZ_WARN("Failed to add peer key: %s", cyxwiz_strerror(err));
    }
}

/* Called when router receives an onion message */
static void on_onion_message(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    CYXWIZ_UNUSED(user_data);

    if (g_onion == NULL) {
        return;
    }

    /* Forward to onion layer for decryption/routing */
    cyxwiz_error_t err = cyxwiz_onion_handle_message(g_onion, from, data, len);
    if (err != CYXWIZ_OK) {
        CYXWIZ_DEBUG("Onion message handling failed: %s", cyxwiz_strerror(err));
    }
}

/* Called when onion data reaches us (final destination) */
static void on_onion_delivery(
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    CYXWIZ_UNUSED(user_data);

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);

    /* Print the received message */
    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║  ANONYMOUS MESSAGE RECEIVED                  ║\n");
    printf("  ╠══════════════════════════════════════════════╣\n");
    printf("  ║  From: %.16s... (via onion)       ║\n", hex_id);
    printf("  ║  Size: %zu bytes                              \n", len);
    printf("  ╠══════════════════════════════════════════════╣\n");

    /* Print message content (if printable) */
    if (len > 0 && data != NULL) {
        printf("  ║  \"");
        for (size_t i = 0; i < len && i < 50; i++) {
            if (data[i] >= 32 && data[i] < 127) {
                putchar(data[i]);
            } else {
                putchar('.');
            }
        }
        if (len > 50) {
            printf("...");
        }
        printf("\"\n");
    }

    printf("  ╚══════════════════════════════════════════════╝\n");
    printf("\n> ");
    fflush(stdout);

    CYXWIZ_INFO("Received %zu bytes via onion from %.16s...", len, hex_id);
}
#endif

/* ============ Interactive Commands ============ */

static char g_cmd_buffer[256];
static size_t g_cmd_len = 0;
static cyxwiz_peer_table_t *g_peer_table = NULL;
static cyxwiz_node_id_t g_local_id;

/* Check if stdin has input available (non-blocking) */
static int stdin_available(void)
{
#ifdef _WIN32
    return _kbhit();
#else
    fd_set fds;
    struct timeval tv = {0, 0};
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
#endif
}

/* Read a character from stdin (non-blocking) */
static int read_char(void)
{
#ifdef _WIN32
    if (_kbhit()) {
        return _getch();
    }
    return -1;
#else
    if (stdin_available()) {
        return getchar();
    }
    return -1;
#endif
}

/* Find peer by ID prefix (hex string) */
static const cyxwiz_peer_t *find_peer_by_prefix(const char *prefix)
{
    if (g_peer_table == NULL || prefix == NULL) {
        return NULL;
    }

    size_t prefix_len = strlen(prefix);
    if (prefix_len < 4) {
        return NULL;  /* Need at least 4 hex chars */
    }

    for (size_t i = 0; i < cyxwiz_peer_table_count(g_peer_table); i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(g_peer_table, i);
        if (peer == NULL) continue;

        char hex_id[65];
        cyxwiz_node_id_to_hex(&peer->id, hex_id);

        if (strncmp(hex_id, prefix, prefix_len) == 0) {
            return peer;
        }
    }

    return NULL;
}

/* Print command help */
static void cmd_help(void)
{
    printf("\n");
    printf("  Available Commands:\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  /help                    Show this help\n");
    printf("  /status                  Show node status\n");
    printf("  /peers                   List connected peers\n");
    printf("  /send <peer_id> <msg>    Send direct message\n");
    printf("  /anon <peer_id> <msg>    Send anonymous message\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  /store <data>            Store data (returns ID)\n");
    printf("  /retrieve <storage_id>   Retrieve stored data\n");
    printf("  /storage                 Show storage status\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  /compute <data>          Submit compute job\n");
    printf("  /jobs                    List active jobs\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  /validators              List validators\n");
    printf("  /credits                 Show work credits\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  /quit                    Exit the daemon\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
    printf("  Note: peer_id can be first 8+ hex chars\n");
    printf("        storage_id is 16 hex chars\n");
    printf("\n");
}

/* Print node status */
static void cmd_status(void)
{
    char hex_id[65];
    cyxwiz_node_id_to_hex(&g_local_id, hex_id);

    printf("\n");
    printf("  Node Status:\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  Node ID:     %.16s...\n", hex_id);
    printf("  Peers:       %zu connected\n",
           g_peer_table ? cyxwiz_peer_table_count(g_peer_table) : 0);

#ifdef CYXWIZ_HAS_CONSENSUS
    if (g_consensus != NULL) {
        printf("  Validators:  %zu registered\n",
               cyxwiz_consensus_validator_count(g_consensus));
    }
#endif

#ifdef CYXWIZ_HAS_CRYPTO
    printf("  Onion:       %s\n", g_onion != NULL ? "enabled" : "disabled");
#endif

    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
}

/* List connected peers */
static void cmd_peers(void)
{
    if (g_peer_table == NULL) {
        printf("  No peer table available\n");
        return;
    }

    size_t count = cyxwiz_peer_table_count(g_peer_table);
    printf("\n");
    printf("  Connected Peers (%zu):\n", count);
    printf("  ───────────────────────────────────────────────\n");

    if (count == 0) {
        printf("  (no peers connected)\n");
    }

    for (size_t i = 0; i < count; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(g_peer_table, i);
        if (peer == NULL) continue;

        char hex_id[65];
        cyxwiz_node_id_to_hex(&peer->id, hex_id);

        printf("  [%zu] %.16s...  %s\n",
               i + 1, hex_id,
               cyxwiz_peer_state_name(peer->state));
    }

    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
}

/* Send direct message */
static void cmd_send(const char *args)
{
    if (args == NULL || *args == '\0') {
        printf("  Usage: /send <peer_id> <message>\n");
        return;
    }

    /* Parse peer ID and message */
    char peer_prefix[32];
    const char *message = NULL;

    const char *space = strchr(args, ' ');
    if (space == NULL) {
        printf("  Usage: /send <peer_id> <message>\n");
        return;
    }

    size_t prefix_len = (size_t)(space - args);
    if (prefix_len >= sizeof(peer_prefix)) {
        prefix_len = sizeof(peer_prefix) - 1;
    }
    memcpy(peer_prefix, args, prefix_len);
    peer_prefix[prefix_len] = '\0';

    message = space + 1;
    while (*message == ' ') message++;

    if (*message == '\0') {
        printf("  Usage: /send <peer_id> <message>\n");
        return;
    }

    /* Find peer */
    const cyxwiz_peer_t *peer = find_peer_by_prefix(peer_prefix);
    if (peer == NULL) {
        printf("  Error: No peer found matching '%s'\n", peer_prefix);
        return;
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(&peer->id, hex_id);

    /* Send via router */
    if (g_router == NULL) {
        printf("  Error: Router not available\n");
        return;
    }

    /* Create a simple text message (type 0x01 = PING with text payload) */
    uint8_t msg_buf[256];
    size_t msg_len = strlen(message);
    if (msg_len > 200) msg_len = 200;

    msg_buf[0] = 0x01;  /* PING message type */
    memcpy(msg_buf + 1, message, msg_len);

    cyxwiz_error_t err = cyxwiz_router_send(g_router, &peer->id, msg_buf, msg_len + 1);
    if (err == CYXWIZ_OK) {
        printf("  Sent to %.16s...: \"%s\"\n", hex_id, message);
    } else {
        printf("  Error sending: %s\n", cyxwiz_strerror(err));
    }
}

/* Send anonymous message via onion routing */
static void cmd_anon(const char *args)
{
#ifndef CYXWIZ_HAS_CRYPTO
    printf("  Error: Onion routing not available (no crypto)\n");
    return;
#else
    if (g_onion == NULL) {
        printf("  Error: Onion routing not initialized\n");
        return;
    }

    if (args == NULL || *args == '\0') {
        printf("  Usage: /anon <peer_id> <message>\n");
        return;
    }

    /* Parse peer ID and message */
    char peer_prefix[32];
    const char *message = NULL;

    const char *space = strchr(args, ' ');
    if (space == NULL) {
        printf("  Usage: /anon <peer_id> <message>\n");
        return;
    }

    size_t prefix_len = (size_t)(space - args);
    if (prefix_len >= sizeof(peer_prefix)) {
        prefix_len = sizeof(peer_prefix) - 1;
    }
    memcpy(peer_prefix, args, prefix_len);
    peer_prefix[prefix_len] = '\0';

    message = space + 1;
    while (*message == ' ') message++;

    if (*message == '\0') {
        printf("  Usage: /anon <peer_id> <message>\n");
        return;
    }

    /* Find peer */
    const cyxwiz_peer_t *peer = find_peer_by_prefix(peer_prefix);
    if (peer == NULL) {
        printf("  Error: No peer found matching '%s'\n", peer_prefix);
        return;
    }

    char hex_id[65];
    cyxwiz_node_id_to_hex(&peer->id, hex_id);

    /* Check if we have a peer to send to */
    size_t peer_count = g_peer_table ? cyxwiz_peer_table_count(g_peer_table) : 0;
    if (peer_count < 1) {
        printf("  Error: Need at least 1 peer for anonymous messaging\n");
        return;
    }

    /* Send via onion (direct 1-hop if only 1 peer, or 2-hop with relay) */
    size_t msg_len = strlen(message);
    if (msg_len > 100) msg_len = 100;  /* Onion payload is limited */

    cyxwiz_error_t err = cyxwiz_onion_send_to(g_onion, &peer->id,
                                               (const uint8_t *)message, msg_len);
    if (err == CYXWIZ_OK) {
        printf("  Sent anonymously to %.16s...\n", hex_id);
    } else {
        printf("  Error sending: %s\n", cyxwiz_strerror(err));
    }
#endif
}

/* Store data */
static void cmd_store(const char *args)
{
#ifndef CYXWIZ_HAS_STORAGE
    printf("  Error: Storage not available (no crypto)\n");
    return;
#else
    if (g_storage == NULL) {
        printf("  Error: Storage not initialized\n");
        return;
    }

    if (args == NULL || *args == '\0') {
        printf("  Usage: /store <data>\n");
        return;
    }

    /* Get connected peers as providers */
    if (g_peer_table == NULL) {
        printf("  Error: No peer table available\n");
        return;
    }

    size_t peer_count = cyxwiz_peer_table_count(g_peer_table);
    if (peer_count < 2) {
        printf("  Error: Need at least 2 peers for distributed storage\n");
        printf("  Current peers: %zu\n", peer_count);
        return;
    }

    /* Collect provider IDs (up to 5 peers, threshold 3) */
    cyxwiz_node_id_t providers[5];
    size_t num_providers = 0;
    uint8_t threshold = 3;

    for (size_t i = 0; i < peer_count && num_providers < 5; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(g_peer_table, i);
        if (peer != NULL && peer->state == CYXWIZ_PEER_STATE_CONNECTED) {
            memcpy(&providers[num_providers], &peer->id, sizeof(cyxwiz_node_id_t));
            num_providers++;
        }
    }

    if (num_providers < 2) {
        printf("  Error: Need at least 2 connected peers\n");
        return;
    }

    /* Adjust threshold for small networks */
    if (num_providers < 3) {
        threshold = (uint8_t)num_providers;
    }

    /* Store the data */
    cyxwiz_storage_id_t storage_id;
    size_t data_len = strlen(args);
    if (data_len > CYXWIZ_STORAGE_MAX_PAYLOAD - 40) {
        data_len = CYXWIZ_STORAGE_MAX_PAYLOAD - 40;
    }

    cyxwiz_error_t err = cyxwiz_storage_store(
        g_storage,
        providers,
        num_providers,
        threshold,
        (const uint8_t *)args,
        data_len,
        CYXWIZ_STORAGE_DEFAULT_TTL_SEC,
        &storage_id
    );

    if (err == CYXWIZ_OK) {
        char hex_id[17];
        cyxwiz_storage_id_to_hex(&storage_id, hex_id);
        printf("\n");
        printf("  Storage initiated:\n");
        printf("  ───────────────────────────────────────────────\n");
        printf("  Storage ID: %s\n", hex_id);
        printf("  Providers:  %zu (threshold %u)\n", num_providers, threshold);
        printf("  TTL:        1 hour\n");
        printf("  ───────────────────────────────────────────────\n");
        printf("\n  Use '/retrieve %s' to get data back\n\n", hex_id);
    } else {
        printf("  Error storing: %s\n", cyxwiz_strerror(err));
    }
#endif
}

/* Retrieve stored data */
static void cmd_retrieve(const char *args)
{
#ifndef CYXWIZ_HAS_STORAGE
    printf("  Error: Storage not available (no crypto)\n");
    return;
#else
    if (g_storage == NULL) {
        printf("  Error: Storage not initialized\n");
        return;
    }

    if (args == NULL || *args == '\0') {
        printf("  Usage: /retrieve <storage_id>\n");
        printf("  storage_id is 16 hex characters\n");
        return;
    }

    /* Parse storage ID from hex */
    cyxwiz_storage_id_t storage_id;
    if (strlen(args) < 16) {
        printf("  Error: Storage ID must be 16 hex characters\n");
        return;
    }

    for (int i = 0; i < CYXWIZ_STORAGE_ID_SIZE; i++) {
        unsigned int byte;
        if (sscanf(args + i * 2, "%02x", &byte) != 1) {
            printf("  Error: Invalid hex in storage ID\n");
            return;
        }
        storage_id.bytes[i] = (uint8_t)byte;
    }

    /* Get providers (all connected peers) */
    if (g_peer_table == NULL) {
        printf("  Error: No peer table available\n");
        return;
    }

    cyxwiz_node_id_t providers[8];
    size_t num_providers = 0;

    for (size_t i = 0; i < cyxwiz_peer_table_count(g_peer_table) && num_providers < 8; i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(g_peer_table, i);
        if (peer != NULL && peer->state == CYXWIZ_PEER_STATE_CONNECTED) {
            memcpy(&providers[num_providers], &peer->id, sizeof(cyxwiz_node_id_t));
            num_providers++;
        }
    }

    if (num_providers == 0) {
        printf("  Error: No connected peers to retrieve from\n");
        return;
    }

    cyxwiz_error_t err = cyxwiz_storage_retrieve(
        g_storage,
        &storage_id,
        providers,
        num_providers
    );

    if (err == CYXWIZ_OK) {
        char hex_id[17];
        cyxwiz_storage_id_to_hex(&storage_id, hex_id);
        printf("  Retrieval initiated for %s\n", hex_id);
        printf("  (results delivered via callback)\n");
    } else {
        printf("  Error retrieving: %s\n", cyxwiz_strerror(err));
    }
#endif
}

/* Show storage status */
static void cmd_storage_status(void)
{
#ifndef CYXWIZ_HAS_STORAGE
    printf("  Error: Storage not available (no crypto)\n");
    return;
#else
    if (g_storage == NULL) {
        printf("  Error: Storage not initialized\n");
        return;
    }

    printf("\n");
    printf("  Storage Status:\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  Provider mode:     %s\n",
           cyxwiz_storage_is_provider(g_storage) ? "enabled" : "disabled");
    printf("  Active operations: %zu\n", cyxwiz_storage_operation_count(g_storage));
    printf("  Stored items:      %zu\n", cyxwiz_storage_stored_count(g_storage));
    printf("  Storage used:      %zu bytes\n", cyxwiz_storage_used_bytes(g_storage));
    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
#endif
}

/* Submit compute job */
static void cmd_compute(const char *args)
{
#ifndef CYXWIZ_HAS_COMPUTE
    printf("  Error: Compute not available\n");
    return;
#else
    if (g_compute == NULL) {
        printf("  Error: Compute not initialized\n");
        return;
    }

    if (args == NULL || *args == '\0') {
        printf("  Usage: /compute <data>\n");
        printf("  Submits a hash job to a worker\n");
        return;
    }

    /* Find a worker (first connected peer) */
    if (g_peer_table == NULL) {
        printf("  Error: No peer table available\n");
        return;
    }

    const cyxwiz_peer_t *worker = NULL;
    for (size_t i = 0; i < cyxwiz_peer_table_count(g_peer_table); i++) {
        const cyxwiz_peer_t *peer = cyxwiz_peer_table_get_peer(g_peer_table, i);
        if (peer != NULL && peer->state == CYXWIZ_PEER_STATE_CONNECTED) {
            worker = peer;
            break;
        }
    }

    if (worker == NULL) {
        printf("  Error: No connected peers to submit job to\n");
        return;
    }

    /* Submit hash job */
    cyxwiz_job_id_t job_id;
    size_t payload_len = strlen(args);
    if (payload_len > CYXWIZ_JOB_MAX_PAYLOAD) {
        payload_len = CYXWIZ_JOB_MAX_PAYLOAD;
    }

    cyxwiz_error_t err = cyxwiz_compute_submit(
        g_compute,
        &worker->id,
        CYXWIZ_JOB_TYPE_HASH,
        (const uint8_t *)args,
        payload_len,
        &job_id
    );

    if (err == CYXWIZ_OK) {
        char job_hex[17];
        char worker_hex[65];
        cyxwiz_job_id_to_hex(&job_id, job_hex);
        cyxwiz_node_id_to_hex(&worker->id, worker_hex);

        printf("\n");
        printf("  Job Submitted:\n");
        printf("  ───────────────────────────────────────────────\n");
        printf("  Job ID:  %s\n", job_hex);
        printf("  Type:    HASH\n");
        printf("  Worker:  %.16s...\n", worker_hex);
        printf("  Payload: %zu bytes\n", payload_len);
        printf("  ───────────────────────────────────────────────\n");
        printf("\n");
    } else {
        printf("  Error submitting job: %s\n", cyxwiz_strerror(err));
    }
#endif
}

/* List active jobs */
static void cmd_jobs(void)
{
#ifndef CYXWIZ_HAS_COMPUTE
    printf("  Error: Compute not available\n");
    return;
#else
    if (g_compute == NULL) {
        printf("  Error: Compute not initialized\n");
        return;
    }

    size_t job_count = cyxwiz_compute_job_count(g_compute);
    printf("\n");
    printf("  Active Jobs (%zu):\n", job_count);
    printf("  ───────────────────────────────────────────────\n");

    if (job_count == 0) {
        printf("  (no active jobs)\n");
    } else {
        printf("  Worker mode: %s\n",
               cyxwiz_compute_is_worker(g_compute) ? "enabled" : "disabled");
        printf("  Use /compute to submit jobs\n");
    }

    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
#endif
}

/* List validators */
static void cmd_validators(void)
{
#ifndef CYXWIZ_HAS_CONSENSUS
    printf("  Error: Consensus not available\n");
    return;
#else
    if (g_consensus == NULL) {
        printf("  Error: Consensus not initialized\n");
        return;
    }

    size_t validator_count = cyxwiz_consensus_validator_count(g_consensus);
    printf("\n");
    printf("  Validators (%zu):\n", validator_count);
    printf("  ───────────────────────────────────────────────\n");

    printf("  Our state:       %s\n",
           cyxwiz_validator_state_name(cyxwiz_consensus_get_state(g_consensus)));
    printf("  Registered:      %s\n",
           cyxwiz_consensus_is_registered(g_consensus) ? "yes" : "no");
    printf("  Active rounds:   %zu\n", cyxwiz_consensus_active_rounds(g_consensus));
    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
#endif
}

/* Show work credits */
static void cmd_credits(void)
{
#ifndef CYXWIZ_HAS_CONSENSUS
    printf("  Error: Consensus not available\n");
    return;
#else
    if (g_consensus == NULL) {
        printf("  Error: Consensus not initialized\n");
        return;
    }

    uint32_t credits = cyxwiz_consensus_get_credits(g_consensus);
    printf("\n");
    printf("  Work Credits:\n");
    printf("  ───────────────────────────────────────────────\n");
    printf("  Current balance: %u credits\n", credits);
    printf("  ───────────────────────────────────────────────\n");
    printf("\n");
    printf("  Credits are earned by:\n");
    printf("    - Completing compute jobs: +%d\n", CYXWIZ_CREDIT_COMPUTE_JOB);
    printf("    - Passing storage proofs:  +%d\n", CYXWIZ_CREDIT_STORAGE_PROOF);
    printf("    - Validation participation: +%d\n", CYXWIZ_CREDIT_VALIDATION);
    printf("    - Correct validation vote:  +%d\n", CYXWIZ_CREDIT_CORRECT_VOTE);
    printf("\n");
#endif
}

/* Process a complete command */
static void process_command(const char *cmd)
{
    /* Skip leading whitespace */
    while (*cmd == ' ') cmd++;

    if (*cmd == '\0') {
        return;
    }

    /* Check for command prefix */
    if (cmd[0] != '/') {
        printf("  Unknown input. Type /help for commands.\n");
        return;
    }

    /* Parse command */
    if (strcmp(cmd, "/help") == 0 || strcmp(cmd, "/?") == 0) {
        cmd_help();
    } else if (strcmp(cmd, "/status") == 0) {
        cmd_status();
    } else if (strcmp(cmd, "/peers") == 0) {
        cmd_peers();
    } else if (strncmp(cmd, "/send ", 6) == 0) {
        cmd_send(cmd + 6);
    } else if (strncmp(cmd, "/anon ", 6) == 0) {
        cmd_anon(cmd + 6);
    } else if (strncmp(cmd, "/store ", 7) == 0) {
        cmd_store(cmd + 7);
    } else if (strncmp(cmd, "/retrieve ", 10) == 0) {
        cmd_retrieve(cmd + 10);
    } else if (strcmp(cmd, "/storage") == 0) {
        cmd_storage_status();
    } else if (strncmp(cmd, "/compute ", 9) == 0) {
        cmd_compute(cmd + 9);
    } else if (strcmp(cmd, "/jobs") == 0) {
        cmd_jobs();
    } else if (strcmp(cmd, "/validators") == 0) {
        cmd_validators();
    } else if (strcmp(cmd, "/credits") == 0) {
        cmd_credits();
    } else if (strcmp(cmd, "/quit") == 0 || strcmp(cmd, "/exit") == 0) {
        printf("  Shutting down...\n");
        g_running = false;
    } else {
        printf("  Unknown command: %s\n", cmd);
        printf("  Type /help for available commands.\n");
    }
}

/* Poll for interactive input (console mode) */
static void poll_interactive(void)
{
    int ch;
    while ((ch = read_char()) != -1) {
        if (ch == '\n' || ch == '\r') {
            /* Command complete */
            g_cmd_buffer[g_cmd_len] = '\0';
            if (g_cmd_len > 0) {
                printf("\n");
                process_command(g_cmd_buffer);
                printf("> ");
                fflush(stdout);
            }
            g_cmd_len = 0;
        } else if (ch == 127 || ch == 8) {
            /* Backspace */
            if (g_cmd_len > 0) {
                g_cmd_len--;
                printf("\b \b");
                fflush(stdout);
            }
        } else if (ch >= 32 && ch < 127 && g_cmd_len < sizeof(g_cmd_buffer) - 1) {
            /* Regular character */
            g_cmd_buffer[g_cmd_len++] = (char)ch;
            putchar(ch);
            fflush(stdout);
        }
    }
}

/* Poll for batch input (stdin line-based, for scripting)
 * In batch mode, we do blocking reads since scripts expect synchronous I/O */
static void poll_batch(void)
{
    /* Read a line from stdin (blocking) */
    if (fgets(g_cmd_buffer, sizeof(g_cmd_buffer), stdin) != NULL) {
        /* Remove trailing newline */
        size_t len = strlen(g_cmd_buffer);
        while (len > 0 && (g_cmd_buffer[len-1] == '\n' || g_cmd_buffer[len-1] == '\r')) {
            g_cmd_buffer[--len] = '\0';
        }

        if (len > 0) {
            printf("> %s\n", g_cmd_buffer);
            process_command(g_cmd_buffer);
            fflush(stdout);
        }
    } else {
        /* EOF reached */
        g_running = false;
    }
}

static void print_banner(void)
{
    printf("\n");
    printf("  ██████╗██╗   ██╗██╗  ██╗██╗    ██╗██╗███████╗\n");
    printf(" ██╔════╝╚██╗ ██╔╝╚██╗██╔╝██║    ██║██║╚══███╔╝\n");
    printf(" ██║      ╚████╔╝  ╚███╔╝ ██║ █╗ ██║██║  ███╔╝ \n");
    printf(" ██║       ╚██╔╝   ██╔██╗ ██║███╗██║██║ ███╔╝  \n");
    printf(" ╚██████╗   ██║   ██╔╝ ██╗╚███╔███╔╝██║███████╗\n");
    printf("  ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚══════╝\n");
    printf("\n");
    printf(" Own Nothing. Access Everything. Leave No Trace.\n");
    printf(" Version %d.%d.%d\n",
        CYXWIZ_VERSION_MAJOR,
        CYXWIZ_VERSION_MINOR,
        CYXWIZ_VERSION_PATCH);
    printf("\n");
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -b, --batch    Batch mode (read commands from stdin)\n");
    printf("  -h, --help     Show this help\n");
}

int main(int argc, char *argv[])
{
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--batch") == 0) {
            g_batch_mode = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    print_banner();

    /* Initialize logging */
    cyxwiz_log_init(CYXWIZ_LOG_DEBUG);

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    CYXWIZ_INFO("Starting CyxWiz node daemon...");

    cyxwiz_error_t err;

    /* Initialize crypto subsystem */
#ifdef CYXWIZ_HAS_CRYPTO
    err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to initialize crypto: %s", cyxwiz_strerror(err));
        return 1;
    }

    /* Create crypto context (3-of-5 MPC, party 1) */
    cyxwiz_crypto_ctx_t *crypto_ctx = NULL;
    err = cyxwiz_crypto_create(&crypto_ctx,
                               CYXWIZ_DEFAULT_THRESHOLD,
                               CYXWIZ_DEFAULT_PARTIES,
                               1);  /* TODO: Get party ID from config */
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to create crypto context: %s", cyxwiz_strerror(err));
        return 1;
    }
#endif

    /* Generate identity keypair first (for consistent node ID) */
    cyxwiz_node_id_t local_id;
#ifdef CYXWIZ_HAS_CONSENSUS
    err = cyxwiz_identity_keygen(&g_identity);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to generate identity: %s", cyxwiz_strerror(err));
        return 1;
    }
    /* Derive node ID from identity for consistent addressing */
    err = cyxwiz_identity_to_node_id(&g_identity, &local_id);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to derive node ID: %s", cyxwiz_strerror(err));
        return 1;
    }
#else
    cyxwiz_node_id_random(&local_id);
#endif

    char hex_id[65];
    cyxwiz_node_id_to_hex(&local_id, hex_id);
    CYXWIZ_INFO("Local node ID: %.16s...", hex_id);

    /* Create peer table */
    cyxwiz_peer_table_t *peer_table = NULL;
    err = cyxwiz_peer_table_create(&peer_table);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to create peer table: %s", cyxwiz_strerror(err));
        return 1;
    }

    /* Set peer state change callback */
    cyxwiz_peer_table_set_callback(peer_table, on_peer_state_change, NULL);

    /* Create transports */
    cyxwiz_transport_t *wifi_transport = NULL;
    cyxwiz_transport_t *udp_transport = NULL;
    cyxwiz_transport_t *primary_transport = NULL;

#ifdef CYXWIZ_HAS_UDP
    /* Try UDP/Internet transport first (if CYXWIZ_BOOTSTRAP is set) */
    const char *bootstrap = getenv("CYXWIZ_BOOTSTRAP");
    if (bootstrap != NULL && strlen(bootstrap) > 0) {
        err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &udp_transport);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to create UDP transport: %s", cyxwiz_strerror(err));
        } else {
            cyxwiz_transport_set_local_id(udp_transport, &local_id);
            cyxwiz_transport_set_peer_callback(udp_transport, on_peer_discovered, NULL);
            cyxwiz_transport_set_recv_callback(udp_transport, on_data_received, NULL);
            primary_transport = udp_transport;
            CYXWIZ_INFO("Using UDP/Internet transport");

            /* Start discovery (register with bootstrap) */
            udp_transport->ops->discover(udp_transport);
        }
    }
#endif

#ifdef CYXWIZ_HAS_WIFI
    /* Fall back to WiFi Direct for local mesh */
    if (primary_transport == NULL) {
        err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &wifi_transport);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to create WiFi transport: %s", cyxwiz_strerror(err));
        } else {
            cyxwiz_transport_set_local_id(wifi_transport, &local_id);
            cyxwiz_transport_set_peer_callback(wifi_transport, on_peer_discovered, NULL);
            cyxwiz_transport_set_recv_callback(wifi_transport, on_data_received, NULL);
            primary_transport = wifi_transport;
        }
    }
#endif

    /* Create discovery context */
    if (primary_transport != NULL) {
        err = cyxwiz_discovery_create(&g_discovery, peer_table, primary_transport, &local_id);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to create discovery context: %s", cyxwiz_strerror(err));
        } else {
            /* Start peer discovery */
            err = cyxwiz_discovery_start(g_discovery);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to start discovery: %s", cyxwiz_strerror(err));
            }
        }

        /* Create router */
        err = cyxwiz_router_create(&g_router, peer_table, primary_transport, &local_id);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to create router: %s", cyxwiz_strerror(err));
        } else {
            cyxwiz_router_set_callback(g_router, on_routed_data, NULL);

            /* Start router */
            err = cyxwiz_router_start(g_router);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to start router: %s", cyxwiz_strerror(err));
            }

#ifdef CYXWIZ_HAS_CRYPTO
            /* Create onion routing context */
            err = cyxwiz_onion_create(&g_onion, g_router, &local_id);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to create onion context: %s", cyxwiz_strerror(err));
            } else {
                /* Set onion delivery callback */
                cyxwiz_onion_set_callback(g_onion, on_onion_delivery, NULL);

                /* Set router's onion callback to forward messages to onion layer */
                cyxwiz_router_set_onion_callback(g_router, on_onion_message, NULL);

                /* Set discovery's key callback to add peer keys to onion context */
                if (g_discovery != NULL) {
                    cyxwiz_discovery_set_key_callback(g_discovery, on_peer_key_exchange, NULL);

                    /* Set our public key for announcements */
                    uint8_t pubkey[CYXWIZ_PUBKEY_SIZE];
                    err = cyxwiz_onion_get_pubkey(g_onion, pubkey);
                    if (err == CYXWIZ_OK) {
                        cyxwiz_discovery_set_pubkey(g_discovery, pubkey);
                    }
                }

                CYXWIZ_INFO("Onion routing enabled");
            }
#endif

#ifdef CYXWIZ_HAS_COMPUTE
            /* Create compute context */
            err = cyxwiz_compute_create(&g_compute, g_router, peer_table, crypto_ctx, &local_id);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to create compute context: %s", cyxwiz_strerror(err));
            } else {
                /* Enable worker mode by default */
                cyxwiz_compute_enable_worker(g_compute, 4);
                CYXWIZ_INFO("Compute protocol enabled (worker mode)");
            }
#endif

#ifdef CYXWIZ_HAS_STORAGE
            /* Create storage context */
            err = cyxwiz_storage_create(&g_storage, g_router, peer_table, crypto_ctx, &local_id);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to create storage context: %s", cyxwiz_strerror(err));
            } else {
                /* Enable storage provider mode by default (1MB, 24hr TTL) */
                cyxwiz_storage_enable_provider(g_storage, 1024 * 1024, 86400);
                CYXWIZ_INFO("Storage protocol enabled (provider mode)");
            }
#endif

#ifdef CYXWIZ_HAS_CONSENSUS
            /* Create consensus context (identity already generated at startup) */
            err = cyxwiz_consensus_create(&g_consensus, g_router, peer_table, &g_identity);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to create consensus context: %s", cyxwiz_strerror(err));
            } else {
                /* Initialize Pedersen parameters for privacy protocol */
                cyxwiz_pedersen_init();

                /* Register as validator */
                err = cyxwiz_consensus_register_validator(g_consensus);
                if (err == CYXWIZ_OK) {
                    CYXWIZ_INFO("Consensus protocol enabled (validator mode)");
                } else {
                    CYXWIZ_WARN("Validator registration pending: %s", cyxwiz_strerror(err));
                }
            }
#endif
        }
    }

    /* Set up global pointers for interactive commands */
    g_peer_table = peer_table;
    memcpy(&g_local_id, &local_id, sizeof(local_id));

    if (g_batch_mode) {
        CYXWIZ_INFO("Node running in BATCH mode. Reading commands from stdin.");
    } else {
        CYXWIZ_INFO("Node running. Type /help for commands, Ctrl+C to stop.");
        printf("\n> ");
        fflush(stdout);
    }

    /* Main event loop */
    while (g_running) {
        /* Poll for commands (batch or interactive) */
        if (g_batch_mode) {
            poll_batch();
        } else {
            poll_interactive();
        }
        uint64_t now = cyxwiz_time_ms();

        /* Poll discovery (sends announcements, cleans stale peers) */
        if (g_discovery != NULL) {
            cyxwiz_discovery_poll(g_discovery, now);
        }

        /* Poll router (handles route discovery, pending sends, route expiry) */
        if (g_router != NULL) {
            cyxwiz_router_poll(g_router, now);
        }

#ifdef CYXWIZ_HAS_CRYPTO
        /* Poll onion context (expires old circuits) */
        if (g_onion != NULL) {
            cyxwiz_onion_poll(g_onion, now);
        }
#endif

#ifdef CYXWIZ_HAS_COMPUTE
        /* Poll compute context (handles timeouts) */
        if (g_compute != NULL) {
            cyxwiz_compute_poll(g_compute, now);
        }
#endif

#ifdef CYXWIZ_HAS_STORAGE
        /* Poll storage context (handles timeouts and TTL expiry) */
        if (g_storage != NULL) {
            cyxwiz_storage_poll(g_storage, now);
        }
#endif

#ifdef CYXWIZ_HAS_CONSENSUS
        /* Poll consensus context (handles round timeouts, heartbeats) */
        if (g_consensus != NULL) {
            cyxwiz_consensus_poll(g_consensus, now);

            /* Test validation trigger - after 30 seconds with 2+ validators */
            static uint64_t test_validation_time = 0;
            static bool test_validation_done = false;
            if (!test_validation_done &&
                cyxwiz_consensus_validator_count(g_consensus) >= 1 &&
                test_validation_time == 0) {
                test_validation_time = now + 30000; /* 30 seconds from now */
                CYXWIZ_INFO("Scheduling test validation in 30 seconds...");
            }
            if (!test_validation_done && test_validation_time > 0 && now >= test_validation_time) {
                test_validation_done = true;
                /* Trigger a test validation round */
                uint8_t test_job_id[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
                uint8_t test_result[32];
                uint8_t test_mac[16];
                memset(test_result, 0xAB, sizeof(test_result));
                memset(test_mac, 0xCD, sizeof(test_mac));
                CYXWIZ_INFO("Triggering test validation round...");
                cyxwiz_error_t verr = cyxwiz_consensus_validate_job(
                    g_consensus, test_job_id, test_result, sizeof(test_result), test_mac);
                if (verr == CYXWIZ_OK) {
                    CYXWIZ_INFO("Test validation round started successfully");
                } else {
                    CYXWIZ_WARN("Failed to start test validation: %s", cyxwiz_strerror(verr));
                }
            }
        }
#endif

        /* Poll all transports */
        if (udp_transport != NULL) {
            udp_transport->ops->poll(udp_transport, 50);
        }
        if (wifi_transport != NULL) {
            wifi_transport->ops->poll(wifi_transport, 50);
        }

        /* TODO: MPC key refresh */

        sleep_ms(100);
    }

    /* Cleanup */
    CYXWIZ_INFO("Shutting down...");

#ifdef CYXWIZ_HAS_CONSENSUS
    /* Destroy consensus context */
    if (g_consensus != NULL) {
        cyxwiz_consensus_destroy(g_consensus);
        g_consensus = NULL;
    }
    cyxwiz_identity_destroy(&g_identity);
#endif

#ifdef CYXWIZ_HAS_STORAGE
    /* Destroy storage context */
    if (g_storage != NULL) {
        cyxwiz_storage_destroy(g_storage);
        g_storage = NULL;
    }
#endif

#ifdef CYXWIZ_HAS_COMPUTE
    /* Destroy compute context */
    if (g_compute != NULL) {
        cyxwiz_compute_destroy(g_compute);
        g_compute = NULL;
    }
#endif

#ifdef CYXWIZ_HAS_CRYPTO
    /* Destroy onion context (before router) */
    if (g_onion != NULL) {
        cyxwiz_onion_destroy(g_onion);
        g_onion = NULL;
    }
#endif

    /* Stop and destroy router */
    if (g_router != NULL) {
        cyxwiz_router_stop(g_router);
        cyxwiz_router_destroy(g_router);
        g_router = NULL;
    }

    /* Stop and destroy discovery */
    if (g_discovery != NULL) {
        cyxwiz_discovery_stop(g_discovery);
        cyxwiz_discovery_destroy(g_discovery);
        g_discovery = NULL;
    }

    if (udp_transport != NULL) {
        cyxwiz_transport_destroy(udp_transport);
    }
    if (wifi_transport != NULL) {
        cyxwiz_transport_destroy(wifi_transport);
    }

    /* Destroy peer table */
    if (peer_table != NULL) {
        size_t peer_count = cyxwiz_peer_table_count(peer_table);
        if (peer_count > 0) {
            CYXWIZ_INFO("Had %zu peers in table", peer_count);
        }
        cyxwiz_peer_table_destroy(peer_table);
    }

#ifdef CYXWIZ_HAS_CRYPTO
    if (crypto_ctx != NULL) {
        cyxwiz_crypto_destroy(crypto_ctx);
    }
#endif

    CYXWIZ_INFO("Goodbye.");
    return 0;
}
