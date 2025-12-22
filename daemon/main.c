/*
 * CyxWiz Protocol - Node Daemon
 *
 * Main entry point for the CyxWiz node.
 * Runs as a background daemon, participating in the mesh network.
 */

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/log.h"
#include "cyxwiz/memory.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include "cyxwiz/crypto.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

static volatile bool g_running = true;

static void signal_handler(int sig)
{
    CYXWIZ_UNUSED(sig);
    CYXWIZ_INFO("Received shutdown signal");
    g_running = false;
}

/* Forward declaration for discovery */
static cyxwiz_discovery_t *g_discovery = NULL;

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

    /* Forward to discovery module for protocol messages */
    if (g_discovery != NULL && len > 0) {
        cyxwiz_discovery_handle_message(g_discovery, from, data, len);
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

int main(int argc, char *argv[])
{
    CYXWIZ_UNUSED(argc);
    CYXWIZ_UNUSED(argv);

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

    /* Generate local node ID */
    cyxwiz_node_id_t local_id;
    cyxwiz_node_id_random(&local_id);

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

#ifdef CYXWIZ_HAS_WIFI
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &wifi_transport);
    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to create WiFi transport: %s", cyxwiz_strerror(err));
    } else {
        cyxwiz_transport_set_peer_callback(wifi_transport, on_peer_discovered, NULL);
        cyxwiz_transport_set_recv_callback(wifi_transport, on_data_received, NULL);
    }
#endif

    /* Create discovery context */
    if (wifi_transport != NULL) {
        err = cyxwiz_discovery_create(&g_discovery, peer_table, wifi_transport, &local_id);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to create discovery context: %s", cyxwiz_strerror(err));
        } else {
            /* Start peer discovery */
            err = cyxwiz_discovery_start(g_discovery);
            if (err != CYXWIZ_OK) {
                CYXWIZ_ERROR("Failed to start discovery: %s", cyxwiz_strerror(err));
            }
        }
    }

    CYXWIZ_INFO("Node running. Press Ctrl+C to stop.");

    /* Main event loop */
    while (g_running) {
        uint64_t now = cyxwiz_time_ms();

        /* Poll discovery (sends announcements, cleans stale peers) */
        if (g_discovery != NULL) {
            cyxwiz_discovery_poll(g_discovery, now);
        }

        /* Poll all transports */
        if (wifi_transport != NULL) {
            wifi_transport->ops->poll(wifi_transport, 100);
        }

        /* TODO: Process routing table updates */
        /* TODO: Handle pending messages */
        /* TODO: MPC key refresh */

        sleep_ms(100);
    }

    /* Cleanup */
    CYXWIZ_INFO("Shutting down...");

    /* Stop and destroy discovery */
    if (g_discovery != NULL) {
        cyxwiz_discovery_stop(g_discovery);
        cyxwiz_discovery_destroy(g_discovery);
        g_discovery = NULL;
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
