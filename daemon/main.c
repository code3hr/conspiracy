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

/* Forward declarations */
static cyxwiz_discovery_t *g_discovery = NULL;
static cyxwiz_router_t *g_router = NULL;
#ifdef CYXWIZ_HAS_CRYPTO
static cyxwiz_onion_ctx_t *g_onion = NULL;
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
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(user_data);

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);
    CYXWIZ_INFO("Received %zu bytes via route from %.16s...", len, hex_id);

    /* TODO: Process application data */
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
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(user_data);

    char hex_id[65];
    cyxwiz_node_id_to_hex(from, hex_id);
    CYXWIZ_INFO("Received %zu bytes via onion from %.16s...", len, hex_id);

    /* TODO: Process application data received via onion routing */
}
#endif

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
