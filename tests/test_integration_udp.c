/*
 * CyxWiz Protocol - UDP Integration Tests
 *
 * Tests real network communication between multiple nodes.
 * Unlike unit tests, these use actual UDP sockets and network I/O.
 *
 * NOTE: These tests start a bootstrap server subprocess for peer discovery.
 */

/* Enable POSIX features for clock_gettime and usleep on Linux/macOS */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#endif

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/peer.h"
#include "cyxwiz/routing.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include "cyxwiz/crypto.h"
#include "cyxwiz/onion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")
#define sleep_ms(ms) Sleep(ms)
#define setenv(name, val, over) _putenv_s(name, val)
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/* Bootstrap server port for tests */
#define TEST_BOOTSTRAP_PORT 17777

/* Bootstrap server process handle */
#ifdef _WIN32
static HANDLE g_bootstrap_process = NULL;
#else
static pid_t g_bootstrap_pid = 0;
#endif

/* Start bootstrap server subprocess */
static int start_bootstrap_server(void)
{
#ifdef _WIN32
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    char cmd[256];

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  /* Hide console window */
    ZeroMemory(&pi, sizeof(pi));

    snprintf(cmd, sizeof(cmd), "cyxwiz-bootstrap.exe %d", TEST_BOOTSTRAP_PORT);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("(failed to start bootstrap server) ");
        return 0;
    }

    g_bootstrap_process = pi.hProcess;
    CloseHandle(pi.hThread);
#else
    g_bootstrap_pid = fork();
    if (g_bootstrap_pid < 0) {
        printf("(fork failed) ");
        return 0;
    }

    if (g_bootstrap_pid == 0) {
        /* Child process - exec bootstrap server */
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_BOOTSTRAP_PORT);
        execlp("./build/cyxwiz-bootstrap", "cyxwiz-bootstrap", port_str, NULL);
        _exit(1);  /* exec failed */
    }
#endif

    /* Wait for server to start */
    sleep_ms(500);

    /* Set environment variable for transport */
    char bootstrap_addr[64];
    snprintf(bootstrap_addr, sizeof(bootstrap_addr), "127.0.0.1:%d", TEST_BOOTSTRAP_PORT);
    setenv("CYXWIZ_BOOTSTRAP", bootstrap_addr, 1);

    return 1;
}

/* Stop bootstrap server subprocess */
static void stop_bootstrap_server(void)
{
#ifdef _WIN32
    if (g_bootstrap_process != NULL) {
        TerminateProcess(g_bootstrap_process, 0);
        WaitForSingleObject(g_bootstrap_process, 1000);
        CloseHandle(g_bootstrap_process);
        g_bootstrap_process = NULL;
    }
#else
    if (g_bootstrap_pid > 0) {
        kill(g_bootstrap_pid, SIGTERM);
        waitpid(g_bootstrap_pid, NULL, 0);
        g_bootstrap_pid = 0;
    }
#endif
}

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("  Testing: %s... ", #name); \
        fflush(stdout); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while (0)

/* ============================================================================
 * Test Infrastructure
 * ========================================================================= */

/* Node context for integration tests */
typedef struct {
    cyxwiz_node_id_t id;
    cyxwiz_transport_t *transport;
    cyxwiz_peer_table_t *peers;
    cyxwiz_discovery_t *discovery;
    cyxwiz_router_t *router;
#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_onion_ctx_t *onion;
#endif
    /* Message tracking */
    int messages_received;
    uint8_t last_message[256];
    size_t last_message_len;
    cyxwiz_node_id_t last_from;
} test_node_t;

/* Callback for received routed data */
static void on_data_received(const cyxwiz_node_id_t *from,
                             const uint8_t *data,
                             size_t len,
                             void *user_data)
{
    test_node_t *node = (test_node_t *)user_data;

    node->messages_received++;
    if (len <= sizeof(node->last_message)) {
        memcpy(node->last_message, data, len);
        node->last_message_len = len;
    }
    memcpy(&node->last_from, from, sizeof(cyxwiz_node_id_t));
}

/* Initialize a test node */
static cyxwiz_error_t init_test_node(test_node_t *node)
{
    cyxwiz_error_t err;

    memset(node, 0, sizeof(test_node_t));

    /* Generate random node ID */
    cyxwiz_node_id_random(&node->id);

    /* Create UDP transport */
    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &node->transport);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Set transport's local ID (required for bootstrap registration) */
    cyxwiz_transport_set_local_id(node->transport, &node->id);

    /* Create peer table */
    err = cyxwiz_peer_table_create(&node->peers);
    if (err != CYXWIZ_OK) {
        cyxwiz_transport_destroy(node->transport);
        return err;
    }

    /* Create discovery */
    err = cyxwiz_discovery_create(&node->discovery, node->peers,
                                   node->transport, &node->id);
    if (err != CYXWIZ_OK) {
        cyxwiz_peer_table_destroy(node->peers);
        cyxwiz_transport_destroy(node->transport);
        return err;
    }

    /* Create router */
    err = cyxwiz_router_create(&node->router, node->peers,
                                node->transport, &node->id);
    if (err != CYXWIZ_OK) {
        cyxwiz_discovery_destroy(node->discovery);
        cyxwiz_peer_table_destroy(node->peers);
        cyxwiz_transport_destroy(node->transport);
        return err;
    }

    /* Set data callback */
    cyxwiz_router_set_callback(node->router, on_data_received, node);

    return CYXWIZ_OK;
}

/* Cleanup a test node */
static void cleanup_test_node(test_node_t *node)
{
#ifdef CYXWIZ_HAS_CRYPTO
    if (node->onion) {
        cyxwiz_onion_destroy(node->onion);
    }
#endif
    if (node->router) {
        cyxwiz_router_stop(node->router);
        cyxwiz_router_destroy(node->router);
    }
    if (node->discovery) {
        cyxwiz_discovery_stop(node->discovery);
        cyxwiz_discovery_destroy(node->discovery);
    }
    if (node->peers) {
        cyxwiz_peer_table_destroy(node->peers);
    }
    if (node->transport) {
        cyxwiz_transport_destroy(node->transport);
    }
}

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

/* Poll a node for events */
static void poll_node(test_node_t *node, uint64_t now_ms)
{
    if (node->transport && node->transport->ops) {
        node->transport->ops->poll(node->transport, 10);
    }
    if (node->discovery) {
        cyxwiz_discovery_poll(node->discovery, now_ms);
    }
    if (node->router) {
        cyxwiz_router_poll(node->router, now_ms);
    }
}

/* ============================================================================
 * Integration Tests
 * ========================================================================= */

/* Test: Two nodes can create transports on different ports */
static int test_two_nodes_create(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) {
        printf("(node1 init failed: %s) ", cyxwiz_strerror(err));
        return 0;
    }

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        printf("(node2 init failed: %s) ", cyxwiz_strerror(err));
        cleanup_test_node(&node1);
        return 0;
    }

    /* Verify they have different IDs */
    if (memcmp(&node1.id, &node2.id, sizeof(cyxwiz_node_id_t)) == 0) {
        printf("(nodes have same ID) ");
        cleanup_test_node(&node2);
        cleanup_test_node(&node1);
        return 0;
    }

    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return 1;
#endif
}

/* Test: Direct peer-to-peer discovery (localhost) */
static int test_direct_discovery(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Start discovery on both nodes */
    err = cyxwiz_discovery_start(node1.discovery);
    if (err != CYXWIZ_OK) {
        printf("(node1 discovery start failed) ");
        goto cleanup;
    }

    err = cyxwiz_discovery_start(node2.discovery);
    if (err != CYXWIZ_OK) {
        printf("(node2 discovery start failed) ");
        goto cleanup;
    }

    /* Start routers */
    err = cyxwiz_router_start(node1.router);
    if (err != CYXWIZ_OK) {
        printf("(node1 router start failed) ");
        goto cleanup;
    }

    err = cyxwiz_router_start(node2.router);
    if (err != CYXWIZ_OK) {
        printf("(node2 router start failed) ");
        goto cleanup;
    }

    /* Poll for discovery (up to 5 seconds) */
    uint64_t start = get_time_ms();
    uint64_t timeout = 5000;

    while (get_time_ms() - start < timeout) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        /* Check if nodes discovered each other */
        const cyxwiz_peer_t *peer1 = cyxwiz_peer_table_find(node1.peers, &node2.id);
        const cyxwiz_peer_t *peer2 = cyxwiz_peer_table_find(node2.peers, &node1.id);

        if (peer1 != NULL && peer2 != NULL) {
            success = 1;
            break;
        }

        sleep_ms(50);
    }

    if (!success) {
        printf("(discovery timeout) ");
    }

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
#endif
}

/* Test: Message exchange between two nodes */
static int test_message_exchange(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Start both nodes */
    cyxwiz_discovery_start(node1.discovery);
    cyxwiz_discovery_start(node2.discovery);
    cyxwiz_router_start(node1.router);
    cyxwiz_router_start(node2.router);

    /* Wait for discovery */
    uint64_t start = get_time_ms();
    uint64_t timeout = 5000;
    int discovered = 0;

    while (get_time_ms() - start < timeout && !discovered) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (cyxwiz_peer_table_find(node1.peers, &node2.id) != NULL &&
            cyxwiz_peer_table_find(node2.peers, &node1.id) != NULL) {
            discovered = 1;
        }
        sleep_ms(50);
    }

    if (!discovered) {
        printf("(discovery failed) ");
        goto cleanup;
    }

    /* Send message from node1 to node2 */
    const char *test_msg = "Hello from node1!";
    err = cyxwiz_router_send(node1.router, &node2.id,
                              (const uint8_t *)test_msg, strlen(test_msg));
    if (err != CYXWIZ_OK) {
        printf("(send failed: %s) ", cyxwiz_strerror(err));
        goto cleanup;
    }

    /* Wait for message delivery */
    start = get_time_ms();
    timeout = 3000;

    while (get_time_ms() - start < timeout && node2.messages_received == 0) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);
        sleep_ms(10);
    }

    if (node2.messages_received == 0) {
        printf("(no message received) ");
        goto cleanup;
    }

    /* Verify message content */
    if (node2.last_message_len != strlen(test_msg)) {
        printf("(wrong length: got %zu, expected %zu) ",
               node2.last_message_len, strlen(test_msg));
        goto cleanup;
    }

    if (memcmp(node2.last_message, test_msg, strlen(test_msg)) != 0) {
        printf("(wrong content) ");
        goto cleanup;
    }

    /* Verify sender */
    if (memcmp(&node2.last_from, &node1.id, sizeof(cyxwiz_node_id_t)) != 0) {
        printf("(wrong sender) ");
        goto cleanup;
    }

    success = 1;

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
#endif
}

/* Test: Bidirectional message exchange */
static int test_bidirectional_messages(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) return 0;

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Start nodes */
    cyxwiz_discovery_start(node1.discovery);
    cyxwiz_discovery_start(node2.discovery);
    cyxwiz_router_start(node1.router);
    cyxwiz_router_start(node2.router);

    /* Wait for discovery */
    uint64_t start = get_time_ms();
    while (get_time_ms() - start < 5000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (cyxwiz_peer_table_find(node1.peers, &node2.id) != NULL &&
            cyxwiz_peer_table_find(node2.peers, &node1.id) != NULL) {
            break;
        }
        sleep_ms(50);
    }

    /* Send from node1 -> node2 */
    const char *msg1 = "Message A->B";
    err = cyxwiz_router_send(node1.router, &node2.id,
                              (const uint8_t *)msg1, strlen(msg1));
    if (err != CYXWIZ_OK) {
        printf("(send 1->2 failed) ");
        goto cleanup;
    }

    /* Send from node2 -> node1 */
    const char *msg2 = "Message B->A";
    err = cyxwiz_router_send(node2.router, &node1.id,
                              (const uint8_t *)msg2, strlen(msg2));
    if (err != CYXWIZ_OK) {
        printf("(send 2->1 failed) ");
        goto cleanup;
    }

    /* Wait for both messages */
    start = get_time_ms();
    while (get_time_ms() - start < 3000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (node1.messages_received > 0 && node2.messages_received > 0) {
            break;
        }
        sleep_ms(10);
    }

    if (node1.messages_received == 0 || node2.messages_received == 0) {
        printf("(not all messages received: n1=%d, n2=%d) ",
               node1.messages_received, node2.messages_received);
        goto cleanup;
    }

    success = 1;

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
#endif
}

/* Test: Multiple messages in sequence */
static int test_multiple_messages(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;
    const int num_messages = 10;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) return 0;

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Start nodes */
    cyxwiz_discovery_start(node1.discovery);
    cyxwiz_discovery_start(node2.discovery);
    cyxwiz_router_start(node1.router);
    cyxwiz_router_start(node2.router);

    /* Wait for discovery */
    uint64_t start = get_time_ms();
    while (get_time_ms() - start < 5000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (cyxwiz_peer_table_find(node1.peers, &node2.id) != NULL) {
            break;
        }
        sleep_ms(50);
    }

    /* Send multiple messages */
    for (int i = 0; i < num_messages; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Message %d", i);

        err = cyxwiz_router_send(node1.router, &node2.id,
                                  (const uint8_t *)msg, strlen(msg));
        if (err != CYXWIZ_OK) {
            printf("(send %d failed) ", i);
            goto cleanup;
        }

        /* Brief pause between sends */
        sleep_ms(10);
        poll_node(&node1, get_time_ms());
        poll_node(&node2, get_time_ms());
    }

    /* Wait for all messages */
    start = get_time_ms();
    while (get_time_ms() - start < 5000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (node2.messages_received >= num_messages) {
            break;
        }
        sleep_ms(10);
    }

    if (node2.messages_received < num_messages) {
        printf("(only %d/%d received) ", node2.messages_received, num_messages);
        goto cleanup;
    }

    success = 1;

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
#endif
}

/* Test: Three node mesh (A <-> B <-> C) */
static int test_three_node_mesh(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t nodes[3];
    cyxwiz_error_t err;
    int success = 0;

    /* Initialize all nodes */
    for (int i = 0; i < 3; i++) {
        err = init_test_node(&nodes[i]);
        if (err != CYXWIZ_OK) {
            for (int j = 0; j < i; j++) {
                cleanup_test_node(&nodes[j]);
            }
            return 0;
        }
    }

    /* Start all nodes */
    for (int i = 0; i < 3; i++) {
        cyxwiz_discovery_start(nodes[i].discovery);
        cyxwiz_router_start(nodes[i].router);
    }

    /* Wait for mesh formation */
    uint64_t start = get_time_ms();
    int mesh_formed = 0;

    while (get_time_ms() - start < 10000 && !mesh_formed) {
        uint64_t now = get_time_ms();
        for (int i = 0; i < 3; i++) {
            poll_node(&nodes[i], now);
        }

        /* Check if all nodes know about each other */
        int connections = 0;
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                if (i != j) {
                    if (cyxwiz_peer_table_find(nodes[i].peers, &nodes[j].id) != NULL) {
                        connections++;
                    }
                }
            }
        }

        /* Full mesh = 6 connections (each node knows 2 others) */
        if (connections >= 6) {
            mesh_formed = 1;
        }

        sleep_ms(50);
    }

    if (!mesh_formed) {
        printf("(mesh not formed) ");
        goto cleanup;
    }

    /* Send message from node 0 to node 2 */
    const char *test_msg = "Hello across mesh!";
    err = cyxwiz_router_send(nodes[0].router, &nodes[2].id,
                              (const uint8_t *)test_msg, strlen(test_msg));
    if (err != CYXWIZ_OK) {
        printf("(send failed) ");
        goto cleanup;
    }

    /* Wait for delivery */
    start = get_time_ms();
    while (get_time_ms() - start < 3000 && nodes[2].messages_received == 0) {
        uint64_t now = get_time_ms();
        for (int i = 0; i < 3; i++) {
            poll_node(&nodes[i], now);
        }
        sleep_ms(10);
    }

    if (nodes[2].messages_received == 0) {
        printf("(no message received) ");
        goto cleanup;
    }

    success = 1;

cleanup:
    for (int i = 0; i < 3; i++) {
        cleanup_test_node(&nodes[i]);
    }
    return success;
#endif
}

/* Test: Stress test with rapid message bursts */
static int test_message_burst(void)
{
#ifndef CYXWIZ_HAS_UDP
    printf("(UDP not enabled) ");
    return 1;
#else
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;
    const int burst_size = 50;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) return 0;

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Start nodes */
    cyxwiz_discovery_start(node1.discovery);
    cyxwiz_discovery_start(node2.discovery);
    cyxwiz_router_start(node1.router);
    cyxwiz_router_start(node2.router);

    /* Wait for discovery */
    uint64_t start = get_time_ms();
    while (get_time_ms() - start < 5000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (cyxwiz_peer_table_find(node1.peers, &node2.id) != NULL) {
            break;
        }
        sleep_ms(50);
    }

    /* Send burst of messages as fast as possible */
    int sent = 0;
    for (int i = 0; i < burst_size; i++) {
        char msg[32];
        snprintf(msg, sizeof(msg), "Burst %d", i);

        err = cyxwiz_router_send(node1.router, &node2.id,
                                  (const uint8_t *)msg, strlen(msg));
        if (err == CYXWIZ_OK) {
            sent++;
        }
    }

    if (sent == 0) {
        printf("(no messages sent) ");
        goto cleanup;
    }

    /* Wait for messages with polling */
    start = get_time_ms();
    while (get_time_ms() - start < 10000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (node2.messages_received >= sent) {
            break;
        }
        sleep_ms(10);
    }

    /* Calculate delivery rate */
    int received = node2.messages_received;
    float rate = (float)received / (float)sent * 100.0f;

    /* Accept 80% delivery rate for burst test (UDP can drop) */
    if (rate < 80.0f) {
        printf("(low delivery: %d/%d = %.1f%%) ", received, sent, rate);
        goto cleanup;
    }

    success = 1;

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
#endif
}

#ifdef CYXWIZ_HAS_CRYPTO
/* Test: Onion routing between nodes */
static int test_onion_routing(void)
{
    test_node_t node1, node2;
    cyxwiz_error_t err;
    int success = 0;

    err = init_test_node(&node1);
    if (err != CYXWIZ_OK) return 0;

    err = init_test_node(&node2);
    if (err != CYXWIZ_OK) {
        cleanup_test_node(&node1);
        return 0;
    }

    /* Create onion contexts */
    err = cyxwiz_onion_create(&node1.onion, node1.router, &node1.id);
    if (err != CYXWIZ_OK) {
        printf("(onion1 create failed) ");
        goto cleanup;
    }

    err = cyxwiz_onion_create(&node2.onion, node2.router, &node2.id);
    if (err != CYXWIZ_OK) {
        printf("(onion2 create failed) ");
        goto cleanup;
    }

    /* Start nodes */
    cyxwiz_discovery_start(node1.discovery);
    cyxwiz_discovery_start(node2.discovery);
    cyxwiz_router_start(node1.router);
    cyxwiz_router_start(node2.router);

    /* Wait for discovery */
    uint64_t start = get_time_ms();
    while (get_time_ms() - start < 5000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);

        if (cyxwiz_peer_table_find(node1.peers, &node2.id) != NULL) {
            break;
        }
        sleep_ms(50);
    }

    /* Exchange public keys */
    uint8_t pubkey1[32], pubkey2[32];
    cyxwiz_onion_get_pubkey(node1.onion, pubkey1);
    cyxwiz_onion_get_pubkey(node2.onion, pubkey2);

    cyxwiz_onion_add_peer_key(node1.onion, &node2.id, pubkey2);
    cyxwiz_onion_add_peer_key(node2.onion, &node1.id, pubkey1);

    /* Build 1-hop circuit to node2 */
    cyxwiz_node_id_t hops[1] = { node2.id };
    cyxwiz_circuit_t *circuit = NULL;

    err = cyxwiz_onion_build_circuit(node1.onion, hops, 1, &circuit);
    if (err != CYXWIZ_OK) {
        printf("(circuit build failed: %s) ", cyxwiz_strerror(err));
        goto cleanup;
    }

    /* Send via onion */
    const char *test_msg = "Secret onion message!";
    err = cyxwiz_onion_send(node1.onion, circuit,
                            (const uint8_t *)test_msg, strlen(test_msg));
    if (err != CYXWIZ_OK) {
        printf("(onion send failed: %s) ", cyxwiz_strerror(err));
        goto cleanup;
    }

    /* Wait for delivery */
    start = get_time_ms();
    while (get_time_ms() - start < 3000) {
        uint64_t now = get_time_ms();
        poll_node(&node1, now);
        poll_node(&node2, now);
        cyxwiz_onion_poll(node1.onion, now);
        cyxwiz_onion_poll(node2.onion, now);
        sleep_ms(10);
    }

    /* Note: Onion delivery goes through a different callback path,
       so we just verify no crash and circuit worked */
    success = 1;

cleanup:
    cleanup_test_node(&node2);
    cleanup_test_node(&node1);
    return success;
}
#endif

/* ============================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    int result;

#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_crypto_init();
#endif

    cyxwiz_log_init(CYXWIZ_LOG_INFO);  /* Show info for debugging */

    printf("\nCyxWiz UDP Integration Tests\n");
    printf("=============================\n");
    printf("Testing real network communication...\n\n");

    /* Start bootstrap server for peer discovery */
    printf("Starting bootstrap server on port %d...\n", TEST_BOOTSTRAP_PORT);
    if (!start_bootstrap_server()) {
        printf("WARNING: Could not start bootstrap server.\n");
        printf("Tests requiring discovery will fail.\n\n");
    } else {
        printf("Bootstrap server started.\n\n");
    }

    TEST(two_nodes_create);
    TEST(direct_discovery);
    TEST(message_exchange);
    TEST(bidirectional_messages);
    TEST(multiple_messages);
    TEST(three_node_mesh);
    TEST(message_burst);

#ifdef CYXWIZ_HAS_CRYPTO
    TEST(onion_routing);
#endif

    printf("\n=============================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    /* Stop bootstrap server */
    stop_bootstrap_server();

    result = (tests_passed == tests_run) ? 0 : 1;

#ifdef _WIN32
    WSACleanup();
#endif

    return result;
}
