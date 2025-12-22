/*
 * CyxWiz Protocol - UDP Transport Tests
 */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    do { \
        printf("  Testing: %s... ", #name); \
        tests_run++; \
        if (test_##name()) { \
            printf("PASS\n"); \
            tests_passed++; \
        } else { \
            printf("FAIL\n"); \
        } \
    } while (0)

/* Test UDP transport creation */
static int test_udp_create(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        printf("(create failed: %s) ", cyxwiz_strerror(err));
        return 0;
    }

    if (transport == NULL) {
        return 0;
    }

    if (transport->type != CYXWIZ_TRANSPORT_UDP) {
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

/* Test transport type name */
static int test_type_name(void)
{
    const char *name = cyxwiz_transport_type_name(CYXWIZ_TRANSPORT_UDP);
    if (name == NULL) {
        return 0;
    }

    if (strcmp(name, "UDP/Internet") != 0) {
        printf("(got '%s') ", name);
        return 0;
    }

    return 1;
}

/* Test max packet size */
static int test_max_packet_size(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    size_t max_size = transport->ops->max_packet_size(transport);

    /* Should be CYXWIZ_MAX_PACKET_SIZE minus the header overhead */
    /* Header is 1 byte type + 32 bytes node ID = 33 bytes */
    if (max_size != (CYXWIZ_MAX_PACKET_SIZE - 33)) {
        printf("(expected %d, got %zu) ", CYXWIZ_MAX_PACKET_SIZE - 33, max_size);
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

/* Test poll without crash */
static int test_poll(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Poll should succeed even with no activity */
    err = transport->ops->poll(transport, 10);  /* 10ms timeout */
    if (err != CYXWIZ_OK) {
        printf("(poll failed: %s) ", cyxwiz_strerror(err));
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

/* Test send to unknown peer fails gracefully */
static int test_send_unknown_peer(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Generate random node ID */
    cyxwiz_node_id_t unknown_id;
    memset(&unknown_id, 0xAB, sizeof(unknown_id));

    uint8_t data[] = "test message";

    /* Send should fail with peer not found */
    err = transport->ops->send(transport, &unknown_id, data, sizeof(data) - 1);
    if (err != CYXWIZ_ERR_PEER_NOT_FOUND) {
        printf("(expected PEER_NOT_FOUND, got %s) ", cyxwiz_strerror(err));
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

/* Test callback registration */
static int recv_callback_called = 0;
static int peer_callback_called = 0;

static void test_recv_callback(
    cyxwiz_transport_t *transport,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len,
    void *user_data)
{
    (void)transport;
    (void)from;
    (void)data;
    (void)len;
    (void)user_data;
    recv_callback_called = 1;
}

static void test_peer_callback(
    cyxwiz_transport_t *transport,
    const cyxwiz_peer_info_t *peer,
    void *user_data)
{
    (void)transport;
    (void)peer;
    (void)user_data;
    peer_callback_called = 1;
}

static int test_callbacks(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Set callbacks */
    cyxwiz_transport_set_recv_callback(transport, test_recv_callback, NULL);
    cyxwiz_transport_set_peer_callback(transport, test_peer_callback, NULL);

    if (transport->on_recv != test_recv_callback) {
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    if (transport->on_peer != test_peer_callback) {
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

/* Test discover (registers with bootstrap) */
static int test_discover(void)
{
#ifdef CYXWIZ_HAS_UDP
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_UDP, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Discover should succeed (sends to bootstrap, but we don't have one) */
    err = transport->ops->discover(transport);
    if (err != CYXWIZ_OK) {
        printf("(discover failed: %s) ", cyxwiz_strerror(err));
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
#else
    printf("(UDP not enabled) ");
    return 1;
#endif
}

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE);  /* Quiet during tests */

    printf("\nCyxWiz UDP Transport Tests\n");
    printf("==========================\n\n");

    TEST(udp_create);
    TEST(type_name);
    TEST(max_packet_size);
    TEST(poll);
    TEST(send_unknown_peer);
    TEST(callbacks);
    TEST(discover);

    printf("\n==========================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
