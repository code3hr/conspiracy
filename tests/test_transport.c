/*
 * CyxWiz Protocol - Transport Tests
 */

#include "cyxwiz/types.h"
#include "cyxwiz/transport.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <stdio.h>
#include <string.h>

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

/* Test secure memory zeroing */
static int test_secure_zero(void)
{
    uint8_t buf[32];
    memset(buf, 0xFF, sizeof(buf));

    cyxwiz_secure_zero(buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Test constant-time comparison */
static int test_secure_compare(void)
{
    uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t c[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99};

    /* Equal buffers should return 0 */
    if (cyxwiz_secure_compare(a, b, 16) != 0) {
        return 0;
    }

    /* Different buffers should return non-zero */
    if (cyxwiz_secure_compare(a, c, 16) == 0) {
        return 0;
    }

    return 1;
}

/* Test transport type names */
static int test_transport_type_name(void)
{
    const char *name;

    name = cyxwiz_transport_type_name(CYXWIZ_TRANSPORT_WIFI_DIRECT);
    if (strcmp(name, "WiFi Direct") != 0) {
        return 0;
    }

    name = cyxwiz_transport_type_name(CYXWIZ_TRANSPORT_BLUETOOTH);
    if (strcmp(name, "Bluetooth") != 0) {
        return 0;
    }

    name = cyxwiz_transport_type_name(CYXWIZ_TRANSPORT_LORA);
    if (strcmp(name, "LoRa") != 0) {
        return 0;
    }

    return 1;
}

/* Test error strings */
static int test_strerror(void)
{
    const char *s;

    s = cyxwiz_strerror(CYXWIZ_OK);
    if (strcmp(s, "Success") != 0) {
        return 0;
    }

    s = cyxwiz_strerror(CYXWIZ_ERR_NOMEM);
    if (strcmp(s, "Out of memory") != 0) {
        return 0;
    }

    return 1;
}

#ifdef CYXWIZ_HAS_WIFI
/* Test WiFi transport creation */
static int test_wifi_transport_create(void)
{
    cyxwiz_transport_t *transport = NULL;
    cyxwiz_error_t err;

    err = cyxwiz_transport_create(CYXWIZ_TRANSPORT_WIFI_DIRECT, &transport);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    if (transport == NULL) {
        return 0;
    }

    if (transport->type != CYXWIZ_TRANSPORT_WIFI_DIRECT) {
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    /* Check max packet size */
    size_t mtu = transport->ops->max_packet_size(transport);
    if (mtu == 0 || mtu > 65535) {
        cyxwiz_transport_destroy(transport);
        return 0;
    }

    cyxwiz_transport_destroy(transport);
    return 1;
}
#endif

int main(void)
{
    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Transport Tests\n");
    printf("======================\n\n");

    TEST(secure_zero);
    TEST(secure_compare);
    TEST(transport_type_name);
    TEST(strerror);

#ifdef CYXWIZ_HAS_WIFI
    TEST(wifi_transport_create);
#endif

    printf("\n======================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
