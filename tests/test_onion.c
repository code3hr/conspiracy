/*
 * CyxWiz Protocol - Onion Routing Tests
 */

#include "cyxwiz/types.h"
#include "cyxwiz/onion.h"
#include "cyxwiz/crypto.h"
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

/* Generate random node ID */
static void random_node_id(cyxwiz_node_id_t *id)
{
    cyxwiz_crypto_random(id->bytes, CYXWIZ_NODE_ID_LEN);
}

/* Test key derivation */
static int test_key_derivation(void)
{
    uint8_t shared_secret[CYXWIZ_KEY_SIZE];
    cyxwiz_node_id_t sender, receiver;
    uint8_t key1[CYXWIZ_KEY_SIZE];
    uint8_t key2[CYXWIZ_KEY_SIZE];

    /* Generate random inputs */
    cyxwiz_crypto_random(shared_secret, CYXWIZ_KEY_SIZE);
    random_node_id(&sender);
    random_node_id(&receiver);

    /* Derive same key twice */
    cyxwiz_error_t err = cyxwiz_onion_derive_hop_key(
        shared_secret, &sender, &receiver, key1);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    err = cyxwiz_onion_derive_hop_key(
        shared_secret, &sender, &receiver, key2);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Should be identical */
    if (memcmp(key1, key2, CYXWIZ_KEY_SIZE) != 0) {
        return 0;
    }

    /* Different sender should give different key */
    cyxwiz_node_id_t sender2;
    random_node_id(&sender2);

    err = cyxwiz_onion_derive_hop_key(
        shared_secret, &sender2, &receiver, key2);
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Should be different */
    if (memcmp(key1, key2, CYXWIZ_KEY_SIZE) == 0) {
        return 0;
    }

    return 1;
}

/* Test single layer wrap/unwrap */
static int test_wrap_unwrap_1hop(void)
{
    uint8_t payload[] = "Hello, onion routing!";
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hop;
    random_node_id(&hop);

    uint8_t key[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(key);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    /* Wrap */
    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        &hop, (const uint8_t (*)[CYXWIZ_KEY_SIZE])&key, 1,
        onion, &onion_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Onion should be larger than payload */
    size_t expected_size = payload_len + CYXWIZ_NODE_ID_LEN + CYXWIZ_ONION_OVERHEAD;
    if (onion_len != expected_size) {
        return 0;
    }

    /* Unwrap */
    cyxwiz_node_id_t next_hop;
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(
        onion, onion_len,
        key,
        &next_hop,
        inner, &inner_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Next hop should be zeros (final destination marker) */
    if (!cyxwiz_node_id_is_zero(&next_hop)) {
        return 0;
    }

    /* Inner data should match original payload */
    if (inner_len != payload_len) {
        return 0;
    }

    if (memcmp(payload, inner, payload_len) != 0) {
        return 0;
    }

    return 1;
}

/* Test two layer onion */
static int test_wrap_unwrap_2hop(void)
{
    uint8_t payload[] = "Secret 2-hop message";
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hops[2];
    random_node_id(&hops[0]);  /* First hop */
    random_node_id(&hops[1]);  /* Second hop (destination) */

    uint8_t keys[2][CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(keys[0]);
    cyxwiz_crypto_random_key(keys[1]);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    /* Wrap with 2 hops */
    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        hops, (const uint8_t (*)[CYXWIZ_KEY_SIZE])keys, 2,
        onion, &onion_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Unwrap first layer (at hop 1) */
    cyxwiz_node_id_t next_hop;
    uint8_t layer1[CYXWIZ_MAX_PACKET_SIZE];
    size_t layer1_len;

    err = cyxwiz_onion_unwrap(
        onion, onion_len,
        keys[0],
        &next_hop,
        layer1, &layer1_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Next hop should be hop 2 */
    if (cyxwiz_node_id_cmp(&next_hop, &hops[1]) != 0) {
        return 0;
    }

    /* Unwrap second layer (at hop 2) */
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(
        layer1, layer1_len,
        keys[1],
        &next_hop,
        inner, &inner_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Next hop should be zeros (final) */
    if (!cyxwiz_node_id_is_zero(&next_hop)) {
        return 0;
    }

    /* Verify payload */
    if (inner_len != payload_len) {
        return 0;
    }

    if (memcmp(payload, inner, payload_len) != 0) {
        return 0;
    }

    return 1;
}

/* Test three layer onion (maximum) */
static int test_wrap_unwrap_3hop(void)
{
    /* With 3 hops, payload is limited to ~29 bytes */
    uint8_t payload[] = "3-hop secret!";  /* 13 bytes */
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hops[3];
    random_node_id(&hops[0]);
    random_node_id(&hops[1]);
    random_node_id(&hops[2]);

    uint8_t keys[3][CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(keys[0]);
    cyxwiz_crypto_random_key(keys[1]);
    cyxwiz_crypto_random_key(keys[2]);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    /* Wrap with 3 hops */
    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        hops, (const uint8_t (*)[CYXWIZ_KEY_SIZE])keys, 3,
        onion, &onion_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Peel all three layers */
    uint8_t current[CYXWIZ_MAX_PACKET_SIZE];
    size_t current_len = onion_len;
    memcpy(current, onion, onion_len);

    cyxwiz_node_id_t next_hop;
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len;

    for (int i = 0; i < 3; i++) {
        err = cyxwiz_onion_unwrap(
            current, current_len,
            keys[i],
            &next_hop,
            inner, &inner_len
        );
        if (err != CYXWIZ_OK) {
            return 0;
        }

        if (i < 2) {
            /* Check next hop is correct */
            if (cyxwiz_node_id_cmp(&next_hop, &hops[i + 1]) != 0) {
                return 0;
            }
            /* Prepare for next iteration */
            memcpy(current, inner, inner_len);
            current_len = inner_len;
        } else {
            /* Last hop - should be zero */
            if (!cyxwiz_node_id_is_zero(&next_hop)) {
                return 0;
            }
        }
    }

    /* Verify final payload */
    if (inner_len != payload_len) {
        return 0;
    }

    if (memcmp(payload, inner, payload_len) != 0) {
        return 0;
    }

    return 1;
}

/* Test tamper detection */
static int test_tamper_detection(void)
{
    uint8_t payload[] = "Do not tamper!";
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hop;
    random_node_id(&hop);

    uint8_t key[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(key);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        &hop, (const uint8_t (*)[CYXWIZ_KEY_SIZE])&key, 1,
        onion, &onion_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Tamper with the ciphertext */
    onion[onion_len / 2] ^= 0xFF;

    /* Unwrap should fail */
    cyxwiz_node_id_t next_hop;
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(
        onion, onion_len,
        key,
        &next_hop,
        inner, &inner_len
    );

    /* Should fail with crypto error */
    return (err == CYXWIZ_ERR_CRYPTO);
}

/* Test wrong key fails */
static int test_wrong_key(void)
{
    uint8_t payload[] = "Wrong key test";
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hop;
    random_node_id(&hop);

    uint8_t key1[CYXWIZ_KEY_SIZE];
    uint8_t key2[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(key1);
    cyxwiz_crypto_random_key(key2);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    /* Wrap with key1 */
    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        &hop, (const uint8_t (*)[CYXWIZ_KEY_SIZE])&key1, 1,
        onion, &onion_len
    );
    if (err != CYXWIZ_OK) {
        return 0;
    }

    /* Unwrap with key2 should fail */
    cyxwiz_node_id_t next_hop;
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(
        onion, onion_len,
        key2,
        &next_hop,
        inner, &inner_len
    );

    return (err == CYXWIZ_ERR_CRYPTO);
}

/* Test payload size limits */
static int test_payload_sizes(void)
{
    /* Test max payload for each hop count */
    size_t max_1hop = cyxwiz_onion_max_payload(1);
    size_t max_2hop = cyxwiz_onion_max_payload(2);
    size_t max_3hop = cyxwiz_onion_max_payload(3);

    /* Verify limits match constants */
    if (max_1hop != CYXWIZ_ONION_PAYLOAD_1HOP) {
        return 0;
    }
    if (max_2hop != CYXWIZ_ONION_PAYLOAD_2HOP) {
        return 0;
    }
    if (max_3hop != CYXWIZ_ONION_PAYLOAD_3HOP) {
        return 0;
    }

    /* Each additional hop reduces payload by OVERHEAD + NODE_ID_SIZE */
    size_t per_hop_cost = CYXWIZ_ONION_OVERHEAD + CYXWIZ_NODE_ID_LEN;
    if (max_1hop - max_2hop != per_hop_cost) {
        return 0;
    }
    if (max_2hop - max_3hop != per_hop_cost) {
        return 0;
    }

    return 1;
}

/* Test node ID zero check */
static int test_node_id_zero(void)
{
    cyxwiz_node_id_t zero_id;
    memset(&zero_id, 0, sizeof(zero_id));

    cyxwiz_node_id_t nonzero_id;
    random_node_id(&nonzero_id);

    if (!cyxwiz_node_id_is_zero(&zero_id)) {
        return 0;
    }

    if (cyxwiz_node_id_is_zero(&nonzero_id)) {
        return 0;
    }

    return 1;
}

/* Test payload too large error */
static int test_payload_too_large(void)
{
    /* Create payload larger than max for 1-hop */
    uint8_t payload[200];  /* Larger than CYXWIZ_ONION_PAYLOAD_1HOP (173) */
    memset(payload, 'A', sizeof(payload));

    cyxwiz_node_id_t hop;
    random_node_id(&hop);

    uint8_t key[CYXWIZ_KEY_SIZE];
    cyxwiz_crypto_random_key(key);

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, sizeof(payload),
        &hop, (const uint8_t (*)[CYXWIZ_KEY_SIZE])&key, 1,
        onion, &onion_len
    );

    return (err == CYXWIZ_ERR_PACKET_TOO_LARGE);
}

/* Test invalid hop count */
static int test_invalid_hop_count(void)
{
    uint8_t payload[] = "Test";
    size_t payload_len = sizeof(payload) - 1;

    cyxwiz_node_id_t hops[4];
    uint8_t keys[4][CYXWIZ_KEY_SIZE];

    for (int i = 0; i < 4; i++) {
        random_node_id(&hops[i]);
        cyxwiz_crypto_random_key(keys[i]);
    }

    uint8_t onion[CYXWIZ_MAX_PACKET_SIZE];
    size_t onion_len;

    /* 0 hops should fail */
    cyxwiz_error_t err = cyxwiz_onion_wrap(
        payload, payload_len,
        hops, (const uint8_t (*)[CYXWIZ_KEY_SIZE])keys, 0,
        onion, &onion_len
    );
    if (err == CYXWIZ_OK) {
        return 0;
    }

    /* 4 hops (> MAX) should fail */
    err = cyxwiz_onion_wrap(
        payload, payload_len,
        hops, (const uint8_t (*)[CYXWIZ_KEY_SIZE])keys, 4,
        onion, &onion_len
    );
    if (err == CYXWIZ_OK) {
        return 0;
    }

    return 1;
}

/* Test circuit finding functions */
static int test_find_circuit_to(void)
{
    cyxwiz_node_id_t local_id;
    random_node_id(&local_id);

    /* We need a mock router - test with NULL should return NULL */
    cyxwiz_circuit_t *circuit = cyxwiz_onion_find_circuit_to(NULL, &local_id);
    if (circuit != NULL) {
        return 0;
    }

    /* NULL destination should return NULL */
    /* Note: can't test with real ctx without router, so test just the NULL cases */

    return 1;
}

/* Test has_circuit_to */
static int test_has_circuit_to(void)
{
    cyxwiz_node_id_t destination;
    random_node_id(&destination);

    /* NULL ctx should return false */
    if (cyxwiz_onion_has_circuit_to(NULL, &destination)) {
        return 0;
    }

    return 1;
}

/* Test send_to parameter validation */
static int test_send_to_validation(void)
{
    cyxwiz_node_id_t destination;
    random_node_id(&destination);
    uint8_t data[] = "test data";

    /* NULL ctx should return error */
    cyxwiz_error_t err = cyxwiz_onion_send_to(NULL, &destination, data, sizeof(data));
    if (err == CYXWIZ_OK) {
        return 0;
    }

    return 1;
}

int main(void)
{
    /* Initialize crypto */
    cyxwiz_error_t err = cyxwiz_crypto_init();
    if (err != CYXWIZ_OK) {
        printf("Failed to initialize crypto\n");
        return 1;
    }

    cyxwiz_log_init(CYXWIZ_LOG_NONE); /* Quiet during tests */

    printf("\nCyxWiz Onion Routing Tests\n");
    printf("==========================\n\n");

    TEST(key_derivation);
    TEST(wrap_unwrap_1hop);
    TEST(wrap_unwrap_2hop);
    TEST(wrap_unwrap_3hop);
    TEST(tamper_detection);
    TEST(wrong_key);
    TEST(payload_sizes);
    TEST(node_id_zero);
    TEST(payload_too_large);
    TEST(invalid_hop_count);
    TEST(find_circuit_to);
    TEST(has_circuit_to);
    TEST(send_to_validation);

    printf("\n==========================\n");
    printf("Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
