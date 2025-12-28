/*
 * CyxWiz Protocol - Onion Unwrap Fuzz Target
 *
 * Tests cyxwiz_onion_unwrap() with random encrypted blobs.
 * Build with: cmake -DCYXWIZ_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
 * Run with: ./fuzz_onion corpus/ -max_len=250
 */

#include "cyxwiz/types.h"
#include "cyxwiz/onion.h"
#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Need at least some data to test */
    if (size < 1) {
        return 0;
    }

    /* Initialize crypto (idempotent) */
    static int initialized = 0;
    if (!initialized) {
        if (cyxwiz_crypto_init() != CYXWIZ_OK) {
            return 0;
        }
        initialized = 1;
    }

    /* Generate a random key for decryption attempts */
    uint8_t key[CYXWIZ_KEY_SIZE];
    if (size >= CYXWIZ_KEY_SIZE) {
        memcpy(key, data, CYXWIZ_KEY_SIZE);
    } else {
        memset(key, 0, sizeof(key));
        memcpy(key, data, size);
    }

    /* Output buffers */
    cyxwiz_node_id_t next_hop;
    uint8_t next_ephemeral[CYXWIZ_EPHEMERAL_SIZE];
    uint8_t inner[CYXWIZ_MAX_PACKET_SIZE];
    size_t inner_len = 0;

    /* Try to unwrap - should not crash regardless of input */
    cyxwiz_error_t err = cyxwiz_onion_unwrap(
        data,
        size,
        key,
        &next_hop,
        next_ephemeral,
        inner,
        &inner_len
    );

    /* Suppress unused variable warnings */
    (void)err;
    (void)next_hop;
    (void)next_ephemeral;
    (void)inner;

    return 0;
}
