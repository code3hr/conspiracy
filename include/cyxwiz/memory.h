/*
 * CyxWiz Protocol - Secure Memory Utilities
 *
 * Memory management with security in mind:
 * - Secure zeroing (compiler can't optimize away)
 * - Guarded allocations
 * - Tracking for leak detection
 */

#ifndef CYXWIZ_MEMORY_H
#define CYXWIZ_MEMORY_H

#include "types.h"

/*
 * Securely zero memory - guaranteed not to be optimized away
 * Use for clearing sensitive data (keys, passwords, etc.)
 */
void cyxwiz_secure_zero(void *ptr, size_t len);

/*
 * Allocate memory, returns NULL on failure
 */
void *cyxwiz_malloc(size_t size);

/*
 * Allocate and zero memory
 */
void *cyxwiz_calloc(size_t nmemb, size_t size);

/*
 * Reallocate memory
 */
void *cyxwiz_realloc(void *ptr, size_t size);

/*
 * Free memory (securely zeros before freeing)
 * Safe to call with NULL
 */
void cyxwiz_free(void *ptr, size_t size);

/*
 * Compare memory in constant time (prevents timing attacks)
 * Returns 0 if equal, non-zero otherwise
 */
int cyxwiz_secure_compare(const void *a, const void *b, size_t len);

/*
 * Pad message buffer with random bytes for traffic analysis prevention
 * Fills buffer from msg_len to target_len with random data
 *
 * @param buf        Message buffer (must have space for target_len bytes)
 * @param msg_len    Current message length
 * @param target_len Target padded length (typically CYXWIZ_PADDED_SIZE)
 */
void cyxwiz_pad_message(uint8_t *buf, size_t msg_len, size_t target_len);

/*
 * Bounds checking macro for array access
 * Returns CYXWIZ_ERR_INVALID if index >= max
 * Use at beginning of functions to validate array indices
 */
#define CYXWIZ_CHECK_BOUNDS(idx, max) \
    do { if ((size_t)(idx) >= (size_t)(max)) return CYXWIZ_ERR_INVALID; } while(0)

/*
 * Bounds checking macro for sizes (must be <= max)
 */
#define CYXWIZ_CHECK_SIZE(size, max) \
    do { if ((size_t)(size) > (size_t)(max)) return CYXWIZ_ERR_INVALID; } while(0)

/*
 * Null pointer check macro
 */
#define CYXWIZ_CHECK_NULL(ptr) \
    do { if ((ptr) == NULL) return CYXWIZ_ERR_INVALID; } while(0)

#endif /* CYXWIZ_MEMORY_H */
