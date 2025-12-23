/*
 * CyxWiz Protocol - Secure Memory Implementation
 */

#include "cyxwiz/memory.h"
#include "cyxwiz/crypto.h"
#include <stdlib.h>
#include <string.h>

/*
 * Secure zero - use volatile to prevent compiler optimization
 */
void cyxwiz_secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0) {
        return;
    }

    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void *cyxwiz_malloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }
    return malloc(size);
}

void *cyxwiz_calloc(size_t nmemb, size_t size)
{
    if (nmemb == 0 || size == 0) {
        return NULL;
    }
    return calloc(nmemb, size);
}

void *cyxwiz_realloc(void *ptr, size_t size)
{
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, size);
}

void cyxwiz_free(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }

    /* Zero before freeing to prevent sensitive data leaks */
    if (size > 0) {
        cyxwiz_secure_zero(ptr, size);
    }

    free(ptr);
}

/*
 * Constant-time comparison to prevent timing attacks
 */
int cyxwiz_secure_compare(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;

    while (len--) {
        diff |= *pa++ ^ *pb++;
    }

    return diff;
}

/*
 * Pad message buffer with random bytes for traffic analysis prevention
 */
void cyxwiz_pad_message(uint8_t *buf, size_t msg_len, size_t target_len)
{
    if (buf == NULL || msg_len >= target_len) {
        return;
    }

    /* Fill padding with random bytes to prevent pattern detection */
    cyxwiz_crypto_random(buf + msg_len, target_len - msg_len);
}
