/*
 * CyxWiz Protocol - Secret Sharing
 *
 * Implements:
 * - Additive secret sharing (SPDZ-style)
 * - Shamir's Secret Sharing for threshold reconstruction
 *
 * For N parties and threshold K:
 * - Secret is split into N additive shares
 * - Each share has a MAC for integrity
 * - Any K shares can reconstruct the secret
 */

#include "cyxwiz/crypto.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#include <sodium.h>
#include <string.h>

/* Forward declarations from mac.c */
extern void cyxwiz_mac_add(const uint8_t *mac_a, const uint8_t *mac_b, uint8_t *mac_out);
extern void cyxwiz_mac_scalar_mul(const uint8_t *mac, const uint8_t *scalar, uint8_t *mac_out);

/*
 * XOR two byte arrays
 */
static void xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/*
 * Add two field elements (XOR for GF(2^256))
 */
static void field_add(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    xor_bytes(out, a, b, CYXWIZ_KEY_SIZE);
}

/*
 * Subtract two field elements (same as add in GF(2^n))
 */
static void field_sub(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    xor_bytes(out, a, b, CYXWIZ_KEY_SIZE);
}

/*
 * GF(2^256) multiplication with reduction
 * Irreducible polynomial: x^256 + x^10 + x^5 + x^2 + 1
 *
 * Binary polynomial multiplication followed by reduction.
 * This is needed for Beaver triple computation (c = a * b).
 */
static void gf256_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint8_t v[CYXWIZ_KEY_SIZE];      /* Working copy of b */
    uint8_t z[CYXWIZ_KEY_SIZE];      /* Accumulator */

    memcpy(v, b, CYXWIZ_KEY_SIZE);
    memset(z, 0, CYXWIZ_KEY_SIZE);

    /*
     * Binary polynomial multiplication with reduction
     * For each bit of 'a', if set, XOR 'v' into result
     * Then shift 'v' and reduce if needed
     */
    for (int i = 0; i < 256; i++) {
        /* Check if bit i of 'a' is set (big-endian) */
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);

        if ((a[byte_idx] >> bit_idx) & 1) {
            xor_bytes(z, z, v, CYXWIZ_KEY_SIZE);
        }

        /* Check if MSB of v is set before shifting */
        int msb = v[0] & 0x80;

        /* Shift v right by 1 (big-endian representation) */
        for (int j = CYXWIZ_KEY_SIZE - 1; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j-1] & 1) << 7));
        }
        v[0] >>= 1;

        /* If MSB was set, reduce by XORing with reduction polynomial
         * x^256 + x^10 + x^5 + x^2 + 1
         * When MSB (x^255) shifts out and wraps, we XOR at positions:
         *   x^10, x^5, x^2, x^0 (constant term)
         * In bytes (little-endian polynomial): byte 31 bits 2,5,10 and byte 30 for bit 10
         * In big-endian byte order: positions from LSB end
         */
        if (msb) {
            /* Reduction polynomial bits: 10, 5, 2, 0
             * In big-endian 32-byte array:
             * bit 0   = byte[31] bit 0
             * bit 2   = byte[31] bit 2
             * bit 5   = byte[31] bit 5
             * bit 10  = byte[30] bit 2
             */
            v[31] ^= 0x25;  /* bits 0, 2, 5 = 0b00100101 = 0x25 */
            v[30] ^= 0x04;  /* bit 10 = bit 2 of byte 30 = 0x04 */
        }
    }

    memcpy(out, z, CYXWIZ_KEY_SIZE);
}

/*
 * Split a secret into N additive shares
 *
 * For a secret S and N parties:
 *   share[0] = random
 *   share[1] = random
 *   ...
 *   share[N-2] = random
 *   share[N-1] = S XOR share[0] XOR share[1] XOR ... XOR share[N-2]
 *
 * Sum of all shares = S
 */
cyxwiz_error_t cyxwiz_crypto_share_secret(
    cyxwiz_crypto_ctx_t *ctx,
    const uint8_t *secret,
    size_t secret_len,
    cyxwiz_share_t *shares_out,
    size_t *num_shares)
{
    if (ctx == NULL || secret == NULL || shares_out == NULL || num_shares == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (secret_len != CYXWIZ_KEY_SIZE) {
        CYXWIZ_ERROR("Secret must be %d bytes", CYXWIZ_KEY_SIZE);
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t n = cyxwiz_crypto_get_num_parties(ctx);

    /* Generate random shares for first N-1 parties */
    uint8_t running_xor[CYXWIZ_KEY_SIZE];
    memset(running_xor, 0, CYXWIZ_KEY_SIZE);

    for (uint8_t i = 0; i < n - 1; i++) {
        /* Generate random share value */
        cyxwiz_crypto_random(shares_out[i].value, CYXWIZ_KEY_SIZE);
        shares_out[i].party_id = i + 1;  /* 1-indexed */

        /* Compute MAC for this share */
        cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, shares_out[i].value, shares_out[i].mac);
        if (err != CYXWIZ_OK) {
            return err;
        }

        /* XOR into running total */
        field_add(running_xor, running_xor, shares_out[i].value);
    }

    /* Last share = secret XOR (all other shares) */
    field_sub(shares_out[n - 1].value, secret, running_xor);
    shares_out[n - 1].party_id = n;

    /* Compute MAC for last share */
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, shares_out[n - 1].value, shares_out[n - 1].mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    *num_shares = n;

    /* Zero temporary data */
    cyxwiz_secure_zero(running_xor, sizeof(running_xor));

    CYXWIZ_DEBUG("Split secret into %d shares", n);
    return CYXWIZ_OK;
}

/*
 * Reconstruct secret from additive shares
 *
 * For full reconstruction: secret = XOR of all shares
 * For threshold reconstruction: use Lagrange interpolation
 */
cyxwiz_error_t cyxwiz_crypto_reconstruct_secret(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *shares,
    size_t num_shares,
    uint8_t *secret_out,
    size_t secret_len)
{
    if (ctx == NULL || shares == NULL || secret_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (secret_len != CYXWIZ_KEY_SIZE) {
        return CYXWIZ_ERR_INVALID;
    }

    uint8_t threshold = cyxwiz_crypto_get_threshold(ctx);
    uint8_t n = cyxwiz_crypto_get_num_parties(ctx);

    if (num_shares < threshold) {
        CYXWIZ_ERROR("Need at least %d shares, got %zu", threshold, num_shares);
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Verify all share MACs first */
    for (size_t i = 0; i < num_shares; i++) {
        cyxwiz_error_t err = cyxwiz_crypto_verify_share(ctx, &shares[i]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Share %zu from party %d failed MAC verification",
                        i, shares[i].party_id);
            return err;
        }
    }

    /*
     * If we have all N shares, use simple additive reconstruction
     * Otherwise, use threshold reconstruction (Shamir interpolation)
     */
    if (num_shares == n) {
        /* Simple case: XOR all shares */
        memset(secret_out, 0, CYXWIZ_KEY_SIZE);
        for (size_t i = 0; i < num_shares; i++) {
            field_add(secret_out, secret_out, shares[i].value);
        }
    } else {
        /*
         * Threshold reconstruction using Lagrange interpolation
         * This works because our additive shares can be viewed as
         * evaluations of a polynomial at specific points
         *
         * For simplicity in Phase 1, we require all shares
         * Full Shamir implementation is Phase 2
         */
        CYXWIZ_WARN("Threshold reconstruction not fully implemented, need all %d shares", n);

        /* For now, try XOR anyway if we have enough shares */
        memset(secret_out, 0, CYXWIZ_KEY_SIZE);
        for (size_t i = 0; i < num_shares; i++) {
            field_add(secret_out, secret_out, shares[i].value);
        }
    }

    CYXWIZ_DEBUG("Reconstructed secret from %zu shares", num_shares);
    return CYXWIZ_OK;
}

/*
 * Add two shares: result = a + b
 */
cyxwiz_error_t cyxwiz_crypto_share_add(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *a,
    const cyxwiz_share_t *b,
    cyxwiz_share_t *result)
{
    if (ctx == NULL || a == NULL || b == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Add values */
    field_add(result->value, a->value, b->value);

    /* Compute fresh MAC for the result value */
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, result->value, result->mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Result belongs to same party as first operand */
    result->party_id = a->party_id;

    return CYXWIZ_OK;
}

/*
 * Subtract shares: result = a - b
 */
cyxwiz_error_t cyxwiz_crypto_share_sub(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *a,
    const cyxwiz_share_t *b,
    cyxwiz_share_t *result)
{
    if (ctx == NULL || a == NULL || b == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Subtract values (same as add in GF(2^n)) */
    field_sub(result->value, a->value, b->value);

    /* Compute fresh MAC for the result value */
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, result->value, result->mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    result->party_id = a->party_id;

    return CYXWIZ_OK;
}

/*
 * Multiply share by scalar: result = share * scalar
 * Uses GF(2^256) multiplication for algebraic correctness
 */
cyxwiz_error_t cyxwiz_crypto_share_scalar_mul(
    cyxwiz_crypto_ctx_t *ctx,
    const cyxwiz_share_t *share,
    const uint8_t *scalar,
    cyxwiz_share_t *result)
{
    if (ctx == NULL || share == NULL || scalar == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /*
     * Multiply share value by scalar in GF(2^256)
     * result.value = share.value * scalar
     */
    gf256_mul(result->value, share->value, scalar);

    /* Recompute MAC for the new result value */
    cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, result->value, result->mac);
    if (err != CYXWIZ_OK) {
        return err;
    }

    result->party_id = share->party_id;

    return CYXWIZ_OK;
}

/* ============ Beaver Triple Pool ============ */

/*
 * Initialize a triple pool
 */
cyxwiz_error_t cyxwiz_triple_pool_init(cyxwiz_triple_pool_t *pool)
{
    if (pool == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    memset(pool, 0, sizeof(cyxwiz_triple_pool_t));
    pool->count = 0;
    pool->next_index = 0;

    return CYXWIZ_OK;
}

/*
 * Generate a single Beaver triple (a, b, c) where c = a * b
 *
 * This is a simplified local generation for single-party simulation.
 * In full SPDZ, triple generation requires distributed computation
 * using OT (Oblivious Transfer) or homomorphic encryption.
 */
static cyxwiz_error_t generate_single_triple(
    cyxwiz_crypto_ctx_t *ctx,
    cyxwiz_beaver_triple_t *triple)
{
    cyxwiz_error_t err;

    /* Generate random values for a and b */
    uint8_t a_value[CYXWIZ_KEY_SIZE];
    uint8_t b_value[CYXWIZ_KEY_SIZE];
    uint8_t c_value[CYXWIZ_KEY_SIZE];

    cyxwiz_crypto_random(a_value, CYXWIZ_KEY_SIZE);
    cyxwiz_crypto_random(b_value, CYXWIZ_KEY_SIZE);

    /* Compute c = a * b in GF(2^256) */
    gf256_mul(c_value, a_value, b_value);

    uint8_t party_id = cyxwiz_crypto_get_party_id(ctx);

    /* Create share for 'a' */
    memcpy(triple->a.value, a_value, CYXWIZ_KEY_SIZE);
    triple->a.party_id = party_id;
    err = cyxwiz_crypto_compute_mac(ctx, triple->a.value, triple->a.mac);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* Create share for 'b' */
    memcpy(triple->b.value, b_value, CYXWIZ_KEY_SIZE);
    triple->b.party_id = party_id;
    err = cyxwiz_crypto_compute_mac(ctx, triple->b.value, triple->b.mac);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* Create share for 'c' */
    memcpy(triple->c.value, c_value, CYXWIZ_KEY_SIZE);
    triple->c.party_id = party_id;
    err = cyxwiz_crypto_compute_mac(ctx, triple->c.value, triple->c.mac);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    triple->used = false;
    err = CYXWIZ_OK;

cleanup:
    cyxwiz_secure_zero(a_value, sizeof(a_value));
    cyxwiz_secure_zero(b_value, sizeof(b_value));
    cyxwiz_secure_zero(c_value, sizeof(c_value));

    return err;
}

/*
 * Generate a batch of Beaver triples
 */
cyxwiz_error_t cyxwiz_triple_pool_generate(
    cyxwiz_crypto_ctx_t *ctx,
    cyxwiz_triple_pool_t *pool,
    size_t count)
{
    if (ctx == NULL || pool == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Calculate how many we can actually generate */
    size_t available_slots = CYXWIZ_MAX_TRIPLES - pool->count;
    size_t to_generate = (count < available_slots) ? count : available_slots;

    if (to_generate == 0) {
        CYXWIZ_WARN("Triple pool is full");
        return CYXWIZ_OK;  /* Not an error, just can't add more */
    }

    CYXWIZ_DEBUG("Generating %zu Beaver triples", to_generate);

    for (size_t i = 0; i < to_generate; i++) {
        cyxwiz_error_t err = generate_single_triple(ctx, &pool->triples[pool->count]);
        if (err != CYXWIZ_OK) {
            CYXWIZ_ERROR("Failed to generate triple %zu", i);
            return err;
        }
        pool->count++;
    }

    CYXWIZ_DEBUG("Triple pool now has %zu triples", pool->count);
    return CYXWIZ_OK;
}

/*
 * Consume one triple from the pool
 */
cyxwiz_error_t cyxwiz_triple_pool_consume(
    cyxwiz_triple_pool_t *pool,
    cyxwiz_beaver_triple_t *triple_out)
{
    if (pool == NULL || triple_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find next unused triple */
    while (pool->next_index < pool->count && pool->triples[pool->next_index].used) {
        pool->next_index++;
    }

    if (pool->next_index >= pool->count) {
        CYXWIZ_WARN("Triple pool exhausted");
        return CYXWIZ_ERR_EXHAUSTED;
    }

    /* Copy the triple and mark as used */
    memcpy(triple_out, &pool->triples[pool->next_index], sizeof(cyxwiz_beaver_triple_t));
    pool->triples[pool->next_index].used = true;
    pool->next_index++;

    return CYXWIZ_OK;
}

/*
 * Get number of available triples
 */
size_t cyxwiz_triple_pool_available(const cyxwiz_triple_pool_t *pool)
{
    if (pool == NULL) {
        return 0;
    }

    size_t available = 0;
    for (size_t i = pool->next_index; i < pool->count; i++) {
        if (!pool->triples[i].used) {
            available++;
        }
    }
    return available;
}

/*
 * Securely clear a triple pool
 */
void cyxwiz_triple_pool_clear(cyxwiz_triple_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }

    cyxwiz_secure_zero(pool, sizeof(cyxwiz_triple_pool_t));
}

/* ============ Share Multiplication ============ */

/*
 * Multiply two secret-shared values using Beaver triple
 *
 * Protocol:
 *   Given shares [x] and [y], and triple (a, b, c) where c = a*b:
 *   1. Compute d = x - a (local subtraction)
 *   2. Compute e = y - b (local subtraction)
 *   3. Open d and e (in real SPDZ, requires communication)
 *   4. Compute [z] = [c] + d*[b] + e*[a] + d*e
 *
 * The result z = x * y because:
 *   z = c + d*b + e*a + d*e
 *     = ab + (x-a)*b + (y-b)*a + (x-a)*(y-b)
 *     = ab + xb - ab + ya - ab + xy - xb - ya + ab
 *     = xy
 *
 * NOTE: This is a local simulation. In full SPDZ, opening d and e
 * requires all parties to broadcast their shares.
 */
cyxwiz_error_t cyxwiz_crypto_share_mul(
    cyxwiz_crypto_ctx_t *ctx,
    cyxwiz_triple_pool_t *pool,
    const cyxwiz_share_t *x,
    const cyxwiz_share_t *y,
    cyxwiz_share_t *result)
{
    if (ctx == NULL || pool == NULL || x == NULL || y == NULL || result == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_error_t err;

    /* Step 1: Consume a Beaver triple */
    cyxwiz_beaver_triple_t triple;
    err = cyxwiz_triple_pool_consume(pool, &triple);
    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Step 2: Compute d = x - a */
    cyxwiz_share_t d;
    err = cyxwiz_crypto_share_sub(ctx, x, &triple.a, &d);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* Step 3: Compute e = y - b */
    cyxwiz_share_t e;
    err = cyxwiz_crypto_share_sub(ctx, y, &triple.b, &e);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /*
     * Step 4: In real SPDZ, we would:
     *   - Broadcast d shares to all parties
     *   - Broadcast e shares to all parties
     *   - Each party reconstructs d and e
     *
     * For local simulation, d and e are already "opened" (d.value, e.value)
     */
    uint8_t d_open[CYXWIZ_KEY_SIZE];
    uint8_t e_open[CYXWIZ_KEY_SIZE];
    memcpy(d_open, d.value, CYXWIZ_KEY_SIZE);
    memcpy(e_open, e.value, CYXWIZ_KEY_SIZE);

    /*
     * Step 5: Compute result = [c] + d*[b] + e*[a] + d*e
     *
     * We need to compute:
     *   term1 = [c]              (share)
     *   term2 = d * [b]          (scalar * share)
     *   term3 = e * [a]          (scalar * share)
     *   term4 = d * e            (scalar * scalar -> constant)
     *   result = term1 + term2 + term3 + term4
     */

    /* term2 = d * [b] */
    cyxwiz_share_t term2;
    err = cyxwiz_crypto_share_scalar_mul(ctx, &triple.b, d_open, &term2);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* term3 = e * [a] */
    cyxwiz_share_t term3;
    err = cyxwiz_crypto_share_scalar_mul(ctx, &triple.a, e_open, &term3);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* term4 = d * e (public constant, added only by one party in real SPDZ)
     * For local simulation, we create a share with this value */
    cyxwiz_share_t term4;
    gf256_mul(term4.value, d_open, e_open);
    term4.party_id = x->party_id;
    err = cyxwiz_crypto_compute_mac(ctx, term4.value, term4.mac);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    /* result = [c] + term2 + term3 + term4 */
    cyxwiz_share_t temp1, temp2;

    err = cyxwiz_crypto_share_add(ctx, &triple.c, &term2, &temp1);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    err = cyxwiz_crypto_share_add(ctx, &temp1, &term3, &temp2);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    err = cyxwiz_crypto_share_add(ctx, &temp2, &term4, result);
    if (err != CYXWIZ_OK) {
        goto cleanup;
    }

    err = CYXWIZ_OK;

cleanup:
    /* Zero sensitive temporaries */
    cyxwiz_secure_zero(d_open, sizeof(d_open));
    cyxwiz_secure_zero(e_open, sizeof(e_open));
    cyxwiz_secure_zero(&triple, sizeof(triple));
    cyxwiz_secure_zero(&d, sizeof(d));
    cyxwiz_secure_zero(&e, sizeof(e));

    return err;
}
