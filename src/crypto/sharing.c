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
 * This is needed for Beaver triple computation (c = a * b) and
 * Lagrange interpolation in Shamir's Secret Sharing.
 *
 * Representation (big-endian bytes):
 *   - byte[31] contains x^0 to x^7 (LSB)
 *   - byte[0] contains x^248 to x^255 (MSB)
 *   - bit j of byte i represents coefficient of x^(8*(31-i) + j)
 */
static void gf256_mul(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    uint8_t v[CYXWIZ_KEY_SIZE];      /* Working copy of b, shifted */
    uint8_t z[CYXWIZ_KEY_SIZE];      /* Accumulator */

    memcpy(v, b, CYXWIZ_KEY_SIZE);
    memset(z, 0, CYXWIZ_KEY_SIZE);

    /*
     * Standard shift-and-add polynomial multiplication
     * Process bits of 'a' from LSB (x^0) to MSB (x^255)
     * For each bit: if set, XOR current v into result
     * Then shift v left (multiply by x) and reduce if overflow
     */
    for (int i = 0; i < 256; i++) {
        /* Bit i of 'a' is at byte (31 - i/8), bit (i % 8)
         * e.g., bit 0 (x^0) is byte[31] bit 0
         *       bit 8 (x^8) is byte[30] bit 0
         */
        int byte_idx = 31 - (i / 8);
        int bit_idx = i % 8;

        if ((a[byte_idx] >> bit_idx) & 1) {
            xor_bytes(z, z, v, CYXWIZ_KEY_SIZE);
        }

        /* Shift v left by 1 (multiply by x) */
        int carry = 0;
        for (int j = CYXWIZ_KEY_SIZE - 1; j >= 0; j--) {
            int new_carry = (v[j] >> 7) & 1;
            v[j] = (uint8_t)((v[j] << 1) | carry);
            carry = new_carry;
        }

        /* If there was carry (x^256 term), reduce modulo p(x)
         * x^256 ≡ x^10 + x^5 + x^2 + 1 (mod p)
         * Positions in our representation:
         *   x^0  = byte[31] bit 0
         *   x^2  = byte[31] bit 2
         *   x^5  = byte[31] bit 5
         *   x^10 = byte[30] bit 2
         */
        if (carry) {
            v[31] ^= 0x25;  /* bits 0, 2, 5 = 0b00100101 */
            v[30] ^= 0x04;  /* bit 2 (which is x^10) */
        }
    }

    memcpy(out, z, CYXWIZ_KEY_SIZE);
}

/*
 * GF(2^256) squaring (optimized: a^2)
 */
static void gf256_square(uint8_t *out, const uint8_t *a)
{
    gf256_mul(out, a, a);
}

/*
 * GF(2^256) inversion using Fermat's little theorem
 * a^(-1) = a^(2^256 - 2) in GF(2^256)
 *
 * The exponent 2^256 - 2 = (2^256 - 1) - 1
 * In binary: 255 ones followed by a zero
 * = 111...110 (255 ones, then 0)
 *
 * We compute this using square-and-multiply.
 */
static void gf256_inverse(uint8_t *out, const uint8_t *a)
{
    uint8_t result[CYXWIZ_KEY_SIZE];
    uint8_t base[CYXWIZ_KEY_SIZE];
    uint8_t temp[CYXWIZ_KEY_SIZE];

    /* Check for zero (no inverse) */
    int is_zero = 1;
    for (size_t i = 0; i < CYXWIZ_KEY_SIZE; i++) {
        if (a[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    if (is_zero) {
        memset(out, 0, CYXWIZ_KEY_SIZE);
        return;
    }

    /* Initialize: result = 1, base = a */
    memset(result, 0, CYXWIZ_KEY_SIZE);
    result[CYXWIZ_KEY_SIZE - 1] = 1;  /* result = 1 */
    memcpy(base, a, CYXWIZ_KEY_SIZE);

    /*
     * Compute a^(2^256 - 2) using square-and-multiply
     * Exponent bits (from LSB): 0, then 255 ones
     * So we skip the first bit (0), then multiply for the next 255 bits (all 1s)
     */

    /* First iteration: square base, don't multiply (bit 0 is 0) */
    gf256_square(temp, base);
    memcpy(base, temp, CYXWIZ_KEY_SIZE);

    /* Next 255 iterations: square and multiply (bits 1-255 are all 1) */
    for (int i = 1; i < 256; i++) {
        /* Multiply result by base */
        gf256_mul(temp, result, base);
        memcpy(result, temp, CYXWIZ_KEY_SIZE);

        /* Square base */
        gf256_square(temp, base);
        memcpy(base, temp, CYXWIZ_KEY_SIZE);
    }

    memcpy(out, result, CYXWIZ_KEY_SIZE);
}

/*
 * Convert integer to field element
 * Sets the least significant byte to the value
 */
static void int_to_field(uint8_t *out, uint8_t val)
{
    memset(out, 0, CYXWIZ_KEY_SIZE);
    out[CYXWIZ_KEY_SIZE - 1] = val;
}

/*
 * Evaluate polynomial at point x
 * P(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ... + coeffs[degree]*x^degree
 *
 * Uses Horner's method: P(x) = ((coeffs[degree]*x + coeffs[degree-1])*x + ...)*x + coeffs[0]
 */
static void poly_eval(
    uint8_t *out,
    const uint8_t coeffs[][CYXWIZ_KEY_SIZE],
    size_t num_coeffs,
    const uint8_t *x)
{
    uint8_t result[CYXWIZ_KEY_SIZE];
    uint8_t temp[CYXWIZ_KEY_SIZE];

    if (num_coeffs == 0) {
        memset(out, 0, CYXWIZ_KEY_SIZE);
        return;
    }

    /* Start with highest degree coefficient */
    memcpy(result, coeffs[num_coeffs - 1], CYXWIZ_KEY_SIZE);

    /* Horner's method: work down to constant term */
    for (size_t i = num_coeffs - 1; i > 0; i--) {
        /* result = result * x */
        gf256_mul(temp, result, x);
        /* result = result + coeffs[i-1] */
        field_add(result, temp, coeffs[i - 1]);
    }

    memcpy(out, result, CYXWIZ_KEY_SIZE);
}

/*
 * Compute Lagrange basis polynomial L_i(0)
 *
 * L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
 *        = Π_{j≠i} x_j / (x_i - x_j)
 *
 * In GF(2^n), subtraction is XOR.
 */
static void lagrange_coeff(
    uint8_t *out,
    const uint8_t *party_ids,
    size_t num_parties,
    size_t i)
{
    uint8_t numerator[CYXWIZ_KEY_SIZE];
    uint8_t denominator[CYXWIZ_KEY_SIZE];
    uint8_t x_i[CYXWIZ_KEY_SIZE];
    uint8_t x_j[CYXWIZ_KEY_SIZE];
    uint8_t diff[CYXWIZ_KEY_SIZE];
    uint8_t temp[CYXWIZ_KEY_SIZE];

    /* Initialize numerator = 1, denominator = 1 */
    memset(numerator, 0, CYXWIZ_KEY_SIZE);
    numerator[CYXWIZ_KEY_SIZE - 1] = 1;
    memset(denominator, 0, CYXWIZ_KEY_SIZE);
    denominator[CYXWIZ_KEY_SIZE - 1] = 1;

    int_to_field(x_i, party_ids[i]);

    for (size_t j = 0; j < num_parties; j++) {
        if (j == i) continue;

        int_to_field(x_j, party_ids[j]);

        /* numerator *= x_j */
        gf256_mul(temp, numerator, x_j);
        memcpy(numerator, temp, CYXWIZ_KEY_SIZE);

        /* diff = x_i - x_j (XOR in GF(2^n)) */
        field_sub(diff, x_i, x_j);

        /* denominator *= diff */
        gf256_mul(temp, denominator, diff);
        memcpy(denominator, temp, CYXWIZ_KEY_SIZE);
    }

    /* result = numerator / denominator = numerator * denominator^(-1) */
    uint8_t denom_inv[CYXWIZ_KEY_SIZE];
    gf256_inverse(denom_inv, denominator);
    gf256_mul(out, numerator, denom_inv);
}

/*
 * Split a secret into N shares using Shamir's Secret Sharing
 *
 * Creates a random polynomial P(x) of degree (threshold - 1):
 *   P(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
 *
 * Each party i gets share = P(i) where i is the party ID (1, 2, ..., N)
 *
 * Any 'threshold' shares can reconstruct the secret using Lagrange interpolation
 * at x=0, recovering P(0) = secret.
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

    uint8_t threshold = cyxwiz_crypto_get_threshold(ctx);
    uint8_t n = cyxwiz_crypto_get_num_parties(ctx);

    /*
     * Build polynomial coefficients:
     * coeffs[0] = secret (constant term)
     * coeffs[1..threshold-1] = random values
     */
    uint8_t coeffs[CYXWIZ_MAX_PARTIES][CYXWIZ_KEY_SIZE];

    /* coeffs[0] = secret */
    memcpy(coeffs[0], secret, CYXWIZ_KEY_SIZE);

    /* Generate random coefficients for x^1 through x^(threshold-1) */
    for (uint8_t i = 1; i < threshold; i++) {
        cyxwiz_crypto_random(coeffs[i], CYXWIZ_KEY_SIZE);
    }

    /* Evaluate polynomial at each party's ID (1, 2, ..., N) */
    for (uint8_t i = 0; i < n; i++) {
        uint8_t party_id = i + 1;  /* 1-indexed */
        uint8_t x[CYXWIZ_KEY_SIZE];

        int_to_field(x, party_id);

        /* Evaluate P(party_id) */
        poly_eval(shares_out[i].value, (const uint8_t (*)[CYXWIZ_KEY_SIZE])coeffs, threshold, x);

        shares_out[i].party_id = party_id;

        /* Compute MAC for this share */
        cyxwiz_error_t err = cyxwiz_crypto_compute_mac(ctx, shares_out[i].value, shares_out[i].mac);
        if (err != CYXWIZ_OK) {
            cyxwiz_secure_zero(coeffs, sizeof(coeffs));
            return err;
        }
    }

    *num_shares = n;

    /* Zero temporary data */
    cyxwiz_secure_zero(coeffs, sizeof(coeffs));

    CYXWIZ_DEBUG("Split secret into %d shares (threshold=%d)", n, threshold);
    return CYXWIZ_OK;
}

/*
 * Reconstruct secret from shares using Lagrange interpolation
 *
 * Given shares (x_i, y_i) where y_i = P(x_i) and P(0) = secret,
 * we compute:
 *   secret = P(0) = Σ y_i * L_i(0)
 *
 * where L_i(0) is the Lagrange basis polynomial evaluated at 0.
 *
 * Only needs 'threshold' shares to reconstruct.
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
     * Lagrange interpolation to find P(0)
     * Use only the first 'threshold' shares (any subset would work)
     *
     * secret = Σ_{i=0}^{t-1} shares[i].value * L_i(0)
     */

    /* Collect party IDs for the shares we'll use */
    uint8_t party_ids[CYXWIZ_MAX_PARTIES];
    size_t use_count = (num_shares < threshold) ? num_shares : threshold;

    for (size_t i = 0; i < use_count; i++) {
        party_ids[i] = shares[i].party_id;
    }

    /* Compute secret = Σ y_i * L_i(0) */
    memset(secret_out, 0, CYXWIZ_KEY_SIZE);

    for (size_t i = 0; i < use_count; i++) {
        uint8_t lambda[CYXWIZ_KEY_SIZE];  /* Lagrange coefficient L_i(0) */
        uint8_t term[CYXWIZ_KEY_SIZE];    /* y_i * L_i(0) */

        /* Compute L_i(0) */
        lagrange_coeff(lambda, party_ids, use_count, i);

        /* term = shares[i].value * lambda */
        gf256_mul(term, shares[i].value, lambda);

        /* secret += term */
        field_add(secret_out, secret_out, term);
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
