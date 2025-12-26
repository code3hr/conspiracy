/*
 * CyxWiz Protocol - Onion Routing Implementation
 *
 * Implements layered encryption for anonymous routing:
 * - X25519 key exchange for shared secrets
 * - XChaCha20-Poly1305 for each layer
 * - Circuit management for multi-hop paths
 */

#include "cyxwiz/onion.h"
#include "cyxwiz/memory.h"
#include "cyxwiz/log.h"

#ifdef CYXWIZ_HAS_CRYPTO
#include <sodium.h>
#endif

#include <string.h>

/* Onion context structure */
struct cyxwiz_onion_ctx {
    cyxwiz_router_t *router;
    cyxwiz_node_id_t local_id;

    /* X25519 keypair */
    uint8_t secret_key[CYXWIZ_KEY_SIZE];
    uint8_t public_key[CYXWIZ_PUBKEY_SIZE];

    /* Active circuits */
    cyxwiz_circuit_t circuits[CYXWIZ_MAX_CIRCUITS];
    size_t circuit_count;

    /* Shared secrets with peers */
    cyxwiz_peer_key_t peer_keys[CYXWIZ_MAX_PEERS];
    size_t peer_key_count;

    /* Delivery callback */
    cyxwiz_delivery_callback_t callback;
    void *user_data;

    /* Next circuit ID */
    uint32_t next_circuit_id;
};

/* ============ Helper Functions ============ */

bool cyxwiz_node_id_is_zero(const cyxwiz_node_id_t *id)
{
    if (id == NULL) {
        return true;
    }
    for (size_t i = 0; i < CYXWIZ_NODE_ID_LEN; i++) {
        if (id->bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static cyxwiz_peer_key_t *find_peer_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id)
{
    for (size_t i = 0; i < ctx->peer_key_count; i++) {
        if (ctx->peer_keys[i].valid &&
            memcmp(&ctx->peer_keys[i].peer_id, peer_id, sizeof(cyxwiz_node_id_t)) == 0) {
            return &ctx->peer_keys[i];
        }
    }
    return NULL;
}

/* ============ Onion Context Lifecycle ============ */

cyxwiz_error_t cyxwiz_onion_create(
    cyxwiz_onion_ctx_t **ctx,
    cyxwiz_router_t *router,
    const cyxwiz_node_id_t *local_id)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_ERROR("Onion routing requires crypto module");
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || router == NULL || local_id == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    cyxwiz_onion_ctx_t *c = cyxwiz_calloc(1, sizeof(cyxwiz_onion_ctx_t));
    if (c == NULL) {
        return CYXWIZ_ERR_NOMEM;
    }

    c->router = router;
    memcpy(&c->local_id, local_id, sizeof(cyxwiz_node_id_t));

    /* Generate X25519 keypair */
    crypto_box_keypair(c->public_key, c->secret_key);

    c->circuit_count = 0;
    c->peer_key_count = 0;
    c->next_circuit_id = 1;
    c->callback = NULL;
    c->user_data = NULL;

    CYXWIZ_INFO("Onion routing context created");
    *ctx = c;
    return CYXWIZ_OK;
#endif
}

void cyxwiz_onion_destroy(cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Zero sensitive data */
    cyxwiz_secure_zero(ctx->secret_key, sizeof(ctx->secret_key));
    for (size_t i = 0; i < ctx->peer_key_count; i++) {
        cyxwiz_secure_zero(ctx->peer_keys[i].shared_secret,
                          sizeof(ctx->peer_keys[i].shared_secret));
    }
    for (size_t i = 0; i < ctx->circuit_count; i++) {
        cyxwiz_secure_zero(ctx->circuits[i].keys,
                          sizeof(ctx->circuits[i].keys));
    }

    cyxwiz_free(ctx, sizeof(cyxwiz_onion_ctx_t));
    CYXWIZ_INFO("Onion routing context destroyed");
}

void cyxwiz_onion_set_callback(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_delivery_callback_t callback,
    void *user_data)
{
    if (ctx == NULL) {
        return;
    }
    ctx->callback = callback;
    ctx->user_data = user_data;
}

cyxwiz_error_t cyxwiz_onion_poll(
    cyxwiz_onion_ctx_t *ctx,
    uint64_t current_time_ms)
{
    if (ctx == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Expire old circuits */
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active) {
            uint64_t age = current_time_ms - ctx->circuits[i].created_at;
            if (age > CYXWIZ_CIRCUIT_TIMEOUT_MS) {
                CYXWIZ_DEBUG("Circuit %u expired", ctx->circuits[i].circuit_id);
                cyxwiz_secure_zero(ctx->circuits[i].keys,
                                  sizeof(ctx->circuits[i].keys));
                ctx->circuits[i].active = false;
                ctx->circuit_count--;
            }
        }
    }

    return CYXWIZ_OK;
}

/* ============ Key Management ============ */

cyxwiz_error_t cyxwiz_onion_get_pubkey(
    cyxwiz_onion_ctx_t *ctx,
    uint8_t *pubkey_out)
{
    if (ctx == NULL || pubkey_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }
    memcpy(pubkey_out, ctx->public_key, CYXWIZ_PUBKEY_SIZE);
    return CYXWIZ_OK;
}

cyxwiz_error_t cyxwiz_onion_add_peer_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id,
    const uint8_t *peer_pubkey)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || peer_id == NULL || peer_pubkey == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Check if already exists */
    cyxwiz_peer_key_t *existing = find_peer_key(ctx, peer_id);
    if (existing != NULL) {
        /* Update existing */
        memcpy(existing->peer_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);

        /* Recompute shared secret */
        if (crypto_scalarmult(existing->shared_secret,
                             ctx->secret_key,
                             peer_pubkey) != 0) {
            CYXWIZ_ERROR("Failed to compute shared secret");
            return CYXWIZ_ERR_CRYPTO;
        }

        existing->established_at = cyxwiz_time_ms();
        CYXWIZ_DEBUG("Updated shared key with peer");
        return CYXWIZ_OK;
    }

    /* Find free slot */
    cyxwiz_peer_key_t *slot = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            slot = &ctx->peer_keys[i];
            break;
        }
    }

    if (slot == NULL) {
        CYXWIZ_WARN("Peer key table full");
        return CYXWIZ_ERR_QUEUE_FULL;
    }

    /* Compute X25519 shared secret */
    if (crypto_scalarmult(slot->shared_secret,
                         ctx->secret_key,
                         peer_pubkey) != 0) {
        CYXWIZ_ERROR("Failed to compute shared secret");
        return CYXWIZ_ERR_CRYPTO;
    }

    memcpy(&slot->peer_id, peer_id, sizeof(cyxwiz_node_id_t));
    memcpy(slot->peer_pubkey, peer_pubkey, CYXWIZ_PUBKEY_SIZE);
    slot->established_at = cyxwiz_time_ms();
    slot->valid = true;
    ctx->peer_key_count++;

    CYXWIZ_DEBUG("Added shared key with peer");
    return CYXWIZ_OK;
#endif
}

bool cyxwiz_onion_has_key(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *peer_id)
{
    if (ctx == NULL || peer_id == NULL) {
        return false;
    }
    return find_peer_key(ctx, peer_id) != NULL;
}

cyxwiz_error_t cyxwiz_onion_derive_hop_key(
    const uint8_t *shared_secret,
    const cyxwiz_node_id_t *sender,
    const cyxwiz_node_id_t *receiver,
    uint8_t *key_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (shared_secret == NULL || sender == NULL ||
        receiver == NULL || key_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Context: "cyxwiz_onion_v1" || sender_id || receiver_id */
    uint8_t context[15 + 32 + 32];
    memcpy(context, "cyxwiz_onion_v1", 15);
    memcpy(context + 15, sender->bytes, 32);
    memcpy(context + 47, receiver->bytes, 32);

    return cyxwiz_crypto_derive_key(shared_secret, CYXWIZ_KEY_SIZE,
                                    context, sizeof(context), key_out);
#endif
}

cyxwiz_error_t cyxwiz_onion_compute_ecdh(
    cyxwiz_onion_ctx_t *ctx,
    const uint8_t *peer_pubkey,
    uint8_t *secret_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || peer_pubkey == NULL || secret_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* X25519 scalar multiplication: shared = our_sk * peer_pk */
    if (crypto_scalarmult(secret_out, ctx->secret_key, peer_pubkey) != 0) {
        return CYXWIZ_ERR_CRYPTO;
    }

    return CYXWIZ_OK;
#endif
}

/* ============ Circuit Management ============ */

cyxwiz_error_t cyxwiz_onion_build_circuit(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *hops,
    uint8_t hop_count,
    cyxwiz_circuit_t **circuit_out)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(hops);
    CYXWIZ_UNUSED(hop_count);
    CYXWIZ_UNUSED(circuit_out);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || hops == NULL || circuit_out == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        CYXWIZ_ERROR("Invalid hop count: %u (max %u)", hop_count, CYXWIZ_MAX_ONION_HOPS);
        return CYXWIZ_ERR_INVALID;
    }

    /* Check we have peer pubkeys for all hops (needed for ephemeral ECDH) */
    for (uint8_t i = 0; i < hop_count; i++) {
        if (!cyxwiz_onion_has_key(ctx, &hops[i])) {
            CYXWIZ_ERROR("No shared key with hop %u", i);
            return CYXWIZ_ERR_NO_KEY;
        }
    }

    /* Find free circuit slot */
    cyxwiz_circuit_t *circuit = NULL;
    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (!ctx->circuits[i].active) {
            circuit = &ctx->circuits[i];
            break;
        }
    }

    if (circuit == NULL) {
        CYXWIZ_ERROR("Circuit table full");
        return CYXWIZ_ERR_CIRCUIT_FULL;
    }

    /* Initialize circuit */
    circuit->circuit_id = ctx->next_circuit_id++;
    circuit->hop_count = hop_count;
    circuit->created_at = cyxwiz_time_ms();
    circuit->active = true;

    /*
     * Generate ephemeral keypairs for each hop and derive per-hop keys.
     * Each hop will use ECDH between the ephemeral pubkey and their private key
     * to derive the layer key. This allows multi-hop routing since each hop
     * can independently derive the correct key without knowing the sender.
     */
    for (uint8_t i = 0; i < hop_count; i++) {
        memcpy(&circuit->hops[i], &hops[i], sizeof(cyxwiz_node_id_t));

        /* Get peer's public key for ECDH */
        cyxwiz_peer_key_t *peer_key = find_peer_key(ctx, &hops[i]);
        if (peer_key == NULL) {
            circuit->active = false;
            return CYXWIZ_ERR_NO_KEY;
        }

        /* Generate ephemeral X25519 keypair for this hop */
        uint8_t ephemeral_sk[CYXWIZ_KEY_SIZE];
        crypto_box_keypair(circuit->ephemeral_pubs[i], ephemeral_sk);

        /* Compute ephemeral shared secret: ephemeral_sk * peer_pubkey */
        uint8_t ephemeral_shared[CYXWIZ_KEY_SIZE];
        if (crypto_scalarmult(ephemeral_shared, ephemeral_sk, peer_key->peer_pubkey) != 0) {
            cyxwiz_secure_zero(ephemeral_sk, sizeof(ephemeral_sk));
            circuit->active = false;
            CYXWIZ_ERROR("Failed to compute ephemeral shared secret");
            return CYXWIZ_ERR_CRYPTO;
        }

        /* Derive hop key from ephemeral shared secret */
        /* Use a simple context for key derivation */
        uint8_t context[32];
        memcpy(context, "cyxwiz_eph_layer", 16);
        memcpy(context + 16, circuit->ephemeral_pubs[i], 16);

        cyxwiz_error_t err = cyxwiz_crypto_derive_key(
            ephemeral_shared, CYXWIZ_KEY_SIZE,
            context, sizeof(context),
            circuit->keys[i]);

        /* Zero sensitive ephemeral data */
        cyxwiz_secure_zero(ephemeral_sk, sizeof(ephemeral_sk));
        cyxwiz_secure_zero(ephemeral_shared, sizeof(ephemeral_shared));

        if (err != CYXWIZ_OK) {
            circuit->active = false;
            return err;
        }
    }

    ctx->circuit_count++;
    CYXWIZ_INFO("Built circuit %u with %u hops (ephemeral keys)", circuit->circuit_id, hop_count);

    *circuit_out = circuit;
    return CYXWIZ_OK;
#endif
}

void cyxwiz_onion_destroy_circuit(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit)
{
    if (ctx == NULL || circuit == NULL) {
        return;
    }

    if (circuit->active) {
        cyxwiz_secure_zero(circuit->keys, sizeof(circuit->keys));
        cyxwiz_secure_zero(circuit->ephemeral_pubs, sizeof(circuit->ephemeral_pubs));
        circuit->active = false;
        ctx->circuit_count--;
        CYXWIZ_DEBUG("Destroyed circuit %u", circuit->circuit_id);
    }
}

cyxwiz_circuit_t *cyxwiz_onion_get_circuit(
    cyxwiz_onion_ctx_t *ctx,
    uint32_t circuit_id)
{
    if (ctx == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active &&
            ctx->circuits[i].circuit_id == circuit_id) {
            return &ctx->circuits[i];
        }
    }
    return NULL;
}

/* ============ Payload Size ============ */

size_t cyxwiz_onion_max_payload(uint8_t hop_count)
{
    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        return 0;
    }

    /*
     * With ephemeral keys, the packet structure is:
     * Header: type(1) + circuit_id(4) + ephemeral(32) = 37 bytes
     * Then encrypted layers, each containing:
     *   - next_hop (32)
     *   - next_ephemeral (32) for non-final layers
     *   - AEAD overhead (40)
     *   - inner data
     * Final layer: zero_hop (32) + payload
     */
    size_t size = CYXWIZ_ONION_MAX_ENCRYPTED;

    /*
     * Each intermediate layer adds: AEAD overhead (40) + next_hop (32) + next_ephemeral (32)
     * Final layer adds: AEAD overhead (40) + zero_hop (32)
     */
    for (uint8_t i = 0; i < hop_count; i++) {
        size_t layer_overhead = CYXWIZ_ONION_OVERHEAD + CYXWIZ_NODE_ID_LEN;

        /* Non-final layers also include next_ephemeral */
        if (i < hop_count - 1) {
            layer_overhead += CYXWIZ_EPHEMERAL_SIZE;
        }

        if (size <= layer_overhead) {
            return 0;
        }
        size -= layer_overhead;
    }

    return size;
}

/* ============ Low-Level Operations ============ */

cyxwiz_error_t cyxwiz_onion_wrap(
    const uint8_t *payload,
    size_t payload_len,
    const cyxwiz_node_id_t *hops,
    const uint8_t (*keys)[CYXWIZ_KEY_SIZE],
    const uint8_t (*ephemeral_pubs)[CYXWIZ_EPHEMERAL_SIZE],
    uint8_t hop_count,
    uint8_t *onion_out,
    size_t *onion_len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(payload);
    CYXWIZ_UNUSED(payload_len);
    CYXWIZ_UNUSED(hops);
    CYXWIZ_UNUSED(keys);
    CYXWIZ_UNUSED(ephemeral_pubs);
    CYXWIZ_UNUSED(hop_count);
    CYXWIZ_UNUSED(onion_out);
    CYXWIZ_UNUSED(onion_len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (payload == NULL || hops == NULL || keys == NULL ||
        ephemeral_pubs == NULL || onion_out == NULL || onion_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (hop_count == 0 || hop_count > CYXWIZ_MAX_ONION_HOPS) {
        return CYXWIZ_ERR_INVALID;
    }

    size_t max_payload = cyxwiz_onion_max_payload(hop_count);
    if (payload_len > max_payload) {
        CYXWIZ_ERROR("Payload too large: %zu > %zu", payload_len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Use temporary buffers for building layers */
    uint8_t buffer1[CYXWIZ_ONION_MAX_ENCRYPTED];
    uint8_t buffer2[CYXWIZ_ONION_MAX_ENCRYPTED];
    uint8_t *current = buffer1;
    uint8_t *next = buffer2;
    size_t current_len;

    /*
     * Build onion from inside out.
     * Final layer: zero_hop (32) + payload
     * Each intermediate layer decrypts to: next_hop (32) + next_ephemeral (32) + inner
     */
    cyxwiz_node_id_t zero_hop;
    memset(&zero_hop, 0, sizeof(zero_hop));

    /* Innermost layer: zeros for next_hop (final destination marker) + payload */
    memcpy(current, &zero_hop, sizeof(cyxwiz_node_id_t));
    memcpy(current + sizeof(cyxwiz_node_id_t), payload, payload_len);
    current_len = sizeof(cyxwiz_node_id_t) + payload_len;

    /* Wrap from inside out (last hop first) */
    for (int i = hop_count - 1; i >= 0; i--) {
        /* Encrypt current data with this hop's key */
        size_t encrypted_len;
        cyxwiz_error_t err = cyxwiz_crypto_encrypt(
            current, current_len,
            keys[i],
            next, &encrypted_len);

        if (err != CYXWIZ_OK) {
            return err;
        }

        /* For non-outermost layers, prepend next_hop + next_ephemeral */
        if (i > 0) {
            /* Make room for next_hop + next_ephemeral */
            size_t header_size = sizeof(cyxwiz_node_id_t) + CYXWIZ_EPHEMERAL_SIZE;
            memmove(next + header_size, next, encrypted_len);

            /* next_hop: where to forward after decryption at hop i-1 */
            memcpy(next, &hops[i], sizeof(cyxwiz_node_id_t));

            /* next_ephemeral: the ephemeral key for hop i */
            memcpy(next + sizeof(cyxwiz_node_id_t), ephemeral_pubs[i], CYXWIZ_EPHEMERAL_SIZE);

            encrypted_len += header_size;
        }

        /* Swap buffers */
        uint8_t *tmp = current;
        current = next;
        next = tmp;
        current_len = encrypted_len;
    }

    memcpy(onion_out, current, current_len);
    *onion_len = current_len;

    return CYXWIZ_OK;
#endif
}

cyxwiz_error_t cyxwiz_onion_unwrap(
    const uint8_t *onion,
    size_t onion_len,
    const uint8_t *key,
    cyxwiz_node_id_t *next_hop_out,
    uint8_t *next_ephemeral_out,
    uint8_t *inner_out,
    size_t *inner_len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(onion);
    CYXWIZ_UNUSED(onion_len);
    CYXWIZ_UNUSED(key);
    CYXWIZ_UNUSED(next_hop_out);
    CYXWIZ_UNUSED(next_ephemeral_out);
    CYXWIZ_UNUSED(inner_out);
    CYXWIZ_UNUSED(inner_len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (onion == NULL || key == NULL || next_hop_out == NULL ||
        inner_out == NULL || inner_len == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (onion_len < CYXWIZ_ONION_OVERHEAD + sizeof(cyxwiz_node_id_t)) {
        CYXWIZ_ERROR("Onion too short: %zu bytes", onion_len);
        return CYXWIZ_ERR_INVALID;
    }

    /* Decrypt the layer */
    uint8_t decrypted[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t decrypted_len;

    cyxwiz_error_t err = cyxwiz_crypto_decrypt(
        onion, onion_len,
        key,
        decrypted, &decrypted_len);

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to decrypt onion layer");
        return CYXWIZ_ERR_CRYPTO;
    }

    if (decrypted_len < sizeof(cyxwiz_node_id_t)) {
        CYXWIZ_ERROR("Decrypted data too short");
        return CYXWIZ_ERR_INVALID;
    }

    /* Extract next_hop */
    memcpy(next_hop_out, decrypted, sizeof(cyxwiz_node_id_t));

    /*
     * If next_hop is non-zero (relay), the next 32 bytes are the ephemeral key
     * for the next hop. If next_hop is zero (final destination), the remaining
     * data is the payload with no ephemeral key.
     */
    size_t offset = sizeof(cyxwiz_node_id_t);

    if (!cyxwiz_node_id_is_zero(next_hop_out)) {
        /* Non-final: extract next_ephemeral */
        if (decrypted_len < sizeof(cyxwiz_node_id_t) + CYXWIZ_EPHEMERAL_SIZE) {
            CYXWIZ_ERROR("Decrypted layer missing ephemeral key");
            return CYXWIZ_ERR_INVALID;
        }

        if (next_ephemeral_out != NULL) {
            memcpy(next_ephemeral_out, decrypted + offset, CYXWIZ_EPHEMERAL_SIZE);
        }
        offset += CYXWIZ_EPHEMERAL_SIZE;
    } else {
        /* Final destination: no ephemeral key */
        if (next_ephemeral_out != NULL) {
            memset(next_ephemeral_out, 0, CYXWIZ_EPHEMERAL_SIZE);
        }
    }

    /* Rest is inner data */
    size_t inner_data_len = decrypted_len - offset;
    memcpy(inner_out, decrypted + offset, inner_data_len);
    *inner_len = inner_data_len;

    return CYXWIZ_OK;
#endif
}

/* ============ Sending Messages ============ */

cyxwiz_error_t cyxwiz_onion_send(
    cyxwiz_onion_ctx_t *ctx,
    cyxwiz_circuit_t *circuit,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(circuit);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || circuit == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    if (!circuit->active) {
        CYXWIZ_ERROR("Circuit not active");
        return CYXWIZ_ERR_INVALID;
    }

    size_t max_payload = cyxwiz_onion_max_payload(circuit->hop_count);
    if (len > max_payload) {
        CYXWIZ_ERROR("Payload too large for circuit: %zu > %zu", len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Build onion with ephemeral keys */
    uint8_t onion[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t onion_len;

    cyxwiz_error_t err = cyxwiz_onion_wrap(
        data, len,
        circuit->hops,
        (const uint8_t (*)[CYXWIZ_KEY_SIZE])circuit->keys,
        (const uint8_t (*)[CYXWIZ_EPHEMERAL_SIZE])circuit->ephemeral_pubs,
        circuit->hop_count,
        onion, &onion_len);

    if (err != CYXWIZ_OK) {
        return err;
    }

    /*
     * Build packet: type (1) + circuit_id (4) + ephemeral_pub (32) + onion
     * The ephemeral_pub for the first hop is included in the header so the
     * first relay can derive the decryption key via ECDH.
     */
    uint8_t packet[CYXWIZ_MAX_PACKET_SIZE];
    size_t packet_len = 0;

    packet[0] = CYXWIZ_MSG_ONION_DATA;
    packet_len = 1;

    /* Circuit ID (big-endian) */
    packet[packet_len++] = (circuit->circuit_id >> 24) & 0xFF;
    packet[packet_len++] = (circuit->circuit_id >> 16) & 0xFF;
    packet[packet_len++] = (circuit->circuit_id >> 8) & 0xFF;
    packet[packet_len++] = circuit->circuit_id & 0xFF;

    /* Ephemeral public key for first hop */
    memcpy(packet + packet_len, circuit->ephemeral_pubs[0], CYXWIZ_EPHEMERAL_SIZE);
    packet_len += CYXWIZ_EPHEMERAL_SIZE;

    /* Encrypted onion data */
    memcpy(packet + packet_len, onion, onion_len);
    packet_len += onion_len;

    /* Send to first hop */
    return cyxwiz_router_send(ctx->router, &circuit->hops[0], packet, packet_len);
#endif
}

/* ============ Message Handling ============ */

cyxwiz_error_t cyxwiz_onion_handle_message(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *from,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(from);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || from == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Header: type (1) + circuit_id (4) + ephemeral_pub (32) = 37 bytes */
    if (len < CYXWIZ_ONION_HEADER_SIZE) {
        CYXWIZ_ERROR("Onion packet too short: %zu < %d", len, CYXWIZ_ONION_HEADER_SIZE);
        return CYXWIZ_ERR_INVALID;
    }

    /* Parse header */
    if (data[0] != CYXWIZ_MSG_ONION_DATA) {
        return CYXWIZ_ERR_INVALID;
    }

    uint32_t circuit_id = ((uint32_t)data[1] << 24) |
                          ((uint32_t)data[2] << 16) |
                          ((uint32_t)data[3] << 8) |
                          (uint32_t)data[4];

    /* Extract ephemeral public key from header */
    const uint8_t *ephemeral_pub = data + 5;

    const uint8_t *onion = data + CYXWIZ_ONION_HEADER_SIZE;
    size_t onion_len = len - CYXWIZ_ONION_HEADER_SIZE;

    /*
     * Derive layer key using ECDH with the ephemeral public key.
     * shared_secret = my_private_key * ephemeral_pub
     * This allows any hop to decrypt without knowing the original sender.
     */
    uint8_t ephemeral_shared[CYXWIZ_KEY_SIZE];
    if (crypto_scalarmult(ephemeral_shared, ctx->secret_key, ephemeral_pub) != 0) {
        CYXWIZ_ERROR("Failed to compute ECDH with ephemeral key");
        return CYXWIZ_ERR_CRYPTO;
    }

    /* Derive hop key from ephemeral shared secret */
    uint8_t hop_key[CYXWIZ_KEY_SIZE];
    uint8_t context[32];
    memcpy(context, "cyxwiz_eph_layer", 16);
    memcpy(context + 16, ephemeral_pub, 16);

    cyxwiz_error_t err = cyxwiz_crypto_derive_key(
        ephemeral_shared, CYXWIZ_KEY_SIZE,
        context, sizeof(context),
        hop_key);

    cyxwiz_secure_zero(ephemeral_shared, sizeof(ephemeral_shared));

    if (err != CYXWIZ_OK) {
        return err;
    }

    /* Unwrap one layer */
    cyxwiz_node_id_t next_hop;
    uint8_t next_ephemeral[CYXWIZ_EPHEMERAL_SIZE];
    uint8_t inner[CYXWIZ_ONION_MAX_ENCRYPTED];
    size_t inner_len;

    err = cyxwiz_onion_unwrap(onion, onion_len, hop_key,
                              &next_hop, next_ephemeral, inner, &inner_len);

    cyxwiz_secure_zero(hop_key, sizeof(hop_key));

    if (err != CYXWIZ_OK) {
        CYXWIZ_ERROR("Failed to unwrap onion layer");
        return err;
    }

    /* Check if this is the final destination */
    if (cyxwiz_node_id_is_zero(&next_hop)) {
        /* Deliver to application */
        CYXWIZ_DEBUG("Onion reached destination, delivering %zu bytes", inner_len);

        if (ctx->callback != NULL) {
            /* Note: 'from' is the immediate sender, not the original sender
             * (which is hidden by the onion routing) */
            ctx->callback(from, inner, inner_len, ctx->user_data);
        }
    } else {
        /* Forward to next hop */
        CYXWIZ_DEBUG("Forwarding onion to next hop");

        /*
         * Build new packet with the next_ephemeral in the header
         * and the inner data as the encrypted payload.
         */
        uint8_t forward_packet[CYXWIZ_MAX_PACKET_SIZE];
        size_t forward_len = 0;

        forward_packet[0] = CYXWIZ_MSG_ONION_DATA;
        forward_len = 1;

        /* Keep same circuit ID */
        forward_packet[forward_len++] = (circuit_id >> 24) & 0xFF;
        forward_packet[forward_len++] = (circuit_id >> 16) & 0xFF;
        forward_packet[forward_len++] = (circuit_id >> 8) & 0xFF;
        forward_packet[forward_len++] = circuit_id & 0xFF;

        /* Include the next_ephemeral in the forwarded packet header */
        memcpy(forward_packet + forward_len, next_ephemeral, CYXWIZ_EPHEMERAL_SIZE);
        forward_len += CYXWIZ_EPHEMERAL_SIZE;

        /* Inner encrypted data */
        memcpy(forward_packet + forward_len, inner, inner_len);
        forward_len += inner_len;

        return cyxwiz_router_send(ctx->router, &next_hop, forward_packet, forward_len);
    }

    return CYXWIZ_OK;
#endif
}

/* ============ Send To Destination ============ */

/*
 * Find circuit that routes to destination
 */
cyxwiz_circuit_t *cyxwiz_onion_find_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    if (ctx == NULL || destination == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < CYXWIZ_MAX_CIRCUITS; i++) {
        if (ctx->circuits[i].active && ctx->circuits[i].hop_count > 0) {
            /* Last hop is the destination */
            const cyxwiz_node_id_t *last_hop =
                &ctx->circuits[i].hops[ctx->circuits[i].hop_count - 1];
            if (memcmp(last_hop, destination, sizeof(cyxwiz_node_id_t)) == 0) {
                return &ctx->circuits[i];
            }
        }
    }
    return NULL;
}

/*
 * Check if circuit exists to destination
 */
bool cyxwiz_onion_has_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination)
{
    return cyxwiz_onion_find_circuit_to(ctx, destination) != NULL;
}

/*
 * Select random relay nodes for circuit building
 * Excludes destination from relay selection
 */
static size_t select_random_relays(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    cyxwiz_node_id_t *relays_out,
    size_t max_relays)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(destination);
    CYXWIZ_UNUSED(relays_out);
    CYXWIZ_UNUSED(max_relays);
    return 0;
#else
    /* Collect all valid peer keys (potential relays) */
    cyxwiz_node_id_t candidates[CYXWIZ_MAX_PEERS];
    size_t candidate_count = 0;

    for (size_t i = 0; i < CYXWIZ_MAX_PEERS && candidate_count < CYXWIZ_MAX_PEERS; i++) {
        if (!ctx->peer_keys[i].valid) {
            continue;
        }

        /* Don't use destination as relay */
        if (memcmp(&ctx->peer_keys[i].peer_id, destination,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        /* Don't use self as relay */
        if (memcmp(&ctx->peer_keys[i].peer_id, &ctx->local_id,
                   sizeof(cyxwiz_node_id_t)) == 0) {
            continue;
        }

        memcpy(&candidates[candidate_count], &ctx->peer_keys[i].peer_id,
               sizeof(cyxwiz_node_id_t));
        candidate_count++;
    }

    if (candidate_count == 0) {
        return 0;
    }

    /* Shuffle candidates using Fisher-Yates */
    for (size_t i = candidate_count - 1; i > 0; i--) {
        uint32_t j;
        randombytes_buf(&j, sizeof(j));
        j = j % (i + 1);

        cyxwiz_node_id_t tmp;
        memcpy(&tmp, &candidates[i], sizeof(cyxwiz_node_id_t));
        memcpy(&candidates[i], &candidates[j], sizeof(cyxwiz_node_id_t));
        memcpy(&candidates[j], &tmp, sizeof(cyxwiz_node_id_t));
    }

    /* Take up to max_relays */
    size_t count = (candidate_count < max_relays) ? candidate_count : max_relays;
    for (size_t i = 0; i < count; i++) {
        memcpy(&relays_out[i], &candidates[i], sizeof(cyxwiz_node_id_t));
    }

    return count;
#endif
}

/*
 * Build circuit to destination with automatic relay selection
 */
static cyxwiz_error_t build_circuit_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    cyxwiz_circuit_t **circuit_out)
{
    /* Check if we have a key with the destination */
    if (!cyxwiz_onion_has_key(ctx, destination)) {
        char hex_id[65];
        cyxwiz_node_id_to_hex(destination, hex_id);
        CYXWIZ_WARN("No shared key with destination %.16s...", hex_id);
        return CYXWIZ_ERR_NO_KEY;
    }

    /* Select relay nodes (prefer 1 relay for better payload capacity) */
    cyxwiz_node_id_t relays[CYXWIZ_MAX_ONION_HOPS - 1];
    size_t relay_count = select_random_relays(ctx, destination, relays, 1);

    /* Build path: [relay(s)...] + destination */
    cyxwiz_node_id_t path[CYXWIZ_MAX_ONION_HOPS];
    uint8_t hop_count = 0;

    /* Add relays to path */
    for (size_t i = 0; i < relay_count; i++) {
        memcpy(&path[hop_count++], &relays[i], sizeof(cyxwiz_node_id_t));
    }

    /* Add destination as final hop */
    memcpy(&path[hop_count++], destination, sizeof(cyxwiz_node_id_t));

    CYXWIZ_DEBUG("Building %u-hop circuit to destination", hop_count);

    return cyxwiz_onion_build_circuit(ctx, path, hop_count, circuit_out);
}

/*
 * Send data to destination via onion routing
 * Automatically builds circuit if needed
 */
cyxwiz_error_t cyxwiz_onion_send_to(
    cyxwiz_onion_ctx_t *ctx,
    const cyxwiz_node_id_t *destination,
    const uint8_t *data,
    size_t len)
{
#ifndef CYXWIZ_HAS_CRYPTO
    CYXWIZ_UNUSED(ctx);
    CYXWIZ_UNUSED(destination);
    CYXWIZ_UNUSED(data);
    CYXWIZ_UNUSED(len);
    return CYXWIZ_ERR_NOT_INITIALIZED;
#else
    if (ctx == NULL || destination == NULL || data == NULL) {
        return CYXWIZ_ERR_INVALID;
    }

    /* Find existing circuit to destination */
    cyxwiz_circuit_t *circuit = cyxwiz_onion_find_circuit_to(ctx, destination);

    /* Build new circuit if none exists */
    if (circuit == NULL) {
        cyxwiz_error_t err = build_circuit_to(ctx, destination, &circuit);
        if (err != CYXWIZ_OK) {
            return err;
        }
    }

    /* Check payload size */
    size_t max_payload = cyxwiz_onion_max_payload(circuit->hop_count);
    if (len > max_payload) {
        CYXWIZ_WARN("Payload too large for %u-hop circuit: %zu > %zu",
                    circuit->hop_count, len, max_payload);
        return CYXWIZ_ERR_PACKET_TOO_LARGE;
    }

    /* Send via the circuit */
    return cyxwiz_onion_send(ctx, circuit, data, len);
#endif
}

/* ============ Statistics ============ */

size_t cyxwiz_onion_circuit_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->circuit_count;
}

size_t cyxwiz_onion_peer_key_count(const cyxwiz_onion_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->peer_key_count;
}
