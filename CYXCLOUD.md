# CyxCloud Design Document

## Philosophy

```
"Own Nothing. Access Everything. Leave No Trace."
              │
              ▼
    ┌─────────────────┐
    │    CyxCloud     │
    │                 │
    │  Your data,     │
    │  everywhere     │
    │  and nowhere.   │
    │                 │
    │  Encrypted.     │
    │  Distributed.   │
    │  Yours.         │
    └─────────────────┘
```

CyxCloud is the distributed storage layer of the CyxWiz ecosystem. Data is encrypted, split across multiple nodes using threshold cryptography (K-of-N), and only the owner can reconstruct it.

## Overview

### Traditional Cloud vs CyxCloud

```
┌─────────────────────────────────────────────────────────────────────┐
│              Traditional Cloud vs CyxCloud                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Traditional (AWS S3, Google Drive):                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  User ──► Upload ──► Single Provider ──► Stored on THEIR    │   │
│  │                                          servers             │   │
│  │                                                              │   │
│  │  Problems:                                                   │   │
│  │  • Provider can read your data                              │   │
│  │  • Provider can be subpoenaed                               │   │
│  │  • Single point of failure                                  │   │
│  │  • Account can be banned                                    │   │
│  │  • Requires identity/payment info                           │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  CyxCloud:                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  User ──► Encrypt ──► Split (K-of-N) ──► Distribute across  │   │
│  │           locally      shares             many nodes         │   │
│  │                                                              │   │
│  │  Properties:                                                 │   │
│  │  • NO ONE can read your data (you hold the key)             │   │
│  │  • NO single node has complete data                         │   │
│  │  • Survives N-K node failures                               │   │
│  │  • No account, no identity                                  │   │
│  │  • Pay with anonymous tokens                                │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Architecture

### K-of-N Threshold Storage

```
┌─────────────────────────────────────────────────────────────────────┐
│                   K-of-N Threshold Storage                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Example: 3-of-5 (need any 3 of 5 shares to reconstruct)           │
│                                                                      │
│  ┌─────────────┐                                                    │
│  │  Original   │                                                    │
│  │    Data     │                                                    │
│  │  "Hello"    │                                                    │
│  └──────┬──────┘                                                    │
│         │                                                            │
│         ▼ Encrypt with user's key                                   │
│  ┌─────────────┐                                                    │
│  │  Encrypted  │                                                    │
│  │ "x8f2a..."  │                                                    │
│  └──────┬──────┘                                                    │
│         │                                                            │
│         ▼ Shamir Secret Sharing (split into 5 shares)               │
│         │                                                            │
│    ┌────┼────┬────┬────┬────┐                                      │
│    ▼    ▼    ▼    ▼    ▼    ▼                                      │
│  ┌───┐┌───┐┌───┐┌───┐┌───┐                                        │
│  │ S1││ S2││ S3││ S4││ S5│  (5 shares)                            │
│  └─┬─┘└─┬─┘└─┬─┘└─┬─┘└─┬─┘                                        │
│    │    │    │    │    │                                            │
│    ▼    ▼    ▼    ▼    ▼                                            │
│  ┌───┐┌───┐┌───┐┌───┐┌───┐                                        │
│  │N1 ││N2 ││N3 ││N4 ││N5 │  (5 different storage nodes)           │
│  └───┘└───┘└───┘└───┘└───┘                                        │
│                                                                      │
│  To retrieve: Contact any 3 nodes, combine shares, decrypt         │
│                                                                      │
│  Security Properties:                                               │
│  • Any 2 shares reveal NOTHING (information-theoretic security)    │
│  • Need 3+ shares to reconstruct                                   │
│  • Any 2 nodes can fail, data still available                      │
│  • No single node has meaningful data                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Store Data Flow                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  User                              Network                          │
│    │                                  │                              │
│    │ 1. Generate encryption key       │                              │
│    │    (or use existing)             │                              │
│    │                                  │                              │
│    │ 2. Encrypt data locally          │                              │
│    │    AES-256-GCM(data, key)        │                              │
│    │                                  │                              │
│    │ 3. Split into K-of-N shares      │                              │
│    │    Shamir(ciphertext, K, N)      │                              │
│    │                                  │                              │
│    │ 4. Select N storage providers    │                              │
│    │    (based on reputation, price)  │                              │
│    │───────────────────────────────────►                            │
│    │                                  │                              │
│    │ 5. Send share[i] to provider[i]  │                              │
│    │    (via onion routing)           │                              │
│    │───────────────────────────────────►                            │
│    │                                  │                              │
│    │ 6. Providers store + return proof│                              │
│    │◄───────────────────────────────────                            │
│    │                                  │                              │
│    │ 7. User stores:                  │                              │
│    │    - Storage ID (hash)           │                              │
│    │    - Encryption key              │                              │
│    │    - Provider list               │                              │
│    │    - Share indices               │                              │
│    │                                  │                              │
│    │ Result: Only user can retrieve   │                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     Retrieve Data Flow                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  User                              Network                          │
│    │                                  │                              │
│    │ 1. Look up storage ID            │                              │
│    │    (get provider list)           │                              │
│    │                                  │                              │
│    │ 2. Contact K providers           │                              │
│    │    (minimum needed)              │                              │
│    │───────────────────────────────────►                            │
│    │                                  │                              │
│    │ 3. Request shares                │                              │
│    │    (with proof of ownership)     │                              │
│    │───────────────────────────────────►                            │
│    │                                  │                              │
│    │ 4. Receive K shares              │                              │
│    │◄───────────────────────────────────                            │
│    │                                  │                              │
│    │ 5. Reconstruct ciphertext        │                              │
│    │    Shamir_combine(shares)        │                              │
│    │                                  │                              │
│    │ 6. Decrypt with key              │                              │
│    │    AES_decrypt(ciphertext, key)  │                              │
│    │                                  │                              │
│    │ Result: Original data recovered  │                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### Storage Metadata

```c
// Storage configuration
typedef struct {
    uint8_t k;                  // Minimum shares needed
    uint8_t n;                  // Total shares created
    uint64_t ttl_seconds;       // Time to live (0 = forever*)
    uint64_t max_size;          // Maximum data size
} cyxcloud_config_t;

// Default: 3-of-5, 30 days TTL
#define CYXCLOUD_DEFAULT_K 3
#define CYXCLOUD_DEFAULT_N 5
#define CYXCLOUD_DEFAULT_TTL (30 * 24 * 3600)

// Storage entry (user keeps this)
typedef struct {
    uint8_t storage_id[16];     // Unique storage identifier
    uint8_t encryption_key[32]; // AES-256 key (USER MUST BACKUP)
    uint8_t data_hash[32];      // SHA256 of original data
    uint64_t size;              // Original data size
    uint64_t created_at;        // Unix timestamp
    uint64_t expires_at;        // Expiration timestamp

    cyxcloud_config_t config;   // K-of-N configuration

    // Provider information
    struct {
        cyxwiz_node_id_t node_id;
        uint8_t share_index;    // Which share (1 to N)
        uint8_t share_hash[32]; // Hash of share for verification
    } providers[16];            // Max N=16
    uint8_t provider_count;
} cyxcloud_storage_t;

// Share (stored by providers)
typedef struct {
    uint8_t storage_id[16];     // Links to storage entry
    uint8_t share_index;        // Which share (1 to N)
    uint8_t share_hash[32];     // SHA256 of share data
    uint64_t size;              // Share size
    uint64_t expires_at;        // When to delete
    uint8_t owner_pubkey[32];   // Who can retrieve (for ACL)
} cyxcloud_share_meta_t;
```

### API Functions

```c
// Create storage context
cyxcloud_ctx_t* cyxcloud_create(cyxwiz_ctx_t* cyxwiz,
                                 cyxcloud_config_t* config);
void cyxcloud_destroy(cyxcloud_ctx_t* ctx);

// Store data
int cyxcloud_store(cyxcloud_ctx_t* ctx,
                    const uint8_t* data,
                    size_t len,
                    cyxcloud_storage_t* storage);

// Retrieve data
int cyxcloud_retrieve(cyxcloud_ctx_t* ctx,
                       const cyxcloud_storage_t* storage,
                       uint8_t* data,
                       size_t* len);

// Delete data (request providers to delete)
int cyxcloud_delete(cyxcloud_ctx_t* ctx,
                     const cyxcloud_storage_t* storage);

// Extend TTL (pay more)
int cyxcloud_extend(cyxcloud_ctx_t* ctx,
                     cyxcloud_storage_t* storage,
                     uint64_t additional_seconds);

// Check availability (verify K+ providers online)
int cyxcloud_check(cyxcloud_ctx_t* ctx,
                    const cyxcloud_storage_t* storage,
                    uint8_t* available_count);

// Repair (re-distribute if providers went offline)
int cyxcloud_repair(cyxcloud_ctx_t* ctx,
                     cyxcloud_storage_t* storage);
```

## Provider System

### Becoming a Storage Provider

```
┌─────────────────────────────────────────────────────────────────────┐
│                  Storage Provider Requirements                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  To become a storage provider:                                      │
│                                                                      │
│  1. Stake minimum CYX (500 CYX)                                     │
│     └─ Collateral for data availability                             │
│                                                                      │
│  2. Declare storage capacity                                        │
│     └─ How much space you're offering                               │
│                                                                      │
│  3. Set pricing                                                     │
│     └─ CYX per GB per day                                           │
│                                                                      │
│  4. Maintain uptime                                                 │
│     └─ Respond to availability proofs                               │
│                                                                      │
│  Provider Configuration:                                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  provider:                                                   │   │
│  │    enabled: true                                             │   │
│  │    capacity: 100GB                                           │   │
│  │    price_per_gb_day: 0.5 CYX                                │   │
│  │    min_ttl: 1 day                                            │   │
│  │    max_ttl: 365 days                                         │   │
│  │    storage_path: /var/cyxcloud/                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Availability Proofs

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Proof of Storage                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Challenge: How do we know providers actually store the data?       │
│                                                                      │
│  Solution: Periodic availability challenges                         │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Validator           Provider                                │   │
│  │     │                   │                                    │   │
│  │     │ Challenge:        │                                    │   │
│  │     │ "Prove you have   │                                    │   │
│  │     │  storage_id X"    │                                    │   │
│  │     │──────────────────►│                                    │   │
│  │     │                   │                                    │   │
│  │     │                   │ Compute:                           │   │
│  │     │                   │ H(share || nonce)                  │   │
│  │     │                   │                                    │   │
│  │     │ Response:         │                                    │   │
│  │     │ hash + proof      │                                    │   │
│  │     │◄──────────────────│                                    │   │
│  │     │                   │                                    │   │
│  │     │ Verify against    │                                    │   │
│  │     │ known share_hash  │                                    │   │
│  │     │                   │                                    │   │
│  │  If valid: Provider keeps earning                            │   │
│  │  If invalid: Provider slashed                                │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Challenge frequency: Random, ~1 per hour per storage              │
│  Grace period: 60 seconds to respond                               │
│  Failure penalty: Warning → Reduced reputation → Slashing          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Provider Data Structures

```c
// Provider configuration
typedef struct {
    bool enabled;
    uint64_t capacity_bytes;        // Total space offered
    uint64_t used_bytes;            // Currently used
    uint64_t price_per_gb_day;      // In CYX smallest unit
    uint32_t min_ttl_hours;         // Minimum storage duration
    uint32_t max_ttl_hours;         // Maximum storage duration
    char storage_path[256];         // Where to store shares
} cyxcloud_provider_config_t;

// Provider statistics
typedef struct {
    uint64_t total_stored;          // Total bytes stored
    uint64_t total_served;          // Total bytes served
    uint32_t active_shares;         // Number of shares held
    uint32_t challenges_passed;     // Successful proofs
    uint32_t challenges_failed;     // Failed proofs
    uint8_t reputation;             // 0-100 score
} cyxcloud_provider_stats_t;

// Provider operations
int cyxcloud_provider_init(cyxcloud_provider_config_t* config);
int cyxcloud_provider_handle_store(const uint8_t* share_data,
                                    size_t len,
                                    cyxcloud_share_meta_t* meta);
int cyxcloud_provider_handle_retrieve(const uint8_t* storage_id,
                                       uint8_t* share_data,
                                       size_t* len);
int cyxcloud_provider_handle_challenge(const uint8_t* storage_id,
                                        const uint8_t* nonce,
                                        uint8_t* proof);
```

## Encryption Details

### Key Management

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Key Management                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Option 1: Per-Storage Key (Default)                                │
│  ───────────────────────────────────                                │
│  • Generate random 256-bit key for each storage                    │
│  • Key stored locally with storage metadata                        │
│  • Maximum security (compromise one key ≠ compromise all)          │
│                                                                      │
│  Option 2: Derived from Master Key                                  │
│  ─────────────────────────────────                                  │
│  • User has master key (from wallet seed)                          │
│  • Storage keys derived: key = HKDF(master, storage_id)            │
│  • Can recover all keys from master                                │
│  • Less secure (master compromise = all compromised)               │
│                                                                      │
│  Option 3: Shared Access Keys                                       │
│  ────────────────────────────                                       │
│  • Encrypt to multiple recipients' public keys                     │
│  • Each recipient can decrypt with their private key               │
│  • Useful for sharing files                                        │
│                                                                      │
│  Key Derivation (Option 2):                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  master_key = wallet_seed                                    │   │
│  │  storage_key = HKDF-SHA256(                                  │   │
│  │      ikm = master_key,                                       │   │
│  │      salt = storage_id,                                      │   │
│  │      info = "cyxcloud-storage-key"                           │   │
│  │  )                                                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Encryption Algorithm

```c
// Encryption parameters
#define CYXCLOUD_KEY_SIZE 32        // AES-256
#define CYXCLOUD_NONCE_SIZE 12      // GCM nonce
#define CYXCLOUD_TAG_SIZE 16        // GCM auth tag

// Encrypt data
int cyxcloud_encrypt(const uint8_t* plaintext, size_t pt_len,
                      const uint8_t* key,
                      uint8_t* ciphertext, size_t* ct_len) {
    // Generate random nonce
    uint8_t nonce[CYXCLOUD_NONCE_SIZE];
    randombytes_buf(nonce, sizeof(nonce));

    // Encrypt with AES-256-GCM
    // Output format: [nonce (12)][ciphertext][tag (16)]
    memcpy(ciphertext, nonce, CYXCLOUD_NONCE_SIZE);

    crypto_aead_aes256gcm_encrypt(
        ciphertext + CYXCLOUD_NONCE_SIZE,  // ciphertext output
        NULL,                               // ciphertext length (optional)
        plaintext, pt_len,                  // plaintext
        NULL, 0,                            // additional data
        NULL,                               // nsec (unused)
        nonce, key
    );

    *ct_len = CYXCLOUD_NONCE_SIZE + pt_len + CYXCLOUD_TAG_SIZE;
    return 0;
}

// Decrypt data
int cyxcloud_decrypt(const uint8_t* ciphertext, size_t ct_len,
                      const uint8_t* key,
                      uint8_t* plaintext, size_t* pt_len) {
    // Extract nonce
    const uint8_t* nonce = ciphertext;
    const uint8_t* ct = ciphertext + CYXCLOUD_NONCE_SIZE;
    size_t ct_only_len = ct_len - CYXCLOUD_NONCE_SIZE;

    // Decrypt with AES-256-GCM
    if (crypto_aead_aes256gcm_decrypt(
            plaintext, NULL,
            NULL,  // nsec
            ct, ct_only_len,
            NULL, 0,  // additional data
            nonce, key) != 0) {
        return -1;  // Authentication failed
    }

    *pt_len = ct_only_len - CYXCLOUD_TAG_SIZE;
    return 0;
}
```

## Shamir Secret Sharing

### Implementation

```c
// Shamir configuration
typedef struct {
    uint8_t k;          // Threshold
    uint8_t n;          // Total shares
} shamir_config_t;

// Share structure
typedef struct {
    uint8_t index;      // Share index (1 to N)
    uint8_t* data;      // Share data
    size_t len;         // Share length (same as secret)
} shamir_share_t;

// Split secret into shares
int shamir_split(const uint8_t* secret, size_t secret_len,
                  shamir_config_t* config,
                  shamir_share_t* shares) {
    // For each byte of the secret:
    // 1. Generate random polynomial of degree K-1
    // 2. Evaluate at points 1, 2, ..., N
    // 3. Each evaluation becomes a share

    for (size_t byte = 0; byte < secret_len; byte++) {
        // Polynomial: f(x) = secret[byte] + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        uint8_t coeffs[config->k];
        coeffs[0] = secret[byte];
        for (int i = 1; i < config->k; i++) {
            randombytes_buf(&coeffs[i], 1);
        }

        // Evaluate at each point
        for (int i = 0; i < config->n; i++) {
            shares[i].index = i + 1;
            shares[i].data[byte] = evaluate_polynomial(coeffs, config->k, i + 1);
        }
    }

    return 0;
}

// Combine shares to recover secret
int shamir_combine(shamir_share_t* shares, uint8_t share_count,
                    uint8_t* secret, size_t secret_len) {
    // Lagrange interpolation to recover f(0) = secret
    for (size_t byte = 0; byte < secret_len; byte++) {
        secret[byte] = lagrange_interpolate(shares, share_count, byte, 0);
    }
    return 0;
}
```

## Integration with CyxHost

### Ephemeral State Backup

```
┌─────────────────────────────────────────────────────────────────────┐
│              CyxHost + CyxCloud Integration                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Use Case: User wants to save container state between sessions      │
│                                                                      │
│  Session 1:                                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  1. User rents container for 1 hour                         │   │
│  │  2. Works on application, generates data                    │   │
│  │  3. Before session ends:                                    │   │
│  │     - Export data: tar -czf backup.tar.gz /app/data         │   │
│  │     - Upload to CyxCloud: cyxcloud store backup.tar.gz      │   │
│  │     - Save storage ID + key locally                         │   │
│  │  4. Session ends, container wiped                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Session 2:                                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  1. User rents NEW container                                │   │
│  │  2. Download from CyxCloud: cyxcloud retrieve <storage_id>  │   │
│  │  3. Extract: tar -xzf backup.tar.gz -C /app/data            │   │
│  │  4. Continue working where left off                         │   │
│  │  5. Repeat backup before session ends                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Security:                                                          │
│  • Host NEVER sees unencrypted data                                │
│  • CyxCloud providers NEVER see unencrypted data                   │
│  • Only user (with key) can access                                 │
│  • Container remains ephemeral                                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## CLI Commands

```bash
# Store data
cyxcloud store myfile.txt
# Output:
# Encrypting... done
# Splitting into 5 shares (3 required)...
# Selecting providers...
# Uploading shares...
#   Provider a3f8c2... [##########] 100%
#   Provider b7e2d1... [##########] 100%
#   Provider c4a9f8... [##########] 100%
#   Provider d5f6a2... [##########] 100%
#   Provider e3b7c9... [##########] 100%
#
# Stored successfully!
# Storage ID: abc123def456
# Encryption Key: 7f9a3b2c... (SAVE THIS!)
# Expires: 2026-01-29 (30 days)
# Cost: 2.5 CYX

# Retrieve data
cyxcloud retrieve abc123def456 --key 7f9a3b2c... --output myfile.txt
# Output:
# Fetching shares...
#   Provider a3f8c2... [##########] 100%
#   Provider b7e2d1... [##########] 100%
#   Provider c4a9f8... [##########] 100%
# Reconstructing...
# Decrypting...
# Saved to myfile.txt

# Check status
cyxcloud status abc123def456
# Output:
# Storage ID: abc123def456
# Size: 1.2 MB (original), 1.5 MB (encrypted)
# Shares: 5 total, 5 available
# Expires: 2026-01-29 (28 days remaining)
# Providers:
#   a3f8c2... [ONLINE]  Share 1
#   b7e2d1... [ONLINE]  Share 2
#   c4a9f8... [ONLINE]  Share 3
#   d5f6a2... [OFFLINE] Share 4  ⚠️
#   e3b7c9... [ONLINE]  Share 5
# Health: GOOD (4/5 online, need 3)

# Extend storage
cyxcloud extend abc123def456 --days 30
# Output:
# Extending storage by 30 days...
# Cost: 2.5 CYX
# New expiration: 2026-02-28
# Confirmed.

# Delete storage
cyxcloud delete abc123def456
# Output:
# Requesting deletion from all providers...
# Deletion requested. Data will be purged within 24 hours.

# List stored items
cyxcloud list
# Output:
# Storage ID        Size    Expires      Health
# abc123def456      1.2 MB  28 days      GOOD (5/5)
# def789ghi012      500 KB  14 days      WARN (3/5)
# jkl345mno678      50 MB   2 days       GOOD (5/5)
```

## Implementation Files

```
include/cyxwiz/
├── cyxcloud.h          # Main CyxCloud header
├── cyxcloud_crypto.h   # Encryption functions
├── cyxcloud_shamir.h   # Secret sharing
└── cyxcloud_provider.h # Provider API

src/storage/
├── storage.c           # Core storage logic
├── crypto.c            # AES-GCM encryption
├── shamir.c            # Shamir implementation
├── provider.c          # Provider daemon
└── client.c            # Client operations

tools/
└── cyxcloud.c          # CLI tool
```

## Open Questions

1. **Redundancy Cost**: 3-of-5 means 67% storage overhead. Acceptable?
   - Alternative: 3-of-4 (33% overhead) but less redundancy

2. **Large Files**: How to handle multi-GB files efficiently?
   - Chunk into smaller pieces?
   - Stream encryption?

3. **Provider Selection**: How to choose which N providers?
   - Geographic distribution?
   - Network latency?
   - Price optimization?

4. **Versioning**: Should we support file versions?
   - Each update is new storage (simple)
   - Or version chain (complex, more features)

5. **Deduplication**: If same data stored twice, share providers?
   - Privacy implications (reveals you have same data)
   - Cost savings significant

---

## Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Data Theft | Provider reads user data | Critical |
| Data Loss | Shares unavailable | High |
| Integrity | Corrupted/modified shares | High |
| Privacy | Link data to identity | High |
| Economic | Provider refuses service after payment | Medium |

### Detailed Threat Analysis

#### Provider Data Theft
- **Description**: Storage provider tries to read stored data
- **Attacker**: Malicious or compromised provider
- **Prerequisites**: Provider has share
- **Impact**: None (single share reveals nothing)
- **Likelihood**: Attempted (by design, no impact)
- **Mitigation**:
  - Data encrypted before splitting
  - K-of-N shares required (any K-1 reveals nothing)
  - Information-theoretic security of Shamir's scheme

#### Share Corruption
- **Description**: Provider returns modified/corrupted share
- **Attacker**: Malicious provider, storage failure
- **Prerequisites**: Provider has share
- **Impact**: Failed reconstruction
- **Likelihood**: Low (detected, recoverable)
- **Mitigation**:
  - Share hashes stored in metadata
  - Verify hash before using share
  - Retrieve from alternate providers if mismatch
  - Provider slashed for invalid share

#### Provider Collusion
- **Description**: K or more providers collude to reconstruct data
- **Attacker**: Coordinated providers
- **Prerequisites**: Control of K providers storing same data
- **Impact**: Data decryption (if they also have key... which they don't)
- **Likelihood**: Very low (key never leaves user)
- **Mitigation**:
  - Even with K shares, need encryption key
  - Key never sent to network
  - Select providers with geographic/ownership diversity

#### Eclipse Attack on Storage
- **Description**: Attacker controls all providers user can reach
- **Attacker**: Network-level adversary
- **Prerequisites**: Control routing to user
- **Impact**: Data unavailability, potential different data served
- **Likelihood**: Low (mesh network hard to eclipse)
- **Mitigation**:
  - Multiple diverse providers
  - Onion routing for retrieval
  - Verify share hashes

### Security Assumptions
1. AES-256-GCM is secure
2. Shamir's Secret Sharing is information-theoretically secure
3. User protects encryption key
4. At least K providers remain honest/available
5. Hash function (SHA256) is collision-resistant

### Trust Boundaries
```
┌──────────────────┐        ┌──────────────────┐
│  User Device     │        │  Provider Nodes  │
│  (plaintext)     │───────►│  (encrypted      │
│                  │        │   shares only)   │
└──────────────────┘        └──────────────────┘
        │
   TRUST BOUNDARY
   (encryption happens here)
```

---

## Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| Provider | Offline | Share unavailable | Request timeout | Use other providers |
| Provider | Corrupted | Bad hash | Hash mismatch | Fetch from other |
| K+ Providers | Offline | Cannot reconstruct | <K responses | Wait or repair |
| Key | Lost | Cannot decrypt | N/A | Unrecoverable |
| Metadata | Lost | Cannot find shares | N/A | Lost forever |
| Network | Partition | Some providers unreachable | Timeout | Retry later |

### Recovery Procedures

#### Provider Failure Recovery
```c
int cyxcloud_retrieve_with_fallback(cyxcloud_ctx_t* ctx,
                                     const cyxcloud_storage_t* storage,
                                     uint8_t* data, size_t* len) {
    shamir_share_t shares[storage->config.n];
    int collected = 0;

    // Try each provider in order of reputation
    for (int i = 0; i < storage->provider_count && collected < storage->config.k; i++) {
        cyxwiz_node_id_t* provider = &storage->providers[i].node_id;

        uint8_t share_data[MAX_SHARE_SIZE];
        size_t share_len;

        int err = cyxcloud_fetch_share(ctx, provider, storage->storage_id,
                                        share_data, &share_len);
        if (err != 0) {
            log_warn("Provider %s offline, trying next", node_id_to_hex(provider));
            continue;
        }

        // Verify hash
        uint8_t computed_hash[32];
        crypto_hash(computed_hash, share_data, share_len);
        if (memcmp(computed_hash, storage->providers[i].share_hash, 32) != 0) {
            log_warn("Provider %s returned corrupt share", node_id_to_hex(provider));
            // Report to reputation system
            cyxreputation_report_failure(provider, CYXREP_CORRUPT_DATA);
            continue;
        }

        shares[collected].index = storage->providers[i].share_index;
        shares[collected].data = share_data;
        shares[collected].len = share_len;
        collected++;
    }

    if (collected < storage->config.k) {
        return CYXCLOUD_INSUFFICIENT_SHARES;
    }

    // Reconstruct and decrypt
    return cyxcloud_reconstruct(shares, collected, storage, data, len);
}
```

#### Share Repair
```c
// When providers go offline, redistribute shares to new providers
int cyxcloud_repair(cyxcloud_ctx_t* ctx, cyxcloud_storage_t* storage) {
    // 1. Check which providers are offline
    int online_count = 0;
    int offline_indices[storage->config.n];
    int offline_count = 0;

    for (int i = 0; i < storage->provider_count; i++) {
        if (cyxcloud_ping_provider(&storage->providers[i].node_id)) {
            online_count++;
        } else {
            offline_indices[offline_count++] = i;
        }
    }

    // 2. If we have K+ online, we can repair
    if (online_count < storage->config.k) {
        return CYXCLOUD_CANNOT_REPAIR;  // Not enough shares available
    }

    // 3. Retrieve and reconstruct secret
    uint8_t plaintext[MAX_DATA_SIZE];
    size_t pt_len;
    int err = cyxcloud_retrieve(ctx, storage, plaintext, &pt_len);
    if (err != 0) return err;

    // 4. For each offline provider, create new share and send to new provider
    for (int i = 0; i < offline_count; i++) {
        int idx = offline_indices[i];

        // Find new provider
        cyxwiz_node_id_t new_provider;
        cyxcloud_select_provider(ctx, &new_provider);

        // Generate replacement share
        shamir_share_t new_share;
        shamir_regenerate_share(plaintext, pt_len, &storage->config,
                                 storage->providers[idx].share_index, &new_share);

        // Upload to new provider
        cyxcloud_upload_share(ctx, &new_provider, &new_share);

        // Update metadata
        storage->providers[idx].node_id = new_provider;
    }

    cyxwiz_secure_zero(plaintext, sizeof(plaintext));
    return CYXCLOUD_OK;
}
```

### What Cannot Be Recovered
- Encryption key (user responsibility)
- Data if <K shares available
- Metadata (storage ID, provider list, key)

---

## Protocol Versioning

### Version Format
```
CyxCloud Protocol: Major.Minor.Patch (SemVer)
Example: 1.0.0
```

### Protocol Messages
```c
// All messages include version
typedef struct {
    uint8_t version;            // Protocol version
    uint8_t type;               // Message type
    uint8_t storage_id[16];     // Storage identifier
    // ... rest of message
} cyxcloud_msg_header_t;

#define CYXCLOUD_MSG_STORE_REQ   0x01
#define CYXCLOUD_MSG_STORE_ACK   0x02
#define CYXCLOUD_MSG_RETRIEVE_REQ 0x03
#define CYXCLOUD_MSG_RETRIEVE_RSP 0x04
#define CYXCLOUD_MSG_CHALLENGE   0x05
#define CYXCLOUD_MSG_PROOF       0x06
#define CYXCLOUD_MSG_DELETE      0x07
```

### Backwards Compatibility

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| New optional field | Patch | No |
| New message type | Minor | No |
| Change encryption algorithm | Major | Yes |
| Change share format | Major | Yes |
| Change K/N limits | Minor | No (user choice) |

### Migration Path
1. Announce new version 30 days before
2. Providers must support both versions during transition
3. New stores use new version
4. Old stores remain accessible until expiry

---

## Rate Limiting & DoS Protection

### Client Limits

| Operation | Limit | Window | Enforcement |
|-----------|-------|--------|-------------|
| Store requests | 10/min | 1 min | Queue excess |
| Retrieve requests | 100/min | 1 min | Queue excess |
| Challenge responses | 60/hour | 1 hour | Per storage |
| Total bandwidth | 10 MB/s | - | Throttle |

### Provider Limits

| Resource | Limit | Enforcement |
|----------|-------|-------------|
| Storage per user | configurable | Reject excess |
| Concurrent uploads | 10 | Queue |
| Challenge processing | 1/sec | Drop excess |
| Total storage | capacity | Reject new |

### DoS Protection
```c
// Provider-side rate limiting
typedef struct {
    cyxwiz_node_id_t client;
    uint32_t request_count;
    uint64_t window_start;
    uint64_t bytes_this_window;
} client_rate_limit_t;

int cyxcloud_provider_check_limit(cyxwiz_node_id_t* client, size_t bytes) {
    client_rate_limit_t* limit = get_or_create_limit(client);

    // Reset window if expired
    if (now() - limit->window_start > 60000) {  // 1 minute
        limit->request_count = 0;
        limit->bytes_this_window = 0;
        limit->window_start = now();
    }

    // Check request count
    if (limit->request_count >= 100) {
        return CYXCLOUD_RATE_LIMITED;
    }

    // Check bandwidth
    if (limit->bytes_this_window + bytes > 10 * 1024 * 1024) {  // 10 MB
        return CYXCLOUD_BANDWIDTH_LIMITED;
    }

    limit->request_count++;
    limit->bytes_this_window += bytes;
    return CYXCLOUD_OK;
}
```

---

## Monitoring & Observability

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cyxcloud_stored_bytes` | Gauge | Total bytes stored |
| `cyxcloud_stored_objects` | Gauge | Total objects stored |
| `cyxcloud_providers_active` | Gauge | Active provider count |
| `cyxcloud_store_ops_total` | Counter | Store operations |
| `cyxcloud_retrieve_ops_total` | Counter | Retrieve operations |
| `cyxcloud_share_availability` | Gauge | % shares retrievable |
| `cyxcloud_challenge_pass_rate` | Gauge | % challenges passed |
| `cyxcloud_repair_ops_total` | Counter | Repair operations |

### Health Checks
```c
typedef struct {
    uint32_t total_objects;
    uint32_t healthy_objects;      // K+ shares available
    uint32_t degraded_objects;     // K to N-1 shares
    uint32_t critical_objects;     // Exactly K shares
    uint32_t lost_objects;         // <K shares
    uint32_t active_providers;
} cyxcloud_health_t;

int cyxcloud_health_check(cyxcloud_ctx_t* ctx, cyxcloud_health_t* health) {
    // Scan all stored objects
    for (int i = 0; i < ctx->storage_count; i++) {
        int available = cyxcloud_count_available_shares(&ctx->storage[i]);

        health->total_objects++;
        if (available == ctx->storage[i].config.n) {
            health->healthy_objects++;
        } else if (available >= ctx->storage[i].config.k + 1) {
            health->degraded_objects++;
        } else if (available == ctx->storage[i].config.k) {
            health->critical_objects++;
        } else {
            health->lost_objects++;
        }
    }

    health->active_providers = cyxcloud_count_active_providers(ctx);
    return CYXCLOUD_OK;
}
```

### Logging

| Level | When to Use | Examples |
|-------|-------------|----------|
| ERROR | Data at risk | <K shares, key loss |
| WARN | Degraded | Provider offline, repair needed |
| INFO | Normal ops | Store complete, retrieve success |
| DEBUG | Troubleshooting | Share details, encryption timing |

---

## Garbage Collection

### Expiry Sweep
```c
// Run periodically on providers (e.g., hourly)
void cyxcloud_provider_gc(void) {
    uint64_t now = time(NULL);
    DIR* dir = opendir(config.storage_path);
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;

        // Load share metadata
        cyxcloud_share_meta_t meta;
        if (load_share_meta(entry->d_name, &meta) != 0) continue;

        // Check expiry
        if (meta.expires_at != 0 && meta.expires_at < now) {
            // Secure delete
            char path[512];
            snprintf(path, sizeof(path), "%s/%s", config.storage_path, entry->d_name);

            // Overwrite with random data before delete
            secure_wipe_file(path);
            unlink(path);

            log_info("GC: Expired share %s deleted", entry->d_name);
            stats.gc_deleted++;
        }
    }

    closedir(dir);
}
```

### Orphan Cleanup
```c
// Clean up shares with no valid owner
void cyxcloud_provider_cleanup_orphans(void) {
    // Shares that haven't been accessed in 90+ days
    // and fail ownership verification
    uint64_t orphan_threshold = 90 * 24 * 3600;

    for (int i = 0; i < share_count; i++) {
        cyxcloud_share_meta_t* meta = &shares[i];

        if (now() - meta->last_accessed > orphan_threshold) {
            // Try to verify owner is still valid
            if (!cyxcloud_verify_owner_exists(meta->owner_pubkey)) {
                secure_delete_share(meta->storage_id);
                log_info("Orphan share %s cleaned up", hex(meta->storage_id));
            }
        }
    }
}
```

### Client-Side Cleanup
```c
// Remove local metadata for expired storage
void cyxcloud_client_cleanup(cyxcloud_ctx_t* ctx) {
    uint64_t now = time(NULL);

    for (int i = ctx->storage_count - 1; i >= 0; i--) {
        if (ctx->storage[i].expires_at < now) {
            // Securely wipe encryption key
            cyxwiz_secure_zero(ctx->storage[i].encryption_key, 32);

            // Remove from list
            memmove(&ctx->storage[i], &ctx->storage[i + 1],
                    (ctx->storage_count - i - 1) * sizeof(cyxcloud_storage_t));
            ctx->storage_count--;

            log_info("Expired storage metadata cleaned up");
        }
    }
}
```

---

## Deduplication

### Privacy-Preserving Dedup
```
┌─────────────────────────────────────────────────────────────────────┐
│                   Deduplication Strategy                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Option 1: No Dedup (Default)                                       │
│  ────────────────────────────                                       │
│  • Each upload treated independently                                │
│  • Maximum privacy (no linkage)                                     │
│  • Higher storage cost                                              │
│                                                                      │
│  Option 2: User-Level Dedup                                         │
│  ──────────────────────────                                         │
│  • Same user, same data = reuse existing storage                   │
│  • Check hash of plaintext before encrypt                          │
│  • No privacy leak (only user knows)                               │
│  • Saves storage for repeated uploads                              │
│                                                                      │
│  Option 3: Global Dedup (Not Recommended)                          │
│  ────────────────────────────────────────                          │
│  • Hash ciphertext, check if exists                                │
│  • Privacy leak: reveals duplicate content                         │
│  • Enables "confirmation attack"                                   │
│  • NOT implemented for privacy reasons                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### User-Level Dedup Implementation
```c
int cyxcloud_store_dedup(cyxcloud_ctx_t* ctx,
                          const uint8_t* data, size_t len,
                          cyxcloud_storage_t* storage) {
    // Hash plaintext
    uint8_t data_hash[32];
    crypto_hash(data_hash, data, len);

    // Check if we already have this exact data
    for (int i = 0; i < ctx->storage_count; i++) {
        if (memcmp(ctx->storage[i].data_hash, data_hash, 32) == 0) {
            // Already stored! Just return existing metadata
            memcpy(storage, &ctx->storage[i], sizeof(cyxcloud_storage_t));
            log_info("Dedup hit: reusing existing storage %s",
                     hex(storage->storage_id));
            return CYXCLOUD_DEDUP_HIT;
        }
    }

    // Not found, store normally
    return cyxcloud_store(ctx, data, len, storage);
}
```

---

## Key Management

### Master Key Derivation
```c
// Derive all storage keys from master
typedef struct {
    uint8_t master_key[32];     // Derived from wallet seed
    uint8_t salt[16];           // Random per-user salt
} cyxcloud_keyring_t;

int cyxcloud_keyring_init(cyxcloud_keyring_t* ring, const uint8_t* wallet_seed) {
    // Derive master key from wallet
    crypto_kdf_derive_from_key(ring->master_key, 32,
                                1, "CyxCloud", wallet_seed);

    // Generate random salt
    randombytes_buf(ring->salt, 16);

    return CYXCLOUD_OK;
}

int cyxcloud_derive_storage_key(cyxcloud_keyring_t* ring,
                                 const uint8_t* storage_id,
                                 uint8_t* key_out) {
    // key = HKDF(master_key, storage_id || salt, "cyxcloud-storage")
    uint8_t info[48];
    memcpy(info, storage_id, 16);
    memcpy(info + 16, ring->salt, 16);
    memcpy(info + 32, "cyxcloud-storage", 16);

    return crypto_kdf_hkdf_sha256_expand(key_out, 32,
                                          (char*)info, sizeof(info),
                                          ring->master_key);
}
```

### Key Rotation
```c
// Re-encrypt data with new key (for key compromise scenarios)
int cyxcloud_rotate_key(cyxcloud_ctx_t* ctx,
                         cyxcloud_storage_t* storage,
                         const uint8_t* new_key) {
    // 1. Retrieve and decrypt with old key
    uint8_t plaintext[MAX_DATA_SIZE];
    size_t pt_len;
    int err = cyxcloud_retrieve(ctx, storage, plaintext, &pt_len);
    if (err != 0) return err;

    // 2. Delete old storage
    cyxcloud_delete(ctx, storage);

    // 3. Re-store with new key
    memcpy(storage->encryption_key, new_key, 32);
    err = cyxcloud_store(ctx, plaintext, pt_len, storage);

    cyxwiz_secure_zero(plaintext, sizeof(plaintext));
    return err;
}
```

### Key Escrow (Optional)
```c
// Allow recovery via trusted parties (M-of-N)
typedef struct {
    uint8_t trustee_pubkeys[5][32];  // Up to 5 trustees
    uint8_t trustee_count;
    uint8_t threshold;                // How many needed
} cyxcloud_key_escrow_t;

int cyxcloud_escrow_key(const uint8_t* key,
                         cyxcloud_key_escrow_t* escrow,
                         uint8_t encrypted_shares[][48]) {  // 32 key + 16 overhead
    // 1. Split key using Shamir
    shamir_share_t shares[escrow->trustee_count];
    shamir_split(key, 32,
                  &(shamir_config_t){escrow->threshold, escrow->trustee_count},
                  shares);

    // 2. Encrypt each share to corresponding trustee's pubkey
    for (int i = 0; i < escrow->trustee_count; i++) {
        crypto_box_seal(encrypted_shares[i], shares[i].data, 32,
                        escrow->trustee_pubkeys[i]);
    }

    return CYXCLOUD_OK;
}
```

---

## Large File Handling

### Chunking Strategy
```c
// Large file chunking parameters
#define CYXCLOUD_CHUNK_SIZE (1 * 1024 * 1024)  // 1 MB chunks
#define CYXCLOUD_MAX_CHUNKS 10000              // ~10 GB max

// Chunked storage metadata
typedef struct {
    uint8_t file_id[16];            // Overall file ID
    uint64_t total_size;            // Original file size
    uint32_t chunk_count;           // Number of chunks
    uint8_t chunk_ids[CYXCLOUD_MAX_CHUNKS][16];  // Each chunk's storage ID
    uint8_t master_key[32];         // Key for deriving chunk keys
} cyxcloud_chunked_storage_t;

int cyxcloud_store_large(cyxcloud_ctx_t* ctx,
                          const char* filepath,
                          cyxcloud_chunked_storage_t* storage) {
    FILE* f = fopen(filepath, "rb");
    fseek(f, 0, SEEK_END);
    storage->total_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    storage->chunk_count = (storage->total_size + CYXCLOUD_CHUNK_SIZE - 1)
                           / CYXCLOUD_CHUNK_SIZE;

    // Generate master key
    randombytes_buf(storage->master_key, 32);

    // Process chunks
    uint8_t chunk_data[CYXCLOUD_CHUNK_SIZE];
    for (uint32_t i = 0; i < storage->chunk_count; i++) {
        size_t chunk_len = fread(chunk_data, 1, CYXCLOUD_CHUNK_SIZE, f);

        // Derive chunk key
        uint8_t chunk_key[32];
        derive_chunk_key(storage->master_key, i, chunk_key);

        // Store chunk
        cyxcloud_storage_t chunk_storage;
        chunk_storage.encryption_key = chunk_key;
        cyxcloud_store(ctx, chunk_data, chunk_len, &chunk_storage);

        memcpy(storage->chunk_ids[i], chunk_storage.storage_id, 16);

        cyxwiz_secure_zero(chunk_key, 32);
    }

    fclose(f);
    cyxwiz_secure_zero(chunk_data, sizeof(chunk_data));
    return CYXCLOUD_OK;
}
```

### Streaming Retrieval
```c
// Stream large file to disk without loading entirely in memory
int cyxcloud_retrieve_large(cyxcloud_ctx_t* ctx,
                             const cyxcloud_chunked_storage_t* storage,
                             const char* output_path) {
    FILE* f = fopen(output_path, "wb");
    uint8_t chunk_data[CYXCLOUD_CHUNK_SIZE];

    for (uint32_t i = 0; i < storage->chunk_count; i++) {
        // Derive chunk key
        uint8_t chunk_key[32];
        derive_chunk_key(storage->master_key, i, chunk_key);

        // Build storage reference
        cyxcloud_storage_t chunk_ref;
        memcpy(chunk_ref.storage_id, storage->chunk_ids[i], 16);
        memcpy(chunk_ref.encryption_key, chunk_key, 32);
        // ... fill other fields from stored metadata

        // Retrieve chunk
        size_t chunk_len;
        int err = cyxcloud_retrieve(ctx, &chunk_ref, chunk_data, &chunk_len);
        if (err != 0) {
            fclose(f);
            return err;
        }

        fwrite(chunk_data, 1, chunk_len, f);
        cyxwiz_secure_zero(chunk_key, 32);
    }

    fclose(f);
    cyxwiz_secure_zero(chunk_data, sizeof(chunk_data));
    return CYXCLOUD_OK;
}
```

### Parallel Chunk Operations
```c
// Download multiple chunks in parallel for speed
int cyxcloud_retrieve_parallel(cyxcloud_ctx_t* ctx,
                                const cyxcloud_chunked_storage_t* storage,
                                uint8_t* output) {
    #define MAX_PARALLEL 4

    // Use thread pool or async I/O
    for (uint32_t i = 0; i < storage->chunk_count; i += MAX_PARALLEL) {
        int batch_size = MIN(MAX_PARALLEL, storage->chunk_count - i);

        // Launch parallel retrievals
        for (int j = 0; j < batch_size; j++) {
            uint32_t chunk_idx = i + j;
            async_retrieve_chunk(ctx, storage, chunk_idx,
                                 output + chunk_idx * CYXCLOUD_CHUNK_SIZE);
        }

        // Wait for batch to complete
        await_all_chunks(batch_size);
    }

    return CYXCLOUD_OK;
}
