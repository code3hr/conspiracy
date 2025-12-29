# CyxToken Design Document

## Philosophy

```
"Own Nothing. Access Everything. Leave No Trace."
              │
              ▼
    ┌─────────────────┐
    │    CyxToken     │
    │                 │
    │  The currency   │
    │  of access.     │
    │                 │
    │  No banks.      │
    │  No identity.   │
    │  Just value.    │
    └─────────────────┘
```

CyxToken (CYX) is the native currency of the CyxWiz ecosystem. It enables anonymous, trustless exchange of value for services on the mesh network.

## Overview

### What CyxToken Is NOT
- NOT a speculative investment token
- NOT running on Ethereum/Solana/etc (no external blockchain)
- NOT requiring KYC or identity
- NOT traceable to real-world identity

### What CyxToken IS
- Native to CyxWiz mesh (runs ON the protocol itself)
- Utility token for accessing network services
- Earned by contributing resources
- Spent by consuming resources
- Anonymous by design

## Token Economics

### Supply Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                      CyxToken Supply Model                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Initial Supply: 0 (No premine, no ICO, no VC allocation)           │
│                                                                      │
│  Emission: Proof of Useful Work (PoUW)                              │
│  ─────────────────────────────────────                              │
│  Tokens are ONLY created when useful work is performed:             │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Work Type              │ Emission Rate    │ Decay            │ │
│  ├───────────────────────────────────────────────────────────────┤ │
│  │  Hosting compute        │ 10 CYX/hour/core │ -1% per month    │ │
│  │  Providing storage      │ 5 CYX/GB/day     │ -1% per month    │ │
│  │  Relaying traffic       │ 1 CYX/GB         │ -1% per month    │ │
│  │  Validating consensus   │ 2 CYX/round      │ -1% per month    │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Decay: Emission rates decrease 1% monthly to approach equilibrium  │
│                                                                      │
│  Burning: Tokens are burned when services are consumed              │
│  ─────────────────────────────────────────────────────              │
│  50% of payment goes to service provider                            │
│  50% is BURNED (removed from circulation)                           │
│                                                                      │
│  This creates deflationary pressure as network usage grows          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Earn vs Spend Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Token Flow Diagram                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                         ┌─────────────┐                             │
│                         │   MINTED    │                             │
│                         │  (new CYX)  │                             │
│                         └──────┬──────┘                             │
│                                │                                     │
│                    Proof of Useful Work                             │
│                                │                                     │
│     ┌──────────────────────────┼──────────────────────────┐        │
│     ▼                          ▼                          ▼        │
│ ┌────────┐              ┌────────────┐              ┌────────┐     │
│ │ Hosts  │              │  Relays    │              │Validators│    │
│ │ earn   │              │  earn      │              │ earn    │     │
│ └───┬────┘              └─────┬──────┘              └────┬────┘     │
│     │                         │                          │          │
│     └─────────────────────────┼──────────────────────────┘          │
│                               │                                      │
│                               ▼                                      │
│                      ┌────────────────┐                             │
│                      │  CIRCULATION   │                             │
│                      │   (CYX pool)   │                             │
│                      └────────┬───────┘                             │
│                               │                                      │
│              Users spend CYX for services                           │
│                               │                                      │
│     ┌─────────────────────────┼──────────────────────────┐         │
│     ▼                         ▼                          ▼         │
│ ┌────────┐              ┌────────────┐              ┌────────┐     │
│ │Compute │              │  Storage   │              │ Relay  │     │
│ │rental  │              │  rental    │              │ access │     │
│ └───┬────┘              └─────┬──────┘              └────┬───┘     │
│     │                         │                          │          │
│     └─────────────────────────┼──────────────────────────┘          │
│                               │                                      │
│            ┌──────────────────┴──────────────────┐                  │
│            ▼                                     ▼                  │
│     ┌────────────┐                       ┌────────────┐            │
│     │  Provider  │                       │   BURNED   │            │
│     │  receives  │                       │ (destroyed)│            │
│     │    50%     │                       │    50%     │            │
│     └────────────┘                       └────────────┘            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Token Operations

### 1. Wallets

```c
// Wallet is derived from X25519 keypair
typedef struct {
    uint8_t pubkey[32];         // Public key (wallet address)
    uint8_t privkey[32];        // Private key (spending key)
    uint64_t balance;           // Current balance in smallest unit
    uint64_t nonce;             // Transaction counter (replay protection)
} cyxtoken_wallet_t;

// Create new wallet
int cyxtoken_wallet_create(cyxtoken_wallet_t* wallet);

// Derive wallet address (first 20 bytes of pubkey hash)
void cyxtoken_wallet_address(const cyxtoken_wallet_t* wallet,
                              char* address);  // 40-char hex string

// Import wallet from seed
int cyxtoken_wallet_from_seed(const uint8_t* seed, size_t seed_len,
                               cyxtoken_wallet_t* wallet);
```

**Wallet Properties:**
- Self-custody only (no hosted wallets)
- Derived from X25519 keypair (same as node identity)
- Can have separate wallets for privacy
- Addresses are pseudonymous (not linked to identity)

### 2. Transactions

```c
// Transaction types
typedef enum {
    CYXTOKEN_TX_TRANSFER,       // Send CYX to another wallet
    CYXTOKEN_TX_STAKE,          // Lock CYX as stake
    CYXTOKEN_TX_UNSTAKE,        // Unlock staked CYX
    CYXTOKEN_TX_ESCROW_LOCK,    // Lock in escrow for service
    CYXTOKEN_TX_ESCROW_RELEASE, // Release escrow to provider
    CYXTOKEN_TX_ESCROW_REFUND,  // Refund escrow to user
    CYXTOKEN_TX_REWARD,         // Emission reward (minting)
    CYXTOKEN_TX_BURN,           // Destroy tokens
} cyxtoken_tx_type_t;

// Transaction structure
typedef struct {
    uint8_t tx_hash[32];        // SHA256 of transaction
    cyxtoken_tx_type_t type;    // Transaction type

    uint8_t from[20];           // Sender address
    uint8_t to[20];             // Recipient address
    uint64_t amount;            // Amount in smallest unit (1 CYX = 10^8)
    uint64_t fee;               // Transaction fee
    uint64_t nonce;             // Sender's nonce
    uint64_t timestamp;         // Unix timestamp

    uint8_t signature[64];      // Ed25519 signature

    // Optional data (for escrow, etc.)
    uint8_t data[64];           // Contract-specific data
    uint8_t data_len;
} cyxtoken_tx_t;

// Create and sign transaction
int cyxtoken_tx_create(cyxtoken_wallet_t* wallet,
                        cyxtoken_tx_type_t type,
                        const uint8_t* to,
                        uint64_t amount,
                        cyxtoken_tx_t* tx);

// Verify transaction
int cyxtoken_tx_verify(const cyxtoken_tx_t* tx);

// Broadcast to network
int cyxtoken_tx_broadcast(cyxtoken_tx_t* tx);
```

### 3. Consensus (Transaction Validation)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Transaction Consensus Flow                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User creates transaction                                        │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  From: abc123...  To: def456...  Amount: 100 CYX        │    │
│     │  Signed by sender's private key                          │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                │                                     │
│                                ▼                                     │
│  2. Broadcast to validator nodes                                    │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Validators receive TX, add to mempool                   │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                │                                     │
│                                ▼                                     │
│  3. Validators verify                                               │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  ✓ Signature valid?                                      │    │
│     │  ✓ Sender has balance?                                   │    │
│     │  ✓ Nonce correct? (no replay)                            │    │
│     │  ✓ Fee sufficient?                                       │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                │                                     │
│                                ▼                                     │
│  4. Block proposal                                                  │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Leader validator proposes block with transactions       │    │
│     │  Other validators vote (2/3 majority required)           │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                │                                     │
│                                ▼                                     │
│  5. Block finalized                                                 │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Transaction included in block                           │    │
│     │  Balances updated                                        │    │
│     │  Block hash added to chain                               │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Block Time: ~10 seconds (adjustable based on network size)        │
│  Finality: Immediate after 2/3 validator confirmation              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Staking System

### Why Stake?

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Staking Requirements                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Role              │ Minimum Stake │ Purpose                        │
│  ──────────────────┼───────────────┼───────────────────────────────│
│  Host Node         │ 1,000 CYX     │ Collateral for user protection│
│  Relay Node        │ 2,000 CYX     │ Higher risk (clearnet exposure)│
│  Validator Node    │ 5,000 CYX     │ Consensus participation        │
│  Storage Provider  │ 500 CYX       │ Data availability guarantee    │
│                                                                      │
│  Staking Benefits:                                                   │
│  • Required to participate as provider                              │
│  • Earn emission rewards proportional to stake                      │
│  • Higher stake = higher trust = more customers                     │
│                                                                      │
│  Slashing Conditions:                                                │
│  • Host: Container terminates early = 10% stake slashed            │
│  • Relay: Logging/tampering detected = 50% stake slashed           │
│  • Validator: Equivocation (double vote) = 100% stake slashed      │
│  • Storage: Data unavailable when requested = 20% stake slashed    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Staking Operations

```c
// Stake structure
typedef struct {
    uint8_t staker[20];         // Staker's wallet address
    uint64_t amount;            // Amount staked
    uint64_t locked_until;      // Unix timestamp (unbonding period)
    cyxtoken_stake_type_t type; // What the stake is for
    bool slashable;             // Can be slashed?
} cyxtoken_stake_t;

// Stake types
typedef enum {
    CYXTOKEN_STAKE_HOST,
    CYXTOKEN_STAKE_RELAY,
    CYXTOKEN_STAKE_VALIDATOR,
    CYXTOKEN_STAKE_STORAGE,
} cyxtoken_stake_type_t;

// Stake CYX
int cyxtoken_stake(cyxtoken_wallet_t* wallet,
                    uint64_t amount,
                    cyxtoken_stake_type_t type);

// Request unstake (starts unbonding period)
int cyxtoken_unstake_request(cyxtoken_wallet_t* wallet,
                              cyxtoken_stake_type_t type);

// Complete unstake (after unbonding period)
int cyxtoken_unstake_complete(cyxtoken_wallet_t* wallet,
                               cyxtoken_stake_type_t type);

// Slash stake (called by validators)
int cyxtoken_slash(const uint8_t* staker,
                    cyxtoken_stake_type_t type,
                    uint8_t slash_percent,
                    const uint8_t* evidence_hash);
```

### Unbonding Period

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Unbonding Timeline                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Role              │ Unbonding Period │ Rationale                   │
│  ──────────────────┼──────────────────┼─────────────────────────────│
│  Host              │ 7 days           │ Cover ongoing rentals       │
│  Relay             │ 14 days          │ Longer exposure window      │
│  Validator         │ 21 days          │ Consensus stability         │
│  Storage           │ 30 days          │ Data retrieval guarantee    │
│                                                                      │
│  Timeline:                                                           │
│  ┌─────┬─────────────────────────────────────────┬─────────────┐   │
│  │ DAY │ 0        7        14        21       30 │             │   │
│  ├─────┼─────────────────────────────────────────┼─────────────┤   │
│  │Host │ Request──────────►Available             │             │   │
│  │Relay│ Request──────────────────────►Available │             │   │
│  │Valid│ Request────────────────────────────►Avail│            │   │
│  │Store│ Request──────────────────────────────────►Available   │   │
│  └─────┴─────────────────────────────────────────┴─────────────┘   │
│                                                                      │
│  During unbonding:                                                   │
│  • Stake still slashable                                            │
│  • No longer earning rewards                                        │
│  • Cannot re-stake until complete                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Escrow System

### Payment Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Escrow Payment Flow                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────┐           ┌─────────┐           ┌─────────┐           │
│  │  User   │           │ Escrow  │           │Provider │           │
│  └────┬────┘           └────┬────┘           └────┬────┘           │
│       │                     │                     │                 │
│       │ 1. Lock payment     │                     │                 │
│       │ (200 CYX)           │                     │                 │
│       │────────────────────►│                     │                 │
│       │                     │                     │                 │
│       │ 2. Escrow confirms  │                     │                 │
│       │◄────────────────────│                     │                 │
│       │                     │                     │                 │
│       │                     │ 3. Provider sees    │                 │
│       │                     │    locked payment   │                 │
│       │                     │────────────────────►│                 │
│       │                     │                     │                 │
│       │ 4. Service begins   │                     │                 │
│       │◄────────────────────┼─────────────────────│                 │
│       │                     │                     │                 │
│       │        ... time passes, service runs ...│                  │
│       │                     │                     │                 │
│       │ 5a. Happy: Time expires OR user releases │                 │
│       │                     │                     │                 │
│       │                     │ 6a. Release to      │                 │
│       │                     │     provider (100)  │                 │
│       │                     │────────────────────►│                 │
│       │                     │                     │                 │
│       │                     │ 6b. Burn (100)      │                 │
│       │                     │────────────────────►│ 🔥              │
│       │                     │                     │                 │
│       │ 5b. Unhappy: Dispute raised              │                 │
│       │                     │                     │                 │
│       │                     │ 6. Validators       │                 │
│       │                     │    arbitrate        │                 │
│       │                     │◄───────────────────►│                 │
│       │                     │                     │                 │
│       │ 7. Refund/release based on evidence      │                 │
│       │◄────────────────────┼────────────────────►│                 │
│       │                     │                     │                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Escrow Contract Structure

```c
// Escrow states
typedef enum {
    CYXTOKEN_ESCROW_LOCKED,     // Payment locked, awaiting service
    CYXTOKEN_ESCROW_ACTIVE,     // Service in progress
    CYXTOKEN_ESCROW_RELEASING,  // Release initiated
    CYXTOKEN_ESCROW_DISPUTED,   // Under dispute
    CYXTOKEN_ESCROW_COMPLETED,  // Successfully completed
    CYXTOKEN_ESCROW_REFUNDED,   // Refunded to user
} cyxtoken_escrow_state_t;

// Escrow contract
typedef struct {
    uint8_t escrow_id[32];      // Unique escrow identifier

    uint8_t user[20];           // User's wallet address
    uint8_t provider[20];       // Provider's wallet address
    uint64_t amount;            // Total amount locked

    cyxtoken_escrow_state_t state;
    uint64_t created_at;        // Lock timestamp
    uint64_t expires_at;        // Service expiration

    // Service details
    uint8_t service_type;       // HOST, STORAGE, RELAY
    uint8_t service_id[32];     // Container ID, storage ID, etc.

    // Signatures
    uint8_t user_sig[64];       // User's agreement signature
    uint8_t provider_sig[64];   // Provider's agreement signature
} cyxtoken_escrow_t;

// Escrow operations
int cyxtoken_escrow_create(cyxtoken_wallet_t* user,
                            const uint8_t* provider,
                            uint64_t amount,
                            uint64_t duration_sec,
                            cyxtoken_escrow_t* escrow);

int cyxtoken_escrow_release(cyxtoken_escrow_t* escrow,
                             uint8_t* release_sig);

int cyxtoken_escrow_dispute(cyxtoken_escrow_t* escrow,
                             const uint8_t* evidence,
                             size_t evidence_len);

int cyxtoken_escrow_refund(cyxtoken_escrow_t* escrow,
                            uint8_t refund_percent);
```

## Privacy Features

### Transaction Privacy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Transaction Privacy Model                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  What's PUBLIC (visible on ledger):                                 │
│  • Transaction exists                                                │
│  • Amount transferred                                                │
│  • Sender address (pseudonymous)                                    │
│  • Recipient address (pseudonymous)                                 │
│  • Timestamp                                                         │
│                                                                      │
│  What's PRIVATE:                                                     │
│  • Real-world identity of sender/recipient                          │
│  • IP address (transactions broadcast via onion routing)            │
│  • Purpose of transaction                                           │
│                                                                      │
│  Privacy Enhancements (optional):                                   │
│  ─────────────────────────────────                                  │
│                                                                      │
│  1. New Address per Transaction                                     │
│     • Generate fresh keypair for each receive                       │
│     • Makes linking transactions harder                             │
│                                                                      │
│  2. CoinJoin-style Mixing (future)                                  │
│     • Multiple users combine transactions                           │
│     • Breaks transaction graph                                      │
│                                                                      │
│  3. Confidential Transactions (future)                              │
│     • Hide amounts with Pedersen commitments                        │
│     • Only parties involved know amount                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Wallet Privacy Best Practices

```
DO:
✓ Use different addresses for different purposes
✓ Broadcast transactions through onion routing
✓ Wait random delays before spending received funds
✓ Use exact amounts when possible (avoid change)

DON'T:
✗ Reuse addresses
✗ Announce your address publicly linked to identity
✗ Send from/to exchanges that require KYC
✗ Consolidate all funds into one address
```

## Token Integration with Services

### CyxHost Integration

```c
// Pay for container rental
int cyxhost_pay(cyxtoken_wallet_t* wallet,
                 cyxhost_rental_contract_t* contract) {
    // 1. Calculate total cost
    uint64_t cost = contract->duration_hours *
                    contract->config.cpu_shares *
                    PRICE_PER_CPU_HOUR;

    // 2. Create escrow
    cyxtoken_escrow_t escrow;
    cyxtoken_escrow_create(wallet,
                           contract->host_id,
                           cost,
                           contract->duration_hours * 3600,
                           &escrow);

    // 3. Link escrow to contract
    memcpy(contract->escrow_id, escrow.escrow_id, 32);

    return CYXTOKEN_OK;
}
```

### CyxCloud Integration

```c
// Pay for storage
int cyxcloud_pay(cyxtoken_wallet_t* wallet,
                  uint64_t size_bytes,
                  uint64_t duration_days,
                  cyxcloud_storage_t* storage) {
    // Price: 5 CYX per GB per day
    uint64_t gb = (size_bytes + GB - 1) / GB;  // Round up
    uint64_t cost = gb * duration_days * 5 * CYX_UNIT;

    // Create payment (not escrow - storage is prepaid)
    cyxtoken_tx_t tx;
    cyxtoken_tx_create(wallet, CYXTOKEN_TX_TRANSFER,
                        CYXCLOUD_TREASURY, cost, &tx);
    cyxtoken_tx_broadcast(&tx);

    // Funds go to storage providers proportionally
    return CYXTOKEN_OK;
}
```

## Token Commands (CLI)

```bash
# Create new wallet
cyxtoken wallet create
# Output:
# Created wallet: 0x7a3f8c21d7b92e4f...
# Seed phrase (BACKUP THIS!): apple banana cherry ...
# Balance: 0 CYX

# Check balance
cyxtoken balance
# Output:
# Address: 0x7a3f8c21d7b92e4f...
# Balance: 1,250.00 CYX
# Staked:  1,000.00 CYX (Host)
# Available: 250.00 CYX

# Send tokens
cyxtoken send 0xdef456... 100
# Output:
# Sending 100 CYX to 0xdef456...
# Fee: 0.01 CYX
# Confirm? [y/N] y
# Transaction: 0xabc789... confirmed in block #12345

# Stake tokens
cyxtoken stake host 1000
# Output:
# Staking 1000 CYX for Host role...
# Transaction confirmed.
# You are now eligible to run CyxHost.

# View transactions
cyxtoken history
# Output:
# TX Hash           Type      Amount    To/From         Time
# 0xabc789...       SEND      -100      0xdef456...     2h ago
# 0xdef012...       REWARD    +50       (emission)      1d ago
# 0x345678...       STAKE     -1000     (locked)        3d ago

# Check network stats
cyxtoken stats
# Output:
# Total Supply: 8,234,567 CYX
# Circulating:  5,123,456 CYX
# Staked:       2,111,111 CYX
# Burned:       1,000,000 CYX
# Emission/day: ~1,000 CYX
# Burn/day:     ~800 CYX
```

## Implementation

### Files to Create

```
include/cyxwiz/
├── cyxtoken.h          # Main token header
├── cyxtoken_wallet.h   # Wallet operations
├── cyxtoken_tx.h       # Transaction types
├── cyxtoken_stake.h    # Staking system
└── cyxtoken_escrow.h   # Escrow contracts

src/token/
├── wallet.c            # Wallet implementation
├── transaction.c       # Transaction handling
├── consensus.c         # Token consensus
├── stake.c             # Staking logic
├── escrow.c            # Escrow management
└── emission.c          # Token minting

tools/
└── cyxtoken.c          # CLI tool
```

### Dependencies
- Ed25519 for signatures (libsodium)
- SHA256 for hashing (libsodium)
- Existing CyxWiz consensus module

## Open Questions

1. **Initial Distribution**: How do early nodes get tokens to stake?
   - Bootstrap period with higher emission?
   - Faucet for verified humans?

2. **Fee Market**: How are transaction fees determined?
   - Fixed fee vs dynamic auction?

3. **Cross-chain Bridge**: Should CYX be bridgeable to Ethereum/etc?
   - Adds liquidity but requires trust/oracle

4. **Governance**: How are protocol parameters changed?
   - Token-weighted voting?
   - Validator committee?

---

## Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Double Spend | Spend same tokens twice | Critical |
| 51% Attack | Control majority validators | Critical |
| Key Theft | Steal private keys | Critical |
| Replay Attack | Reuse old transaction | High |
| Sybil Attack | Fake validators | High |
| Denial of Service | Block transactions | Medium |

### Detailed Threat Analysis

#### Double Spend Attack
- **Description**: Attacker spends tokens, then reverses transaction
- **Attacker**: Well-resourced adversary
- **Prerequisites**: Network partition or validator collusion
- **Impact**: Token theft, loss of trust
- **Likelihood**: Low (PBFT-style finality)
- **Mitigation**:
  - Immediate finality after 2/3 validator confirmation
  - No block reorganizations
  - Transaction nonces prevent replay
  - Wait for finality before accepting payment

#### 51% Validator Attack
- **Description**: Attacker controls majority of validators
- **Attacker**: Nation-state or wealthy adversary
- **Prerequisites**: Acquire 51%+ of staked tokens
- **Impact**: Censorship, invalid transactions
- **Likelihood**: Low (stake requirement + slashing)
- **Mitigation**:
  - High minimum stake (5000 CYX)
  - Slashing for misbehavior
  - Geographic diversity incentives
  - Gradual stake accumulation limits

#### Private Key Theft
- **Description**: Attacker obtains wallet private key
- **Attacker**: Malware, phishing, physical access
- **Prerequisites**: Access to victim's device
- **Impact**: Complete wallet drain
- **Likelihood**: Medium (user responsibility)
- **Mitigation**:
  - Secure memory for keys
  - Optional hardware wallet support
  - Multi-sig wallets (future)
  - Time-locked recovery (future)

#### Transaction Replay
- **Description**: Rebroadcast old valid transaction
- **Attacker**: Network observer
- **Prerequisites**: Capture valid transaction
- **Impact**: Unintended repeat payments
- **Likelihood**: Low (nonce protection)
- **Mitigation**:
  - Transaction nonces (incrementing counter)
  - Nonce must be exactly current+1
  - Timestamp bounds (not too old/future)

### Security Assumptions
1. Ed25519 signatures are unforgeable
2. SHA256 is collision-resistant
3. At least 2/3 of validators are honest
4. Users protect their private keys
5. Network latency is bounded

### Trust Boundaries
```
┌──────────────────┐        ┌──────────────────┐
│  User Wallet     │        │  Validator Set   │
│  (private key)   │───────►│  (consensus)     │
└──────────────────┘        └──────────────────┘
        │                            │
   TRUST BOUNDARY 1            TRUST BOUNDARY 2
        │                            │
        ▼                            ▼
┌──────────────────┐        ┌──────────────────┐
│  Network Layer   │        │  Ledger State    │
│  (broadcast)     │        │  (balances)      │
└──────────────────┘        └──────────────────┘
```

- **Trust boundary 1**: User → Network (signature verification)
- **Trust boundary 2**: Validators → Ledger (consensus rules)

---

## Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| Wallet | Key loss | Cannot spend | User reports | Restore from seed |
| Transaction | Rejected | Error returned | Immediate | Fix and retry |
| Validator | Crash | Missing votes | Heartbeat | Restart, resync |
| Consensus | No quorum | No new blocks | Block timeout | Wait for validators |
| Ledger | State corruption | Invalid balances | Merkle mismatch | Resync from peers |
| Escrow | Timeout | Stuck funds | Expiry check | Auto-refund |

### Recovery Procedures

#### Lost Wallet Recovery
```c
// Restore from seed phrase
int cyxtoken_wallet_recover(const char* seed_phrase,
                             cyxtoken_wallet_t* wallet) {
    // 1. Validate seed phrase (BIP39)
    if (!validate_mnemonic(seed_phrase)) {
        return CYXTOKEN_INVALID_SEED;
    }

    // 2. Derive master key
    uint8_t master_key[32];
    mnemonic_to_seed(seed_phrase, master_key);

    // 3. Derive wallet keypair
    cyxwiz_crypto_derive_keypair(master_key, wallet->pubkey, wallet->privkey);

    // 4. Query network for balance
    wallet->balance = cyxtoken_query_balance(wallet->pubkey);
    wallet->nonce = cyxtoken_query_nonce(wallet->pubkey);

    cyxwiz_secure_zero(master_key, 32);
    return CYXTOKEN_OK;
}
```

#### Validator Crash Recovery
```c
int cyxtoken_validator_recover(cyxtoken_validator_t* validator) {
    // 1. Load last known state from WAL
    cyxtoken_state_t state;
    cyxtoken_load_wal(&state);

    // 2. Request missing blocks from peers
    uint64_t local_height = state.block_height;
    uint64_t network_height = cyxtoken_query_height();

    for (uint64_t h = local_height + 1; h <= network_height; h++) {
        cyxtoken_block_t block;
        cyxtoken_fetch_block(h, &block);
        cyxtoken_apply_block(&state, &block);
    }

    // 3. Resume consensus participation
    cyxtoken_validator_start(validator, &state);

    return CYXTOKEN_OK;
}
```

#### Escrow Timeout Recovery
```c
// Automatic handling of expired escrows
void cyxtoken_escrow_timeout_check(void) {
    uint64_t now = time(NULL);

    for (int i = 0; i < escrow_count; i++) {
        cyxtoken_escrow_t* e = &escrows[i];

        if (e->state == CYXTOKEN_ESCROW_ACTIVE && e->expires_at < now) {
            // Grace period expired - release to provider
            cyxtoken_escrow_release(e, NULL);
        }

        if (e->state == CYXTOKEN_ESCROW_DISPUTED &&
            e->dispute_expires_at < now) {
            // Dispute timeout - default to user refund
            cyxtoken_escrow_refund(e, 100);
        }
    }
}
```

### What Cannot Be Recovered
- Lost private keys (no backup = funds lost forever)
- Transactions already finalized
- Slashed stake (burned permanently)
- Burned tokens

---

## Protocol Versioning

### Version Format
```
CyxToken Protocol: Major.Minor.Patch (SemVer)
Example: 1.2.0
```

### Version Fields
```c
// Transaction includes version
typedef struct {
    uint8_t version;            // Protocol version
    // ... rest of transaction
} cyxtoken_tx_t;

// Block includes version
typedef struct {
    uint8_t version;            // Block format version
    uint8_t min_tx_version;     // Minimum TX version accepted
    // ... rest of block
} cyxtoken_block_t;
```

### Consensus Upgrade Process
```
┌─────────────────────────────────────────────────────────────────────┐
│                   Protocol Upgrade Timeline                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Day 0        Day 30       Day 60       Day 90       Day 120       │
│    │            │            │            │            │            │
│    ▼            ▼            ▼            ▼            ▼            │
│  ┌────┐      ┌────┐      ┌────┐      ┌────┐      ┌────┐          │
│  │BIP │      │Vote│      │Lock│      │Activate    │Enforce│       │
│  │Prop│─────►│    │─────►│    │─────►│    │─────►│      │        │
│  └────┘      └────┘      └────┘      └────┘      └────┘          │
│                                                                      │
│  BIP Prop: Proposal published with specification                    │
│  Vote: Validators signal support (need 80% approval)                │
│  Lock: If approved, version locked in                               │
│  Activate: New rules active, old still accepted                     │
│  Enforce: Old version rejected                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Backwards Compatibility

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| New optional TX field | Patch | No |
| New TX type | Minor | No |
| Change signature scheme | Major | Yes |
| Change consensus rules | Major | Yes |
| Change block structure | Major | Yes |

---

## Rate Limiting & DoS Protection

### Transaction Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| TX per block | 1000 | Block size |
| TX per address per block | 10 | Anti-spam |
| Minimum fee | 0.001 CYX | Economic spam filter |
| Max TX size | 512 bytes | Network efficiency |
| Mempool per peer | 100 TX | Memory protection |

### Fee-Based Prioritization
```c
// Transaction priority = fee / size
uint64_t cyxtoken_tx_priority(cyxtoken_tx_t* tx) {
    return (tx->fee * 1000) / cyxtoken_tx_size(tx);
}

// Validators include highest priority first
void cyxtoken_build_block(cyxtoken_block_t* block) {
    // Sort mempool by priority
    qsort(mempool, mempool_count, sizeof(cyxtoken_tx_t),
          compare_priority);

    // Include top transactions up to block limit
    for (int i = 0; i < mempool_count && block->tx_count < MAX_TX; i++) {
        if (cyxtoken_tx_verify(&mempool[i]) == CYXTOKEN_OK) {
            block->transactions[block->tx_count++] = mempool[i];
        }
    }
}
```

### Validator DoS Protection
```c
// Rate limit incoming transactions from peers
typedef struct {
    cyxwiz_node_id_t peer_id;
    uint32_t tx_count;
    uint64_t window_start;
} peer_rate_limit_t;

int cyxtoken_check_peer_limit(cyxwiz_node_id_t* peer) {
    peer_rate_limit_t* limit = find_peer_limit(peer);

    if (now() - limit->window_start > 60) {  // 1 minute window
        limit->tx_count = 0;
        limit->window_start = now();
    }

    if (limit->tx_count >= 100) {  // 100 TX/min per peer
        return CYXTOKEN_RATE_LIMITED;
    }

    limit->tx_count++;
    return CYXTOKEN_OK;
}
```

---

## Monitoring & Observability

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cyxtoken_supply_total` | Gauge | Total tokens in existence |
| `cyxtoken_supply_circulating` | Gauge | Non-staked tokens |
| `cyxtoken_supply_staked` | Gauge | Staked tokens |
| `cyxtoken_supply_burned` | Counter | Total burned |
| `cyxtoken_tx_total` | Counter | Transactions processed |
| `cyxtoken_tx_pending` | Gauge | Mempool size |
| `cyxtoken_block_height` | Gauge | Current block height |
| `cyxtoken_block_time_ms` | Histogram | Block production time |
| `cyxtoken_validator_count` | Gauge | Active validators |
| `cyxtoken_escrow_active` | Gauge | Active escrows |

### Health Checks
```c
typedef struct {
    bool consensus_healthy;     // Producing blocks?
    bool mempool_healthy;       // Not overloaded?
    uint64_t block_height;      // Current height
    uint64_t last_block_time;   // When last block produced
    uint32_t validator_count;   // Active validators
    uint32_t peer_count;        // Connected peers
} cyxtoken_health_t;

int cyxtoken_health_check(cyxtoken_health_t* health) {
    health->block_height = cyxtoken_get_height();
    health->last_block_time = cyxtoken_get_last_block_time();
    health->consensus_healthy = (now() - health->last_block_time) < 60;
    health->mempool_healthy = mempool_count < MAX_MEMPOOL * 0.9;
    health->validator_count = cyxtoken_active_validators();
    health->peer_count = cyxwiz_peer_count();
    return CYXTOKEN_OK;
}
```

### Logging

| Level | When to Use | Examples |
|-------|-------------|----------|
| ERROR | Critical failures | Consensus halt, double spend detected |
| WARN | Anomalies | High mempool, validator timeout |
| INFO | Normal ops | Block produced, TX confirmed |
| DEBUG | Troubleshooting | Vote details, signature verification |

---

## Inflation Schedule

### Emission Curve
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Token Emission Over Time                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Year 1: Bootstrap Phase                                            │
│  ───────────────────────                                            │
│  • Emission: 10 CYX/hour/core (hosting)                             │
│  • Purpose: Incentivize early adopters                              │
│  • Expected supply: ~5M CYX                                          │
│                                                                      │
│  Year 2-3: Growth Phase                                             │
│  ──────────────────────                                             │
│  • Emission decays 1% monthly                                       │
│  • By end of Y3: ~5.5 CYX/hour/core                                 │
│  • Expected supply: ~15M CYX                                         │
│                                                                      │
│  Year 4-10: Maturity Phase                                          │
│  ────────────────────────                                           │
│  • Emission continues decaying                                      │
│  • By Y10: ~2 CYX/hour/core                                         │
│  • Burn rate approaches emission                                    │
│  • Expected supply: ~50M CYX (plateau)                              │
│                                                                      │
│  Long-term: Equilibrium                                             │
│  ──────────────────────                                             │
│  • Emission ≈ Burn (stable supply)                                  │
│  • Emission floor: 0.5 CYX/hour/core                                │
│  • Never fully zero (incentive must exist)                          │
│                                                                      │
│  Emission Formula:                                                   │
│  emission_rate = base_rate * (0.99 ^ months_since_genesis)          │
│  emission_rate = max(emission_rate, floor_rate)                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Emission by Activity
```c
// Emission rates (in CYX units, 1 CYX = 10^8 units)
typedef struct {
    uint64_t hosting_per_cpu_hour;     // Base: 10 CYX
    uint64_t storage_per_gb_day;       // Base: 5 CYX
    uint64_t relay_per_gb;             // Base: 1 CYX
    uint64_t validation_per_round;     // Base: 2 CYX
    uint64_t decay_per_month_ppm;      // 10000 = 1%
    uint64_t floor_multiplier_ppm;     // 50000 = 5% of base
} cyxtoken_emission_params_t;

uint64_t cyxtoken_current_emission_rate(cyxtoken_emission_params_t* params,
                                         uint64_t months_since_genesis) {
    // Apply monthly decay
    uint64_t rate = params->hosting_per_cpu_hour;
    for (uint64_t m = 0; m < months_since_genesis; m++) {
        rate = rate * (1000000 - params->decay_per_month_ppm) / 1000000;
    }

    // Apply floor
    uint64_t floor = params->hosting_per_cpu_hour *
                     params->floor_multiplier_ppm / 1000000;
    return rate > floor ? rate : floor;
}
```

---

## Governance Model

### Parameter Changes
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Governance Parameters                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Changeable by Governance:                                          │
│  • Emission rates (within bounds)                                   │
│  • Burn percentage (25-75%)                                         │
│  • Minimum stake amounts                                            │
│  • Unbonding periods                                                │
│  • Slashing percentages                                             │
│  • Block time target                                                │
│  • Maximum validators                                               │
│                                                                      │
│  NOT Changeable (Hardcoded):                                        │
│  • Maximum supply formula                                           │
│  • Signature algorithm (Ed25519)                                    │
│  • Hash function (SHA256)                                           │
│  • Core protocol structure                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Proposal Process
```c
// Governance proposal
typedef struct {
    uint8_t proposal_id[32];
    char title[128];
    char description[1024];

    // What parameter to change
    char parameter[64];
    uint64_t old_value;
    uint64_t new_value;

    // Voting
    uint64_t voting_start;
    uint64_t voting_end;
    uint64_t votes_for;
    uint64_t votes_against;
    uint64_t quorum_required;       // Minimum participation
    uint64_t approval_required;     // % needed to pass

    // Proposer
    uint8_t proposer[20];
    uint64_t deposit;               // Returned if passes
} cyxtoken_proposal_t;

// Voting weights
// 1 staked CYX = 1 vote
// Must be validator to propose
// Proposal requires deposit (slashed if spam)
```

### Voting Rules
```
┌─────────────────────────────────────────────────────────────────────┐
│                      Voting Parameters                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Proposal Deposit:      100 CYX (returned if passes or quorum met) │
│  Voting Period:         14 days                                     │
│  Quorum:               33% of staked CYX must vote                 │
│  Approval Threshold:   66% of votes must be FOR                    │
│  Implementation Delay: 7 days after approval                       │
│                                                                      │
│  Who Can Vote:         Anyone with staked CYX                      │
│  Who Can Propose:      Validators only                             │
│                                                                      │
│  Vote Options:                                                       │
│  • FOR     - Support the proposal                                   │
│  • AGAINST - Oppose the proposal                                    │
│  • ABSTAIN - Count toward quorum but not approval                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Anonymous Transfers

### Stealth Addresses
```c
// Stealth address protocol (one-time addresses)
typedef struct {
    uint8_t scan_pubkey[32];    // For scanning blockchain
    uint8_t spend_pubkey[32];   // For spending received funds
} cyxtoken_stealth_meta_t;

// Generate one-time address for receiver
int cyxtoken_stealth_generate(const cyxtoken_stealth_meta_t* receiver,
                               uint8_t* one_time_address,
                               uint8_t* tx_pubkey) {
    // 1. Generate ephemeral keypair
    uint8_t r[32], R[32];
    crypto_scalarmult_base(R, r);  // R = r*G

    // 2. Compute shared secret
    uint8_t shared[32];
    crypto_scalarmult(shared, r, receiver->scan_pubkey);  // shared = r*S

    // 3. Derive one-time address
    uint8_t hash[32];
    crypto_hash(hash, shared, 32);
    // P = H(shared)*G + spend_pubkey
    crypto_scalarmult_base(one_time_address, hash);
    for (int i = 0; i < 32; i++) {
        one_time_address[i] ^= receiver->spend_pubkey[i];
    }

    memcpy(tx_pubkey, R, 32);  // Include in transaction
    return CYXTOKEN_OK;
}
```

### Future Privacy Enhancements

#### Confidential Transactions
```
┌─────────────────────────────────────────────────────────────────────┐
│                  Confidential Transactions (Future)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Goal: Hide transaction amounts while proving validity              │
│                                                                      │
│  Technique: Pedersen Commitments                                    │
│  ─────────────────────────────                                      │
│  • Amount committed as: C = amount*G + blinding*H                   │
│  • Validators can verify: sum(inputs) = sum(outputs)               │
│  • But cannot see individual amounts                                │
│                                                                      │
│  Range Proofs:                                                       │
│  ─────────────                                                       │
│  • Prove amount is non-negative without revealing                   │
│  • Bulletproofs for efficiency                                      │
│                                                                      │
│  Trade-offs:                                                         │
│  • Larger transactions (~2KB vs 512 bytes)                          │
│  • Slower verification                                              │
│  • Optional (users choose privacy level)                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Fee Market

### Dynamic Fee Calculation
```c
// Base fee adjusts based on block utilization
typedef struct {
    uint64_t base_fee;          // Current base fee
    uint64_t min_fee;           // Floor (0.001 CYX)
    uint64_t max_fee;           // Ceiling (1 CYX)
    uint64_t target_utilization; // Target block fill (50%)
    uint64_t adjustment_rate;    // How fast fee changes
} cyxtoken_fee_params_t;

uint64_t cyxtoken_calculate_base_fee(cyxtoken_fee_params_t* params,
                                      uint64_t last_block_utilization) {
    uint64_t new_fee = params->base_fee;

    if (last_block_utilization > params->target_utilization) {
        // Block was full, increase fee
        uint64_t excess = last_block_utilization - params->target_utilization;
        new_fee += (params->base_fee * excess * params->adjustment_rate) / 1000000;
    } else {
        // Block had space, decrease fee
        uint64_t slack = params->target_utilization - last_block_utilization;
        new_fee -= (params->base_fee * slack * params->adjustment_rate) / 1000000;
    }

    // Clamp to bounds
    if (new_fee < params->min_fee) new_fee = params->min_fee;
    if (new_fee > params->max_fee) new_fee = params->max_fee;

    return new_fee;
}
```

### Fee Distribution
```
┌─────────────────────────────────────────────────────────────────────┐
│                      Fee Distribution                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Transaction Fee Breakdown:                                         │
│  ──────────────────────────                                         │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐│
│  │                    Total Fee: 0.01 CYX                         ││
│  ├────────────────────────────────────────────────────────────────┤│
│  │  Block Proposer:    50%  (0.005 CYX)                          ││
│  │  All Validators:    30%  (0.003 CYX, split by stake)          ││
│  │  Burned:            20%  (0.002 CYX)                          ││
│  └────────────────────────────────────────────────────────────────┘│
│                                                                      │
│  This creates incentives for:                                       │
│  • Validators to include transactions                               │
│  • Deflationary pressure (burn)                                     │
│  • Network security (validator rewards)                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Priority Tiers
```c
// Users can specify priority
typedef enum {
    CYXTOKEN_PRIORITY_LOW,      // 1x base fee (may wait)
    CYXTOKEN_PRIORITY_NORMAL,   // 1.5x base fee (next few blocks)
    CYXTOKEN_PRIORITY_HIGH,     // 2x base fee (next block)
    CYXTOKEN_PRIORITY_URGENT,   // 5x base fee (immediate)
} cyxtoken_priority_t;

uint64_t cyxtoken_recommended_fee(cyxtoken_priority_t priority) {
    uint64_t base = cyxtoken_get_base_fee();
    switch (priority) {
        case CYXTOKEN_PRIORITY_LOW:    return base;
        case CYXTOKEN_PRIORITY_NORMAL: return base * 3 / 2;
        case CYXTOKEN_PRIORITY_HIGH:   return base * 2;
        case CYXTOKEN_PRIORITY_URGENT: return base * 5;
    }
    return base;
}
```
