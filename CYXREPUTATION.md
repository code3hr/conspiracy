# CyxReputation Design Document

## Philosophy

```
"Own Nothing. Access Everything. Leave No Trace."
              │
              ▼
    ┌─────────────────┐
    │  CyxReputation  │
    │                 │
    │  Trust without  │
    │  identity.      │
    │                 │
    │  Prove yourself │
    │  by actions,    │
    │  not papers.    │
    └─────────────────┘
```

CyxReputation is a decentralized trust system that allows nodes to build and verify reputation without revealing identity. Reputation is earned through consistent, verifiable good behavior and lost through bad behavior.

## Overview

### The Problem

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Trust Without Identity                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Traditional Trust:                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Real Name + ID + History = Trust Score                      │   │
│  │                                                              │   │
│  │  Problems:                                                   │   │
│  │  • Requires identity (violates privacy)                     │   │
│  │  • Centralized (Yelp, credit bureaus)                       │   │
│  │  • Can be gamed (fake reviews)                              │   │
│  │  • Hard to recover from (one bad mark = forever)            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  CyxWiz Challenge:                                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  How do we trust anonymous nodes?                           │   │
│  │  • Host: Will they keep my container running?               │   │
│  │  • Storage: Will they keep my data available?               │   │
│  │  • Relay: Will they forward my traffic reliably?            │   │
│  │  • User: Will they pay for services?                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Solution: Reputation based on verifiable on-chain behavior        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### The Solution

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CyxReputation Model                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Reputation = f(Stake, History, Challenges, Feedback)               │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  ┌──────────────┐                                           │   │
│  │  │    Stake     │  "Skin in the game"                       │   │
│  │  │   (20%)      │  More stake = more to lose                │   │
│  │  └──────────────┘                                           │   │
│  │         +                                                    │   │
│  │  ┌──────────────┐                                           │   │
│  │  │   History    │  "Track record"                           │   │
│  │  │   (40%)      │  Successful services over time            │   │
│  │  └──────────────┘                                           │   │
│  │         +                                                    │   │
│  │  ┌──────────────┐                                           │   │
│  │  │  Challenges  │  "Proof of capability"                    │   │
│  │  │   (25%)      │  Passed validator challenges              │   │
│  │  └──────────────┘                                           │   │
│  │         +                                                    │   │
│  │  ┌──────────────┐                                           │   │
│  │  │   Feedback   │  "Peer review"                            │   │
│  │  │   (15%)      │  Ratings from service users               │   │
│  │  └──────────────┘                                           │   │
│  │         =                                                    │   │
│  │  ┌──────────────┐                                           │   │
│  │  │  REPUTATION  │  0-100 score                              │   │
│  │  │    SCORE     │                                           │   │
│  │  └──────────────┘                                           │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Score Components

### 1. Stake Component (20%)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Stake Component                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Principle: "Put your money where your mouth is"                    │
│                                                                      │
│  More stake = More trustworthy (more to lose if misbehaving)       │
│                                                                      │
│  Formula:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  stake_score = min(100, (stake / reference_stake) * 100)    │   │
│  │                                                              │   │
│  │  Where reference_stake varies by role:                      │   │
│  │  • Host: 5,000 CYX (for 100 points)                         │   │
│  │  • Relay: 10,000 CYX                                        │   │
│  │  • Validator: 20,000 CYX                                    │   │
│  │  • Storage: 2,500 CYX                                       │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Examples:                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Host with 1,000 CYX stake:  1000/5000 * 100 = 20 points    │   │
│  │  Host with 5,000 CYX stake:  5000/5000 * 100 = 100 points   │   │
│  │  Host with 10,000 CYX stake: capped at 100 points           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Weighted contribution: stake_score * 0.20                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2. History Component (40%)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    History Component                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Principle: "Past behavior predicts future behavior"                │
│                                                                      │
│  Tracks successful vs failed service completions over time         │
│                                                                      │
│  Formula:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  success_rate = successful_services / total_services        │   │
│  │  age_factor = min(1, days_active / 180)  // Max at 6 months │   │
│  │  volume_factor = min(1, total_services / 100)  // Max at 100│   │
│  │                                                              │   │
│  │  history_score = success_rate * age_factor * volume_factor  │   │
│  │                  * 100                                       │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  What counts as "successful":                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Host:                                                       │   │
│  │  ✓ Container ran for full rental period                     │   │
│  │  ✓ All uptime proofs submitted                              │   │
│  │  ✓ No disputes filed (or disputes resolved in favor)        │   │
│  │                                                              │   │
│  │  Storage:                                                    │   │
│  │  ✓ Data available when requested                            │   │
│  │  ✓ All availability challenges passed                       │   │
│  │  ✓ Data returned correctly                                  │   │
│  │                                                              │   │
│  │  Relay:                                                      │   │
│  │  ✓ Traffic forwarded successfully                           │   │
│  │  ✓ Latency within acceptable range                          │   │
│  │  ✓ No tampering detected                                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Time decay: Recent history weighted more than old history         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  weight(service) = 0.95^(days_ago / 7)                      │   │
│  │  • Service from today: weight = 1.0                         │   │
│  │  • Service from 1 week ago: weight = 0.95                   │   │
│  │  • Service from 1 month ago: weight = 0.81                  │   │
│  │  • Service from 6 months ago: weight = 0.27                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Weighted contribution: history_score * 0.40                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 3. Challenge Component (25%)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Challenge Component                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Principle: "Prove you can do what you claim"                       │
│                                                                      │
│  Validators periodically challenge nodes to prove capability       │
│                                                                      │
│  Challenge Types:                                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Availability Challenge (all roles):                        │   │
│  │  "Are you online right now?"                                │   │
│  │  - Random pings, must respond within 30 seconds             │   │
│  │                                                              │   │
│  │  Compute Challenge (hosts):                                  │   │
│  │  "Can you compute X within Y time?"                         │   │
│  │  - Hash computation benchmark                                │   │
│  │  - Verifies claimed CPU capacity                            │   │
│  │                                                              │   │
│  │  Storage Challenge (storage providers):                      │   │
│  │  "Do you still have this data?"                             │   │
│  │  - Must return hash of (share + nonce)                      │   │
│  │  - Proves data hasn't been deleted                          │   │
│  │                                                              │   │
│  │  Bandwidth Challenge (relays):                               │   │
│  │  "Transfer this data at promised speed"                     │   │
│  │  - Measure actual throughput                                │   │
│  │  - Verify claimed bandwidth                                 │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Formula:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  challenge_score = (passed_challenges / total_challenges)   │   │
│  │                    * 100                                     │   │
│  │                                                              │   │
│  │  Only challenges from last 30 days counted                  │   │
│  │  Minimum 10 challenges required for reliable score          │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Failure Penalties:                                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  1st failure: Warning, -5 points                            │   │
│  │  2nd failure: -10 points                                    │   │
│  │  3rd failure: -20 points + temporary suspension             │   │
│  │  Persistent failures: Slashing consideration                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Weighted contribution: challenge_score * 0.25                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4. Feedback Component (15%)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Feedback Component                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Principle: "Let users vote with their experience"                  │
│                                                                      │
│  Users can rate providers after service completion                 │
│                                                                      │
│  Rating Scale:                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ⭐⭐⭐⭐⭐ (5) - Excellent, exceeded expectations            │   │
│  │  ⭐⭐⭐⭐   (4) - Good, met expectations                      │   │
│  │  ⭐⭐⭐     (3) - Acceptable, some issues                     │   │
│  │  ⭐⭐       (2) - Poor, significant issues                    │   │
│  │  ⭐         (1) - Failed, do not use                          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Anti-Gaming Measures:                                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  1. Sybil Resistance                                        │   │
│  │     - Only users who completed service can rate             │   │
│  │     - One rating per service instance                       │   │
│  │     - Rating linked to on-chain service record              │   │
│  │                                                              │   │
│  │  2. Reputation-Weighted                                      │   │
│  │     - Ratings from high-rep users count more                │   │
│  │     - New accounts have less influence                      │   │
│  │     weight = sqrt(rater_reputation / 100)                   │   │
│  │                                                              │   │
│  │  3. Stake-Weighted                                           │   │
│  │     - Users with more at stake = more trusted ratings       │   │
│  │     - Prevents cheap fake reviews                           │   │
│  │                                                              │   │
│  │  4. Outlier Filtering                                        │   │
│  │     - Remove statistical outliers                           │   │
│  │     - 1 bad review among 100 good = probably noise          │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Formula:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  weighted_sum = Σ(rating * weight)                          │   │
│  │  total_weight = Σ(weight)                                   │   │
│  │  avg_rating = weighted_sum / total_weight                   │   │
│  │                                                              │   │
│  │  feedback_score = (avg_rating - 1) / 4 * 100                │   │
│  │  // Maps 1-5 rating to 0-100 score                          │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Weighted contribution: feedback_score * 0.15                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Final Score Calculation

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Final Reputation Score                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  reputation = (stake_score * 0.20) +                                │
│               (history_score * 0.40) +                              │
│               (challenge_score * 0.25) +                            │
│               (feedback_score * 0.15)                               │
│                                                                      │
│  Score Interpretation:                                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  90-100: Excellent  ⭐⭐⭐⭐⭐  Premium tier, priority routing │   │
│  │  75-89:  Good       ⭐⭐⭐⭐    Reliable, recommended         │   │
│  │  60-74:  Average    ⭐⭐⭐      Acceptable, some caution       │   │
│  │  40-59:  Below Avg  ⭐⭐        Use with caution               │   │
│  │  20-39:  Poor       ⭐          Consider alternatives          │   │
│  │  0-19:   Critical   ⚠️          Avoid, may be slashed soon     │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Example Calculation:                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Host "abc123":                                              │   │
│  │                                                              │   │
│  │  Stake: 3,000 CYX → 60/100 * 0.20 = 12.0                    │   │
│  │  History: 95% success, 4 months, 50 services                │   │
│  │           → 85/100 * 0.40 = 34.0                            │   │
│  │  Challenges: 48/50 passed → 96/100 * 0.25 = 24.0            │   │
│  │  Feedback: 4.2 average rating → 80/100 * 0.15 = 12.0        │   │
│  │                                                              │   │
│  │  TOTAL: 12.0 + 34.0 + 24.0 + 12.0 = 82.0                    │   │
│  │  Rating: GOOD ⭐⭐⭐⭐                                         │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Structures

```c
// Reputation score breakdown
typedef struct {
    uint8_t total;              // 0-100 final score
    uint8_t stake_score;        // 0-100
    uint8_t history_score;      // 0-100
    uint8_t challenge_score;    // 0-100
    uint8_t feedback_score;     // 0-100
} cyxrep_score_t;

// Service record (on-chain)
typedef struct {
    uint8_t service_id[32];     // Unique service identifier
    cyxwiz_node_id_t provider;  // Who provided
    cyxwiz_node_id_t user;      // Who used (can be anonymous)
    uint8_t service_type;       // HOST, STORAGE, RELAY
    uint64_t started_at;        // Unix timestamp
    uint64_t ended_at;          // Unix timestamp
    uint8_t outcome;            // SUCCESS, FAILED, DISPUTED
    uint8_t user_rating;        // 1-5 (0 = not rated)
} cyxrep_service_record_t;

// Challenge record
typedef struct {
    uint8_t challenge_id[32];
    cyxwiz_node_id_t node;      // Who was challenged
    cyxwiz_node_id_t validator; // Who challenged
    uint8_t challenge_type;     // AVAILABILITY, COMPUTE, STORAGE, BANDWIDTH
    uint64_t timestamp;
    bool passed;
    uint32_t response_time_ms;  // How fast they responded
} cyxrep_challenge_record_t;

// Node reputation state
typedef struct {
    cyxwiz_node_id_t node_id;

    // Current scores
    cyxrep_score_t score;

    // Stake info
    uint64_t stake_amount;
    uint64_t stake_locked_until;

    // History stats
    uint32_t total_services;
    uint32_t successful_services;
    uint64_t first_service_at;

    // Challenge stats
    uint32_t challenges_received;
    uint32_t challenges_passed;
    uint64_t last_challenge_at;

    // Feedback stats
    uint32_t ratings_received;
    uint64_t rating_sum;        // For calculating average
} cyxrep_state_t;
```

## API Functions

```c
// Get reputation score
int cyxrep_get_score(const cyxwiz_node_id_t* node,
                      cyxrep_score_t* score);

// Get detailed reputation state
int cyxrep_get_state(const cyxwiz_node_id_t* node,
                      cyxrep_state_t* state);

// Record service completion
int cyxrep_record_service(cyxrep_service_record_t* record);

// Submit user rating
int cyxrep_submit_rating(const uint8_t* service_id,
                          uint8_t rating);

// Challenge a node (validators only)
int cyxrep_issue_challenge(const cyxwiz_node_id_t* node,
                            uint8_t challenge_type);

// Respond to challenge
int cyxrep_respond_challenge(const uint8_t* challenge_id,
                              const uint8_t* response,
                              size_t response_len);

// Verify challenge response (validators)
int cyxrep_verify_challenge(const uint8_t* challenge_id,
                             const uint8_t* response,
                             bool* passed);
```

## Reputation Recovery

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Reputation Recovery                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Lost reputation CAN be recovered through consistent good behavior  │
│                                                                      │
│  Recovery Mechanisms:                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  1. Time Decay of Negative Events                           │   │
│  │     - Bad events lose weight over time                      │   │
│  │     - After 6 months, old failures barely count             │   │
│  │     - Fresh start possible with patience                    │   │
│  │                                                              │   │
│  │  2. Increased Stake                                          │   │
│  │     - Add more stake to boost stake component               │   │
│  │     - Shows commitment to good behavior                     │   │
│  │     - Immediate partial recovery                            │   │
│  │                                                              │   │
│  │  3. Consistent Performance                                   │   │
│  │     - Every successful service helps                        │   │
│  │     - Every passed challenge helps                          │   │
│  │     - Cumulative improvement                                │   │
│  │                                                              │   │
│  │  4. Appeal Process                                           │   │
│  │     - For false accusations                                 │   │
│  │     - Requires evidence submission                          │   │
│  │     - Validators review and decide                          │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  What CANNOT be recovered:                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Slashed stake (gone forever)                             │   │
│  │  • Proven malicious behavior (permanent record)             │   │
│  │  • Validator consensus on bad faith                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## CLI Commands

```bash
# Check your reputation
cyxrep score
# Output:
# Node: a3f8c21d7b92...
# Role: Host
#
# REPUTATION: 82/100 ⭐⭐⭐⭐ (Good)
#
# Breakdown:
#   Stake:      60/100 (3,000 CYX staked)       × 0.20 = 12.0
#   History:    85/100 (95% success, 4 months)  × 0.40 = 34.0
#   Challenges: 96/100 (48/50 passed)           × 0.25 = 24.0
#   Feedback:   80/100 (4.2 avg rating)         × 0.15 = 12.0
#                                               ─────────────
#                                       Total:         82.0

# Check another node's reputation
cyxrep lookup b7e2d1f8a3c9...
# Output:
# Node: b7e2d1f8a3c9...
# Role: Storage Provider
# REPUTATION: 71/100 ⭐⭐⭐ (Average)
# Active since: 45 days ago
# Services completed: 23
# Recent issues: 2 availability failures

# View service history
cyxrep history
# Output:
# Service ID        Type    Duration  Outcome    Rating  Date
# abc123...         HOST    1 day     SUCCESS    ⭐⭐⭐⭐  2 days ago
# def456...         HOST    1 hour    SUCCESS    ⭐⭐⭐⭐⭐ 5 days ago
# ghi789...         HOST    1 week    DISPUTED   -       2 weeks ago
# ...

# View challenge history
cyxrep challenges
# Output:
# Challenge ID      Type          Result    Response Time  Date
# xyz123...         AVAILABILITY  PASSED    45ms           1 hour ago
# uvw456...         COMPUTE       PASSED    1.2s           3 hours ago
# rst789...         AVAILABILITY  FAILED    TIMEOUT        1 day ago
# ...

# Rate a provider (after service)
cyxrep rate abc123... 4 --comment "Good uptime, slight latency"
# Output:
# Rating submitted: 4/5 stars for service abc123...
# Thank you for your feedback!
```

## Implementation Files

```
include/cyxwiz/
├── cyxrep.h            # Main reputation header
├── cyxrep_score.h      # Score calculation
├── cyxrep_challenge.h  # Challenge system
└── cyxrep_feedback.h   # Feedback/rating system

src/reputation/
├── score.c             # Score calculation
├── history.c           # Service history tracking
├── challenge.c         # Challenge issuance/response
├── feedback.c          # Rating system
└── recovery.c          # Reputation recovery logic

tools/
└── cyxrep.c            # CLI tool
```

## Open Questions

1. **Cold Start**: How do new nodes build reputation from zero?
   - Grace period with limited capacity?
   - Mentorship from established nodes?

2. **Sybil Attacks**: What prevents creating many identities?
   - Stake requirement
   - Time-based reputation building
   - Challenge difficulty for new nodes?

3. **Rating Collusion**: What if users and providers collude on ratings?
   - Random challenge verification
   - Cross-reference with on-chain data

4. **Score Manipulation**: Can validators manipulate scores?
   - Multiple independent validators
   - Score calculation is deterministic
   - Validator reputation affects trust in challenges

5. **Privacy**: How much reputation data is public?
   - Score is public
   - Individual ratings anonymous?
   - Service details private?

---

## Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Sybil Attack | Create many fake identities | High |
| Score Manipulation | False ratings, fake challenges | High |
| Collusion | Users + providers coordinate | Medium |
| Eclipse | Control all of victim's raters | High |
| Griefing | False negative reviews | Medium |
| Gaming | Exploit formula weaknesses | Medium |

### Detailed Threat Analysis

#### Sybil Attack
- **Description**: Attacker creates many fake nodes to boost reputation
- **Attacker**: Anyone with resources
- **Prerequisites**: Capital for stakes
- **Impact**: Illegitimate high reputation
- **Likelihood**: Medium (stake cost deters)
- **Mitigation**:
  - Stake requirement for each identity
  - Long reputation building time
  - Network analysis for suspicious patterns
  - Challenge difficulty scales with node count

#### Rating Collusion
- **Description**: Provider and user collude to exchange fake positive ratings
- **Attacker**: Coordinated actors
- **Prerequisites**: Multiple accounts
- **Impact**: Inflated reputation scores
- **Likelihood**: Medium
- **Mitigation**:
  - Ratings weighted by rater's reputation
  - Statistical anomaly detection
  - Challenge scores can't be faked
  - Service must have on-chain proof

#### Validator Manipulation
- **Description**: Validator issues unfair challenges or false failures
- **Attacker**: Malicious validator
- **Prerequisites**: Validator status
- **Impact**: Unfair reputation damage
- **Likelihood**: Low (validator reputation at stake)
- **Mitigation**:
  - Multiple validators per challenge
  - Appeal process with evidence
  - Validator reputation affected by disputed decisions
  - Deterministic challenge verification

#### Griefing (False Negatives)
- **Description**: Competitor leaves false negative reviews
- **Attacker**: Competing provider
- **Prerequisites**: Complete service
- **Impact**: Unfair reputation damage
- **Likelihood**: Medium
- **Mitigation**:
  - Ratings weighted by rater reputation
  - Outlier filtering
  - One rating per service (can't spam)
  - Appeal process

### Security Assumptions
1. Stake requirement makes Sybil attacks costly
2. Majority of validators are honest
3. Challenge verification is deterministic
4. On-chain records are immutable
5. Statistical analysis can detect anomalies

### Trust Boundaries
```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│  Individual      │        │  Validator       │        │  Consensus       │
│  Nodes           │───────►│  Network         │───────►│  (Final Score)   │
│  (self-report)   │        │  (verification)  │        │                  │
└──────────────────┘        └──────────────────┘        └──────────────────┘
        │                            │                           │
   TRUST BOUNDARY 1            TRUST BOUNDARY 2           TRUST BOUNDARY 3
   (unverified claims)         (validated data)          (immutable record)
```

---

## Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| Score DB | Corruption | Wrong scores | Hash mismatch | Rebuild from chain |
| Validator | Offline | Challenges fail | Timeout | Use alternate |
| Challenge | Timeout | Miss deadline | Timer | Auto-retry |
| Rating | Lost | Not recorded | Tx fail | Resubmit |
| History | Incomplete | Missing records | Sync check | Resync from peers |

### Recovery Procedures

#### Score Corruption Recovery
```c
// Rebuild reputation from on-chain data
int cyxrep_rebuild_from_chain(cyxwiz_node_id_t* node) {
    cyxrep_state_t state = {0};
    memcpy(&state.node_id, node, sizeof(cyxwiz_node_id_t));

    // 1. Get stake from token module
    state.stake_amount = cyxtoken_get_stake(node);

    // 2. Replay all service records
    cyxrep_service_record_t records[1000];
    int count = cyxrep_get_all_services(node, records, 1000);

    for (int i = 0; i < count; i++) {
        if (records[i].outcome == CYXREP_SUCCESS) {
            state.successful_services++;
        }
        state.total_services++;

        if (state.first_service_at == 0 || records[i].started_at < state.first_service_at) {
            state.first_service_at = records[i].started_at;
        }

        if (records[i].user_rating > 0) {
            state.ratings_received++;
            state.rating_sum += records[i].user_rating;
        }
    }

    // 3. Replay all challenge records
    cyxrep_challenge_record_t challenges[1000];
    int challenge_count = cyxrep_get_all_challenges(node, challenges, 1000);

    for (int i = 0; i < challenge_count; i++) {
        state.challenges_received++;
        if (challenges[i].passed) {
            state.challenges_passed++;
        }
    }

    // 4. Recalculate score
    cyxrep_calculate_score(&state);

    // 5. Store rebuilt state
    cyxrep_store_state(&state);

    return CYXREP_OK;
}
```

#### Missed Challenge Recovery
```c
// Handle missed challenge (node was offline)
int cyxrep_handle_missed_challenge(const uint8_t* challenge_id) {
    cyxrep_challenge_record_t challenge;
    cyxrep_get_challenge(challenge_id, &challenge);

    // Check if within grace period (5 minutes)
    if (now() - challenge.timestamp < 300) {
        // Still can respond
        return cyxrep_respond_challenge(challenge_id, generate_response(&challenge));
    }

    // Missed permanently - penalty applied
    // But check for extenuating circumstances
    if (was_network_partition_active(challenge.timestamp)) {
        // Network issue - request review
        cyxrep_request_challenge_review(challenge_id, CYXREP_REASON_NETWORK_PARTITION);
        return CYXREP_UNDER_REVIEW;
    }

    // Accept penalty
    return CYXREP_CHALLENGE_FAILED;
}
```

### What Cannot Be Recovered
- Slashed stake (permanently burned)
- Proven malicious behavior records
- Time lost during reputation building

---

## Protocol Versioning

### Version Format
```
CyxReputation Protocol: Major.Minor.Patch (SemVer)
Example: 1.0.0
```

### Score Algorithm Versioning
```c
// Score calculation includes version
typedef struct {
    uint8_t algorithm_version;  // Which formula version
    uint8_t total;
    // ... rest of score
} cyxrep_score_t;

// Version history
// v1.0: Initial formula (stake 20%, history 40%, challenge 25%, feedback 15%)
// v1.1: Added time decay for negative events
// v2.0: Changed challenge weight to 30%, reduced feedback to 10%

// Scores are recalculated on version change
void cyxrep_on_version_upgrade(uint8_t old_version, uint8_t new_version) {
    // Recalculate all scores with new formula
    for (int i = 0; i < node_count; i++) {
        cyxrep_recalculate_score(&nodes[i], new_version);
    }
}
```

### Backwards Compatibility

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| Weight adjustment | Minor | No (recalculate) |
| New component | Major | Yes |
| Remove component | Major | Yes |
| API change | Major | Yes |

### Governance for Changes
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Score Formula Changes                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Process:                                                           │
│  1. Proposal submitted with rationale                               │
│  2. 14-day discussion period                                        │
│  3. Validator vote (requires 66% approval)                         │
│  4. 30-day notice before implementation                             │
│  5. Simultaneous recalculation for all nodes                        │
│                                                                      │
│  Constraints:                                                        │
│  • No single component can exceed 50%                               │
│  • Stake component minimum 10%                                      │
│  • Must maintain Sybil resistance properties                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Rate Limiting & DoS Protection

### Rating Limits

| Operation | Limit | Window | Enforcement |
|-----------|-------|--------|-------------|
| Submit rating | 10/hour | 1 hour | Queue excess |
| Query score | 100/min | 1 min | Cache |
| Issue challenge | 5/hour/node | 1 hour | Reject |
| Appeal | 1/week/node | 7 days | Reject |

### Challenge Limits
```c
// Prevent challenge flooding
typedef struct {
    cyxwiz_node_id_t target;
    uint32_t challenges_today;
    uint64_t last_challenge_at;
} challenge_rate_t;

int cyxrep_check_challenge_limit(cyxwiz_node_id_t* target) {
    challenge_rate_t* limit = get_challenge_limit(target);

    // Max 24 challenges per day per node
    if (limit->challenges_today >= 24) {
        return CYXREP_RATE_LIMITED;
    }

    // Minimum 1 hour between challenges from same validator
    if (now() - limit->last_challenge_at < 3600) {
        return CYXREP_TOO_SOON;
    }

    limit->challenges_today++;
    limit->last_challenge_at = now();
    return CYXREP_OK;
}
```

### Anti-Spam for Ratings
```c
// Prevent rating spam
int cyxrep_validate_rating(const uint8_t* service_id, uint8_t rating) {
    // 1. Verify service exists and is completed
    cyxrep_service_record_t record;
    if (cyxrep_get_service(service_id, &record) != CYXREP_OK) {
        return CYXREP_INVALID_SERVICE;
    }

    if (record.outcome == CYXREP_ONGOING) {
        return CYXREP_SERVICE_NOT_COMPLETE;
    }

    // 2. Verify caller was the user
    if (memcmp(&record.user, &current_user, sizeof(cyxwiz_node_id_t)) != 0) {
        return CYXREP_NOT_AUTHORIZED;
    }

    // 3. Check if already rated
    if (record.user_rating > 0) {
        return CYXREP_ALREADY_RATED;
    }

    // 4. Rating window (must rate within 7 days)
    if (now() - record.ended_at > 7 * 24 * 3600) {
        return CYXREP_RATING_WINDOW_CLOSED;
    }

    return CYXREP_OK;
}
```

---

## Monitoring & Observability

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cyxrep_scores_distribution` | Histogram | Score distribution |
| `cyxrep_challenges_total` | Counter | Total challenges |
| `cyxrep_challenges_passed` | Counter | Passed challenges |
| `cyxrep_ratings_total` | Counter | Total ratings |
| `cyxrep_ratings_distribution` | Histogram | Rating distribution |
| `cyxrep_appeals_total` | Counter | Appeals submitted |
| `cyxrep_appeals_success_rate` | Gauge | Appeal success % |

### Health Checks
```c
typedef struct {
    uint32_t total_nodes;
    uint32_t active_nodes;          // Score > 0
    float avg_score;
    uint32_t challenges_today;
    uint32_t ratings_today;
    uint32_t pending_appeals;
} cyxrep_health_t;

int cyxrep_health_check(cyxrep_health_t* health) {
    health->total_nodes = count_all_nodes();
    health->active_nodes = count_active_nodes();
    health->avg_score = calculate_average_score();
    health->challenges_today = count_challenges_today();
    health->ratings_today = count_ratings_today();
    health->pending_appeals = count_pending_appeals();
    return CYXREP_OK;
}
```

### Logging

| Level | When to Use | Examples |
|-------|-------------|----------|
| ERROR | Score corruption, consensus failure | Invalid score hash |
| WARN | Suspicious patterns, appeals | Multiple 1-star ratings |
| INFO | Normal operations | Challenge passed, rating submitted |
| DEBUG | Algorithm details | Weight calculations |

### Anomaly Detection
```c
// Detect suspicious patterns
typedef struct {
    cyxwiz_node_id_t node;
    float anomaly_score;        // 0-1, higher = more suspicious
    char reason[256];
} cyxrep_anomaly_t;

void cyxrep_detect_anomalies(cyxrep_anomaly_t* anomalies, int* count) {
    *count = 0;

    for (int i = 0; i < node_count; i++) {
        cyxrep_state_t* state = &nodes[i];

        // Check for rating collusion (same users always rate high)
        float rating_entropy = calculate_rating_entropy(state);
        if (rating_entropy < 0.3) {
            anomalies[*count].node = state->node_id;
            anomalies[*count].anomaly_score = 1.0 - rating_entropy;
            snprintf(anomalies[*count].reason, 256,
                     "Low rating entropy (%.2f), possible collusion", rating_entropy);
            (*count)++;
        }

        // Check for suspiciously perfect scores
        if (state->score.total == 100 && state->total_services < 50) {
            anomalies[*count].node = state->node_id;
            anomalies[*count].anomaly_score = 0.7;
            snprintf(anomalies[*count].reason, 256,
                     "Perfect score with low service count");
            (*count)++;
        }
    }
}
```

---

## Cold Start Solution

### New Node Bootstrap
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Cold Start Problem & Solution                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Problem: New nodes have zero reputation, nobody trusts them        │
│                                                                      │
│  Solution: Probationary Period                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Phase 1: New Node (Days 1-7)                               │   │
│  │  • Default score: 30/100 (Below Average)                    │   │
│  │  • Max service size: 10% of normal                          │   │
│  │  • Higher stake requirement: 2x normal                      │   │
│  │  • More frequent challenges: 4x normal                      │   │
│  │                                                              │   │
│  │  Phase 2: Probationary (Days 8-30)                          │   │
│  │  • Score based on actual performance                        │   │
│  │  • Max service size: 50% of normal                          │   │
│  │  • Normal stake requirement                                 │   │
│  │  • 2x challenge frequency                                   │   │
│  │                                                              │   │
│  │  Phase 3: Established (Day 31+)                             │   │
│  │  • Full capabilities unlocked                               │   │
│  │  • Normal challenge frequency                               │   │
│  │  • Can accept any service size                              │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Vouching System
```c
// Established nodes can vouch for new nodes
typedef struct {
    cyxwiz_node_id_t voucher;       // Who is vouching
    cyxwiz_node_id_t vouchee;       // Who is being vouched for
    uint64_t stake_at_risk;         // Voucher's stake at risk
    uint64_t vouched_at;
    uint64_t expires_at;            // Vouch valid for 30 days
} cyxrep_vouch_t;

int cyxrep_vouch_for(cyxwiz_node_id_t* new_node, uint64_t stake_amount) {
    // 1. Voucher must have high reputation
    cyxrep_score_t voucher_score;
    cyxrep_get_score(&current_node, &voucher_score);
    if (voucher_score.total < 80) {
        return CYXREP_VOUCHER_REP_TOO_LOW;
    }

    // 2. Voucher puts stake at risk
    if (stake_amount < MIN_VOUCH_STAKE) {
        return CYXREP_STAKE_TOO_LOW;
    }

    // 3. Create vouch record
    cyxrep_vouch_t vouch = {
        .voucher = current_node,
        .vouchee = *new_node,
        .stake_at_risk = stake_amount,
        .vouched_at = now(),
        .expires_at = now() + 30 * 24 * 3600
    };
    cyxrep_store_vouch(&vouch);

    // 4. Boost new node's starting reputation
    cyxrep_apply_vouch_boost(new_node, stake_amount);

    return CYXREP_OK;
}

// If vouchee misbehaves, voucher loses stake
void cyxrep_vouch_penalty(cyxwiz_node_id_t* bad_node) {
    cyxrep_vouch_t vouches[10];
    int count = cyxrep_get_active_vouches(bad_node, vouches, 10);

    for (int i = 0; i < count; i++) {
        // Slash voucher's at-risk stake
        cyxtoken_slash(&vouches[i].voucher, vouches[i].stake_at_risk / 2);
        // Remaining goes to impacted users
    }
}
```

---

## Reputation Portability

### Cross-Identity Reputation
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Reputation Portability                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Problem: User wants to change identity but keep reputation         │
│  (privacy rotation, key compromise, etc.)                           │
│                                                                      │
│  Solution: Zero-Knowledge Reputation Proof                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Old Identity                  New Identity                  │   │
│  │  ┌──────────┐                 ┌──────────┐                  │   │
│  │  │ abc123   │                 │ def456   │                  │   │
│  │  │ Rep: 85  │    ZK Proof    │ Rep: 85  │                  │   │
│  │  │          │ ─────────────► │ (same)   │                  │   │
│  │  └──────────┘                 └──────────┘                  │   │
│  │                                                              │   │
│  │  ZK Proof proves:                                           │   │
│  │  1. "I control an identity with score >= X"                 │   │
│  │  2. "That identity has not been slashed"                    │   │
│  │  3. "I'm the rightful owner" (signature)                    │   │
│  │                                                              │   │
│  │  Without revealing:                                          │   │
│  │  • Which old identity                                       │   │
│  │  • Exact score (only range)                                 │   │
│  │  • Service history                                          │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Constraints:                                                        │
│  • Old identity locked (can't use both)                            │
│  • One transfer per identity ever                                  │
│  • New identity starts at 80% of proven score                      │
│  • 30-day cooldown before transfer takes effect                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementation
```c
// Generate ZK proof of reputation
int cyxrep_generate_portability_proof(cyxrep_portability_proof_t* proof,
                                        uint8_t min_score) {
    cyxrep_score_t my_score;
    cyxrep_get_score(&current_node, &my_score);

    if (my_score.total < min_score) {
        return CYXREP_SCORE_TOO_LOW;
    }

    // Generate ZK proof that:
    // 1. We know a valid identity with score >= min_score
    // 2. That identity hasn't been slashed
    // 3. We have the private key

    // Using Schnorr-based ZK proof
    cyxwiz_zkp_prove_range(proof->score_proof, my_score.total, min_score, 100);
    cyxwiz_zkp_prove_membership(proof->not_slashed_proof,
                                 &current_node, slashed_set, false);
    cyxwiz_zkp_prove_ownership(proof->ownership_proof, &current_node);

    return CYXREP_OK;
}

// Apply portability proof to new identity
int cyxrep_apply_portability_proof(cyxwiz_node_id_t* new_identity,
                                     cyxrep_portability_proof_t* proof) {
    // 1. Verify ZK proofs
    if (!cyxwiz_zkp_verify_all(proof)) {
        return CYXREP_INVALID_PROOF;
    }

    // 2. Check proof hasn't been used before
    if (cyxrep_proof_used(proof->hash)) {
        return CYXREP_PROOF_ALREADY_USED;
    }

    // 3. Mark proof as used
    cyxrep_mark_proof_used(proof->hash);

    // 4. Create new identity with transferred score (80%)
    uint8_t transferred_score = proof->proven_min_score * 80 / 100;
    cyxrep_set_initial_score(new_identity, transferred_score);

    return CYXREP_OK;
}
```

---

## Appeals Process

### Dispute Resolution
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Appeals Process                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  When to Appeal:                                                    │
│  • False negative rating you believe was unfair                    │
│  • Challenge failure due to network issues                         │
│  • Service marked failed incorrectly                               │
│  • Suspected coordinated attack on reputation                      │
│                                                                      │
│  Process:                                                           │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                                                              │   │
│  │  Step 1: Submit Appeal (Day 0)                              │   │
│  │  • Describe issue                                           │   │
│  │  • Provide evidence (logs, timestamps, etc.)                │   │
│  │  • Pay appeal fee (refunded if successful)                  │   │
│  │                                                              │   │
│  │  Step 2: Initial Review (Days 1-3)                          │   │
│  │  • Validator committee reviews evidence                     │   │
│  │  • May request additional information                       │   │
│  │  • Decides: Accept, Reject, or Escalate                     │   │
│  │                                                              │   │
│  │  Step 3a: Quick Resolution (Days 4-7)                       │   │
│  │  • Clear cases resolved by committee                        │   │
│  │  • Score adjusted if appeal upheld                          │   │
│  │  • Fee refunded if successful                               │   │
│  │                                                              │   │
│  │  Step 3b: Full Arbitration (Days 4-14)                      │   │
│  │  • Complex cases go to full validator vote                  │   │
│  │  • Both parties can submit arguments                        │   │
│  │  • Majority vote determines outcome                         │   │
│  │                                                              │   │
│  │  Step 4: Final Decision                                      │   │
│  │  • Decision is binding                                      │   │
│  │  • No further appeals (except to governance)                │   │
│  │                                                              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Appeal Data Structure
```c
typedef struct {
    uint8_t appeal_id[32];
    cyxwiz_node_id_t appellant;
    uint8_t appeal_type;            // RATING, CHALLENGE, SERVICE
    uint8_t subject_id[32];         // What's being appealed
    char reason[1024];
    uint8_t evidence_hash[32];      // IPFS/CyxCloud reference
    uint64_t submitted_at;
    uint64_t fee_paid;

    // Resolution
    uint8_t status;                 // PENDING, REVIEWING, RESOLVED
    uint8_t outcome;                // UPHELD, REJECTED
    char resolution_reason[512];
    uint64_t resolved_at;
    cyxwiz_node_id_t resolver;      // Validator who resolved
} cyxrep_appeal_t;

int cyxrep_submit_appeal(uint8_t appeal_type,
                          const uint8_t* subject_id,
                          const char* reason,
                          const uint8_t* evidence_hash) {
    // 1. Check appeal limits
    if (count_recent_appeals(&current_node) >= 1) {
        return CYXREP_APPEAL_LIMIT_REACHED;
    }

    // 2. Pay appeal fee
    uint64_t fee = get_appeal_fee(appeal_type);
    if (cyxtoken_transfer(&current_node, &appeal_escrow, fee) != CYXTOKEN_OK) {
        return CYXREP_INSUFFICIENT_FUNDS;
    }

    // 3. Create appeal
    cyxrep_appeal_t appeal = {
        .appellant = current_node,
        .appeal_type = appeal_type,
        .fee_paid = fee,
        .submitted_at = now(),
        .status = CYXREP_APPEAL_PENDING
    };
    memcpy(appeal.subject_id, subject_id, 32);
    strncpy(appeal.reason, reason, 1024);
    memcpy(appeal.evidence_hash, evidence_hash, 32);

    // Generate appeal ID
    cyxwiz_crypto_hash(appeal.appeal_id, &appeal, sizeof(appeal));

    // 4. Submit to validator network
    cyxrep_broadcast_appeal(&appeal);

    return CYXREP_OK;
}
```

---

## Anti-Sybil Measures

### Multi-Layer Defense
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Anti-Sybil Defenses                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Layer 1: Economic (Stake Requirement)                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Each identity requires minimum stake                     │   │
│  │  • Creating N identities costs N × stake                    │   │
│  │  • Slashing risk multiplied across identities               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 2: Temporal (Time-Based Reputation)                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Reputation takes time to build                           │   │
│  │  • New identities limited in capabilities                   │   │
│  │  • Can't fast-track via multiple identities                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 3: Behavioral (Network Analysis)                             │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Detect coordinated behavior patterns                     │   │
│  │  • Flag identities that always rate each other              │   │
│  │  • Identify same-owner clusters                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Layer 4: Challenge-Based (Proof of Uniqueness)                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • Simultaneous challenges to suspected Sybils              │   │
│  │  • Same hardware can't respond to multiple                  │   │
│  │  • Timing analysis of responses                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Sybil Detection Algorithm
```c
// Detect potential Sybil clusters
typedef struct {
    cyxwiz_node_id_t nodes[100];
    int node_count;
    float confidence;           // 0-1, how confident this is Sybil
    char reason[256];
} sybil_cluster_t;

void cyxrep_detect_sybil_clusters(sybil_cluster_t* clusters, int* count) {
    *count = 0;

    // 1. Rating graph analysis
    // Build graph: nodes connected by mutual positive ratings
    // Detect dense subgraphs (potential collusion)
    detect_dense_subgraphs(clusters, count);

    // 2. Timing correlation
    // Nodes that are always online/offline together
    detect_timing_correlation(clusters, count);

    // 3. Challenge response analysis
    // Same response patterns, timing, or failures
    detect_challenge_patterns(clusters, count);

    // 4. Transaction graph
    // Funds flowing in circles
    detect_circular_transactions(clusters, count);
}

// Simultaneous challenge for Sybil verification
int cyxrep_sybil_challenge(sybil_cluster_t* cluster) {
    // Issue compute challenge to all suspected nodes at exact same time
    uint8_t challenges[100][32];
    uint64_t challenge_time = now() + 5;  // 5 second preparation

    for (int i = 0; i < cluster->node_count; i++) {
        cyxrep_schedule_challenge(&cluster->nodes[i], challenge_time,
                                   CYXREP_CHALLENGE_COMPUTE, challenges[i]);
    }

    // Wait for responses
    sleep_until(challenge_time + 30);

    // Analyze response times
    // Real separate nodes: random response times
    // Sybils on same hardware: sequential or impossible simultaneity
    float correlation = analyze_response_correlation(challenges, cluster->node_count);

    if (correlation > 0.9) {
        // Very likely Sybil
        cluster->confidence = correlation;
        return CYXREP_SYBIL_DETECTED;
    }

    return CYXREP_NO_SYBIL;
}
