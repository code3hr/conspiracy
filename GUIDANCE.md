# CyxWiz Project Guidance

Brutally honest assessment and path forward.

## The Hard Questions

### 1. Who is your user?

Not defined. "Privacy enthusiasts" is not a user. "IoT developers" is not a user. Who wakes up tomorrow and *needs* this?

### 2. Why not existing solutions?

| Your Feature | Already Exists | Difference |
|--------------|----------------|------------|
| LoRa mesh chat | **Meshtastic** - millions of users, tested, huge community | You're untested |
| Private messaging | **Signal** - audited, proven, billions of messages | You're unaudited |
| P2P mesh | **Briar** - works over Tor, WiFi, BT | Actually deployed |
| Decentralized chat | **Matrix/Session** | Federated, working today |

### 3. The LoRa story is weak

LoRa is **untested on real hardware**. That's the main differentiator and it's theoretical. Meshtastic has been running on real LoRa devices for years with an active community.

### 4. The math doesn't work

- 3-hop onion over LoRa = **29 bytes payload**
- That's ~25 characters of actual message
- "Hello, how are you today?" won't fit

The privacy feature (onion routing) kills usability on the core transport (LoRa). Pick one.

### 5. Complexity is the enemy of security

Current stack:
- Custom transport layer
- Custom routing protocol
- Custom DHT
- Custom onion routing
- Custom MPC crypto
- Custom consensus (PoUW)
- Custom storage protocol

Each of these is a PhD thesis worth of attack surface. Signal uses boring, audited, proven primitives. CyxWiz is rolling its own everything.

### 6. IoT security is not a protocol problem

IoT is insecure because:
- Manufacturers don't care (cost)
- Users don't update firmware
- Devices are abandoned after 2 years

A new protocol doesn't fix any of this. A thermostat company won't rewrite their stack to use CyxWiz.

---

## What You Actually Have

A **technically impressive project** that demonstrates:
- Network protocols
- Cryptography
- Systems programming
- Mesh networking

This is valuable for **skills and portfolio**. It's not (yet) valuable for solving a real problem.

---

## The Gap That Actually Exists

| Solution | Off-Grid | Private | Long Range |
|----------|----------|---------|------------|
| Signal | No | Yes | N/A (needs internet) |
| Meshtastic | Yes | **No** (relay sees msgs) | Yes |
| Briar | Yes | Yes | **No** (BT/WiFi only) |
| CyxWiz | Yes | Yes | Yes |

**The gap: Long-range off-grid with real privacy.**

Meshtastic nodes can read messages they relay. That's fine for hikers sharing GPS. It's not fine for journalists in Iran.

---

## Real Users Who Need This

### 1. Journalists/Activists in Hostile Regimes
- Signal blocked in China, Iran, Russia, Myanmar
- Internet shut down during protests (Iran 2022, Myanmar 2021, Belarus 2020)
- They need: works without internet, can't be blocked, actually private

### 2. Disaster Response
- After earthquakes/hurricanes: no cell towers for days
- First responders need secure comms
- Current options: expensive proprietary (GoTenna Pro $500+) or unencrypted

### 3. Rural/Remote Communities
- Indigenous communities, remote farms, research stations
- No cell coverage, too spread for WiFi
- Need private communication over km distances

### 4. Specific High-Value Industrial
- Medical devices (HIPAA), defense, financial
- Can't trust cloud, need E2E + long range
- Low volume but pays real money

---

## What You'd Need To Do

### 1. Pick ONE user and validate

Don't build more code. Talk to people.

- Contact journalists at CPJ (Committee to Protect Journalists)
- Reach out to EFF, Access Now, Citizen Lab
- Ask: "What do you actually use? What's broken?"

If they say "we're fine with Signal + Meshtastic separately" - there's no market.
If they say "we need them combined but can't find it" - there's something.

### 2. Fix the Onion/LoRa Math

Current design: 3-hop onion = 29 bytes payload = useless

**Options:**

```
Option A: 1-hop onion on LoRa (173 bytes)
- Still hides source from relay nodes
- Actually usable payload

Option B: No onion on LoRa, E2E encryption only
- Relay sees metadata (who talks to who)
- But can't read content
- Honest trade-off for constrained channel

Option C: Onion only on UDP, direct E2E on LoRa
- Different privacy levels per transport
- Pragmatic, not pure
```

Pick one. Document the trade-off honestly.

### 3. Test LoRa This Week

Buy hardware:
- 2x RYLR896 modules: $25 total on Amazon
- 2x USB-TTL adapters: $10
- Or: 2x Heltec LoRa 32 boards: $40 total

If you can't spend $50 to validate your core thesis, this isn't serious.

### 4. Simplify The Stack

Current:
```
Transport + Peer + Routing + DHT + Onion + MPC + Consensus + Storage + Compute + ZKP + Privacy
```

For messaging, you need:
```
Transport + Peer + Routing + E2E Encryption + (optional) Onion
```

Kill the rest. Every line of code is a bug waiting to happen. Ship something that works.

### 5. Consider Integration, Not Competition

Instead of competing with Meshtastic:
- Build CyxWiz as an **encryption layer** for Meshtastic
- Or contribute onion routing to their codebase
- Leverage their 500K+ users instead of starting from zero

Instead of competing with Signal:
- Build a **transport plugin** that adds LoRa mesh
- Use their proven crypto, add your network layer

---

## Funding Path

If you validate a real use case, there's money:

| Funder | Focus | Grants |
|--------|-------|--------|
| Open Technology Fund | Censorship circumvention | $50K-500K |
| Mozilla Foundation | Privacy/open source | Varies |
| NLnet | Internet freedom | €5K-50K |
| Access Now | Digital rights | Project-based |
| EFF | Privacy tools | Connections/support |

These orgs fund **exactly this** - but only if you can show real users with real problems.

---

## The Honest Path Forward

```
Week 1:  Buy LoRa hardware, test basic communication
Week 2:  Get one message through onion routing over LoRa
Week 3:  Talk to 5 potential users (journalists, activists, NGOs)
Week 4:  Decide: pivot, partner, or proceed

If proceed:
- Strip to minimum (transport + encryption + onion)
- Ship working LoRa demo
- Document real-world test results
- Apply for OTF/NLnet funding
```

---

## The Question You Must Answer

> "I'm building private mesh communication for [SPECIFIC USER] who currently uses [CURRENT SOLUTION] but struggles with [SPECIFIC PROBLEM] that I solve by [YOUR UNIQUE APPROACH]."

Fill in those blanks with real answers, not hypotheticals.

If you can't fill them in, keep researching until you can.
If you can fill them in, you might have something real.

---

## Decision Framework

### Worth Pursuing If:
- You validate real users with real pain
- LoRa actually works when tested
- You can simplify to a shippable product
- You find a niche Meshtastic/Signal don't serve

### Not Worth Pursuing If:
- Users say "Signal + Meshtastic is fine"
- LoRa testing reveals fundamental issues
- You can't articulate who this is for
- It remains a "cool tech" project without users

---

## Summary

**Current state:** Technically impressive, unvalidated, too complex.

**To make it real:**
1. Test LoRa on hardware (this week)
2. Talk to real potential users (journalists, activists)
3. Simplify ruthlessly (drop 70% of the stack)
4. Ship something people can actually use
5. Compete on the real gap: private + off-grid + long-range

The tech is good. The product strategy needs work.
