# The Truth About CyxWiz

**Read this before using CyxWiz for anything.**

---

## Status: ALPHA - NOT PRODUCTION READY

CyxWiz is an **experimental research project**. It has NOT been:
- Security audited
- Tested on real networks with real users
- Validated against actual adversaries
- Deployed in production anywhere

**Do not use for security-critical applications.**

---

## Honest Assessment

| Component | Code Exists | Unit Tests | Real Network Testing | Battle-Tested |
|-----------|-------------|------------|---------------------|---------------|
| UDP Transport | Yes | Yes | No | No |
| NAT Traversal (STUN) | Yes | Yes | No | No |
| DHT Discovery | Yes | Yes | No | No |
| Relay Fallback | Partial | Partial | No | No |
| Onion Routing | Yes | Yes | No | No |
| Distributed Storage | Yes | Yes | No | No |
| Distributed Compute | Yes | Yes | No | No |
| MPC Crypto | Yes | Yes | No | No |
| Consensus (PoUW) | Yes | Yes | No | No |

**Translation:** The code compiles. Unit tests pass. CI is green. But we have **zero evidence** any of this works on real networks with real users.

---

## Known Limitations

### Security
- **No audit.** The crypto code has never been professionally reviewed.
- **C code.** Memory safety bugs are possible (we've already fixed several).
- **Unproven claims.** Security properties are theoretical, not demonstrated.

### Network
- **Untested NAT traversal.** We don't know if hole-punching works across real home routers.
- **Bootstrap problem unsolved.** DHT needs seed nodes. Who runs them?
- **Sybil resistance unproven.** A determined attacker could flood the DHT.

### Scale
- **Zero users.** Nobody outside the developer has run this.
- **Unknown failure modes.** We don't know what breaks under load.
- **No stress testing.** Memory leaks and edge cases unknown.

---

## What We're Building Toward

The vision is real:
- Private communication without servers
- Distributed compute and storage
- Anonymity through onion routing
- Mesh networking for infrastructure-free operation

But vision is not reality. **We're not there yet.**

---

## Current Focus: CyxChat

We've recognized that CyxWiz tried to be too many things at once. The new strategy:

1. **Freeze CyxWiz** - No new features until the foundation is proven
2. **Focus on CyxChat** - One app, one use case: private messaging
3. **Test on real networks** - Prove the foundation works
4. **Get real users** - Ship to humans, fix what breaks

CyxChat is the car. CyxWiz is the engine. Nobody buys engines - they buy cars.

---

## The Path Forward

### Phase 1: Prove the Foundation
- Test UDP connectivity between real machines on different networks
- Verify NAT traversal works with actual home routers
- Confirm DHT discovery functions with 3+ nodes
- Validate relay fallback when direct connection fails

### Phase 2: Ship CyxChat MVP
- 1:1 messaging only (no groups, no files)
- Works across NAT
- Reliable message delivery

### Phase 3: Get Real Users
- 5-10 beta testers using it daily
- Collect feedback
- Fix what breaks

### Phase 4: Expand (Later)
- Only after phases 1-3 succeed
- Group chat, file transfer, etc.

---

## Use At Your Own Risk

If you use CyxWiz:
- Assume it's broken until proven otherwise
- Don't trust it with sensitive information
- Report bugs and security issues
- Help us test on real networks

**This is experimental software. Treat it accordingly.**

---

## Why This Document Exists

We wrote marketing copy before we had a product. We described enterprise use cases for code that hasn't been tested by a single external user. That was wrong.

This document is our commitment to honesty. We'd rather have 10 users who understand what they're getting than 1000 who expect something we can't deliver.

The code is real. The vision is real. The production-readiness is not.

---

*"The first step to building something great is admitting what you don't have yet."*
