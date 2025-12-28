# Changelog

All notable changes to CyxWiz Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-12-28

### Added

#### Onion Routing
- Multi-hop onion routing with layered XChaCha20-Poly1305 encryption
- Ephemeral X25519 keys for per-circuit forward secrecy
- Circuit management with automatic expiration
- Anonymous message delivery via `/anon` daemon command

#### Privacy Protocol
- Pedersen commitments for hidden values
- Range proofs for value bounds verification
- Anonymous credentials with blind signatures
- Anonymous voting integration with consensus
- Service tokens for privacy-preserving resource access
- Reputation proofs without identity disclosure

#### Consensus
- Proof of Useful Work (PoUW) mechanism
- Validator registration with Schnorr identity proofs
- Work credit accumulation from compute/storage contributions
- Stake-weighted validation voting
- Validator slashing for equivocation detection
- Evidence hash verification for slash reports

#### Daemon
- Interactive command shell (`/help`, `/status`, `/peers`)
- Batch mode for scripting (`--batch` flag)
- Direct messaging (`/send`) and anonymous messaging (`/anon`)
- Storage commands (`/store`, `/retrieve`, `/storage`)
- Compute commands (`/compute`, `/jobs`)
- Consensus commands (`/validators`, `/credits`)

#### Transport Drivers
- WiFi Direct: Linux wpa_supplicant + Windows WinRT
- Bluetooth: Linux BlueZ L2CAP + Windows RFCOMM
- LoRa: Serial AT commands + Linux SPI for SX127x
- UDP: NAT traversal via STUN, hole punching

#### Security
- MPC key refresh for forward secrecy
- `CYXWIZ_PARTY_ID` environment variable for MPC config
- Graceful peer disconnect with goodbye messages

#### Other
- Chunked results for large compute job outputs
- End-to-end demo scripts
- Comprehensive test suite (14 test suites)
- GitHub Actions CI for Linux, macOS, Windows
- Multi-platform release builds

### Changed
- Improved error handling across all modules
- Better cross-platform compiler compatibility (GCC, Clang, MSVC)
- Test framework now supports SKIP for environment-dependent tests

### Fixed
- Various CI build fixes for all platforms
- Transport availability detection in tests
- BlueZ linking on Linux
- Compiler warnings across all platforms

## [0.1.0] - 2024-12-01

### Added

#### Core Protocol
- Transport abstraction layer for protocol-agnostic communication
- 250-byte packet size constraint (LoRa compatibility)
- Node ID based on 256-bit identifiers

#### Peer Management
- Peer discovery protocol with announcements
- Peer table with connection state tracking
- Ping/pong keepalive mechanism
- Maximum 64 concurrent peers

#### Mesh Routing
- On-demand route discovery via broadcast flooding
- Source routing with embedded hop paths
- Route caching with automatic expiration
- Maximum 5 hops per route

#### MPC Cryptography
- SPDZ-based multi-party computation
- Additive secret sharing
- K-of-N threshold reconstruction
- Information-theoretic MACs
- XChaCha20-Poly1305 symmetric encryption
- X25519 key exchange

#### Distributed Compute
- Job marketplace for task distribution
- Worker capability announcements
- Job submission with MAC-verified results
- Job status tracking and cancellation

#### Distributed Storage (CyxCloud)
- K-of-N threshold storage
- Data chunking for large files
- Provider discovery and selection
- Proof of Storage challenges

#### Zero-Knowledge Proofs
- Schnorr identity proofs
- Range proofs via bit decomposition

#### Infrastructure
- Secure memory utilities (zeroing, constant-time compare)
- Configurable logging system
- CMake build system with feature toggles
- libsodium integration

[0.2.0]: https://github.com/username/cyxwiz/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/username/cyxwiz/releases/tag/v0.1.0
