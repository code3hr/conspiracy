# CyxWiz Error Codes Reference

This document describes all error codes returned by CyxWiz Protocol functions.

## Quick Reference

| Code | Name | Description |
|------|------|-------------|
| 0 | `CYXWIZ_OK` | Success |
| -1 | `CYXWIZ_ERR_NOMEM` | Out of memory |
| -2 | `CYXWIZ_ERR_INVALID` | Invalid argument |
| -3 | `CYXWIZ_ERR_TRANSPORT` | Transport error |
| -4 | `CYXWIZ_ERR_CRYPTO` | Cryptographic error |
| -5 | `CYXWIZ_ERR_TIMEOUT` | Operation timed out |
| -6 | `CYXWIZ_ERR_PEER_NOT_FOUND` | Peer not found |
| -7 | `CYXWIZ_ERR_BUFFER_TOO_SMALL` | Buffer too small |
| -8 | `CYXWIZ_ERR_NOT_INITIALIZED` | Not initialized |
| -9 | `CYXWIZ_ERR_ALREADY_INIT` | Already initialized |
| -10 | `CYXWIZ_ERR_PACKET_TOO_LARGE` | Packet exceeds transport MTU |
| -11 | `CYXWIZ_ERR_NO_ROUTE` | No route to destination |
| -12 | `CYXWIZ_ERR_QUEUE_FULL` | Pending queue full |
| -13 | `CYXWIZ_ERR_TTL_EXPIRED` | TTL reached zero |
| -14 | `CYXWIZ_ERR_NO_KEY` | No shared key with peer |
| -15 | `CYXWIZ_ERR_CIRCUIT_FULL` | Circuit table full |
| -16 | `CYXWIZ_ERR_EXHAUSTED` | Resource exhausted |
| -17 | `CYXWIZ_ERR_JOB_NOT_FOUND` | Job not found |
| -18 | `CYXWIZ_ERR_JOB_INVALID` | Invalid job format |
| -19 | `CYXWIZ_ERR_WORKER_BUSY` | Worker at capacity |
| -20 | `CYXWIZ_ERR_MAC_INVALID` | MAC verification failed |
| -21 | `CYXWIZ_ERR_STORAGE_NOT_FOUND` | Storage ID not found |
| -22 | `CYXWIZ_ERR_STORAGE_EXPIRED` | Data has expired |
| -23 | `CYXWIZ_ERR_STORAGE_FULL` | Provider storage is full |
| -24 | `CYXWIZ_ERR_STORAGE_UNAUTHORIZED` | Not authorized to access |
| -25 | `CYXWIZ_ERR_INSUFFICIENT_SHARES` | Not enough shares for reconstruction |
| -26 | `CYXWIZ_ERR_STORAGE_CORRUPTED` | Share verification failed |
| -27 | `CYXWIZ_ERR_POS_NO_COMMITMENT` | No PoS commitment stored |
| -28 | `CYXWIZ_ERR_POS_INVALID_PROOF` | Proof verification failed |
| -29 | `CYXWIZ_ERR_POS_CHALLENGE_PENDING` | Challenge already in progress |
| -30 | `CYXWIZ_ERR_POS_INVALID_BLOCK` | Block index out of range |
| -31 | `CYXWIZ_ERR_INSUFFICIENT_RELAYS` | Not enough relay nodes for SURB |
| -32 | `CYXWIZ_ERR_PROOF_INVALID` | ZKP verification failed |
| -33 | `CYXWIZ_ERR_CONSENSUS_NO_QUORUM` | Consensus quorum not reached |
| -34 | `CYXWIZ_ERR_CONSENSUS_SLASHED` | Validator is slashed |
| -35 | `CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR` | Not a registered validator |
| -36 | `CYXWIZ_ERR_CONSENSUS_INSUFFICIENT_CREDITS` | Not enough work credits |
| -37 | `CYXWIZ_ERR_COMMITMENT_INVALID` | Pedersen commitment verification failed |
| -38 | `CYXWIZ_ERR_RANGE_PROOF_FAILED` | Range proof verification failed |
| -39 | `CYXWIZ_ERR_CREDENTIAL_EXPIRED` | Credential has expired |
| -40 | `CYXWIZ_ERR_CREDENTIAL_INVALID` | Credential verification failed |
| -41 | `CYXWIZ_ERR_TOKEN_EXPIRED` | Service token has expired |
| -42 | `CYXWIZ_ERR_TOKEN_INSUFFICIENT` | Insufficient token units |
| -99 | `CYXWIZ_ERR_UNKNOWN` | Unknown error |

## Usage

```c
#include "cyxwiz/types.h"

cyxwiz_error_t err = some_cyxwiz_function();
if (err != CYXWIZ_OK) {
    printf("Error: %s\n", cyxwiz_strerror(err));
}
```

## Error Categories

### General Errors (-1 to -10)

#### CYXWIZ_ERR_NOMEM (-1)
Memory allocation failed. The system is out of available memory.

**Recovery**: Free unused resources or reduce memory usage. Consider reducing `CYXWIZ_MAX_PEERS` or route cache size.

#### CYXWIZ_ERR_INVALID (-2)
Invalid argument passed to function. Check parameter values and types.

**Recovery**: Validate input parameters before calling. Common causes: NULL pointers, out-of-range values, malformed data.

#### CYXWIZ_ERR_TRANSPORT (-3)
Transport layer error. The underlying network transport failed.

**Recovery**: Check transport initialization. Verify hardware (WiFi adapter, Bluetooth, LoRa module) is functioning. May need to reinitialize transport.

#### CYXWIZ_ERR_CRYPTO (-4)
Cryptographic operation failed. Encryption, decryption, or verification error.

**Recovery**: Ensure libsodium is properly initialized (`cyxwiz_crypto_init()`). Check key validity and data integrity.

#### CYXWIZ_ERR_TIMEOUT (-5)
Operation timed out waiting for response.

**Recovery**: Retry the operation. Check network connectivity. Peer may be unreachable or offline.

#### CYXWIZ_ERR_PEER_NOT_FOUND (-6)
Specified peer not found in peer table.

**Recovery**: Ensure peer discovery has run. The peer may have disconnected or never connected.

#### CYXWIZ_ERR_BUFFER_TOO_SMALL (-7)
Provided buffer is too small for the data.

**Recovery**: Allocate a larger buffer. Check expected data size before calling.

#### CYXWIZ_ERR_NOT_INITIALIZED (-8)
Module or context not initialized.

**Recovery**: Call the appropriate `_create()` or `_init()` function before use.

#### CYXWIZ_ERR_ALREADY_INIT (-9)
Module or context already initialized.

**Recovery**: Only initialize once. Check for duplicate initialization calls.

#### CYXWIZ_ERR_PACKET_TOO_LARGE (-10)
Packet exceeds transport MTU (250 bytes for LoRa).

**Recovery**: Split data into smaller chunks. Use chunked message APIs for large payloads.

### Routing Errors (-11 to -16)

#### CYXWIZ_ERR_NO_ROUTE (-11)
No route to destination. Route discovery failed or no path exists.

**Recovery**: Wait for route discovery to complete. Destination may be unreachable. Try again after discovery interval.

#### CYXWIZ_ERR_QUEUE_FULL (-12)
Pending message queue is full. Too many messages awaiting route discovery.

**Recovery**: Wait for pending messages to be sent. Reduce sending rate or increase `CYXWIZ_MAX_PENDING`.

#### CYXWIZ_ERR_TTL_EXPIRED (-13)
Time-to-live reached zero during forwarding.

**Recovery**: Message traversed too many hops. Destination may be too far (>5 hops) or route is stale.

#### CYXWIZ_ERR_NO_KEY (-14)
No shared key with peer for onion encryption.

**Recovery**: Ensure peer discovery with key exchange has completed. Call `cyxwiz_onion_add_peer_key()` after receiving peer's public key.

#### CYXWIZ_ERR_CIRCUIT_FULL (-15)
Onion circuit table is full (max 16 circuits).

**Recovery**: Destroy unused circuits. Wait for circuits to expire (`CYXWIZ_CIRCUIT_TIMEOUT_MS`).

#### CYXWIZ_ERR_EXHAUSTED (-16)
Resource pool exhausted (e.g., MPC triples).

**Recovery**: Regenerate resources. For MPC, generate new multiplication triples.

### Compute Errors (-17 to -20)

#### CYXWIZ_ERR_JOB_NOT_FOUND (-17)
Job ID not found in job table.

**Recovery**: Verify job ID. Job may have completed, been cancelled, or expired.

#### CYXWIZ_ERR_JOB_INVALID (-18)
Invalid job format or parameters.

**Recovery**: Check job specification. Ensure required fields are present and valid.

#### CYXWIZ_ERR_WORKER_BUSY (-19)
Worker is at maximum capacity.

**Recovery**: Retry later or find another worker. Query for available workers.

#### CYXWIZ_ERR_MAC_INVALID (-20)
Message authentication code verification failed.

**Recovery**: Data may be corrupted or tampered. Re-request data from source.

### Storage Errors (-21 to -30)

#### CYXWIZ_ERR_STORAGE_NOT_FOUND (-21)
Storage ID not found on provider.

**Recovery**: Verify storage ID. Data may have been deleted or provider changed.

#### CYXWIZ_ERR_STORAGE_EXPIRED (-22)
Stored data has exceeded its TTL.

**Recovery**: Re-store data with new TTL if still needed.

#### CYXWIZ_ERR_STORAGE_FULL (-23)
Provider has no available storage space.

**Recovery**: Choose a different provider or wait for space to become available.

#### CYXWIZ_ERR_STORAGE_UNAUTHORIZED (-24)
Not authorized to access this storage.

**Recovery**: Verify access credentials. Only the data owner can retrieve/delete.

#### CYXWIZ_ERR_INSUFFICIENT_SHARES (-25)
Not enough shares available for K-of-N reconstruction.

**Recovery**: Contact more providers. Need at least K shares to reconstruct.

#### CYXWIZ_ERR_STORAGE_CORRUPTED (-26)
Share verification failed. Data integrity compromised.

**Recovery**: Retrieve shares from other providers. Report corrupted provider.

#### CYXWIZ_ERR_POS_NO_COMMITMENT (-27)
Provider has no Proof of Storage commitment for this data.

**Recovery**: Request commitment from provider. May need to re-store data.

#### CYXWIZ_ERR_POS_INVALID_PROOF (-28)
Proof of Storage verification failed.

**Recovery**: Provider may not have the data. Consider it lost from this provider.

#### CYXWIZ_ERR_POS_CHALLENGE_PENDING (-29)
A Proof of Storage challenge is already in progress.

**Recovery**: Wait for current challenge to complete before issuing new one.

#### CYXWIZ_ERR_POS_INVALID_BLOCK (-30)
Requested block index is out of range.

**Recovery**: Check data size and block index bounds.

### Privacy Errors (-31 to -42)

#### CYXWIZ_ERR_INSUFFICIENT_RELAYS (-31)
Not enough relay nodes available for anonymous routing.

**Recovery**: Wait for more peers to connect. Need sufficient network size for anonymity.

#### CYXWIZ_ERR_PROOF_INVALID (-32)
Zero-knowledge proof verification failed.

**Recovery**: Proof was incorrectly generated or data was tampered.

#### CYXWIZ_ERR_CONSENSUS_NO_QUORUM (-33)
Consensus voting failed to reach quorum.

**Recovery**: Wait for more validators to come online. Retry validation.

#### CYXWIZ_ERR_CONSENSUS_SLASHED (-34)
Validator has been slashed for misbehavior.

**Recovery**: Validator is permanently banned. Register a new validator identity.

#### CYXWIZ_ERR_CONSENSUS_NOT_VALIDATOR (-35)
Node is not a registered validator.

**Recovery**: Register as validator with `cyxwiz_consensus_register()`.

#### CYXWIZ_ERR_CONSENSUS_INSUFFICIENT_CREDITS (-36)
Not enough work credits for validation.

**Recovery**: Earn credits by completing compute jobs or storage proofs.

#### CYXWIZ_ERR_COMMITMENT_INVALID (-37)
Pedersen commitment verification failed.

**Recovery**: Commitment opening doesn't match. Data may be tampered.

#### CYXWIZ_ERR_RANGE_PROOF_FAILED (-38)
Range proof verification failed. Value not in claimed range.

**Recovery**: Proof was incorrectly generated or claims are false.

#### CYXWIZ_ERR_CREDENTIAL_EXPIRED (-39)
Anonymous credential has expired.

**Recovery**: Request new credential from issuer.

#### CYXWIZ_ERR_CREDENTIAL_INVALID (-40)
Credential verification failed. Invalid signature or attributes.

**Recovery**: Credential may be forged or corrupted. Request new credential.

#### CYXWIZ_ERR_TOKEN_EXPIRED (-41)
Service access token has expired.

**Recovery**: Request new service token.

#### CYXWIZ_ERR_TOKEN_INSUFFICIENT (-42)
Token does not have enough units for requested operation.

**Recovery**: Acquire more token units or reduce request size.

### Unknown Error (-99)

#### CYXWIZ_ERR_UNKNOWN (-99)
Unclassified error condition.

**Recovery**: Check logs for more details. May indicate a bug.
