# Contributing to CyxWiz Protocol

Thank you for your interest in contributing to CyxWiz Protocol!

## Getting Started

### Prerequisites

- C11-compliant compiler (GCC 7+, Clang 6+, MSVC 2019+)
- CMake 3.16+
- libsodium (required for crypto module)

### Installing Dependencies

**Linux (Ubuntu/Debian):**
```bash
sudo apt install build-essential cmake libsodium-dev libbluetooth-dev
```

**macOS:**
```bash
brew install cmake libsodium
```

**Windows:**
```bash
vcpkg install libsodium:x64-windows
```

### Building

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

## Code Style

### Naming Conventions

- **Functions**: `cyxwiz_module_action()` (lowercase with underscores)
- **Types**: `cyxwiz_module_t` (typedef structs with `_t` suffix)
- **Constants**: `CYXWIZ_CONSTANT_NAME` (uppercase with underscores)
- **Macros**: `CYXWIZ_MACRO_NAME` (uppercase with underscores)
- **Static functions**: `module_internal_action()` (no prefix)
- **Local variables**: `snake_case`

### Examples

```c
/* Public function */
cyxwiz_error_t cyxwiz_peer_table_add(
    cyxwiz_peer_table_t *table,
    const cyxwiz_node_id_t *node_id,
    cyxwiz_transport_t *transport,
    int8_t rssi
);

/* Type definition */
typedef struct {
    cyxwiz_node_id_t id;
    cyxwiz_peer_state_t state;
    uint64_t last_seen;
} cyxwiz_peer_t;

/* Constant */
#define CYXWIZ_MAX_PEERS 64

/* Static helper */
static bool is_peer_expired(const cyxwiz_peer_t *peer, uint64_t now);
```

### Formatting

- 4-space indentation (no tabs)
- Opening brace on same line for functions and control statements
- Maximum line length: 100 characters
- Single blank line between functions
- Comments: `/* C-style */` for multi-line, `//` avoided

### Memory Safety

- Use `cyxwiz_secure_zero()` to clear sensitive data
- Use `cyxwiz_secure_compare()` for constant-time comparisons
- Use `cyxwiz_free(ptr, size)` which zeros before freeing
- Check all allocations for NULL

## Critical Constraint: LoRa Packet Size

**All protocol messages must fit in 250 bytes.**

This is the maximum transmission unit for LoRa radio, ensuring the protocol works on all transports. When designing new features:

1. Calculate worst-case packet size
2. Test with LoRa transport enabled
3. Use chunking for large payloads
4. Document payload capacity in comments

Example from onion routing:
```c
/* Payload capacity per hop count:
 * 1-hop: 173 bytes
 * 2-hop: 101 bytes
 * 3-hop: 29 bytes (max hops)
 */
```

## Adding New Features

### 1. Headers in `include/cyxwiz/`

Public API declarations go in header files:
- One header per module
- Include guards: `#ifndef CYXWIZ_MODULE_H`
- Document all public functions with comments
- Use opaque types (`struct cyxwiz_foo_t;`) for implementation hiding

### 2. Implementation in `src/`

- Core modules: `src/core/`
- Transport drivers: `src/transport/`
- Crypto operations: `src/crypto/`
- Utilities: `src/util/`

### 3. Tests in `tests/`

Every feature needs tests:
```c
static int test_feature_name(void)
{
    /* Setup */
    /* Action */
    /* Verify */
    return 1; /* Pass */
}
```

Run specific test:
```bash
./build/test_module
```

### 4. Update CMakeLists.txt

Add source files and test executables:
```cmake
list(APPEND CYXWIZ_SOURCES src/core/newmodule.c)

add_executable(test_newmodule tests/test_newmodule.c)
target_link_libraries(test_newmodule PRIVATE cyxwiz)
add_test(NAME test_newmodule COMMAND test_newmodule)
```

## Transport Drivers

New transport drivers implement `cyxwiz_transport_ops_t`:

```c
typedef struct {
    cyxwiz_error_t (*init)(cyxwiz_transport_t *t);
    void (*shutdown)(cyxwiz_transport_t *t);
    cyxwiz_error_t (*send)(cyxwiz_transport_t *t, const uint8_t *data,
                           size_t len, const cyxwiz_node_id_t *dest);
    cyxwiz_error_t (*poll)(cyxwiz_transport_t *t, uint8_t *buf,
                           size_t *len, cyxwiz_node_id_t *src);
    cyxwiz_error_t (*discover)(cyxwiz_transport_t *t);
    void (*stop_discover)(cyxwiz_transport_t *t);
    size_t (*max_packet_size)(cyxwiz_transport_t *t);
} cyxwiz_transport_ops_t;
```

Key requirements:
- `max_packet_size()` must return <= 250
- Handle platform differences with `#ifdef`
- Support graceful degradation in CI (return `CYXWIZ_ERR_TRANSPORT` if unavailable)

## Error Handling

Return `cyxwiz_error_t` from all functions that can fail:

```c
cyxwiz_error_t cyxwiz_foo_bar(...)
{
    if (invalid_input) {
        return CYXWIZ_ERR_INVALID;
    }

    void *ptr = malloc(size);
    if (!ptr) {
        return CYXWIZ_ERR_NOMEM;
    }

    /* ... */

    return CYXWIZ_OK;
}
```

See [docs/ERROR_CODES.md](docs/ERROR_CODES.md) for the full error code reference.

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Implement**: Follow code style guidelines
3. **Test**: Ensure all tests pass on Linux, macOS, and Windows
4. **Document**: Update relevant documentation
5. **Submit**: Create PR with clear description

### PR Title Format

```
feat: Add new feature description
fix: Fix bug description
docs: Update documentation
refactor: Code cleanup description
test: Add tests for feature
```

### Checklist

- [ ] Code follows naming conventions
- [ ] All packets fit in 250 bytes
- [ ] Tests added and passing
- [ ] No compiler warnings (`-Wall -Wextra -Werror`)
- [ ] Memory operations use secure functions
- [ ] Documentation updated

## Security

### Reporting Vulnerabilities

For security issues, please email security@[project-domain] instead of opening a public issue.

### Security Guidelines

- Never log sensitive data (keys, plaintext)
- Use constant-time comparisons for secrets
- Zero memory after use with `cyxwiz_secure_zero()`
- Validate all input sizes before processing
- Check return values from crypto functions

## Questions?

- Check [CLAUDE.md](CLAUDE.md) for technical details
- See [How_To.md](How_To.md) for usage examples
- Open an issue for questions
