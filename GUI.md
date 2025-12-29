# CyxWiz GUI Implementation Plan

## Overview
Add a Flutter-based GUI to CyxWiz with dual architecture:
- **Web**: Flutter Web app served by daemon HTTP server
- **Desktop**: Flutter Desktop apps using dart:ffi to call C library directly

## Architecture

```
+---------------------------------------------------------------------+
|                    Flutter GUI Application                          |
|  +-------------------------+    +---------------------------------+ |
|  |   Flutter Web (Browser) |    |  Flutter Desktop (Win/Mac/Linux)| |
|  +------------+------------+    +-------------+-------------------+ |
|               |                               |                      |
|               | HTTP/WebSocket                | dart:ffi             |
+---------------+-------------------------------+----------------------+
                |                               |
+---------------v---------------+ +-------------v-----------------------+
|    Daemon HTTP Server         | |       libcyxwiz.so/dll              |
|  - Static file serving        | |  - Stable C API for FFI             |
|  - REST API endpoints         | |  - Direct function calls            |
|  - WebSocket real-time        | |  - Callback registration            |
+---------------+---------------+ +-------------+-----------------------+
                |                               |
                +---------------+---------------+
                                |
+-------------------------------v-------------------------------------+
|                     CyxWiz Core Library                              |
|   peer_table, router, onion, storage, compute, consensus...         |
+---------------------------------------------------------------------+
```

## Project Structure

```
cyxwiz/
├── include/cyxwiz/       # C headers (existing)
├── src/                  # C source (existing)
├── daemon/               # Daemon executable (existing)
├── gui/                  # NEW: Flutter project
│   ├── lib/
│   │   ├── main.dart
│   │   ├── src/
│   │   │   ├── api/              # API layer (HTTP for web, FFI for desktop)
│   │   │   │   ├── api.dart      # Abstract API interface
│   │   │   │   ├── http_api.dart # HTTP/WebSocket implementation
│   │   │   │   └── ffi_api.dart  # dart:ffi implementation
│   │   │   ├── models/           # Data models
│   │   │   ├── providers/        # State management
│   │   │   ├── screens/          # UI screens
│   │   │   └── widgets/          # Reusable widgets
│   │   └── ffi/
│   │       ├── bindings.dart     # Generated FFI bindings
│   │       └── cyxwiz_ffi.dart   # FFI wrapper
│   ├── web/                      # Web-specific assets
│   ├── windows/                  # Windows desktop config
│   ├── linux/                    # Linux desktop config
│   ├── macos/                    # macOS desktop config
│   └── pubspec.yaml
└── CMakeLists.txt        # Updated for shared library
```

## Part 1: C Backend Updates

### 1.1 Shared Library Build
Update CMakeLists.txt to build `libcyxwiz` as shared library for FFI:
- Add `BUILD_SHARED_LIBS` option
- Export symbols properly (dllexport on Windows)
- Generate .dll/.so/.dylib

### 1.2 Stable FFI API (`include/cyxwiz/ffi.h`)

#### Symbol Export Macro
```c
#ifdef _WIN32
    #ifdef CYXWIZ_BUILDING_DLL
        #define CYXWIZ_EXPORT __declspec(dllexport)
    #else
        #define CYXWIZ_EXPORT __declspec(dllimport)
    #endif
#else
    #define CYXWIZ_EXPORT __attribute__((visibility("default")))
#endif
```

#### Opaque Context Type
```c
// Opaque handle - internal structure hidden from FFI
typedef struct cyxwiz_ffi_ctx cyxwiz_ffi_ctx_t;
```

#### Context Lifecycle
```c
/**
 * Create a new CyxWiz context.
 * Returns NULL on failure. Call cyxwiz_ffi_get_error() for details.
 */
CYXWIZ_EXPORT cyxwiz_ffi_ctx_t* cyxwiz_ffi_create(void);

/**
 * Destroy context and free all resources.
 * Safe to call with NULL.
 */
CYXWIZ_EXPORT void cyxwiz_ffi_destroy(cyxwiz_ffi_ctx_t* ctx);

/**
 * Start the node (discovery, routing, etc).
 * Returns 0 on success, negative error code on failure.
 */
CYXWIZ_EXPORT int cyxwiz_ffi_start(cyxwiz_ffi_ctx_t* ctx);

/**
 * Stop the node gracefully.
 */
CYXWIZ_EXPORT void cyxwiz_ffi_stop(cyxwiz_ffi_ctx_t* ctx);

/**
 * Poll for events. Call this regularly (every 100ms recommended).
 * Returns number of events processed.
 */
CYXWIZ_EXPORT int cyxwiz_ffi_poll(cyxwiz_ffi_ctx_t* ctx);

/**
 * Get last error message (thread-local).
 * Returns empty string if no error.
 */
CYXWIZ_EXPORT const char* cyxwiz_ffi_get_error(void);
```

#### Status & Information
```c
/**
 * Get node ID as hex string (64 chars + null).
 * Returns pointer to internal buffer - valid until next call.
 */
CYXWIZ_EXPORT const char* cyxwiz_ffi_get_node_id(cyxwiz_ffi_ctx_t* ctx);

/**
 * Get peer count.
 */
CYXWIZ_EXPORT int cyxwiz_ffi_get_peer_count(cyxwiz_ffi_ctx_t* ctx);

/**
 * Get full status as JSON.
 * Caller must free returned string with cyxwiz_ffi_free_string().
 *
 * Example output:
 * {
 *   "node_id": "a3f8c2...",
 *   "peer_count": 12,
 *   "onion_enabled": true,
 *   "mpc_party_id": 1,
 *   "nat_type": "cone",
 *   "uptime_sec": 3600
 * }
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_get_status_json(cyxwiz_ffi_ctx_t* ctx);

/**
 * Get peer list as JSON array.
 * Caller must free returned string with cyxwiz_ffi_free_string().
 *
 * Example output:
 * [
 *   {"id": "b7e2d1...", "state": "connected", "latency_ms": 45, "reputation": 85},
 *   {"id": "c4a9f8...", "state": "connecting", "latency_ms": 0, "reputation": 50}
 * ]
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_get_peers_json(cyxwiz_ffi_ctx_t* ctx);
```

#### Messaging
```c
/**
 * Send direct message to peer.
 * @param peer_id Hex string (first 8+ chars for prefix match)
 * @param msg UTF-8 message content
 * @param msg_len Length of message
 * Returns 0 on success, negative error code on failure.
 */
CYXWIZ_EXPORT int cyxwiz_ffi_send(
    cyxwiz_ffi_ctx_t* ctx,
    const char* peer_id,
    const char* msg,
    size_t msg_len
);

/**
 * Send anonymous message via onion routing.
 * Same parameters as cyxwiz_ffi_send().
 */
CYXWIZ_EXPORT int cyxwiz_ffi_send_anon(
    cyxwiz_ffi_ctx_t* ctx,
    const char* peer_id,
    const char* msg,
    size_t msg_len
);
```

#### Storage
```c
/**
 * Store data in distributed storage.
 * Returns storage ID as hex string (16 chars).
 * Caller must free returned string with cyxwiz_ffi_free_string().
 * Returns NULL on failure.
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_store(
    cyxwiz_ffi_ctx_t* ctx,
    const uint8_t* data,
    size_t len
);

/**
 * Initiate retrieval from distributed storage.
 * Result delivered via callback (RETRIEVE_COMPLETE event).
 * Returns 0 on success, negative error code on failure.
 */
CYXWIZ_EXPORT int cyxwiz_ffi_retrieve(
    cyxwiz_ffi_ctx_t* ctx,
    const char* storage_id
);

/**
 * Get storage status as JSON.
 * Caller must free returned string.
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_get_storage_status_json(cyxwiz_ffi_ctx_t* ctx);
```

#### Compute
```c
// Job types
#define CYXWIZ_FFI_JOB_HASH     0
#define CYXWIZ_FFI_JOB_ENCRYPT  1
#define CYXWIZ_FFI_JOB_DECRYPT  2
#define CYXWIZ_FFI_JOB_VERIFY   3

/**
 * Submit compute job to network.
 * Returns job ID as hex string (16 chars).
 * Caller must free returned string.
 * Returns NULL on failure.
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_submit_job(
    cyxwiz_ffi_ctx_t* ctx,
    int job_type,
    const uint8_t* data,
    size_t len
);

/**
 * Get active jobs as JSON array.
 * Caller must free returned string.
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_get_jobs_json(cyxwiz_ffi_ctx_t* ctx);
```

#### Consensus
```c
/**
 * Get validator list as JSON array.
 * Caller must free returned string.
 */
CYXWIZ_EXPORT char* cyxwiz_ffi_get_validators_json(cyxwiz_ffi_ctx_t* ctx);

/**
 * Get current work credits balance.
 */
CYXWIZ_EXPORT uint32_t cyxwiz_ffi_get_credits(cyxwiz_ffi_ctx_t* ctx);
```

#### Callbacks & Events
```c
/**
 * Callback function type for events.
 * @param event_json JSON string describing the event (see Event System section)
 * @param user_data User-provided context pointer
 *
 * IMPORTANT: This callback is invoked from cyxwiz_ffi_poll().
 * The event_json string is valid only during the callback.
 * Copy it if you need to retain it.
 */
typedef void (*cyxwiz_ffi_callback_t)(
    const char* event_json,
    void* user_data
);

/**
 * Register event callback.
 * Only one callback can be registered at a time.
 * Pass NULL to unregister.
 */
CYXWIZ_EXPORT void cyxwiz_ffi_set_callback(
    cyxwiz_ffi_ctx_t* ctx,
    cyxwiz_ffi_callback_t callback,
    void* user_data
);
```

#### Memory Management
```c
/**
 * Free a string returned by any cyxwiz_ffi_* function.
 * Safe to call with NULL.
 */
CYXWIZ_EXPORT void cyxwiz_ffi_free_string(char* str);
```

#### FFI Implementation Notes
```c
// src/ffi/ffi.c - Internal structure
struct cyxwiz_ffi_ctx {
    cyxwiz_peer_table_t* peer_table;
    cyxwiz_discovery_t* discovery;
    cyxwiz_router_t* router;
    cyxwiz_transport_t* transport;
    cyxwiz_node_id_t local_id;

#ifdef CYXWIZ_HAS_CRYPTO
    cyxwiz_crypto_ctx_t* crypto;
    cyxwiz_onion_ctx_t* onion;
#endif

#ifdef CYXWIZ_HAS_COMPUTE
    cyxwiz_compute_ctx_t* compute;
#endif

#ifdef CYXWIZ_HAS_STORAGE
    cyxwiz_storage_ctx_t* storage;
#endif

#ifdef CYXWIZ_HAS_CONSENSUS
    cyxwiz_consensus_ctx_t* consensus;
    cyxwiz_identity_keypair_t identity;
#endif

    // Event callback
    cyxwiz_ffi_callback_t callback;
    void* callback_user_data;

    // Internal buffers for node_id etc.
    char node_id_hex[65];

    bool running;
};
```

### 1.3 HTTP Server Module (`src/gui/gui.c`)

#### Header (`include/cyxwiz/gui.h`)
```c
// GUI server context
typedef struct cyxwiz_gui_ctx cyxwiz_gui_ctx_t;

// Configuration
typedef struct {
    const char* static_path;  // Path to Flutter web build (CYXWIZ_GUI_PATH)
    uint16_t port;            // HTTP port (default: 19851)
    const char* bind_addr;    // Bind address (default: "127.0.0.1")
    bool auto_open_browser;   // Open browser on start
} cyxwiz_gui_config_t;

// Lifecycle
CYXWIZ_EXPORT cyxwiz_gui_ctx_t* cyxwiz_gui_create(
    cyxwiz_ffi_ctx_t* ffi_ctx,
    const cyxwiz_gui_config_t* config
);
CYXWIZ_EXPORT void cyxwiz_gui_destroy(cyxwiz_gui_ctx_t* ctx);
CYXWIZ_EXPORT int cyxwiz_gui_start(cyxwiz_gui_ctx_t* ctx);
CYXWIZ_EXPORT void cyxwiz_gui_stop(cyxwiz_gui_ctx_t* ctx);

// Poll - call from main loop (handles connections, WebSocket frames)
CYXWIZ_EXPORT int cyxwiz_gui_poll(cyxwiz_gui_ctx_t* ctx);

// Broadcast event to all WebSocket clients
CYXWIZ_EXPORT void cyxwiz_gui_broadcast(cyxwiz_gui_ctx_t* ctx, const char* event_json);
```

#### Internal Architecture
```c
// src/gui/gui.c

// Maximum concurrent connections
#define GUI_MAX_CLIENTS 16

// Client connection states
typedef enum {
    GUI_CLIENT_NONE,        // Slot unused
    GUI_CLIENT_HTTP,        // Regular HTTP request
    GUI_CLIENT_WEBSOCKET,   // Upgraded to WebSocket
} gui_client_state_t;

// Single client connection
typedef struct {
    gui_client_state_t state;
    socket_t sock;              // Platform socket handle
    uint8_t recv_buf[8192];     // Receive buffer
    size_t recv_len;
    uint8_t send_buf[65536];    // Send buffer (large for static files)
    size_t send_len;
    size_t send_pos;
    bool ws_fin;                // WebSocket frame state
    uint8_t ws_opcode;
    uint64_t ws_payload_len;
    uint8_t ws_mask[4];
} gui_client_t;

// Server context
struct cyxwiz_gui_ctx {
    cyxwiz_ffi_ctx_t* ffi;      // FFI context for API calls
    cyxwiz_gui_config_t config;

    socket_t listen_sock;        // Listening socket
    gui_client_t clients[GUI_MAX_CLIENTS];

    // Static file cache (optional optimization)
    struct {
        char* path;
        uint8_t* data;
        size_t len;
        const char* mime_type;
    } file_cache[32];
    size_t cache_count;
};
```

### 1.4 REST API Endpoints
```
GET  /api/status     - Node status JSON
GET  /api/peers      - Peer list JSON
POST /api/send       - Send message {peer_id, message}
POST /api/anon       - Send anonymous {peer_id, message}
GET  /api/storage    - Storage status
POST /api/store      - Store data {data}
POST /api/retrieve   - Retrieve {storage_id}
GET  /api/jobs       - Compute jobs
POST /api/compute    - Submit job {type, data}
GET  /api/validators - Validator list
GET  /api/credits    - Work credits
WS   /ws             - WebSocket for real-time events
```

## Part 2: Flutter Application

### 2.1 API Abstraction Layer
```dart
// api.dart - Abstract interface
abstract class CyxwizApi {
  Future<NodeStatus> getStatus();
  Stream<List<Peer>> watchPeers();
  Future<void> sendMessage(String peerId, String message);
  Future<void> sendAnonymous(String peerId, String message);
  // ... etc
}

// Factory to create appropriate implementation
CyxwizApi createApi() {
  if (kIsWeb) return HttpApi();
  return FfiApi();
}
```

### 2.2 HTTP/WebSocket Implementation (Web)
```dart
// http_api.dart
class HttpApi implements CyxwizApi {
  final String baseUrl;
  WebSocketChannel? _ws;

  // REST calls for commands
  // WebSocket stream for events
}
```

### 2.3 FFI Implementation (Desktop)
Uses background isolate to keep UI responsive:

```dart
// ffi_api.dart
class FfiApi implements CyxwizApi {
  late final SendPort _isolateSendPort;
  late final ReceivePort _mainReceivePort;
  late final Isolate _workerIsolate;

  Future<void> init() async {
    _mainReceivePort = ReceivePort();
    _workerIsolate = await Isolate.spawn(
      _ffiWorker,
      _mainReceivePort.sendPort,
    );
    // Wait for isolate to send back its SendPort
    _isolateSendPort = await _mainReceivePort.first;
  }

  // Commands sent to isolate, responses come back via ReceivePort
  Future<NodeStatus> getStatus() async {
    _isolateSendPort.send({'cmd': 'getStatus'});
    return await _responseStream.firstWhere((r) => r['cmd'] == 'getStatus');
  }
}

// Worker isolate entry point
void _ffiWorker(SendPort mainSendPort) {
  final receivePort = ReceivePort();
  mainSendPort.send(receivePort.sendPort);

  // Load C library and create context
  final lib = DynamicLibrary.open('libcyxwiz.dll');
  final ctx = lib.lookupFunction<...>('cyxwiz_ffi_create')();

  // Poll loop + command handling
  receivePort.listen((message) {
    switch (message['cmd']) {
      case 'getStatus':
        final json = lib.lookupFunction<...>('cyxwiz_ffi_get_status_json')(ctx);
        mainSendPort.send({'cmd': 'getStatus', 'data': json.toDartString()});
        break;
      // ... other commands
    }
  });

  // Background polling
  Timer.periodic(Duration(milliseconds: 100), (_) {
    lib.lookupFunction<...>('cyxwiz_ffi_poll')(ctx);
  });
}
```

### 2.4 State Management (Provider)
```dart
// providers/node_provider.dart
class NodeProvider extends ChangeNotifier {
  final CyxwizApi _api;
  NodeStatus? _status;
  List<Peer> _peers = [];
  bool _loading = true;

  NodeStatus? get status => _status;
  List<Peer> get peers => _peers;
  bool get loading => _loading;

  NodeProvider(this._api) {
    _init();
  }

  Future<void> _init() async {
    _status = await _api.getStatus();
    _loading = false;
    notifyListeners();

    // Subscribe to real-time updates
    _api.watchPeers().listen((peers) {
      _peers = peers;
      notifyListeners();
    });
  }

  Future<void> sendMessage(String peerId, String msg) async {
    await _api.sendMessage(peerId, msg);
  }
}

// main.dart - Provider setup
void main() {
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => NodeProvider(createApi())),
        ChangeNotifierProvider(create: (_) => StorageProvider(createApi())),
        ChangeNotifierProvider(create: (_) => ComputeProvider(createApi())),
      ],
      child: CyxwizApp(),
    ),
  );
}
```

### 2.5 UI Screens

**7 Main Screens:**

1. **Dashboard** - Overview with status cards (Node ID, Peers, Credits, NAT Type, Onion Status, Uptime) and activity feed
2. **Peers** - Live peer list with states, latency, reputation, expandable details
3. **Messages** - Chat-like interface with conversation list, direct/anonymous toggle
4. **Storage** - Store/retrieve forms, status panel, operation history
5. **Compute** - Job submission, active jobs table, worker status
6. **Consensus** - Validator list, credit earnings breakdown, voting status
7. **Settings** - Network, privacy, storage, and compute configuration

### 2.6 Reusable Widgets

Key widgets to build:
- `StatusCard` - Dashboard stats display
- `PeerRow` - Peer list item with actions
- `NodeIdText` - Truncated ID with copy button
- `ActivityItem` - Feed item with icon and timestamp
- `MessageBubble` - Chat message display
- `JobCard` - Compute job status
- `StorageOpCard` - Storage operation display
- `SettingsSection` - Grouped settings container
- `LoadingOverlay` - Async operation indicator
- `ConnectionStatusIndicator` - App bar status

### 2.7 Theme
```dart
final cyxwizTheme = ThemeData(
  brightness: Brightness.dark,
  primaryColor: Color(0xFF6C63FF),       // Purple accent
  scaffoldBackgroundColor: Color(0xFF0D1117),  // Deep dark bg
  cardColor: Color(0xFF161B22),          // Slightly lighter cards
);
```

### 2.8 Event System
Events pushed via WebSocket (web) or callbacks (desktop):

```json
// Peer events
{"type": "peer_connected", "peer": {"id": "a3f8...", "state": "connected"}}
{"type": "peer_disconnected", "peer_id": "a3f8..."}
{"type": "peer_updated", "peer": {"id": "a3f8...", "latency": 45, "reputation": 85}}

// Message events
{"type": "message_received", "from": "b7e2...", "content": "Hello", "anonymous": false}
{"type": "onion_message", "from": "c4a9...", "content": "Secret", "anonymous": true}

// Storage events
{"type": "store_complete", "storage_id": "abc123def456"}
{"type": "retrieve_complete", "storage_id": "abc123def456", "data": "..."}
{"type": "store_failed", "error": "Not enough peers"}

// Compute events
{"type": "job_submitted", "job_id": "xyz789", "type": "hash"}
{"type": "job_complete", "job_id": "xyz789", "result": "..."}
{"type": "job_failed", "job_id": "xyz789", "error": "Worker offline"}

// Consensus events
{"type": "credits_updated", "credits": 1275}
{"type": "validation_round", "round_id": 42, "status": "voting"}
```

## Implementation Phases

### Phase 1: C Backend
1. Add shared library build to CMake
2. Create `include/cyxwiz/ffi.h` with stable API
3. Implement `src/ffi/ffi.c` wrapping existing modules
4. Test with simple C program

### Phase 2: HTTP Server
1. Create `src/gui/gui.c` with HTTP server
2. Implement REST endpoints
3. Add WebSocket support
4. Integrate with daemon main.c
5. Test with curl/browser

### Phase 3: Flutter Project Setup
1. Create `gui/` Flutter project
2. Set up project structure
3. Add dependencies (provider, http, web_socket_channel)
4. Configure web/desktop platforms

### Phase 4: Flutter API Layer
1. Define abstract API interface
2. Implement HTTP/WebSocket API for web
3. Generate FFI bindings (ffigen)
4. Implement FFI API for desktop
5. Test both implementations

### Phase 5: Flutter UI
1. Implement data models
2. Create state management (providers)
3. Build dashboard screen
4. Build peer list screen
5. Build messaging screen
6. Build storage screen
7. Build compute screen
8. Build validators screen
9. Add settings screen

### Phase 6: Polish
1. Error handling and loading states
2. Animations and transitions
3. Testing (unit, widget, integration)
4. Documentation

## Configuration

### Environment Variables
- `CYXWIZ_GUI_PATH` - Path to Flutter web build output
- `CYXWIZ_GUI_PORT` - HTTP server port (default: 19851)

### Default Settings
- HTTP server binds to 127.0.0.1 only (localhost)
- Port 19851 (one above mesh port 19850)
- WebSocket at ws://localhost:19851/ws

## Files to Create/Modify

### New C Files
- `include/cyxwiz/ffi.h` - FFI API header
- `include/cyxwiz/gui.h` - GUI/HTTP server header
- `src/ffi/ffi.c` - FFI API implementation
- `src/gui/gui.c` - HTTP server implementation
- `src/gui/api.c` - REST API handlers
- `src/gui/websocket.c` - WebSocket implementation

### Modified C Files
- `CMakeLists.txt` - Add shared library build, gui module
- `daemon/main.c` - Add GUI initialization and polling

### Flutter Files
- `gui/` - Entire Flutter project (see structure above)

## Part 3: Testing Strategy

### 3.1 C Code Tests
- Unit tests for FFI API functions
- HTTP request parsing tests
- WebSocket handshake and frame tests
- Integration tests (spawn daemon, test HTTP)

### 3.2 Flutter Tests
- Unit tests for models and API layer
- Widget tests for all custom widgets
- Provider tests for state management
- Integration tests for screen navigation

### 3.3 End-to-End Tests
- Full daemon + Flutter web integration
- HTTP endpoint verification
- WebSocket event streaming

## Part 4: Deployment & Distribution

### 4.1 Build Pipeline
- GitHub Actions CI/CD for all platforms
- C library builds for Windows/macOS/Linux
- Flutter builds for web/desktop targets

### 4.2 Packaging
- **Windows**: NSIS installer (.exe)
- **macOS**: App bundle with DMG
- **Linux**: AppImage + .deb + .rpm packages

### 4.3 Distribution Channels
| Platform | Primary | Secondary |
|----------|---------|-----------|
| Windows | GitHub Releases (.exe) | Microsoft Store |
| macOS | GitHub Releases (.dmg) | Homebrew cask |
| Linux | GitHub Releases (.AppImage) | apt/dnf repos |
| Web | GitHub Pages | Self-hosted |

### 4.4 Auto-Update
- Check GitHub releases API for new versions
- Platform-specific download URLs
- User notification with release notes

### 4.5 Release Checklist
- All tests passing
- Version bumped
- CHANGELOG updated
- Artifacts built for all platforms
- GitHub release created
- Package managers updated

---

## Part 5: Security & Threat Model

### Threat Categories

| Category | Examples | Severity |
|----------|----------|----------|
| Integrity | Tampered API responses, malicious FFI calls | Critical |
| Confidentiality | Credential leakage, key exposure in logs | High |
| Availability | UI freeze, WebSocket DoS | Medium |
| Authentication | Session hijacking, CSRF | High |
| Authorization | Privilege escalation via API | High |

### Specific Threats

#### XSS (Cross-Site Scripting) - Web Only
- **Description**: Attacker injects malicious scripts via message content or peer IDs
- **Attacker**: Malicious peer on mesh network
- **Prerequisites**: Victim opens web GUI
- **Impact**: Session theft, credential exfiltration, UI manipulation
- **Likelihood**: Medium
- **Mitigation**:
  - Flutter Web auto-escapes by default
  - Sanitize all incoming JSON strings
  - Content Security Policy headers
  - No `dangerouslySetInnerHTML` patterns

#### CSRF (Cross-Site Request Forgery) - Web Only
- **Description**: Attacker tricks browser into making API calls
- **Attacker**: External website the user visits
- **Prerequisites**: User logged into GUI in another tab
- **Impact**: Unauthorized actions (send messages, store data)
- **Likelihood**: Medium
- **Mitigation**:
  - Same-origin check on API endpoints
  - CSRF tokens for state-changing operations
  - SameSite cookie attribute

#### Local Privilege Escalation - Desktop
- **Description**: Malicious code gains access via FFI context
- **Attacker**: Local malware, malicious plugin
- **Prerequisites**: Code execution on user's machine
- **Impact**: Full node compromise, key theft
- **Likelihood**: Low
- **Mitigation**:
  - FFI context not exportable
  - Secure memory for keys
  - Platform-specific sandboxing where available

#### WebSocket Hijacking
- **Description**: Attacker intercepts or spoofs WebSocket events
- **Attacker**: Network observer (LAN attack)
- **Prerequisites**: Same network as victim
- **Impact**: Event injection, data interception
- **Likelihood**: Low (localhost-only by default)
- **Mitigation**:
  - Bind to 127.0.0.1 only
  - Optional TLS for remote access
  - Origin header validation

#### Malicious Peer Data
- **Description**: Corrupted/malicious data from peers crashes GUI
- **Attacker**: Any mesh peer
- **Prerequisites**: Connected to network
- **Impact**: Denial of service, potential code execution
- **Likelihood**: Medium
- **Mitigation**:
  - Strict JSON schema validation
  - Length limits on all strings
  - Graceful error handling with fallback views

### Security Assumptions
1. Localhost binding is secure (no LAN attackers)
2. Flutter framework's built-in XSS protections are sufficient
3. OS-level process isolation protects FFI context
4. Users don't run untrusted Flutter plugins

### Trust Boundaries
```
+------------------+      +-------------------+      +------------------+
|  Flutter UI      | <--> |  API Layer        | <--> |  CyxWiz Core     |
|  (Untrusted      |      |  (Validation      |      |  (Trusted        |
|   display data)  |      |   boundary)       |      |   operations)    |
+------------------+      +-------------------+      +------------------+
         |
         v
+------------------+
|  User Input      |
|  (Untrusted)     |
+------------------+
```

- **Trust boundary 1**: User input → API layer (validate all inputs)
- **Trust boundary 2**: Peer data → API layer (sanitize, length-check)
- **Trust boundary 3**: FFI boundary (validate JSON, catch panics)

---

## Part 6: Failure & Recovery

### Failure Modes

| Component | Failure Mode | Symptoms | Detection | Recovery |
|-----------|--------------|----------|-----------|----------|
| WebSocket | Connection lost | No events | Heartbeat timeout | Auto-reconnect with backoff |
| HTTP API | Request timeout | Spinner, error | 30s timeout | Retry 3x, show error |
| FFI | C library crash | App crash | Process exit | Restart app, reload state |
| FFI Isolate | Isolate death | No responses | Completer timeout | Respawn isolate |
| State | Corrupted provider | Wrong data | Validation fail | Reset to fresh state |
| Storage | Local cache full | Save fails | Write error | Clear old entries |

### Recovery Procedures

#### WebSocket Reconnection
```dart
class ReconnectingWebSocket {
  int _retryCount = 0;
  final _maxRetries = 10;
  final _baseDelay = Duration(seconds: 1);

  void _scheduleReconnect() {
    if (_retryCount >= _maxRetries) {
      _showPermanentError();
      return;
    }
    final delay = _baseDelay * pow(2, _retryCount).clamp(1, 60);
    _retryCount++;
    Future.delayed(delay, _connect);
  }

  void _onConnected() {
    _retryCount = 0;  // Reset on success
    _resyncState();   // Fetch current state
  }
}
```

#### FFI Isolate Recovery
```dart
class FfiApi {
  Future<void> _respawnIsolate() async {
    await _workerIsolate?.kill();
    _workerIsolate = await Isolate.spawn(_ffiWorker, _mainReceivePort.sendPort);
    // Re-register callbacks
    // Resync state from C context
  }
}
```

#### Graceful Degradation
- Network offline: Show cached data with "offline" banner
- API errors: Show last known state + error indicator
- FFI unavailable: Web falls back to HTTP-only mode

### State Persistence

| State | Persisted | Location | Recovery |
|-------|-----------|----------|----------|
| Settings | Yes | SharedPreferences | Auto-load on start |
| Message history | Optional | Local SQLite | Re-fetch from daemon |
| Peer list | No | Memory | Refreshed from API |
| Credentials | Yes (encrypted) | Platform keychain | User re-enters if lost |

### What Cannot Be Recovered
- In-flight messages at crash time (not ACKed)
- Unsaved form inputs
- Ephemeral UI state (scroll positions, expanded rows)

---

## Part 7: Protocol Versioning

### API Version Format
```
Major.Minor.Patch (SemVer)
Example: 1.2.3
```

### Version Negotiation

#### HTTP API
```http
GET /api/version
Response: {"api_version": "1.2.0", "min_supported": "1.0.0"}

GET /api/status
X-API-Version: 1.2.0  (response header)
```

#### WebSocket
```json
// First message after connect
{"type": "hello", "api_version": "1.2.0", "client_version": "1.1.0"}

// Server response
{"type": "welcome", "api_version": "1.2.0", "compatible": true}
// or
{"type": "incompatible", "min_version": "1.2.0", "upgrade_url": "..."}
```

#### FFI
```c
// Get library version
CYXWIZ_EXPORT const char* cyxwiz_ffi_version(void);  // Returns "1.2.0"
CYXWIZ_EXPORT int cyxwiz_ffi_version_major(void);    // Returns 1
CYXWIZ_EXPORT int cyxwiz_ffi_version_minor(void);    // Returns 2

// Check compatibility
CYXWIZ_EXPORT bool cyxwiz_ffi_compatible(int major, int minor);
```

### Backwards Compatibility Policy

| Change Type | Version Bump | Breaking? |
|-------------|--------------|-----------|
| New optional field | Patch | No |
| New endpoint | Minor | No |
| New required field | Major | Yes |
| Remove endpoint | Major | Yes |
| Change field type | Major | Yes |
| Rename field | Major | Yes |

### Migration Path
1. New major version announced 30 days before release
2. Old version supported for 90 days after new release
3. Client shows upgrade prompt when server version ahead
4. Automatic schema migration for local storage

---

## Part 8: Rate Limiting & DoS Protection

### HTTP API Limits

| Endpoint | Rate Limit | Burst | Response When Exceeded |
|----------|------------|-------|------------------------|
| GET endpoints | 60/min | 10 | 429 Too Many Requests |
| POST /api/send | 30/min | 5 | 429 + retry-after header |
| POST /api/store | 10/min | 2 | 429 |
| WebSocket messages | 100/min | 20 | Close connection |

### Client-Side Throttling
```dart
class ThrottledApi {
  final _rateLimiter = RateLimiter(
    maxRequests: 60,
    window: Duration(minutes: 1),
  );

  Future<T> request<T>(Future<T> Function() fn) async {
    await _rateLimiter.acquire();
    return fn();
  }
}
```

### DoS Mitigation

#### Connection Limits
- Max 16 HTTP clients
- Max 8 WebSocket connections
- Connection timeout: 30 seconds idle

#### Request Limits
- Max request body: 1 MB
- Max URL length: 2048 chars
- Max header size: 8 KB

#### Response to Abuse
```c
// Server-side tracking
typedef struct {
    uint32_t ip_addr;
    uint32_t request_count;
    uint64_t window_start;
    uint8_t violations;
} rate_limit_entry_t;

// Escalating response
// 1st violation: 429 response
// 2nd violation: 60s cooldown
// 3rd violation: 10 minute ban
// 4th+ violation: 1 hour ban
```

### WebSocket Flow Control
- Backpressure on slow clients
- Event queue max: 1000 messages
- Stale events dropped with warning

---

## Part 9: Monitoring & Observability

### Key Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gui_http_requests_total` | Counter | endpoint, status | Total HTTP requests |
| `gui_http_latency_ms` | Histogram | endpoint | Request latency |
| `gui_ws_connections` | Gauge | - | Active WebSocket connections |
| `gui_ws_messages_total` | Counter | direction | WebSocket messages sent/received |
| `gui_ffi_calls_total` | Counter | function | FFI function calls |
| `gui_ffi_latency_ms` | Histogram | function | FFI call latency |
| `gui_errors_total` | Counter | type, source | Errors by category |

### Health Check Endpoints

| Endpoint | Method | Success Response | Failure Response |
|----------|--------|------------------|------------------|
| `/health` | GET | 200 `{"status": "ok"}` | 503 `{"status": "degraded", "reason": "..."}` |
| `/ready` | GET | 200 `{"ready": true}` | 503 `{"ready": false}` |

### Health Check Logic
```c
// /health - basic liveness
bool gui_is_healthy(cyxwiz_gui_ctx_t* ctx) {
    return ctx != NULL && ctx->listen_sock != INVALID_SOCKET;
}

// /ready - full readiness
bool gui_is_ready(cyxwiz_gui_ctx_t* ctx) {
    return gui_is_healthy(ctx)
        && ctx->ffi != NULL
        && cyxwiz_ffi_get_peer_count(ctx->ffi) > 0;
}
```

### Logging

| Level | When to Use | Examples |
|-------|-------------|----------|
| ERROR | Unrecoverable | FFI crash, socket bind fail |
| WARN | Recoverable | Client disconnect, rate limit hit |
| INFO | Normal ops | Client connect, API call |
| DEBUG | Troubleshooting | Request/response bodies, state changes |

### Log Format
```
[2024-01-15T10:30:45.123Z] [INFO] [gui] Client connected from 127.0.0.1:54321
[2024-01-15T10:30:45.456Z] [DEBUG] [api] GET /api/status -> 200 (12ms)
[2024-01-15T10:30:46.789Z] [WARN] [ws] Client 3 exceeded rate limit, throttling
```

### Alerting Conditions (for operators)
- HTTP error rate > 10% for 5 minutes
- WebSocket connections = 0 for 1 minute (no clients)
- FFI error rate > 1% for 1 minute
- Request latency P99 > 500ms

---

## Part 10: Accessibility (a11y)

### Target Compliance
- **WCAG 2.1 Level AA** for all screens
- **Platform accessibility APIs**: iOS VoiceOver, Android TalkBack, Windows Narrator, macOS VoiceOver

### Semantic Structure
```dart
// All interactive elements have semantics
Semantics(
  label: 'Send message to peer ${peer.shortId}',
  button: true,
  child: IconButton(
    onPressed: () => _sendMessage(peer),
    icon: Icon(Icons.send),
  ),
)

// Screen reader announcements for state changes
SemanticsService.announce('Message sent successfully', TextDirection.ltr);
```

### Keyboard Navigation
| Key | Action |
|-----|--------|
| Tab / Shift+Tab | Navigate between elements |
| Enter / Space | Activate focused element |
| Arrow keys | Navigate within lists/tables |
| Escape | Close dialogs/menus |
| Ctrl+1-7 | Jump to screen (Dashboard, Peers, ...) |

### Focus Management
```dart
// Trap focus in dialogs
FocusScope(
  autofocus: true,
  child: AlertDialog(...),
)

// Return focus after dialog closes
void _closeDialog() {
  Navigator.pop(context);
  _previousFocus?.requestFocus();
}
```

### Color & Contrast
- Minimum contrast ratio: 4.5:1 (text), 3:1 (large text)
- Don't rely on color alone (icons + labels)
- Support system high-contrast mode

### Screen Reader Testing
| Screen | Key Announcements |
|--------|-------------------|
| Dashboard | "Dashboard. 12 peers connected. 450 credits." |
| Peers | "Peer list. 12 items. Peer a3f8, connected, 45 milliseconds latency." |
| Messages | "Message from peer b7e2: Hello world. Received 2 minutes ago." |

### Motion & Animation
```dart
// Respect reduced motion preference
final reduceMotion = MediaQuery.of(context).disableAnimations;

AnimatedContainer(
  duration: reduceMotion ? Duration.zero : Duration(milliseconds: 300),
  ...
)
```

---

## Part 11: Internationalization (i18n)

### Supported Locales (Initial)
| Locale | Language | RTL |
|--------|----------|-----|
| en_US | English (US) | No |
| en_GB | English (UK) | No |
| es_ES | Spanish | No |
| zh_CN | Chinese (Simplified) | No |
| ar_SA | Arabic | Yes |
| he_IL | Hebrew | Yes |

### Implementation
```dart
// pubspec.yaml
dependencies:
  flutter_localizations:
    sdk: flutter
  intl: ^0.18.0

// lib/l10n/app_en.arb
{
  "dashboardTitle": "Dashboard",
  "peerCount": "{count, plural, =0{No peers} =1{1 peer} other{{count} peers}}",
  "@peerCount": {
    "placeholders": {
      "count": {"type": "int"}
    }
  },
  "sendButton": "Send",
  "messageHint": "Type a message..."
}

// Usage
Text(AppLocalizations.of(context)!.dashboardTitle)
Text(AppLocalizations.of(context)!.peerCount(peerList.length))
```

### RTL Support
```dart
// Automatic RTL based on locale
MaterialApp(
  localizationsDelegates: [...],
  supportedLocales: [...],
  builder: (context, child) {
    return Directionality(
      textDirection: Bidi.isRtlLanguage(Localizations.localeOf(context).languageCode)
          ? TextDirection.rtl
          : TextDirection.ltr,
      child: child!,
    );
  },
)

// Mirrored layouts for RTL
Padding(
  padding: EdgeInsetsDirectional.only(start: 16),  // Not left/right
  child: ...
)
```

### Number & Date Formatting
```dart
// Locale-aware formatting
final formatter = NumberFormat.compact(locale: locale);
Text(formatter.format(credits));  // "1.2K" or "1,2K" depending on locale

final dateFormatter = DateFormat.yMMMd(locale);
Text(dateFormatter.format(timestamp));  // "Jan 15, 2024" or "15 Jan 2024"
```

### Translation Workflow
1. Extract strings: `flutter gen-l10n`
2. Send `.arb` files to translators
3. Import translated `.arb` files
4. Test with pseudo-localization (double-length strings)

---

## Part 12: Offline Mode

### Offline Capability Matrix

| Feature | Offline Support | Notes |
|---------|----------------|-------|
| View dashboard | Partial | Cached status, stale indicator |
| View peer list | Partial | Last known list, "offline" badge |
| Read messages | Full | All cached locally |
| Send messages | Queued | Sent when online |
| Storage ops | No | Requires network |
| Compute jobs | No | Requires network |
| Settings | Full | Local only |

### Caching Strategy

```dart
// Local cache with Hive
@HiveType(typeId: 0)
class CachedStatus {
  @HiveField(0)
  final int peerCount;
  @HiveField(1)
  final int credits;
  @HiveField(2)
  final DateTime cachedAt;
}

class CacheManager {
  static const maxAge = Duration(hours: 24);

  Future<NodeStatus> getStatus() async {
    final cached = await _cache.get('status');
    if (cached != null && !_isStale(cached)) {
      return cached.toStatus();
    }

    try {
      final fresh = await _api.getStatus();
      await _cache.put('status', CachedStatus.fromStatus(fresh));
      return fresh;
    } catch (e) {
      if (cached != null) return cached.toStatus(); // Stale is better than nothing
      rethrow;
    }
  }
}
```

### Offline Detection
```dart
class ConnectivityProvider extends ChangeNotifier {
  bool _isOnline = true;
  StreamSubscription? _sub;

  void init() {
    _sub = Connectivity().onConnectivityChanged.listen((result) {
      _isOnline = result != ConnectivityResult.none;
      notifyListeners();
    });
  }

  bool get isOnline => _isOnline;
}

// UI indicator
Consumer<ConnectivityProvider>(
  builder: (context, conn, _) => conn.isOnline
      ? SizedBox.shrink()
      : Banner(message: 'Offline', color: Colors.orange),
)
```

### Message Queue (Outbox)
```dart
class MessageOutbox {
  final _queue = <QueuedMessage>[];

  Future<void> send(String peerId, String content) async {
    final msg = QueuedMessage(peerId, content, DateTime.now());
    _queue.add(msg);
    await _persist();

    if (_isOnline) {
      await _flush();
    }
  }

  Future<void> _flush() async {
    while (_queue.isNotEmpty) {
      final msg = _queue.first;
      try {
        await _api.sendMessage(msg.peerId, msg.content);
        _queue.removeAt(0);
        await _persist();
      } catch (e) {
        break;  // Stop on first failure
      }
    }
  }
}
```

### Service Worker (Web Only)
```javascript
// web/service_worker.js
const CACHE_NAME = 'cyxwiz-gui-v1';
const STATIC_ASSETS = [
  '/',
  '/main.dart.js',
  '/flutter.js',
  '/icons/Icon-192.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(STATIC_ASSETS))
  );
});

self.addEventListener('fetch', (event) => {
  // Cache-first for static assets
  // Network-first for API calls
});
```

### Sync on Reconnect
```dart
class SyncManager {
  Future<void> onReconnect() async {
    // 1. Flush message outbox
    await _outbox.flush();

    // 2. Refresh stale caches
    await _cache.refreshStale();

    // 3. Re-subscribe to events
    await _ws.resubscribe();

    // 4. Reconcile any conflicts
    await _reconcile();
  }
}
