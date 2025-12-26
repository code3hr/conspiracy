# CyxWiz End-to-End Demo

This demo runs a local CyxWiz mesh network to demonstrate:

1. **Peer Discovery** - Nodes find each other via bootstrap server
2. **Mesh Routing** - Messages routed through the network
3. **Onion Routing** - Anonymous 3-hop encrypted paths
4. **Consensus** - Validators agree on job results

## Quick Start

### Windows (PowerShell)

```powershell
# Build first
cd D:\Dev\conspiracy
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --config Release

# Run demo
.\demo\run_demo.ps1
```

### Linux/macOS

```bash
# Build first
cd /path/to/conspiracy
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run demo
chmod +x demo/run_demo.sh
./demo/run_demo.sh
```

## Manual Setup

If you prefer to run components manually:

### Terminal 1: Bootstrap Server

```bash
# Windows
build-release\Release\cyxwiz-bootstrap.exe 7777

# Linux/macOS
./build/cyxwiz-bootstrap 7777
```

### Terminal 2-4: Nodes

```bash
# Windows
set CYXWIZ_BOOTSTRAP=127.0.0.1:7777
build-release\Release\cyxwizd.exe

# Linux/macOS
export CYXWIZ_BOOTSTRAP=127.0.0.1:7777
./build/cyxwizd
```

## What to Watch For

### Bootstrap Server Output

```
CyxWiz Bootstrap Server
=======================
Listening on port 7777

Registered: a1b2c3d4e5f6...  from 127.0.0.1:54321 (total: 1)
Registered: f6e5d4c3b2a1...  from 127.0.0.1:54322 (total: 2)
Sent 1 peers to 127.0.0.1:54322
```

### Node Output

```
  ██████╗██╗   ██╗██╗  ██╗██╗    ██╗██╗███████╗
 ██╔════╝╚██╗ ██╔╝╚██╗██╔╝██║    ██║██║╚══███╔╝
 ██║      ╚████╔╝  ╚███╔╝ ██║ █╗ ██║██║  ███╔╝
 ...

[INFO] Local node ID: a1b2c3d4e5f67890...
[INFO] Using UDP/Internet transport
[INFO] Discovered peer via UDP (RSSI: 0 dBm)
[INFO] Peer f6e5d4c3... state: UNKNOWN -> ACTIVE
[INFO] Onion routing enabled
[INFO] Compute protocol enabled (worker mode)
[INFO] Storage protocol enabled (provider mode)
[INFO] Consensus protocol enabled (validator mode)
[INFO] Node running. Press Ctrl+C to stop.

[INFO] Scheduling test validation in 30 seconds...
[INFO] Triggering test validation round...
[INFO] Test validation round started successfully
```

## Architecture

```
   ┌─────────────────────────────────────────────────┐
   │              Bootstrap Server                    │
   │                (port 7777)                       │
   │   - Tracks registered nodes                      │
   │   - Provides peer lists to new nodes             │
   └─────────────────────────────────────────────────┘
                        │
           ┌────────────┼────────────┐
           │            │            │
           ▼            ▼            ▼
   ┌───────────┐  ┌───────────┐  ┌───────────┐
   │   Node 1  │──│   Node 2  │──│   Node 3  │
   │           │  │           │  │           │
   │ - Router  │  │ - Router  │  │ - Router  │
   │ - Onion   │  │ - Onion   │  │ - Onion   │
   │ - Compute │  │ - Compute │  │ - Compute │
   │ - Storage │  │ - Storage │  │ - Storage │
   │ - Consens │  │ - Consens │  │ - Consens │
   └───────────┘  └───────────┘  └───────────┘
```

## Troubleshooting

### "Bootstrap not found"

Build the project first:
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Nodes don't discover each other

1. Check firewall allows UDP on ports 7777+
2. Ensure `CYXWIZ_BOOTSTRAP` is set correctly
3. Try running on `0.0.0.0` instead of `127.0.0.1`

### Windows Defender warning

The first time you run, Windows may ask for network permission. Click "Allow access".
