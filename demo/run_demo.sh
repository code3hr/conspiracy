#!/bin/bash
# CyxWiz End-to-End Demo
# ========================
# This script demonstrates the CyxWiz mesh network:
# 1. Starts a bootstrap server
# 2. Launches 3 nodes that discover each other
# 3. Nodes form a mesh and run consensus

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"
BOOTSTRAP="$BUILD_DIR/cyxwiz-bootstrap"
DAEMON="$BUILD_DIR/cyxwizd"

# Check if executables exist
if [ ! -f "$BOOTSTRAP" ]; then
    echo "ERROR: Bootstrap not found. Run: cmake --build build"
    exit 1
fi
if [ ! -f "$DAEMON" ]; then
    echo "ERROR: Daemon not found. Run: cmake --build build"
    exit 1
fi

echo ""
echo "  ================================================"
echo "       CyxWiz End-to-End Demo"
echo "  ================================================"
echo ""
echo "  This demo will:"
echo "  1. Start a bootstrap server on port 7777"
echo "  2. Launch 3 nodes that connect via UDP"
echo "  3. Nodes will discover each other"
echo "  4. After 30s, consensus validation will trigger"
echo ""
echo "  Press Ctrl+C to stop the demo."
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping all processes..."
    kill $BOOTSTRAP_PID 2>/dev/null || true
    kill $NODE1_PID 2>/dev/null || true
    kill $NODE2_PID 2>/dev/null || true
    kill $NODE3_PID 2>/dev/null || true
    echo "Demo complete!"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start bootstrap server
echo "[1/4] Starting bootstrap server..."
$BOOTSTRAP 7777 &
BOOTSTRAP_PID=$!
sleep 2

# Set bootstrap address
export CYXWIZ_BOOTSTRAP="127.0.0.1:7777"

# Start 3 nodes
echo "[2/4] Starting Node 1..."
$DAEMON &
NODE1_PID=$!
sleep 1

echo "[3/4] Starting Node 2..."
$DAEMON &
NODE2_PID=$!
sleep 1

echo "[4/4] Starting Node 3..."
$DAEMON &
NODE3_PID=$!

echo ""
echo "  ================================================"
echo "       Demo Running!"
echo "  ================================================"
echo ""
echo "  Watch for:"
echo "  - 'Registered' messages in bootstrap"
echo "  - 'Discovered peer' messages in nodes"
echo "  - 'Peer state: UNKNOWN -> ACTIVE' transitions"
echo "  - 'Triggering test validation' after 30s"
echo ""
echo "  Press Ctrl+C to stop..."
echo ""

# Wait for all processes
wait
