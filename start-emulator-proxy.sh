#!/bin/bash
# Start Android emulator with Burp proxy configured
#
# Usage: ./start-emulator-proxy.sh [proxy-host:port]
#
# Prerequisites:
#   - Burp Suite running on host (default: localhost:8080)
#   - Burp CA certificate installed (run install-burp-cert.sh first)

set -e

PROXY="${1:-10.0.2.2:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Starting Emulator with Proxy ==="
echo "Proxy: $PROXY"
echo ""

# Start emulator
"$SCRIPT_DIR/start-emulator.sh"

# Wait briefly for settings to be available
echo ""
echo "Configuring proxy..."
sleep 2

# Configure proxy
"$SCRIPT_DIR/configure-proxy.sh" "$PROXY"

echo ""
echo "=== Emulator Ready with Proxy ==="
echo "Proxy: $PROXY"
echo ""
echo "Verify Burp is receiving traffic:"
echo "  1. Open browser in emulator"
echo "  2. Visit any HTTP site"
echo "  3. Check Burp's HTTP History tab"
echo ""
echo "For HTTPS interception, ensure Burp CA is installed:"
echo "  ./install-burp-cert.sh"
