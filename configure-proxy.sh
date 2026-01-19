#!/bin/bash
# Configure Android emulator proxy settings
#
# Usage: ./configure-proxy.sh [host:port]
#        ./configure-proxy.sh --disable
#    or: BURP_PROXY=10.0.2.2:8080 ./configure-proxy.sh
#
# Default proxy: 10.0.2.2:8080 (Burp on host machine)
# Note: 10.0.2.2 is the Android emulator's special alias for the host's localhost

set -e

# Show usage
show_usage() {
    echo "Usage: ./configure-proxy.sh [host:port]"
    echo "       ./configure-proxy.sh --disable"
    echo "   or: BURP_PROXY=10.0.2.2:8080 ./configure-proxy.sh"
    echo ""
    echo "Examples:"
    echo "  ./configure-proxy.sh              # Enable proxy (default: 10.0.2.2:8080)"
    echo "  ./configure-proxy.sh 10.0.2.2:8081  # Enable proxy on custom port"
    echo "  ./configure-proxy.sh --disable    # Disable proxy"
    echo "  BURP_PROXY=10.0.2.2:8081 ./configure-proxy.sh  # Use env var"
    echo ""
    echo "Priority: CLI argument > BURP_PROXY env var > default (10.0.2.2:8080)"
}

# Check for help flag
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    show_usage
    exit 0
fi

# Check if emulator is running
if ! adb devices | grep -q "emulator"; then
    echo "ERROR: No emulator detected."
    echo "Start an emulator first: ./start-emulator.sh"
    exit 1
fi

# Get device ID (first emulator found)
DEVICE_ID=$(adb devices | grep "emulator" | head -1 | cut -f1)

# Show current proxy setting
echo "=== Proxy Configuration ==="
echo "Device: $DEVICE_ID"
echo ""
CURRENT_PROXY=$(adb -s "$DEVICE_ID" shell settings get global http_proxy 2>/dev/null || echo "null")
echo "Current proxy: $CURRENT_PROXY"

# Handle disable flag
if [ "$1" = "--disable" ] || [ "$1" = "--off" ]; then
    adb -s "$DEVICE_ID" shell settings put global http_proxy :0
    echo ""
    echo "Proxy DISABLED"
    echo ""
    echo "To re-enable: ./configure-proxy.sh"
    exit 0
fi

# Get proxy address (priority: CLI arg > env var > default)
if [ -n "$1" ]; then
    PROXY="$1"
elif [ -n "$BURP_PROXY" ]; then
    PROXY="$BURP_PROXY"
else
    PROXY="10.0.2.2:8080"
fi

# Validate proxy format (basic check)
if ! echo "$PROXY" | grep -qE "^[0-9.]+:[0-9]+$"; then
    echo "ERROR: Invalid proxy format. Use host:port (e.g., 10.0.2.2:8080)"
    exit 1
fi

# Set proxy
adb -s "$DEVICE_ID" shell settings put global http_proxy "$PROXY"

echo ""
echo "Proxy ENABLED: $PROXY"
echo ""
echo "Verify Burp Suite is listening on the host machine."
echo "To disable: ./configure-proxy.sh --disable"
