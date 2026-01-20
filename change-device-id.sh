#!/bin/bash
#
# Change Android Device ID
#
# Changes the android_id on the emulator and optionally clears app data.
# This makes the emulator appear as a different device to apps that track
# device limits.
#
# Usage:
#   ./change-device-id.sh                    # Generate random ID
#   ./change-device-id.sh abc123def456789a   # Use specific ID
#   ./change-device-id.sh --clear com.example.app  # Clear app after changing ID
#
# Examples:
#   ./change-device-id.sh --clear openroads.fueldiscountapp
#   ./change-device-id.sh myCustomId123 --clear com.example.app
#

set -e

# Parse arguments
NEW_ID=""
CLEAR_APP=""
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --clear)
            CLEAR_APP="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [new_id] [--clear package_name]"
            echo ""
            echo "Options:"
            echo "  new_id            16-character hex ID (random if not specified)"
            echo "  --clear PACKAGE   Clear app data after changing ID"
            echo ""
            echo "Examples:"
            echo "  $0                              # Random new ID"
            echo "  $0 abc123def456789a             # Specific ID"
            echo "  $0 --clear com.example.app      # Random ID + clear app"
            exit 0
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# Get new ID from positional args or generate random
if [ ${#POSITIONAL[@]} -gt 0 ]; then
    NEW_ID="${POSITIONAL[0]}"
else
    NEW_ID=$(openssl rand -hex 8)
fi

# Validate ID format (should be hex)
if ! [[ "$NEW_ID" =~ ^[a-fA-F0-9]+$ ]]; then
    echo "Error: ID must be hexadecimal characters only"
    exit 1
fi

# Get current ID
CURRENT_ID=$(adb shell settings get secure android_id)

echo "=== Device ID Changer ==="
echo ""
echo "Current android_id: $CURRENT_ID"
echo "New android_id:     $NEW_ID"
echo ""

# Change the ID
adb shell settings put secure android_id "$NEW_ID"

# Verify
VERIFY_ID=$(adb shell settings get secure android_id)
if [ "$VERIFY_ID" = "$NEW_ID" ]; then
    echo "[OK] android_id changed successfully"
else
    echo "[ERROR] Failed to change android_id"
    exit 1
fi

# Clear app data if requested
if [ -n "$CLEAR_APP" ]; then
    echo ""
    echo "Clearing data for: $CLEAR_APP"
    if adb shell pm clear "$CLEAR_APP" 2>/dev/null; then
        echo "[OK] App data cleared"
    else
        echo "[WARN] Could not clear app data (app may not be installed)"
    fi
fi

echo ""
echo "Done! The emulator will now appear as a different device."
echo ""
echo "Next steps:"
echo "1. Launch the app: adb shell monkey -p $CLEAR_APP 1"
echo "2. Log in with your credentials"
echo "3. The app will register this as a new device"
