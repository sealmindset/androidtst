#!/bin/bash
# Connect to a physical Android device for Bluetooth testing
#
# Usage: TARGET_PACKAGE=com.example.app ./connect-device.sh

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$PATH"

PACKAGE_NAME="${TARGET_PACKAGE:-}"

echo "=== Physical Device Connection ==="
echo ""
echo "Prerequisites:"
echo "  1. Enable Developer Options on your Android device:"
echo "     Settings > About Phone > Tap 'Build Number' 7 times"
echo "  2. Enable USB Debugging:"
echo "     Settings > Developer Options > USB Debugging"
echo "  3. Connect device via USB cable"
echo ""

# Check for connected devices
echo "Checking for connected devices..."
DEVICES=$(adb devices | grep -v "List" | grep -v "^$" | grep -v "emulator")

if [ -z "$DEVICES" ]; then
    echo "No physical devices found."
    echo ""
    echo "Troubleshooting:"
    echo "  - Ensure USB cable supports data transfer (not charge-only)"
    echo "  - Check for 'Allow USB debugging' prompt on device"
    echo "  - Try: adb kill-server && adb start-server"
    echo ""

    # Also check for wireless debugging
    echo "For wireless debugging (Android 11+):"
    echo "  1. Enable Wireless debugging in Developer Options"
    echo "  2. Run: adb pair <ip>:<port>"
    echo "  3. Run: adb connect <ip>:<port>"
    exit 1
fi

echo "Connected devices:"
echo "$DEVICES"
echo ""

# Get device info
DEVICE_ID=$(echo "$DEVICES" | head -1 | cut -f1)
echo "Using device: $DEVICE_ID"
echo ""

echo "Device Info:"
echo "  Model: $(adb -s "$DEVICE_ID" shell getprop ro.product.model)"
echo "  Android: $(adb -s "$DEVICE_ID" shell getprop ro.build.version.release)"
echo "  SDK: $(adb -s "$DEVICE_ID" shell getprop ro.build.version.sdk)"
echo ""

# Check Bluetooth status
echo "Bluetooth Status:"
BT_STATE=$(adb -s "$DEVICE_ID" shell settings get global bluetooth_on 2>/dev/null)
if [ "$BT_STATE" = "1" ]; then
    echo "  Bluetooth: ON"
else
    echo "  Bluetooth: OFF"
    echo ""
    echo "  To enable Bluetooth via ADB:"
    echo "    adb shell am start -a android.bluetooth.adapter.action.REQUEST_ENABLE"
fi
echo ""

# Check proxy status
echo "Proxy Status:"
PROXY_SETTING=$(adb -s "$DEVICE_ID" shell settings get global http_proxy 2>/dev/null)
if [ -n "$PROXY_SETTING" ] && [ "$PROXY_SETTING" != ":0" ] && [ "$PROXY_SETTING" != "null" ]; then
    echo "  Proxy: ENABLED ($PROXY_SETTING)"
else
    echo "  Proxy: DISABLED"
    echo "  To enable: ./configure-proxy.sh"
fi
echo ""

# Check if target app is installed (if TARGET_PACKAGE is set)
if [ -n "$PACKAGE_NAME" ]; then
    if adb -s "$DEVICE_ID" shell pm list packages | grep -q "$PACKAGE_NAME"; then
        echo "Target app ($PACKAGE_NAME): INSTALLED"

        # Get app version
        VERSION=$(adb -s "$DEVICE_ID" shell dumpsys package "$PACKAGE_NAME" | grep versionName | head -1 | cut -d'=' -f2)
        echo "  Version: $VERSION"
    else
        echo "Target app ($PACKAGE_NAME): NOT INSTALLED"
        echo ""
        echo "Install from Play Store or use:"
        echo "  adb install path/to/app.apk"
    fi
else
    echo "No TARGET_PACKAGE set. Skipping app check."
    echo "Set TARGET_PACKAGE to check app installation status."
fi

echo ""
echo "=== Ready for Testing ==="
echo ""
echo "Run the test harness:"
echo "  ./run-tests.sh"
echo "  # or"
echo "  python3 test_harness.py"
echo ""
echo "Bluetooth-specific commands:"
echo "  # Enable Bluetooth"
echo "  adb shell am start -a android.bluetooth.adapter.action.REQUEST_ENABLE"
echo ""
echo "  # Open Bluetooth settings"
echo "  adb shell am start -a android.settings.BLUETOOTH_SETTINGS"
echo ""
echo "  # Check paired devices"
echo "  adb shell dumpsys bluetooth_manager | grep -A5 'Bonded devices'"
echo ""
echo "  # View Bluetooth logs"
echo "  adb logcat -s BluetoothAdapter:V BluetoothGatt:V"
