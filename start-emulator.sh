#!/bin/bash
# Start the Android Emulator with Google Play Store

set -e

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
export PATH="$ANDROID_SDK_ROOT/emulator:$ANDROID_SDK_ROOT/platform-tools:$PATH"

AVD_NAME="Android_Test_Device"

echo "=== Starting Android Emulator ==="
echo "Device: $AVD_NAME"
echo ""

# Check if emulator is already running
if adb devices | grep -q "emulator"; then
    echo "Emulator is already running."
    adb devices
    exit 0
fi

# Start emulator in background
# Options:
#   -no-snapshot-load: Start fresh each time
#   -gpu host: Use host GPU for better performance
#   -no-audio: Disable audio (optional, remove if you need sound)
echo "Starting emulator (this may take a minute)..."
nohup emulator -avd "$AVD_NAME" \
    -gpu host \
    -no-audio \
    -no-boot-anim \
    > /tmp/emulator.log 2>&1 &

EMULATOR_PID=$!
echo "Emulator PID: $EMULATOR_PID"

# Wait for emulator to boot
echo "Waiting for emulator to boot..."
adb wait-for-device

# Wait for boot to complete
echo "Waiting for system to fully boot..."
while [ "$(adb shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
    sleep 2
    echo -n "."
done
echo ""

echo ""
echo "=== Emulator Ready ==="
echo ""
echo "Device info:"
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
echo ""
echo "To interact with the emulator:"
echo "  - ADB shell: adb shell"
echo "  - Install APK: adb install <path-to-apk>"
echo "  - Take screenshot: adb exec-out screencap -p > screenshot.png"
echo "  - Stop emulator: adb emu kill"
