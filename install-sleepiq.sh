#!/bin/bash
# Install SleepIQ App from Google Play Store

set -e

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$PATH"

PACKAGE_NAME="com.selectcomfort.SleepIQ"
PLAY_STORE_URL="https://play.google.com/store/apps/details?id=$PACKAGE_NAME"

echo "=== SleepIQ App Installation ==="
echo ""

# Check if emulator is running
if ! adb devices | grep -q "emulator"; then
    echo "ERROR: No emulator running. Start it first with: ./start-emulator.sh"
    exit 1
fi

# Check if app is already installed
if adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo "SleepIQ app is already installed!"
    echo ""
    echo "To launch the app:"
    echo "  adb shell monkey -p $PACKAGE_NAME 1"
    echo ""
    echo "To uninstall and reinstall:"
    echo "  adb uninstall $PACKAGE_NAME"
    exit 0
fi

echo "Opening Google Play Store to SleepIQ app page..."
echo ""

# Open Play Store to the app page
adb shell am start -a android.intent.action.VIEW \
    -d "market://details?id=$PACKAGE_NAME"

echo "=============================================="
echo "MANUAL STEPS REQUIRED:"
echo "=============================================="
echo ""
echo "1. The Play Store should now be open on the emulator"
echo "2. Sign in to your Google Account if prompted"
echo "3. Click 'Install' to download the SleepIQ app"
echo "4. Wait for installation to complete"
echo ""
echo "Once installed, run: ./run-tests.sh"
echo ""
echo "=============================================="
echo ""
echo "Alternative: If you have the APK file, install directly:"
echo "  adb install path/to/sleepiq.apk"
echo ""

# Wait for user to install
read -p "Press Enter once you've installed the app from Play Store..."

# Verify installation
if adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo ""
    echo "SUCCESS: SleepIQ app is now installed!"

    # Get app info
    echo ""
    echo "App Info:"
    adb shell dumpsys package "$PACKAGE_NAME" | grep -E "versionName|versionCode|firstInstallTime" | head -5
else
    echo ""
    echo "WARNING: SleepIQ app not detected. Please try installing again."
fi
