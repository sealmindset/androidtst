#!/bin/bash
# Android Test Harness Setup Script
# Installs Android SDK, creates emulator with Google Play Store

set -e

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-mac-11076708_latest.zip"

echo "=== Android Test Harness Setup ==="
echo ""

# Check for Java (test if it actually works, not just if command exists)
if ! java -version &> /dev/null; then
    echo "Java is required. Installing via Homebrew..."
    brew install openjdk@17
    echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zshrc
    export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
fi

# Ensure Homebrew Java is in PATH for this session
if [ -d "/opt/homebrew/opt/openjdk@17/bin" ]; then
    export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
fi

echo "Java version:"
java -version

# Create SDK directory
echo ""
echo "=== Setting up Android SDK ==="
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"

# Download command-line tools if not present
if [ ! -d "$ANDROID_SDK_ROOT/cmdline-tools/latest" ]; then
    echo "Downloading Android command-line tools..."
    cd /tmp
    curl -L -o cmdline-tools.zip "$CMDLINE_TOOLS_URL"
    unzip -q -o cmdline-tools.zip
    mv cmdline-tools "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm cmdline-tools.zip
    echo "Command-line tools installed."
else
    echo "Command-line tools already installed."
fi

# Set up environment variables
export ANDROID_SDK_ROOT="$ANDROID_SDK_ROOT"
export ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

# Add to shell profile if not already there
SHELL_PROFILE="$HOME/.zshrc"
if ! grep -q "ANDROID_SDK_ROOT" "$SHELL_PROFILE" 2>/dev/null; then
    echo "" >> "$SHELL_PROFILE"
    echo "# Android SDK" >> "$SHELL_PROFILE"
    echo "export ANDROID_SDK_ROOT=\"$ANDROID_SDK_ROOT\"" >> "$SHELL_PROFILE"
    echo "export ANDROID_HOME=\"$ANDROID_SDK_ROOT\"" >> "$SHELL_PROFILE"
    echo 'export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"' >> "$SHELL_PROFILE"
    echo "Added Android SDK to $SHELL_PROFILE"
fi

# Accept licenses
echo ""
echo "=== Accepting SDK Licenses ==="
yes | sdkmanager --licenses > /dev/null 2>&1 || true

# Install required SDK components
echo ""
echo "=== Installing SDK Components ==="
echo "This may take a while..."

# Install platform-tools (adb)
sdkmanager "platform-tools"

# Install emulator
sdkmanager "emulator"

# Install system image with Google Play Store (API 34 - Android 14)
# Using google_apis_playstore for Play Store access
sdkmanager "system-images;android-34;google_apis_playstore;arm64-v8a"

# Install platform
sdkmanager "platforms;android-34"

# Install build-tools
sdkmanager "build-tools;34.0.0"

echo ""
echo "=== Creating AVD (Android Virtual Device) ==="

# Create AVD with Google Play Store
AVD_NAME="SleepIQ_Test_Device"

# Check if AVD already exists
if avdmanager list avd | grep -q "$AVD_NAME"; then
    echo "AVD '$AVD_NAME' already exists."
else
    echo "Creating AVD '$AVD_NAME' with Google Play Store..."
    echo "no" | avdmanager create avd \
        --name "$AVD_NAME" \
        --package "system-images;android-34;google_apis_playstore;arm64-v8a" \
        --device "pixel_6" \
        --force
    echo "AVD created successfully."
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To use the Android tools, either:"
echo "  1. Restart your terminal, or"
echo "  2. Run: source ~/.zshrc"
echo ""
echo "Then you can:"
echo "  - Start emulator: ./start-emulator.sh"
echo "  - Install SleepIQ app: ./install-sleepiq.sh"
echo "  - Run test harness: ./run-tests.sh"
