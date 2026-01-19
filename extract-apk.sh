#!/bin/bash
# Extract APK from installed app

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$PATH"

PACKAGE_NAME="${1:-com.selectcomfort.SleepIQ}"
OUTPUT_DIR="$(dirname "$0")/apks"

mkdir -p "$OUTPUT_DIR"

echo "=== APK Extractor ==="
echo ""
echo "Package: $PACKAGE_NAME"
echo ""

# Check device connection
if ! adb devices | grep -qE "device$|emulator"; then
    echo "ERROR: No device connected."
    echo "Start the emulator or connect a physical device."
    exit 1
fi

# Check if package is installed
if ! adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo "ERROR: Package '$PACKAGE_NAME' is not installed."
    exit 1
fi

# Get the APK path(s)
echo "Finding APK location..."
APK_PATHS=$(adb shell pm path "$PACKAGE_NAME")

if [ -z "$APK_PATHS" ]; then
    echo "ERROR: Could not find APK path."
    exit 1
fi

echo "Found:"
echo "$APK_PATHS"
echo ""

# Get app version for filename
VERSION=$(adb shell dumpsys package "$PACKAGE_NAME" | grep versionName | head -1 | sed 's/.*versionName=//' | tr -d '[:space:]')
echo "Version: $VERSION"
echo ""

# Pull each APK (some apps have split APKs)
COUNT=0
echo "$APK_PATHS" | while read -r line; do
    APK_PATH=$(echo "$line" | sed 's/package://')

    if [ -z "$APK_PATH" ]; then
        continue
    fi

    # Determine output filename
    BASENAME=$(basename "$APK_PATH")
    if [ "$BASENAME" = "base.apk" ]; then
        OUTPUT_FILE="$OUTPUT_DIR/${PACKAGE_NAME##*.}_v${VERSION}.apk"
    else
        OUTPUT_FILE="$OUTPUT_DIR/${PACKAGE_NAME##*.}_v${VERSION}_${BASENAME}"
    fi

    echo "Extracting: $APK_PATH"
    echo "       To: $OUTPUT_FILE"

    adb pull "$APK_PATH" "$OUTPUT_FILE"

    if [ $? -eq 0 ]; then
        SIZE=$(ls -lh "$OUTPUT_FILE" | awk '{print $5}')
        echo "Success! Size: $SIZE"
    else
        echo "Failed to extract."
    fi
    echo ""
done

echo "=== Done ==="
echo ""
echo "APKs saved to: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*.apk 2>/dev/null
echo ""
echo "To install on another device:"
echo "  adb install $OUTPUT_DIR/${PACKAGE_NAME##*.}_v${VERSION}.apk"
