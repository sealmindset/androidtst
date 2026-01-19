#!/bin/bash
# Decode APK to extract resources and manifest using apktool
#
# Usage: ./decode-apk.sh [path/to/app.apk]
#        (defaults to most recent APK in apks/ directory)
#
# Prerequisites:
#   - apktool installed: brew install apktool

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for apktool
if ! command -v apktool &> /dev/null; then
    echo "ERROR: apktool is not installed."
    echo ""
    echo "Install with Homebrew:"
    echo "  brew install apktool"
    exit 1
fi

# Get APK path
if [ -n "$1" ]; then
    APK_PATH="$1"
else
    # Find most recent APK in apks/ directory
    APK_PATH=$(ls -t "$SCRIPT_DIR/apks"/*.apk 2>/dev/null | head -1)
    if [ -z "$APK_PATH" ]; then
        echo "ERROR: No APK specified and none found in apks/"
        echo ""
        echo "Usage: ./decode-apk.sh [path/to/app.apk]"
        echo ""
        echo "Extract an APK first: ./extract-apk.sh <package-name>"
        exit 1
    fi
fi

# Validate APK exists
if [ ! -f "$APK_PATH" ]; then
    echo "ERROR: APK not found: $APK_PATH"
    exit 1
fi

# Create output directory based on APK name
APK_NAME=$(basename "$APK_PATH" .apk)
OUTPUT_DIR="$SCRIPT_DIR/decompiled/${APK_NAME}/apktool"

echo "=== APK Decoder (apktool) ==="
echo ""
echo "Input:  $APK_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

# Run apktool decode
echo "Decoding APK..."
apktool d "$APK_PATH" -o "$OUTPUT_DIR" -f

echo ""
echo "=== Decode Complete ==="
echo ""
echo "Key files for security analysis:"
echo ""

# Show manifest info
if [ -f "$OUTPUT_DIR/AndroidManifest.xml" ]; then
    echo "AndroidManifest.xml:"
    PERMS=$(grep -c "uses-permission" "$OUTPUT_DIR/AndroidManifest.xml" 2>/dev/null || echo "0")
    EXPORTED=$(grep -c 'exported="true"' "$OUTPUT_DIR/AndroidManifest.xml" 2>/dev/null || echo "0")
    echo "  Permissions requested: $PERMS"
    echo "  Exported components: $EXPORTED"
    echo "  View: cat $OUTPUT_DIR/AndroidManifest.xml"
fi

echo ""

# Check for network security config
if [ -f "$OUTPUT_DIR/res/xml/network_security_config.xml" ]; then
    echo "Network Security Config found:"
    echo "  $OUTPUT_DIR/res/xml/network_security_config.xml"
    echo ""
fi

echo "Directories:"
echo "  $OUTPUT_DIR/AndroidManifest.xml - App manifest"
echo "  $OUTPUT_DIR/res/                 - Resources (layouts, strings, xml)"
echo "  $OUTPUT_DIR/smali/               - Smali bytecode"
echo ""
echo "Quick analysis:"
echo "  # View permissions"
echo "  grep 'uses-permission' $OUTPUT_DIR/AndroidManifest.xml"
echo ""
echo "  # Find exported components (potential attack surface)"
echo "  grep -B2 'exported=\"true\"' $OUTPUT_DIR/AndroidManifest.xml"
