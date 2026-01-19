#!/bin/bash
# Decompile APK to Java source using jadx
#
# Usage: ./decompile-apk.sh [path/to/app.apk]
#        (defaults to most recent APK in apks/ directory)
#
# Prerequisites:
#   - jadx installed: brew install jadx

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for jadx
if ! command -v jadx &> /dev/null; then
    echo "ERROR: jadx is not installed."
    echo ""
    echo "Install with Homebrew:"
    echo "  brew install jadx"
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
        echo "Usage: ./decompile-apk.sh [path/to/app.apk]"
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
OUTPUT_DIR="$SCRIPT_DIR/decompiled/${APK_NAME}/jadx"

echo "=== APK Decompiler (jadx) ==="
echo ""
echo "Input:  $APK_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

mkdir -p "$OUTPUT_DIR"

# Run jadx
echo "Decompiling (this may take a minute)..."
jadx "$APK_PATH" -d "$OUTPUT_DIR" --show-bad-code --deobf

echo ""
echo "=== Decompilation Complete ==="
echo ""
echo "Source files:"
find "$OUTPUT_DIR/sources" -name "*.java" 2>/dev/null | wc -l | xargs echo "  Java files:"
echo ""
echo "Key directories:"
echo "  $OUTPUT_DIR/sources/      - Decompiled Java source"
echo "  $OUTPUT_DIR/resources/    - Extracted resources"
echo ""
echo "To browse source code:"
echo "  code $OUTPUT_DIR/sources   # Open in VS Code"
echo "  # or"
echo "  ls $OUTPUT_DIR/sources     # List packages"
