#!/bin/bash
# Install Burp Suite CA certificate on Android emulator
#
# Usage: ./install-burp-cert.sh [path/to/burp-ca.der]
#
# Get Burp CA cert: Burp > Proxy > Options > Import/Export CA > Export as DER

set -e

CERT_PATH="${1:-$HOME/burp-ca.der}"

# Check if cert file exists
if [ ! -f "$CERT_PATH" ]; then
    echo "ERROR: Certificate not found: $CERT_PATH"
    echo ""
    echo "Export Burp CA certificate:"
    echo "  1. Open Burp Suite"
    echo "  2. Proxy > Options (or Proxy Settings in newer versions)"
    echo "  3. Import/Export CA Certificate"
    echo "  4. Export > Certificate in DER format"
    echo "  5. Save as: $CERT_PATH"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Check if emulator is running
if ! adb devices | grep -q "emulator"; then
    echo "ERROR: No emulator detected."
    echo "Start an emulator first: ./start-emulator.sh"
    exit 1
fi

# Get device ID (first emulator found)
DEVICE_ID=$(adb devices | grep "emulator" | head -1 | cut -f1)

echo "=== Installing Burp CA Certificate ==="
echo "Device: $DEVICE_ID"
echo "Certificate: $CERT_PATH"
echo ""

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo "ERROR: openssl is required but not installed."
    echo "Install with: brew install openssl"
    exit 1
fi

# Convert DER to PEM format (Android prefers .crt extension)
echo "Converting certificate to PEM format..."
TEMP_CERT="/tmp/burp-ca.crt"
openssl x509 -inform DER -in "$CERT_PATH" -out "$TEMP_CERT"

# Push certificate to emulator
echo "Pushing certificate to emulator..."
adb -s "$DEVICE_ID" push "$TEMP_CERT" /sdcard/Download/burp-ca.crt

# Clean up temp file
rm -f "$TEMP_CERT"

# Open security settings for user to install
echo "Opening security settings..."
adb -s "$DEVICE_ID" shell am start -a android.settings.SECURITY_SETTINGS

echo ""
echo "=== Certificate Pushed Successfully ==="
echo ""
echo "Complete installation on the emulator:"
echo "  1. Settings app should open automatically"
echo "  2. Scroll down and tap 'Encryption & credentials'"
echo "  3. Tap 'Install a certificate'"
echo "  4. Select 'CA certificate'"
echo "  5. Tap 'Install anyway' on the warning"
echo "  6. Navigate to Downloads folder"
echo "  7. Select 'burp-ca.crt'"
echo "  8. Certificate will be installed"
echo ""
echo "After installation, HTTPS traffic can be intercepted."
echo "Note: Some apps use certificate pinning which requires additional bypasses."
