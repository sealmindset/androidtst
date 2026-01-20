# Android Test Harness

A general-purpose test harness for running and testing Android apps in an emulated environment. Configure it once and use it to test any Android application.

## Overview

This harness provides:
- **Automated emulator setup** - One-command SDK and AVD installation
- **App installation** - Install any app from Play Store or APK
- **UI automation** - Python and shell-based test frameworks
- **Security testing** - Templates for IDOR and other vulnerability tests

## Prerequisites

- macOS (Apple Silicon or Intel)
- Homebrew (for Java installation if needed)
- ~10GB free disk space for Android SDK and emulator images

## Quick Start

### 1. Run Setup

```bash
./setup.sh
```

This will:
- Install Java (if needed)
- Download Android SDK command-line tools
- Install platform-tools (ADB), emulator, and system images
- Create an Android Virtual Device (AVD) with Google Play Store support

### 2. Reload Shell Environment

```bash
source ~/.zshrc
```

### 3. Configure Target App

Create a `.env` file with your target app:

```bash
cp .env.example .env
# Edit .env with your target package name
```

Example `.env`:
```
TARGET_PACKAGE=com.example.myapp
```

### 4. Start the Emulator

```bash
./start-emulator.sh
```

Wait for the emulator to fully boot (you'll see "Emulator Ready").

### 5. Install Your App

```bash
# Using argument:
./install-app.sh com.example.myapp

# Or using environment variable:
TARGET_PACKAGE=com.example.myapp ./install-app.sh
```

This opens the Google Play Store on the emulator. You'll need to:
1. Sign in to your Google Account (first time only)
2. Click "Install" on the app page

### 6. Run Tests

**Shell-based (interactive):**
```bash
TARGET_PACKAGE=com.example.myapp ./run-tests.sh
```

**Python-based (programmatic):**
```bash
TARGET_PACKAGE=com.example.myapp python3 test_harness.py
```

## Scripts Overview

| Script | Purpose |
|--------|---------|
| `setup.sh` | One-time setup of Android SDK and emulator |
| `start-emulator.sh` | Start the Android emulator |
| `install-app.sh` | Install app from Play Store (takes package name as argument) |
| `run-tests.sh` | Interactive shell-based test harness |
| `test_harness.py` | Python test automation framework |
| `configure-proxy.sh` | Configure emulator proxy settings |
| `install-burp-cert.sh` | Install Burp CA certificate on emulator |
| `start-emulator-proxy.sh` | Start emulator with proxy pre-configured |
| `extract-apk.sh` | Extract APK from installed app |
| `decompile-apk.sh` | Decompile APK to Java source using jadx |
| `decode-apk.sh` | Decode APK resources and manifest using apktool |
| `analyze-apk.sh` | Unified APK analysis with security scan |
| `search-code.sh` | Search decompiled code for patterns |
| `frida_root_bypass.js` | Frida script to bypass root detection |
| `frida_emulator_bypass.js` | Frida script to bypass emulator detection |
| `frida_ssl_bypass.js` | Frida script to bypass SSL pinning |
| `frida_device_id_spoofer.js` | Frida script to spoof device ID for multi-device use |
| `change-device-id.sh` | Change emulator android_id (no root/frida needed) |
| `api_extractor` | **Full API reverse engineering pipeline** |

## API Extraction (Reverse Engineering)

Extract complete API documentation from any installed Android app.

### Quick Start

```bash
# Extract APIs from an installed app
./api_extractor com.example.app

# Or from an existing APK file
./api_extractor --apk path/to/app.apk
```

### What It Does

1. **Extracts APK** from the installed app
2. **Decompiles** with jadx to Java source
3. **Analyzes** code for:
   - API endpoints and URLs
   - Authentication patterns (login, tokens, sessions)
   - API keys (Google, AWS, Firebase, etc.)
   - HTTP request patterns (headers, methods)
   - Data models and JSON fields
4. **Generates documentation**:
   - `docs/<app>/api_reference.md` - Complete endpoint reference
   - `docs/<app>/authentication.md` - Auth flow documentation
   - `docs/<app>/api_keys.md` - Discovered secrets
   - `docs/<app>/openapi/api.yaml` - OpenAPI 3.0 spec

### Example Output

```bash
./api_extractor openroads.fueldiscountapp

# Output:
# docs/fueldiscountapp/
# ├── README.md              # Summary and quick start
# ├── api_reference.md       # All endpoints with examples
# ├── authentication.md      # Login flow, tokens, sessions
# ├── api_keys.md            # Google Maps key, etc.
# ├── request_patterns.md    # Headers, methods, params
# ├── data_models.md         # JSON fields
# ├── raw_urls.txt           # All discovered URLs
# ├── raw_endpoints.txt      # All discovered endpoints
# └── openapi/
#     └── api.yaml           # Import into Postman/Swagger
```

### Use Cases

- **Security testing**: Find hidden endpoints, exposed keys
- **API documentation**: Generate docs for undocumented APIs
- **Interoperability**: Use app APIs from scripts/tools
- **Research**: Understand how apps communicate

## Proxy Integration

Route emulator traffic through Burp Suite CE for security testing.

### Prerequisites

1. **Burp Suite CE** running on localhost:8080
2. **Burp CA certificate** exported (see below)

### Quick Start

```bash
# 1. Export Burp CA certificate (one-time setup)
#    Burp > Proxy > Options > Import/Export CA > Export as DER
#    Save as: ~/burp-ca.der

# 2. Install certificate on emulator
./install-burp-cert.sh

# 3. Start emulator with proxy
./start-emulator-proxy.sh
```

### Manual Proxy Control

```bash
# Enable proxy (default: Burp on host)
./configure-proxy.sh

# Enable proxy with custom address
./configure-proxy.sh 10.0.2.2:8081

# Disable proxy
./configure-proxy.sh --disable

# Check current proxy setting
adb shell settings get global http_proxy
```

### Troubleshooting Proxy

**No traffic in Burp:**
- Verify Burp is listening: Proxy > Options > Proxy Listeners
- Check proxy is set: `adb shell settings get global http_proxy`
- Ensure emulator can reach host: `adb shell ping -c 1 10.0.2.2`

**HTTPS traffic not visible:**
- Install Burp CA certificate: `./install-burp-cert.sh`
- Some apps use certificate pinning (see Security Bypasses section)

**Connection refused:**
- Burp may not be running
- Check Burp's proxy listener is bound to all interfaces or localhost

## APK Analysis

Decompile APKs to examine source code and resources.

### Quick Analysis

Run a complete analysis with one command:
```bash
./analyze-apk.sh com.example.app_v1.2.3.apk
# or auto-select most recent:
./analyze-apk.sh
```

This will:
- Decompile to Java source (jadx)
- Decode resources and manifest (apktool)
- Scan for common security issues
- Generate a summary report with:
  - Permissions (highlighting dangerous ones)
  - Exported components (attack surface)
  - Network configuration issues
  - Potential hardcoded secrets
  - Network-related classes

### Prerequisites

Install decompilation tools:
```bash
brew install jadx    # Java source decompilation
brew install apktool # Resource extraction (optional)
```

### Decompiling APKs

```bash
# 1. Extract APK from device
./extract-apk.sh com.example.app

# 2. Decompile to Java source
./decompile-apk.sh apks/app_v1.2.3.apk
# or auto-select most recent APK:
./decompile-apk.sh

# 3. Decode resources and manifest (optional)
./decode-apk.sh apks/app_v1.2.3.apk
# or auto-select most recent:
./decode-apk.sh

# Output structure:
# decompiled/<app>/jadx/sources/      - Java source code
# decompiled/<app>/jadx/resources/    - App resources
# decompiled/<app>/apktool/AndroidManifest.xml - App manifest
# decompiled/<app>/apktool/res/       - Resources
# decompiled/<app>/apktool/smali/     - Smali bytecode
```

### Examining Code

```bash
# Open in VS Code
code decompiled/<app>/jadx/sources

# Search for interesting patterns
grep -r "api.example.com" decompiled/<app>/jadx/sources/
grep -r "password" decompiled/<app>/jadx/sources/
grep -r "secret" decompiled/<app>/jadx/sources/

# Find network-related code
grep -rl "HttpURLConnection\|OkHttp\|Retrofit" decompiled/<app>/jadx/sources/
```

### Searching Code

Use preset patterns for common security searches:
```bash
# Find hardcoded secrets
./search-code.sh --preset secrets

# Find network-related code
./search-code.sh --preset network

# Find crypto operations
./search-code.sh --preset crypto

# Find storage operations
./search-code.sh --preset storage

# Find authentication code
./search-code.sh --preset auth

# Custom pattern search
./search-code.sh "api.example.com"

# Search specific app
./search-code.sh --preset secrets com.example.app
```

Available presets: `secrets`, `network`, `crypto`, `storage`, `auth`

### Security Analysis Tips

**Check permissions:**
```bash
grep 'uses-permission' decompiled/<app>/apktool/AndroidManifest.xml
```

**Find exported components (attack surface):**
```bash
grep -B2 'exported="true"' decompiled/<app>/apktool/AndroidManifest.xml
```

**Check for cleartext traffic:**
```bash
grep -i 'cleartextTrafficPermitted' decompiled/<app>/apktool/res/xml/*.xml
```

**Search for hardcoded secrets:**
```bash
grep -rE '(api_key|apikey|secret|password|token).*=' decompiled/<app>/jadx/sources/
```

## Security Bypasses

Use Frida scripts to bypass common security measures in apps.

### Prerequisites

Install Frida tools:
```bash
pip install frida-tools
```

Ensure the Android emulator is running and `frida-server` is installed on it:
```bash
# Download frida-server for your emulator architecture
# Push to device and run as root
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### Root Detection Bypass

Many apps detect rooted devices and refuse to run. Use `frida_root_bypass.js` to hide root status:

```bash
# Spawn app with root bypass
frida -U -l frida_root_bypass.js -f com.example.app

# Attach to running app
frida -U -l frida_root_bypass.js com.example.app
```

**What it bypasses:**
- File.exists() checks for su, Magisk, busybox
- Runtime.exec() and ProcessBuilder su/which commands
- Build.TAGS "test-keys" detection
- System.getProperty() for ro.debuggable/ro.secure
- PackageManager checks for root management apps
- Native libc system() and access() calls
- RootBeer library (if present)

### Emulator Detection Bypass

Some apps detect emulator environments and refuse to run. Use `frida_emulator_bypass.js` to appear as a real device:

```bash
# Spawn app with emulator bypass
frida -U -l frida_emulator_bypass.js -f com.example.app

# Attach to running app
frida -U -l frida_emulator_bypass.js com.example.app
```

**What it bypasses:**
- Build class fields (FINGERPRINT, MODEL, MANUFACTURER, BRAND, etc.)
- TelephonyManager (IMEI, IMSI, phone number, carrier info)
- File.exists() for qemu_pipe, goldfish, ranchu files
- System.getProperty() and SystemProperties for emulator indicators
- SensorManager availability checks
- Native fopen() and access() for low-level file detection

**Spoofed device:** Pixel 6 Pro (configurable in script)

### Device ID Spoofer

Apps with device limits (e.g., "only 2 devices allowed") track your device by `android_id` and other identifiers.

#### Simple Method (Recommended)

Use the `change-device-id.sh` script to change the emulator's `android_id`. No root or Frida required:

```bash
# Change device ID and clear app data (recommended)
./change-device-id.sh --clear openroads.fueldiscountapp

# Just change device ID (random)
./change-device-id.sh

# Use a specific ID
./change-device-id.sh abc123def456789a

# Then launch the app
adb shell monkey -p openroads.fueldiscountapp 1
```

The app will now see the emulator as a completely different device, allowing you to use it alongside your real phone without hitting device limits.

#### Frida Method (Advanced)

For apps that check multiple identifiers or cache the device ID, use `frida_device_id_spoofer.js`:

```bash
# Spawn app with device ID spoofing
frida -U -l frida_device_id_spoofer.js -f com.example.app

# Use with SSL bypass to intercept traffic too
frida -U -l frida_device_id_spoofer.js -l frida_ssl_bypass.js -f com.example.app
```

**What it spoofs:**
- Settings.Secure `android_id` (primary device identifier)
- TelephonyManager device IDs (IMEI, IMSI, SIM serial)
- Build.SERIAL and Build.getSerial()
- WiFi and Bluetooth MAC addresses
- react-native-device-info library hooks (if present)

**Configuration:** Edit `CUSTOM_DEVICE_ID` in the script to use a fixed ID instead of random.

**Use case:** Run the same app on your real phone AND emulator simultaneously without hitting device limits. Each launch generates a new random device ID, making the emulator appear as a fresh device.

### SSL Pinning Bypass

Apps with certificate pinning block traffic interception. Use `frida_ssl_bypass.js`:

```bash
# Spawn app with SSL bypass
frida -U -l frida_ssl_bypass.js -f com.example.app
```

**What it bypasses:**
- TrustManagerImpl.verifyChain
- SSLContext.init with custom TrustManager
- OkHttp CertificatePinner

### Combining Bypasses

Load multiple scripts for comprehensive bypass:
```bash
# Root + SSL bypass
frida -U -l frida_root_bypass.js -l frida_ssl_bypass.js -f com.example.app

# All bypasses (root + emulator + SSL)
frida -U -l frida_root_bypass.js -l frida_emulator_bypass.js -l frida_ssl_bypass.js -f com.example.app
```

### Troubleshooting Frida

**frida-server not running:**
```bash
adb shell "ps | grep frida"
# If not running, start it:
adb shell "/data/local/tmp/frida-server &"
```

**Permission denied:**
```bash
# frida-server needs root
adb root
adb shell "/data/local/tmp/frida-server &"
```

**App crashes on attach:**
- Try spawning (`-f`) instead of attaching
- Check logcat for crash reason: `adb logcat | grep -i frida`

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TARGET_PACKAGE` | Yes | Android package name (e.g., `com.example.app`) |
| `TEST_EMAIL` | No | Test account email (for auth-required apps) |
| `TEST_PASSWORD` | No | Test account password |
| `TARGET_ID` | No | Target identifier for security tests |
| `API_BASE` | No | API base URL for backend testing |

### .env File

Copy `.env.example` to `.env` and configure:

```bash
TARGET_PACKAGE=com.example.myapp
# TEST_EMAIL=test@example.com
# TEST_PASSWORD=secret
# TARGET_ID=12345
# API_BASE=https://api.example.com/v1
```

## Using the Python Test Harness

The Python harness provides a programmatic API for test automation:

```python
from test_harness import AndroidTestHarness

# Create harness for your target app
harness = AndroidTestHarness("com.example.myapp")

# Launch the app
harness.launch_app()

# Take screenshot
harness.screenshot("login_screen")

# Find and click UI elements
harness.ui.click_text("Sign In")
harness.ui.click_id("com.example.myapp:id/login_button")

# Input text
harness.adb.input_text("user@example.com")

# Wait for elements
harness.ui.wait_for_text("Welcome", timeout=10)

# Run all tests
harness.run_all_tests()
```

## Security Testing

The `example_idor_test.py` file provides a template for IDOR vulnerability testing. Copy and customize it for your target app:

```bash
cp example_idor_test.py test_myapp_idor.py
# Edit test_myapp_idor.py with your API endpoints
```

See the CUSTOMIZE markers in the template for guidance on what to change.

## Manual ADB Commands

Once the emulator is running, you can interact with it directly:

```bash
# Check connected devices
adb devices

# Take screenshot
adb exec-out screencap -p > screenshot.png

# Install APK directly
adb install path/to/app.apk

# Get UI hierarchy (for identifying elements)
adb shell uiautomator dump /sdcard/ui.xml
adb pull /sdcard/ui.xml

# Tap at coordinates
adb shell input tap 500 1000

# Input text
adb shell input text 'your_text'

# Swipe gesture
adb shell input swipe 500 1500 500 500 300

# Key events
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_HOME
adb shell input keyevent KEYCODE_ENTER

# Launch app (replace with your package)
adb shell monkey -p com.example.myapp 1

# Force stop app
adb shell am force-stop com.example.myapp

# Clear app data
adb shell pm clear com.example.myapp

# Uninstall app
adb uninstall com.example.myapp

# View logs (filter by tag)
adb logcat | grep MyApp

# Stop emulator
adb emu kill
```

## Emulator Configuration

The default AVD is configured as:
- **Device**: Pixel 6
- **Android Version**: 14 (API 34)
- **System Image**: Google APIs with Play Store (arm64)

To modify, edit the AVD or create a new one:
```bash
# List available system images
sdkmanager --list | grep system-images

# Create new AVD
avdmanager create avd --name MyDevice --package "system-images;android-34;google_apis_playstore;arm64-v8a" --device "pixel_7"

# List AVDs
avdmanager list avd
```

## Troubleshooting

### Emulator won't start
- Check Java is installed: `java -version`
- Verify ANDROID_SDK_ROOT: `echo $ANDROID_SDK_ROOT`
- Check emulator logs: `cat /tmp/emulator.log`

### Play Store issues
- Ensure you're using `google_apis_playstore` system image
- Sign in with a valid Google account
- Check internet connectivity in emulator

### App crashes
- View logs: `adb logcat | grep -E "(FATAL|CRASH)"`
- Clear app data: `adb shell pm clear com.example.myapp`

### Slow emulator
- Enable GPU acceleration: `-gpu host` (already enabled)
- Allocate more RAM in AVD settings
- Close other heavy applications

## Screenshots

Screenshots are saved to the `screenshots/` directory with timestamps.

## Adding Custom Tests

Edit `test_harness.py` to add custom test scenarios:

```python
def test_custom_scenario(self) -> bool:
    """Your custom test."""
    print("\n=== Test: Custom Scenario ===")
    self.launch_app()

    # Your test logic here
    if self.ui.wait_for_text("Expected Text"):
        print("PASS")
        return True
    else:
        print("FAIL")
        return False
```

Then add it to `run_all_tests()`.
