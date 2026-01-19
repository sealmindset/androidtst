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
