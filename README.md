# SleepIQ Android Test Harness

A test harness for running and testing the SleepIQ Android app in an emulated environment.

## Prerequisites

- macOS (Apple Silicon or Intel)
- Homebrew (for Java installation if needed)
- ~10GB free disk space for Android SDK and emulator images

## Quick Start

### 1. Run Setup

```bash
cd android-test-harness
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

### 3. Start the Emulator

```bash
./start-emulator.sh
```

Wait for the emulator to fully boot (you'll see "Emulator Ready").

### 4. Install SleepIQ App

```bash
./install-sleepiq.sh
```

This opens the Google Play Store on the emulator. You'll need to:
1. Sign in to your Google Account (first time only)
2. Click "Install" on the SleepIQ app page

### 5. Run Tests

**Shell-based (interactive):**
```bash
./run-tests.sh
```

**Python-based (programmatic):**
```bash
python3 test_harness.py
```

## Scripts Overview

| Script | Purpose |
|--------|---------|
| `setup.sh` | One-time setup of Android SDK and emulator |
| `start-emulator.sh` | Start the Android emulator |
| `install-sleepiq.sh` | Open Play Store to install SleepIQ |
| `run-tests.sh` | Interactive shell-based test harness |
| `test_harness.py` | Python test automation framework |

## Using the Python Test Harness

The Python harness provides a programmatic API for test automation:

```python
from test_harness import SleepIQTestHarness

harness = SleepIQTestHarness()

# Launch the app
harness.launch_app()

# Take screenshot
harness.screenshot("login_screen")

# Find and click UI elements
harness.ui.click_text("Sign In")
harness.ui.click_id("com.selectcomfort.SleepIQ:id/login_button")

# Input text
harness.adb.input_text("user@example.com")

# Wait for elements
harness.ui.wait_for_text("Welcome", timeout=10)

# Run all tests
harness.run_all_tests()
```

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

# Launch app
adb shell monkey -p com.selectcomfort.SleepIQ 1

# Force stop app
adb shell am force-stop com.selectcomfort.SleepIQ

# Clear app data
adb shell pm clear com.selectcomfort.SleepIQ

# Uninstall app
adb uninstall com.selectcomfort.SleepIQ

# View logs
adb logcat | grep SleepIQ

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
- View logs: `adb logcat | grep -E "(SleepIQ|FATAL|CRASH)"`
- Clear app data: `adb shell pm clear com.selectcomfort.SleepIQ`

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
