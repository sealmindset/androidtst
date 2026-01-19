#!/bin/bash
# Android Test Harness - Basic UI Automation
#
# Usage: TARGET_PACKAGE=com.example.app ./run-tests.sh

set -e

ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$PATH"

# Get package name from environment variable
PACKAGE_NAME="${TARGET_PACKAGE:-}"
if [ -z "$PACKAGE_NAME" ]; then
    echo "ERROR: TARGET_PACKAGE environment variable not set"
    echo ""
    echo "Usage: TARGET_PACKAGE=com.example.app ./run-tests.sh"
    echo ""
    echo "Or set in .env file:"
    echo "  TARGET_PACKAGE=com.example.app"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCREENSHOTS_DIR="$SCRIPT_DIR/screenshots"

mkdir -p "$SCREENSHOTS_DIR"

echo "=== Android Test Harness ==="
echo "Package: $PACKAGE_NAME"
echo ""

# Check if emulator is running
if ! adb devices | grep -q "emulator"; then
    echo "ERROR: No emulator running. Start it first with: ./start-emulator.sh"
    exit 1
fi

# Check if app is installed
if ! adb shell pm list packages | grep -q "$PACKAGE_NAME"; then
    echo "ERROR: Target app not installed. Install it first with: ./install-app.sh $PACKAGE_NAME"
    exit 1
fi

# Function to take screenshot
take_screenshot() {
    local name="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local filename="$SCREENSHOTS_DIR/${name}_${timestamp}.png"
    adb exec-out screencap -p > "$filename"
    echo "Screenshot saved: $filename"
}

# Function to get UI hierarchy (for debugging)
get_ui_hierarchy() {
    local filename="$SCRIPT_DIR/ui_hierarchy.xml"
    adb shell uiautomator dump /sdcard/ui_hierarchy.xml
    adb pull /sdcard/ui_hierarchy.xml "$filename"
    echo "UI hierarchy saved: $filename"
}

# Function to tap at coordinates
tap() {
    local x="$1"
    local y="$2"
    adb shell input tap "$x" "$y"
    sleep 1
}

# Function to input text
input_text() {
    local text="$1"
    # Replace spaces with %s for adb input
    local escaped_text=$(echo "$text" | sed 's/ /%s/g')
    adb shell input text "$escaped_text"
}

# Function to press back button
press_back() {
    adb shell input keyevent KEYCODE_BACK
    sleep 0.5
}

# Function to press home button
press_home() {
    adb shell input keyevent KEYCODE_HOME
    sleep 0.5
}

# Function to scroll down
scroll_down() {
    adb shell input swipe 500 1500 500 500 300
    sleep 1
}

# Function to scroll up
scroll_up() {
    adb shell input swipe 500 500 500 1500 300
    sleep 1
}

echo "Starting target app..."
adb shell am force-stop "$PACKAGE_NAME"
sleep 1

# Launch the app
adb shell monkey -p "$PACKAGE_NAME" -c android.intent.category.LAUNCHER 1
sleep 3

echo "App launched. Taking initial screenshot..."
take_screenshot "app_launch"

echo ""
echo "=== Test Harness Ready ==="
echo ""
echo "Available commands (run in another terminal):"
echo ""
echo "  # Take screenshot"
echo "  adb exec-out screencap -p > screenshot.png"
echo ""
echo "  # Get UI hierarchy for element identification"
echo "  adb shell uiautomator dump /sdcard/ui.xml && adb pull /sdcard/ui.xml"
echo ""
echo "  # Tap at coordinates (x, y)"
echo "  adb shell input tap 500 1000"
echo ""
echo "  # Input text"
echo "  adb shell input text 'your_text_here'"
echo ""
echo "  # Swipe (x1 y1 x2 y2 duration_ms)"
echo "  adb shell input swipe 500 1500 500 500 300"
echo ""
echo "  # Press keys"
echo "  adb shell input keyevent KEYCODE_BACK"
echo "  adb shell input keyevent KEYCODE_HOME"
echo "  adb shell input keyevent KEYCODE_ENTER"
echo ""
echo "  # Force stop app"
echo "  adb shell am force-stop $PACKAGE_NAME"
echo ""
echo "  # Clear app data"
echo "  adb shell pm clear $PACKAGE_NAME"
echo ""
echo "Screenshots saved to: $SCREENSHOTS_DIR"
echo ""

# Interactive mode
echo "=== Interactive Mode ==="
echo "Commands: screenshot, hierarchy, back, home, scroll-up, scroll-down, tap X Y, text TEXT, quit"
echo ""

while true; do
    read -p "> " cmd args

    case "$cmd" in
        screenshot|ss)
            take_screenshot "manual"
            ;;
        hierarchy|ui)
            get_ui_hierarchy
            ;;
        back)
            press_back
            ;;
        home)
            press_home
            ;;
        scroll-up|up)
            scroll_up
            ;;
        scroll-down|down)
            scroll_down
            ;;
        tap)
            read x y <<< "$args"
            if [ -n "$x" ] && [ -n "$y" ]; then
                tap "$x" "$y"
            else
                echo "Usage: tap X Y"
            fi
            ;;
        text)
            if [ -n "$args" ]; then
                input_text "$args"
            else
                echo "Usage: text YOUR_TEXT"
            fi
            ;;
        launch|start)
            adb shell monkey -p "$PACKAGE_NAME" -c android.intent.category.LAUNCHER 1
            ;;
        stop)
            adb shell am force-stop "$PACKAGE_NAME"
            ;;
        clear)
            adb shell pm clear "$PACKAGE_NAME"
            ;;
        quit|exit|q)
            echo "Exiting test harness..."
            exit 0
            ;;
        help|h)
            echo "Commands:"
            echo "  screenshot (ss) - Take a screenshot"
            echo "  hierarchy (ui)  - Dump UI hierarchy"
            echo "  back            - Press back button"
            echo "  home            - Press home button"
            echo "  scroll-up (up)  - Scroll up"
            echo "  scroll-down     - Scroll down"
            echo "  tap X Y         - Tap at coordinates"
            echo "  text TEXT       - Input text"
            echo "  launch          - Launch app"
            echo "  stop            - Force stop app"
            echo "  clear           - Clear app data"
            echo "  quit (q)        - Exit"
            ;;
        *)
            echo "Unknown command. Type 'help' for available commands."
            ;;
    esac
done
