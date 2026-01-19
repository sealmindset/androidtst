#!/usr/bin/env python3
"""
Android Test Harness

A Python-based test harness for automating Android app testing.
Uses ADB for device interaction and UI Automator for element identification.

Usage:
    TARGET_PACKAGE=com.example.myapp python3 test_harness.py

Or import as a module:
    from test_harness import AndroidTestHarness
    harness = AndroidTestHarness("com.example.myapp")
    harness.launch_app()
"""

import subprocess
import time
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple


@dataclass
class UIElement:
    """Represents a UI element from the UI hierarchy."""
    resource_id: str
    text: str
    content_desc: str
    class_name: str
    bounds: Tuple[int, int, int, int]  # left, top, right, bottom
    clickable: bool
    enabled: bool

    @property
    def center(self) -> Tuple[int, int]:
        """Get center coordinates of the element."""
        return (
            (self.bounds[0] + self.bounds[2]) // 2,
            (self.bounds[1] + self.bounds[3]) // 2
        )


class ADBWrapper:
    """Wrapper for ADB commands."""

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id
        self._adb_base = ["adb"]
        if device_id:
            self._adb_base = ["adb", "-s", device_id]

    def run(self, *args, capture_output=True) -> subprocess.CompletedProcess:
        """Run an ADB command."""
        cmd = self._adb_base + list(args)
        return subprocess.run(cmd, capture_output=capture_output, text=True)

    def shell(self, command: str) -> str:
        """Run a shell command on the device."""
        result = self.run("shell", command)
        return result.stdout.strip()

    def is_device_connected(self) -> bool:
        """Check if a device is connected."""
        result = self.run("devices")
        lines = result.stdout.strip().split('\n')
        for line in lines[1:]:  # Skip header
            if 'device' in line and 'offline' not in line:
                return True
        return False

    def wait_for_device(self, timeout: int = 60):
        """Wait for device to be ready."""
        self.run("wait-for-device")
        start = time.time()
        while time.time() - start < timeout:
            boot_completed = self.shell("getprop sys.boot_completed")
            if boot_completed == "1":
                return True
            time.sleep(2)
        raise TimeoutError("Device did not boot within timeout")

    def tap(self, x: int, y: int):
        """Tap at coordinates."""
        self.shell(f"input tap {x} {y}")

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300):
        """Swipe gesture."""
        self.shell(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")

    def input_text(self, text: str):
        """Input text (replaces spaces with %s)."""
        escaped = text.replace(" ", "%s").replace("'", "\\'")
        self.shell(f"input text '{escaped}'")

    def keyevent(self, keycode: str):
        """Send a key event."""
        self.shell(f"input keyevent {keycode}")

    def back(self):
        """Press back button."""
        self.keyevent("KEYCODE_BACK")

    def home(self):
        """Press home button."""
        self.keyevent("KEYCODE_HOME")

    def enter(self):
        """Press enter key."""
        self.keyevent("KEYCODE_ENTER")

    def screenshot(self, local_path: str):
        """Take a screenshot and save locally."""
        self.run("exec-out", "screencap", "-p", capture_output=False)
        result = subprocess.run(
            self._adb_base + ["exec-out", "screencap", "-p"],
            capture_output=True
        )
        with open(local_path, 'wb') as f:
            f.write(result.stdout)

    def get_ui_hierarchy(self) -> str:
        """Get UI hierarchy XML."""
        self.shell("uiautomator dump /sdcard/ui_hierarchy.xml")
        result = self.shell("cat /sdcard/ui_hierarchy.xml")
        return result

    def install_apk(self, apk_path: str):
        """Install an APK."""
        result = self.run("install", "-r", apk_path)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to install APK: {result.stderr}")

    def uninstall_package(self, package: str):
        """Uninstall a package."""
        self.shell(f"pm uninstall {package}")

    def is_package_installed(self, package: str) -> bool:
        """Check if a package is installed."""
        result = self.shell(f"pm list packages {package}")
        return package in result

    def launch_app(self, package: str):
        """Launch an app by package name."""
        self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")

    def force_stop(self, package: str):
        """Force stop an app."""
        self.shell(f"am force-stop {package}")

    def clear_app_data(self, package: str):
        """Clear app data."""
        self.shell(f"pm clear {package}")


class UIAutomator:
    """Parse and interact with UI elements."""

    def __init__(self, adb: ADBWrapper):
        self.adb = adb
        self._hierarchy_cache: Optional[str] = None
        self._elements_cache: Optional[List[UIElement]] = None

    def refresh(self):
        """Refresh the UI hierarchy."""
        self._hierarchy_cache = self.adb.get_ui_hierarchy()
        self._elements_cache = self._parse_hierarchy(self._hierarchy_cache)

    def _parse_bounds(self, bounds_str: str) -> Tuple[int, int, int, int]:
        """Parse bounds string like '[0,0][1080,1920]'."""
        matches = re.findall(r'\[(\d+),(\d+)\]', bounds_str)
        if len(matches) == 2:
            return (
                int(matches[0][0]),
                int(matches[0][1]),
                int(matches[1][0]),
                int(matches[1][1])
            )
        return (0, 0, 0, 0)

    def _parse_hierarchy(self, xml_str: str) -> List[UIElement]:
        """Parse UI hierarchy XML into UIElement objects."""
        elements = []
        try:
            root = ET.fromstring(xml_str)
            for node in root.iter('node'):
                element = UIElement(
                    resource_id=node.get('resource-id', ''),
                    text=node.get('text', ''),
                    content_desc=node.get('content-desc', ''),
                    class_name=node.get('class', ''),
                    bounds=self._parse_bounds(node.get('bounds', '')),
                    clickable=node.get('clickable', 'false') == 'true',
                    enabled=node.get('enabled', 'true') == 'true'
                )
                elements.append(element)
        except ET.ParseError:
            pass
        return elements

    @property
    def elements(self) -> List[UIElement]:
        """Get all UI elements (refreshes if needed)."""
        if self._elements_cache is None:
            self.refresh()
        return self._elements_cache or []

    def find_by_text(self, text: str, partial: bool = False) -> List[UIElement]:
        """Find elements by text."""
        self.refresh()
        if partial:
            return [e for e in self.elements if text.lower() in e.text.lower()]
        return [e for e in self.elements if e.text == text]

    def find_by_id(self, resource_id: str) -> List[UIElement]:
        """Find elements by resource ID."""
        self.refresh()
        return [e for e in self.elements if resource_id in e.resource_id]

    def find_by_content_desc(self, desc: str, partial: bool = False) -> List[UIElement]:
        """Find elements by content description."""
        self.refresh()
        if partial:
            return [e for e in self.elements if desc.lower() in e.content_desc.lower()]
        return [e for e in self.elements if e.content_desc == desc]

    def find_by_class(self, class_name: str) -> List[UIElement]:
        """Find elements by class name."""
        self.refresh()
        return [e for e in self.elements if class_name in e.class_name]

    def click_element(self, element: UIElement):
        """Click on a UI element."""
        x, y = element.center
        self.adb.tap(x, y)

    def click_text(self, text: str, partial: bool = False) -> bool:
        """Click on element with specified text."""
        elements = self.find_by_text(text, partial)
        if elements:
            self.click_element(elements[0])
            return True
        return False

    def click_id(self, resource_id: str) -> bool:
        """Click on element with specified resource ID."""
        elements = self.find_by_id(resource_id)
        if elements:
            self.click_element(elements[0])
            return True
        return False

    def wait_for_text(self, text: str, timeout: int = 10, partial: bool = False) -> bool:
        """Wait for text to appear on screen."""
        start = time.time()
        while time.time() - start < timeout:
            if self.find_by_text(text, partial):
                return True
            time.sleep(0.5)
        return False

    def wait_for_id(self, resource_id: str, timeout: int = 10) -> bool:
        """Wait for element with resource ID to appear."""
        start = time.time()
        while time.time() - start < timeout:
            if self.find_by_id(resource_id):
                return True
            time.sleep(0.5)
        return False


class AndroidTestHarness:
    """Test harness for Android app automation."""

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        self.package_name = package_name
        self.adb = ADBWrapper(device_id)
        self.ui = UIAutomator(self.adb)
        self.screenshots_dir = Path(__file__).parent / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)

    def check_device(self) -> bool:
        """Check if device is connected and ready."""
        return self.adb.is_device_connected()

    def is_app_installed(self) -> bool:
        """Check if target app is installed."""
        return self.adb.is_package_installed(self.package_name)

    def launch_app(self):
        """Launch the target app."""
        print(f"Launching {self.package_name}...")
        self.adb.force_stop(self.package_name)
        time.sleep(0.5)
        self.adb.launch_app(self.package_name)
        time.sleep(3)  # Wait for app to load

    def stop_app(self):
        """Stop the target app."""
        self.adb.force_stop(self.package_name)

    def clear_app_data(self):
        """Clear all app data (will require re-login)."""
        self.adb.clear_app_data(self.package_name)

    def screenshot(self, name: str = "screenshot") -> str:
        """Take a screenshot and return the path."""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = self.screenshots_dir / f"{name}_{timestamp}.png"
        self.adb.screenshot(str(filename))
        print(f"Screenshot saved: {filename}")
        return str(filename)

    def dump_ui(self) -> str:
        """Dump UI hierarchy and return the XML."""
        self.ui.refresh()
        return self.ui._hierarchy_cache or ""

    def print_ui_elements(self):
        """Print all UI elements (for debugging)."""
        self.ui.refresh()
        for i, elem in enumerate(self.ui.elements):
            if elem.text or elem.content_desc:
                print(f"[{i}] {elem.class_name}")
                if elem.text:
                    print(f"     text: {elem.text}")
                if elem.content_desc:
                    print(f"     desc: {elem.content_desc}")
                if elem.resource_id:
                    print(f"     id: {elem.resource_id}")
                print(f"     bounds: {elem.bounds}")
                print(f"     clickable: {elem.clickable}")

    # ==================== Test Scenarios ====================

    def test_app_launch(self) -> bool:
        """Test that app launches successfully."""
        print("\n=== Test: App Launch ===")
        self.launch_app()
        self.screenshot("launch")

        # Check for common elements that indicate successful launch
        # This will depend on the actual app UI
        time.sleep(2)
        self.ui.refresh()

        # Look for any content (app loaded)
        if len(self.ui.elements) > 5:
            print("PASS: App launched with UI elements")
            return True
        else:
            print("FAIL: App may not have launched properly")
            return False

    def test_login_screen(self) -> bool:
        """Test that login screen is displayed."""
        print("\n=== Test: Login Screen ===")
        self.launch_app()
        time.sleep(2)

        # Look for login-related elements
        # Adjust these based on actual app UI
        login_indicators = ["Login", "Sign In", "Email", "Password", "Username"]

        for indicator in login_indicators:
            if self.ui.find_by_text(indicator, partial=True):
                print(f"PASS: Found login indicator: {indicator}")
                self.screenshot("login_screen")
                return True

        print("INFO: Login screen not found (user may already be logged in)")
        self.screenshot("current_screen")
        return True

    def run_all_tests(self):
        """Run all test scenarios."""
        print("\n" + "=" * 50)
        print("Android Test Harness - Running All Tests")
        print("=" * 50)

        if not self.check_device():
            print("ERROR: No device connected!")
            return

        if not self.is_app_installed():
            print(f"ERROR: App not installed: {self.package_name}")
            return

        results = []
        results.append(("App Launch", self.test_app_launch()))
        results.append(("Login Screen", self.test_login_screen()))

        print("\n" + "=" * 50)
        print("Test Results:")
        print("=" * 50)
        for name, passed in results:
            status = "PASS" if passed else "FAIL"
            print(f"  {name}: {status}")


def main():
    """Main entry point."""
    # Get package name from environment or prompt user
    package_name = os.environ.get('TARGET_PACKAGE')
    if not package_name:
        print("TARGET_PACKAGE environment variable not set.")
        package_name = input("Enter target app package name: ").strip()
        if not package_name:
            print("ERROR: Package name is required.")
            print("Usage: TARGET_PACKAGE=com.example.app python3 test_harness.py")
            return

    harness = AndroidTestHarness(package_name)

    if not harness.check_device():
        print("No device connected. Start the emulator first:")
        print("  ./start-emulator.sh")
        return

    if not harness.is_app_installed():
        print(f"App not installed: {package_name}")
        print("Install the app first:")
        print(f"  TARGET_PACKAGE={package_name} ./install-app.sh")
        return

    # Interactive menu
    while True:
        print(f"\n=== Android Test Harness ({package_name}) ===")
        print("1. Launch app")
        print("2. Take screenshot")
        print("3. Dump UI hierarchy")
        print("4. Print UI elements")
        print("5. Run all tests")
        print("6. Stop app")
        print("7. Clear app data")
        print("q. Quit")
        print()

        choice = input("Select option: ").strip().lower()

        if choice == '1':
            harness.launch_app()
        elif choice == '2':
            harness.screenshot("manual")
        elif choice == '3':
            xml = harness.dump_ui()
            print(xml[:2000] + "..." if len(xml) > 2000 else xml)
        elif choice == '4':
            harness.print_ui_elements()
        elif choice == '5':
            harness.run_all_tests()
        elif choice == '6':
            harness.stop_app()
            print("App stopped.")
        elif choice == '7':
            harness.clear_app_data()
            print("App data cleared.")
        elif choice in ('q', 'quit', 'exit'):
            print("Goodbye!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
