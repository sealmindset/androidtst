# Run IDOR Test from Android Test Harness

**ATTORNEY-CLIENT PRIVILEGED**

---

## You're Already Set Up!

Since you have the Android test harness with Android Studio running, you can run the IDOR test **right now**.

---

## Quick Start (2 options)

### Option 1: Fully Automated (Python)

```bash
cd /Users/rob.vance@sleepnumber.com/Documents/GitHub/siqassess/android-test-harness

# Run the IDOR test
python3 test_idor.py
```

**What it does:**
1. Checks if Android device is connected
2. Monitors logcat for JWT token (15 seconds)
3. Authenticates to get session cookie
4. Tests IDOR by requesting different user ID
5. **Validates email is DIFFERENT from yours**
6. Tests Feedback API
7. Provides clear CREDIBLE/BLUFF verdict

**Total time:** 2-3 minutes

---

### Option 2: Manual JWT Capture + Test

If automatic JWT extraction doesn't work:

**Step 1: Get JWT from Android Studio Profiler**

1. In Android Studio → **View → Tool Windows → Profiler**
2. Click **"+"** → Select device → **com.selectcomfort.SleepIQ**
3. **Network** tab → Click any request to `api.sleepiq.sleepnumber.com`
4. Copy **Authorization** header value
5. Save it:
```bash
echo "YOUR_JWT_TOKEN_HERE" > /tmp/jwt_token.txt
```

**Step 2: Run Test**
```bash
cd /Users/rob.vance@sleepnumber.com/Documents/GitHub/siqassess/android-test-harness
python3 test_idor.py
```

**Total time:** 5 minutes

---

## Alternative: Use Existing Test Scripts

You can also use the bash scripts in the parent directory:

```bash
# From android-test-harness directory:
cd ..

# Run comprehensive test with JWT
./test_with_captured_jwt.sh
```

---

## What the Python Test Does

```python
# test_idor.py performs these tests:

1. Extract JWT token from Android logcat
   - Monitors logs while you navigate in app
   - Captures Authorization header

2. Authenticate to SleepIQ API
   - Get JSESSIONID cookie

3. Test IDOR on Sleeper Endpoint
   - Request: YOUR_ID + 1
   - Extract email from response
   - Compare: Is it DIFFERENT from yours?
   - If different → IDOR CONFIRMED ✓

4. Test Feedback API
   - Check if returns multiple users' data

5. Provide Legal Verdict
   - CREDIBLE → Incident response required
   - BLUFF → No breach notification
```

---

## Expected Output

### If Running Successfully:

```
============================================================
SLEEPIQ IDOR VULNERABILITY TEST
============================================================
Authorization: Dennis Hansen, SVP Deputy General Counsel
Date: 2026-01-03 14:45:00
============================================================

✓ Android device connected

[1/5] Extracting JWT token from logcat...
    (Make sure SleepIQ app is running and you're logged in)

⏳ Monitoring logs for 15 seconds...
   (Navigate in the SleepIQ app on your device)

✓ Found JWT token: eyJraWQiOiJvTHY1aDZQdEZSdm1qSjhQTjFmZGRsQ2pVZlRF...
✓ Saved to /tmp/jwt_token.txt

[2/5] Authenticating to get session cookie...
✓ Authenticated: {"userId": "-9223372019953519548", ...}
✓ Session ID: BDC9E05BAC032DFE2085A425F8870139...

[3/5] Testing IDOR on Sleeper Endpoint...
============================================================
Your Sleeper ID:  -9223372019953519548
Testing ID:       -9223372019953519549
(Attempting to access another user's data)

HTTP Status: 200
Response: {"sleepers":[{"email":"john.doe@example.com"...

Response contains email: john.doe@example.com
Your email:              ravance@gmail.com

🚨🚨🚨 CRITICAL VULNERABILITY CONFIRMED! 🚨🚨🚨
🚨 Successfully accessed ANOTHER USER's data!
🚨 Their email: john.doe@example.com
🚨 Threat actor's claims are VALIDATED!

[4/5] Testing Feedback API Exposure...
============================================================
HTTP Status: 200
🚨 CRITICAL: Feedback API returns 15 users' data!

============================================================
FINAL VERDICT
============================================================

🚨 BLACKMAIL THREAT IS CREDIBLE
============================================================

CRITICAL vulnerabilities exist that match
the threat actor's claims.

LEGAL RECOMMENDATION:
  ✓ DO NOT PAY the extortion demand
  ✓ Report to FBI immediately
  ✓ Treat as confirmed data breach
  ✓ Begin GDPR 72-hour notification assessment
  ✓ Initiate incident response procedures

============================================================
```

---

## Troubleshooting

### "adb not found"
```bash
# Install Android SDK platform tools
brew install android-platform-tools
```

### "No Android device connected"
```bash
# Check device connection
adb devices

# If empty:
# 1. Connect phone via USB
# 2. Enable USB Debugging (Settings → Developer Options)
# 3. Accept "Allow USB debugging" on phone
```

### "No JWT token found"
The automatic extraction may not work if the app doesn't log the token.

**Solution:** Use Android Studio Profiler (Option 2 above)

### "JWT token expired"
JWT tokens expire after ~1 hour.

**Solution:**
- Re-run the script to extract fresh token
- Or capture new token from Android Studio

---

## Integration with Existing Test Harness

The `test_idor.py` script integrates with your existing test harness:

```python
# You can also import it as a module:
from test_idor import extract_jwt_from_logcat, test_idor

# Or add IDOR tests to your existing test_harness.py
```

---

## Files

- **test_idor.py** - Main IDOR test script (THIS FILE)
- **test_harness.py** - Your existing test automation framework
- **frida_*.js** - Frida scripts for advanced instrumentation
- **run-tests.sh** - Shell-based test harness

---

## Quick Command Reference

```bash
# Run from android-test-harness directory:

# Option 1: Python IDOR test
python3 test_idor.py

# Option 2: Use parent directory scripts
cd .. && ./test_with_captured_jwt.sh

# Option 3: Manual adb monitoring
adb logcat | grep -E "Authorization|eyJ"

# Option 4: Use Android Studio Profiler
# (See START_NOW.md in parent directory)
```

---

## Bottom Line

**You have everything set up already!**

Just run:
```bash
cd /Users/rob.vance@sleepnumber.com/Documents/GitHub/siqassess/android-test-harness
python3 test_idor.py
```

Or if you prefer shell scripts:
```bash
cd /Users/rob.vance@sleepnumber.com/Documents/GitHub/siqassess
./test_with_captured_jwt.sh
# (After capturing JWT via Android Studio Profiler)
```

**Timeline:** 2-5 minutes to definitive answer

**The test properly validates:**
✅ Response email ≠ Your email = **IDOR CONFIRMED**
✅ Response email = Your email = **Inconclusive**
✅ HTTP 403/404 = **Secure**

---

**Ready to test! Your android-test-harness is already set up.**
