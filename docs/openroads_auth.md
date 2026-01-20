# Open Roads Authentication & API Keys

## API Keys & Credentials Found in APK

### 1. Google Maps API Key

| Property | Value |
|----------|-------|
| **Key** | `AIzaSyBLBLDA-kIki0Dcqe05LmIY8IfQ2kxaiLw` |
| **Location** | `AndroidManifest.xml` |
| **Service** | Google Maps Directions API |
| **Usage** | Route planning and directions |

**Manifest Entry:**
```xml
<meta-data
    android:name="com.google.android.geo.API_KEY"
    android:value="AIzaSyBLBLDA-kIki0Dcqe05LmIY8IfQ2kxaiLw"/>
```

---

## Session Authentication

### API Key (Session Token)

The app uses a session-based `api_key` for authentication:

| Property | Description |
|----------|-------------|
| **Type** | Session token |
| **Obtained** | POST `/authenticate` response |
| **Storage** | AsyncStorage key: `api_key` |
| **Lifespan** | Until logout or expiration |
| **Usage** | Query parameter on all authenticated requests |

**How it's used:**
```
GET /endpoint?api_key={session_api_key}
POST /endpoint?api_key={session_api_key}
```

---

## Authentication Endpoints

### 1. Login (POST /authenticate)

**Request:**
```json
{
  "email": "user@example.com",
  "password": "userpassword"
}
```

**Success Response:**
```json
{
  "api_key": "abc123...",
  "response": {
    "api_key": "abc123..."
  }
}
```

**2FA Required Response:**
```json
{
  "response": {
    "two_factor_auth_delivery_options": ["email", "sms"]
  }
}
```

---

### 2. Registration (POST /register)

**Request:**
```json
{
  "email": "user@example.com",
  "password": "userpassword",
  "password_confirmation": "userpassword"
}
```

**Success Response:**
```json
{
  "api_key": "abc123...",
  "response": {
    "api_key": "abc123..."
  }
}
```

---

### 3. Two-Factor Authentication

#### Send 2FA Code (POST /send_two_factor_code)

**Request:**
```json
{
  "method": "email"  // or "sms"
}
```

#### Verify 2FA Code (POST /verify_two_factor_code?api_key={temp_key})

**Request:**
```json
{
  "code": "123456"
}
```

**Success Response:**
```json
{
  "api_key": "abc123...",
  "response": {
    "api_key": "abc123..."
  }
}
```

---

### 4. Password Reset Flow

#### Step 1: Generate Reset Code (POST /generate_password_reset_code)

**Request:**
```json
{
  "email": "user@example.com"
}
```

#### Step 2: Verify Reset Code (POST /verify_password_reset_code)

**Request:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**Response:**
```json
{
  "response": {
    "password_change_token": "token123..."
  }
}
```

#### Step 3: Change Password (POST /change_expired_password)

**Request:**
```json
{
  "email": "user@example.com",
  "password_change_token": "token123...",
  "password": "newpassword",
  "password_confirmation": "newpassword"
}
```

---

### 5. Change Password (Authenticated)

**Endpoint:** POST `/change_password?api_key={key}`

**Request:**
```json
{
  "current_password": "oldpassword",
  "password": "newpassword",
  "password_confirmation": "newpassword"
}
```

---

## Local Storage Keys

| Key | Type | Description |
|-----|------|-------------|
| `api_key` | String | Session authentication token |
| `user_email` | String | User's email address |
| `dev_mode` | Boolean | Developer mode flag |
| `brand_image_{id}` | String | Cached brand image IDs |

---

## Device Identification Headers

The app sends device info that may be used for:
- Device limiting (max devices per account)
- Analytics
- Fraud detection

| Field | Source |
|-------|--------|
| `uniqueId` | `android_id` from Settings.Secure |
| `deviceId` | `Build.BOARD` |
| `bundleId` | Package name |
| `systemName` | "Android" |
| `systemVersion` | Android version |
| `appVersion` | App version name |
| `buildNumber` | App version code |
| `brand` | Device brand |
| `model` | Device model |
| `deviceType` | Phone/Tablet |

---

## Security Notes

1. **API Key in URL**: The session `api_key` is passed as a query parameter, which may be logged in server access logs.

2. **No OAuth**: The app uses simple email/password authentication, not OAuth.

3. **2FA Optional**: Two-factor authentication is supported but may not be enforced.

4. **Device Binding**: The `uniqueId` (android_id) is sent with requests and may be used to limit concurrent devices.

---

## Bypassing Device Limits

To use the app on multiple devices simultaneously:

```bash
# Change the emulator's android_id
./change-device-id.sh --clear openroads.fueldiscountapp

# The emulator will now appear as a new device
```

See [Device ID Spoofer](../README.md#device-id-spoofer) for details.
