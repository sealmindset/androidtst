# Open Roads API Documentation

## Overview

The Open Roads app (`openroads.fueldiscountapp`) uses a REST API hosted at `https://hydrocarbon-xl.herokuapp.com/`.

**This documentation is sufficient to use the API independently from the app.**

---

## Base URL

```
https://hydrocarbon-xl.herokuapp.com/
```

---

## Required Request Format

### Headers (ALL requests)

```http
Accept: application/json
Content-Type: application/json
```

### Query Parameters (ALL requests)

Every request must include these query parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `api_key` | Yes* | Session token from `/authenticate` (*except login/register) |
| `deviceId` | Yes | URL-encoded device identifier (android_id) |
| `versionId` | Yes | URL-encoded app version |

**Example URL:**
```
https://hydrocarbon-xl.herokuapp.com/find_all_nearby_gas_locations?api_key=abc123&deviceId=fa0113a1aefe6a1d&versionId=1.3.6
```

### Request Body (POST requests)

JSON body with endpoint-specific fields:
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

### Timeouts

- GET requests: 10 seconds
- POST requests: 15 seconds

---

## Authentication Flow

### Step 1: Login

```http
POST /authenticate?deviceId={deviceId}&versionId={versionId}
Content-Type: application/json
Accept: application/json

{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

**Success Response:**
```json
{
  "response": {
    "api_key": "your-session-token-here"
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

### Step 2: Store api_key

Save the `api_key` from the response. Include it in all subsequent requests.

### Step 3: Use API

```http
GET /account_cards?api_key={api_key}&deviceId={deviceId}&versionId={versionId}
Accept: application/json
```

---

## Complete cURL Examples

### Login

```bash
# Variables
DEVICE_ID="fa0113a1aefe6a1d"  # Your android_id or any 16-char hex
VERSION_ID="1.3.6"
EMAIL="user@example.com"
PASSWORD="yourpassword"

# Login request
curl -X POST "https://hydrocarbon-xl.herokuapp.com/authenticate?deviceId=${DEVICE_ID}&versionId=${VERSION_ID}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}"
```

### Find Nearby Gas Stations

```bash
API_KEY="your-api-key-from-login"
DEVICE_ID="fa0113a1aefe6a1d"
VERSION_ID="1.3.6"

curl -X POST "https://hydrocarbon-xl.herokuapp.com/find_all_nearby_gas_locations?api_key=${API_KEY}&deviceId=${DEVICE_ID}&versionId=${VERSION_ID}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d "{\"latitude\":37.7749,\"longitude\":-122.4194}"
```

### Get Account Cards

```bash
curl -X GET "https://hydrocarbon-xl.herokuapp.com/account_cards?api_key=${API_KEY}&deviceId=${DEVICE_ID}&versionId=${VERSION_ID}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json"
```

---

## API Endpoints Reference

### Authentication & Account

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/authenticate` | `email`, `password` | No |
| POST | `/register` | `email`, `password`, `password_confirmation` | No |
| POST | `/verify_two_factor_code` | `code` | Partial |
| POST | `/send_two_factor_code` | `method` (email/sms) | Yes |
| POST | `/generate_password_reset_code` | `email` | No |
| POST | `/verify_password_reset_code` | `email`, `code` | No |
| POST | `/change_password` | `email`, `password_change_token`, `password`, `password_confirmation` | Yes |
| POST | `/change_expired_password` | `email`, `password_change_token`, `password`, `password_confirmation` | No |
| POST | `/save_account_profile_info` | profile fields | Yes |
| GET | `/account_cards` | - | Yes |
| POST | `/link_existing_account_card` | `card_number` | Yes |

### Fuel Prices & Locations

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/find_all_nearby_gas_locations` | `latitude`, `longitude` | Yes |
| POST | `/find_better_prices_within_range` | `latitude`, `longitude`, `fuel_type` | Yes |
| POST | `/get_locations_for_route` | `waypoints[]` | Yes |
| POST | `/search_city_state` | `city`, `state` | Yes |
| GET | `/get_fuel_price_location_details?id={id}` | - | Yes |
| GET | `/get_merchants` | - | Yes |
| POST | `/get_all_location_special_events` | `{}` (empty) | Yes |

### Brand & Partner Data

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| GET | `/get_brand_images` | - | Yes |
| GET | `/get_brand_image?id={id}` | - | Yes |
| GET | `/get_partners_with_content` | - | Yes |
| GET | `/get_partner_vip_interstitial/{id}` | - | Yes |
| POST | `/get_partner_map_content/{id}` | varies | Yes |
| POST | `/get_vip_offers` | `{}` | Yes |

### Transactions

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/get_fuel_transactions_for_card_paged` | `card_id`, `page`, `per_page` | Yes |

### Charity/Impact

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/get_charity_project_info` | `{}` | Yes |

### Programs & Applications

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/save_fuel_program_application` | application data | Yes |
| POST | `/save_insurance_program_application` | application data | Yes |
| POST | `/generate_loves_connect_code` | `{}` | Yes |

### Analytics/Logging

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/log_get_directions` | `fuel_price_id` | Yes |
| POST | `/log_view_better_prices` | `fuel_price_id` | Yes |
| POST | `/log_view_transaction_details` | `fuel_transaction_id` | Yes |

### Support

| Method | Endpoint | Body Parameters | Auth |
|--------|----------|-----------------|------|
| POST | `/create_user_ticket` | `subject`, `message` | Yes |

---

## Response Format

### Success Response

```json
{
  "response": {
    // endpoint-specific data
  }
}
```

### Error Response

```json
{
  "errors": ["Error message 1", "Error message 2"]
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Session expired (re-authenticate) |
| 4xx | Client error |
| 5xx | Server error |

---

## External APIs

### Google Maps Directions

```bash
curl "https://maps.googleapis.com/maps/api/directions/json?origin=37.7749,-122.4194&destination=34.0522,-118.2437&key=AIzaSyBLBLDA-kIki0Dcqe05LmIY8IfQ2kxaiLw"
```

---

## Device ID Requirements

The `deviceId` parameter is used for:
- Device limiting (max devices per account)
- Analytics tracking
- Fraud prevention

**To use the API from a script/tool:**
- Generate any 16-character hexadecimal string
- Keep it consistent for the same "device"
- Use a different ID to appear as a different device

```bash
# Generate a random device ID
DEVICE_ID=$(openssl rand -hex 8)
echo $DEVICE_ID  # e.g., "fa0113a1aefe6a1d"
```

---

## Python Example

```python
import requests

BASE_URL = "https://hydrocarbon-xl.herokuapp.com"
DEVICE_ID = "fa0113a1aefe6a1d"
VERSION_ID = "1.3.6"

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def login(email, password):
    url = f"{BASE_URL}/authenticate?deviceId={DEVICE_ID}&versionId={VERSION_ID}"
    response = requests.post(url, headers=HEADERS, json={
        "email": email,
        "password": password
    })
    data = response.json()
    return data.get("response", {}).get("api_key")

def find_nearby_stations(api_key, lat, lng):
    url = f"{BASE_URL}/find_all_nearby_gas_locations?api_key={api_key}&deviceId={DEVICE_ID}&versionId={VERSION_ID}"
    response = requests.post(url, headers=HEADERS, json={
        "latitude": lat,
        "longitude": lng
    })
    return response.json()

# Usage
api_key = login("user@example.com", "password")
if api_key:
    stations = find_nearby_stations(api_key, 37.7749, -122.4194)
    print(stations)
```

---

## See Also

- [Authentication Details](./openroads_auth.md) - Credentials and tokens
- [OpenAPI Specifications](./openapi/) - Swagger/OpenAPI spec files
