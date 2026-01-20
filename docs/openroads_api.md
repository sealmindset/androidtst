# Open Roads API Documentation

## Overview

The Open Roads app (`openroads.fueldiscountapp`) uses a REST API hosted at `https://hydrocarbon-xl.herokuapp.com/`.

All authenticated endpoints require an `api_key` query parameter obtained after login.

---

## Base URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Main API | `https://hydrocarbon-xl.herokuapp.com/` | Primary backend API |
| Account Portal | `https://apply.myopenroads.com/` | Account management web portal |
| Static Assets | `https://d1wp6m56sqw74a.cloudfront.net/` | CDN for images and assets |
| Google Maps | `https://maps.googleapis.com/maps/api/` | Directions and mapping |

---

## Authentication

### Authentication Flow

1. User submits email/password to `/authenticate`
2. Server returns `api_key` on success
3. All subsequent requests include `?api_key={key}` query parameter
4. Two-factor authentication may be required (see 2FA endpoints)

### Credentials Storage

| Key | Storage | Description |
|-----|---------|-------------|
| `api_key` | AsyncStorage | Session token for API calls |
| `user_email` | AsyncStorage | User's email address |

---

## API Endpoints

### Authentication & Account

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/authenticate` | Login with email/password | No |
| POST | `/register` | Create new account | No |
| POST | `/verify_two_factor_code` | Verify 2FA code | Partial (api_key in URL) |
| POST | `/send_two_factor_code` | Request 2FA code delivery | Yes |
| POST | `/generate_password_reset_code` | Request password reset | No |
| POST | `/verify_password_reset_code` | Verify reset code | No |
| POST | `/change_password` | Change password (logged in) | Yes |
| POST | `/change_expired_password` | Change expired password | Partial |
| POST | `/save_account_profile_info` | Update profile | Yes |
| GET | `/account_cards` | Get linked fuel cards | Yes |
| POST | `/link_existing_account_card` | Link a fuel card | Yes |

### Fuel Prices & Locations

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/find_all_nearby_gas_locations` | Find gas stations nearby | Yes |
| POST | `/find_better_prices_within_range` | Find cheaper fuel prices | Yes |
| POST | `/get_locations_for_route` | Get stations along route | Yes |
| POST | `/search_city_state` | Search locations by city/state | Yes |
| GET | `/get_fuel_price_location_details` | Get station details | Yes |
| GET | `/get_merchants` | Get merchant list | Yes |
| POST | `/get_all_location_special_events` | Get promotions/events | Yes |

### Brand & Partner Data

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/get_brand_images` | Get all brand logos | Yes |
| GET | `/get_brand_image` | Get specific brand logo | Yes |
| GET | `/get_partners_with_content` | Get partner information | Yes |
| GET | `/get_partner_vip_interstitial/{id}` | Get VIP partner details | Yes |
| POST | `/get_partner_map_content/{id}` | Get partner map data | Yes |
| POST | `/get_vip_offers` | Get VIP discount offers | Yes |

### Transactions

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/get_fuel_transactions_for_card_paged` | Get transaction history | Yes |

### Charity/Impact

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/get_charity_project_info` | Get charity project details | Yes |

### Programs & Applications

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/save_fuel_program_application` | Apply for fuel program | Yes |
| POST | `/save_insurance_program_application` | Apply for insurance program | Yes |
| POST | `/generate_loves_connect_code` | Generate Love's connect code | Yes |

### Analytics/Logging

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/log_get_directions` | Log directions request | Yes |
| POST | `/log_view_better_prices` | Log price comparison view | Yes |
| POST | `/log_view_transaction_details` | Log transaction view | Yes |

### Support

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/create_user_ticket` | Submit support ticket | Yes |

---

## External APIs

### Google Maps Directions API

| Method | Endpoint | Auth |
|--------|----------|------|
| GET | `https://maps.googleapis.com/maps/api/directions/json` | API Key |

**API Key:** `AIzaSyBLBLDA-kIki0Dcqe05LmIY8IfQ2kxaiLw`

### Static Content

| URL | Description |
|-----|-------------|
| `https://hydrocarbon-xl.herokuapp.com/tsd/terms.txt` | Terms of Service |
| `https://hydrocarbon-xl.herokuapp.com/tsd/privacy.txt` | Privacy Policy |
| `https://hydrocarbon-xl.herokuapp.com/tsd/TSD-RV-App-and-Setting-up-Pin.pdf` | Setup Guide |

### Web Portal

| URL | Description |
|-----|-------------|
| `https://apply.myopenroads.com/user-portal/account-deletion-request?api_key={key}` | Account deletion |
| `https://myopenroads.com/loves` | Love's partnership info |
| `https://myopenroads.com/vip-access` | VIP access info |

---

## Request/Response Format

### Standard Request Headers

```
Content-Type: application/json
```

### Authentication Parameter

All authenticated endpoints append:
```
?api_key={api_key}
```

Or if URL already has parameters:
```
&api_key={api_key}
```

### Standard Response Structure

```json
{
  "api_key": "string (on auth success)",
  "errors": ["array of error messages"],
  "response": { ... },
  "two_factor_auth_delivery_options": ["array (if 2FA required)"]
}
```

---

## Device Identification

The app sends device information with requests:

| Field | Source | Description |
|-------|--------|-------------|
| `uniqueId` | `Settings.Secure.android_id` | Primary device identifier |
| `deviceId` | `Build.BOARD` | Hardware board name |
| `model` | `Build.MODEL` | Device model |
| `brand` | `Build.BRAND` | Device brand |
| `systemVersion` | `Build.VERSION.RELEASE` | Android version |

---

## See Also

- [OpenAPI Specifications](./openapi/) - Swagger/OpenAPI spec files
- [Authentication Details](./openroads_auth.md) - Detailed auth documentation
