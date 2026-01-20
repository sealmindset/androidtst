# OpenAPI Specifications for Open Roads

This directory contains OpenAPI 3.0 specifications for all APIs used by the Open Roads app.

## Files

| File | Description |
|------|-------------|
| [openroads-api.yaml](./openroads-api.yaml) | Main Open Roads backend API |
| [google-maps-api.yaml](./google-maps-api.yaml) | Google Maps Directions API |
| [external-services.yaml](./external-services.yaml) | Static content and web portals |

## Main API Base URL

```
https://hydrocarbon-xl.herokuapp.com/
```

## Authentication

The main API uses query parameter authentication:

```
GET /endpoint?api_key={session_token}
POST /endpoint?api_key={session_token}
```

The `api_key` is obtained from the `/authenticate` endpoint after successful login.

## API Keys Found in APK

| Service | Key | Location |
|---------|-----|----------|
| Google Maps | `AIzaSyBLBLDA-kIki0Dcqe05LmIY8IfQ2kxaiLw` | AndroidManifest.xml |

## Viewing Specifications

You can view these specs using:

1. **Swagger Editor**: https://editor.swagger.io/
2. **Swagger UI**: Import the YAML file
3. **VS Code**: Install "OpenAPI (Swagger) Editor" extension
4. **Postman**: Import as OpenAPI 3.0 collection

## Endpoints Summary

### Authentication (6 endpoints)
- POST `/authenticate` - Login
- POST `/register` - Create account
- POST `/verify_two_factor_code` - 2FA verification
- POST `/send_two_factor_code` - Request 2FA code
- POST `/generate_password_reset_code` - Password reset
- POST `/change_password` - Change password

### Account (3 endpoints)
- POST `/save_account_profile_info` - Update profile
- GET `/account_cards` - Get fuel cards
- POST `/link_existing_account_card` - Link card

### Fuel Locations (7 endpoints)
- POST `/find_all_nearby_gas_locations` - Nearby stations
- POST `/find_better_prices_within_range` - Better prices
- POST `/get_locations_for_route` - Route planning
- POST `/search_city_state` - Location search
- GET `/get_fuel_price_location_details` - Station details
- GET `/get_merchants` - Merchant list
- POST `/get_all_location_special_events` - Promotions

### Partners & VIP (5 endpoints)
- GET `/get_brand_images` - Brand logos
- GET `/get_partners_with_content` - Partner info
- GET `/get_partner_vip_interstitial/{id}` - VIP details
- POST `/get_partner_map_content/{id}` - Map content
- POST `/get_vip_offers` - VIP offers

### Transactions (1 endpoint)
- POST `/get_fuel_transactions_for_card_paged` - Transaction history

### Programs (3 endpoints)
- POST `/save_fuel_program_application` - Fuel program
- POST `/save_insurance_program_application` - Insurance
- POST `/generate_loves_connect_code` - Love's connect

### Analytics (3 endpoints)
- POST `/log_get_directions` - Log directions
- POST `/log_view_better_prices` - Log price views
- POST `/log_view_transaction_details` - Log transaction views

### Support (1 endpoint)
- POST `/create_user_ticket` - Support ticket

**Total: 29 endpoints**
