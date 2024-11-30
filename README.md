# GO-AUTH: Authentication Service

## Task

Implement a part of an authentication service with two REST endpoints:

1. Issue a pair of Access and Refresh tokens for a user by `GUID`.
2. Refresh an Access token using a Refresh token.

## API Endpoints

### 1. Token Endpoint
**POST** `/auth/token`

**Query params:** `guid` - user identifier with length of 16

### 2. Refresh Endpoint
**POST** `/auth/refresh`

**Request:**
```json
{
  "user_id": "user-guid"
}
```