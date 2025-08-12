# ROSboard Authentication Setup

ROSboard now includes Google OAuth device authentication to secure access to your ROS topics and system data.

## Prerequisites

1. A Google Cloud Project
2. Google OAuth 2.0 credentials

## Setup Instructions

### 1. Create Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Choose "TVs and other devices" as the application type
6. Note down your `Client ID` and `Client Secret`

### 2. Set Environment Variables

Set these environment variables before running ROSboard:

```bash
export GOOGLE_CLIENT_ID="your-google-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export COOKIE_SECRET="your-secure-cookie-secret"
export ALLOWED_EMAIL_DOMAINS="kiwibot.com,company.com"  # Restrict access to specific domains (optional)
```

### Domain Whitelisting

The `ALLOWED_EMAIL_DOMAINS` environment variable allows you to restrict access to users with emails from specific domains:

#### **Configuration Examples:**

```bash
# Allow only Kiwibot employees
export ALLOWED_EMAIL_DOMAINS="kiwibot.com"

# Allow multiple company domains
export ALLOWED_EMAIL_DOMAINS="kiwibot.com,company.com,startup.io"

# No restrictions (default behavior)
export ALLOWED_EMAIL_DOMAINS=""  # or don't set the variable
```

#### **How It Works:**

1. **User attempts to authenticate** via Google OAuth
2. **System checks email domain** against the whitelist
3. **If domain is allowed**: Authentication proceeds normally ✅
4. **If domain is blocked**: User receives "Access denied" error ❌

#### **Security Benefits:**

- **Restrict access** to company employees only
- **Prevent unauthorized users** from accessing ROSboard
- **Domain-level access control** without managing individual user lists
- **Easy to update** when company domains change

#### **Error Handling:**

When a user with a blocked domain tries to authenticate, they'll see:
- **Error message**: "Access denied: Your email domain is not allowed."
- **HTTP status**: 403 Forbidden
- **Clear feedback**: User knows why access was denied

**Important**: 
- `COOKIE_SECRET` should be a long, random string for production use
- Never commit these credentials to version control

### 3. Run ROSboard

Start ROSboard as usual:

```bash
ros2 run rosboard rosboard_node
```

The authentication system will automatically:
- Redirect unauthenticated users to `/login.html`
- Require Google OAuth before allowing access to ROS data
- Maintain secure sessions using cookies

## How It Works

1. **Device Code Flow**: Uses Google's device authorization flow, which is ideal for devices without keyboards
2. **QR Code**: Users can scan a QR code or enter a code manually
3. **Secure Sessions**: Authenticated users get secure cookies for 60 days
4. **Protected Access**: Both the web interface and WebSocket connections require authentication

## Security Features

- Secure HTTP-only cookies
- SameSite cookie protection
- Token verification against Google's servers
- Session expiration after 60 days
- Automatic logout on session expiry

## Production Considerations

1. **HTTPS**: Enable HTTPS and set `secure=True` in cookie settings
2. **Strong Secrets**: Use a strong, random COOKIE_SECRET
3. **Domain Restrictions**: Consider restricting OAuth to specific domains
4. **Monitoring**: Monitor authentication logs for security issues

## API Endpoints

- `GET /me` - Check authentication status
- `POST /auth/start` - Start OAuth flow
- `POST /auth/poll` - Poll for OAuth completion
- `POST /logout` - Logout user
- `GET /login.html` - Login page
- `GET /` - Main application (requires authentication)

## Admin Monitoring

ROSboard now includes comprehensive admin monitoring capabilities for WebSocket connections:

### Admin Interface
- **URL**: `http://your-robot-ip:8888/admin.html`
- **Features**: Real-time connection monitoring and user tracking (read-only)

### Admin API Endpoints
- **`GET /admin`** - Get connection statistics and user information

### Connection Statistics
The admin interface provides:
- **Total Connections**: Number of active WebSocket connections
- **Unique Users**: Number of different authenticated users
- **User Details**: List of connected users with connection counts
- **Real-time Updates**: Auto-refresh every 5 seconds

### Enhanced User Tracking
The system now tracks not just user connections, but also the source of each connection:

- **`user@email.com (via cookie from rosboard)`** - Authenticated user from main ROSboard interface
- **`user@email.com (via cookie from foxglove)`** - Same authenticated user connecting from Foxglove
- **`user@email.com (via dropped_association from foxglove)`** - User reconnecting via dropped user tracking
- **`user@email.com (via persistent_association from foxglove)`** - User reconnecting via persistent session file
- **`external_client (via external from foxglove)`** - Unauthenticated external client

This allows you to see exactly how your authenticated users are accessing the system across different interfaces and recovery scenarios.

### Authentication Method Types

The system now supports multiple authentication methods for robust user tracking:

1. **`cookie`** - Standard cookie-based authentication (most secure)
2. **`dropped_association`** - User reconnecting within 5 seconds of disconnection
3. **`persistent_association`** - User reconnecting via persistent session file (restart recovery)
4. **`external`** - Unauthenticated external client
5. **`no-auth`** - Authentication system disabled


## Foxglove Compatibility

### The Problem

When authentication is enabled, external clients like Foxglove (running on different domains) cannot connect to the ROSboard WebSocket because:

1. **Cross-Origin Cookie Access**: Foxglove instances cannot access ROSboard's authentication cookies
2. **WebSocket Authentication**: The WebSocket connection requires valid session cookies
3. **Domain Mismatch**: Different domains prevent cookie sharing

For this we enable the connection of external clients without authentication and associate the Foxglove connection with the last user that was connected (we asume it clicked on the Foxglove button which redirected to Foxglove).

## Persistent Session System

### The Problem with Restarts

When ROSboard restarts (due to crashes, updates, or system reboots), all in-memory user tracking is lost. This means:

- **Foxglove connections** become `"external_client"` instead of showing the user's email
- **User association** is lost until the user re-authenticates
- **Admin monitoring** shows anonymous connections

### The Solution: Multi-Layer Session Persistence

ROSboard now includes a robust persistent session system that handles **both** planned restarts and **runtime crashes**:

1. **Real-time Session Saving**: Sessions are saved when Foxglove connections open and close
2. **Periodic Auto-Save**: Sessions are automatically saved every 15 seconds during runtime
3. **Restart Recovery**: Sessions are restored from file on startup within configurable timeout

### How It Works

#### **During Normal Operation:**
1. **User authenticates on ROSboard** → gets session cookies
2. **User connects to Foxglove** → WebSocket shows their email
3. **Session automatically saved** → every 30 seconds + on connection events
4. **User disconnects** → final session state saved

#### **During Runtime Crashes:**
1. **ROSboard dies unexpectedly** → sessions preserved in file (last save within 30s)
2. **Foxglove reconnects** → system checks persistent file
3. **If within timeout** → connection associated with saved user email ✅
4. **If timeout expired** → shows as `external_client` ❌