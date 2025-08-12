#!/usr/bin/env python3
"""
Configuration file for ROSboard authentication
"""

import os

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

# Cookie Configuration
COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "rosboard_default_secret_change_in_production")

# Domain Whitelist Configuration
ALLOWED_EMAIL_DOMAINS = os.environ.get("ALLOWED_EMAIL_DOMAINS", "").split(",")
if ALLOWED_EMAIL_DOMAINS == [""]:  # Handle empty string case
    ALLOWED_EMAIL_DOMAINS = []

# Persistent Session Configuration
# This is used to store the session data for the Foxglove connection in case rosboard dies
# So we can associate the Foxglove connection with the last user that was connected
PERSISTENT_SESSION_FILE = os.environ.get("PERSISTENT_SESSION_FILE", "rosboard_foxglove_sessions.pkl")
PERSISTENT_SESSION_TIMEOUT = int(os.environ.get("PERSISTENT_SESSION_TIMEOUT", "60"))  # seconds

def is_email_domain_allowed(email):
    """Check if the email domain is in the allowed whitelist"""
    if not ALLOWED_EMAIL_DOMAINS:  # No restrictions
        return True
    
    if not email or "@" not in email:
        return False
    
    domain = email.split("@")[1].lower()
    return domain in [d.strip().lower() for d in ALLOWED_EMAIL_DOMAINS]

# Authentication URLs
DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
TOKEN_URL = "https://oauth2.googleapis.com/token"

def validate_config():
    """Validate that required configuration is present"""
    auth_enabled = True
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print("WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variable not set")
        print("Authentication will be disabled - ROSboard will run without security")
        auth_enabled = False
    else:
        if COOKIE_SECRET == "rosboard_default_secret_change_in_production":
            print("WARNING: Using default COOKIE_SECRET. Set COOKIE_SECRET environment variable for production")
    
    if auth_enabled:
        print("INFO: Google OAuth authentication is enabled")
        if ALLOWED_EMAIL_DOMAINS:
            print(f"INFO: Domain restrictions enabled for: {', '.join(ALLOWED_EMAIL_DOMAINS)}")
    else:
        print("INFO: Running ROSboard without authentication")
    
    return auth_enabled 