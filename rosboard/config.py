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

# Authentication URLs
DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
TOKEN_URL = "https://oauth2.googleapis.com/token"

# Check if required environment variables are set
def validate_config():
    """Validate that required configuration is present"""
    auth_enabled = True
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        print("WARNING: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variable not set")
        print("Authentication will be disabled - ROSboard will run without security")
        auth_enabled = False
    
    if COOKIE_SECRET == "rosboard_default_secret_change_in_production":
        print("WARNING: Using default COOKIE_SECRET. Set COOKIE_SECRET environment variable for production")
    
    if auth_enabled:
        print("INFO: Google OAuth authentication is enabled")
    else:
        print("INFO: Running ROSboard without authentication")
    
    return auth_enabled 