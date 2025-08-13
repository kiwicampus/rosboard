#!/usr/bin/env python3
"""
Configuration file for ROSboard authentication
"""

import os
import logging

# Set up logging
logger = logging.getLogger("ROSboard")
logger.setLevel(logging.INFO)

# Create console handler if none exists
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)

# Authentication URLs
DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
TOKEN_URL = "https://oauth2.googleapis.com/token"

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("ROSBOARD_GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("ROSBOARD_GOOGLE_CLIENT_SECRET")

# Cookie Configuration
COOKIE_SECRET = os.environ.get("ROSBOARD_COOKIE_SECRET", "rosboard_default_secret_change_in_production")

# Domain Whitelist Configuration
ALLOWED_EMAIL_DOMAINS = os.environ.get("ROSBOARD_ALLOWED_EMAIL_DOMAINS", "").split(",")
if ALLOWED_EMAIL_DOMAINS == [""]:  # Handle empty string case
    ALLOWED_EMAIL_DOMAINS = []


def is_email_domain_allowed(email):
    """Check if the email domain is in the allowed whitelist"""
    if not ALLOWED_EMAIL_DOMAINS:  # No restrictions
        return True
    
    if not email or "@" not in email:
        return False
    
    domain = email.split("@")[1].lower()
    return domain in [d.strip().lower() for d in ALLOWED_EMAIL_DOMAINS]

def validate_config(google_auth_enabled, allow_external_clients):
    """Validate that required configuration is present"""
    auth_enabled = True
    
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not google_auth_enabled:
        if not google_auth_enabled:
            logger.info("Google OAuth authentication is disabled on WebUI. Also any WS client can connect to ROSboard.")
        else:
            logger.warning("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variable not set, need to set for Google OAuth authentication")
            logger.warning("Authentication will be disabled - ROSboard main page will run without security")
        auth_enabled = False
    else:
        if COOKIE_SECRET == "rosboard_default_secret_change_in_production":
            logger.warning("Using default COOKIE_SECRET. Set COOKIE_SECRET environment variable for production")
    
    if auth_enabled:
        logger.info("Google OAuth authentication is enabled on WebUI. Any WS client will require to login with a Google account if accessing from WebUI")
        if ALLOWED_EMAIL_DOMAINS:
            logger.info(f"Only users with email from the following domains can connect to ROSboard: {', '.join(ALLOWED_EMAIL_DOMAINS)}")
        if allow_external_clients:
            logger.info("Allowing external WS clients to connect to ROSboard (standalone Foxglove connections, other ROSboard client libs, etc)")
    
    return auth_enabled 