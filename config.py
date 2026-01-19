#!/usr/bin/env python3
"""
Android Test Harness Configuration Module

Loads configuration from environment variables (via .env file).
Credentials are optional - only required for scripts that need authentication.

Usage:
    from config import config

    # Always available
    package = config.target_package  # Required

    # Optional - may be None
    email = config.test_email
    api = config.api_base

    # For scripts requiring auth
    config.require_auth()  # Raises if auth vars missing
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass  # python-dotenv not installed, rely on environment variables


class ConfigurationError(Exception):
    """Raised when required configuration is missing."""
    pass


@dataclass
class Config:
    """Configuration for Android Test Harness.

    Required environment variables:
        TARGET_PACKAGE: Android package name to test (e.g., com.example.app)

    Optional environment variables:
        TEST_EMAIL: Email address for test account (if app requires auth)
        TEST_PASSWORD: Password for test account (if app requires auth)
        TARGET_ID: Target identifier for testing (e.g., user ID, resource ID)
        API_BASE: Base URL for API testing
    """
    target_package: Optional[str]
    test_email: Optional[str]
    test_password: Optional[str]
    target_id: Optional[str]
    api_base: Optional[str]

    @classmethod
    def from_environment(cls) -> 'Config':
        """Load configuration from environment variables.

        Does not raise on missing optional variables.
        Use require_auth() to validate auth-related vars when needed.
        """
        return cls(
            target_package=os.environ.get('TARGET_PACKAGE'),
            test_email=os.environ.get('TEST_EMAIL'),
            test_password=os.environ.get('TEST_PASSWORD'),
            target_id=os.environ.get('TARGET_ID'),
            api_base=os.environ.get('API_BASE')
        )

    def require_package(self) -> str:
        """Validate and return TARGET_PACKAGE (required for most operations).

        Raises:
            ConfigurationError: If TARGET_PACKAGE is not set.
        """
        if not self.target_package:
            raise ConfigurationError(
                "Missing required environment variable: TARGET_PACKAGE\n"
                "\n"
                "To configure:\n"
                "  export TARGET_PACKAGE=com.example.app\n"
                "\n"
                "Or add to .env file:\n"
                "  TARGET_PACKAGE=com.example.app"
            )
        return self.target_package

    def require_auth(self) -> tuple:
        """Validate auth variables are set.

        Raises:
            ConfigurationError: If TEST_EMAIL or TEST_PASSWORD is missing.

        Returns:
            Tuple of (test_email, test_password)
        """
        missing = []

        if not self.test_email:
            missing.append('TEST_EMAIL')

        if not self.test_password:
            missing.append('TEST_PASSWORD')

        if missing:
            raise ConfigurationError(
                f"Missing required auth variables: {', '.join(missing)}\n"
                f"\n"
                f"To configure:\n"
                f"  1. Copy .env.example to .env\n"
                f"  2. Fill in your credentials\n"
                f"  3. Run again\n"
                f"\n"
                f"Or set environment variables directly:\n"
                f"  export TEST_EMAIL=your-email@example.com\n"
                f"  export TEST_PASSWORD=your-password"
            )

        return (self.test_email, self.test_password)


# Global config instance - loaded on import
# Does NOT raise if optional vars are missing
config = Config.from_environment()
