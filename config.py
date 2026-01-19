#!/usr/bin/env python3
"""
Android Test Harness Configuration Module

Loads configuration from environment variables (via .env file).
All sensitive credentials must be provided via environment - no hardcoded defaults.

Usage:
    from config import config

    email = config.test_email
    password = config.test_password
"""

import os
from dataclasses import dataclass
from pathlib import Path

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
        TEST_EMAIL: Email address for test account
        TEST_PASSWORD: Password for test account
        SLEEPER_ID: Sleeper ID for IDOR testing

    Optional environment variables:
        API_BASE: Base URL for API (default: https://api.sleepiq.sleepnumber.com/rest)
    """
    test_email: str
    test_password: str
    sleeper_id: str
    api_base: str

    @classmethod
    def from_environment(cls) -> 'Config':
        """Load configuration from environment variables.

        Raises:
            ConfigurationError: If required environment variables are missing.
        """
        missing = []

        test_email = os.environ.get('TEST_EMAIL')
        if not test_email:
            missing.append('TEST_EMAIL')

        test_password = os.environ.get('TEST_PASSWORD')
        if not test_password:
            missing.append('TEST_PASSWORD')

        sleeper_id = os.environ.get('SLEEPER_ID')
        if not sleeper_id:
            missing.append('SLEEPER_ID')

        if missing:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"\n"
                f"To configure:\n"
                f"  1. Copy .env.example to .env\n"
                f"  2. Fill in your credentials\n"
                f"  3. Run again\n"
                f"\n"
                f"Or set environment variables directly:\n"
                f"  export TEST_EMAIL=your-email@example.com\n"
                f"  export TEST_PASSWORD=your-password\n"
                f"  export SLEEPER_ID=your-sleeper-id"
            )

        api_base = os.environ.get('API_BASE', 'https://api.sleepiq.sleepnumber.com/rest')

        return cls(
            test_email=test_email,
            test_password=test_password,
            sleeper_id=sleeper_id,
            api_base=api_base
        )


# Global config instance - loaded on import
# This will raise ConfigurationError if required vars are missing
config = Config.from_environment()
