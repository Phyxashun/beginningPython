"""
Error handling utilities for the credential verification system.

This module provides consistent error message formatting and
standard error messages for common scenarios.
"""

from debug_utils import DEBUG_MODE, display_debug
from terminal_colors import display_error, display_warning


class CredentialError:
  """Standard error messages for credential operations."""

  # File operation errors
  FILE_NOT_FOUND = (
    "Failed to locate credentials file at '{path}'\n"
    "Please ensure:\n"
    "- The file exists at the specified location\n"
    "- You have correct read permissions\n"
    "- The path is correctly specified in CREDENTIALS_PATH environment variable"
  )

  INVALID_JSON = (
    "Failed to parse credentials file as JSON\n"
    "Please ensure:\n"
    "- The file contains valid JSON syntax\n"
    "- The file is not empty\n"
    "- The file encoding is UTF-8"
  )

  INVALID_FORMAT = (
    "Credentials file has unexpected format\n"
    "Expected format:\n"
    "{\n"
    '    "service_name": {\n'
    '        "Key": "your_key",\n'
    '        "Secret": "your_secret"\n'
    "    }\n"
    "}"
  )

  # Verification errors
  VERIFICATION_FAILED = (
    "Failed to verify {service} credentials\n"
    "Please check:\n"
    "- Key and Secret are entered correctly\n"
    "- Credentials have not expired\n"
    "- Service name matches exactly"
  )

  SERVICE_NOT_FOUND = "Service '{service}' not found in stored credentials\nAvailable services: {available_services}"

  NO_CREDENTIALS = (
    "No valid credentials found\nPlease ensure:\n- Credentials file is not empty\n- At least one service is configured"
  )

  NO_INPUT_CREDENTIALS = "No credentials provided for verification\nOperation cancelled"

  # Runtime errors
  HASH_ERROR = "Failed to hash credential: {detail}\nPlease ensure the input is a valid string"

  VERIFICATION_ERROR = "Error during credential verification: {detail}\nThis might indicate corrupted credential data"


def format_error_message(message_template: str, **kwargs) -> str:
  """Format an error message with provided parameters."""
  try:
    return message_template.format(**kwargs)
  except KeyError as e:
    if DEBUG_MODE:
      display_debug(f"Error formatting message: missing key {e}")
    return message_template
  except Exception as e:
    if DEBUG_MODE:
      display_debug(f"Error formatting message: {e}")
    return message_template


def handle_credential_error(error_template: str, error_type: str, **kwargs) -> None:
  """Handle a credential operation error with consistent formatting."""
  error_message = format_error_message(error_template, **kwargs)

  if DEBUG_MODE:
    error_message = f"{error_message}\nError Type: {error_type}"

  display_error(error_message)


def handle_credential_warning(warning_template: str, warning_type: str, **kwargs) -> None:
  """Handle a credential operation warning with consistent formatting."""
  warning_message = format_error_message(warning_template, **kwargs)

  if DEBUG_MODE:
    warning_message = f"{warning_message}\nWarning Type: {warning_type}"

  display_warning(warning_message)
