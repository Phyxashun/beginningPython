"""
Debug utilities for the credential verification system.

This module contains debug-specific functionality and helpers
for development and testing purposes.
"""

import os
from typing import Any, Dict

from terminal_colors import TerminalColors

# Debug configuration
DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() == "true"
DISPLAY_COLOR = TerminalColors.YELLOW if DEBUG_MODE else TerminalColors.WHITE


def format_debug_message(message_text: str) -> str:
  """Format a debug message with appropriate color."""
  return f"{DISPLAY_COLOR}{message_text}{TerminalColors.COLOR_RESET}"


def display_debug_status() -> None:
  """Display the debug mode status message."""
  if DEBUG_MODE:
    status_message = (
      f"{TerminalColors.BOLD}{DISPLAY_COLOR}"
      f"DEBUG MODE IS {TerminalColors.BLINK}ENABLED{TerminalColors.BLINK_OFF}!"
      f"{TerminalColors.EFFECT_OFF}\n"
    )
    print(status_message)


def display_debug(debug_message: str) -> None:
  """Display a debug message if debug mode is enabled."""
  if DEBUG_MODE:
    print(format_debug_message(debug_message))


def get_safe_credential_display(credentials: Dict[str, Any]) -> Dict[str, Any]:
  """Create a safe version of credentials for debug display."""
  return {service_name: {"Key": "[HIDDEN]", "Secret": "[HIDDEN]"} for service_name in credentials.keys()}


def get_test_credentials(stored_credentials: Dict[str, Any]) -> Dict[str, Any]:
  """Get a single credential for testing in debug mode."""
  if not stored_credentials:
    return {}

  test_service = next(iter(stored_credentials.keys()))
  return {test_service: stored_credentials[test_service]}
