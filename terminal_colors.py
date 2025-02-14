"""
Terminal color and formatting utilities.

This module provides constants and utilities for terminal
color formatting and display.
"""

from colorist import Color, Effect


class TerminalColors:
  """Terminal color and formatting constants."""

  BOLD = f"{Effect.BOLD}"
  BLINK = f"{Effect.BLINK}"
  BLINK_OFF = f"{Effect.BLINK_OFF}"
  EFFECT_OFF = f"{Effect.OFF}"
  WHITE = f"{Color.WHITE}"
  RED = f"{Color.RED}"
  GREEN = f"{Color.GREEN}"
  YELLOW = f"{Color.YELLOW}"
  COLOR_RESET = f"{Color.OFF}"


def format_terminal_message(message_text: str, text_color: str) -> str:
  """Format a message with color and reset codes."""
  return f"{text_color}{message_text}{TerminalColors.COLOR_RESET}"


def display_error(error_message: str) -> None:
  """Display an error message in red."""
  print(format_terminal_message(error_message, TerminalColors.RED))


def display_warning(warning_message: str) -> None:
  """Display a warning message in yellow."""
  print(format_terminal_message(warning_message, TerminalColors.YELLOW))


def display_success(success_message: str) -> None:
  """Display a success message in green."""
  print(format_terminal_message(success_message, TerminalColors.GREEN))
