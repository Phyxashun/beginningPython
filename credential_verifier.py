"""
Credential Verification System

This module provides a secure system for storing and verifying credentials using bcrypt hashing.
It supports storing multiple service credentials in a JSON file and provides both interactive
and debug modes for credential verification.

Features:
    - Secure password hashing using bcrypt
    - JSON-based credential storage
    - Cross-platform terminal support
    - Color-coded output for better readability
    - Debug mode for testing
    - Support for multiple service credentials

Example usage:
    $ python credential_verifier.py
    # Follow the interactive prompts to verify credentials

Environment Variables:
    DEBUG: Set to "true" to enable debug mode (default: "false")
    CREDS_PATH: Path to the credentials JSON file (default: "./data.json")

Author: Dusty Dew
Email: phyxashun.proton@proton.me
Version: 1.0.0
Date: February 14, 2025
License: MIT
"""

import json
import os
import platform
import sys
from enum import Enum
from getpass import getpass
from typing import Any, Dict, List, Optional, TypedDict, TypeVar, Union, cast

import bcrypt

from debug_utils import (
  DEBUG_MODE,
  display_debug,
  display_debug_status,
  get_safe_credential_display,
  get_test_credentials,
)
from error_handling import CredentialError, handle_credential_error, handle_credential_warning
from terminal_colors import display_success

# Constants and Configuration
CREDENTIALS_PATH = os.environ.get("CREDENTIALS_PATH", "./data.json")


class SecurityLimits:
  """Security limits for different credential types"""

  # Standard password limits (bcrypt)
  BCRYPT_MAX_SIZE = 72
  MIN_CREDENTIAL_SIZE = 1

  # Bearer token limits
  BEARER_MAX_SIZE = 1024  # Allow for long API tokens

  # Other limits
  MAX_SERVICE_NAME_LENGTH = 100
  MAX_CREDENTIALS_PER_FILE = 1000


# Type definitions
ServiceName = str
T = TypeVar("T")  # Can be str for plain text or bytes for hashed


class CredentialPair(TypedDict):
  """Type class for credential key-secret pairs"""

  Key: T
  Secret: T


PlainCredentialsDict = Dict[ServiceName, CredentialPair[str]]
HashedCredentialsDict = Dict[ServiceName, CredentialPair[bytes]]
ValidationResult = Dict[ServiceName, bool]


class CredentialType(Enum):
  """Types of credentials with their specific limits"""

  BEARER = "Bearer"
  STANDARD = "Standard"


def validate_credential_string(
  credential: str, credential_name: str, cred_type: CredentialType = CredentialType.STANDARD
) -> Optional[str]:
  """
  Validate a credential string against security requirements.

  Args:
      credential: The credential string to validate
      credential_name: Name of the credential for error messages
      cred_type: Type of credential (Bearer or Standard)

  Returns:
      str or None: Validated credential or None if invalid
  """
  if not isinstance(credential, str):
    handle_credential_error(f"Invalid {credential_name} type: must be string", "InvalidType")
    return None

  # First check for empty or whitespace
  stripped_credential = credential.strip()
  if not stripped_credential:
    handle_credential_error(f"Invalid {credential_name}: cannot be empty or whitespace", "EmptyCredential")
    return None

  # Get appropriate size limit based on credential type
  max_size = SecurityLimits.BEARER_MAX_SIZE if cred_type == CredentialType.BEARER else SecurityLimits.BCRYPT_MAX_SIZE

  # Check the UTF-8 encoded length
  encoded_length = len(stripped_credential.encode("utf-8"))
  if not SecurityLimits.MIN_CREDENTIAL_SIZE <= encoded_length <= max_size:
    handle_credential_error(
      f"Invalid {credential_name} length: must be between "
      f"{SecurityLimits.MIN_CREDENTIAL_SIZE} and {max_size} bytes when UTF-8 encoded",
      "InvalidLength",
    )
    return None

  return stripped_credential


def validate_credential_pair(service_name: str, creds: Dict[str, str]) -> bool:
  """Validate a credential pair based on service type"""
  # Determine credential type based on service name
  cred_type = CredentialType.BEARER if service_name.lower() == "bearer" else CredentialType.STANDARD

  # Validate both key and secret with appropriate type
  valid_key = validate_credential_string(creds["Key"], "key", cred_type)
  valid_secret = validate_credential_string(creds["Secret"], "secret", cred_type)

  return bool(valid_key and valid_secret)


def validate_service_name(service_name: str) -> Optional[str]:
  """
  Validate a service name against requirements.

  Args:
      service_name: The service name to validate

  Returns:
      str or None: Validated service name or None if invalid
  """
  if not isinstance(service_name, str):
    handle_credential_error("Invalid service name type: must be string", "InvalidType")
    return None

  service_name = service_name.strip()
  if not service_name:
    handle_credential_error("Invalid service name: cannot be empty or whitespace", "EmptyServiceName")
    return None

  if len(service_name) > SecurityLimits.MAX_SERVICE_NAME_LENGTH:
    handle_credential_error(
      f"Service name too long: maximum {SecurityLimits.MAX_SERVICE_NAME_LENGTH} characters", "ServiceNameTooLong"
    )
    return None

  if not service_name.isprintable():
    handle_credential_error("Service name contains invalid characters", "InvalidCharacters")
    return None

  return service_name


def clear_terminal_screen() -> None:
  """Clear the terminal screen in a cross-platform way."""
  try:
    os.system("cls" if platform.system() == "Windows" else "clear")
  except Exception as error:
    display_debug(f"Failed to clear screen: {error}")


def hash_credential(plain_text: str, cred_type: CredentialType = CredentialType.STANDARD) -> Optional[bytes]:
  """
  Generate a salt and hash the given credential using bcrypt.

  Args:
      plain_text: The plain text credential to hash
      cred_type: Type of credential (Bearer or Standard)

  Returns:
      bytes or None: Hashed credential or None if hashing fails
  """
  try:
    validated_text = validate_credential_string(plain_text, "credential", cred_type)
    if not validated_text:
      return None

    # For Bearer tokens, we store them directly as UTF-8 bytes without hashing
    if cred_type == CredentialType.BEARER:
      return validated_text.encode("utf-8")

    # For standard credentials, use bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(validated_text.encode("utf-8"), salt)
  except Exception as error:
    handle_credential_error(CredentialError.HASH_ERROR, "HashingError", detail=str(error))
    return None


def verify_credential(stored_hash: bytes, input_text: str, service_name: str = "") -> bool:
  """
  Verify if the input credential matches the stored hash.

  Args:
      stored_hash: The stored hashed credential
      input_text: The plain text credential to verify
      service_name: Name of the service for determining credential type

  Returns:
      bool: True if credentials match, False otherwise
  """
  try:
    if not stored_hash:
      return False

    cred_type = CredentialType.BEARER if service_name.lower() == "bearer" else CredentialType.STANDARD
    validated_text = validate_credential_string(input_text, "credential", cred_type)
    if not validated_text:
      return False

    # For Bearer tokens, compare the UTF-8 bytes directly
    if cred_type == CredentialType.BEARER:
      return stored_hash == validated_text.encode("utf-8")

    # For standard credentials, use bcrypt
    if isinstance(stored_hash, str):
      stored_hash = stored_hash.encode("utf-8")
    return bcrypt.checkpw(validated_text.encode("utf-8"), stored_hash)
  except Exception as error:
    handle_credential_error(CredentialError.VERIFICATION_ERROR, "VerificationError", detail=str(error))
    return False


def is_hash_value(credential_value: Any) -> bool:
  """
  Check if a value appears to be already hashed with bcrypt.

  Args:
      credential_value: The value to check

  Returns:
      bool: True if value appears to be hashed, False otherwise
  """
  try:
    if isinstance(credential_value, bytes):
      return True
    if isinstance(credential_value, str) and credential_value.startswith("$2b$"):
      return True
  except Exception:
    pass
  return False


def process_credential_value(raw_value: Union[str, bytes], service_name: str) -> Optional[bytes]:
  """
  Process a credential value, ensuring it's properly hashed or stored.

  Args:
      raw_value: The credential value to process
      service_name: Name of the service for determining credential type

  Returns:
      bytes or None: Processed credential or None if processing fails
  """
  try:
    if is_hash_value(raw_value):
      return raw_value if isinstance(raw_value, bytes) else raw_value.encode("utf-8")

    cred_type = CredentialType.BEARER if service_name.lower() == "bearer" else CredentialType.STANDARD
    return hash_credential(str(raw_value), cred_type)
  except Exception as error:
    handle_credential_error("Failed to process credential value", "ProcessingError", detail=str(error))
    return None


def validate_credential_format(credential_data: Any) -> bool:
  """
  Check if credentials dictionary has the expected structure.

  Args:
      credential_data: The data to validate

  Returns:
      bool: True if format is valid, False otherwise
  """
  try:
    if not isinstance(credential_data, dict):
      return False

    if len(credential_data) > SecurityLimits.MAX_CREDENTIALS_PER_FILE:
      handle_credential_error(
        f"Too many credentials: maximum {SecurityLimits.MAX_CREDENTIALS_PER_FILE} allowed", "TooManyCredentials"
      )
      return False

    for service_name, creds in credential_data.items():
      if not validate_service_name(service_name):
        return False

      if not isinstance(creds, dict):
        return False

      if not {"Key", "Secret"} == set(creds.keys()):
        return False

      if any(not isinstance(v, (str, bytes)) for v in creds.values()):
        return False

      # Validate the credential pair based on service type
      if not validate_credential_pair(service_name, creds):
        return False

    return True
  except Exception:
    return False


def create_hashed_credentials(plain_credentials: PlainCredentialsDict) -> HashedCredentialsDict:
  """
  Create a hashed version of the credentials dictionary.

  Args:
      plain_credentials: Dictionary of plain text credentials

  Returns:
      HashedCredentialsDict: Dictionary of hashed credentials
  """
  hashed_creds: HashedCredentialsDict = {}

  for service_name, creds in plain_credentials.items():
    validated_name = validate_service_name(service_name)
    if not validated_name:
      continue

    key_hash = process_credential_value(creds["Key"], service_name)
    secret_hash = process_credential_value(creds["Secret"], service_name)

    if key_hash and secret_hash:
      hashed_creds[validated_name] = {"Key": key_hash, "Secret": secret_hash}

  return hashed_creds


def verify_credentials(
  input_credentials: PlainCredentialsDict, stored_credentials: HashedCredentialsDict
) -> ValidationResult:
  """
  Verify if the provided credentials match the stored hashed credentials.

  Args:
      input_credentials: Dictionary of credentials to verify
      stored_credentials: Dictionary of stored hashed credentials

  Returns:
      ValidationResult: Dictionary mapping service names to verification results
  """
  results: ValidationResult = {}

  for service_name, creds in input_credentials.items():
    validated_name = validate_service_name(service_name)
    if not validated_name or validated_name not in stored_credentials:
      results[service_name] = False
      continue

    results[service_name] = verify_credential(
      stored_credentials[validated_name]["Key"], creds["Key"], service_name
    ) and verify_credential(stored_credentials[validated_name]["Secret"], creds["Secret"], service_name)

  return results


def load_stored_credentials(file_path: str = CREDENTIALS_PATH) -> PlainCredentialsDict:
  """
  Load and validate credentials from a JSON file.

  Args:
      file_path: Path to the credentials file

  Returns:
      PlainCredentialsDict: Dictionary of loaded credentials
  """
  try:
    if not os.path.isfile(file_path):
      handle_credential_error(CredentialError.FILE_NOT_FOUND, "FileNotFound", path=file_path)
      return {}

    if not os.access(file_path, os.R_OK):
      handle_credential_error("Cannot read credentials file: permission denied", "PermissionDenied", path=file_path)
      return {}

    file_size = os.path.getsize(file_path)
    if file_size == 0:
      handle_credential_error("Credentials file is empty", "EmptyFile", path=file_path)
      return {}

    if file_size > 1024 * 1024:  # 1MB limit
      handle_credential_error("Credentials file too large", "FileTooLarge", path=file_path)
      return {}

    with open(file_path) as credentials_file:
      file_contents = json.load(credentials_file)

      if not validate_credential_format(file_contents):
        handle_credential_warning(CredentialError.INVALID_FORMAT, "InvalidFormat")
        return {}

      stored_credentials = cast(PlainCredentialsDict, file_contents)

      if DEBUG_MODE:
        safe_display = get_safe_credential_display(stored_credentials)
        display_debug(f"Stored credential keys: {list(stored_credentials.keys())}\n")

      return stored_credentials

  except json.JSONDecodeError:
    handle_credential_error(CredentialError.INVALID_JSON, "InvalidJSON")
  except Exception as error:
    handle_credential_error(
      f"Unexpected error loading credentials: {str(error)}\nPlease check file permissions and format", "UnexpectedError"
    )

  return {}


def get_user_credentials(available_services: List[ServiceName]) -> PlainCredentialsDict:
  """
  Interactively prompt the user to enter credentials for verification.

  Args:
      available_services: List of available service names

  Returns:
      PlainCredentialsDict: Dictionary containing the entered credentials
  """
  if not available_services:
    handle_credential_warning(CredentialError.NO_CREDENTIALS, "NoCredentials")
    return {}

  print(f"Available services: {', '.join(available_services)}")

  try:
    selected_service = input("Enter the service to verify: ")
    validated_service = validate_service_name(selected_service)

    if not validated_service:
      return {}

    if validated_service not in available_services:
      handle_credential_error(
        CredentialError.SERVICE_NOT_FOUND,
        "ServiceNotFound",
        service=validated_service,
        available_services=", ".join(available_services),
      )
      return {}

    # Determine credential type based on service name
    cred_type = CredentialType.BEARER if validated_service.lower() == "bearer" else CredentialType.STANDARD

    key = getpass("Enter key: ")
    if not validate_credential_string(key, "key", cred_type):
      return {}

    secret = getpass("Enter secret: ")
    if not validate_credential_string(secret, "secret", cred_type):
      return {}

    return {validated_service: {"Key": key, "Secret": secret}}

  except KeyboardInterrupt:
    handle_credential_warning(CredentialError.NO_INPUT_CREDENTIALS, "InputCancelled")
  except Exception as error:
    handle_credential_error("Unexpected error during credential input", "InputError", detail=str(error))

  return {}


def display_validation_results(validation_results: ValidationResult) -> None:
  """
  Display whether each credential is valid with color-coded output.

  Args:
      validation_results: Dictionary of validation results
  """
  if not validation_results:
    handle_credential_warning("No validation results to display", "NoResults")
    return

  for service_name, is_valid in validation_results.items():
    if is_valid:
      display_success(f"{service_name}: Login successful.")
    else:
      handle_credential_error(CredentialError.VERIFICATION_FAILED, "VerificationFailed", service=service_name)


def main() -> None:
  """Main entry point for the credential verification system."""
  try:
    clear_terminal_screen()
    display_debug_status()

    stored_credentials = load_stored_credentials()
    if not stored_credentials:
      handle_credential_error(CredentialError.NO_CREDENTIALS, "NoCredentials")
      sys.exit(1)

    hashed_credentials = create_hashed_credentials(stored_credentials)
    if not hashed_credentials:
      handle_credential_error("Failed to process stored credentials", "ProcessingError")
      sys.exit(1)

    input_credentials = {}
    if DEBUG_MODE:
      input_credentials = get_test_credentials(stored_credentials)
      display_debug("Using test credentials for debugging")
    else:
      input_credentials = get_user_credentials(list(stored_credentials.keys()))

    if not input_credentials:
      handle_credential_warning(CredentialError.NO_INPUT_CREDENTIALS, "NoInput")
      sys.exit(0)

    validation_results = verify_credentials(input_credentials, hashed_credentials)
    display_validation_results(validation_results)

  except KeyboardInterrupt:
    print("\n")  # Ensure clean line break
    handle_credential_warning("Operation cancelled by user", "UserCancelled")
    sys.exit(0)
  except Exception as error:
    handle_credential_error("Unexpected error occurred", "SystemError", detail=str(error))
    if DEBUG_MODE:
      raise  # Re-raise in debug mode for full traceback
    sys.exit(1)


if __name__ == "__main__":
  main()
