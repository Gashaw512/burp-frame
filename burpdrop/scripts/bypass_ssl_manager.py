# bypass_ssl_manager.py
"""
Bypass SSL manager — list, download, and apply Frida SSL bypass scripts.

Behavior:
 - list_bypass_scripts(): list .js files in the scripts directory (creates dir if missing).
 - download_generic_bypass_script(overwrite=False): download a known generic bypass script.
 - apply_bypass_script(package_name, script_filename, launch_app=True):
      applies script by calling functions from frida_manager (launch or attach).
 - ensure_generic_script_available(): helper to auto-download when no scripts exist.
"""

from __future__ import annotations

import os
import sys
from typing import List

# Prefer requests but handle if not installed
try:
    import requests
except ImportError:
    requests = None  # We'll inform the user if a download is attempted without requests

from .logger import Logger
from .utils import get_tool_path

try:
    from .frida_manager import run_frida_script, launch_application_with_script, verify_frida_server
except ImportError:
    run_frida_script = None
    launch_application_with_script = None
    verify_frida_server = None

logger = Logger()

# --- Constants & paths ---
SCRIPTS_BASE_DIR = os.path.abspath(
    os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "frida_scripts", "bypass")
    )
)
os.makedirs(SCRIPTS_BASE_DIR, exist_ok=True)

GENERIC_BYPASS_SCRIPT_URL = "https://github.com/0xCD4/SSL-bypass"
GENERIC_BYPASS_SCRIPT_RAW_URL = "https://github.com/0xCD4/SSL-bypass/blob/main/root_bypass.js?raw=true"
GENERIC_BYPASS_SCRIPT_FILENAME = "universal_bypass.js"


# --- Helpers ---

def _is_interactive() -> bool:
    """Return True if running in a TTY (safe to prompt)."""
    return sys.stdin.isatty() and sys.stdout.isatty()

def _local_script_path(filename: str) -> str:
    """Return full absolute path for a script filename in the bypass scripts directory."""
    return os.path.join(SCRIPTS_BASE_DIR, filename)


# --- Public API ---

def list_bypass_scripts() -> List[str]:
    """
    List all .js bypass scripts available in the scripts directory.

    Returns:
        List[str]: Sorted list of script filenames.
    """
    logger.info(f"Scanning for SSL bypass scripts in: {SCRIPTS_BASE_DIR}")
    try:
        files = [
            f for f in os.listdir(SCRIPTS_BASE_DIR)
            if f.endswith(".js") and os.path.isfile(_local_script_path(f))
        ]
    except Exception as e:
        logger.error(f"Failed to list scripts directory: {e}")
        return []

    if not files:
        logger.info("No .js SSL bypass scripts found in the directory.")
        logger.info("You can download a generic one using 'burp-frame bypass-ssl download'.")
        return []

    logger.info("Available SSL bypass scripts:")
    for f in sorted(files):
        logger.info(f"  - {f}")

    return sorted(files)


def download_generic_bypass_script(overwrite: bool = False, timeout: int = 15) -> bool:
    """
    Download the generic universal SSL bypass script.

    Args:
        overwrite (bool): Whether to overwrite if the script file already exists.
        timeout (int): HTTP request timeout in seconds.

    Returns:
        bool: True if download succeeded, False otherwise.
    """
    local_path = _local_script_path(GENERIC_BYPASS_SCRIPT_FILENAME)

    logger.info(f"Preparing to download generic SSL bypass script: {GENERIC_BYPASS_SCRIPT_FILENAME}")
    logger.warn("DISCLAIMER: This downloads code from a public source. Review the script before use.")
    logger.info(f"Source repository: {GENERIC_BYPASS_SCRIPT_URL}")

    if requests is None:
        logger.error("Python package 'requests' is not available. Install it (pip install requests) to enable downloads.")
        return False

    if os.path.exists(local_path) and not overwrite:
        if _is_interactive():
            choice = input(f"Script already exists at {local_path}. Overwrite? (y/N): ").strip().lower()
            if choice != 'y':
                logger.info("Download aborted by user.")
                return False
        else:
            logger.warn(f"Script already exists at {local_path} and overwrite=False. Skipping download.")
            return False

    try:
        logger.info(f"Downloading from raw URL: {GENERIC_BYPASS_SCRIPT_RAW_URL}")
        response = requests.get(GENERIC_BYPASS_SCRIPT_RAW_URL, timeout=timeout)
        response.raise_for_status()

        with open(local_path, "wb") as fh:
            fh.write(response.content)

        logger.success(f"Downloaded '{GENERIC_BYPASS_SCRIPT_FILENAME}' -> {local_path}")
        logger.info("IMPORTANT: Review the downloaded script before applying it to any device.")
        return True

    except requests.exceptions.RequestException as re:
        logger.error(f"HTTP download failed: {re}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error saving script: {e}")
        return False


def ensure_generic_script_available() -> List[str]:
    """
    Ensure at least one bypass script is available locally.
    Attempts to auto-download the generic script if none found.

    Returns:
        List[str]: List of available scripts after ensuring.
    """
    scripts = list_bypass_scripts()
    if scripts:
        return scripts

    logger.info("No bypass scripts found locally — attempting to download the generic script.")
    if not download_generic_bypass_script():
        logger.error("Failed to obtain generic bypass script automatically.")
        return []

    return list_bypass_scripts()


def apply_bypass_script(package_name: str, script_filename: str, launch_app: bool = True) -> bool:
    """
    Apply a bypass script to a running or launching app via Frida.

    Args:
        package_name (str): Android app package name to target.
        script_filename (str): Filename of the bypass script to apply.
        launch_app (bool): If True, launch the app with the script; otherwise attach to running.

    Returns:
        bool: True on success, False otherwise.
    """
    script_path = _local_script_path(script_filename)

    if not os.path.exists(script_path):
        logger.warn(f"Bypass script '{script_filename}' not found at: {script_path}")

        if script_filename == GENERIC_BYPASS_SCRIPT_FILENAME:
            logger.info("Attempting to download the generic bypass script automatically...")
            if not download_generic_bypass_script():
                logger.error("Could not download generic bypass script.")
                return False
            script_path = _local_script_path(script_filename)
            if not os.path.exists(script_path):
                logger.error("Script still missing after attempted download.")
                return False
        else:
            available = ensure_generic_script_available()
            if available:
                logger.info("Available scripts were downloaded/located. You can re-run with one of these filenames.")
            return False

    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB not found in PATH. Please configure ADB before applying bypass scripts.")
        return False

    # Import device_manager.check_device_connection at runtime to avoid circular import
    try:
        from .device_manager import check_device_connection
    except ImportError:
        check_device_connection = None

    if check_device_connection:
        if not check_device_connection(adb_path):
            logger.error("No connected Android device detected or device not ready.")
            return False
    else:
        logger.warn("device_manager.check_device_connection not available — skipping device connection check.")

    if verify_frida_server is not None:
        try:
            if not verify_frida_server():
                logger.warn("Frida server does not appear to be running. Please deploy/start Frida server first.")
                return False
        except Exception as e:
            logger.warn(f"Error while verifying Frida server: {e}. Proceeding anyway.")

    if launch_app and launch_application_with_script is None:
        logger.error("Frida launch helper (launch_application_with_script) is not available in frida_manager.")
        return False

    if not launch_app and run_frida_script is None:
        logger.error("Frida attach helper (run_frida_script) is not available in frida_manager.")
        return False

    logger.info(f"Applying SSL bypass script '{script_filename}' to '{package_name}' (launch_app={launch_app})...")

    try:
        if launch_app:
            success = launch_application_with_script(package_name, script_path)
        else:
            success = run_frida_script(script_path, package_name)

        if success:
            logger.success(f"Script '{script_filename}' applied successfully to '{package_name}'.")
            logger.info("Keep this terminal open while Frida is attached to keep the hook active.")
            return True
        else:
            logger.error(f"Frida reported failure while applying '{script_filename}' to '{package_name}'.")
            return False

    except Exception as e:
        logger.error(f"Exception while applying bypass script: {e}")
        return False
