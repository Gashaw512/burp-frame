# Will handle all ADB-related functions

import os
import time
from collections import namedtuple

# Local imports from the same package
from .logger import Logger
from .utils import run_adb_command

logger = Logger()

# --- Constants ---
DEVICE_CERT_DIR = "/system/etc/security/cacerts"
MAGISK_CERT_DIR = "/data/adb/modules/system_ca_cert_mojito/system/etc/security/cacerts"

# --- ADB Command Result Named Tuple (Moved from utils.py for direct use here, or imported) ---
# Assuming AdbCommandResult is now imported from utils.py, no need to redefine here
# AdbCommandResult = namedtuple('AdbCommandResult', ['stdout', 'stderr', 'returncode'])


def check_device_connection(adb_path):
    """
    Checks if a single Android device is connected and ready.
    Args:
        adb_path (str): Path to the ADB executable.
    Returns:
        bool: True if a device is connected and ready, False otherwise.
    """
    logger.info("Checking device connection...")
    result = run_adb_command(adb_path, ["get-state"])
    if result.stdout == "device":
        logger.success("Device connected and ready.")
        return True
    
    logger.error("No device found or not ready.")
    logger.info("Troubleshooting:")
    logger.info("1. Ensure your emulator is running or device is connected via USB.")
    logger.info("2. If a physical device, enable 'USB debugging' in Developer Options.")
    logger.info("3. Check for multiple connected devices with 'adb devices'.")
    return False

def get_android_version(adb_path):
    """
    Retrieves the Android version from the connected device.
    Args:
        adb_path (str): Path to the ADB executable.
    Returns:
        str or None: The Android version string, or None if it cannot be determined.
    """
    logger.info("Detecting Android version...")
    result = run_adb_command(adb_path, ["shell", "getprop ro.build.version.release"])
    if result.returncode == 0 and result.stdout:
        version = result.stdout.strip()
        logger.info(f"Android version detected: {version}")
        return version
    else:
        logger.warn("Could not determine Android version.")
        return None

def perform_install_certificate(adb_path, cert_file, cert_hash, dry_run=False, is_magisk=False):
    """
    Handles the entire certificate installation process on the device.
    This function was previously named `install_certificate` in your `adb_client.py`.
    Renamed to avoid conflict and align with clearer flow naming.
    Args:
        adb_path (str): Path to the ADB executable.
        cert_file (str): Local path to the prepared certificate file (.0 extension).
        cert_hash (str): Subject hash of the certificate.
        dry_run (bool): If True, simulate the installation without actual changes.
        is_magisk (bool): If True, install to Magisk systemless path.
    Returns:
        bool: True if installation (or dry run) was successful, False otherwise.
    """
    if dry_run:
        logger.warn("DRY RUN: No changes will be made to the device.")

    if is_magisk:
        logger.info("Magisk mode selected. Installing certificate to systemless path.")
        result = run_adb_command(adb_path, ["shell", "test -d " + MAGISK_CERT_DIR])
        if result.returncode != 0:
            logger.error("Magisk systemless module 'system_ca_cert_mojito' not found.")
            logger.info("Please install it from Magisk's download section or a trusted source and try again.")
            return False
        remote_path = f"{MAGISK_CERT_DIR}/{cert_hash}.0"
    else:
        logger.info("Standard root mode selected.")
        remote_path = f"{DEVICE_CERT_DIR}/{cert_hash}.0"

    steps = 5
    current_step = 1
    
    logger.info("Getting root access...")
    if dry_run:
        logger.info("[DRY RUN] Would run: adb root")
    else:
        run_adb_command(adb_path, ["root"])
    logger.progress("Installation progress", current_step, steps)
    current_step += 1
    time.sleep(1) # Give ADB some time to get root

    logger.info("Remounting filesystem...")
    if dry_run:
        logger.info("[DRY RUN] Would run: adb remount")
        logger.success("Filesystem remounted as read-write (simulated)")
    else:
        result = run_adb_command(adb_path, ["remount"])
        if result.returncode != 0 or "remount succeeded" not in result.stdout.lower():
            logger.error("Failed to remount filesystem.")
            logger.error("Error: " + result.stderr)
            logger.info("This can happen if the device is not rooted or is protected by dm-verity.")
            logger.info("Try running 'adb disable-verity && adb reboot' manually before using burp-frame.")
            return False
        logger.success("Filesystem remounted as read-write")
    logger.progress("Installation progress", current_step, steps)
    current_step += 1
    
    logger.info(f"Pushing certificate to device: {remote_path}...")
    if dry_run:
        logger.info(f"[DRY RUN] Would run: adb push {cert_file} {remote_path}")
    else:
        result = run_adb_command(adb_path, ["push", cert_file, remote_path])
        if result.returncode != 0:
            logger.error("Failed to push certificate.")
            logger.error("Error: " + result.stderr)
            return False
        logger.success("Certificate pushed successfully.")
    logger.progress("Installation progress", current_step, steps)
    current_step += 1
    
    logger.info("Setting permissions...")
    if dry_run:
        logger.info(f"[DRY RUN] Would run: adb shell chmod 644 {remote_path}")
    else:
        result = run_adb_command(adb_path, ["shell", f"chmod 644 {remote_path}"])
        if result.returncode != 0:
            logger.error("Failed to set permissions.")
            logger.error("Error: " + result.stderr)
            return False
        logger.success("Permissions set to 644.")
    logger.progress("Installation progress", current_step, steps)
    current_step += 1
    
    logger.info("Rebooting device...")
    if dry_run:
        logger.info("[DRY RUN] Would run: adb reboot")
        logger.success("Device rebooting (simulated)")
        logger.info("You can now connect to your device after it reboots.")
    else:
        run_adb_command(adb_path, ["reboot"])
        logger.info("Device rebooting. Please wait...")
        # Wait for device to come back online
        run_adb_command(adb_path, ["wait-for-device"]) 
        logger.success("Device reconnected after reboot.")
    logger.progress("Installation progress", current_step, steps)
    
    return True

def configure_proxy(adb_path, host=None, port=None, revert=False):
    """
    Configures or reverts the global HTTP proxy settings on the Android device.
    Args:
        adb_path (str): Path to the ADB executable.
        host (str, optional): The proxy host IP address. Required if revert is False.
        port (str, optional): The proxy port. Defaults to '8080'.
        revert (bool): If True, reverts proxy settings to default.
    Returns:
        bool: True if proxy configuration was successful, False otherwise.
    """
    if revert:
        command = ["shell", "settings", "put", "global", "http_proxy", ":0"]
        description = "reverting global HTTP proxy"
    elif host:
        proxy_string = f"{host}:{port or '8080'}"
        command = ["shell", "settings", "put", "global", "http_proxy", proxy_string]
        description = f"setting global HTTP proxy to {proxy_string}"
    else:
        logger.error("Invalid proxy command. Must specify --set HOST:PORT or --revert.")
        return False

    logger.info(f"Attempting {description}...")
    result = run_adb_command(adb_path, command)

    if result.returncode == 0:
        logger.success(f"Successfully {description}.")
        return True
    else:
        logger.error(f"Failed to {description}.")
        logger.error(f"Error: {result.stderr}")
        return False

def get_current_proxy_settings(adb_path):
    """
    Retrieves the current global HTTP proxy settings from the Android device.
    Args:
        adb_path (str): Path to the ADB executable.
    Returns:
        str or None: The current proxy string (e.g., "HOST:PORT") or None if not set/error.
    """
    logger.info("Retrieving current proxy settings...")
    result = run_adb_command(adb_path, ["shell", "settings", "get", "global", "http_proxy"])
    
    if result.returncode == 0 and result.stdout:
        proxy_setting = result.stdout.strip()
        if proxy_setting and proxy_setting != ":0": # :0 means no proxy in settings
            logger.info(f"Current device proxy: {proxy_setting}")
            return proxy_setting
        else:
            logger.info("No global HTTP proxy is currently set on the device.")
            return None
    else:
        logger.error(f"Failed to retrieve current proxy settings. Error: {result.stderr}")
        return None
