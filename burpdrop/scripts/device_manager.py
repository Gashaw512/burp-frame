import time
import re # Already imported, just re-iterating for clarity
import os # For os.path.basename in install_apk and others

from .logger import Logger
# No explicit import of config or get_tool_path from utils as they are passed directly
from .utils import run_adb_command, get_tool_path # Import get_tool_path and run_adb_command from utils

logger = Logger()

# --- Constants ---
# These are moved to device_manager as they are directly used by perform_install_certificate within this module.
DEVICE_CERT_DIR = "/system/etc/security/cacerts"
MAGISK_CERT_DIR = "/data/adb/modules/system_ca_cert_mojito/system/etc/security/cacerts"


def check_device_connection(adb_path):
    """
    Checks if an Android device is connected via ADB and ready.
    
    Args:
        adb_path (str): Path to the ADB executable.
        
    Returns:
        bool: True if a device is connected and ready, False otherwise.
    """
    logger.info("Checking device connection...")
    result = run_adb_command(adb_path, ["get-state"])
    
    # 'adb get-state' output is usually "device", "offline", "unknown"
    if result.returncode == 0 and "device" in result.stdout.strip():
        logger.success("✓ Device connected and ready.")
        return True
    else:
        logger.error(f"❌ No device detected or device is not ready. ADB output: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"ADB stderr: {result.stderr.strip()}")
        logger.info("Please ensure your device is connected, ADB debugging is enabled, and drivers are installed.")
        logger.info("For remote devices, ensure 'adb tcpip' is enabled on the device and firewall allows connection.")
        return False

def get_android_version(adb_path):
    """
    Detects the Android version of the connected device.
    
    Args:
        adb_path (str): Path to the ADB executable.
        
    Returns:
        str or None: The Android version (e.g., "11", "12"), or None on failure.
    """
    logger.info("Detecting Android version...")
    # Using 'getprop ro.build.version.release' is robust for most Android versions
    result = run_adb_command(adb_path, ["shell", "getprop", "ro.build.version.release"])
    if result.returncode == 0 and result.stdout:
        version = result.stdout.strip()
        logger.info(f"Android version detected: {version}")
        return version
    else:
        logger.error(f"Failed to detect Android version. ADB stderr: {result.stderr}")
        return None

def perform_install_certificate(adb_path, cert_prepared_file, cert_hash, dry_run=False, use_magisk=False):
    """
    Installs the prepared CA certificate onto the Android device.
    This function handles both standard system installation (requires root and remount)
    and Magisk systemless installation.
    
    Args:
        adb_path (str): Path to the ADB executable.
        cert_prepared_file (str): Local path to the prepared certificate file (e.g., 9a4a7530.0).
        cert_hash (str): The hash of the certificate (used for Magisk module name and file naming).
        dry_run (bool): If True, simulates the installation steps without executing them.
        use_magisk (bool): If True, installs the certificate as a Magisk systemless module.
        
    Returns:
        bool: True if installation was successful (or dry run), False otherwise.
    """
    logger.info("Initiating certificate installation on device...")

    if dry_run:
        logger.info("[DRY RUN] Simulating certificate installation...")

    if use_magisk:
        logger.info("Attempting Magisk systemless installation...")
        # Define paths for the Magisk module
        remote_magisk_module_dir = f"/data/adb/modules/burp_ca_cert_{cert_hash}"
        remote_cert_path_in_module = f"{remote_magisk_module_dir}/system/etc/security/cacerts/{cert_hash}.0"
        
        if dry_run:
            logger.info(f"[DRY RUN] Would create Magisk module directory: {remote_magisk_module_dir}")
            logger.info(f"[DRY RUN] Would push certificate to: {remote_cert_path_in_module}")
            logger.info("[DRY RUN] Would create module.prop and post-fs-data.sh.")
            return True

        # Pre-check for Magisk/Root access. A simple 'su -c echo' is a good indicator.
        logger.info("Checking for Magisk/Root access...")
        su_test_result = run_adb_command(adb_path, ["shell", "su", "-c", "echo 'root_ok'"])
        if su_test_result.returncode != 0 or "root_ok" not in su_test_result.stdout:
            logger.error("Magisk/Root access not detected or not granted. Cannot proceed with Magisk installation.")
            logger.info("Please ensure Magisk is installed, enabled, and ADB has root permissions (via 'adb root' or Magisk prompts).")
            return False
        logger.success("Magisk/Root access detected.")

        # Create module directory structure on the device
        logger.info(f"Creating Magisk module directory: {remote_magisk_module_dir}...")
        # Need to use 'su -c' because /data/adb is usually not directly writable by adb push
        result = run_adb_command(adb_path, ["shell", "su", "-c", f"mkdir -p {remote_magisk_module_dir}/system/etc/security/cacerts"])
        if result.returncode != 0:
            logger.error(f"Failed to create Magisk module directory. ADB stderr: {result.stderr}")
            return False
        logger.success("Magisk module directory created.")

        # Push certificate to a temporary location first, then move it with root
        logger.info(f"Pushing certificate to Magisk module: {remote_cert_path_in_module}...")
        temp_remote_cert_path = f"/sdcard/{os.path.basename(cert_prepared_file)}"
        result = run_adb_command(adb_path, ["push", cert_prepared_file, temp_remote_cert_path])
        if result.returncode != 0:
            logger.error(f"Failed to push certificate to temporary location. ADB stderr: {result.stderr}")
            return False
        
        # Move the certificate from temp to final Magisk module path with root permissions
        move_cmd = f"su -c 'mv {temp_remote_cert_path} {remote_cert_path_in_module}'"
        result = run_adb_command(adb_path, ["shell", move_cmd])
        if result.returncode != 0:
            logger.error(f"Failed to move certificate to Magisk module path. ADB stderr: {result.stderr}")
            run_adb_command(adb_path, ["shell", f"rm {temp_remote_cert_path}"]) # Attempt to clean up temp file
            return False
        logger.success("Certificate pushed and moved into Magisk module.")

        # Create module.prop file for Magisk module identification
        module_prop_content = f"""id=burp_ca_cert_{cert_hash}
name=Burp Suite CA Certificate
version=v1.0
versionCode=1
author=Burp-Frame
description=Systemless installation of Burp Suite CA certificate for traffic interception.
"""
        # Create locally, push, then delete local copy
        temp_module_prop_path = os.path.join(os.path.dirname(cert_prepared_file), "module.prop")
        with open(temp_module_prop_path, "w") as f:
            f.write(module_prop_content)
        
        result = run_adb_command(adb_path, ["push", temp_module_prop_path, f"{remote_magisk_module_dir}/module.prop"])
        if result.returncode != 0:
            logger.error(f"Failed to push module.prop. ADB stderr: {result.stderr}")
            os.remove(temp_module_prop_path)
            return False
        logger.success("module.prop created.")
        os.remove(temp_module_prop_path) # Clean up local temp file

        # Create post-fs-data.sh (minimal, might be empty if no specific boot scripts needed)
        # Magisk generally handles symlinking, so post-fs-data.sh might not be strictly needed for a simple CA.
        post_fs_data_content = f"""#!/system/bin/sh
# This script is executed in post-fs-data mode by Magisk.
# No special commands are typically needed here for a simple CA cert module
# as Magisk handles the bind mounts to /system/etc/security/cacerts automatically.
"""
        temp_post_fs_data_path = os.path.join(os.path.dirname(cert_prepared_file), "post-fs-data.sh")
        with open(temp_post_fs_data_path, "w") as f:
            f.write(post_fs_data_content)
        
        result = run_adb_command(adb_path, ["push", temp_post_fs_data_path, f"{remote_magisk_module_dir}/post-fs-data.sh"])
        if result.returncode != 0:
            logger.error(f"Failed to push post-fs-data.sh. ADB stderr: {result.stderr}")
            os.remove(temp_post_fs_data_path)
            return False
        
        # Set executable permissions for the script
        result = run_adb_command(adb_path, ["shell", "su", "-c", f"chmod 755 {remote_magisk_module_dir}/post-fs-data.sh"])
        if result.returncode != 0:
            logger.error(f"Failed to set permissions for post-fs-data.sh. ADB stderr: {result.stderr}")
            os.remove(temp_post_fs_data_path)
            return False

        logger.success("post-fs-data.sh created and permissions set.")
        os.remove(temp_post_fs_data_path) # Clean up local temp file

        logger.info("Magisk module created. A device reboot might be required for the module to activate.")
        return True

    else: # Standard (non-Magisk) system installation path
        logger.info("Attempting standard system certificate installation (requires root and system remount).")
        remote_cert_path = f"{DEVICE_CERT_DIR}/{cert_hash}.0"
        
        if dry_run:
            logger.info(f"[DRY RUN] Would push certificate to: {remote_cert_path}")
            logger.info("[DRY RUN] Would remount /system as read-write, push, then remount read-only.")
            return True

        # Remount /system as RW
        # The internal remount_system_rw handles its own logging and root check implicitly via adb remount.
        if not remount_system_rw(adb_path):
            logger.error("Failed to remount /system as read-write. Cannot install certificate to system partition.")
            logger.info("Ensure device is rooted and ADB has root permissions (`adb root`).")
            return False
        logger.success("/system remounted as read-write.")

        # Push certificate to /system/etc/security/cacerts/
        logger.info(f"Pushing certificate to {remote_cert_path}...")
        # Push to a temporary location first, then move with root permissions
        temp_remote_cert_path = f"/data/local/tmp/{os.path.basename(cert_prepared_file)}"
        result = run_adb_command(adb_path, ["push", cert_prepared_file, temp_remote_cert_path])
        if result.returncode != 0:
            logger.error(f"Failed to push certificate to temporary location. ADB stderr: {result.stderr}")
            return False
        
        # Move the certificate from temp to final system path with root permissions
        move_cmd = f"su -c 'mv {temp_remote_cert_path} {remote_cert_path}'"
        result = run_adb_command(adb_path, ["shell", move_cmd])
        if result.returncode != 0:
            logger.error(f"Failed to move certificate to system path. ADB stderr: {result.stderr}")
            run_adb_command(adb_path, ["shell", f"rm {temp_remote_cert_path}"]) # Clean up temp
            return False
        
        # Set correct permissions for the certificate file
        chmod_cmd = f"su -c 'chmod 644 {remote_cert_path}'"
        result = run_adb_command(adb_path, ["shell", chmod_cmd])
        if result.returncode != 0:
            logger.error(f"Failed to set permissions for certificate. ADB stderr: {result.stderr}")
            return False
        logger.success("Certificate pushed and permissions set.")

        # Remount /system as RO for security
        if not remount_system_ro(adb_path):
            logger.error("Failed to remount /system as read-only. Device may be left insecure.")
            # Still return True if cert push succeeded, but warn user about security implications
            return True
        logger.success("/system remounted as read-only.")
        logger.info("Certificate installed. A device reboot might be required to apply changes.")
        return True
    
    return False # Should not be reached in normal flow

# --- Core Device Management Functions ---

def reboot_device():
    """
    Reboots the connected Android device.
    
    Returns:
        bool: True if the reboot command was successfully sent, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot reboot device.")
        return False
    
    logger.info("Attempting to reboot the Android device...")
    # 'adb reboot' command sends the reboot signal and exits quickly.
    # It doesn't wait for the device to fully reboot, so a subsequent wait-for-device is good.
    result = run_adb_command(adb_path, ["reboot"])

    if result.returncode == 0:
        logger.success("Reboot command sent successfully. Device should be rebooting now.")
        logger.info("Please wait for the device to restart and reconnect via ADB (this may take a minute or two).")
        # Optional: Add a wait-for-device if calling this in sequence with other commands
        # run_adb_command(adb_path, ["wait-for-device"]) # This would block
        return True
    else:
        logger.error(f"Failed to send reboot command. ADB stderr: {result.stderr}")
        return False

def remount_system_rw(adb_path):
    """
    Remounts the /system partition of the Android device as read-write.
    Requires root access.
    
    Args:
        adb_path (str): Path to the ADB executable.
        
    Returns:
        bool: True if remount was successful, False otherwise.
    """
    logger.info("Attempting to remount /system partition as read-write...")
    # 'adb remount' is a convenience command that internally tries to do 'su -c mount -o rw,remount /system'
    result = run_adb_command(adb_path, ["remount"])

    if result.returncode == 0:
        logger.success("✓ /system remounted as read-write.")
        return True
    else:
        logger.error(f"❌ Failed to remount /system as read-write. ADB stderr: {result.stderr}")
        logger.info("Ensure device is rooted and ADB has root permissions (`adb root` might be needed first).")
        return False

def remount_system_ro(adb_path):
    """
    Remounts the /system partition of the Android device as read-only.
    Requires root access.
    
    Args:
        adb_path (str): Path to the ADB executable.
        
    Returns:
        bool: True if remount was successful, False otherwise.
    """
    logger.info("Attempting to remount /system partition as read-only...")
    # Explicitly use 'su -c mount -o ro,remount /system' for read-only remount
    result = run_adb_command(adb_path, ["shell", "su", "-c", "mount -o ro,remount /system"])

    if result.returncode == 0:
        logger.success("✓ /system remounted as read-only.")
        return True
    else:
        logger.error(f"❌ Failed to remount /system as read-only. ADB stderr: {result.stderr}")
        logger.info("Manual remount to read-only might be required for security. You can try 'adb shell su -c \"mount -o ro,remount /system\"'.")
        return False

def list_adb_connected_devices():
    """
    Lists all connected Android devices recognized by ADB, along with their status and properties.
    
    Returns:
        list of dict: A list of dictionaries, each containing 'serial', 'state', 'model', and 'product'.
                      Returns an empty list if no devices found or an error occurs.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot list devices.")
        return []

    logger.info("Listing ADB connected devices...")
    # 'adb devices -l' provides a long listing including product, model, and device names.
    result = run_adb_command(adb_path, ["devices", "-l"])

    devices = []
    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().splitlines()
        # Skip the first line which is typically "List of devices attached"
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2: # At least serial and state must be present
                    serial = parts[0]
                    state = parts[1]
                    model = "N/A"
                    product = "N/A"

                    # Parse 'product:', 'model:', 'device:' from the rest of the line
                    # Using regex to robustly find these key-value pairs
                    remaining_info = " ".join(parts[2:])
                    model_match = re.search(r"model:(\S+)", remaining_info)
                    if model_match:
                        model = model_match.group(1)
                    product_match = re.search(r"product:(\S+)", remaining_info)
                    if product_match:
                        product = product_match.group(1)

                    devices.append({'serial': serial, 'state': state, 'model': model, 'product': product})
                else:
                    logger.warn(f"Skipping malformed device line (less than 2 parts): {line.strip()}")
        
        if devices:
            logger.info(f"Found {len(devices)} connected ADB device(s):")
            for dev in devices:
                logger.info(f"  - Serial: {dev['serial']}, State: {dev['state']}, Model: {dev['model']} (Product: {dev['product']})")
        else:
            logger.info("No ADB devices found.")
        return devices
    else:
        logger.error(f"Failed to list ADB devices. ADB stderr: {result.stderr}")
        return []

def install_apk(apk_path):
    """
    Installs an APK file onto the connected Android device.
    
    Args:
        apk_path (str): Local path to the APK file.
        
    Returns:
        bool: True if installation was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot install APK.")
        return False
    
    if not os.path.exists(apk_path):
        logger.error(f"APK file not found at: {apk_path}")
        return False

    logger.info(f"Installing APK: {apk_path}...")
    # 'adb install' command handles pushing and installing.
    result = run_adb_command(adb_path, ["install", apk_path])

    # ADB install outputs "Success" to stdout on success, errors to stderr or stdout
    if result.returncode == 0 and "Success" in result.stdout:
        logger.success(f"Successfully installed {os.path.basename(apk_path)}.")
        return True
    else:
        logger.error(f"Failed to install APK. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"ADB stderr: {result.stderr.strip()}")
        logger.info("Common issues: APK corrupted, insufficient storage, incompatible ABI, or app already installed with different signature.")
        return False

def uninstall_package(package_name):
    """
    Uninstalls an application package from the connected Android device.
    
    Args:
        package_name (str): The package name of the application to uninstall (e.g., "com.example.app").
        
    Returns:
        bool: True if uninstallation was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot uninstall package.")
        return False
    
    logger.info(f"Uninstalling package: {package_name}...")
    # 'adb uninstall' command
    result = run_adb_command(adb_path, ["uninstall", package_name])

    # ADB uninstall can output success to stderr or stdout sometimes depending on Android version/ADB version
    if result.returncode == 0 and ("Success" in result.stdout or "Success" in result.stderr):
        logger.success(f"Successfully uninstalled package: {package_name}.")
        return True
    else:
        logger.error(f"Failed to uninstall package: {package_name}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"ADB stderr: {result.stderr.strip()}")
        logger.info("Common issues: Package not found, or insufficient permissions.")
        return False

def connect_adb_device(ip_address, port="5555"):
    """
    Connects to an Android device over TCP/IP using ADB.
    
    Args:
        ip_address (str): The IP address of the target device.
        port (str): The port for ADB connection, defaults to "5555".
        
    Returns:
        bool: True if connection was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot connect to remote device.")
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to connect to ADB device at {target}...")
    
    # 'adb connect' command
    result = run_adb_command(adb_path, ["connect", target])

    # Check for success message in stdout (e.g., "connected to 192.168.1.10:5555")
    if result.returncode == 0 and "connected to" in result.stdout:
        logger.success(f"Successfully connected to device at {target}.")
        logger.info("Ensure ADB debugging over network is enabled on the device (usually by running 'adb tcpip 5555' from a USB-connected session first).")
        return True
    else:
        logger.error(f"Failed to connect to device at {target}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"ADB stderr: {result.stderr.strip()}")
        logger.info("Possible issues: Device not listening on ADB TCP (run 'adb tcpip 5555' on device), wrong IP/port, or firewall blocking connection.")
        return False

def disconnect_adb_device(ip_address, port="5555"):
    """
    Disconnects from a remote Android device connected over TCP/IP using ADB.
    
    Args:
        ip_address (str): The IP address of the target device to disconnect from.
        port (str): The port for ADB connection, defaults to "5555".
        
    Returns:
        bool: True if disconnection was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot disconnect from remote device.")
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to disconnect from ADB device at {target}...")
    
    # 'adb disconnect' command
    result = run_adb_command(adb_path, ["disconnect", target])

    # Check for success (e.g., "disconnected 192.168.1.10:5555" or "no such device 192.168.1.10:5555" if it was already not connected)
    if result.returncode == 0 and ("disconnected" in result.stdout or "no such device" in result.stdout):
        logger.success(f"Successfully disconnected from device at {target}.")
        return True
    else:
        logger.error(f"Failed to disconnect from device at {target}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"ADB stderr: {result.stderr.strip()}")
        return False
