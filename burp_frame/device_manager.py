# burp_frame/device_manager.py

import time
import re
import os
import shlex
import shutil

from .logger import Logger
# Import the central command runner and tool path finder
from .utils import get_tool_path, run_command

logger = Logger()

# --- Constants ---
# These are moved to a more appropriate scope within the module or are handled dynamically.
DEVICE_CERT_DIR = "/system/etc/security/cacerts"

# --- Device Status & Information Functions ---

def check_device_connection():
    """
    Checks if an Android device is connected via ADB and ready.
    
    Returns:
        bool: True if a device is connected and ready, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False

    logger.info("Checking device connection...")
    result = run_command([adb_path, "get-state"])
    
    if result.returncode == 0 and "device" in result.stdout:
        logger.success("✓ Device connected and ready.")
        return True
    else:
        logger.error(f"❌ No device detected or device is not ready. ADB output: {result.stdout}")
        logger.info("Please ensure your device is connected, ADB debugging is enabled, and drivers are installed.")
        return False

def get_android_version():
    """
    Detects the Android version of the connected device.
    
    Returns:
        str or None: The Android version (e.g., "11", "12"), or None on failure.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return None

    logger.info("Detecting Android version...")
    result = run_command([adb_path, "shell", "getprop", "ro.build.version.release"])
    if result.returncode == 0 and result.stdout:
        version = result.stdout.strip()
        logger.info(f"Android version detected: {version}")
        return version
    else:
        logger.error(f"Failed to detect Android version. ADB stderr: {result.stderr}")
        return None

# --- Certificate Installation & Management Functions ---

def perform_install_certificate(cert_prepared_file, cert_hash, dry_run=False, use_magisk=False):
    """
    Installs the prepared CA certificate onto the Android device.
    This function handles both standard system installation (requires root and remount)
    and Magisk systemless installation.
    
    Args:
        cert_prepared_file (str): Local path to the prepared certificate file.
        cert_hash (str): The hash of the certificate.
        dry_run (bool): If True, simulates the installation steps.
        use_magisk (bool): If True, installs the certificate as a Magisk module.
        
    Returns:
        bool: True if installation was successful (or dry run), False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False

    logger.info("Initiating certificate installation on device...")

    if dry_run:
        logger.info("[DRY RUN] Simulating certificate installation...")
        return True

    if use_magisk:
        return _install_with_magisk(adb_path, cert_prepared_file, cert_hash)
    else:
        return _install_to_system(adb_path, cert_prepared_file, cert_hash)

def _install_to_system(adb_path, cert_prepared_file, cert_hash):
    """
    Performs the standard system certificate installation.
    """
    logger.info("Attempting standard system certificate installation (requires root and system remount).")
    
    # 1. Remount /system as read-write
    if not remount_system_rw():
        logger.error("Failed to remount /system as read-write. Cannot install certificate.")
        return False
    
    # 2. Push certificate to a temporary location
    temp_remote_cert_path = f"/data/local/tmp/{os.path.basename(cert_prepared_file)}"
    logger.info(f"Pushing certificate to temporary path: {temp_remote_cert_path}...")
    result = run_command([adb_path, "push", cert_prepared_file, temp_remote_cert_path])
    if result.returncode != 0:
        logger.error(f"Failed to push certificate. ADB stderr: {result.stderr}")
        return False
    
    # 3. Move the certificate to the final system path with root permissions
    remote_cert_path = f"{DEVICE_CERT_DIR}/{cert_hash}.0"
    move_cmd = shlex.quote(f"mv {temp_remote_cert_path} {remote_cert_path}")
    logger.info(f"Moving certificate to final path: {remote_cert_path}...")
    result = run_command([adb_path, "shell", "su", "-c", move_cmd])
    if result.returncode != 0:
        logger.error(f"Failed to move certificate. ADB stderr: {result.stderr}")
        run_command([adb_path, "shell", "rm", temp_remote_cert_path]) # Clean up temp
        return False
    
    # 4. Set correct permissions
    chmod_cmd = shlex.quote(f"chmod 644 {remote_cert_path}")
    logger.info("Setting correct permissions...")
    result = run_command([adb_path, "shell", "su", "-c", chmod_cmd])
    if result.returncode != 0:
        logger.error(f"Failed to set permissions. ADB stderr: {result.stderr}")
        return False
    
    logger.success("✓ Certificate pushed and permissions set.")
    
    # 5. Remount /system as read-only for security
    if not remount_system_ro():
        logger.warn("⚠️ Failed to remount /system as read-only. Device may be left insecure.")
        return True # The certificate is installed, so we continue, but warn the user
    
    logger.success("✓ /system remounted as read-only.")
    logger.info("Certificate installed. A device reboot may be required to apply changes.")
    return True


def _install_with_magisk(adb_path,cert_prepared_file, cert_hash):
    """
    Performs the systemless Magisk certificate installation.

    This function automates the process of creating a Magisk module, pushing it
    to the device, and installing it with root permissions. It first checks for
    Magisk's presence and attempts to gain root access via ADB.

    Args:
        cert_prepared_file (str): Local path to the prepared certificate file (e.g., 9a4a7530.0).
        cert_hash (str): The hash of the certificate.

    Returns:
        bool: True if installation was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False

    logger.info("Attempting Magisk systemless installation...")

    # Step 1: Check for Magisk's presence by looking for its package name.
    logger.info("Checking for Magisk app...")
    result = run_command([adb_path, "shell", "pm", "list", "packages", "com.topjohnwu.magisk"])
    if "com.topjohnwu.magisk" not in result.stdout:
        logger.error("❌ Magisk app not found on the device. Cannot proceed.")
        logger.info("To use this feature, your device must be rooted with Magisk.")
        return False
    logger.success("✓ Magisk app detected.")

    # Step 2: Ensure ADB has root permissions.
    logger.info("Requesting ADB root privileges...")
    adb_root_check = run_command([adb_path, "root"])
    if "restarting adbd as root" in adb_root_check.stdout:
        logger.info("ADB daemon is restarting with root permissions. Waiting for device to reconnect...")
        time.sleep(3) # Wait for the daemon to restart
        if not check_device_connection(adb_path):
            logger.error("❌ Failed to reconnect after 'adb root'.")
            return False

    # Step 3: Verify 'su' access.
    logger.info("Verifying 'su' permissions...")
    su_check = run_command([adb_path, "shell", "su", "-c", "id -u"])
    if su_check.returncode != 0 or su_check.stdout.strip() != "0":
        logger.error("❌ Root access denied by 'su' command. Cannot proceed with Magisk installation.")
        logger.info("Please accept the root access prompt on your device if it appears.")
        return False
    logger.success("✓ Root access verified.")

    # Step 4: Prepare the Magisk module locally.
    magisk_module_id = f"burp_ca_cert_{cert_hash}"
    local_temp_module_dir = os.path.join(tempfile.gettempdir(), magisk_module_id)
    
    try:
        cert_module_path = os.path.join(local_temp_module_dir, "system", "etc", "security", "cacerts")
        os.makedirs(cert_module_path, exist_ok=True)
        shutil.copy(cert_prepared_file, cert_module_path)

        module_prop_content = f"""id={magisk_module_id}
name=Burp Suite CA Certificate
version=v1.0
versionCode=1
author=Burp-Frame
description=Systemless installation of Burp Suite CA certificate.
"""
        with open(os.path.join(local_temp_module_dir, "module.prop"), "w") as f:
            f.write(module_prop_content)

    except Exception as e:
        logger.error(f"❌ Failed to prepare local Magisk module files: {e}")
        return False

    # Step 5: Push and install the module.
    remote_temp_module_path = f"/data/local/tmp/{magisk_module_id}"
    remote_final_module_path = f"/data/adb/modules/{magisk_module_id}"

    logger.info(f"Pushing Magisk module to temporary location: {remote_temp_module_path}...")
    push_result = run_command([adb_path, "push", local_temp_module_dir, "/data/local/tmp/"])
    if push_result.returncode != 0:
        logger.error(f"❌ Failed to push Magisk module. ADB stderr: {push_result.stderr}")
        return False
    
    logger.info(f"Moving module from temporary to final location: {remote_final_module_path}...")
    move_command = shlex.quote(f"mv {remote_temp_module_path} {remote_final_module_path}")
    move_result = run_command([adb_path, "shell", "su", "-c", move_command])

    if move_result.returncode != 0:
        logger.error(f"❌ Failed to move Magisk module. ADB stderr: {move_result.stderr}")
        return False

    # Step 6: Clean up local temporary files.
    try:
        shutil.rmtree(local_temp_module_dir)
    except Exception as e:
        logger.warning(f"⚠️ Failed to clean up local temp directory: {e}")

    logger.success("✓ Magisk module created and installed.")
    logger.info("A device reboot is required for the module to activate. Please reboot the device now.")
    return True





# ... (General Device Commands) ...

def reboot_device():
    """Reboots the connected Android device."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
    
    logger.info("Attempting to reboot the Android device...")
    result = run_command([adb_path, "reboot"])
    
    if result.returncode == 0:
        logger.success("✓ Reboot command sent. Device should be rebooting now.")
        return True
    else:
        logger.error(f"❌ Failed to send reboot command. ADB stderr: {result.stderr}")
        return False

def remount_system_rw():
    """Remounts the /system partition as read-write."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False

    logger.info("Attempting to remount /system partition as read-write...")
    result = run_command([adb_path, "remount"])

    if result.returncode == 0:
        logger.success("✓ /system remounted as read-write.")
        return True
    else:
        logger.error(f"❌ Failed to remount /system as read-write. ADB stderr: {result.stderr}")
        logger.info("Ensure device is rooted and ADB has root permissions (`adb root` might be needed first).")
        return False

def remount_system_ro():
    """Remounts the /system partition as read-only."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
        
    logger.info("Attempting to remount /system partition as read-only...")
    # Using shlex.quote to handle a single, quoted command string for su -c
    remount_cmd = shlex.quote("mount -o ro,remount /system")
    result = run_command([adb_path, "shell", "su", "-c", remount_cmd])

    if result.returncode == 0:
        logger.success("✓ /system remounted as read-only.")
        return True
    else:
        logger.error(f"❌ Failed to remount /system as read-only. ADB stderr: {result.stderr}")
        logger.info("Manual remount might be required. You can try: 'adb shell su -c \"mount -o ro,remount /system\"'.")
        return False

def list_adb_connected_devices():
    """
    Lists all connected Android devices and their details.
    
    Returns:
        list of dict: A list of dictionaries with device info.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return []

    logger.info("Listing ADB connected devices...")
    result = run_command([adb_path, "devices", "-l"])
    
    devices = []
    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().splitlines()
        for line in lines[1:]: # Skip the header
            parts = line.split()
            if len(parts) >= 2:
                info = {'serial': parts[0], 'state': parts[1]}
                remaining_info = " ".join(parts[2:])
                
                model_match = re.search(r"model:(\S+)", remaining_info)
                if model_match: info['model'] = model_match.group(1)
                
                product_match = re.search(r"product:(\S+)", remaining_info)
                if product_match: info['product'] = product_match.group(1)

                devices.append(info)
    
    if devices:
        logger.info(f"Found {len(devices)} connected ADB device(s):")
        for dev in devices:
            logger.info(f"  - Serial: {dev.get('serial')}, State: {dev.get('state')}, Model: {dev.get('model', 'N/A')}")
    else:
        logger.info("No ADB devices found.")
    return devices

def install_apk(apk_path):
    """Installs an APK file onto the connected Android device."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
    
    if not os.path.exists(apk_path):
        logger.error(f"APK file not found at: {apk_path}")
        return False
    
    logger.info(f"Installing APK: {os.path.basename(apk_path)}...")
    result = run_command([adb_path, "install", apk_path])
    
    if result.returncode == 0 and "Success" in result.stdout:
        logger.success(f"✓ Successfully installed {os.path.basename(apk_path)}.")
        return True
    else:
        logger.error(f"❌ Failed to install APK. ADB stdout: {result.stdout.strip()}")
        logger.info("Common issues: APK corrupted, insufficient storage, incompatible ABI, or app already installed with a different signature.")
        return False

def uninstall_package(package_name):
    """Uninstalls an application package from the connected Android device."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
    
    logger.info(f"Uninstalling package: {package_name}...")
    result = run_command([adb_path, "uninstall", package_name])

    if result.returncode == 0 and ("Success" in result.stdout or "Success" in result.stderr):
        logger.success(f"✓ Successfully uninstalled package: {package_name}.")
        return True
    else:
        logger.error(f"❌ Failed to uninstall package: {package_name}. ADB stdout: {result.stdout.strip()}")
        logger.info("Common issues: Package not found, or insufficient permissions.")
        return False

def connect_adb_device(ip_address, port="5555"):
    """Connects to an Android device over TCP/IP."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to connect to ADB device at {target}...")
    
    result = run_command([adb_path, "connect", target])

    if result.returncode == 0 and "connected to" in result.stdout:
        logger.success(f"✓ Successfully connected to device at {target}.")
        logger.info("Ensure ADB debugging over network is enabled on the device.")
        return True
    else:
        logger.error(f"❌ Failed to connect to device at {target}. ADB stdout: {result.stdout.strip()}")
        logger.info("Possible issues: Device not listening on ADB TCP, wrong IP/port, or firewall blocking connection.")
        return False

def disconnect_adb_device(ip_address, port="5555"):
    """Disconnects from a remote Android device."""
    adb_path = get_tool_path("adb")
    if not adb_path:
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to disconnect from ADB device at {target}...")
    
    result = run_command([adb_path, "disconnect", target])

    if result.returncode == 0 and ("disconnected" in result.stdout or "no such device" in result.stdout):
        logger.success(f"✓ Successfully disconnected from device at {target}.")
        return True
    else:
        logger.error(f"❌ Failed to disconnect from device at {target}. ADB stdout: {result.stdout.strip()}")
        return False