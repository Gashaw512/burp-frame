import subprocess
import os
import re
import time
import shlex # For robust splitting of commands
import shutil # For rmtree
import posixpath # Import posixpath for explicit forward-slash path joining

from .logger import Logger
from .utils import run_adb_command, get_tool_path, TEMP_CERT_DIR

logger = Logger() # Corrected: Directly get the singleton Logger instance

# --- Constants ---
# These are internal paths on the Android device
DEVICE_CERT_DIR = "/system/etc/security/cacerts"
MAGISK_MODULES_DIR = "/data/adb/modules" # Base directory for Magisk modules

# --- Core Device Connection & Info ---

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

    if result.returncode == 0 and "device" in result.stdout.strip():
        logger.success("✓ Device connected and ready.")
        return True
    else:
        logger.error(f"❌ No device detected or device is not ready. ADB output: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"  ADB stderr: {result.stderr.strip()}")
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
    result = run_adb_command(adb_path, ["shell", "getprop", "ro.build.version.release"])
    if result.returncode == 0 and result.stdout:
        version = result.stdout.strip()
        logger.info(f"Android version detected: {version}")
        return version
    else:
        logger.error(f"❌ Failed to detect Android version. ADB stderr: {result.stderr.strip()}")
        return None

# --- Advanced Remounting Functions (ULTIMATE ROBUSTNESS) ---

def _get_device_tool_path(tool_name, common_paths):
    """
    Attempts to find a tool (like 'su' or 'magisk') on the Android device by checking common paths.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        return None

    for path in common_paths:
        result = run_adb_command(adb_path, ["shell", f"test -x {path} && echo EXISTS"])
        if result.returncode == 0 and "EXISTS" in result.stdout:
            logger.info(f"Found '{tool_name}' at: {path}")
            return path
    logger.debug(f"Could not find '{tool_name}' at common paths. Falling back to simple name.")
    return tool_name # Fallback to just the command name if not found in specific paths

def _is_partition_mounted_ro(adb_path, mount_point):
    """
    Checks if a given mount point is currently mounted as read-only.
    """
    result = run_adb_command(adb_path, ["shell", "cat /proc/mounts"])
    if result.returncode == 0 and result.stdout:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == mount_point:
                options = parts[3].split(',')
                if 'ro' in options:
                    return True
    return False

def _get_system_mount_points():
    """
    Attempts to read /proc/mounts to find potential system-related mount points
    that can be remounted, ordered by likelihood of being the primary system partition.
    
    Returns:
        list: A list of candidate mount points (e.g., ['/system', '/system_root', '/']).
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("❌ ADB path not configured. Cannot detect mount points.")
        return []

    logger.info("Detecting potential /system mount points from /proc/mounts...")
    result = run_adb_command(adb_path, ["shell", "cat /proc/mounts"])

    mount_points = set()
    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().splitlines()
        for line in lines:
            parts = line.split()
            if len(parts) > 1:
                path = parts[1]
                # Filter for relevant system-like mount points
                # Include / (root) if it's not a tmpfs or similar volatile mount
                if path.startswith('/system') or (path == '/' and 'rootfs' in line):
                    mount_points.add(path)
                elif re.match(r'^/dev/root$', parts[0]) and path == '/': # Specific for /dev/root on /
                    mount_points.add(path)
                
    # Prioritize common system paths, then others, for remounting attempts
    candidates = []
    if '/system' in mount_points:
        candidates.append('/system')
    if '/system_root' in mount_points: # For Android 10+ using super partition
        candidates.append('/system_root')
    if '/' in mount_points:
        # Check if '/' is a primary rootfs mount, not just a tempfs or overlay
        stdout_root_mount, stderr_root_mount, returncode_root_mount = run_adb_command(adb_path, ["shell", "grep -E '^/dev/root|rootfs' /proc/mounts | grep ' / '"])

        if returncode_root_mount == 0 and stdout_root_mount:
            if '/' not in candidates: # Avoid duplicates if already added by other logic
                candidates.append('/')
    
    # Add any other detected mount points (sorted for consistency)
    for mp in sorted(list(mount_points)):
        if mp not in candidates:
            candidates.append(mp)

    logger.info(f"Detected potential mount point candidates: {', '.join(candidates) if candidates else 'None'}")
    return candidates


def remount_system(mode="rw"):
    """
    Attempts to remount the /system partition (or its equivalent) of the Android device
    to read-write ('rw') or read-only ('ro').
    This function tries multiple common 'mount' command variations and dynamically
    identifies potential mount points for robustness. Requires root access.

    Args:
        mode (str): "rw" to remount as read-write, "ro" to remount as read-only.
    Returns:
        bool: True if remount successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error(f"❌ ADB path not configured. Cannot remount /system to {mode}.")
        return False

    logger.info(f"Attempting to remount /system partition as read-{mode}...")

    # Strategy 1: Try direct 'adb remount' command (often the simplest and most effective)
    logger.info("Trying 'adb remount' command first (high-level, often works)..")
    result = run_adb_command(adb_path, ["remount"])
    if result.returncode == 0 and "succeeded" in result.stdout.lower():
        logger.success(f"✓ /system remounted as read-{mode} via 'adb remount'.")
        return True
    elif result.returncode == 0 and "already" in result.stdout.lower() and mode == "ro":
        logger.success(f"✓ /system is already read-only. No action needed via 'adb remount'.")
        return True
    elif result.returncode != 0:
        logger.warning(f"⚠ 'adb remount' failed ({result.returncode}). STDOUT: '{result.stdout.strip()}' STDERR: '{result.stderr.strip()}'. Trying other methods.")
        # If it failed for RW, this could be because adbd isn't running as root. Try `adb root`
        if mode == "rw" and "adbd cannot run as root" in result.stderr.lower():
            logger.info("Attempting 'adb root' and re-trying 'adb remount'...")
            root_result = run_adb_command(adb_path, ["root"])
            if root_result.returncode == 0:
                time.sleep(2) # Give adbd time to restart as root
                re_remount_result = run_adb_command(adb_path, ["remount"])
                if re_remount_result.returncode == 0 and "succeeded" in re_remount_result.stdout.lower():
                    logger.success(f"✓ /system remounted as read-write via 'adb root' then 'adb remount'.")
                    return True
                else:
                    logger.warning(f"⚠ Re-try with 'adb root' also failed. STDOUT: '{re_remount_result.stdout.strip()}' STDERR: '{re_remount_result.stderr.strip()}'.")


    # Strategy 2: Find 'su' binary and use specific `su -c` mount commands
    su_path = _get_device_tool_path("su", ["/system/bin/su", "/system/xbin/su", "/data/adb/magisk/su"])
    if not su_path:
        logger.warning("⚠ 'su' binary not found at common paths. Root commands might fail. Falling back to generic 'su'.")
        su_path = "su" # Fallback to just 'su' in PATH

    mount_points = _get_system_mount_points()
    if not mount_points:
        logger.warning("⚠ No viable system mount points detected in /proc/mounts. Cannot attempt remount.")
        if mode == "ro":
            logger.info("Consider rebooting your device. Most Android systems automatically remount /system as read-only upon reboot.")
        return False

    # Define a list of common 'mount' command syntaxes to try (via 'su -c')
    # These prioritize forms less likely to trigger 'invalid option -- o'
    # Adding more variations that might be accepted by different `su`/`mount` versions
    mount_command_templates = [
        # Standard forms
        'mount -o remount,{mode} {mp}',
        'mount -o {mode},remount {mp}',
        'mount {mp} -o remount,{mode}',
        
        # Explicit full paths to mount binary (for specific ROMs/setups)
        '/system/bin/mount -o remount,{mode} {mp}',
        '/vendor/bin/mount -o remount,{mode} {mp}',
        '/apex/com.android.runtime/bin/mount -o remount,{mode} {mp}', # Android 10+
        
        # Busybox/Toybox variants (if present)
        'busybox mount -o remount,{mode} {mp}', 
        'toybox mount -o remount,{mode} {mp}',
        
        # More verbose/explicit remounts (sometimes needed for older/specific root)
        # Removed the 'mount -t auto {device} {mp} -o remount,{mode}' as it's hard to dynamically get {device}
    ]

    for mp in mount_points:
        logger.info(f"Attempting to remount '{mp}' as read-{mode} using 'su -c' commands...")
        for template in mount_command_templates:
            cmd = template.format(mode=mode, mp=mp)
            # Use shlex.quote to properly quote the inner command for su -c, especially if it contains spaces
            full_su_cmd = f"{su_path} -c {shlex.quote(cmd)}"
            result = run_adb_command(adb_path, ["shell", full_su_cmd])

            # Success check: exit code 0 and common success indicators in stdout/stderr
            if result.returncode == 0 and \
               ("succeeded" in result.stdout.lower() or \
                "remount" in result.stdout.lower() or \
                "remounting" in result.stdout.lower() or \
                not result.stderr): # If no stderr, it often implies success
                
                # For RO, explicitly verify it's read-only
                if mode == "ro":
                    if _is_partition_mounted_ro(adb_path, mp):
                        logger.success(f"✓ '{mp}' successfully remounted as read-{mode} using command: '{cmd}'. (Verified RO)")
                        return True
                    else:
                        logger.warning(f"⚠ Command '{cmd}' reported success but partition '{mp}' is not verified as read-only. STDOUT: '{result.stdout}'")
                else: # For RW, just success from command is enough
                    logger.success(f"✓ '{mp}' successfully remounted as read-{mode} using command: '{cmd}'.")
                    return True
            
            # Detailed failure logging based on specific errors
            elif result.stderr:
                stderr_lower = result.stderr.lower()
                if "invalid option" in stderr_lower or "not in /proc/mounts" in stderr_lower or "read-only file system" in stderr_lower or "permission denied" in stderr_lower:
                    logger.warning(f"⚠ Command '{cmd}' failed due to specific error. STDERR: '{result.stderr.strip()}'")
                else: # Generic error
                    logger.warning(f"⚠ Command '{cmd}' failed with exit code {result.returncode}. STDOUT: '{result.stdout.strip()}' STDERR: '{result.stderr.strip()}'")
            elif result.returncode != 0:
                logger.warning(f"⚠ Command '{cmd}' failed with exit code {result.returncode}. STDOUT: '{result.stdout.strip()}'.")

    logger.error(f"❌ ❌ Failed to remount /system as read-{mode} after all programmatic attempts.")
    if mode == "ro":
        logger.info("⭐ ACTION REQUIRED: Please **reboot your Android device** now.")
        logger.info("Most Android systems automatically remount /system as read-only upon reboot, which is the most reliable way.")
    elif mode == "rw":
        logger.info("If you require read-write access to /system, you may need to manually run `adb root` or specific commands for your device's root solution.")
    return False

# Convenience functions for specific modes
def remount_system_rw(adb_path): # Keep adb_path as argument for cli.py compatibility
    """Remounts the /system partition as read-write."""
    return remount_system(mode="rw")

def remount_system_ro(adb_path): # Keep adb_path as argument for cli.py compatibility
    """Remounts the /system partition as read-only."""
    return remount_system(mode="ro")


def _calculate_local_cert_fingerprint(cert_path):
    """
    Calculates the SHA-1 fingerprint of a local certificate file.
    Assumes OpenSSL is installed on the host.
    
    Args:
        cert_path (str): Path to the local certificate file (PEM or DER).
        
    Returns:
        str or None: SHA-1 fingerprint (e.g., "AB:CD:EF:...") or None on failure.
                     The returned format is without colons for easy comparison.
    """
    openssl_path = get_tool_path("openssl")
    if not openssl_path:
        logger.error("❌ OpenSSL not configured. Cannot calculate certificate fingerprint.")
        return None
    
    # Determine input format based on file extension
    input_format = "DER" if cert_path.lower().endswith((".der", ".crt")) else "PEM" # .crt can be DER or PEM, but .der is more specific
    
    try:
        # openssl x509 -inform <format> -in <file> -noout -fingerprint -sha1
        command = [openssl_path, "x509", "-inform", input_format, "-in", cert_path, "-noout", "-fingerprint", "-sha1"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        # Output will be like 'SHA1 Fingerprint=AB:CD:EF:...'
        fingerprint_line = result.stdout.strip()
        # Regex to extract the fingerprint part (20 bytes, 59 chars with colons)
        match = re.search(r"([0-9A-Fa-f:]{59})", fingerprint_line) 
        if match:
            # Remove colons and convert to uppercase for consistent comparison
            return match.group(1).replace(":", "").upper()
        else:
            logger.error(f"❌ Could not parse SHA1 fingerprint from OpenSSL output: {fingerprint_line}")
            return None
    except FileNotFoundError:
        logger.error(f"❌ OpenSSL executable not found at '{openssl_path}'.")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ OpenSSL failed to get fingerprint for '{cert_path}'. STDOUT: {e.stdout.strip()} STDERR: {e.stderr.strip()}")
        return None
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred calculating fingerprint for '{cert_path}': {str(e)}")
        return None

def _get_installed_cert_fingerprints_on_device():
    """
    Retrieves SHA-1 fingerprints of all certificates currently installed in the
    `/system/etc/security/cacerts/` directory on the Android device.
    It pulls each cert to a temporary host location, calculates its fingerprint
    using the host's OpenSSL, then cleans up the temporary file.
    
    Returns:
        set: A set of SHA-1 fingerprints (e.g., {"ABCD123...", "EFGH456..."}).
             Returns an empty set on failure or if no certs are found.
    """
    adb_path = get_tool_path("adb")
    openssl_path = get_tool_path("openssl")
    if not adb_path or not openssl_path:
        logger.error("❌ ADB or OpenSSL not configured. Cannot check installed certificates on device.")
        return set()

    logger.info("Checking for pre-existing Burp Suite CA certificate on device...")
    installed_fingerprints = set()
    temp_pull_dir = os.path.join(TEMP_CERT_DIR, "pulled_device_certs")
    os.makedirs(temp_pull_dir, exist_ok=True)

    try:
        list_cmd = ["shell", f"ls -1 {DEVICE_CERT_DIR}"]
        ls_result = run_adb_command(adb_path, list_cmd)

        if ls_result.returncode == 0 and ls_result.stdout:
            device_cert_filenames = [f.strip() for f in ls_result.stdout.strip().splitlines() if f.strip().endswith(".0")]
            
            if not device_cert_filenames:
                logger.info("No .0 certificate files found in /system/etc/security/cacerts/ to check.")
                return installed_fingerprints

            # Log a concise message about starting the scan, without per-file detail
            logger.info(f"Scanning {len(device_cert_filenames)} existing certificates on device for a match...")
            
            for cert_filename in device_cert_filenames:
                device_file_path = posixpath.join(DEVICE_CERT_DIR, cert_filename)
                local_temp_cert_path = os.path.join(temp_pull_dir, cert_filename)

                pull_result = run_adb_command(adb_path, ["pull", device_file_path, local_temp_cert_path])
                
                if pull_result.returncode == 0 and os.path.exists(local_temp_cert_path):
                    fingerprint = _calculate_local_cert_fingerprint(local_temp_cert_path)
                    if fingerprint:
                        installed_fingerprints.add(fingerprint)
                        # Removed verbose logging for each found certificate
                    os.remove(local_temp_cert_path)
                else:
                    # Keep this warning as it indicates a genuine issue with a specific file pull
                    logger.warn(f"⚠ Failed to pull {device_file_path}. ADB stderr: {pull_result.stderr.strip()}")
        else:
            logger.info("No certificate files found or directory inaccessible in /system/etc/security/cacerts/.")
            if ls_result.stderr:
                logger.debug(f"ls stderr: {ls_result.stderr.strip()}") # Use debug for verbose adb ls errors

    except Exception as e:
        logger.error(f"❌ An error occurred while checking installed certificates on device: {str(e)}")
    finally:
        if os.path.exists(temp_pull_dir):
            shutil.rmtree(temp_pull_dir)
    
    logger.info(f"Completed scanning existing device certificates. Total unique installed certificates found: {len(installed_fingerprints)}.")
    return installed_fingerprints

def perform_install_certificate(adb_path, cert_prepared_file, cert_hash, dry_run=False, use_magisk=False):
    """
    Installs the prepared CA certificate onto the Android device.
    This function handles both standard system installation (requires root and remount)
    and Magisk systemless installation. It checks for existing certificates by SHA-1 fingerprint.
    
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

    # Step 1: Calculate fingerprint of the certificate to be installed
    local_cert_fingerprint = _calculate_local_cert_fingerprint(cert_prepared_file)
    if not local_cert_fingerprint:
        logger.error("❌ Failed to calculate SHA-1 fingerprint for the certificate to be installed. Aborting.")
        return False

    # Step 2: Check if the certificate is already installed (unless it's a dry run)
    cert_already_present = False
    if not dry_run:
        installed_fingerprints = _get_installed_cert_fingerprints_on_device()
        if local_cert_fingerprint in installed_fingerprints:
            logger.success(f"✓ Burp Suite CA certificate (SHA-1: **{local_cert_fingerprint}**) is **already installed** on the device.")
            logger.info("No installation action needed.")
            cert_already_present = True
        else:
            logger.info(f"Burp Suite CA certificate (SHA-1: **{local_cert_fingerprint}**) not found on device. Proceeding with installation...")
    else:
        logger.info("[DRY RUN] Simulating certificate installation...")


    if cert_already_present:
        return True # Certificate confirmed as present, so the installation goal is met.

    if use_magisk:
        logger.info("Attempting **Magisk systemless installation**.")
        remote_magisk_module_dir = posixpath.join(MAGISK_MODULES_DIR, f"burp_ca_cert_{cert_hash}")
        remote_cert_path_in_module = posixpath.join(remote_magisk_module_dir, "system", "etc", "security", "cacerts", f"{cert_hash}.0")
        
        if dry_run:
            logger.info(f"[DRY RUN] Would create Magisk module directory: {remote_magisk_module_dir}")
            logger.info(f"[DRY RUN] Would push certificate to: {remote_cert_path_in_module}")
            logger.info("[DRY RUN] Would create module.prop and post-fs-data.sh.")
            return True

        logger.info("Checking for Magisk/Root access...")
        su_test_result = run_adb_command(adb_path, ["shell", "su", "-c", "echo 'root_ok'"])
        if su_test_result.returncode != 0 or "root_ok" not in su_test_result.stdout.strip():
            logger.error("❌ **Magisk/Root access not detected or not granted.** Cannot proceed with Magisk installation.")
            logger.info("Please ensure Magisk is installed, enabled, and ADB has root permissions (`adb root` or Magisk prompts).")
            return False
        logger.success("✓ **Magisk/Root access detected.**")

        logger.info(f"Creating Magisk module directory: **{remote_magisk_module_dir}**...")
        result = run_adb_command(adb_path, ["shell", "su", "-c", f"mkdir -p {remote_magisk_module_dir}/system/etc/security/cacerts"])
        if result.returncode != 0:
            logger.error(f"❌ Failed to create Magisk module directory. ADB stderr: {result.stderr.strip()}")
            return False
        logger.success("✓ **Magisk module directory created.**")

        logger.info(f"Copying certificate to Magisk module: **{remote_cert_path_in_module}**...")
        temp_remote_cert_name = os.path.basename(cert_prepared_file)
        temp_remote_cert_path = f"/sdcard/{temp_remote_cert_name}"
        result = run_adb_command(adb_path, ["push", cert_prepared_file, temp_remote_cert_path])
        if result.returncode != 0:
            logger.error(f"❌ Failed to push certificate to temporary location. ADB stderr: {result.stderr.strip()}")
            return False
        
        move_cmd = f"mv {temp_remote_cert_path} {remote_cert_path_in_module}"
        result = run_adb_command(adb_path, ["shell", "su", "-c", move_cmd])
        if result.returncode != 0:
            logger.error(f"❌ Failed to move certificate to Magisk module path. ADB stderr: {result.stderr.strip()}")
            run_adb_command(adb_path, ["shell", f"rm {temp_remote_cert_path}"])
            return False
        logger.success(f"✓ **Certificate copied into Magisk module.**")

        module_prop_content = f"""id=burp_ca_cert_{cert_hash}
name=Burp Suite CA Certificate
version=v1.0
versionCode=1
author=Burp-Frame
description=Systemless installation of Burp Suite CA certificate for traffic interception.
"""
        temp_module_prop_path = os.path.join(os.path.dirname(cert_prepared_file), "module.prop")
        with open(temp_module_prop_path, "w") as f:
            f.write(module_prop_content)
        
        result = run_adb_command(adb_path, ["push", temp_module_prop_path, posixpath.join(remote_magisk_module_dir, "module.prop")])
        if result.returncode != 0:
            logger.error(f"❌ Failed to push module.prop. ADB stderr: {result.stderr.strip()}")
            os.remove(temp_module_prop_path)
            return False
        logger.success("✓ **module.prop created.**")
        os.remove(temp_module_prop_path)

        post_fs_data_content = f"""#!/system/bin/sh
# This script is executed in post-fs-data mode by Magisk.
# No special commands are typically needed here for a simple CA cert module
# as Magisk handles the bind mounts to /system/etc/security/cacerts automatically.
"""
        temp_post_fs_data_path = os.path.join(os.path.dirname(cert_prepared_file), "post-fs-data.sh")
        with open(temp_post_fs_data_path, "w") as f:
            f.write(post_fs_data_content)
        
        result = run_adb_command(adb_path, ["push", temp_post_fs_data_path, posixpath.join(remote_magisk_module_dir, "post-fs-data.sh")])
        if result.returncode != 0:
            logger.error(f"❌ Failed to push post-fs-data.sh. ADB stderr: {result.stderr.strip()}")
            os.remove(temp_post_fs_data_path)
            return False
        
        result = run_adb_command(adb_path, ["shell", "su", "-c", f"chmod 755 {posixpath.join(remote_magisk_module_dir, 'post-fs-data.sh')}"])
        if result.returncode != 0:
            logger.error(f"❌ Failed to set permissions for post-fs-data.sh. ADB stderr: {result.stderr.strip()}")
            os.remove(temp_post_fs_data_path)
            return False

        logger.success("✓ **post-fs-data.sh created and permissions set.**")
        os.remove(temp_post_fs_data_path)

        logger.success(f"✓ **Certificate installed at: `{remote_cert_path_in_module}` (via Magisk module).**")
        logger.info("Magisk module created. A device reboot might be required for the module to activate.")
        return True

    else: # Standard (non-Magisk) system installation path
        logger.info("Attempting **standard system certificate installation** (requires root and system remount).")
        remote_cert_path = posixpath.join(DEVICE_CERT_DIR, f"{cert_hash}.0")
        
        if dry_run:
            logger.info(f"[DRY RUN] Would push certificate to: {remote_cert_path}")
            logger.info("[DRY RUN] Would remount /system as read-write, push, then remount read-only.")
            return True

        logger.info("Attempting remount as RW...")
        if not remount_system(mode="rw"): 
            logger.error("❌ **Failed to remount /system as read-write.** Cannot install certificate to system partition.")
            logger.info("Ensure device is rooted and ADB has root permissions (`adb root`).")
            return False
        logger.success("✓ **Remount successful.**")

        logger.info(f"Copying certificate to **{remote_cert_path}**...")
        temp_remote_cert_name = os.path.basename(cert_prepared_file)
        temp_remote_cert_path = f"/data/local/tmp/{temp_remote_cert_name}"
        result = run_adb_command(adb_path, ["push", cert_prepared_file, temp_remote_cert_path])
        if result.returncode != 0:
            logger.error(f"❌ Failed to push certificate to temporary location. ADB stderr: {result.stderr.strip()}")
            return False
        
        move_cmd = f"mv {temp_remote_cert_path} {remote_cert_path}"
        result = run_adb_command(adb_path, ["shell", "su", "-c", move_cmd])
        if result.returncode != 0:
            logger.error(f"❌ Failed to move certificate to system path. ADB stderr: {result.stderr.strip()}")
            run_adb_command(adb_path, ["shell", f"rm {temp_remote_cert_path}"])
            return False
        
        chmod_cmd = f"chmod 644 {remote_cert_path}"
        result = run_adb_command(adb_path, ["shell", "su", "-c", chmod_cmd])
        if result.returncode != 0:
            logger.error(f"❌ Failed to set permissions for certificate. ADB stderr: {result.stderr.strip()}")
            return False
        logger.success(f"✓ **Certificate installed at `{remote_cert_path}`.**")

        logger.info("Remounting system back to RO...")
        if not remount_system(mode="ro"):
            logger.error("❌ **Failed to remount /system as read-only.** Device may be left insecure.")
            return True
        logger.success("✓ **System remounted as read-only.**")
        logger.info("Certificate installed. A device reboot might be required to apply changes or for security hardening.")
        return True
    
# --- Other Core Device Management Functions ---

def reboot_device():
    """
    Reboots the connected Android device.
    
    Returns:
        bool: True if the reboot command was successfully sent, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("❌ ADB path not configured. Cannot reboot device.")
        return False
    
    logger.info("Attempting to reboot the Android device...")
    result = run_adb_command(adb_path, ["reboot"])

    if result.returncode == 0:
        logger.success("✓ Reboot command sent successfully. Device should be rebooting now.")
        logger.info("Please wait for the device to restart and reconnect via ADB (this may take a minute or two).")
        return True
    else:
        logger.error(f"❌ Failed to send reboot command. ADB stderr: {result.stderr.strip()}")
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
        logger.error("❌ ADB path not configured. Cannot list devices.")
        return []

    logger.info("Listing ADB connected devices...")
    result = run_adb_command(adb_path, ["devices", "-l"])

    devices = []
    if result.returncode == 0 and result.stdout:
        lines = result.stdout.strip().splitlines()
        if len(lines) > 1: # Skip "List of devices attached"
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    serial = parts[0]
                    state = parts[1]
                    model = "N/A"
                    product = "N/A"

                    remaining_info = " ".join(parts[2:])
                    model_match = re.search(r"model:(\S+)", remaining_info)
                    if model_match:
                        model = model_match.group(1)
                    product_match = re.search(r"product:(\S+)", remaining_info)
                    if product_match:
                        product = product_match.group(1)

                    devices.append({'serial': serial, 'state': state, 'model': model, 'product': product})
                else:
                    logger.warning(f"⚠ Skipping malformed device line: {line.strip()}")
        
        if devices:
            logger.info(f"Found {len(devices)} connected ADB device(s):")
            for dev in devices:
                logger.info(f"  - Serial: {dev['serial']}, State: {dev['state']}, Model: {dev['model']} (Product: {dev['product']})")
        else:
            logger.info("No ADB devices found.")
        return devices
    else:
        logger.error(f"❌ Failed to list ADB devices. ADB stderr: {result.stderr.strip()}")
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
        logger.error("❌ ADB path not configured. Cannot install APK.")
        return False
    
    if not os.path.exists(apk_path):
        logger.error(f"❌ APK file not found at: {apk_path}")
        return False

    logger.info(f"Installing APK: {apk_path}...")
    result = run_adb_command(adb_path, ["install", apk_path])

    if result.returncode == 0 and "Success" in result.stdout:
        logger.success(f"✓ Successfully installed {os.path.basename(apk_path)}.")
        return True
    else:
        logger.error(f"❌ Failed to install APK. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"  ADB stderr: {result.stderr.strip()}")
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
        logger.error("❌ ADB path not configured. Cannot uninstall package.")
        return False
    
    logger.info(f"Uninstalling package: {package_name}...")
    result = run_adb_command(adb_path, ["uninstall", package_name])

    if result.returncode == 0 and ("Success" in result.stdout or "Success" in result.stderr):
        logger.success(f"✓ Successfully uninstalled package: {package_name}.")
        return True
    else:
        logger.error(f"❌ Failed to uninstall package: {package_name}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"  ADB stderr: {result.stderr.strip()}")
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
        logger.error("❌ ADB path not configured. Cannot connect to remote device.")
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to connect to ADB device at {target}...")
    
    result = run_adb_command(adb_path, ["connect", target])

    if result.returncode == 0 and "connected to" in result.stdout:
        logger.success(f"✓ Successfully connected to device at {target}.")
        logger.info("Ensure ADB debugging over network is enabled on the device (usually by running 'adb tcpip 5555' from a USB-connected session first).")
        return True
    else:
        logger.error(f"❌ Failed to connect to device at {target}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"  ADB stderr: {result.stderr.strip()}")
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
        logger.error("❌ ADB path not configured. Cannot disconnect from remote device.")
        return False
    
    target = f"{ip_address}:{port}"
    logger.info(f"Attempting to disconnect from ADB device at {target}...")
    
    result = run_adb_command(adb_path, ["disconnect", target])

    if result.returncode == 0 and ("disconnected" in result.stdout or "no such device" in result.stdout):
        logger.success(f"✓ Successfully disconnected from device at {target}.")
        return True
    else:
        logger.error(f"❌ Failed to disconnect from device at {target}. ADB stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.error(f"  ADB stderr: {result.stderr.strip()}")
        return False
