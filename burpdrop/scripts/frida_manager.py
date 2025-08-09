import os
import requests
import json
import time
import lzma # For .xz decompression
import shutil # For file operations like copyfileobj
import subprocess # Explicitly import subprocess for clarity in run_frida_script
import re # Import regex for parsing ps output

from .logger import Logger
from .utils import run_adb_command, get_tool_path # Import utils functions

logger = Logger()

# --- Constants ---
FRIDA_SERVER_DIR = "/data/local/tmp" # Common directory for pushing temp binaries on Android
FRIDA_SERVER_NAME_PREFIX = "frida-server"
FRIDA_RELEASES_URL = "https://api.github.com/repos/frida/frida/releases/latest"
# Define a temporary directory for Frida downloads/decompression within the package
FRIDA_TEMP_DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_frida_download")


def _get_device_arch(adb_path):
    """
    Determines the CPU architecture (ABI) of the connected Android device.
    
    Args:
        adb_path (str): Path to the ADB executable.
    
    Returns:
        str or None: Device architecture (e.g., 'arm', 'arm64', 'x86', 'x86_64'),
                     or None if it cannot be determined.
    """
    logger.info("Detecting device architecture for Frida...")
    # Command to get CPU ABI (Application Binary Interface)
    result = run_adb_command(adb_path, ["shell", "getprop", "ro.product.cpu.abi"])
    if result.returncode == 0 and result.stdout:
        abi = result.stdout.strip()
        logger.info(f"Device ABI detected: {abi}")
        
        # Map common ABIs to Frida's naming conventions (Frida uses simplified names)
        if "arm64" in abi:
            return "arm64"
        elif "arm" in abi: # Catches armeaibi-v7a, etc.
            return "arm"
        elif "x86_64" in abi:
            return "x86_64"
        elif "x86" in abi:
            return "x86"
        else:
            logger.warn(f"Unsupported or unrecognized device ABI for Frida: '{abi}'.")
            logger.info("Please manually check Frida's GitHub releases for compatible architectures.")
            return None
    else:
        logger.error(f"Could not determine device ABI. ADB stderr: {result.stderr}")
        return None

def _download_frida_server(device_arch):
    """
    Downloads the appropriate Frida server binary for the detected device architecture
    from the latest GitHub releases.
    
    Args:
        device_arch (str): The detected device architecture (e.g., 'arm', 'arm64', 'x86', 'x86_64').
    
    Returns:
        str or None: Local path to the downloaded and decompressed Frida server binary, or None on failure.
    """
    logger.info(f"Attempting to download latest Frida server for architecture: {device_arch}...")
    
    # Ensure temporary download directory exists and is clean
    os.makedirs(FRIDA_TEMP_DOWNLOAD_DIR, exist_ok=True)
    for item in os.listdir(FRIDA_TEMP_DOWNLOAD_DIR):
        item_path = os.path.join(FRIDA_TEMP_DOWNLOAD_DIR, item)
        try:
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        except Exception as e:
            logger.error(f"Error cleaning up old temp file {item_path}: {e}")

    try:
        logger.info(f"Fetching latest Frida release info from: {FRIDA_RELEASES_URL}")
        response = requests.get(FRIDA_RELEASES_URL, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        release_info = response.json()
        
        assets = release_info.get("assets", [])
        download_url = None
        
        # Frida server binary names are typically like 'frida-server-<version>-android-{arch}.xz'
        expected_asset_name_part = f"android-{device_arch}.xz"
        
        for asset in assets:
            asset_name = asset.get("name", "")
            if asset_name.startswith(FRIDA_SERVER_NAME_PREFIX) and asset_name.endswith(expected_asset_name_part):
                download_url = asset.get("browser_download_url")
                logger.info(f"Found Frida server asset: {asset_name} (URL: {download_url})")
                break
        
        if not download_url:
            logger.error(f"No Frida server binary found for Android-{device_arch} in the latest release assets.")
            logger.info("This might mean the architecture is not directly supported, asset naming changed, or release is incomplete.")
            logger.info("Please check Frida's GitHub releases directly: https://github.com/frida/frida/releases")
            return None
        
        compressed_file_path = os.path.join(FRIDA_TEMP_DOWNLOAD_DIR, os.path.basename(download_url))
        decompressed_file_path = os.path.join(FRIDA_TEMP_DOWNLOAD_DIR, FRIDA_SERVER_NAME_PREFIX)

        logger.info(f"Downloading Frida server from {download_url} to {compressed_file_path}...")
        with requests.get(download_url, stream=True, timeout=60) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(compressed_file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        if total_size > 0:
                            progress_percent = (downloaded_size / total_size) * 100
                            # Update progress on the same line
                            logger.progress("Downloading Frida server", int(progress_percent), 100)
        logger.success("Frida server download complete.")

        logger.info(f"Decompressing {os.path.basename(compressed_file_path)} to {decompressed_file_path}...")
        try:
            with lzma.open(compressed_file_path, 'rb') as f_in:
                with open(decompressed_file_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            logger.success("Frida server decompression complete.")
            return decompressed_file_path
        except lzma.LZMAError as e:
            logger.error(f"Failed to decompress .xz file. It might be corrupted or not a valid .xz archive: {e}")
            return None
        finally:
            if os.path.exists(compressed_file_path):
                os.remove(compressed_file_path) # Clean up the compressed file

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during Frida server download: {e}")
        logger.info("Please check your internet connection and GitHub API access (e.g., firewall, proxy settings).")
        return None
    except json.JSONDecodeError:
        logger.error("Failed to parse Frida releases JSON response. GitHub API response might be malformed.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during Frida server download: {e}")
        return None


def deploy_frida_server():
    """
    Deploys the Frida server binary to the Android device and starts it.
    This function first attempts to automatically download the correct binary.
    If download fails or is not preferred, it checks for a manually configured path.
    
    Returns:
        bool: True if deployment and start were successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot deploy Frida.")
        return False

    # Check device connection first
    from .device_manager import check_device_connection # Import dynamically to avoid circular dependency
    if not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready for Frida deployment.")
        return False

    device_arch = _get_device_arch(adb_path)
    if not device_arch:
        logger.error("Failed to determine device architecture for Frida deployment.")
        return False
    
    frida_server_local_path = None
    
    # 1. Attempt automated download
    logger.info("Attempting automated Frida server download...")
    frida_server_local_path = _download_frida_server(device_arch)
    
    # 2. Fallback to manually configured path if automated download failed
    if not frida_server_local_path or not os.path.exists(frida_server_local_path):
        logger.warn("Automated Frida server download failed or binary not found locally.")
        logger.info("Checking for manually configured Frida server binary path (via 'burp-frame config --frida-server-binary')...")
        frida_server_local_path = get_tool_path("frida_server_binary") 
        
        if not frida_server_local_path or not os.path.exists(frida_server_local_path):
            logger.error(f"Frida server binary for {device_arch} not found at configured path either.")
            logger.info("Please download it manually from `https://github.com/frida/frida/releases/latest` (e.g., 'frida-server-*-android-{arch}.xz').")
            logger.info("Decompress it and configure its path using: `burp-frame config --frida-server-binary /path/to/frida-server-binary`.")
            return False

    remote_path = f"{FRIDA_SERVER_DIR}/{FRIDA_SERVER_NAME_PREFIX}"
    
    # Optional: Check if Frida server is already running on device and kill it for a clean deploy
    logger.info("Checking for existing Frida server processes on device...")
    # Use 'ps -A | grep' for more robust detection of running processes
    check_running_result = run_adb_command(adb_path, ["shell", f"ps -A | grep {FRIDA_SERVER_NAME_PREFIX}"])
    
    running_pids = []
    if check_running_result.returncode == 0:
        for line in check_running_result.stdout.splitlines():
            if FRIDA_SERVER_NAME_PREFIX in line and "grep" not in line:
                match = re.search(r"^\S+\s+(\d+)", line.strip()) # Match user/root then PID
                if match:
                    running_pids.append(match.group(1))

    if running_pids:
        pid_str = ", ".join(running_pids)
        logger.warn(f"Existing Frida server detected with PID(s): {pid_str}. Attempting to kill for clean deployment.")
        
        kill_succeeded = True
        for pid in running_pids:
            kill_command = ["shell", "kill", "-9", pid] 
            single_kill_result = run_adb_command(adb_path, kill_command)
            if single_kill_result.returncode != 0:
                logger.error(f"Failed to kill PID {pid}. ADB stderr: {single_kill_result.stderr}")
                kill_succeeded = False
        
        if kill_succeeded:
            logger.success(f"Existing Frida server(s) (PID(s) {pid_str}) killed successfully.")
            time.sleep(1) # Give it a moment to terminate
        else:
            logger.error(f"Failed to kill all existing Frida server(s) (PID(s) {pid_str}). Proceeding, but may cause issues.")

    logger.info(f"Pushing Frida server from '{frida_server_local_path}' to device '{remote_path}'...")
    push_result = run_adb_command(adb_path, ["push", frida_server_local_path, remote_path])
    if push_result.returncode != 0:
        logger.error(f"Failed to push Frida server. ADB stderr: {push_result.stderr}")
        return False
    logger.success("Frida server pushed successfully.")

    logger.info(f"Setting executable permissions for '{remote_path}'...")
    chmod_result = run_adb_command(adb_path, ["shell", "chmod", "755", remote_path])
    if chmod_result.returncode != 0:
        logger.error(f"Failed to set permissions for Frida server. ADB stderr: {chmod_result.stderr}")
        return False
    logger.success("Permissions set.")

    logger.info("Starting Frida server on device in background (output redirected to /dev/null)...")
    start_command_str = f"nohup {remote_path} >/dev/null 2>&1 &"
    start_result = run_adb_command(adb_path, ["shell", start_command_str])
    
    if start_result.returncode == 0:
        logger.success("Frida server initiation command sent to device. Verifying process status...")
        time.sleep(3) # Give it a bit more time to start up
        
        check_running_result = run_adb_command(adb_path, ["shell", f"ps -A | grep {FRIDA_SERVER_NAME_PREFIX}"])
        
        verified_pids = []
        if check_running_result.returncode == 0:
            for line in check_running_result.stdout.splitlines():
                if FRIDA_SERVER_NAME_PREFIX in line and "grep" not in line:
                    match = re.search(r"^\S+\s+(\d+)", line.strip())
                    if match:
                        verified_pids.append(match.group(1))

        if verified_pids:
            logger.success(f"Frida server appears to be running on the device with PID(s): {', '.join(verified_pids)}.")
            logger.info("You can now run Frida scripts from your host machine.")
            return True
        else:
            logger.warn("Frida server process not detected after initiation or failed to parse PID from 'ps' output.")
            logger.info("This might indicate the server failed to start, exited immediately, or 'ps' output is unexpected.")
            logger.info("Please check device logs (`adb logcat`) for more details on Frida server startup issues.")
            return False
    else:
        logger.error(f"Failed to send Frida server start command. ADB stderr: {start_result.stderr}")
        return False


def list_processes():
    """
    Lists all running processes on the Android device that Frida can potentially attach to.
    
    Returns:
        list of dict: A list of dictionaries, each containing 'pid', 'user', and 'name'.
                      Returns an empty list if unable to retrieve processes.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot list processes.")
        return []

    logger.info("Retrieving list of running processes on the device...")
    # Using 'ps -A' or 'ps -ef' for comprehensive listing. 'ps -A' is generally simpler.
    result = run_adb_command(adb_path, ["shell", "ps", "-A"]) # '-A' for all processes

    processes = []
    if result.returncode == 0 and result.stdout:
        # Expected header example (might vary slightly by Android version):
        # USER      PID   PPID  VSZ RSS WCHAN            ADDR S NAME
        # Match lines for processes, skipping header and empty lines
        lines = result.stdout.splitlines()
        if len(lines) > 1: # Skip header line
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 9: # At least 9 columns for standard ps -A output
                    try:
                        user = parts[0]
                        pid = parts[1]
                        name = parts[8] # Process name is typically the last part
                        processes.append({'user': user, 'pid': pid, 'name': name})
                    except IndexError:
                        logger.warn(f"Could not parse process line: {line.strip()}")
                elif len(parts) > 0: # Catch lines that might not match exactly, but log for debug
                    logger.warn(f"Skipping malformed process line: {line.strip()}")
        
        logger.info(f"Found {len(processes)} running processes.")
        return processes
    else:
        logger.error(f"Failed to retrieve process list. ADB stderr: {result.stderr}")
        return []

def kill_frida_process(target):
    """
    Kills a specific process by PID or package name using Frida CLI if available,
    or falls back to ADB shell kill.
    
    Args:
        target (str): The process ID (PID) as a string or the application package name.
                      If a package name, it will attempt to find its PID first.
                      
    Returns:
        bool: True if the process was successfully killed, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot kill process.")
        return False

    from .device_manager import check_device_connection # Import dynamically
    if not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready.")
        return False

    target_pid = None
    if target.isdigit(): # Target is a PID
        target_pid = target
        logger.info(f"Attempting to kill process with PID: {target_pid}...")
    else: # Target is likely a package name
        logger.info(f"Attempting to find PID for package: {target}...")
        processes = list_processes() # Get fresh process list
        for proc in processes:
            # Check if process name matches package name
            # Or if 'target' is a substring of process name (common for apps)
            if target in proc['name']:
                target_pid = proc['pid']
                logger.info(f"Found process '{proc['name']}' with PID {target_pid} for package '{target}'.")
                break
        
        if not target_pid:
            logger.error(f"Could not find a running process for package '{target}'.")
            return False

    # Attempt to kill using ADB shell kill command
    logger.info(f"Executing ADB shell command to kill PID {target_pid}...")
    kill_command = ["shell", "kill", "-9", target_pid] # Use -9 for forceful termination
    result = run_adb_command(adb_path, kill_command)

    if result.returncode == 0:
        logger.success(f"Successfully killed process with PID {target_pid} ({target}).")
        time.sleep(1) # Give it a moment to terminate
        # Optional: Verify it's no longer running
        check_result = run_adb_command(adb_path, ["shell", f"ps -A | grep {target_pid}"])
        if check_result.returncode != 0 or target_pid not in check_result.stdout:
            logger.info("Process successfully verified as terminated.")
            return True
        else:
            logger.warn("Process might still be running or quickly restarted. Manual verification advised.")
            return False # Return false if still detected, even after kill command returned 0
    else:
        logger.error(f"Failed to kill process with PID {target_pid}. ADB stderr: {result.stderr}")
        logger.info("Ensure you have sufficient permissions (root access).")
        return False


def launch_application_with_script(package_name, script_path):
    """
    Launches an Android application and injects a Frida script into it upon launch.
    Requires `frida-server` to be running on the device.
    
    Args:
        package_name (str): The package name of the application to launch (e.g., "com.example.app").
        script_path (str): Local path to the Frida JS script file.
        
    Returns:
        bool: True if the application was successfully launched with the script, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot launch application with script.")
        return False

    from .device_manager import check_device_connection # Import dynamically
    if not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready.")
        return False

    if not os.path.exists(script_path):
        logger.error(f"Frida script not found at: {script_path}")
        return False

    frida_cli_path = get_tool_path("frida_cli")
    if not frida_cli_path:
        logger.error("Frida CLI tool ('frida') not found.")
        logger.info("Please install it (`pip install frida-tools`) or configure its path.")
        return False
    
    # Check if Frida server is running before attempting to launch with script
    check_frida_running_result = run_adb_command(adb_path, ["shell", f"ps -A | grep {FRIDA_SERVER_NAME_PREFIX}"])
    if check_frida_running_result.returncode != 0 or FRIDA_SERVER_NAME_PREFIX not in check_frida_running_result.stdout:
        logger.error("Frida server is not running on the device. Please run 'burp-frame frida deploy' first.")
        return False

    logger.info(f"Attempting to launch application '{package_name}' and inject script '{script_path}'...")
    
    # Frida command to spawn/attach and inject a script
    # -U: connect to USB device
    # -f <package_name>: spawn the app
    # -l <script_path>: load the script
    # --no-pause: prevent Frida from pausing the spawned app at launch
    command_args = [
        frida_cli_path, "-U", "-f", package_name, "-l", script_path, "--no-pause"
    ]

    try:
        logger.info(f"Executing Frida launch command: {' '.join(command_args)}")
        # This command will block as Frida remains attached to the spawned process.
        # Output will show the Frida agent's activity.
        result = subprocess.run(
            command_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        # Log all output from Frida for debugging
        logger.info(f"Frida CLI STDOUT:\n{result.stdout.strip()}")
        if result.stderr:
            logger.warn(f"Frida CLI STDERR (warnings/errors):\n{result.stderr.strip()}")

        if result.returncode == 0:
            logger.success(f"Successfully launched '{package_name}' with script '{script_path}'.")
            logger.info("Frida CLI will remain attached. Press Ctrl+C to detach when done (this will not kill the app).")
            return True
        else:
            logger.error(f"Failed to launch '{package_name}' with script. Exit code: {result.returncode}.")
            if "frida.core.RPC.FrontEnd.ScriptNotFound" in result.stderr:
                logger.error("Error: Script not found by Frida. Check script_path and Frida server's access.")
            elif "Failed to spawn" in result.stderr:
                logger.error("Error: Failed to spawn the application. Ensure package name is correct and app is installable/launchable.")
            elif "frida-server is not running" in result.stderr:
                logger.error("Error: Frida server is not running on the device. Run 'burp-frame frida deploy'.")
            return False
    except FileNotFoundError:
        logger.error(f"Frida CLI tool not found at '{frida_cli_path}'. Please verify your 'burp-frame config --frida-cli' setting.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during launching application with script: {e}")
        return False

def run_frida_script(script_path, target=None):
    """
    Executes a Frida script against a target application or process on the device.
    It automatically determines the Frida CLI path.
    
    Args:
        script_path (str): Local path to the Frida JS script file.
        target (str, optional): Target application package name (e.g., "com.example.app")
                                or process ID. If None, targets all processes.
    
    Returns:
        bool: True if script execution command was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot ensure device connection for Frida script.")
        return False

    from .device_manager import check_device_connection # Import dynamically to avoid circular dependency
    if not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready for Frida script execution.")
        return False

    if not os.path.exists(script_path):
        logger.error(f"Frida script not found at: {script_path}")
        return False

    frida_cli_path = get_tool_path("frida_cli") 
    if not frida_cli_path:
        logger.error("Frida CLI tool ('frida') not found.")
        logger.info("Please install it (`pip install frida-tools`) or configure its path using: `burp-frame config --frida-cli /path/to/frida-cli`.")
        return False
    
    # Check if Frida server is running before attempting to run a script
    check_frida_running_result = run_adb_command(adb_path, ["shell", f"ps -A | grep {FRIDA_SERVER_NAME_PREFIX}"])
    if check_frida_running_result.returncode != 0 or FRIDA_SERVER_NAME_PREFIX not in check_frida_running_result.stdout:
        logger.error("Frida server is not running on the device. Please run 'burp-frame frida deploy' first.")
        return False

    command_args = [frida_cli_path, "-U"] # -U to connect to USB device
    
    if target:
        # Check if target is a package name (starts with alphabetical char) or PID (digits only)
        if target.isdigit():
            command_args.extend(["-p", target]) # -p for process ID
            logger.info(f"Targeting process ID: {target}")
        else:
            command_args.extend(["-f", target]) # -f for package name
            logger.info(f"Targeting package: {target}")
    else:
        logger.info("No specific target provided for Frida script. Script will attempt to run globally or attach to first process.")
    
    command_args.extend(["-l", script_path]) # -l for script file

    # If targeting a package with -f, --no-pause is often needed to prevent the app from pausing at launch.
    if target and not target.isdigit(): # Assuming it's a package name if not a digit
        command_args.append("--no-pause")

    logger.info(f"Executing Frida script '{script_path}' against target '{target if target else 'globally/first process'}'...")
    
    try:
        logger.info(f"Frida CLI command: {' '.join(command_args)}")
        result = subprocess.run(
            command_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        logger.info(f"Frida CLI STDOUT:\n{result.stdout.strip()}")
        if result.stderr:
            logger.warn(f"Frida CLI STDERR (warnings/errors):\n{result.stderr.strip()}")

        if result.returncode == 0:
            logger.success("Frida script execution command completed.")
            return True
        else:
            logger.error(f"Frida script execution failed. Exit code: {result.returncode}.")
            if "frida.core.RPC.ScriptNotFound" in result.stderr:
                logger.error("Error: Frida script not found by the server. Ensure the path is correct and accessible.")
            elif "Failed to attach" in result.stderr or "unable to find process" in result.stderr:
                logger.error("Error: Failed to attach to target. Ensure the app is running and Frida server is active.")
            elif "frida-server is not running" in result.stderr:
                logger.error("Error: Frida server is not running on the device. Run 'burp-frame frida deploy'.")
            return False
    except FileNotFoundError:
        logger.error(f"Frida CLI tool not found at '{frida_cli_path}'. Please verify your 'burp-frame config --frida-cli' setting.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during Frida script execution: {e}")
        return False
