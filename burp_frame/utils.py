import os
import subprocess
import shutil
from collections import namedtuple

from .logger import Logger # Import the Logger (singleton)
from .config import load_config # Import configuration loading

# Initialize logger for this module (will get the singleton instance)
logger = Logger()

# --- Constants ---
# Define TEMP_CERT_DIR here as it's a general temporary file location related to cleanup
TEMP_CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_cert")

# --- Named Tuple for Command Results ---
# Define this globally in utils.py as it's a generic structure for command outputs
AdbCommandResult = namedtuple('AdbCommandResult', ['stdout', 'stderr', 'returncode'])

def run_adb_command(adb_path, command):
    """
    Executes an ADB command using subprocess and returns a named tuple with results.
    This function is a core utility for any module needing to interact with ADB.
    Args:
        adb_path (str): The absolute path to the ADB executable.
        command (list): A list of strings representing the ADB subcommand and its arguments.
    Returns:
        AdbCommandResult: A named tuple containing stdout, stderr, and returncode.
                          Returns (None, None, 1) if ADB executable is not found.
    """
    try:
        # Log the command execution at DEBUG level (only visible in verbose mode)
        logger.debug(f"Executing ADB command: {adb_path} {' '.join(command)}")
        result = subprocess.run(
            [adb_path] + command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, # Decode stdout/stderr as text
            check=False # Do not raise CalledProcessError for non-zero exit codes
        )
        
        # Log stdout and exit code at DEBUG level
        if result.stdout:
            logger.debug(f"  STDOUT: {result.stdout.strip()}")
        
        if result.stderr:
            # ADB sometimes prints non-error information to stderr (e.g., "1 file pulled").
            # Only log as WARN if it's a non-zero exit code or contains typical error keywords.
            stderr_lower = result.stderr.strip().lower()
            if result.returncode != 0 or "error" in stderr_lower or "failed" in stderr_lower or "permission denied" in stderr_lower:
                logger.warn(f"  STDERR: {result.stderr.strip()}")
            else:
                logger.debug(f"  STDERR (non-critical): {result.stderr.strip()}")
        
        logger.debug(f"  Exit Code: {result.returncode}")

        return AdbCommandResult(result.stdout.strip(), result.stderr.strip(), result.returncode)
    except FileNotFoundError:
        logger.error(f"ADB executable not found at '{adb_path}'. Please ensure ADB is installed and configured correctly.")
        logger.info("Check your 'burp-frame config --adb <path>' setting.")
        return AdbCommandResult(None, None, 1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while running ADB command: {e}")
        return AdbCommandResult(None, None, 1)

def get_tool_path(tool_name):
    """
    Retrieves the absolute path for a specified external tool (e.g., 'adb', 'openssl').
    It first checks the saved configuration, then system's PATH.
    Args:
        tool_name (str): The name of the tool (e.g., 'adb', 'openssl').
    Returns:
        str or None: The absolute path to the tool, or None if not found.
    """
    config = load_config() # Load the global configuration
    config_path = config.get(f"{tool_name}_path")

    # 1. Check if path is configured and exists
    if config_path and os.path.exists(config_path):
        logger.debug(f"Found '{tool_name}' at configured path: {config_path}") # Changed to debug
        return config_path
    
    # 2. Check if tool is in system's PATH
    path_from_env = shutil.which(tool_name)
    if path_from_env:
        logger.debug(f"Found '{tool_name}' in system PATH: {path_from_env}") # Changed to debug
        return path_from_env
    
    # 3. Tool not found
    logger.error(f"'{tool_name}' executable not found in configured path or system PATH.")
    logger.error(f"Please install '{tool_name}' and add it to your system's PATH, or use 'burp-frame config --{tool_name} /path/to/tool' to specify its location.")
    return None

def cleanup_temp_files():
    """
    Removes temporary files and directories created by the framework, especially certs.
    This should be registered to run on application exit.
    """
    if os.path.exists(TEMP_CERT_DIR):
        try:
            shutil.rmtree(TEMP_CERT_DIR)
            logger.info("Cleaned temporary certificate files.")
        except Exception as e:
            logger.error(f"Cleanup of temporary files failed: {str(e)}")
