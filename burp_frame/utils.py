# burp_frame/utils.py

import os
import subprocess
import shutil
import tempfile
from collections import namedtuple
from pathlib import Path

# Import the Logger (singleton) from the main package
# Assuming burp_frame is the package name at the root
from .logger import Logger 
from .config import load_config # Import configuration loading

# Initialize logger for this module (will get the singleton instance)
logger = Logger()

# --- Constants ---
# Define a general temporary directory for the framework
FRAMEWORK_TEMP_DIR = os.path.join(tempfile.gettempdir(), "burp-frame")
TEMP_CERT_DIR = os.path.join(FRAMEWORK_TEMP_DIR, "temp_certs")

# --- Named Tuple for Command Results ---
# Define this globally as it's a generic structure for command outputs
CommandResult = namedtuple('CommandResult', ['stdout', 'stderr', 'returncode'])

# --- Utility Functions ---

def create_temp_dir():
    """
    Creates the main temporary directory for the framework if it doesn't exist.
    """
    os.makedirs(FRAMEWORK_TEMP_DIR, exist_ok=True)
    logger.debug(f"Ensured framework temporary directory exists at: {FRAMEWORK_TEMP_DIR}")

def run_command(command, executable_path=None):
    """
    Executes a shell command and returns a named tuple with results.
    This is a generic function to be used for any external command, not just ADB.

    Args:
        command (list): A list of strings representing the command and its arguments.
        executable_path (str, optional): The absolute path to the executable. If None,
                                        the function assumes the executable is in PATH.
    
    Returns:
        CommandResult: A named tuple containing stdout, stderr, and returncode.
                       Returns (None, None, 1) if the executable is not found.
    """
    full_command = [executable_path] + command if executable_path else command
    command_str = ' '.join(full_command)
    
    try:
        logger.debug(f"Executing command: {command_str}")
        
        result = subprocess.run(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # Decode stdout/stderr as text
            check=False, # Do not raise CalledProcessError
        )
        
        # Log stdout and stderr at DEBUG level
        if result.stdout:
            logger.debug(f"  STDOUT: {result.stdout.strip()}")
        if result.stderr:
            logger.debug(f"  STDERR: {result.stderr.strip()}")

        return CommandResult(result.stdout.strip(), result.stderr.strip(), result.returncode)
    
    except FileNotFoundError:
        logger.error(f"Executable not found for command: '{full_command[0]}'.")
        return CommandResult(None, None, 1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while running command '{full_command[0]}': {e}")
        return CommandResult(None, None, 1)

def get_tool_path(tool_name):
    """
    Retrieves the absolute path for a specified external tool (e.g., 'adb', 'openssl').
    It first checks the saved configuration, then system's PATH.
    
    Args:
        tool_name (str): The name of the tool (e.g., 'adb', 'openssl').
    
    Returns:
        str or None: The absolute path to the tool, or None if not found.
    """
    config = load_config()  # Load the global configuration
    config_path = config.get(f"{tool_name}_path")

    # 1. Check if path is configured and exists
    if config_path and os.path.exists(config_path):
        logger.debug(f"Found '{tool_name}' at configured path: {config_path}")
        return config_path
    
    # 2. Check if tool is in system's PATH
    path_from_env = shutil.which(tool_name)
    if path_from_env:
        logger.debug(f"Found '{tool_name}' in system PATH: {path_from_env}")
        return path_from_env
    
    # 3. Tool not found
    logger.error(f"'{tool_name}' executable not found in configured path or system PATH.")
    logger.error(f"Please install '{tool_name}' and add it to your system's PATH, or use 'burp-frame config --{tool_name} /path/to/tool' to specify its location.")
    return None

def cleanup_temp_files():
    """
    Removes temporary files and directories created by the framework.
    This should be registered to run on application exit.
    """
    if os.path.exists(FRAMEWORK_TEMP_DIR):
        try:
            shutil.rmtree(FRAMEWORK_TEMP_DIR)
            logger.info("Cleaned temporary files.")
        except Exception as e:
            logger.error(f"Cleanup of temporary files failed: {e}")