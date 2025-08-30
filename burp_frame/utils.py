# burp_frame/utils.py

import os
import subprocess
import shutil
import tempfile
import sys
import shlex  # For robust command quoting
from collections import namedtuple
from typing import List, Optional

from .logger import Logger
from .config import load_config

logger = Logger()

# --- Constants ---
# Define the main temporary directory for the framework
FRAMEWORK_TEMP_DIR = os.path.join(tempfile.gettempdir(), "burp-frame")
TEMP_CERT_DIR = os.path.join(FRAMEWORK_TEMP_DIR, "temp_certs")

# --- Named Tuple for Command Results ---
# A generic and reusable structure for all command outputs.
CommandResult = namedtuple('CommandResult', ['stdout', 'stderr', 'returncode'])

# --- Core Utility Functions ---

def create_temp_dir() -> None:
    """
    Creates the main temporary directory for the framework if it doesn't exist.
    """
    try:
        os.makedirs(FRAMEWORK_TEMP_DIR, exist_ok=True)
        logger.debug(f"Ensured framework temporary directory exists at: {FRAMEWORK_TEMP_DIR}")
    except OSError as e:
        logger.error(f"Failed to create temporary directory at {FRAMEWORK_TEMP_DIR}: {e}")

def run_command(command: List[str], timeout: int = 300) -> CommandResult:
    """
    Executes a shell command and returns a named tuple with results.
    This is a centralized function for all command execution.

    Args:
        command (list): A list of strings representing the command and its arguments.
        timeout (int): The maximum time in seconds to wait for the command to complete.

    Returns:
        CommandResult: A named tuple containing stdout, stderr, and returncode.
    """
    command_str = ' '.join(shlex.quote(arg) for arg in command)
    logger.info(f"Executing command: {command_str}")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )

        if result.stdout:
            logger.info(f"  STDOUT: {result.stdout.strip()}")
        if result.stderr:
            logger.warn(f"  STDERR: {result.stderr.strip()}")
        logger.info(f"  Exit Code: {result.returncode}")

        return CommandResult(result.stdout.strip(), result.stderr.strip(), result.returncode)

    except FileNotFoundError:
        logger.error(f"Executable not found: '{command[0]}'. Please check your configuration and system PATH.")
        return CommandResult("", "Executable not found", 1)
    except PermissionError:
        logger.error(f"Permission denied to execute: '{command[0]}'. Please check file permissions.")
        return CommandResult("", "Permission denied", 1)
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds.")
        return CommandResult("", "Command timed out", 1)
    except OSError as e:
        logger.error(f"OS error while running command '{command_str}': {e}")
        return CommandResult("", str(e), 1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while running command '{command_str}': {e}", exc_info=sys.exc_info())
        return CommandResult("", "An unexpected error occurred", 1)

def run_adb_command(adb_path: str, command: List[str]) -> CommandResult:
    """
    A specialized wrapper for running ADB commands.
    It constructs the full command list and passes it to the generic `run_command`.
    
    Args:
        adb_path (str): The absolute path to the ADB executable.
        command (list): A list of strings representing the ADB subcommand and its arguments.

    Returns:
        CommandResult: A named tuple with stdout, stderr, and returncode.
    """
    # Defensive check to ensure a valid ADB path is provided before running.
    if not adb_path or not os.path.exists(adb_path):
        logger.error(f"ADB executable not found at '{adb_path}'. Cannot execute command.")
        return CommandResult(None, "ADB path not found or invalid.", 1)
        
    full_command = [adb_path] + command
    return run_command(full_command)

def get_tool_path(tool_name: str) -> Optional[str]:
    """
    Retrieves the absolute path for a specified external tool (e.g., 'adb', 'openssl').
    It first checks the saved configuration, then the system's PATH.

    Args:
        tool_name (str): The name of the tool (e.g., 'adb', 'openssl').

    Returns:
        str or None: The absolute path to the tool, or None if not found.
    """
    config = load_config()
    config_path = config.get(f"{tool_name}_path")

    # 1. Check if path is configured and exists
    if config_path and os.path.exists(config_path):
        logger.info(f"Found '{tool_name}' at configured path: {config_path}")
        return config_path
    
    # 2. Check if tool is in system's PATH
    path_from_env = shutil.which(tool_name)
    if path_from_env:
        logger.info(f"Found '{tool_name}' in system PATH: {path_from_env}")
        return path_from_env
    
    # 3. Tool not found
    logger.error(f"'{tool_name}' executable not found in configured path or system PATH.")
    logger.error(f"Please install '{tool_name}' and add it to your system's PATH, or use 'burp-frame config --{tool_name} /path/to/tool' to specify its location.")
    return None

def cleanup_temp_files() -> None:
    """
    Removes temporary files and directories created by the framework.
    """
    if os.path.exists(FRAMEWORK_TEMP_DIR):
        try:
            shutil.rmtree(FRAMEWORK_TEMP_DIR)
            logger.info("Cleaned temporary files.")
        except Exception as e:
            logger.error(f"Cleanup of temporary files failed: {e}")