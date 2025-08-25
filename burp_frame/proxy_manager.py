import os
import re
import json # Used for potential future state management (e.g., per-app proxy tracking)
import time # For potential delays in testing

from .logger import Logger
from .utils import run_command, get_tool_path # Import get_tool_path and run_command from utils

logger = Logger()

def _validate_host_port(host, port):
    """
    Validates the host IP address/hostname and port number.
    
    Args:
        host (str): The host IP address or hostname.
        port (str): The port number as a string.
        
    Returns:
        bool: True if validation passes, False otherwise.
    """
    # Basic IP address validation (IPv4 only)
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) and not re.match(r"^[a-zA-Z0-9.-]+$", host):
        logger.warn(f"Host '{host}' does not appear to be a standard IPv4 address or simple hostname. Proceeding anyway, but ensure it's resolvable by the device.")
    
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            logger.error(f"Invalid port number: {port}. Port must be between 1 and 65535.")
            return False
    except ValueError:
        logger.error(f"Invalid port format: '{port}'. Port must be a number.")
        return False
    
    return True

def set_global_proxy(host, port='8080'):
    """
    Sets the global HTTP proxy settings on the Android device.
    
    Args:
        host (str): The proxy host IP address or hostname.
        port (str): The proxy port. Defaults to '8080'.
    
    Returns:
        bool: True if proxy configuration was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB executable path not configured. Cannot set global proxy.")
        return False

    if not _validate_host_port(host, port):
        return False

    proxy_string = f"{host}:{port}"
    command = ["shell", "settings", "put", "global", "http_proxy", proxy_string]
    description = f"setting global HTTP proxy to {proxy_string}"
    
    logger.info(f"Attempting {description}...")
    result = run_command(adb_path, command)

    if result.returncode == 0:
        logger.success(f"Successfully {description}.")
        return True
    else:
        logger.error(f"Failed to {description}.")
        logger.error(f"ADB stderr: {result.stderr}")
        return False

def clear_global_proxy():
    """
    Clears (reverts) the global HTTP proxy settings on the Android device.
    
    Returns:
        bool: True if proxy settings were cleared successfully, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB executable path not configured. Cannot clear global proxy.")
        return False

    command = ["shell", "settings", "put", "global", "http_proxy", ":0"]
    description = "reverting global HTTP proxy"
    logger.info("Attempting to revert device proxy settings...")
    
    result = run_command(adb_path, command)

    if result.returncode == 0:
        logger.success(f"Successfully {description}.")
        return True
    else:
        logger.error(f"Failed to {description}.")
        logger.error(f"ADB stderr: {result.stderr}")
        return False

def get_current_global_proxy_settings():
    """
    Retrieves the current global HTTP proxy settings from the Android device.
    
    Returns:
        str or None: The current proxy string (e.g., "HOST:PORT") if set,
                     None if no proxy is set or an error occurs.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB executable path not configured. Cannot retrieve proxy settings.")
        return None

    logger.info("Retrieving current global proxy settings...")
    command = ["shell", "settings", "get", "global", "http_proxy"]
    result = run_command(adb_path, command)
    
    if result.returncode == 0 and result.stdout:
        proxy_setting = result.stdout.strip()
        if proxy_setting and proxy_setting != "null" and proxy_setting != ":0": 
            logger.info(f"Current global device proxy: {proxy_setting}")
            return proxy_setting
        else:
            logger.info("No global HTTP proxy is currently set on the device.")
            return None
    else:
        logger.error(f"Failed to retrieve current global proxy settings. ADB stderr: {result.stderr}")
        return None

def test_proxy_connection(test_url="http://google.com"):
    """
    Tests if the currently configured global proxy is working by making a request
    from the device using `curl`.
    
    Args:
        test_url (str): The URL to test the proxy connection with.
        
    Returns:
        bool: True if the test was successful, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB executable path not configured. Cannot test proxy.")
        return False

    current_proxy = get_current_global_proxy_settings() # This logs its own finding
    if not current_proxy:
        logger.warn("No global proxy is set on the device. Cannot perform proxy test without one.")
        return False # Explicitly False, as the test itself cannot proceed without a proxy.

    logger.info(f"Testing proxy connection to {test_url} via {current_proxy}...")
    # Use `curl` on the device to make a request through the proxy.
    # We use --proxy-anyauth to ensure it tries various auth methods if needed,
    # and -v for verbose output that can help debug.
    # Adding a timeout for the curl command.
    command = ["shell", f"curl --proxy {current_proxy} --connect-timeout 5 {test_url}"]
    result = run_command(adb_path, command) # Verbose output from curl will go to stdout/stderr

    if result.returncode == 0:
        logger.success(f"Proxy test to {test_url} succeeded!")
        return True
    else:
        logger.error(f"Proxy test to {test_url} failed. Curl exited with code {result.returncode}.")
        if "Failed to connect to" in result.stderr or "Connection refused" in result.stderr:
            logger.error("Possible issues: Proxy not running, incorrect IP/port, or firewall blocking connection.")
        elif "Could not resolve host" in result.stderr:
            logger.error("Possible issues: DNS resolution issue through proxy, or incorrect hostname.")
        return False

def get_device_ip_addresses():
    """
    Retrieves and displays the active IP addresses on the Android device for various interfaces.
    
    Returns:
        bool: True if IP addresses were retrieved, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB executable path not configured. Cannot retrieve device IPs.")
        return False

    logger.info("Retrieving device IP addresses (Wi-Fi, Mobile, etc.)...")
    command = ["shell", "ip", "addr", "show"]
    result = run_command(adb_path, command)

    if result.returncode == 0 and result.stdout:
        ip_info = result.stdout.strip()
        logger.info("Device Network Interfaces and IPs:")
        found_ips = False
        
        # Regex to find interface name, IPv4, and IPv6 addresses
        # Pattern for interface line: number: name: <flags>
        interface_pattern = r"^\d+:\s+(\w+):" 
        ipv4_pattern = r"inet\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+"
        ipv6_pattern = r"inet6\s([0-9a-fA-F:]+)/\d+"
        
        lines = ip_info.splitlines()
        current_interface_name = "unknown_interface" # Default if not found
        for line in lines:
            line = line.strip()

            # Check for interface name line first
            interface_match = re.match(interface_pattern, line)
            if interface_match:
                current_interface_name = interface_match.group(1) # Extract the interface name (e.g., 'lo', 'eth0', 'wlan0')
                continue # Move to the next line to find IPs for this interface
            
            ipv4_match = re.search(ipv4_pattern, line)
            if ipv4_match:
                ip_address = ipv4_match.group(1)
                logger.info(f"  - {current_interface_name} (IPv4): {ip_address}")
                found_ips = True
            
            ipv6_match = re.search(ipv6_pattern, line)
            if ipv6_match:
                ip_address = ipv6_match.group(1)
                logger.info(f"  - {current_interface_name} (IPv6): {ip_address}")
                found_ips = True
        
        if not found_ips:
            logger.warn("No active IP addresses found on device interfaces.")
        return True
    else:
        logger.error(f"Failed to retrieve device IP addresses. ADB stderr: {result.stderr}")
        return False

# --- Per-App Proxying (Conceptual - Requires more advanced Android techniques) ---
# The functions below are placeholders. A robust implementation would be complex
# and likely involve either integrating with a custom VPN client on the device
# (e.g., via Android's VpnService API) or more advanced Frida scripting.

def set_app_proxy(package_name, host, port='8080'):
    """
    (Conceptual) Attempts to set a proxy for a specific application.
    This is highly dependent on Android version and app implementation.
    A reliable solution often involves a custom VPN on the device or Frida.
    """
    logger.warn(f"Per-app proxying for '{package_name}' is not universally reliable via ADB 'settings put'.")
    logger.info("A robust per-app proxy often requires a custom VPN on the device or Frida instrumentation.")
    logger.info(f"Attempting to set proxy for '{package_name}' to {host}:{port} (might not affect all traffic)...")
    
    adb_path = get_tool_path("adb")
    if not adb_path: return False

    if not _validate_host_port(host, port):
        return False
    
    proxy_string = f"http://{host}:{port}"
    # This command attempts to pass proxy settings via intent extras for a new activity.
    # It's not persistent or comprehensive for all app traffic.
    command = ["shell", "am", "start", "-a", "android.intent.action.VIEW", 
               "-n", f"{package_name}/.MainActivity", "--ez", "http_proxy", proxy_string] # Assuming MainActivity
    
    # Try with "am start -n <package_name>/<main_activity_name>" if known, or just package_name
    # For a general approach, just the package name often attempts to start the default activity.
    # Simplified:
    command_alt = ["shell", "am", "start", "--user", "0", "-a", "android.intent.action.MAIN", "-n", package_name, 
                   "--es", "http_proxy", proxy_string] # --es for string extra

    logger.info(f"Executing conceptual per-app proxy command: {' '.join(command_alt)}")
    result = run_command(adb_path, command_alt) # Using the more general command_alt

    if result.returncode == 0:
        logger.success(f"Attempted to launch '{package_name}' with proxy. Verify manually by checking app's traffic.")
        logger.info("For persistent or comprehensive per-app proxying, consider Frida or a custom VPN.")
        return True
    else:
        logger.error(f"Failed to attempt setting per-app proxy for '{package_name}'. Error: {result.stderr}")
        return False

def clear_app_proxy(package_name):
    """
    (Conceptual) Attempts to clear proxy settings for a specific application.
    Highly dependent on how the proxy was set initially.
    """
    logger.warn(f"Clearing per-app proxy for '{package_name}' is conceptual and might not be effective for all apps.")
    logger.info("If proxy was set via Frida or a VPN, clear it using that method.")
    logger.info("This command only attempts to clear settings applied by 'burp-frame proxy app set'.")

    # In a real scenario, you'd need to reverse the specific setting logic or kill the app.
    # For now, we'll just log and return True, assuming previous 'set' was transient.
    adb_path = get_tool_path("adb")
    if not adb_path: return False

    logger.info(f"Attempting to force stop '{package_name}' to clear potential transient proxy settings.")
    result = run_command(adb_path, ["shell", "am", "force-stop", package_name])
    if result.returncode == 0:
        logger.success(f"Successfully force-stopped '{package_name}'.")
        return True
    else:
        logger.error(f"Failed to force stop '{package_name}'. Error: {result.stderr}")
        return False


def get_app_proxy(package_name):
    """
    (Conceptual) Attempts to retrieve proxy settings for a specific application.
    Not directly possible via standard ADB shell commands for arbitrary apps.
    """
    logger.warn(f"Retrieving per-app proxy settings for '{package_name}' is not directly possible via ADB for arbitrary apps.")
    logger.info("You would typically need dynamic analysis (e.g., Frida) to inspect an app's runtime network configurations.")
    return None

def list_apps_with_proxy_settings_by_tool():
    """
    (Conceptual) Lists applications for which this tool *might* have attempted to set proxy settings.
    Requires internal tracking by the tool (e.g., in config.json).
    """
    logger.warn("Listing apps with per-app proxy settings is conceptual and requires internal tracking by burp-frame.")
    logger.info("This feature would list apps that 'burp-frame proxy app set' has attempted to configure.")
    logger.info("Currently, burp-frame does not maintain a persistent list of per-app proxy configurations.")
    # For now, it's a placeholder. If you implement persistent storage for per-app configs,
    # you would load and display them here.
    return True # Indicate command execution success, even if list is empty
