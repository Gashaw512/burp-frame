#!/usr/bin/env python3
import argparse
import sys
import atexit
import os
import json

# --- DEBUGGING LINE ---
# This line will print the absolute path of the cli.py file being executed.
# This helps confirm if you're running the correct version.
print(f"DEBUG: Running cli.py from: {os.path.abspath(__file__)}")
# --- END DEBUGGING LINE ---

# Import core utilities and managers
from .logger import Logger
from .config import load_config, save_config
from .utils import get_tool_path, cleanup_temp_files
from .device_manager import (
    check_device_connection, get_android_version, perform_install_certificate,
    reboot_device, remount_system_rw, remount_system_ro,
    list_adb_connected_devices, install_apk, uninstall_package,
    connect_adb_device, disconnect_adb_device
)
from .cert_manager import get_cert_file, convert_cert
from .proxy_manager import (
    set_global_proxy, clear_global_proxy, get_current_global_proxy_settings,
    test_proxy_connection, get_device_ip_addresses,
    set_app_proxy, clear_app_proxy, get_app_proxy, list_apps_with_proxy_settings_by_tool
)
from .frida_manager import (
    deploy_frida_server, run_frida_script, list_processes, kill_frida_process,
    launch_application_with_script
)
from .bypass_ssl_manager import (
    list_bypass_scripts, download_generic_bypass_script, apply_bypass_script
)
# Note: Replaced with new unified managers
# from .modules.universal_bypass_manager import AndroidDeviceManager, FridaBypassManager
# from .modules.frida_cert_repin_bypass import apply_frida_cert_repin_bypass

# NEW: Import the unified modules for detection and bypass
from .modules.detection.universal_detector import run_detection
from .modules.bypass.bypass_auto_manager import apply_auto_bypass

# --- Constants ---
VERSION = "1.0.0"  # Framework version
logger = Logger()  # Instantiate Logger first

# Comprehensive HELP_TEXT for the unified framework
HELP_TEXT = f"""
=====================================================
Burp-Frame v{VERSION} - Unified Android PenTesting Framework
=====================================================
Streamline your mobile security assessments with powerful, automated tools.

Commands:
  install            Install Burp Suite CA certificate on Android devices.
  proxy              Configure device HTTP proxy settings for traffic interception.
  frida              Deploy and interact with Frida for dynamic instrumentation.
  bypass-ssl         Manage and apply Frida SSL pinning bypass scripts.
  detect             Run a comprehensive scan to detect security countermeasures.
  bypass             Automatically apply bypasses based on detected countermeasures.
  device             Manage Android device state and installed applications.
  config             Manage paths for external tools (ADB, OpenSSL).
  logs               View detailed operation logs.
  help               Show this help message.

For command-specific help: burp-frame [command] --help
"""

# Register cleanup function to run when the script exits
atexit.register(cleanup_temp_files)


# --- Command Flow Functions (Partial - Assumed from previous context) ---

def _install_flow(args, config):
    logger.info("Initiating certificate installation process...")
    # ... (Actual implementation is omitted for brevity) ...
    return True

def _proxy_flow(args, config):
    logger.info("Initiating device proxy configuration...")
    # ... (Actual implementation is omitted for brevity) ...
    return True

def _frida_flow(args, config):
    logger.info("Frida module functionality is being utilized.")
    # ... (Actual implementation is omitted for brevity) ...
    return True

def _bypass_ssl_flow(args, config):
    logger.info("Initiating SSL Pinning Bypass operations...")
    # ... (Actual implementation is omitted for brevity) ...
    return True

def _universal_bypass_flow(args, config):
    logger.info("Initiating Universal Android Security Bypass...")
    # ... (Actual implementation is omitted for brevity) ...
    return True

def _device_flow(args, config):
    logger.info("Initiating device management operations...")
    # ... (Actual implementation is omitted for brevity) ...
    return True

# --- Command Flow Functions (Provided by user) ---
def _config_flow(args, config):
    """Handles the 'config' command logic (managing tool paths)."""
    new_config = config.copy()
    
    updated_any = False
    
    if args.adb:
        abs_path = os.path.abspath(args.adb)
        if os.path.exists(abs_path):
            new_config['adb_path'] = abs_path
            logger.success(f"ADB path set to: {abs_path}")
            updated_any = True
        else:
            logger.error(f"Path not found: {args.adb}")
            return False

    if args.openssl:
        abs_path = os.path.abspath(args.openssl)
        if os.path.exists(abs_path):
            new_config['openssl_path'] = abs_path
            logger.success(f"OpenSSL path set to: {abs_path}")
            updated_any = True
        else:
            logger.error(f"Path not found: {args.openssl}")
            return False

    if args.frida_server_binary:
        abs_path = os.path.abspath(args.frida_server_binary)
        if os.path.exists(abs_path):
            new_config['frida_server_binary_path'] = abs_path
            logger.success(f"Frida server binary path set to: {abs_path}")
            updated_any = True
        else:
            logger.error(f"Path not found: {args.frida_server_binary}")
            return False

    if args.frida_cli:
        abs_path = os.path.abspath(args.frida_cli)
        if os.path.exists(abs_path):
            new_config['frida_cli_path'] = abs_path
            logger.success(f"Frida CLI path set to: {abs_path}")
            updated_any = True
        else:
            logger.error(f"Path not found: {args.frida_cli}")
            return False
    
    if not updated_any and not args.adb and not args.openssl and not args.frida_server_binary and not args.frida_cli:
        logger.info("Current configuration:")
        if new_config:
            for key, value in new_config.items():
                logger.info(f"- {key}: {value}")
        else:
            logger.info("No paths configured yet.")
        logger.info("\nTo set paths, use: burp-frame config --adb \"/path/to/adb\"")
    
    save_config(new_config)
    return True

def _logs_flow(args, config):
    """Handles the 'logs' command logic (viewing log files)."""
    logger.info("Viewing recent logs...")
    logs_dir = logger.log_dir
    
    if not os.path.exists(logs_dir) or not os.listdir(logs_dir):
        logger.info("No log files available.")
        return False
    
    logs = [f for f in os.listdir(logs_dir) if f.startswith('burp-frame_') and f.endswith('.log')]
    logs.sort(reverse=True)
    
    if not logs:
        logger.info("No 'burp-frame' log files found.")
        return False

    print("\nRecent Log Files (most recent first):")
    for i, log in enumerate(logs[:5], 1):
        print(f"  {i}. {log}")
    
    try:
        selection = input("\nEnter log number to view (or Enter to go back): ").strip()
        if not selection:
            return True
            
        index = int(selection) - 1
        if 0 <= index < len(logs):
            log_file = os.path.join(logs_dir, logs[index])
            print("\n" + "="*80)
            print(f" Log File: {log_file} ".center(80))
            print("="*80)
            with open(log_file, 'r', encoding='utf-8') as f:
                print(f.read())
            print("="*80)
            print("End of log".center(80))
            print("="*80)
            return True
        else:
            logger.error("Invalid log number selection.")
            return False
    except ValueError:
        logger.error("Please enter a valid number.")
        return False
    except Exception as e:
        logger.error(f"Error viewing log file: {str(e)}")
        return False

# --- NEW Command Flow Functions ---
def _detect_flow(args, config):
    """Handles the 'detect' command logic."""
    logger.info("Initiating security countermeasure detection...")
    results = run_detection(args.package, attach=args.attach)
    if results:
        print("\n--- Detection Results ---")
        print(json.dumps(results, indent=2))
        return True
    else:
        logger.error("Detection failed or returned no results.")
        return False

def _bypass_flow(args, config):
    """Handles the 'bypass' command logic."""
    logger.info("Initiating automatic bypass process...")
    success = apply_auto_bypass(args.package, attach=args.attach)
    if success:
        logger.success("Automatic bypass process completed successfully.")
    else:
        logger.error("Automatic bypass process failed.")
    return success

# --- Main Parser and Dispatcher ---
def parse_arguments():
    """Configures and parses command-line arguments for the framework."""
    parser = argparse.ArgumentParser(
        description=f"burp-frame v{VERSION} - A unified penetration testing framework for Android.",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    # Global options
    parser.add_argument('--version', action='version', version=f'burp-frame v{VERSION}', help='Show framework version and exit.')
    parser.add_argument('--help', action='store_true', help='Show general help message and exit.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging for detailed output.')

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Framework Commands')

    # 'install' subcommand
    install_parser = subparsers.add_parser(
        'install',
        help='Install Burp Suite CA certificate on an Android device.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    install_parser.add_argument('--dry-run', action='store_true', help='Simulate the installation without modifying the device.')
    install_parser.add_argument('--magisk', action='store_true', help='Install certificate for Magisk systemless root (requires Magisk module).')

    # 'proxy' subcommand
    proxy_parser = subparsers.add_parser(
        'proxy',
        help='Configure device HTTP proxy settings for traffic interception.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    proxy_subsubparsers = proxy_parser.add_subparsers(dest='proxy_command', help='Proxy Commands')
    proxy_set_parser = proxy_subsubparsers.add_parser('set', help='Set the global HTTP proxy.')
    proxy_set_parser.add_argument('host_port', metavar='HOST:PORT', help='Host and port for the proxy (e.g., 192.168.1.100:8080).')
    proxy_clear_parser = proxy_subsubparsers.add_parser('clear', help='Clear the global HTTP proxy.')
    proxy_get_parser = proxy_subsubparsers.add_parser('get', help='Get the current global HTTP proxy settings.')
    proxy_test_parser = proxy_subsubparsers.add_parser('test', help='Test the global HTTP proxy connection.')
    proxy_test_parser.add_argument('--url', default='http://google.com', help='URL to test connectivity with (default: http://google.com).')
    proxy_ips_parser = proxy_subsubparsers.add_parser('ips', help='Display device IP addresses and network interfaces.')
    proxy_app_parser = proxy_subsubparsers.add_parser(
        'app',
        help='Manage per-application proxy settings (conceptual/limited via ADB).',
        formatter_class=argparse.RawTextHelpFormatter
    )
    proxy_app_subsubparsers = proxy_app_parser.add_subparsers(dest='app_command', help='Per-App Proxy Commands')
    proxy_app_set_parser = proxy_app_subsubparsers.add_parser('set', help='Set proxy for a specific app (conceptual).')
    proxy_app_set_parser.add_argument('package_name', help='Package name of the target application (e.g., com.example.app).')
    proxy_app_set_parser.add_argument('host_port', metavar='HOST:PORT', help='Host and port for the app proxy.')
    proxy_app_clear_parser = proxy_app_subsubparsers.add_parser('clear', help='Clear proxy for a specific app (conceptual).')
    proxy_app_clear_parser.add_argument('package_name', help='Package name of the target application.')
    proxy_app_get_parser = proxy_app_subsubparsers.add_parser('get', help='Get proxy for a specific app (conceptual).')
    proxy_app_get_parser.add_argument('package_name', help='Package name of the target application.')
    proxy_app_list_parser = proxy_app_subsubparsers.add_parser('list', help='List apps with per-app proxy settings (conceptual).')

    # 'frida' subcommand
    frida_parser = subparsers.add_parser(
        'frida',
        help='Deploy and interact with Frida for dynamic instrumentation.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    frida_subsubparsers = frida_parser.add_subparsers(dest='frida_command', help='Frida Subcommands')
    frida_deploy_parser = frida_subsubparsers.add_parser('deploy', help='Deploy Frida server to the device.')
    frida_script_parser = frida_subsubparsers.add_parser('script', help='Run a Frida script.')
    frida_script_parser.add_argument('--script', required=True, help='Path to the Frida JS script to run locally.')
    frida_script_parser.add_argument('--target', help='Target application (e.g., com.example.app) or process ID for the script.')
    frida_ps_parser = frida_subsubparsers.add_parser('ps', help='List all running processes on the device.')
    frida_kill_parser = frida_subsubparsers.add_parser('kill', help='Kill a process by PID or package name.')
    frida_kill_parser.add_argument('target', help='Process ID (PID) or package name of the target to kill.')
    frida_launch_parser = frida_subsubparsers.add_parser('launch', help='Launch an app and inject a Frida script.')
    frida_launch_parser.add_argument('package_name', help='Package name of the application to launch.')
    frida_launch_parser.add_argument('--script', required=True, help='Path to the Frida JS script to inject.')
    frida_cert_repin_parser = frida_subsubparsers.add_parser(
        'cert-repin',
        help='Apply a specific Frida script to bypass SSL pinning by injecting a custom CA certificate.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    frida_cert_repin_parser.add_argument('package_name', help='Package name of the target application (e.g., com.example.app).')
    frida_cert_repin_parser.add_argument('--cert', required=True, help='Path to the local .der or .0 certificate file (e.g., /path/to/burp.0).')
    frida_cert_repin_parser.add_argument('--attach', action='store_true', help='Attach to a running app instead of launching it.')

    # 'bypass-ssl' subcommand
    bypass_ssl_parser = subparsers.add_parser(
        'bypass-ssl',
        help='Manage and apply Frida SSL pinning bypass scripts.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    bypass_ssl_subsubparsers = bypass_ssl_parser.add_subparsers(dest='bypass_ssl_command', help='Bypass SSL Commands')
    bypass_ssl_list_parser = bypass_ssl_subsubparsers.add_parser('list', help='List available local SSL bypass scripts.')
    bypass_ssl_download_parser = bypass_ssl_subsubparsers.add_parser('download', help='Download a generic SSL bypass script from a public source.')
    bypass_ssl_apply_parser = bypass_ssl_subsubparsers.add_parser('apply', help='Apply a local SSL bypass script to a target application.')
    bypass_ssl_apply_parser.add_argument('package_name', help='Package name of the target application.')
    bypass_ssl_apply_parser.add_argument('--script', required=True, help='Filename of the bypass script (must be in the scripts directory).')
    bypass_ssl_apply_parser.add_argument('--target-running', action='store_true', 
                                         help='Attach to a running app instead of launching it (default is launch).')

    # 'universal-bypass' subcommand
    universal_bypass_parser = subparsers.add_parser(
        'universal-bypass',
        help='Apply a comprehensive Frida script to bypass various security checks (SSL, debugger, root, emulator).',
        formatter_class=argparse.RawTextHelpFormatter
    )
    universal_bypass_parser.add_argument('package', help='Target Android package name (e.g., com.example.app).')
    universal_bypass_parser.add_argument('-a', '--attach', action='store_true', help='Attach to a running app instead of launching it.')

    # 'device' subcommand
    device_parser = subparsers.add_parser(
        'device',
        help='Manage Android device state (reboot, remount) and applications (install, uninstall, connect).',
        formatter_class=argparse.RawTextHelpFormatter
    )
    device_subsubparsers = device_parser.add_subparsers(dest='device_command', help='Device Management Commands')
    device_reboot_parser = device_subsubparsers.add_parser('reboot', help='Reboot the connected Android device.')
    device_remount_rw_parser = device_subsubparsers.add_parser('remount-rw', help='Remount /system partition as read-write (requires root).')
    device_remount_ro_parser = device_subsubparsers.add_parser('remount-ro', help='Remount /system partition as read-only (requires root).')
    device_ls_parser = device_subsubparsers.add_parser('ls', help='List all connected ADB devices and their properties.')
    device_install_parser = device_subsubparsers.add_parser('install', help='Install an APK file onto the device.')
    device_install_parser.add_argument('apk_path', help='Local path to the APK file.')
    device_uninstall_parser = device_subsubparsers.add_parser('uninstall', help='Uninstall an application by package name.')
    device_uninstall_parser.add_argument('package_name', help='Package name of the application to uninstall (e.g., com.example.app).')
    device_connect_parser = device_subsubparsers.add_parser('connect', help='Connect to a device over TCP/IP (e.g., 192.168.1.10:5555).')
    device_connect_parser.add_argument('ip_address_port', metavar='IP_ADDRESS[:PORT]', help='IP address and optional port (default 5555).')
    device_disconnect_parser = device_subsubparsers.add_parser('disconnect', help='Disconnect from a device over TCP/IP (e.g., 192.168.1.10:5555).')
    device_disconnect_parser.add_argument('ip_address_port', metavar='IP_ADDRESS[:PORT]', help='IP address and optional port (default 5555).')

    # 'config' subcommand
    config_parser = subparsers.add_parser(
        'config',
        help='Configure paths for external tools like ADB, OpenSSL, and Frida.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    config_parser.add_argument('--adb', help='Path to the ADB executable (e.g., C:\\platform-tools\\adb.exe or /usr/bin/adb).')
    config_parser.add_argument('--openssl', help='Path to the OpenSSL executable (e.g., C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe or /usr/bin/openssl).')
    config_parser.add_argument('--frida-server-binary', help='Path to the manually downloaded Frida server binary (e.g., frida-server-android-arm64).')
    config_parser.add_argument('--frida-cli', help='Path to the Frida CLI tool (e.g., /usr/local/bin/frida).')

    # 'logs' subcommand
    logs_parser = subparsers.add_parser(
        'logs',
        help='View recent operation logs generated by the framework.',
        formatter_class=argparse.RawTextHelpFormatter 
    )

    # NEW: 'detect' command
    detect_parser = subparsers.add_parser('detect', help='Run a comprehensive detection scan for security countermeasures.')
    detect_parser.add_argument('package', type=str, help='The package name of the application to analyze.')
    detect_parser.add_argument('--attach', action='store_true', help='Attach to a running app instead of spawning a new one.')

    # NEW: 'bypass' command
    bypass_parser = subparsers.add_parser('bypass', help='Automatically apply bypasses based on detected countermeasures.')
    bypass_parser.add_argument('package', type=str, help='The package name of the application to analyze and bypass.')
    bypass_parser.add_argument('--attach', action='store_true', help='Attach to a running app instead of spawning a new one.')

    args = parser.parse_args()
    
    if not hasattr(args, 'command') and not args.help:
        parser.print_help()
        sys.exit(1)
    
    return args

# --- Main Entry Point ---
def main():
    """Main function to parse arguments and execute commands."""
    args = parse_arguments()
    
    if hasattr(args, 'verbose') and args.verbose:
        logger.set_level("DEBUG")

    logger.info(f"Starting Burp-Frame v{VERSION}")
    
    if args.help:
        print(HELP_TEXT)
        return
    
    atexit.register(cleanup_temp_files)

    config = load_config()

    command_executed = False
    if args.command == 'install':
        command_executed = _install_flow(args, config)
    elif args.command == 'proxy':
        command_executed = _proxy_flow(args, config)
    elif args.command == 'frida':
        command_executed = _frida_flow(args, config)
    elif args.command == 'bypass-ssl':
        command_executed = _bypass_ssl_flow(args, config)
    elif args.command == 'universal-bypass':
        command_executed = _universal_bypass_flow(args, config)
    elif args.command == 'device':
        command_executed = _device_flow(args, config)
    elif args.command == 'config':
        command_executed = _config_flow(args, config)
    elif args.command == 'logs':
        command_executed = _logs_flow(args, config)
    # NEW command dispatchers
    elif args.command == 'detect':
        command_executed = _detect_flow(args, config)
    elif args.command == 'bypass':
        command_executed = _bypass_flow(args, config)
    else:
        logger.error("No valid command provided. Use 'burp-frame --help' for usage.")
        sys.exit(1)

    if command_executed:
        logger.info(f"Command '{args.command}' finished successfully.")
    else:
        logger.error(f"Command '{args.command}' failed or was interrupted.")
        sys.exit(1)

if __name__ == "__main__":
    main()