#!/usr/bin/env python3
import argparse
import sys
import atexit
import os

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
# NEW: Import from the new universal_bypass_manager module
from .modules.universal_bypass_manager import AndroidDeviceManager, FridaBypassManager


# --- Constants ---
VERSION = "1.0.0" # Framework version
logger = Logger()

# Comprehensive HELP_TEXT for the unified framework
HELP_TEXT = f"""
=====================================================
Burp-Frame v{VERSION} - Unified Android PenTesting Framework
=====================================================
Streamline your mobile security assessments with powerful, automated tools.

Commands:
  install           Install Burp Suite CA certificate on Android devices.
  proxy             Configure device HTTP proxy settings for traffic interception.
  frida             Deploy and interact with Frida for dynamic instrumentation.
  bypass-ssl        Manage and apply Frida SSL pinning bypass scripts.
  universal-bypass  Apply a comprehensive Frida script to bypass various security checks.
  device            Manage Android device state and installed applications.
  config            Manage paths for external tools (ADB, OpenSSL).
  logs              View detailed operation logs.
  help              Show this help message.

Options:
  --version         Display framework version.
  --help            Show detailed help for commands.

Examples:
  burp-frame install --magisk                 # Install Burp cert via Magisk
  burp-frame proxy set --host 192.168.1.100 --port 8080 # Set device global proxy
  burp-frame frida deploy                     # Deploy Frida server
  burp-frame bypass-ssl download              # Download a generic bypass script
  burp-frame bypass-ssl apply com.example.app --script universal_bypass.js # Apply specific bypass
  burp-frame universal-bypass com.example.app # Apply universal bypass (launch app)
  burp-frame device ls                        # List connected ADB devices
  burp-frame device connect 192.168.1.50      # Connect to a device over TCP/IP (default port 5555)
  burp-frame device reboot                    # Reboot the connected device
  burp-frame device install app.apk           # Install an APK
  burp-frame config --adb "/usr/bin/adb"      # Set ADB executable path
  burp-frame logs                             # View recent logs

For command-specific help: burp-frame [command] --help
"""

# Register cleanup function to run when the script exits
atexit.register(cleanup_temp_files)


# --- Command Flow Functions ---

def _install_flow(args, config):
    """Handles the 'install' command logic (CA certificate installation)."""
    logger.info("Initiating certificate installation process...")
    
    adb_path = get_tool_path("adb")
    openssl_path = get_tool_path("openssl")

    if not adb_path or not openssl_path:
        logger.error("Required tools (ADB or OpenSSL) not found/configured. Please run 'burp-frame config'.")
        return False

    if not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready.")
        return False

    android_version = get_android_version(adb_path)
    if android_version:
        try:
            if float(android_version) >= 7.0:
                logger.warn(f"Android {android_version} detected. Certificate pinning is common on this version.")
                logger.warn("This tool only installs the CA certificate. You may need Frida to bypass pinning for some apps.")
        except ValueError:
            logger.warn(f"Could not parse Android version: {android_version}. Proceeding with installation.")
    
    try:
        cert_local_der_path = get_cert_file()
    except KeyboardInterrupt:
        logger.warn("\nCertificate path input cancelled by user (Ctrl+C). Installation aborted.")
        return False

    if not cert_local_der_path:
        logger.error("Certificate file selection cancelled or failed.")
        return False
    
    cert_prepared_file, cert_hash = convert_cert(cert_local_der_path, openssl_path)
    if not cert_prepared_file or not cert_hash:
        logger.error("Certificate conversion failed. Please ensure your .der file is valid and OpenSSL is functional.")
        return False
    

    if perform_install_certificate(adb_path, cert_prepared_file, cert_hash, args.dry_run, args.magisk):
        logger.success("\n" + "="*60)
        if args.dry_run:
            logger.success("DRY RUN COMPLETE: No changes were made.".center(60))
        else:
            logger.success("CERTIFICATE INSTALLED SUCCESSFULLY!".center(60))
        logger.success("="*60)
        logger.info("You can now attempt to intercept HTTPS traffic in Burp Suite.")
        return True
    else:
        logger.error("Certificate installation failed.")
        return False


def _proxy_flow(args, config):
    """Handles the 'proxy' command logic (device proxy configuration)."""
    logger.info("Initiating device proxy configuration...")

    if not check_device_connection(get_tool_path("adb")):
        logger.error("No Android device detected or device is not ready for proxy configuration.")
        return False
    
    if args.proxy_command == 'set':
        host_port = args.host_port.split(':')
        host = host_port[0]
        port = host_port[1] if len(host_port) > 1 else "8080"
        return set_global_proxy(host=host, port=port)
    
    elif args.proxy_command == 'clear':
        return clear_global_proxy()
    
    elif args.proxy_command == 'get':
        proxy_info = get_current_global_proxy_settings()
        # Always return True for 'get' as it successfully retrieved the information, regardless of proxy presence
        return True 
    
    elif args.proxy_command == 'test':
        # The test_proxy_connection function will handle logging its own success/failure.
        # It also explicitly returns False if no proxy is set, which is desired for the test's outcome.
        return test_proxy_connection(args.url) 

    elif args.proxy_command == 'ips':
        return get_device_ip_addresses()

    elif args.proxy_command == 'app':
        if args.app_command == 'set':
            host_port = args.host_port.split(':')
            host = host_port[0]
            port = host_port[1] if len(host_port) > 1 else "8080"
            return set_app_proxy(args.package_name, host=host, port=port)
        elif args.app_command == 'clear':
            return clear_app_proxy(args.package_name)
        elif args.app_command == 'get':
            return get_app_proxy(args.package_name)
        elif args.app_command == 'list':
            return list_apps_with_proxy_settings_by_tool()

    return False


def _frida_flow(args, config):
    """Handles the 'frida' command logic (Frida deployment and interaction)."""
    logger.info("Frida module functionality is being utilized.") # Updated message

    if not check_device_connection(get_tool_path("adb")):
        logger.error("No Android device detected or device is not ready for Frida operations.")
        return False
    
    if args.frida_command == 'deploy':
        return deploy_frida_server()

    elif args.frida_command == 'script':
        return run_frida_script(args.script, args.target)
    
    elif args.frida_command == 'ps':
        processes = list_processes()
        if processes:
            logger.info("Active Processes:")
            # Print header
            print(f"{'USER':<10} {'PID':<8} {'NAME':<50}")
            print(f"{'-'*10:<10} {'-'*8:<8} {'-'*50:<50}")
            for p in processes:
                print(f"{p['user']:<10} {p['pid']:<8} {p['name']:<50}")
            return True
        else:
            logger.info("No processes found or unable to retrieve list.")
            return False

    elif args.frida_command == 'kill':
        # args.target is defined by the parser for 'kill' subcommand
        if not args.target:
            logger.error("Error: A target (PID or package name) is required for 'frida kill'.")
            return False
        return kill_frida_process(args.target)

    elif args.frida_command == 'launch':
        if not args.package_name or not args.script:
            logger.error("Error: --package-name and --script are required for 'frida launch'.")
            return False
        return launch_application_with_script(args.package_name, args.script)

    return False

def _bypass_ssl_flow(args, config):
    """Handles the 'bypass-ssl' command logic (SSL Pinning Bypass)."""
    logger.info("Initiating SSL Pinning Bypass operations...")

    # For 'download' command, device connection isn't strictly necessary.
    # For 'list' command, device connection isn't strictly necessary.
    # For 'apply' command, device connection IS necessary.
    if args.bypass_ssl_command == 'apply' and not check_device_connection(get_tool_path("adb")):
        logger.error("No Android device detected or device is not ready for applying bypass scripts.")
        return False
    
    if args.bypass_ssl_command == 'list':
        return list_bypass_scripts()
    
    elif args.bypass_ssl_command == 'download':
        return download_generic_bypass_script()
    
    elif args.bypass_ssl_command == 'apply':
        if not args.package_name or not args.script:
            logger.error("Error: --package-name and --script are required for 'bypass-ssl apply'.")
            return False
        
        # Decide whether to launch or attach based on 'target-running' flag
        launch_app = not args.target_running # If --target-running is present, launch_app is False
        
        return apply_bypass_script(
            package_name=args.package_name,
            script_filename=args.script,
            launch_app=launch_app
        )
    return False

def _universal_bypass_flow(args, config):
    """
    Handles the 'universal-bypass' command logic to apply a comprehensive Frida script.
    """
    logger.info("Initiating Universal Android Security Bypass...")
    
    # Instantiate your framework's AndroidDeviceManager
    device_manager = AndroidDeviceManager()
    if not device_manager.is_device_connected():
        logger.error("No Android device detected. Please connect a device with USB debugging enabled.")
        return False
    
    # Instantiate your framework's FridaBypassManager
    frida_bypass_manager = FridaBypassManager(device_manager)
    
    if not frida_bypass_manager.connect_frida():
        logger.error("Failed to connect to Frida device. Ensure frida-server is running on device.")
        return False
    
    success = frida_bypass_manager.inject_script(args.package, launch_app=not args.attach)
    
    if success:
        logger.success("Universal Android Security Bypass Suite successfully applied.")
        # The inject_script will keep the session alive with sys.stdin.read()
    else:
        logger.error("Failed to apply Universal Android Security Bypass Suite.")
    
    return success


def _device_flow(args, config):
    """Handles the 'device' command logic (device control and app management)."""
    logger.info("Initiating device management operations...")

    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot perform device operations.")
        return False

    # For 'connect' and 'disconnect', we don't necessarily need a device to be already connected.
    # The check is more for other commands that require an active connection.
    if args.device_command not in ['connect', 'disconnect'] and not check_device_connection(adb_path):
        logger.error("No Android device detected or device is not ready for this device management operation.")
        return False
    
    if args.device_command == 'reboot':
        return reboot_device()
    
    elif args.device_command == 'remount-rw':
        return remount_system_rw(adb_path)
    
    elif args.device_command == 'remount-ro':
        return remount_system_ro(adb_path)
    
    elif args.device_command == 'ls':
        devices = list_adb_connected_devices()
        return True # list_adb_connected_devices handles its own logging and returns a list. True if executed without crash.
    
    elif args.device_command == 'install':
        if not args.apk_path:
            logger.error("Error: --apk-path is required for 'device install'.")
            return False
        # Ensure apk_path is absolute for better handling
        args.apk_path = os.path.abspath(args.apk_path)
        return install_apk(args.apk_path)

    elif args.device_command == 'uninstall':
        if not args.package_name:
            logger.error("Error: --package-name is required for 'device uninstall'.")
            return False
        return uninstall_package(args.package_name)

    elif args.device_command == 'connect':
        # ip_address:port is one argument from CLI, need to split
        ip_parts = args.ip_address_port.split(':')
        ip_address = ip_parts[0]
        port = ip_parts[1] if len(ip_parts) > 1 else "5555"
        return connect_adb_device(ip_address, port)

    elif args.device_command == 'disconnect':
        # ip_address:port is one argument from CLI, need to split
        ip_parts = args.ip_address_port.split(':')
        ip_address = ip_parts[0]
        port = ip_parts[1] if len(ip_parts) > 1 else "5555"
        return disconnect_adb_device(ip_address, port)

    return False


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


# --- Argument Parsing ---

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

    # Proxy Set
    proxy_set_parser = proxy_subsubparsers.add_parser('set', help='Set the global HTTP proxy.')
    proxy_set_parser.add_argument('host_port', metavar='HOST:PORT', help='Host and port for the proxy (e.g., 192.168.1.100:8080).')
    
    # Proxy Clear
    proxy_clear_parser = proxy_subsubparsers.add_parser('clear', help='Clear the global HTTP proxy.')

    # Proxy Get
    proxy_get_parser = proxy_subsubparsers.add_parser('get', help='Get the current global HTTP proxy settings.')

    # Proxy Test
    proxy_test_parser = proxy_subsubparsers.add_parser('test', help='Test the global HTTP proxy connection.')
    proxy_test_parser.add_argument('--url', default='http://google.com', help='URL to test connectivity with (default: http://google.com).')

    # Proxy IPs (Device network interfaces)
    proxy_ips_parser = proxy_subsubparsers.add_parser('ips', help='Display device IP addresses and network interfaces.')

    # Proxy App (Per-App proxy) - New sub-subcommand group
    proxy_app_parser = proxy_subsubparsers.add_parser(
        'app',
        help='Manage per-application proxy settings (conceptual/limited via ADB).',
        formatter_class=argparse.RawTextHelpFormatter
    )
    proxy_app_subsubparsers = proxy_app_parser.add_subparsers(dest='app_command', help='Per-App Proxy Commands')

    # Proxy App Set
    proxy_app_set_parser = proxy_app_subsubparsers.add_parser('set', help='Set proxy for a specific app (conceptual).')
    proxy_app_set_parser.add_argument('package_name', help='Package name of the target application (e.g., com.example.app).')
    proxy_app_set_parser.add_argument('host_port', metavar='HOST:PORT', help='Host and port for the app proxy.')

    # Proxy App Clear
    proxy_app_clear_parser = proxy_app_subsubparsers.add_parser('clear', help='Clear proxy for a specific app (conceptual).')
    proxy_app_clear_parser.add_argument('package_name', help='Package name of the target application.')

    # Proxy App Get
    proxy_app_get_parser = proxy_app_subsubparsers.add_parser('get', help='Get proxy for a specific app (conceptual).')
    proxy_app_get_parser.add_argument('package_name', help='Package name of the target application.')

    # Proxy App List
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

    # New Frida 'ps' command
    frida_ps_parser = frida_subsubparsers.add_parser('ps', help='List all running processes on the device.')

    # New Frida 'kill' command
    frida_kill_parser = frida_subsubparsers.add_parser('kill', help='Kill a process by PID or package name.')
    frida_kill_parser.add_argument('target', help='Process ID (PID) or package name of the target to kill.')

    # New Frida 'launch' command
    frida_launch_parser = frida_subsubparsers.add_parser('launch', help='Launch an app and inject a Frida script.')
    frida_launch_parser.add_argument('package_name', help='Package name of the application to launch.')
    frida_launch_parser.add_argument('--script', required=True, help='Path to the Frida JS script to inject.')


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


    # NEW: 'universal-bypass' subcommand
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

    # Device Connection commands
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
        formatter_class=argparse.RawTextHelpFormatter # Corrected from 'formatter' to 'formatter_class'
    )

    args = parser.parse_args()
    
    # If no command is given, or if --help is explicitly requested, show full help
    if not hasattr(args, 'command') and not args.help:
        parser.print_help()
        sys.exit(1)
    
    return args


# --- Main Entry Point ---

def main():
    """Main function to parse arguments and execute commands."""
    args = parse_arguments()
    
    logger.info(f"Starting Burp-Frame v{VERSION}")
    
    if args.help:
        print(HELP_TEXT)
        return
    
    # Register cleanup here after logger is initialized
    atexit.register(cleanup_temp_files)

    config = load_config() # Load configuration once

    command_executed = False
    if args.command == 'install':
        command_executed = _install_flow(args, config)
    elif args.command == 'proxy':
        command_executed = _proxy_flow(args, config)
    elif args.command == 'frida':
        command_executed = _frida_flow(args, config)
    elif args.command == 'bypass-ssl':
        command_executed = _bypass_ssl_flow(args, config)
    elif args.command == 'universal-bypass': # NEW command flow
        command_executed = _universal_bypass_flow(args, config)
    elif args.command == 'device':
        command_executed = _device_flow(args, config)
    elif args.command == 'config':
        command_executed = _config_flow(args, config)
    elif args.command == 'logs':
        command_executed = _logs_flow(args, config)
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
