# burp_frame/modules/bypass/bypass_auto_manager.py

import frida
import os
import json
import time

from burp_frame.logger import Logger
from burp_frame.modules.detection.universal_detector import run_detection

logger = Logger()

# Map detected countermeasures to their corresponding bypass scripts.
# This is the core logic for the automatic bypass feature.
BYPASS_MAPPING = {
    'ssl_pinning': 'ssl_pinning_bypass.js',
    'root_detection': 'root_bypass.js',
    'debugger_detection': 'debugger_bypass.js',
    'emulator_detection': 'emulator_bypass.js',
    # Add more mappings as you create new bypass scripts
}

def apply_auto_bypass(package_name: str, attach: bool = False, timeout: int = 20) -> bool:
    """
    Automatically detects and applies appropriate Frida bypasses for an Android app.

    Args:
        package_name (str): The Android package name (e.g., "com.example.app").
        attach (bool): If True, attach to a running application. If False, spawn and attach.
        timeout (int): The maximum number of seconds to wait for a Frida device.

    Returns:
        bool: True if the bypass process completed successfully, False otherwise.
    """
    logger.info(f"Starting automatic bypass for '{package_name}'...")

    # Step 1: Run detection to identify countermeasures
    detection_results = run_detection(package_name, attach, timeout)

    if not detection_results:
        logger.error("Could not get detection results. Aborting auto-bypass.")
        return False
    
    detections = detection_results.get('detections', {})
    logger.info("Detection complete. Found countermeasures:")
    for detection_type, detected in detections.items():
        if detected:
            logger.info(f"  - {detection_type.replace('_', ' ').capitalize()}: Detected")

    # Step 2: Determine which bypasses to apply based on detection results
    bypasses_to_apply = []
    for detection_type, script_name in BYPASS_MAPPING.items():
        if detections.get(detection_type):
            bypasses_to_apply.append(script_name)

    if not bypasses_to_apply:
        logger.warning("No bypasses required based on detection results. Exiting.")
        return True
    
    logger.info(f"Applying the following bypasses: {', '.join(bypasses_to_apply)}")

    # Step 3: Connect to Frida and apply bypasses
    try:
        device = frida.get_usb_device(timeout)
        session = device.attach(package_name)

        for script_name in bypasses_to_apply:
            script_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'scripts',
                script_name
            )

            if not os.path.exists(script_path):
                logger.error(f"Bypass script not found: {script_path}. Skipping.")
                continue

            with open(script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()

            try:
                script = session.create_script(script_content)
                script.load()
                logger.info(f"Successfully loaded {script_name}")
                # Wait a moment for the script to execute
                time.sleep(1)
            except Exception as e:
                logger.error(f"Failed to load or execute {script_name}: {e}")

        logger.info("All selected bypasses have been applied. Keep Frida session running.")
        logger.info("Press CTRL+C to detach the session.")
        session.attach(package_name)
        session.enable_child_gating()
        session.detach()
        return True

    except frida.ServerNotRunningError:
        logger.error("Frida server is not running on the device. Please start it first.")
    except frida.TransportError as e:
        logger.error(f"Frida transport error: {e}. Check USB connection.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during bypass application: {e}", exc_info=True)
    finally:
        # A detached session should not need a separate detach call
        if 'session' in locals() and session:
            try:
                session.detach()
                logger.debug("Frida session detached.")
            except Exception as e:
                logger.warning(f"Error detaching Frida session: {e}")
    
    return False