# burp_frame/modules/detection/detection_manager.py

import frida
import json
import os
import time

from burp_frame.logger import Logger

# Initialize logger for this module
logger = Logger()

# Define the path to the comprehensive detector script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMPREHENSIVE_DETECTOR_PATH = os.path.join(SCRIPT_DIR, 'scripts', 'comprehensive_detector.js')

def run_detection(package_name: str, attach: bool = False, timeout: int = 20) -> dict | None:
    """
    Runs the comprehensive detector script on the target application to find security
    countermeasures and gather environment data.

    Args:
        package_name (str): The Android package name (e.g., "com.example.app").
        attach (bool): If True, attach to a running application. If False, spawn a new one.
        timeout (int): The maximum number of seconds to wait for a Frida device.

    Returns:
        dict | None: A dictionary of detection results and environment data if successful,
                     otherwise None.
    """
    if not os.path.exists(COMPREHENSIVE_DETECTOR_PATH):
        logger.error(f"Comprehensive detector script not found at: {COMPREHENSIVE_DETECTOR_PATH}")
        return None

    session = None
    script = None
    detection_results = {}
    
    # Use a flag to wait for the final report from the script
    report_received = False

    def on_message(message, data):
        nonlocal detection_results, report_received
        if message['type'] == 'send':
            try:
                payload = json.loads(message['payload'])
                # The comprehensive script sends messages with a 'type' key
                if payload.get('type') == 'final_report':
                    detection_results.update(payload.get('payload', {}))
                    report_received = True
                elif payload.get('type') == 'hook_triggered':
                    # Log real-time hook triggers for better user feedback
                    logger.info(f"[*] Hook Triggered: {payload.get('detail', 'N/A')}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON from Frida script: {e}")
                logger.debug(f"Raw message payload: {message['payload']}")
        elif message['type'] == 'error':
            logger.error(f"Frida script error: {message['description']}")
        else:
            logger.debug(f"Frida message: {message}")

    try:
        # Get the USB device, with a timeout
        device = frida.get_usb_device(timeout)
        logger.info(f"Connected to Frida device: {device.name}")

        with open(COMPREHENSIVE_DETECTOR_PATH, 'r', encoding='utf-8') as f:
            script_content = f.read()

        if attach:
            logger.info(f"Attaching to running application: {package_name}")
            session = device.attach(package_name)
        else:
            logger.info(f"Spawning application: {package_name} and injecting script...")
            pid = device.spawn(package_name)
            session = device.attach(pid)
            device.resume(pid)  # Resume the spawned process to run the script

        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()

        logger.info("Frida script loaded. Waiting for detection results...")
        
        # Wait for the final report with a timeout
        start_time = time.time()
        while not report_received and (time.time() - start_time) < 15:  # 15-second wait
            time.sleep(0.5)

        if not report_received:
            logger.error("Timeout: Did not receive the final detection report from the script.")
            return None

        return detection_results

    except frida.ServerNotRunningError:
        logger.error("Frida server is not running on the device. Please start it.")
    except frida.NotSupportedError as e:
        logger.error(f"Frida operation not supported: {e}. Check device configuration.")
    except frida.ProcessNotRespondingError:
        logger.error(f"The target application '{package_name}' did not respond. It might have crashed.")
    except frida.TransportError as e:
        logger.error(f"Frida transport error: {e}. Check the USB connection.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during Frida detection: {e}", exc_info=True)
    finally:
        if script:
            try:
                script.unload()
                logger.debug("Frida script unloaded.")
            except Exception as e:
                logger.warning(f"Error unloading Frida script: {e}")
        if session:
            try:
                session.detach()
                logger.debug("Frida session detached.")
            except Exception as e:
                logger.warning(f"Error detaching Frida session: {e}")
    
    return None