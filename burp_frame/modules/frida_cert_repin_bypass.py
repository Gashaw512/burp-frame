import os
import subprocess
import time
import sys
import frida # Directly import frida as it's a core dependency for this module

# Local imports from your framework's 'scripts' package
from ..logger import Logger
from ..utils import get_tool_path, run_command
from ..device_manager import check_device_connection # Need device check for this module

logger = Logger()

# The specific Frida script payload for certificate re-pinning/injection
CERT_REPINNING_FRIDA_JS = """
setTimeout(function(){
    Java.perform(function (){
        console.log("");
        console.log("[.] Cert Pinning Bypass/Re-Pinning (Custom CA Injection)");

        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        console.log("[+] Loading our CA from /data/local/tmp/cert-der.crt...");
        var cf = CertificateFactory.getInstance("X.509");

        var fileInputStream;
        try {
            fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
        } catch(err) {
            console.error("[!] Error opening cert file on device: " + err);
            console.warn("[!] Make sure the certificate was pushed to /data/local/tmp/cert-der.crt");
            return; // Exit Frida script if cert not found
        }

        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();

        var certInfo = Java.cast(ca, X509Certificate);
        console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

        console.log("[+] Creating a KeyStore for our CA...");
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null); // Load empty KeyStore
        keyStore.setCertificateEntry("ca", ca); // Add our CA

        console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore); // Initialize with our custom KeyStore
        console.log("[+] Our custom TrustManager is ready.");

        console.log("[+] Hijacking SSLContext methods now...");
        console.log("[-] Waiting for the app to invoke SSLContext.init()...");

        // Overload for SSLContext.init(KeyManager[], TrustManager[], SecureRandom)
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", 
            "[Ljavax.net.ssl.TrustManager;", 
            "java.security.SecureRandom"
        ).implementation = function(a,b,c) {
            console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
            // Call the original init method, but with our custom TrustManager array
            SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;", 
                "[Ljavax.net.ssl.TrustManager;", 
                "java.security.SecureRandom"
            ).call(this, a, tmf.getTrustManagers(), c);
            console.log("[+] SSLContext initialized with our custom TrustManager!");
        }

        // Example for OkHTTP3 (if needed, but usually SSLContext.init is sufficient)
        // try {
        //     var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        //     CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
        //         console.log("[*] OkHTTP3 CertificatePinner.check() called - bypassed (manual hook)");
        //         return;
        //     };
        // } catch (e) { console.warn("[!] OkHTTP3 CertificatePinner hook failed: " + e); }

        console.log("[*] Certificate re-pinning bypass script loaded successfully.");
    });
},0); // setTimeout with 0 ensures it runs after Java.perform is fully set up
"""

def _push_cert_to_device(local_cert_path):
    """
    Pushes the local certificate file to /data/local/tmp/cert-der.crt on the device.
    Assumes local_cert_path is the full path to the .0 or .der file.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot push certificate.")
        return False

    device_cert_path = "/data/local/tmp/cert-der.crt" # Hardcoded path as expected by the Frida script

    logger.info(f"Pushing certificate from '{local_cert_path}' to '{device_cert_path}' on device...")
    
    result = run_command(adb_path, ["push", local_cert_path, device_cert_path])
    
    if result.returncode == 0:
        logger.success(f"Certificate successfully pushed to {device_cert_path}.")
        return True
    else:
        logger.error(f"Failed to push certificate. ADB stderr: {result.stderr}")
        return False

def apply_frida_cert_repin_bypass(package_name: str, local_cert_path: str, launch_app: bool = True):
    """
    Applies the certificate re-pinning Frida bypass to a target Android application.
    
    Args:
        package_name (str): The package name of the target application.
        local_cert_path (str): Full path to the local .der or .0 certificate file.
        launch_app (bool): If True, launch the app and inject; else, attach to running app.
            
    Returns:
        bool: True if script injection was successful and maintained, False otherwise.
    """
    adb_path = get_tool_path("adb")
    if not adb_path:
        logger.error("ADB path not configured. Cannot proceed with bypass.")
        return False

    if not check_device_connection(adb_path):
        logger.error("No Android device detected. Please connect a device with USB debugging enabled.")
        return False

    if not os.path.exists(local_cert_path):
        logger.error(f"Local certificate file not found: {local_cert_path}. Aborting.")
        return False

    # 1. Push the certificate to the device
    if not _push_cert_to_device(local_cert_path):
        logger.error("Failed to push certificate to device. Aborting cert re-pinning bypass.")
        return False

    # 2. Connect to Frida and inject the script
    logger.info("Connecting to Frida device via USB...")
    try:
        device = frida.get_usb_device(timeout=5)
        logger.success("Frida device connected.")
    except frida.TransportError as e:
        logger.error(f"Frida device connection failed: {e}")
        logger.info("Ensure 'frida-server' is running on your Android device (use 'burp-frame frida deploy').")
        return False

    pid = None
    if launch_app:
        logger.info(f"Attempting to launch app '{package_name}' for injection...")
        # Use adb to launch the app
        launch_result = run_command(adb_path, ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        if launch_result.returncode != 0:
            logger.error(f"Failed to launch app {package_name}. ADB stderr: {launch_result.stderr}")
            return False
        
        time.sleep(3) # Give app time to start
        
        try:
            pid = device.get_process(package_name).pid
        except frida.ProcessNotFoundError:
            logger.error(f"Failed to find PID for '{package_name}' after launching. Is the package name correct?")
            return False
    else:
        logger.info(f"Attempting to attach to running app '{package_name}'...")
        try:
            pid = device.get_process(package_name).pid
        except frida.ProcessNotFoundError:
            logger.error(f"Cannot find running process for package '{package_name}'. Is the app running?")
            return False

    logger.info(f"Attaching to process (PID: {pid}) to inject certificate re-pinning bypass script...")

    try:
        session = device.attach(pid)
        
        def on_message(message, data):
            if message['type'] == 'send':
                logger.info(f"[FRIDA-SCRIPT] {message['payload']}")
            elif message['type'] == 'error':
                logger.error(f"[FRIDA-SCRIPT-ERROR] {message['description']}")
        
        script = session.create_script(CERT_REPINNING_FRIDA_JS)
        script.on('message', on_message) # Attach the message handler
        script.load()
        
        device.resume(pid) # Resume the spawned process if it was spawned

        logger.success("Certificate re-pinning bypass script injected successfully.")
        logger.info("HTTPS traffic for this app should now be interceptable via your proxy with your custom CA.")
        logger.info("Keep this script running; do not close the session.")
        
        # Keep the Python script running to maintain the Frida session
        sys.stdin.read() # This will keep the script alive until interrupted (Ctrl+C)

        return True
    except Exception as e:
        logger.error(f"Failed to inject script: {e}")
        logger.info("Possible causes: Frida-server not running, app crash, incorrect package name, or permissions.")
        return False

