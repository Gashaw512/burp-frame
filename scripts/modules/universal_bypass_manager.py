import os
import subprocess
import time
import sys
import frida # Directly import frida as it's a core dependency for this module

# Local imports from your framework's 'scripts' package
from ..logger import Logger
from ..utils import get_tool_path, run_adb_command

logger = Logger()


class AndroidDeviceManager:
    """
    Manages basic Android device interactions via ADB for the universal bypass module.
    Leverages burp-frame's existing utility functions for consistency.
    """
    def __init__(self):
        # adb_path is now dynamically retrieved from burp-frame's config
        self.adb_path = get_tool_path("adb")
        if not self.adb_path:
            logger.error("ADB path not configured. Please run 'burp-frame config --adb <path_to_adb_exe>'.")
            sys.exit(1) # Exit if ADB is not configured, as it's critical

    def is_device_connected(self):
        """
        Checks if an Android device is connected and ready using burp-frame's utility.
        """
        logger.info("Checking Android device connection...")
        # Use your framework's run_adb_command for consistency
        result = run_adb_command(self.adb_path, ["get-state"])
        connected = result.stdout.strip() == "device"
        if connected:
            logger.info("Android device detected and ready.")
        else:
            logger.warn("No Android device detected. Please connect a device and enable USB debugging.")
            logger.info("Ensure 'adb tcpip' is used for network connections, if applicable.")
        return connected

    def get_package_pid(self, package_name):
        """
        Retrieves the PID of a running Android application by package name.
        """
        logger.info(f"Attempting to find PID for package: {package_name}")
        # Use your framework's run_adb_command
        result = run_adb_command(self.adb_path, ["shell", "pidof", package_name])
        pid = result.stdout.strip()
        if pid and pid.isdigit():
            logger.info(f"Found running app PID for {package_name}: {pid}")
            return int(pid)
        else:
            logger.info(f"No running process found for {package_name}.")
            return None

    def launch_app(self, package_name):
        """
        Launches an Android application using ADB's monkey command.
        """
        logger.info(f"Launching app {package_name} on device...")
        # Use your framework's run_adb_command
        result = run_adb_command(self.adb_path, ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
        if result.returncode == 0:
            time.sleep(3)   # wait a bit for app to start
            logger.info("App launched successfully (may take a moment to appear).")
            return True
        else:
            logger.error(f"Failed to launch app {package_name}. ADB stderr: {result.stderr}")
            return False


class FridaBypassManager:
    """
    Manages the injection of a universal security bypass script into an Android application
    using Frida. Includes SSL pinning, debugger, root, and emulator detection bypasses.
    """
    # Universal bypass JavaScript payload - ENHANCED WITH MORE COMPREHENSIVE HOOKS
    UNIVERSAL_BYPASS_JS = """
    Java.perform(function() {
        console.log("[*] Universal Bypass Script Initiated.");

        // --- 1) SSL Pinning Bypass (Comprehensive Hooks) ---
        try {
            var ArrayList = Java.use('java.util.ArrayList');
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            // 1.1) Custom TrustManager that trusts all certificates
            var TrustAllManager = Java.registerClass({
                name: 'com.bypass.TrustAllManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return [] }
                }
            });

            var TrustManagers = [TrustAllManager.$new()];
            var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            SSLContext_init.implementation = function (km, tm, sr) {
                console.log('[*] SSLContext.init() hooked, installing TrustAllManager');
                SSLContext_init.call(this, km, TrustManagers, sr);
            };

            // 1.2) OkHttp3 CertificatePinner bypass
            try {
                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (p0, p1) {
                    console.log('[*] OkHttp3 CertificatePinner.check(String, List) bypassed for ' + p0);
                    return;
                };
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (p0, p1) {
                    console.log('[*] OkHttp3 CertificatePinner.check(String, Certificate[]) bypassed for ' + p0);
                    return;
                };
            } catch (e) { /* OkHttp3 might not be present */ }

            // 1.3) HttpsURLConnection HostnameVerifier and SSLSocketFactory bypass
            try {
                var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
                    console.log('[*] HttpsURLConnection.setDefaultHostnameVerifier() bypass');
                };
                HttpsURLConnection.setSSLSocketFactory.implementation = function (factory) {
                    console.log('[*] HttpsURLConnection.setSSLSocketFactory() bypass');
                };
            } catch (e) { /* HttpsURLConnection might not be used */ }

            // 1.4) TrustManagerImpl (Android 7+) bypass - for Conscrypt
            try {
                var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    console.log('[*] TrustManagerImpl.verifyChain() bypassed for ' + host);
                    return untrustedChain; // Return original chain to allow connection
                };
            } catch (e) { /* Conscrypt might not be used or Android version older */ }

            // 1.5) HostnameVerifier (generic)
            try {
                var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
                // Hooking common OkHttp's internal HostnameVerifier if present
                var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
                OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (host, sess) {
                    console.log('[*] OkHostnameVerifier.verify() bypassed for ' + host);
                    return true;
                };
            } catch (e) { /* OkHostnameVerifier might not be present */ }

            console.log("[+] SSL Pinning bypass hooks installed.");
        } catch (e) { console.error("[!] SSL Pinning bypass setup failed: " + e); }


        // --- 2) Root Detection Bypass (Comprehensive Hooks) ---
        try {
            var String = Java.use('java.lang.String');

            // 2.1) Common file path checks (e.g., /system/bin/su)
            var File = Java.use('java.io.File');
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                var suspicious = [
                    '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su',
                    '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su',
                    '/system/bin/failsafe/su', '/su/bin/su', '/system/app/SuperSU',
                    '/system/bin/busybox', '/system/xbin/busybox', '/data/local/tmp/busybox'
                ];
                if (suspicious.indexOf(String.valueOf(path)) >= 0) {
                    console.log('[*] File.exists() root path hidden: ' + path);
                    return false;
                }
                return this.exists.call(this);
            };

            // 2.2) Runtime.exec checks (e.g., 'which su', 'su -c')
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
                try {
                    var joined = cmd.join(' ');
                    if (joined.indexOf('which su') >= 0 || joined.indexOf('/su') >= 0 || joined.indexOf('busybox') >= 0) {
                        console.log('[*] Runtime.exec() blocked: ' + joined);
                        throw new java.io.IOException('Command blocked by UASB');
                    }
                } catch (e) {} // Don't crash if error during string ops
                return this.exec.call(this, cmd);
            };
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                if (cmd.indexOf('which su') >= 0 || cmd.indexOf('/su') >= 0 || cmd.indexOf('busybox') >= 0) {
                    console.log('[*] Runtime.exec() blocked: ' + cmd);
                    throw new java.io.IOException('Command blocked by UASB');
                }
                return this.exec.call(this, cmd);
            };

            // 2.3) System properties checks (e.g., ro.debuggable)
            try {
                var SystemProperties = Java.use('android.os.SystemProperties');
                SystemProperties.get.overload('java.lang.String').implementation = function (key) {
                    var v = this.get.call(this, key);
                    if (key && (key.indexOf('ro.debuggable') >= 0 || key.indexOf('ro.secure') >= 0 || key.indexOf('ro.build.tags') >= 0)) {
                        console.log('[*] SystemProperties.get(' + key + ') forged');
                        // Return '0' for debuggable, 'user' for build tags
                        if (key.indexOf('ro.build.tags') >= 0) return 'release-keys';
                        return '0';
                    }
                    return v;
                };
            } catch (e) { /* SystemProperties might not be directly hooked */ }

            // 2.4) RootBeer example (if specific library is used)
            try {
                var RootUtil = Java.use('com.scottyab.rootbeer.RootBeer');
                RootUtil.isRooted.implementation = function() {
                    console.log("[*] Bypassing RootBeer Root detection: returning false");
                    return false;
                };
            } catch (e) { /* RootBeer not found or different version */ }

            console.log("[+] Root detection bypass hooks installed.");
        } catch (e) { console.error("[!] Root detection bypass setup failed: " + e); }


        // --- 3) Debugger Detection Bypass ---
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function() {
                console.log("[*] Bypassing debugger detection: returning false");
                return false;
            };
        } catch (e) { console.warn("[!] Debugger detection bypass setup failed: " + e); }

        // --- 4) Emulator Detection Bypass ---
        try {
            var Build = Java.use('android.os.Build');
            Build.FINGERPRINT.value = "google/sdk_gphone_x86/generic_x86:11/RSR1.201013.001/6604421:userdebug/dev-keys";
            Build.MODEL.value = "Pixel 3a XL";
            Build.MANUFACTURER.value = "Google";
            Build.BRAND.value = "google";
            Build.DEVICE.value = "generic_x86";
            console.log("[*] Emulator detection values overridden");
        } catch (e) { console.warn("[!] Emulator detection bypass setup failed: " + e); }

        console.log("[*] Universal Android Security Bypass Suite active.");
    });
    """

    def __init__(self, device_manager: AndroidDeviceManager):
        self.device_manager = device_manager
        self.device = None

    def connect_frida(self):
        """
        Connects to the Frida device (assumes USB connection).
        """
        try:
            logger.info("Connecting to Frida device via USB...")
            self.device = frida.get_usb_device(timeout=5)
            logger.success("Frida device connected.")
            return True
        except frida.TransportError as e:
            logger.error(f"Frida device connection failed: {e}")
            logger.info("Ensure 'frida-server' is running on your Android device (use 'burp-frame frida deploy').")
            return False

    def deploy_frida_server(self):
        """
        Placeholder/recommendation: In a real framework, this would call
        burp-frame's frida_manager.deploy_frida_server().
        For now, this UniversalBypassManager relies on it being deployed externally.
        """
        logger.warn("Frida server deployment is handled by 'burp-frame frida deploy'.")
        logger.info("Please ensure frida-server is running on the device before injecting.")


    def inject_script(self, package_name: str, launch_app=True):
        """
        Injects the universal bypass script into the target application.
        
        Args:
            package_name (str): The package name of the Android application.
            launch_app (bool): If True, launch the app and inject; else, attach to running app.
            
        Returns:
            bool: True if script injection was successful, False otherwise.
        """
        if not self.device:
            logger.error("Frida device not connected. Call connect_frida() first.")
            return False

        pid = None
        if launch_app:
            # Launch app via ADB, then get its PID for Frida
            logger.info(f"Attempting to launch app '{package_name}' for injection...")
            if not self.device_manager.launch_app(package_name):
                logger.error("Failed to launch target app. Cannot proceed with injection.")
                return False
            # Give the app a moment to start and register its process
            time.sleep(2)
            try:
                pid = self.device.get_process(package_name).pid
            except frida.ProcessNotFoundError:
                logger.error(f"Failed to find PID for '{package_name}' after launching. Is the package name correct?")
                return False
        else:
            # Attach to already running app
            pid = self.device_manager.get_package_pid(package_name)
            if not pid:
                logger.error(f"Cannot find running process for package '{package_name}'. Is the app running?")
                return False

        logger.info(f"Attaching to process (PID: {pid}) to inject universal bypass script...")

        try:
            session = self.device.attach(pid)
            # Route messages from the Frida script to Python's logger
            def on_message(message, data):
                if message['type'] == 'send':
                    logger.info(f"[FRIDA-SCRIPT] {message['payload']}")
                elif message['type'] == 'error':
                    logger.error(f"[FRIDA-SCRIPT-ERROR] {message['description']}")
            
            script = session.create_script(self.UNIVERSAL_BYPASS_JS)
            script.on('message', on_message) # Attach the message handler
            script.load()
            
            logger.success("Universal bypass script injected successfully.")
            logger.info("SSL Pinning, Debugger, Root, and Emulator checks should now be bypassed.")
            logger.info("Keep the current terminal session open; do not close it, as Frida needs to remain attached.")
            
            # Keep the Python script running to maintain the Frida session
            sys.stdin.read() # This will keep the script alive until interrupted

            return True
        except Exception as e:
            logger.error(f"Failed to inject script: {e}")
            logger.info("Possible causes: Frida-server not running, app crash, incorrect package name, or permissions.")
            return False
