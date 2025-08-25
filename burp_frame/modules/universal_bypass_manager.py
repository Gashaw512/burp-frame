import os
import sys
import time
import frida # Ensure frida is installed (pip install frida)

# Local imports from your framework's 'scripts' package
from ..logger import Logger
from ..utils import get_tool_path, run_adb_command
from ..device_manager import check_device_connection 

logger = Logger()


class AndroidDeviceManager:
    """
    Manages basic Android device interactions via ADB for the universal bypass module.
    Leverages burp-frame's existing utility functions for consistency.
    """
    def __init__(self):
        self.adb_path = get_tool_path("adb")
        if not self.adb_path:
            logger.error("ADB path not configured. Please run 'burp-frame config --adb <path_to_adb_exe>'.")
            raise RuntimeError("ADB path not configured, cannot proceed.")

    def is_device_connected(self) -> bool:
        """
        Checks if an Android device is connected and ready using burp-frame's utility.
        This performs a general ADB device check, not necessarily a Frida-specific one.
        """
        logger.info("Checking general Android device connection via ADB...")
        return check_device_connection(self.adb_path)

    def get_package_pid_adb(self, package_name: str) -> int | None:
        """
        Retrieves the PID of a running Android application by package name using ADB's 'pidof'.
        """
        logger.info(f"Attempting to find PID for package '{package_name}' using ADB pidof...")
        result = run_adb_command(adb_path, ["shell", "pidof", package_name])
        pid_str = result.stdout.strip()
        if pid_str and pid_str.isdigit():
            pid = int(pid_str)
            logger.info(f"Found running app PID for '{package_name}': {pid}")
            return pid
        else:
            logger.info(f"No running process found for '{package_name}' via pidof.")
            return None

    def launch_app_adb(self, package_name: str) -> bool:
        """
        Launches an Android application using ADB's monkey command.
        """
        logger.info(f"Launching app '{package_name}' on device using ADB monkey command...")
        command = ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"]
        result = run_adb_command(
            , command)
        
        if result.returncode == 0:
            logger.info("App launch command sent successfully. Giving app a moment to start...")
            time.sleep(3)
            return True
        else:
            logger.error(f"Failed to send launch command for app '{package_name}'. ADB stderr: {result.stderr}")
            return False


class FridaBypassManager:
    """
    Manages the injection of a universal security bypass script into an Android application
    using Frida. Includes SSL pinning, debugger, root, and emulator detection bypasses.
    """
    UNIVERSAL_BYPASS_JS = """
    // Frida Universal Android Security Bypass (UASB) Suite
    // Designed for comprehensive bypasses of SSL Pinning, Root Detection,
    // Debugger Detection, and basic Emulator Detection.

    // Robust function to wait for Java to be defined and then call Java.perform
    function waitForJavaAndPerform(callback) {
        if (typeof Java === 'undefined') {
            console.log("[DIAGNOSTIC] Java is UNDEFINED at start, waiting...");
            var intervalCount = 0;
            var maxIntervals = 500; // ~50 seconds (500 * 100ms)
            var intervalId = setInterval(function() {
                intervalCount++;
                if (typeof Java !== 'undefined') {
                    clearInterval(intervalId);
                    console.log("[DIAGNOSTIC] Java is now defined after " + intervalCount + " checks. Proceeding with Java.perform.");
                    Java.perform(callback);
                } else if (intervalCount >= maxIntervals) {
                    clearInterval(intervalId);
                    console.error("[DIAGNOSTIC] Max wait time reached. Java object still undefined. Aborting script execution.");
                    send({ type: 'error', description: 'Java object never became defined after max wait time.', stack: new Error().stack });
                } else {
                    if (intervalCount % 50 === 0) { // Log every 5 seconds
                        console.log("[DIAGNOSTIC] Still waiting for Java... (" + intervalCount + " checks)");
                    }
                }
            }, 100); // Check every 100ms
        } else {
            console.log("[DIAGNOSTIC] Java is already defined. Directly calling Java.perform.");
            Java.perform(callback);
        }
    }

    // Wrap the call to waitForJavaAndPerform in setImmediate to give the app more time
    setImmediate(function() {
        waitForJavaAndPerform(function() {
            console.log("------------------------------------------");
            console.log("[*] Universal Android Security Bypass (UASB) Suite Initiated.");
            console.log("------------------------------------------");

            // --- 1) SSL Pinning Bypass (Comprehensive Hooks) ---
            try {
                var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var TrustManagers = Java.array('Ljavax.net.ssl.TrustManager;', [
                    Java.registerClass({
                        name: 'com.bypass.TrustAllX509TrustManager',
                        implements: [TrustManager],
                        methods: {
                            checkClientTrusted: function (chain, authType) {
                                // console.log("[+] checkClientTrusted: " + authType);
                            },
                            checkServerTrusted: function (chain, authType) {
                                // console.log("[+] checkServerTrusted: " + authType);
                            },
                            getAcceptedIssuers: function () {
                                return Java.array('Ljava.security.cert.X509Certificate;', []);
                            }
                        }
                    }).$new()
                ]);

                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
                    console.log('[+] SSLContext.init() hooked: Injecting TrustAllX509TrustManager.');
                    this.init(km, TrustManagers, sr);
                };
                
                try {
                    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certificates) {
                        console.log('[+] OkHttp3 CertificatePinner.check(String, List) bypassed for: ' + hostname);
                        return;
                    };
                    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, certificates) {
                        console.log('[+] OkHttp3 CertificatePinner.check(String, Certificate[]) bypassed for: ' + hostname);
                        return;
                    };
                } catch (e) { /* OkHttp3 not found or different version, gracefully ignore */ }

                try {
                    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        console.log('[+] TrustManagerImpl.verifyChain() bypassed for host: ' + host);
                        return untrustedChain; 
                    };
                } catch (e) { /* Conscrypt TrustManagerImpl not found or Android version older */ }

                try {
                    var WebViewClient = Java.use('android.webkit.WebViewClient');
                    WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (view, handler, error) {
                        console.log('[+] WebViewClient.onReceivedSslError() bypassed. Proceeding anyway. Error: ' + error.toString());
                        handler.proceed();
                    };
                } catch (e) { /* WebViewClient not found or not applicable */ }

                console.log("[+] SSL Pinning bypass hooks installed successfully.");
            } catch (e) { 
                console.error("[!] SSL Pinning bypass setup failed: " + e.message); 
            }


            // --- 2) Root Detection Bypass (Comprehensive Hooks) ---
            try {
                var File = Java.use('java.io.File');
                var String = Java.use('java.lang.String');
                var BufferedReader = Java.use('java.io.BufferedReader');
                var InputStreamReader = Java.use('java.io.InputStreamReader');

                var suspiciousFiles = [
                    '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su',
                    '/data/local/xbin/su', '/data/local/bin/su', '/system/sd/xbin/su',
                    '/system/bin/failsafe/su', '/su/bin/su', '/system/app/SuperSU',
                    '/system/bin/busybox', '/system/xbin/busybox', '/data/local/tmp/busybox',
                    '/vendor/bin/su', '/vendor/xbin/su', '/vendor/app/Superuser.apk',
                    '/system/etc/init.d/99SuperSUDaemon', '/system/etc/rc.d/99SuperSUDaemon'
                ];
                File.exists.implementation = function () {
                    var path = this.getAbsolutePath();
                    if (suspiciousFiles.indexOf(String.valueOf(path)) >= 0) {
                        console.log('[+] File.exists() bypassed: Root artifact hidden at ' + path);
                        return false;
                    }
                    return this.exists.call(this);
                };
                File.canExecute.implementation = function() {
                    var path = this.getAbsolutePath();
                     if (suspiciousFiles.indexOf(String.valueOf(path)) >= 0) {
                        console.log('[+] File.canExecute() bypassed: Root artifact hidden at ' + path);
                        return false;
                    }
                    return this.canExecute.call(this);
                };

                var Runtime = Java.use('java.lang.Runtime');
                var execMethods = [
                    Runtime.exec.overload('[Ljava.lang.String;'),
                    Runtime.exec.overload('java.lang.String'),
                    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;'),
                    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;'),
                    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File'),
                    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File')
                ];

                execMethods.forEach(function(method) {
                    method.implementation = function (cmd) {
                        var command = Array.isArray(cmd) ? cmd.join(' ') : cmd;
                        var blockedCommands = ['which su', 'su -c', '/su', 'busybox', 'mount', 'getprop'];
                        
                        var isBlocked = blockedCommands.some(function(blockedCmd) {
                            return command.indexOf(blockedCmd) >= 0;
                        });

                        if (isBlocked) {
                            console.log('[+] Runtime.exec() bypassed: Command blocked: ' + command);
                            try {
                                return Runtime.getRuntime().exec("echo", null, null);
                            } catch (e) {
                                console.warn("Failed to execute dummy command, throwing IOException instead for: " + command);
                                throw new java.io.IOException('Command blocked by UASB');
                            }
                        }
                        return this.exec.apply(this, arguments);
                    };
                });
                
                try {
                    var SystemProperties = Java.use('android.os.SystemProperties');
                    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
                        var originalValue = this.get.call(this, key);
                        if (key === 'ro.debuggable' || key === 'ro.secure') {
                            console.log(`[+] SystemProperties.get('${key}') bypassed: Original: '${originalValue}', Returning: '0'.`);
                            return '0';
                        }
                        if (key === 'ro.build.tags') {
                            console.log(`[+] SystemProperties.get('${key}') bypassed: Original: '${originalValue}', Returning: 'release-keys'.`);
                            return 'release-keys';
                        }
                        return originalValue;
                    };
                    SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
                        var originalValue = this.get.call(this, key, def);
                        if (key === 'ro.debuggable' || key === 'ro.secure') {
                            console.log(`[+] SystemProperties.get('${key}', '${def}') bypassed: Original: '${originalValue}', Returning: '0'.`);
                            return '0';
                        }
                        if (key === 'ro.build.tags') {
                            console.log(`[+] SystemProperties.get('${key}', '${def}') bypassed: Original: '${originalValue}', Returning: 'release-keys'.`);
                            return 'release-keys';
                        }
                        return originalValue;
                    };
                } catch (e) { /* SystemProperties might be internal/unavailable on some versions */ }


                try {
                    var System = Java.use('java.lang.System');
                    System.getenv.overload('java.lang.String').implementation = function (name) {
                        if (name === 'PATH') {
                            var originalPath = this.getenv.call(this, name);
                            var cleanedPath = originalPath.split(':').filter(function(p) {
                                return !p.includes('/su') && !p.includes('busybox') && !p.includes('/sbin');
                            }).join(':');
                            console.log('[+] System.getenv("PATH") cleaned for root artifacts.');
                            return cleanedPath;
                        }
                        return this.getenv.call(this, name);
                    };
                    System.getenv.overload().implementation = function () {
                        console.log('[!] System.getenv() without args called. Might expose root paths.');
                        return this.getenv.call(this);
                    };
                } catch (e) { /* System.getenv hook might fail */ }

                try {
                    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
                    RootBeer.isRooted.implementation = function() {
                        console.log("[+] Bypassing RootBeer.isRooted(): returning false");
                        return false;
                    };
                    try {
                        var ArrayList = Java.use('java.util.ArrayList');
                        RootBeer.detectRootManagementApps.implementation = function() { console.log("[+] Bypassing RootBeer.detectRootManagementApps(): returning empty list"); return ArrayList.$new(); };
                        RootBeer.detectTestKeys.implementation = function() { console.log("[+] Bypassing RootBeer.detectTestKeys(): returning false"); return false; };
                        RootBeer.detectBusyBoxBinary.implementation = function() { console.log("[+] Bypassing RootBeer.detectBusyBoxBinary(): returning false"); return false; };
                        RootBeer.detectRootCloaking.implementation = function() { console.log("[+] Bypassing RootBeer.detectRootCloaking(): returning false"); return false; };
                        RootBeer.checkForBinary.overload('java.lang.String[]').implementation = function() { console.log("[+] Bypassing RootBeer.checkForBinary(String[]): returning false"); return false; };
                        RootBeer.checkForBinary.overload('java.lang.String').implementation = function() { console.log("[+] Bypassing RootBeer.checkForBinary(String): returning false"); return false; };
                    } catch (e) { /* Specific RootBeer methods not found, ignore */ }
                } catch (e) { /* RootBeer library not present, ignore */ }

                console.log("[+] Root detection bypass hooks installed successfully.");
            } catch (e) { 
                console.error("[!] Root detection bypass setup failed: " + e.message); 
            }

            // --- 2.5) Native Hook for /proc/self/maps (Frida Detection Evasion) ---
            // This hook attempts to hide Frida's libraries from being detected by monitoring access to process maps.
            try {
                var openPtr = Module.findExportByName(null, "open"); // Find the native 'open' function
                if (openPtr) {
                    Interceptor.attach(openPtr, {
                        onEnter: function (args) {
                            // args[0] is the path. Check if it's a valid pointer.
                            if (args[0].isNull()) {
                                this.path = null;
                                return;
                            }
                            // Safely read the C string from the NativePointer
                            try {
                                this.path = args[0].readCString();
                            } catch (e) {
                                // Handle cases where reading CString fails (e.g., invalid memory access)
                                this.path = null;
                                console.warn("[DIAGNOSTIC] Error reading path from open() call: " + e.message + " (PID: " + Process.getCurrentThreadId() + ")");
                            }

                            if (this.path && (this.path.indexOf("/proc/self/maps") !== -1 || this.path.indexOf("/proc/" + Process.getCurrentThreadId() + "/maps") !== -1)) {
                                console.log("[DIAGNOSTIC] Detected access to 'maps' file: " + this.path + " (PID: " + Process.getCurrentThreadId() + ")");
                                console.log("[+] Blocking access to /proc/self/maps for anti-Frida detection.");
                                this.block_maps_access = true; // Flag to block this specific open call
                            } else {
                                this.block_maps_access = false;
                            }
                        },
                        onLeave: function (retval) {
                            if (this.block_maps_access) {
                                console.log("[+] Intercepted and blocked open() call for: " + this.path);
                                retval.replace(-1); // Return -1 (error) to indicate failure to open
                            }
                        }
                    });
                    console.log("[+] Native hook for open() (for /proc/self/maps) installed successfully.");
                } else {
                    console.warn("[!] Native hook for open() not installed: 'open' export not found in loaded modules. (This is normal on some older Android/kernel versions, or if hook point is different)");
                }
            } catch (e) {
                console.error("[!] Native hook setup for /proc/self/maps failed: " + e.message);
                // console.debug(e.stack); // Uncomment for detailed debugging if this consistently fails
            }


            // --- 3) Debugger Detection Bypass ---
            try {
                var Debug = Java.use('android.os.Debug');
                Debug.isDebuggerConnected.implementation = function() {
                    console.log("[+] Bypassing Debug.isDebuggerConnected(): returning false");
                    return false;
                };

                var System = Java.use('java.lang.System');
                System.getProperty.overload('java.lang.String').implementation = function (key) {
                    var originalValue = this.getProperty.call(this, key);
                    if (key === 'android.os.Debug.isDebuggerConnected') {
                        console.log(`[+] System.getProperty("android.os.Debug.isDebuggerConnected") bypassed: Original: '${originalValue}', Returning: "false"`);
                        return 'false';
                    }
                    return originalValue;
                };
                System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
                    var originalValue = this.getProperty.call(this, key, def);
                    if (key === 'android.os.Debug.isDebuggerConnected') {
                        console.log(`[+] System.getProperty("${key}", "${def}") bypassed: Original: '${originalValue}', Returning: "false"`);
                        return 'false';
                    }
                    return originalValue;
                };

                try {
                    var ActivityManager = Java.use('android.app.ActivityManager');
                    ActivityManager.getMemoryInfo.implementation = function(memoryInfo) {
                        this.getMemoryInfo(memoryInfo);
                        console.log("[+] ActivityManager.getMemoryInfo() hooked for debugger detection.");
                    };
                } catch (e) { /* ActivityManager hook failed */ }

                console.log("[+] Debugger detection bypass hooks installed successfully.");
            } catch (e) { 
                console.error("[!] Debugger detection bypass setup failed: " + e.message); 
            }

            // --- 4) Emulator Detection Bypass ---
            try {
                var Build = Java.use('android.os.Build');
                var Build_VERSION = Java.use('android.os.Build$VERSION');

                // Store original values for logging or potential restoration
                var originalFingerprint = Build.FINGERPRINT.value;
                var originalModel = Build.MODEL.value;
                var originalManufacturer = Build.MANUFACTURER.value;
                var originalBrand = Build.BRAND.value;
                var originalDevice = Build.DEVICE.value;
                var originalProduct = Build.PRODUCT.value;
                var originalHardware = Build.HARDWARE.value;
                var originalHost = Build.HOST.value;
                var originalBoard = Build.BOARD.value;


                Build.FINGERPRINT.value = "google/sdk_gphone_x86/generic_x86:11/RSR1.201013.001/6604421:userdebug/dev-keys";
                Build.MODEL.value = "Pixel 3a XL";
                Build.MANUFACTURER.value = "Google";
                Build.BRAND.value = "google";
                Build.DEVICE.value = "generic_x86";
                Build.PRODUCT.value = "sdk_gphone_x86";
                // Change hardware from 'goldfish' (emulator) to something more realistic
                Build.HARDWARE.value = "angler"; // Example for a physical device
                Build.HOST.value = "build-server"; // Generic non-emulator host
                Build.BOARD.value = "walleye"; // Example for a physical device board

                console.log(`[+] Emulator detection values overridden:
                    FINGERPRINT: '${originalFingerprint}' -> '${Build.FINGERPRINT.value}'
                    MODEL: '${originalModel}' -> '${Build.MODEL.value}'
                    MANUFACTURER: '${originalManufacturer}' -> '${Build.MANUFACTURER.value}'
                    BRAND: '${originalBrand}' -> '${Build.BRAND.value}'
                    DEVICE: '${originalDevice}' -> '${Build.DEVICE.value}'
                    PRODUCT: '${originalProduct}' -> '${Build.PRODUCT.value}'
                    HARDWARE: '${originalHardware}' -> '${Build.HARDWARE.value}'
                    HOST: '${originalHost}' -> '${Build.HOST.value}'
                    BOARD: '${originalBoard}' -> '${Build.BOARD.value}'
                `);

                try {
                    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
                    TelephonyManager.getDeviceId.overload().implementation = function () {
                        console.log("[+] TelephonyManager.getDeviceId() bypassed.");
                        return "0123456789ABCDEF";
                    };
                    TelephonyManager.getSubscriberId.overload().implementation = function () {
                        console.log("[+] TelephonyManager.getSubscriberId() bypassed.");
                        return "123456789012345";
                    };
                    TelephonyManager.getNetworkOperatorName.overload().implementation = function () {
                        console.log("[+] TelephonyManager.getNetworkOperatorName() bypassed.");
                        return "Fake Mobile";
                    };
                    TelephonyManager.getSimOperatorName.overload().implementation = function () {
                        console.log("[+] TelephonyManager.getSimOperatorName() bypassed.");
                        return "Fake SIM";
                    };
                } catch (e) { /* TelephonyManager hooks might fail if not used or different Android version */ }

                console.log("[+] Emulator detection bypass hooks installed successfully.");
            } catch (e) { 
                console.error("[!] Emulator detection bypass setup failed: " + e.message); 
            }

            console.log("------------------------------------------");
            console.log("[*] Universal Android Security Bypass (UASB) Suite Active.");
            console.log("------------------------------------------");
        });
    });
    """

    def __init__(self, device_manager: AndroidDeviceManager):
        self.device_manager = device_manager
        self.device = None
        self.session = None # Initialize session to None

    def connect_frida(self) -> bool:
        """
        Connects to the Frida device (assumes USB connection).
        """
        try:
            logger.info("Connecting to Frida device via USB (timeout 15s)...")
            self.device = frida.get_usb_device(timeout=15) # Increased timeout
            logger.success("✓ Frida device connected.")
            return True
        except frida.TimedOutError:
            logger.error("❌ Timed out waiting for Frida USB device. Ensure frida-server is running on device.")
            logger.info("Run `burp-frame frida deploy` to start/restart the server, or check ADB connection.")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to get Frida device: {e}")
            logger.info("Ensure frida-server is running on your device and ADB forwarding is set up (e.g., `adb forward tcp:27042 tcp:27042`).")
            return False

    def is_process_alive(self, pid: int) -> bool:
        """
        Checks if a process with the given PID is still alive.
        """
        if not self.device:
            return False
        try:
            # Attempt to get process info; if it fails, process is likely dead
            self.device.get_process(pid)
            return True
        except frida.ProcessNotFoundError:
            return False
        except Exception as e:
            logger.warn(f"⚠️ Could not check process liveness for PID {pid}: {e}")
            return False

    def inject_script(self, package_name: str, launch_app: bool = True, frida_timeout: int = 60) -> bool:
        """
        Injects the universal bypass script into the target application.
        """
        if not self.device:
            logger.error("❌ Frida device not connected. Call connect_frida() first.")
            return False

        self.session = None 
        pid = None

        try:
            if launch_app:
                logger.info(f"Launching app '{package_name}' for injection via Frida spawn (timeout: {frida_timeout}s)...")
                try:
                    logger.info(f"Checking for existing instances of '{package_name}' to kill before spawning...")
                    running_process = self.device.get_process(package_name) 
                    if running_process:
                        logger.info(f"App '{package_name}' is already running (PID: {running_process.pid}). Killing for clean spawn.")
                        self.device.kill(running_process.pid)
                        time.sleep(1) # Give it a moment to terminate
                except frida.ProcessNotFoundError:
                    pass
                except Exception as e:
                    logger.warn(f"⚠️ Error checking/killing running app before spawn: {e}")

                pid = self.device.spawn([package_name], timeout=frida_timeout)
                logger.info(f"App '{package_name}' spawned with PID: {pid}. Attempting to attach...")
                self.session = self.device.attach(pid) 
                logger.info(f"Attached to spawned app '{package_name}' (PID: {pid}). Resuming process...")
                self.device.resume(pid)
                time.sleep(2) # Give it a moment to resume and potentially crash
                
            else: # Attach to already running app
                logger.info(f"Attempting to ATTACH to running app '{package_name}' for injection (timeout: {frida_timeout}s)...")
                try:
                    self.session = self.device.attach(package_name) 
                    pid = self.session.pid
                    logger.info(f"Attached to '{package_name}' (PID: {pid}).")
                    time.sleep(2) # Give it a moment to attach and potentially crash
                except frida.ProcessNotFoundError:
                    logger.error(f"❌ Application '{package_name}' is not running. Cannot attach.")
                    return False
                except frida.TimedOutError:
                    logger.error(f"❌ Timeout trying to attach to '{package_name}'. This might mean the app started and died quickly or Frida server is unresponsive.")
                    logger.info("Ensure the app is stable and `frida-server` is healthy.")
                    return False
            
            # Post-attachment/spawn check
            if pid and not self.is_process_alive(pid):
                logger.error(f"❌ Target application process (PID: {pid}) for '{package_name}' is no longer alive immediately after Frida operation. It likely crashed.")
                logger.info("This indicates a strong anti-tampering mechanism or a stability issue with the app/emulator.")
                return False
            elif not self.session:
                logger.error("❌ Frida session could not be established despite process possibly being alive.")
                return False

            logger.info("Frida session is active. Loading universal bypass script...")
            script = self.session.create_script(self.UNIVERSAL_BYPASS_JS)
            
            def on_message(message: dict, data):
                """Callback function to handle messages from the Frida script."""
                if message['type'] == 'send':
                    payload = message.get('payload', '')
                    if isinstance(payload, str):
                        if payload.startswith('[DIAGNOSTIC]'):
                            logger.debug(f"[FRIDA-JS-DIAG] {payload[13:].strip()}")
                        elif payload.startswith('[INFO]'):
                            logger.info(f"[FRIDA-JS] {payload[6:].strip()}")
                        elif payload.startswith('[WARN]') or payload.startswith('[WARNING]'):
                            logger.warn(f"[FRIDA-JS] {payload[6:].strip()}")
                        elif payload.startswith('[ERROR]'):
                            logger.error(f"[FRIDA-JS] {payload[7:].strip()}")
                        elif payload.startswith('[+]'):
                            logger.success(f"[FRIDA-JS] {payload[3:].strip()}")
                        elif payload.startswith('[-]'):
                            logger.info(f"[FRIDA-JS] {payload[3:].strip()}")
                        elif payload.startswith('[*]'):
                            logger.info(f"[FRIDA-JS] {payload[3:].strip()}")
                        elif payload.startswith('[!]'):
                            logger.warn(f"[FRIDA-JS] {payload[3:].strip()}")
                        else:
                            logger.info(f"[FRIDA-JS] {payload}")
                    else:
                        logger.info(f"[FRIDA-JS] {payload} (type: {type(payload).__name__})")
                elif message['type'] == 'error':
                    logger.error(f"[FRIDA-SCRIPT ERROR] {message.get('description', 'Unknown error')}")
                    if 'stack' in message:
                        logger.debug(f"[FRIDA-SCRIPT STACK] {message['stack']}")
                else:
                    logger.debug(f"[FRIDA-UNKNOWN MESSAGE TYPE] {message}")

            script.on('message', on_message)
            script.load()
            
            logger.success("✓ Universal bypass script loaded and injected successfully.")
            logger.info("SSL Pinning, Debugger, Root, and Emulator checks should now be bypassed for this application.")
            logger.info("To maintain the bypass, keep this terminal session open. Press Ctrl+C to detach Frida.")
            
            sys.stdin.read()

            return True
        except frida.core.RPCException as e:
            logger.error(f"❌ Frida RPC error during script injection: {e}")
            logger.info("This often means the injected script encountered a runtime error, or the target process died unexpectedly.")
            logger.info("Check the Frida script output for detailed errors reported by the script. If the process crashed, no further script output will be seen.")
            return False
        except frida.TransportError as e:
            logger.error(f"❌ Frida transport error during script injection: {e}")
            logger.info("This could be a timeout or connection loss. Ensure `frida-server` is stable on your device, ADB forwarding is correct, and network connectivity is robust.")
            logger.info("You might need to kill the app/process, restart frida-server (`burp-frame frida deploy`), or reboot the device.")
            return False
        except frida.NotSupportedError as e:
            logger.error(f"❌ Frida Not Supported Error: {e}")
            logger.info("This often means `frida-server` does not have sufficient permissions to attach to the process (e.g., **device not rooted**, or **SELinux restrictions**).")
            logger.info("Ensure your Android device is properly rooted and `frida-server` is running with root privileges.")
            logger.info("For non-rooted devices, you may need to use a Frida Gadget, which is outside the scope of this universal bypass feature.")
            return False
        except Exception as e:
            logger.error(f"❌ An unexpected critical error occurred during script injection: {e}")
            logger.info("Please ensure all dependencies are correctly installed and configured.")
            return False
        finally:
            if self.session:
                try:
                    self.session.detach()
                    logger.info("Frida session detached.")
                except Exception as e:
                    logger.warn(f"⚠️ Warning: Error detaching Frida session gracefully: {e}")
