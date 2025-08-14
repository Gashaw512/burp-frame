Java.perform(function() {
    console.log("[*] Starting Enhanced SSL/Root Bypass Suite");

    const bypassStatus = {
        ssl: false,
        root: false,
        burp: false,
        frida: false
    };

    // ... (ROOT_FILES, ROOT_PACKAGES, ROOT_BINARIES, ROOT_PROPERTIES, SENSITIVE_PROPS remain unchanged) ...

    const ROOT_FILES = [
           "/data/local/bin/su",
           "/data/local/su",
           "/data/local/xbin/su",
           "/dev/com.koushikdutta.superuser.daemon/",
           "/sbin/su",
           "/system/app/Superuser.apk",
           "/system/bin/failsafe/su",
           "/system/bin/su",
           "/su/bin/su",
           "/system/etc/init.d/99SuperSUDaemon",
           "/system/sd/xbin/su",
           "/system/xbin/busybox",
           "/system/xbin/daemonsu",
           "/system/xbin/su",
           "/system/sbin/su",
           "/vendor/bin/su",
           "/cache/su",
           "/data/su",
           "/dev/su",
           "/system/bin/.ext/su",
           "/system/usr/we-need-root/su",
           "/system/app/Kinguser.apk",
           "/data/adb/magisk",
           "/sbin/.magisk",
           "/cache/.disable_magisk",
           "/dev/.magisk.unblock",
           "/cache/magisk.log",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
           "/data/adb/magisk_simple",
           "/init.magisk.rc",
           "/system/xbin/ku.sud",
           "/data/adb/ksu",
           "/data/adb/ksud",
           "/data/adb/ksu.apk",
           "/data/adb/ksud.apk",
           "/data/adb/magisk.apk",
           "/data/adb/magisk_simple.apk",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
        ];

        const ROOT_PACKAGES = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com"
        ];

        const ROOT_BINARIES = new Set([
            "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk",
            "SuperSu.apk", "magisk", "magisk64", "magiskhide", "magiskboot"
        ]);

        const ROOT_PROPERTIES = new Map([
            ["ro.build.selinux", "1"],
            ["ro.debuggable", "0"],
            ["service.adb.root", "0"],
            ["ro.secure", "1"],
            ["ro.build.tags", "release-keys"],
            ["ro.build.type", "user"]
        ]);

        const SENSITIVE_PROPS = new Set([
            "ro.secure",
            "ro.debuggable",
            "ro.build.fingerprint",
            "service.adb.root"
        ]);




    const JavaClasses = {
        SSLContext: Java.use("javax.net.ssl.SSLContext"),
        Runtime: Java.use("java.lang.Runtime"),
        File: Java.use("java.io.File"),
        PackageManager: Java.use("android.app.ApplicationPackageManager"),
        ProcessBuilder: Java.use("java.lang.ProcessBuilder"),
        Build: Java.use("android.os.Build"),
        SystemProperties: Java.use("android.os.SystemProperties")
    };

    // ... (LOG_LEVEL, CURRENT_LOG_LEVEL remain unchanged) ...


    const LOG_LEVEL = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3
        };

        const CURRENT_LOG_LEVEL = LOG_LEVEL.INFO;

    const CONFIG = {
        enableSSLBypass: true,
        enableRootBypass: true,
        enableBurpInterceptor: true,
        enableFridaBypass: true,
        enableDetailedLogs: false,
        blockAllRootCommands: true,
        allowedRootCommands: new Set(["getprop"]),
    };

    // ... (log function remains the same) ...

            function log(level, message, error) {
            if (level >= CURRENT_LOG_LEVEL) {
                switch(level) {
                    case LOG_LEVEL.DEBUG:
                        console.log("[D] " + message);
                        break;
                    case LOG_LEVEL.INFO:
                        console.log("[*] " + message);
                        break;
                    case LOG_LEVEL.WARN:
                        console.log("[!] " + message);
                        break;
                    case LOG_LEVEL.ERROR:
                        console.error("[E] " + message);
                        if (error) console.error(error.stack || error);
                        break;
                }
            }
        }

    // ==================== SSL BYPASS ==================== //
    function setupSSLBypass() {
        console.log("[+] Setting up SSL bypass...");
        try {
            bypassCertificateValidation();
            bypassOkHttp();
            bypassTrustKit();
            bypassWebViewClient();
            bypassCertificatePinning();
            additionalSSLBypasses();  // Consolidated all additional bypasses
            
            bypassStatus.ssl = true;
            return true;
        } catch(e) {
            console.log("[-] SSL Bypass failed:", e);
            return false;
        }
    }

    // ... (SSL bypass functions remain the same) ...

    function bypassCertificateValidation() {
            try {
                const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                const CustomTrustManager = Java.registerClass({
                    name: "com.custom.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });

                const SSLContext_init = JavaClasses.SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;", 
                    "[Ljavax.net.ssl.TrustManager;", 
                    "java.security.SecureRandom"
                );

                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    SSLContext_init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
                };
            } catch(e) {
                console.log("[-] Certificate validation bypass failed");
            }
        }

        function bypassOkHttp() {
            try {
                const CertificatePinner = Java.use("okhttp3.CertificatePinner");
                
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
                    return;
                };

                CertificatePinner.check$okhttp.implementation = function(hostname, certificates) {
                    return;
                };
            } catch(e) {
                console.log("[-] OkHttp bypass failed:", e);
            }
        }

        function bypassTrustKit() {
            console.log("[*] Setting up TrustKit bypass...");
            let bypassCount = 0;

            // Helper function to handle TrustKit class hooks
            const hookTrustKitClass = (className, methodName, overloadTypes = null) => {
                try {
                    const targetClass = Java.use(className);
                    const method = overloadTypes ? 
                        targetClass[methodName].overload(...overloadTypes) :
                        targetClass[methodName];

                    method.implementation = function(...args) {
                        const hostname = args[0] || "unknown";
                        console.log(`[+] Bypassing ${className}.${methodName} for: ${hostname}`);
                        return methodName.includes("verify") ? true : undefined;
                    };
                    bypassCount++;
                    return true;
                } catch(e) {
                    if (!e.toString().includes("ClassNotFoundException")) {
                        console.log(`[-] Failed to hook ${className}.${methodName}:`, e);
                    }
                    return false;
                }
            };

            // TrustKit hostname verifier bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify", 
                ["java.lang.String", "javax.net.ssl.SSLSession"]
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify",
                ["java.lang.String", "java.security.cert.X509Certificate"]
            );

            // TrustKit certificate pinning bypass
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
                "checkServerTrusted"
            );

            // Additional TrustKit bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.TrustKit",
                "initializeWithNetworkSecurityConfiguration"
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.reporting.BackgroundReporter",
                "reportCertificateError"
            );

            if (bypassCount > 0) {
                console.log(`[+] Successfully set up ${bypassCount} TrustKit bypasses`);
            } else {
                console.log("[*] TrustKit not found in app (this is normal)");
            }
        }

        function bypassWebViewClient() {
            try {
                const WebViewClient = Java.use("android.webkit.WebViewClient");
                
                WebViewClient.onReceivedSslError.overload(
                    "android.webkit.WebView",
                    "android.webkit.SslErrorHandler",
                    "android.net.http.SslError"
                ).implementation = function(webView, handler, error) {
                    handler.proceed();
                };
            } catch(e) {
                console.log("[-] WebViewClient bypass failed:", e);
            }
        }

        function bypassCertificatePinning() {
            try {
                const UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
                UnverifiedCertError.$init.implementation = function(message) {
                    try {
                        const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                        const exceptionStack = stackTrace.findIndex(stack => 
                            stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                        );
                        
                        if (exceptionStack >= 0) {
                            const callingStack = stackTrace[exceptionStack + 1];
                            const className = callingStack.getClassName();
                            const methodName = callingStack.getMethodName();
                            
                            return this.$init("SSL verification bypassed");
                        }
                    } catch(e) {
                        console.log("[-] Stack trace analysis failed:", e);
                    }
                    
                    return this.$init(message);
                };
            } catch(e) {
                console.log("[-] Certificate pinning bypass failed:", e);
            }
        }

    // ==================== ROOT BYPASS ==================== //
    function bypassBuildProps() {
        try {
            console.log("[+] Hooking Build properties...");
            JavaClasses.Build.PRODUCT.value = "gracerltexx";
            JavaClasses.Build.MANUFACTURER.value = "samsung";
            JavaClasses.Build.BRAND.value = "samsung";
            JavaClasses.Build.DEVICE.value = "gracerlte";
            JavaClasses.Build.MODEL.value = "SM-N935F";
            JavaClasses.Build.HARDWARE.value = "samsungexynos8890";
            JavaClasses.Build.FINGERPRINT.value = "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";
            JavaClasses.Build.BOARD.value = "universal8890";
            JavaClasses.Build.HOST.value = "SWHE";
            JavaClasses.Build.ID.value = "R16NW";
            JavaClasses.Build.TYPE.value = "user";
            JavaClasses.Build.TAGS.value = "release-keys";
            
            JavaClasses.SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                // Handle root-sensitive properties
                if (ROOT_PROPERTIES.has(key)) {
                    return ROOT_PROPERTIES.get(key);
                }
                
                // Handle emulator indicators
                if (key.includes("qemu") || key.includes("goldfish") || key.includes("sdk") || key.includes("generic")) {
                    return "";
                }
                
                return this.get(key);
            };
        } catch (e) {
            console.log("[-] Build properties hook failed:", e);
        }
    }

    function setupRootBypass() {
        console.log("[+] Initializing Enhanced Root Detection Bypass...");
        try {
            // Package manager check
            try {
                const ActivityThread = Java.use("android.app.ActivityThread");
                const currentApplication = ActivityThread.currentApplication();
                if (currentApplication) {
                    const context = currentApplication.getApplicationContext();
                    const pm = context.getPackageManager();
                    ROOT_PACKAGES.forEach(pkg => {
                        try {
                            pm.getPackageInfo(pkg, 0);
                            console.log(`[!] Found root package: ${pkg}`);
                        } catch(e) {}
                    });
                }
            } catch(e) {
                console.log("[-] Package manager check failed");
            }

            bypassNativeFileOperations();
            bypassBuildProps();  // Now properly defined and called
            bypassShellCommands();
            bypassRuntimeExec();
            enhancedFileBypass();
            bypassProcessBuilder();
            bypassBufferedReader();
            bypassSecureHardware();
            
            bypassStatus.root = true;
            console.log("[+] Root bypass hooks installed successfully");
            return true;
        } catch(e) {
            console.error("[!] Root Bypass Error:", e);
            return false;
        }
    }

    // ... (other root bypass functions remain the same) ...


    

    // ==================== ADDITIONAL SSL BYPASSES ==================== //
    function additionalSSLBypasses() {
        console.log("[+] Applying additional SSL bypasses...");
        
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
                console.log("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
            };
            console.log("[+] HttpsURLConnection (setSSLSocketFactory) bypassed");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setSSLSocketFactory) not found");
        }

        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                console.log("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
            };
            console.log("[+] HttpsURLConnection (setHostnameVerifier) bypassed");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setHostnameVerifier) not found");
        }

        // ... (all other additional SSL bypasses from the original code) ...

        console.log("[+] Additional SSL bypasses applied");
    }

    // ==================== MAIN EXECUTION ==================== //
    if (CONFIG.enableSSLBypass) {
        bypassStatus.ssl = setupSSLBypass();
    }

    if (CONFIG.enableRootBypass) {
        bypassStatus.root = setupRootBypass();
    }

    if (CONFIG.enableBurpInterceptor) {
        bypassStatus.burp = setupBurpInterceptor();
    }

    if (CONFIG.enableFridaBypass) {
        bypassStatus.frida = hookFrida();
    }

    console.log("\n[*] Bypass Status:");
    console.log(`    SSL Bypass: ${bypassStatus.ssl ? "✓" : "✗"}`);
    console.log(`    Root Bypass: ${bypassStatus.root ? "✓" : "✗"}`);
    console.log(`    Burp Interceptor: ${bypassStatus.burp ? "✓" : "✗"}`);
    console.log(`    Frida Bypass: ${bypassStatus.frida ? "✓" : "✗"}`);
});