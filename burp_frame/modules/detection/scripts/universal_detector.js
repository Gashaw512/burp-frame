/*
* comprehensive_detector.js - A comprehensive Frida script for detecting
* Android security countermeasures and gathering environmental data.
*/

// Main Frida entry point
Java.perform(function () {

    // Final result object to be sent back to the Python program
    const results = {
        detections: {
            ssl_pinning: false,
            root_detection: false,
            debugger_detection: false,
            emulator_detection: false,
            anti_frida: false,
        },
        app_environment: {
            files_directory: null,
            cache_directory: null,
            external_cache_directory: null,
            code_cache_directory: null,
            obb_dir: null,
            package_code_path: null,
        },
        device_environment: {
            application_name: null,
            model: null,
            board: null,
            brand: null,
            device: null,
            host: null,
            id: null,
            product: null,
            user: null,
            version: null,
        },
        summary: "No countermeasures detected.",
    };

    // --- Detection Functions ---

    /**
     * Hooks common SSL pinning methods and updates the results.
     */
    function detectSslPinning() {
        try {
            // Hook SSLPeerUnverifiedException for general pinning checks
            const UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
            UnverifiedCertError.$init.implementation = function (str) {
                results.detections.ssl_pinning = true;
                results.summary = "SSL Pinning detected. (SSLPeerUnverifiedException)";
                send(JSON.stringify({ type: 'hook_triggered', detail: 'javax.net.ssl.SSLPeerUnverifiedException' }));
                return this.$init(str);
            };

            // Hook OkHttp3 CertificatePinner for specific OkHttp-based checks
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certificates) {
                results.detections.ssl_pinning = true;
                results.summary = "SSL Pinning detected. (OkHttp3 CertificatePinner)";
                send(JSON.stringify({ type: 'hook_triggered', detail: 'okhttp3.CertificatePinner.check' }));
                return this.check(host, certificates);
            };
        } catch (e) {
            console.warn("Failed to hook SSL pinning classes:", e);
        }
    }

    /**
     * Hooks common root detection methods.
     */
    function detectRoot() {
        try {
            // Hook File.exists for root-related file checks
            const File = Java.use('java.io.File');
            const rootFiles = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su', '/system/xbin/su', '/data/local/xbin/su'];
            File.exists.implementation = function () {
                const path = this.getAbsolutePath();
                if (rootFiles.includes(path)) {
                    results.detections.root_detection = true;
                    results.summary = "Root detected. (File existence check)";
                    send(JSON.stringify({ type: 'hook_triggered', detail: `File.exists for: ${path}` }));
                }
                return this.exists();
            };
            
            // Hook Runtime.exec for shell command checks
            const Runtime = Java.use('java.lang.Runtime');
            const suCheckCommands = ['which su', 'id'];
            Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
                if (suCheckCommands.includes(cmd)) {
                    results.detections.root_detection = true;
                    results.summary = "Root detected. (Runtime.exec)";
                    send(JSON.stringify({ type: 'hook_triggered', detail: `Runtime.exec with command: ${cmd}` }));
                }
                return this.exec(cmd);
            };
        } catch (e) {
            console.warn("Failed to hook root detection classes:", e);
        }
    }

    /**
     * Hooks methods for debugger presence.
     */
    function detectDebugger() {
        try {
            const Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function () {
                results.detections.debugger_detection = true;
                results.summary = "Debugger detected. (isDebuggerConnected)";
                send(JSON.stringify({ type: 'hook_triggered', detail: 'android.os.Debug.isDebuggerConnected' }));
                return this.isDebuggerConnected();
            };
        } catch (e) {
            console.warn("Failed to hook debugger detection classes:", e);
        }
    }

    /**
     * Hooks methods for emulator presence.
     */
    function detectEmulator() {
        try {
            const Build = Java.use('android.os.Build');
            const properties = {
                'ro.kernel.qemu': 'emulator',
                'ro.build.tags': 'test-keys',
                'ro.product.device': 'generic',
            };
            for (const prop in properties) {
                const propValue = Build[prop];
                if (propValue && propValue.value.includes(properties[prop])) {
                    results.detections.emulator_detection = true;
                    results.summary = "Emulator detected. (Build property)";
                    send(JSON.stringify({ type: 'hook_triggered', detail: `Emulator property check on: ${prop}` }));
                }
            }
        } catch (e) {
            console.warn("Failed to check emulator properties:", e);
        }
    }

    /**
     * Hooks native functions for anti-Frida measures.
     */
    function detectAntiFrida() {
        try {
            const fopen = Module.findExportByName(null, 'fopen');
            if (fopen) {
                Interceptor.attach(fopen, {
                    onEnter: function (args) {
                        const filePath = Memory.readCString(args[0]);
                        if (filePath.includes('frida')) {
                            results.detections.anti_frida = true;
                            results.summary = "Anti-Frida detected. (fopen)";
                            send(JSON.stringify({ type: 'hook_triggered', detail: `fopen hook on: ${filePath}` }));
                        }
                    }
                });
            }
        } catch (e) {
            console.warn("Failed to hook fopen for anti-Frida:", e);
        }
    }

    // --- Information Gathering Functions ---

    /**
     * Gathers application-specific environment details.
     */
    function gatherAppEnvironment() {
        try {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const currentApplication = ActivityThread.currentApplication();
            if (currentApplication) {
                const context = currentApplication.getApplicationContext();
                results.app_environment.files_directory = context.getFilesDir().getAbsolutePath().toString();
                results.app_environment.cache_directory = context.getCacheDir().getAbsolutePath().toString();
                results.app_environment.external_cache_directory = context.getExternalCacheDir().getAbsolutePath().toString();
                results.app_environment.code_cache_directory = 'getCodeCacheDir' in context ? context.getCodeCacheDir().getAbsolutePath().toString() : 'n/a';
                results.app_environment.obb_dir = context.getObbDir().getAbsolutePath().toString();
                results.app_environment.package_code_path = context.getPackageCodePath().toString();
            }
        } catch (e) {
            console.warn("Failed to gather app environment data:", e);
        }
    }

    /**
     * Gathers device-specific environment details.
     */
    function gatherDeviceEnvironment() {
        try {
            const Build = Java.use('android.os.Build');
            const ActivityThread = Java.use('android.app.ActivityThread');
            const currentApplication = ActivityThread.currentApplication();
            const context = currentApplication.getApplicationContext();

            results.device_environment.application_name = context.getPackageName();
            results.device_environment.model = Build.MODEL.value.toString();
            results.device_environment.board = Build.BOARD.value.toString();
            results.device_environment.brand = Build.BRAND.value.toString();
            results.device_environment.device = Build.DEVICE.value.toString();
            results.device_environment.host = Build.HOST.value.toString();
            results.device_environment.id = Build.ID.value.toString();
            results.device_environment.product = Build.PRODUCT.value.toString();
            results.device_environment.user = Build.USER.value.toString();
            results.device_environment.version = Java.androidVersion;
        } catch (e) {
            console.warn("Failed to gather device environment data:", e);
        }
    }

    // --- Main Execution Block ---

    function main() {
        // Set up the detection hooks
        detectSslPinning();
        detectRoot();
        detectDebugger();
        detectEmulator();
        detectAntiFrida();

        // Gather environmental information immediately
        gatherAppEnvironment();
        gatherDeviceEnvironment();

        // Wait a moment for hooks to be triggered and then send the final report.
        setTimeout(() => {
            send(JSON.stringify({ type: 'final_report', payload: results }, null, 2));
        }, 5000);
    }

    main();

});