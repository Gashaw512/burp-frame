/**
 * Frida SSL Pinning Bypass Script
 *
 * This script is designed for ethical testing and debugging of your own Android applications.
 * It hooks into various Android Java APIs related to SSL/TLS certificate validation
 * and forces them to trust all certificates, effectively bypassing SSL pinning.
 *
 * Use this script responsibly on applications you have explicit permission to test.
 *
 * Components targeted:
 * 1. javax.net.ssl.X509TrustManager (General certificate validation)
 * 2. okhttp3.CertificatePinner (OkHttp specific pinning)
 * 3. android.webkit.WebViewClient (WebView SSL errors)
 * 4. com.datatheorem.android.trustkit (TrustKit library pinning)
 * 5. javax.net.ssl.SSLPeerUnverifiedException (Bypassing certificate pinning exceptions)
 * 6. javax.net.ssl.HostnameVerifier (General hostname verification)
 */

Java.perform(function() {
    console.log("[+] SSL Pinning Bypass Script Loaded!");

    // --- 1. Universal TrustManager Bypass ---
    // This is the most common and effective bypass, targeting the core X509TrustManager interface.
    // It makes the app trust any certificate presented by the server.
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const CustomTrustManager = Java.registerClass({
            name: "com.bypass.CustomTrustManager", // Unique class name to avoid conflicts
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    // console.log("[*] checkClientTrusted hooked: Client always trusted.");
                },
                checkServerTrusted: function(chain, authType) {
                    // This method is crucial for server certificate validation.
                    // By doing nothing, we implicitly trust the server.
                    // console.log("[*] checkServerTrusted hooked: Server always trusted.");
                },
                getAcceptedIssuers: function() {
                    // Return an empty array of accepted issuers.
                    // This tells the system that we don't have any predefined trusted CAs.
                    return [];
                }
            }
        });

        // Hook SSLContext.init to inject our custom TrustManager.
        // This makes sure our "trust-all" logic is applied when SSL contexts are initialized.
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] SSLContext.init hooked: Injecting custom TrustManager.");
            return this.init(keyManager, [CustomTrustManager.$new()], secureRandom);
        };
        console.log("[+] Universal X509TrustManager bypass applied.");
    } catch (e) {
        console.warn("[-] X509TrustManager bypass failed (this is normal if app uses different SSL implementation):", e.message);
    }

    // --- 2. OkHttp CertificatePinner Bypass ---
    // OkHttp is a very popular HTTP client library for Android.
    // It has its own certificate pinning mechanism.
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
            console.log("[+] OkHttp CertificatePinner.check hooked for:", hostname);
            // By returning nothing, we effectively bypass the pinning check.
            return;
        };

        // Newer versions or specific configurations of OkHttp might use this overload.
        CertificatePinner.check$okhttp.implementation = function(hostname, certificates) {
            console.log("[+] OkHttp CertificatePinner.check$okhttp hooked for:", hostname);
            return;
        };
        console.log("[+] OkHttp CertificatePinner bypass applied.");
    } catch (e) {
        console.warn("[-] OkHttp CertificatePinner bypass failed (this is normal if OkHttp is not used):", e.message);
    }

    // --- 3. WebViewClient Bypass ---
    // Android WebViews can also perform SSL validation. This hooks the method
    // that handles SSL errors and tells it to proceed anyway.
    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.overload(
            "android.webkit.WebView",
            "android.webkit.SslErrorHandler",
            "android.net.http.SslError"
        ).implementation = function(webView, handler, error) {
            console.log("[+] WebViewClient.onReceivedSslError hooked: Proceeding with SSL error for URL:", webView.getUrl());
            handler.proceed(); // Always proceed despite SSL errors
        };
        console.log("[+] WebViewClient bypass applied.");
    } catch (e) {
        console.warn("[-] WebViewClient bypass failed (this is normal if WebView is not used or different class):", e.message);
    }

    // --- 4. TrustKit Bypass ---
    // TrustKit is another common library for SSL pinning.
    // This attempts to hook its verification methods.
    const trustKitClasses = [
        "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
        "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
        "com.datatheorem.android.trustkit.TrustKit",
        "com.datatheorem.android.trustkit.reporting.BackgroundReporter"
    ];

    let trustKitBypassCount = 0;
    trustKitClasses.forEach(className => {
        try {
            const targetClass = Java.use(className);
            // Generic hook for any 'verify' or 'check' methods within these classes
            targetClass.$methods.forEach(methodName => {
                if (methodName.includes("verify") || methodName.includes("check")) {
                    const method = targetClass[methodName];
                    method.overloads.forEach(overload => {
                        overload.implementation = function(...args) {
                            console.log(`[+] TrustKit: Bypassing ${className}.${methodName} (overload ${overload.argumentTypes.length} args)`);
                            // For verification methods, return true (success)
                            if (overload.returnType.name === "boolean") {
                                return true;
                            }
                            // For other methods (e.g., reportCertificateError), just skip original call
                            return undefined; // Or return original call if desired: this[methodName].apply(this, args);
                        };
                        trustKitBypassCount++;
                    });
                }
            });
        } catch (e) {
            // Class not found is expected if TrustKit is not used by the app.
            // console.warn(`[-] TrustKit bypass for ${className} failed (normal if not used):`, e.message);
        }
    });
    if (trustKitBypassCount > 0) {
        console.log(`[+] TrustKit bypass applied. Hooked ${trustKitBypassCount} methods.`);
    } else {
        console.log("[*] TrustKit classes not found or not in use by target application (this is common).");
    }

    // --- 5. SSLPeerUnverifiedException Bypass ---
    // Some apps explicitly throw this exception to enforce pinning.
    // We hook the constructor to prevent it from being thrown.
    try {
        const UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
        UnverifiedCertError.$init.implementation = function(message) {
            console.log("[+] SSLPeerUnverifiedException constructor hooked: Suppressing exception.");
            // Instead of throwing the real exception, we call a benign constructor or just return.
            // This effectively swallows the pinning exception.
            return this.$init("SSL verification bypassed by Frida.");
        };
        console.log("[+] SSLPeerUnverifiedException bypass applied.");
    } catch (e) {
        console.warn("[-] SSLPeerUnverifiedException bypass failed (normal if not explicitly thrown by app):", e.message);
    }

    // --- 6. HostnameVerifier Bypass ---
    // This is for hostname validation, ensuring the hostname in the URL matches the one on the certificate.
    // We make it always return true.
    try {
        const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        HostnameVerifier.verify.implementation = function(hostname, session) {
            console.log("[+] HostnameVerifier.verify hooked: Always returning true for:", hostname);
            return true; // Always trust the hostname
        };
        console.log("[+] HostnameVerifier bypass applied.");

        // For HttpsURLConnection which often uses a default HostnameVerifier
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        const NullHostnameVerifier = Java.registerClass({
            name: 'com.bypass.NullHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) {
                    // console.log('[*] NullHostnameVerifier.verify: Always returning true for ' + hostname);
                    return true;
                }
            }
        });
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hv) {
            console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier hooked: Setting custom NullHostnameVerifier.");
            // Replace the app's default with our trust-all verifier
            return this.setDefaultHostnameVerifier(NullHostnameVerifier.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function(hv) {
            console.log("[+] HttpsURLConnection.setHostnameVerifier hooked: Setting custom NullHostnameVerifier.");
            // Replace any explicit verifier set by the app with our trust-all verifier
            return this.setHostnameVerifier(NullHostnameVerifier.$new());
        };
        console.log("[+] HttpsURLConnection HostnameVerifier bypass applied.");
    } catch (e) {
        console.warn("[-] HostnameVerifier bypass failed (normal if not used or different class):", e.message);
    }

    console.log("[+] All common SSL Pinning bypasses attempted. Check console for specific hook statuses.");
});
