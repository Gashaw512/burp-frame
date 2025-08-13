# 🔐 burp-frame – Unified Android Penetration Testing Framework

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Gashaw%20Kidanu-orange)](#)

**burp-frame** is a **professional-grade, cross-platform automation tool** meticulously designed to streamline mobile security assessments on ​**rooted Android devices and emulators​**. It functions as a **"one-shot" tester's toolkit** 🎯, unifying essential tasks for **HTTPS traffic interception** and ​**dynamic analysis**​, encompassing comprehensive certificate management, flexible global and per-application proxy configurations, robust Frida server deployment, and advanced, **​**highly effective SSL pinning and security bypass techniques**​.

Built for  **security professionals**, **pen testers**, and **mobile developers**,`burp-frame` automates complex, multi-step workflows with a **user-friendly yet powerful command-line interface (CLI)**, supported by robust logging and cross-platform compatibility.

![burpDrop Workflow](https://via.placeholder.com/800x400?text=BurpDrop+Workflow+Diagram)

---


## ✨ Key Features

-   **Unified CLI**: A singular, intuitive command-line interface for orchestrating all Android pentesting operations, simplifying complex workflows.
    
-   **Certificate Installation (`install` module)**:
    
    -   **One-command certificate installation** of Burp Suite CA certificates directly onto the Android device.
        
    -   **Automates conversion** of Burp CA certificates from DER format to the Android-compatible `.0` format, complete with subject hash calculation.
        
    -   **Intelligent deployment**: Pushes converted certificates to the traditional `/system/etc/security/cacerts/` path, or leverages the systemless capabilities of Magisk.
        
    -   **Magisk Support**: Specifically designed to install certificates seamlessly into the systemless Magisk path, maintaining system integrity.
        
    -   **Dry-run mode**: Allows simulation of the entire certificate installation process without making any actual modifications to the device, ideal for testing and verification.
        
-   **Proxy Management (`proxy` module)**:
    
    -   **Flexible global HTTP proxy settings**: Easily set and clear system-wide HTTP proxy configurations on the Android device via ADB for comprehensive traffic interception.
        
    -   **(Conceptual) Per-application proxy settings**: Provides a framework for managing proxy settings for specific applications, though practical effectiveness may vary across Android versions and app implementations.
        
    -   **Connectivity testing**: Includes functionality to test the configured global proxy's connectivity, ensuring your interception setup is active and correctly routing traffic.
        
    -   **Network intelligence**: Discover and display active network interfaces and their associated IP addresses on the connected device.
        
-   **Frida Integration (`frida` module)**:
    
    -   **Automated Frida server deployment**: Deploys the appropriate `frida-server` binary to the connected Android device based on its architecture and intelligently attempts to start it in the background.
        
    -   **Process management**: List all running processes on the device, and kill processes efficiently by either their PID or package name.
        
    -   **Script injection**: Launch target applications with a custom Frida JavaScript script immediately injected, enabling early instrumentation.
        
    -   **Advanced Certificate Re-Pinning Bypass**: A specialized Frida capability to inject a custom CA certificate (like your Burp CA) directly into an application's trust store at runtime, effectively bypassing SSL pinning even when traditional certificate installation methods fail.
        
-   **SSL Pinning & Security Bypasses (`bypass-ssl` & `universal-bypass` modules)**:
    
    -   **Generic SSL Bypass**: Facilitates the management (listing, downloading) and application of general-purpose Frida scripts designed to bypass various forms of SSL pinning implemented in Android applications.
        
    - **Comprehensive Universal Bypass**: It provides **one-shot bypassing of common Android security mechanisms** directly from your terminal. Deploys a **powerful, all-in-one Frida  script (enhanced with the latest techniques)** to comprehensively bypass multiple crucial security checks, including:
      - **SSL pinning:** Covering multiple methods including OkHttp, Conscrypt, and HostnameVerifier.
      - **Root detection:** Bypassing checks via filesystem anomalies, Runtime exec calls, SystemProperties, and common libraries like RootBeer.
      - **Debugger checks:** Circumventing detection mechanisms for attached debuggers.
      - **Emulator checks:** Masking indicators that reveal an application is running in an emulated environment.

-   **Device Management (`device` module)**:
    
    -   **Essential device control**: Remotely reboot the connected Android device.
        
    -   **File system manipulation**: Remount the `/system` partition as either read-write (`remount-rw`) or read-only (`remount-ro`), crucial for system-level modifications (requires root).
        
    -   **Device discovery**: List all currently connected ADB devices and their properties.
        
    -   **Application lifecycle management**: Effortlessly install and uninstall APKs onto the device.
        
    -   **Flexible connectivity**: Connect to and disconnect from ADB devices over TCP/IP (e.g., for Wi-Fi debugging).
        
-   **Automation & Usability**:
    
    -   **Automated cleanup**: Ensures all temporary certificate files and directories created by the framework are removed upon application exit.
        
    -   **Interactive and intelligent CLI**: Provides clear prompts, auto-validation of inputs, and helpful, context-aware messages to guide the user.
        
    -   **Detailed logging**: Generates timestamped, categorized logs to a dedicated `logs/` directory, essential for auditing, troubleshooting, and documenting pentesting activities.
        
    -   **Cross-Platform Compatibility**: Fully supports Windows, macOS, and Linux operating systems.
---

## 📦 Requirements

- **Python 3.7+** The framework is built on modern Python features.
- **[ADB (Android Debug Bridge)](https://developer.android.com/studio/releases/platform-tools)** The primary tool for device communication. Ensure it's installed and accessible in your system's PATH.
- [OpenSSL](https://www.openssl.org/) available in `PATH`. It is required for certificate conversions. Ensure it's installed and available in your PATH.
- **Frida CLI (frida-tools):** Install via `pip install frida-tools` (note: `pip install frida` also covers the Python library requirement).
- **Frida Server:** The on-device component of Frida. `burp-frame frida deploy` automates its download and deployment, requiring a working internet connection for the initial setup.
- **Rooted Android device or emulator** Essential for modifying system partitions (e.g., for certificate installation) and for many advanced Frida operations.  (e.g., [Genymotion](https://www.genymotion.com/), or Magisk-patched Android Virtual Devices (AVDs))
- **Burp Suite CA certificate** Exported as a `.der` format file from Burp Suite. This is necessary for the `install` command and the `frida cert-repin` functionality.
---

## 🚀 Installation

### Option 1: From PyPI (recommended)

For the easiest installation, use pip:

```bash
pip install burp-frame

```

### Option 2: From source

For development or to access the latest features, clone the repository and install from source:

```bash
git clone https://github.com/Gashaw512/android-traffic-interception-guide
cd android-traffic-interception-guide/ # Navigate to the project root directory
pip install . # Installs the 'burp-frame' package from the current directory

```

> ✅ **Tip**: Always use a Python [virtual environment](https://docs.python.org/3/library/venv.html "null") (`python -m venv .venv` then `source .venv/bin/activate`) to isolate project dependencies and avoid conflicts with system-wide Python packages.

## ⚙️ Quick Start

Follow these steps to get started quickly with `burp-frame`:

### 1. Configure External Tool Paths

Before `burp-frame` can operate, you must tell it where to find your `adb` and `openssl` executables. You can also configure paths for Frida binaries if they are not in your system's `PATH`.

```
# Example for Windows:
burp-frame config --adb "C:\path\to\your\platform-tools\adb.exe" --openssl "C:\path\to\OpenSSL\bin\openssl.exe"

# Example for Linux/macOS:
burp-frame config --adb "/usr/local/bin/adb" --openssl "/usr/bin/openssl"

```

You can verify your current configuration settings at any time:

```bash
burp-frame config

```

### 2. Connect Your Android Device

Ensure your Android device (physical or emulator) is properly connected and recognized by ADB.

-   Enable **USB debugging** on your Android phone or emulator (typically found in Developer Options).
    
-   Verify your device is detected by ADB:
    
```bash
    adb devices
    
```
    

### 3. Deploy Frida Server

For all Frida-related commands to function, the `frida-server` must be running on your Android device. `burp-frame` automates this process:

```bash
burp-frame frida deploy

```

# 📝 Command-Specific Usage

## install Module: Certificate Installation
Automates installing Burp Suite's CA certificate on your Android device.

1. **Export Burp certificate:**  
   In Burp Suite: `Proxy → Proxy Settings/Options → Import/Export CA Certificate`. Choose DER format and save (e.g., `burp.der`).

2. **Standard interactive install (prompt-based):**  
```bash
   burp-frame install
```
(You'll be prompted to select the certificate file path). The device will automatically reboot once successful.

### Install for Magisk systemless root:
```bash
burp-frame install --magisk
```
### Simulate installation without making changes:
```bash
burp-frame install --dry-run
```
## proxy Module: Device Proxy Configuration
Manages global and conceptual per-app HTTP proxy settings.

### Set global HTTP proxy:
```bash
burp-frame proxy set <YOUR_HOST_IP>:8080
```
Example:
```bash
burp-frame proxy set 192.168.1.100:8080
```
### Clear global HTTP proxy:
```bash
burp-frame proxy clear
```
### Get current global HTTP proxy settings:
```bash
burp-frame proxy get
```
### Test global HTTP proxy connection:
```bash
burp-frame proxy test --url http://google.com
```
### Display device IP addresses:
```bash
burp-frame proxy ips
```
### (Conceptual) Set per-app proxy:
```bash
burp-frame proxy app set com.example.app <YOUR_HOST_IP>:8080
```

### (Conceptual) Clear per-app proxy::
```bash
burp-frame proxy app clear com.example.app
```

### (Conceptual) List apps with proxy settings::
```bash
burp-frame proxy app list
```
## frida Module: Dynamic Instrumentation
Interact with Frida for process management and script injection.

### Deploy Frida server to the device:
```bash
burp-frame frida deploy
```
### List all running processes on the device:
```bash
burp-frame frida ps
```
### Kill a process by PID or package name:
```bash
burp-frame frida kill <PID_OR_PACKAGE_NAME>
# Example: burp-frame frida kill com.example.app
```
### Launch an app and inject a custom Frida script:
```bash
burp-frame frida launch <PACKAGE_NAME> --script /path/to/your/custom_frida_script.js
```
### Apply certificate re-pinning bypass (using a custom CA):
This command pushes a local certificate (e.g., your Burp CA) to the device and uses a Frida script to inject it into the app's trust store.

```bash
burp-frame frida cert-repin <PACKAGE_NAME> --cert /path/to/your/burp_certificate_file.0
```
To attach to a running app:
```bash
burp-frame frida cert-repin <PACKAGE_NAME> --cert /path/to/your/burp_certificate_file.0 --attach
```
💡 Note: The .0 certificate file is generated by burp-frame install (or manually converted from DER using openssl).
## bypass-ssl Module: Generic SSL Pinning Bypasses
Manage and apply general-purpose SSL pinning bypass scripts.

### List available local SSL bypass scripts:
```bash
burp-frame bypass-ssl list
```
### Download a generic SSL bypass script:
```bash
burp-frame bypass-ssl download
```
### Apply a local SSL bypass script to a target application:
```bash
burp-frame bypass-ssl apply <PACKAGE_NAME> --script universal_bypass.js
```
#### To attach to a running app:
```bash
burp-frame bypass-ssl apply <PACKAGE_NAME> --script universal_bypass.js --target-running
```
## universal-bypass Module: Comprehensive Security Bypasses
Apply a powerful, all-in-one Frida script to bypass various security checks.

### Apply universal bypass (launches app and injects):
```bash
burp-frame universal-bypass <PACKAGE_NAME>
```
### Apply universal bypass (attaches to running app and injects):
```bash
burp-frame universal-bypass <PACKAGE_NAME> --attach
```
⚠️ **Important:** Both `frida cert-repin` and `universal-bypass` commands will keep your terminal session active to maintain the Frida injection. Close the session (Ctrl+C) when you are done.

## device Module: Android Device Management
Control device state and manage installed applications.

### Reboot the connected Android device:
```bash
burp-frame device reboot
```
### Remount /system partition as read-write (requires root):
```bash
burp-frame device remount-rw
```
### Remount /system partition as read-only (requires root):
```bash
burp-frame device remount-ro
```
### List all connected ADB devices:
```bash
burp-frame device ls
```
### Install an APK file onto the device:
```bash
burp-frame device install /path/to/your/app.apk
```
### Uninstall an application by package name:
```bash
burp-frame device uninstall com.example.app
```
### Connect to a device over TCP/IP:
```bash
burp-frame device connect 192.168.1.10:5555
```
### Disconnect from a device over TCP/IP:
```bash
burp-frame device disconnect 192.168.1.10:5555
```

## config Module: Tool Path Configuration
Manage paths for external tools like ADB, OpenSSL, and Frida binaries.

### Interactive configuration wizard:
```bash
burp-frame config
```
### Set specific paths directly:
```bash
burp-frame config --adb "/path/to/adb" --openssl "/path/to/openssl" --frida-server-binary "/path/to/frida-server" --frida-cli "/path/to/frida"
```
### View current configuration:
```bash
burp-frame config
```
You can also manually inspect the `config.json` file located in the user's config directory:

- **Linux/macOS:** `~/.config/burp-frame/config.json`
- **Windows:** `C:\Users\YOUR_USER\AppData\Roaming\burp-frame\config.json`

## logs Module: View Operation Logs
Access detailed operation logs for troubleshooting and auditing.

### View recent logs and select a log file to display:
```bash
burp-frame logs
```
⚠️ **Troubleshooting**

| Issue                                                | Solution                                                                                                          |
|------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| ❌ adb or openssl not found                          | Run `burp-frame config` to set the correct paths.                                                               |
| ❌ Certificate conversion fails                       | Ensure OpenSSL is installed and accessible. Confirm the certificate is in DER format.                            |
| ❌ Device not detected                                | Run `adb devices` to confirm connection. Ensure USB debugging is enabled on your device. Check ADB drivers if on Windows. For remote connections, ensure `adb tcpip` is enabled on the device and firewall allows connection. |
| ❌ frida-server not running/found                    | After `burp-frame frida deploy`, verify `frida-server` is running on the device. Check device logs for errors if it fails to start. |
| ❌ Frida attachment fails                             | Ensure the target app is running (for `--attach`), correct package name is used, and device has `frida-server` running. Check device memory and process limits. |
| ⚠️ adb remount fails                                 | Ensure your device/emulator is rooted. Some devices have dm-verity enabled on `/system`. Try `adb disable-verity` followed by `adb reboot`, `adb root`, then `adb remount`. |
| ❌ ImportError after PyPI install                    | Ensure `pip install burp-frame` completed without errors. If running from source, make sure you ran `pip install .` from the project root (where `pyproject.toml` is). |
| ❌ TypeError: ArgumentParser.__init__() got an unexpected keyword argument 'formatter' | Update your `cli.py` to use `formatter_class=argparse.RawTextHelpFormatter` instead of `formatter=...` in all `add_parser` calls. |

📚 **FAQ**

### How do I export the certificate from Burp?
Go to: `Proxy → Options → Import/Export CA Certificate`. Choose DER format and save the file (e.g., `burp.der`).

### Why does burp-frame require root access for certificate installation?
Android mandates that trusted CA certificates are installed into the system's certificate store, which resides in a protected `/system` partition. Modifying this partition requires root privileges. Magisk provides a systemless way to do this.

### My emulator isn't rooted. What now?
`burp-frame` requires root access for system-level certificate installation and many advanced Frida operations. Use one of the following:
- ✅ **Genymotion** (emulators are rooted by default).
- ✅ **Magisk-patched AVDs** (Android Virtual Devices).
- ✅ **Custom rooted emulator images**.

### adb remount fails?
This is usually due to `dm-verity` issues on the device. Ensure the device is rooted and consider disabling `dm-verity` if necessary.









## ⚙️ Quick Start

### 1. Export your Burp certificate

In **Burp Suite**:  
`Proxy → Proxy Settings/ Options → Import / Export CA Certificate`

- Choose **DER format**
- Save it as `burp.der`

---

### 2. Connect your Android device

- Enable **USB debugging** on your phone or emulator  
- Ensure `adb` is accessible from your terminal (i.e., added to your system `PATH`)

---
### 3. Install the certificate

Run:

```bash
burpdrop install

```

> You’ll be prompted to select the certificate file path

> The device will automatically reboot once the installation is successful
---
## 🧪 Example Usage

```bash

# Standard interactive install (prompt-based)
burpdrop install

# Install for Magisk systemless root
burpdrop install --magisk

# Simulate installation without making changes
burpdrop install --dry-run

# View recent logs
burpdrop logs

# Interactive configuration wizard (to set adb/openssl paths)
burpdrop config

# Set ADB and OpenSSL paths directly
burpdrop config --adb "/path/to/adb" --openssl "/path/to/openssl"

# Help
burpdrop help

```

---
## ⚠️ Troubleshooting

| Issue                          | Solution                                                                 |
|-------------------------------|--------------------------------------------------------------------------|
| ❌ `adb` not found             | Run `burpdrop config` to set the correct path                           |
| ❌ Certificate conversion fails| Make sure **OpenSSL** is installed and the cert is in **DER** format     |
| ❌ Device not detected         | Run `adb devices` to confirm connection; ensure **USB debugging** is enabled |
| ⚠️ `adb remount` fails        | Ensure your device/emulator is **rooted**. Use `adb root` if needed      |





| Issue | Solution | |-------------------------------|--------------------------------------------------------------------------| | ❌ adb not found | Run burpdrop config to set the correct path | | ❌ Certificate conversion fails| Make sure OpenSSL is installed and the cert is in DER format | | ❌ Device not detected | Run adb devices to confirm connection; ensure USB debugging is enabled | | ⚠️ adb remount fails | Ensure your device/emulator is rooted. Use adb root if needed | | ❌ ImportError on local run | Ensure you are running with pip install . or using the wrapper scripts (burpDrop.sh/.bat) |

> This will render as a neat table on GitHub. Let me know if you'd prefer a bullet list format or collapsible FAQs instead.
---
## 🔧 Configuration

o set up or override tool paths, use the config command:

```bash

burpdrop config

```
You can also manually edit the config.json file located inside the installed package (e.g., site-packages/burpdrop/scripts/config.json).

```json

{
  "adb_path": "/custom/path/to/adb",
  "openssl_path": "/custom/path/to/openssl"
}
```
---
## 📚 FAQ

### ❓ How do I export the certificate from Burp?

Go to:  
**Proxy → Options → Import/Export CA Certificate**  
- Choose **DER format**  
- Save the file (e.g., `burp.der`)

---

### ❓ My emulator isn’t rooted. What now?

`burpDrop` requires root access to push the certificate to `/system/`.  
Use one of the following:

- ✅ Genymotion (emulators are rooted by default)  
- ✅ Magisk-patched AVDs  
- ✅ Custom rooted emulator images

---

### ❓ `adb remount` fails?

This is usually due to **verity** being enabled on the system partition.  
Try running:

```bash
adb disable-verity
adb reboot
adb root
adb remount

```
---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!  
If you’d like to help improve **burpDrop**, follow these steps:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

📄 **CONTRIBUTING.md** – _coming soon_

For suggestions, feedback, or collaboration inquiries:  
📧 [kidanugashaw@gmail.com](mailto:kidanugashaw@gmail.com)

---

## 📝 License

Distributed under the **MIT License**.  
© 2025 [Gashaw Kidanu](https://github.com/yourusername).  
See the [LICENSE](LICENSE) file for full details.

---

## 👋 Final Notes

**burpDrop** is actively maintained and designed for extensibility.  
Whether you’re a red teamer, security engineer, or mobile developer —  
this tool streamlines the HTTPS interception process on Android.

> **Intercept with confidence. Secure with precision.**  
> — _burpDrop_

---



