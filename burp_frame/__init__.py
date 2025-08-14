# burp-frame/burp_frame/__init__.py

# Define package version
# This __version__ string should ideally match the version in pyproject.toml
__version__ = "1.0.0"

# Define what names are exposed when someone does `from burp_frame import *`
# This helps control the public API of your package.
__all__ = [
    'logger',             # The logger module (burp_frame/logger.py)
    'utils',              # The utilities module (burp_frame/utils.py)
    'config',             # The config module (burp_frame/config.py)
    'device_manager',     # The device_manager module (burp_frame/device_manager.py)
    'cert_manager',       # The cert_manager module (burp_frame/cert_manager.py)
    'proxy_manager',      # The proxy_manager module (burp_frame/proxy_manager.py)
    'frida_manager',      # The frida_manager module (burp_frame/frida_manager.py)
    'bypass_ssl_manager', # The bypass_ssl_manager module (burp_frame/bypass_ssl_manager.py)
    'modules',            # The modules sub-package (burp_frame/modules/)
    'cli'                 # The cli module (burp_frame/cli.py)
]

# We do NOT instantiate Logger or load config here directly.
# The cli.py (main entry point) should handle these instantiations
# to avoid circular imports and side effects upon general package import.
