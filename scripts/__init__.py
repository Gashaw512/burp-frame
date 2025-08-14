# burp-frame/scripts/__init__.py

# Define package version
# This __version__ string should ideally match the version in pyproject.toml
__version__ = "1.0.0"

# Define what names are exposed when someone does `from scripts import *`
# This helps control the public API of your package.
__all__ = [
    'logger',             # The logger module (scripts/logger.py)
    'utils',              # The utilities module (scripts/utils.py)
    'config',             # The config module (scripts/config.py)
    'device_manager',     # The device_manager module (scripts/device_manager.py)
    'cert_manager',       # The cert_manager module (scripts/cert_manager.py)
    'proxy_manager',      # The proxy_manager module (scripts/proxy_manager.py)
    'frida_manager',      # The frida_manager module (scripts/frida_manager.py)
    'bypass_ssl_manager', # The bypass_ssl_manager module (scripts/bypass_ssl_manager.py)
    'modules',            # The modules sub-package (scripts/modules/)
    'cli'                 # The cli module (scripts/cli.py)
]

# We do NOT instantiate Logger or load config here directly.
# The cli.py (main entry point) should handle these instantiations
# to avoid circular imports and side effects upon general package import.
