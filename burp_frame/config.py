import os
import json

from .logger import Logger # Import the Logger (singleton)

# Initialize logger for this module (will get the singleton instance)
logger = Logger()

# --- Constants ---
# Define the path for the configuration file
# It will be located in the same directory as the config.py script
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def load_config():
    """
    Loads configuration settings from a JSON file.
    
    Returns:
        dict: A dictionary containing the loaded configuration settings.
              Returns an empty dictionary if the file does not exist or is invalid.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.debug("Configuration loaded.") # Changed to DEBUG level
                return config
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from configuration file: {CONFIG_FILE}. File might be corrupted.")
            return {}
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading configuration: {e}")
            return {}
    else:
        logger.info("Configuration file not found. Starting with empty configuration.")
        return {}

def save_config(config_data):
    """
    Saves configuration settings to a JSON file.
    
    Args:
        config_data (dict): A dictionary containing the configuration settings to save.
    
    Returns:
        bool: True if configuration was saved successfully, False otherwise.
    """
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=4)
        logger.success(f"Configuration saved to {CONFIG_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        return False
