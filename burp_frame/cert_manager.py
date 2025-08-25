import os
import re
import subprocess
import shutil # For robust directory cleanup
import hashlib # For SHA1 fingerprint calculation

from .logger import Logger
from .utils import TEMP_CERT_DIR, get_tool_path # Import TEMP_CERT_DIR and get_tool_path from utils

logger = Logger() # Corrected: Directly get the singleton Logger instance

def get_cert_file():
    """
    Prompts the user for the path to the Burp Suite .der certificate file.
    Includes robust path cleaning and user guidance.
    
    Returns:
        str or None: The absolute path to the .der certificate file, or None if cancelled/failed.
    """
    logger.info("\nPlease provide the path to your Burp Suite .der certificate.")
    logger.info("You can drag and drop the file into this window.")
    logger.info("(Type 'help' for assistance or 'exit' to cancel)")

    while True:
        try:
            path_input = input("Certificate path: ").strip()
            if not path_input:
                continue
            if path_input.lower() == 'help':
                logger.info("Help: Export Burp certificate from Proxy > Proxy Settings/Options > Import/Export CA Certificate.")
                logger.info("      Save as DER format (e.g., 'burp.der') and provide the full path here.")
                continue
            if path_input.lower() == 'exit':
                logger.info("Certificate path input cancelled.")
                return None

            # Clean path from potential quotes or escaped spaces from drag-and-drop
            clean_path = re.sub(r'^["\']|["\']$', '', path_input)
            clean_path = clean_path.replace("\\ ", " ") # Handle escaped spaces, common on Linux/macOS

            if not os.path.exists(clean_path):
                logger.error("❌ File not found. Please ensure the path is correct and try again.")
                continue
            if not clean_path.lower().endswith('.der'):
                logger.warning("⚠ File does not have a '.der' extension. This might not be a valid Burp certificate.")
                user_choice = input("Continue anyway? (y/N): ").strip().lower()
                if user_choice != 'y':
                    continue

            return os.path.abspath(clean_path)
        except KeyboardInterrupt:
            logger.warn("\nCertificate path input cancelled by user (Ctrl+C).")
            return None
        except Exception as e:
            logger.error(f"❌ An unexpected error occurred during path input: {str(e)}")
            continue

def convert_cert(cert_path, openssl_path):
    """
    Converts a DER certificate to the subject_hash.0 format for Android.
    This involves:
    1. Converting DER to PEM format.
    2. Calculating the OpenSSL subject hash (old method for Android compatibility).
    3. Renaming the PEM file to <subject_hash>.0.
    
    Args:
        cert_path (str): The local path to the input DER certificate file.
        openssl_path (str): The absolute path to the OpenSSL executable.
        
    Returns:
        tuple (str, str) or (None, None): A tuple containing the absolute path
                                          to the prepared .0 file and its hash,
                                          or (None, None) on failure.
    """
    try:
        # Ensure TEMP_CERT_DIR is clean
        if os.path.exists(TEMP_CERT_DIR):
            shutil.rmtree(TEMP_CERT_DIR)
        os.makedirs(TEMP_CERT_DIR, exist_ok=True)

        logger.info("Converting certificate format for Android installation...")
        pem_file = os.path.join(TEMP_CERT_DIR, "burp.pem")

        # Step 1: Convert DER to PEM
        logger.progress("Converting DER to PEM...", 1, 3)
        subprocess.run(
            [openssl_path, "x509", "-inform", "der", "-in", cert_path, "-out", pem_file],
            check=True, capture_output=True, text=True, encoding='utf-8' # check=True raises CalledProcessError on non-zero exit
        )
        logger.success("✓ DER to PEM conversion successful.")

        # Step 2: Calculate subject hash (old method)
        logger.progress("Calculating certificate subject hash...", 2, 3)
        result_hash = subprocess.run(
            [openssl_path, "x509", "-inform", "pem", "-subject_hash_old", "-in", pem_file],
            check=True, capture_output=True, text=True, encoding='utf-8'
        )
        cert_hash = result_hash.stdout.splitlines()[0].strip()
        logger.success(f"✓ Certificate subject hash calculated: {cert_hash}")

        # Step 3: Rename PEM to <hash>.0
        logger.progress("Finalizing conversion and naming...", 3, 3)
        hash_file = os.path.join(TEMP_CERT_DIR, f"{cert_hash}.0")
        os.rename(pem_file, hash_file) # Rename the PEM file to its hash.0 equivalent
        
        logger.success(f"✓ Certificate prepared: {cert_hash}.0 at `{hash_file}`")
        return hash_file, cert_hash

    except FileNotFoundError:
        logger.error(f"❌ OpenSSL executable not found at '{openssl_path}'. Please configure its path via 'burp-frame config --openssl <path>'.")
        return None, None
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ OpenSSL command failed with exit code {e.returncode}.")
        logger.error(f"  STDOUT: {e.stdout.strip() if e.stdout else 'N/A'}")
        logger.error(f"  STDERR: {e.stderr.strip() if e.stderr else 'N/A'}")
        logger.info("Please ensure your .der file is a valid certificate and OpenSSL is correctly installed.")
        return None, None
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred during certificate conversion: {str(e)}")
        return None, None

