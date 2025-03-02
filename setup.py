import os
import subprocess
import sys
import winreg
import wget
import logging

# Setup logging for setup process
logging.basicConfig(
    filename="setup.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="a"
)
logger = logging.getLogger()

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False

if not is_admin():
    logger.info("Elevating to Administrator privileges...")
    print("Elevating to Administrator privileges...")
    try:
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to elevate privileges: {e}")
        print("Failed to elevate privileges. Please run manually as Administrator.")
        sys.exit(1)

def check_npcap_installed():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
        winreg.CloseKey(key)
        logger.info("Npcap is already installed. Skipping installation.")
        print("Npcap is already installed. Skipping installation.")
        return True
    except FileNotFoundError:
        logger.info("Npcap not detected.")
        return False

def install_npcap():
    NPCAP_URL = "https://npcap.com/dist/npcap-1.79.exe"  # Updated URL
    installer_path = "npcap_installer.exe"
    try:
        # Download Npcap installer
        if not os.path.exists(installer_path):
            logger.info("Downloading Npcap installer...")
            print("Downloading Npcap installer...")
            wget.download(NPCAP_URL, installer_path)
            if not os.path.exists(installer_path) or os.path.getsize(installer_path) == 0:
                raise Exception("Failed to download Npcap installer or file is empty")

        # Verify file exists and is executable
        if not os.access(installer_path, os.X_OK):
            os.chmod(installer_path, 0o755)  # Make executable if needed

        # Attempt silent installation
        logger.info("Installing Npcap silently...")
        print("Installing Npcap silently...")
        result = subprocess.run([installer_path, "/S"], capture_output=True, text=True, check=True)
        logger.debug(f"Npcap installation output: {result.stdout}")
        if result.stderr:
            logger.warning(f"Npcap installation stderr: {result.stderr}")

        # Clean up
        os.remove(installer_path)
        logger.info("Npcap installed successfully")
        print("Npcap installed successfully")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install Npcap silently: {e}\nOutput: {e.output}\nStderr: {e.stderr}")
        print(f"Failed to install Npcap silently: {e}")
        # Attempt non-silent install as fallback
        try:
            logger.info("Attempting non-silent Npcap installation...")
            print("Attempting non-silent Npcap installation...")
            subprocess.run([installer_path], check=True)
            os.remove(installer_path)
            logger.info("Npcap installed successfully (non-silent)")
            print("Npcap installed successfully (non-silent)")
            return True
        except subprocess.CalledProcessError as e2:
            logger.error(f"Non-silent Npcap installation also failed: {e2}")
            print(f"Non-silent Npcap installation also failed: {e2}")
    except Exception as e:
        logger.error(f"Failed to install Npcap automatically: {e}")
        print(f"Failed to install Npcap automatically: {e}")
    
    print("Please download and install Npcap manually from https://npcap.com/#download")
    return False

if __name__ == "__main__":
    logger.info("Starting Npcap setup process...")
    print("Starting Npcap setup process...")

    # Check and install Npcap
    if not check_npcap_installed():
        if not install_npcap():
            logger.warning("Npcap not installed. Network monitoring may fail.")
            print("Npcap not installed. Network monitoring may fail.")
        else:
            logger.info("Npcap setup completed successfully")
            print("Npcap setup completed successfully")
    else:
        logger.info("Npcap setup completed (already installed)")
        print("Npcap setup completed (already installed)")