import subprocess
import sys
import os
import time
import json
import threading
import getpass
from datetime import datetime

DEBUG = False  # Set to True for verbose device detection debugging

# --- Spinner Class for Feedback ---
class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner_symbols = ['-', '\\', '|', '/']
        self.delay = 0.1
        self.running = False
        self.spinner_thread = None
        self.message = message

    def _spin(self):
        while self.running:
            for symbol in self.spinner_symbols:
                if not self.running:
                    break
                sys.stdout.write(f"\r{self.message} {symbol}")
                sys.stdout.flush()
                time.sleep(self.delay)
        sys.stdout.write("\r" + " " * (len(self.message) + 5) + "\r")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.spinner_thread = threading.Thread(target=self._spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()

    def stop(self):
        self.running = False
        if self.spinner_thread and self.spinner_thread.is_alive():
            self.spinner_thread.join()

# --- Utility Functions ---
def run_command(command, input_data=None, spinner_message=None, check_returncode=True):
    spinner = None
    if spinner_message:
        spinner = Spinner(spinner_message)
        spinner.start()

    try:
        process = subprocess.run(
            command,
            input=input_data,
            text=True,
            capture_output=True,
            check=check_returncode,
            encoding='utf-8'
        )
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        print(f"\nError executing command: {' '.join(command)}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        raise
    finally:
        if spinner:
            spinner.stop()

def get_block_devices():
    try:
        stdout, _ = run_command(
            ["lsblk", "--json", "-o", "NAME,SIZE,TYPE,ROTA,MODEL,VENDOR,FSTYPE,MOUNTPOINT,RM"],
            check_returncode=True
        )
        data = json.loads(stdout)
    except Exception as e:
        print(f"Error listing block devices: {e}")
        sys.exit(1)

    devices = []
    for block in data.get('blockdevices', []):
        if block.get('type') != 'disk':
            continue
        device_name = f"/dev/{block['name']}"
        size = block.get('size', 'Unknown Size')
        model = (block.get('model') or '').strip()
        vendor = (block.get('vendor') or '').strip()
        removable = block.get('rm', False)

        if "nvme" in block['name'].lower():
            continue
        if not removable:
            continue

        is_mounted = False
        if block.get('mountpoint'):
            is_mounted = True
        if 'children' in block:
            for child in block['children']:
                if child.get('mountpoint'):
                    is_mounted = True
                    break
        # We don't filter out mounted devices here, as the user might want to open an already LUKS-encrypted,
        # but currently mounted, device after unmounting.

        display_name = f"{vendor} {model} {size}" if model and vendor else f"{device_name} {size}"
        devices.append({
            'name': device_name,
            'size': size,
            'display_name': display_name,
            'model': model,
            'vendor': vendor,
            'is_mounted': is_mounted # Add mount status to device info
        })
    return devices

def get_partition_table_type(device_path):
    try:
        stdout, _ = run_command(["parted", "-s", device_path, "print"], check_returncode=False)
        for line in stdout.splitlines():
            if "Partition Table:" in line:
                return line.split(":")[1].strip().lower()
    except Exception:
        pass
    return "unknown"

def detect_luks_encryption(device_path):
    try:
        stdout, _ = run_command(["lsblk", "--json", "-o", "NAME,TYPE,FSTYPE", device_path], check_returncode=True)
        data = json.loads(stdout)
        
        def is_crypt_type(entry):
            return entry.get("type") == "crypt" or entry.get("fstype") == "crypto_LUKS"

        if is_crypt_type(data['blockdevices'][0]):
            return True
        
        for child in data['blockdevices'][0].get("children", []):
            if is_crypt_type(child):
                return True
    except Exception as e:
        if DEBUG:
            print(f"DEBUG: Could not determine LUKS status for {device_path}: {e}")
    return False

def luks_header_backup(device_path):
    device_base = os.path.basename(device_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.expanduser("~/luks_backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = os.path.join(backup_dir, f"{device_base}_{timestamp}.header")
    try:
        run_command(["cryptsetup", "luksHeaderBackup", device_path, "--header-backup-file", backup_file])
        print(f"\nLUKS header backup saved to: {backup_file}")
        print("Keep this file safe! Use it to restore with:\n  cryptsetup luksHeaderRestore <device> --header-backup-file <file>")
    except Exception as e:
        print(f"Failed to back up LUKS header: {e}")

def check_root_privileges():
    if os.geteuid() != 0:
        print("This script must be run with root privileges. Try:\n  sudo python3 script.py")
        sys.exit(1)

# --- Main ---
def main():
    check_root_privileges()

    print("--- USB Dongle LUKS Encryption Script ---")
    print("WARNING: This will ERASE ALL DATA on the selected device if you choose to encrypt.")
    print("Only GPT partition tables are supported for new encryption.")
    print("-" * 40)

    suitable_devices = get_block_devices()
    if not suitable_devices:
        print("No suitable USB devices found. Ensure it's connected, unmounted, and removable.")
        sys.exit(0)

    print("\nAvailable USB Devices:")
    for i, device in enumerate(suitable_devices):
        mount_status = "(Currently Mounted)" if device['is_mounted'] else ""
        print(f"  [{i + 1}] {device['name']} ({device['display_name']}) {mount_status}")

    while True:
        selection = input("\nEnter the number of the device to encrypt/open (or 'q' to quit): ").strip()
        if selection.lower() == 'q':
            print("Exiting.")
            sys.exit(0)
        try:
            device_index = int(selection) - 1
            if 0 <= device_index < len(suitable_devices):
                selected_device = suitable_devices[device_index]
                break
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid input.")

    device_path = selected_device['name']
    print(f"\nSelected: {device_path} ({selected_device['display_name']})")

    if detect_luks_encryption(device_path):
        print(f"\nNote: {device_path} appears to be already LUKS-encrypted.")
        while True:
            action = input("Do you want to open it (type 'open'), re-encrypt (type 're-encrypt'), or exit (type 'exit')? ").strip().lower()
            if action == 'exit':
                print("Exiting.")
                sys.exit(0)
            elif action == 'open':
                mapper_name = input("Enter mapper name (e.g., 'my_encrypted_usb'): ").strip()
                if not mapper_name:
                    print("Mapper name cannot be empty.")
                    sys.exit(1)
                if os.path.exists(f"/dev/mapper/{mapper_name}"):
                    print(f"Error: /dev/mapper/{mapper_name} already exists. Use a different name or close it first.")
                    sys.exit(1)
                passphrase = getpass.getpass("Enter LUKS passphrase: ")
                try:
                    run_command(
                        ["cryptsetup", "luksOpen", device_path, mapper_name],
                        input_data=passphrase + "\n",
                        spinner_message=f"Opening LUKS volume '{mapper_name}'"
                    )
                    opened_device_path = f"/dev/mapper/{mapper_name}"
                    print(f"Successfully opened: {opened_device_path}")
                    print("You may now mount it (e.g., 'sudo mount /dev/mapper/{mapper_name} /mnt/usb')")
                    sys.exit(0)
                except subprocess.CalledProcessError as e:
                    if e.returncode == 5: # Specific error code for "device in use"
                        print(f"\nError: The device '{device_path}' is currently in use.")
                        print("Please ensure it is unmounted and any existing LUKS mappings are closed.")
                        print("A quick fix is to **safely remove the USB dongle, then reinsert it**, and run the script again.")
                        sys.exit(1) # Exit after prompting
                    else:
                        print(f"Failed to open LUKS device: {e}")
                        sys.exit(1)
            elif action == 're-encrypt':
                print("\nWARNING: Re-encrypting will ERASE ALL DATA on the selected device.")
                confirmation_text = "I understand and want to re-encrypt this device"
                print(f"\nType '{confirmation_text}' to proceed with re-encryption:")
                if input("> ").strip() != confirmation_text:
                    print("Re-encryption cancelled. Exiting.")
                    sys.exit(0)
                # Fall through to the encryption logic
                break 
            else:
                print("Invalid choice. Type 'open', 're-encrypt', or 'exit'.")
    
    # If not detected as LUKS or user chose to re-encrypt, proceed with encryption
    pt_type = get_partition_table_type(device_path)
    if pt_type != 'gpt':
        print(f"\nError: {device_path} uses '{pt_type}' partition table.")
        print("Only GPT is supported. Convert it using tools like 'gparted' or 'parted'.")
        sys.exit(1)
    else:
        print(f"Partition Table: {pt_type.upper()} (OK)")

    confirmation_text = "I understand and want to encrypt this device"
    print(f"\nType '{confirmation_text}' to proceed:")
    if input("> ").strip() != confirmation_text:
        print("Confirmation failed. Exiting.")
        sys.exit(0)

    while True:
        passphrase1 = getpass.getpass("Enter LUKS passphrase: ")
        passphrase2 = getpass.getpass("Confirm LUKS passphrase: ")
        if passphrase1 != passphrase2:
            print("Passphrases do not match.")
        elif len(passphrase1) < 8:
            print("Passphrase too short. Use at least 8 characters.")
        else:
            break

    try:
        run_command(
            ["cryptsetup", "luksFormat",
             "--type", "luks2",
             "--cipher", "aes-xts-plain64",
             "--key-size", "512",
             "--hash", "sha512",
             "--iter-time", "2000",
             "--pbkdf", "argon2id",
             device_path],
            input_data="YES\n" + passphrase1 + "\n" + passphrase1 + "\n", # Add "YES" for confirmation
            spinner_message=f"Formatting {device_path} with LUKS"
        )
        print(f"\nSuccessfully formatted {device_path} with LUKS.")
    except Exception as e:
        print(f"Formatting failed: {e}")
        sys.exit(1)

    luks_header_backup(device_path)

    mapper_name = input("Enter mapper name to open LUKS volume (e.g., 'my_encrypted_usb'): ").strip()
    if not mapper_name:
        print("Mapper name cannot be empty.")
        sys.exit(1)

    if os.path.exists(f"/dev/mapper/{mapper_name}"):
        print(f"/dev/mapper/{mapper_name} already exists. Please use a different name or close it first.")
        sys.exit(1)

    try:
        run_command(
            ["cryptsetup", "luksOpen", device_path, mapper_name],
            input_data=passphrase1 + "\n",
            spinner_message=f"Opening LUKS volume '{mapper_name}'"
        )
        opened_device_path = f"/dev/mapper/{mapper_name}"
        print(f"\nSuccessfully opened: {opened_device_path}")
        print(f"You can now create a filesystem on it, e.g.:\n  sudo mkfs.ext4 {opened_device_path}")
        print(f"And mount it, e.g.:\n  sudo mount {opened_device_path} /mnt/usb")
    except Exception as e:
        print(f"Failed to open LUKS volume: {e}")
        sys.exit(1)

    print("\nScript finished.")

if __name__ == "__main__":
    main()