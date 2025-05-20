# KnexyceBTC

def install_pip():
    import subprocess
    import sys
    import os
    import urllib.request
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'])
        print("PIP is already installed.")
        return
    except subprocess.CalledProcessError:
        print("PIP is not installed. Installing...")
    try:
        subprocess.check_call([sys.executable, '-m', 'ensurepip'])
        print("PIP has been installed successfully using 'ensurepip'.")
        return
    except subprocess.CalledProcessError:
        print("'ensurepip' has failed. Attempting to install PIP via 'get-pip.py'...")
    try:
        url = "https://bootstrap.pypa.io/get-pip.py"
        get_pip_script = "get-pip.py"
        urllib.request.urlretrieve(url, get_pip_script)
        print("Downloaded 'get-pip.py'.")
        subprocess.check_call([sys.executable, get_pip_script])
        print("PIP has been installed successfully using 'get-pip.py'.")
        os.remove(get_pip_script)
        print("Cleaned up 'get-pip.py'.")
    except Exception as e:
        print(f"Failed to install PIP: {e}")
        sys.exit(1)

def pip_install(package_name, upgrade=True, user=False):
    import subprocess
    import sys
    import re
    def is_valid_package_name(package_name):
        return bool(re.match(r'^[a-zA-Z0-9_\-]+$', package_name))
    def install_package(package_name):
        if not is_valid_package_name(package_name):
            print(f"Invalid package name: {package_name}")
            return
        try:
            command = [sys.executable, '-m', 'pip', 'install', package_name]
            if upgrade:
                command.append('--upgrade')
            if user:
                command.append('--user')
            subprocess.run(command, check=True)
            print(f"{package_name} has been installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package_name}: {e}")
    install_package(package_name)

def upgrade_pip():
    import subprocess
    import sys
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        print("PIP has been upgraded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to upgrade PIP: {e}")

def handle_pip():
    install_pip()
    upgrade_pip()
    pip_install("secp256k1")
    pip_install("base58")
    pip_install("bit")
    pip_install("requests")
    pip_install("getpass")
    pip_install("cryptography")

def encrypt_message(message: str, knexyce_key: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    encrypted_data = salt + iv + encrypted_message
    encrypted_message_base64 = base64.b64encode(encrypted_data).decode()
    return encrypted_message_base64

def decrypt_message(encrypted_message_base64: str, knexyce_key: str):
    encrypted_data = base64.b64decode(encrypted_message_base64)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()

def create_btc_wallet():
    def generate_valid_private_key():
        while True:
            private_key_bytes = os.urandom(32)
            private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
            if 1 <= private_key_int < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                return private_key_bytes
            else:
                continue
    
    def public_key_to_address(public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        network_prefix = b'\x00'
        prefixed_hash = network_prefix + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
        address_bytes = prefixed_hash + checksum
        address = base58.b58encode(address_bytes)
        return address.decode('utf-8')
    
    storage_valid_private_key = generate_valid_private_key()
    storage_private_key = PrivateKey(storage_valid_private_key)
    storage_public_key = storage_private_key.pubkey
    transaction_valid_private_key = generate_valid_private_key()
    transaction_private_key = PrivateKey(transaction_valid_private_key)
    transaction_public_key = transaction_private_key.pubkey
    sto_pri = storage_private_key.private_key.hex()
    sto_pub = storage_public_key.serialize(compressed=True).hex()
    sto_add = public_key_to_address(storage_public_key.serialize(compressed=True))
    tra_pri = transaction_private_key.private_key.hex()
    tra_pub = transaction_public_key.serialize(compressed=True).hex()
    tra_add = public_key_to_address(transaction_public_key.serialize(compressed=True))
    passphrase = getpass.getpass("Enter a secure passphrase to encrypt the Private Keys. ")
    enc_sto_pri = encrypt_message(sto_pri, passphrase)
    enc_tra_pri = encrypt_message(tra_pri, passphrase)
    private_key_bytes = None
    storage_valid_private_key = None
    transaction_valid_private_key = None
    storage_private_key = None
    transaction_private_key = None
    sto_pri = None
    tra_pri = None
    print("")
    print("Bitcoin Wallet Info")
    print("To decrypt the Private Keys, enter the 'decrypt' command.")
    print("")
    print("Bitcoin Storage Wallet")
    print(f"Private Key (Encrypted): {enc_sto_pri}")
    print(f"Public Key: {sto_pub}")
    print(f"Bitcoin Address: {sto_add}")
    print("")
    print("Bitcoin Transaction Wallet")
    print(f"Private Key (Encrypted): {enc_tra_pri}")
    print(f"Public Key: {tra_pub}")
    print(f"Bitcoin Address: {tra_add}")
    print("")

def decrypt_keys(enc_sto_pri=None, enc_tra_pri=None):
    enc_sto_pri = input("Enter the Encrypted Storage Private Key: ").strip()
    enc_tra_pri = input("Enter the Encrypted Transaction Private Key: ").strip()
    passphrase = getpass.getpass("Enter the passphrase for the Encrypted Private Keys: ")
    dec_sto_pri = decrypt_message(enc_sto_pri, passphrase)
    dec_tra_pri = decrypt_message(enc_tra_pri, passphrase)
    print(f"Decrypted Storage Key: {dec_sto_pri}")
    print(f"Decrypted Transaction Key: {dec_tra_pri}")

def try_decrypt_keys():
    try:
        decrypt_keys()
    except Exception as e:
        print(f"Error: {e}")

def try_create_wallet():
    try:
        create_btc_wallet()
    except Exception as e:
        print(f"Error: {e}")

def transaction_system():
    def estimate_fee(amount_satoshis):
        try:
            response = requests.get("https://mempool.space/api/v1/fees/recommended")
            fee_rates = response.json()
            fast_fee = fee_rates["fastestFee"]
            estimated_size = 250
            fee = fast_fee * estimated_size
            return max(fee, 1)
        except Exception as e:
            print(f"Error estimating fee: {e}")
            return 1000
    
    def hex_to_wif(private_key_hex, compressed=True):
        private_key_bytes = bytes.fromhex(private_key_hex)
        private_key_with_version = b'\x80' + private_key_bytes
        if compressed:
            private_key_with_version += b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(private_key_with_version).digest()).digest()[:4]
        wif = base58.b58encode(private_key_with_version + checksum)
        return wif.decode('utf-8')
    
    def create_transaction():
        private_key = getpass.getpass("Enter your private key: ")
        if private_key.startswith(("5", "K", "L")):
            wif_private_key = private_key
        else:
            wif_private_key = hex_to_wif(private_key)
        key = Key(wif_private_key)
        to_address = input("Enter the target Bitcoin address: ")
        amount = Decimal(input("Enter the amount of Bitcoin to send (in BTC): "))
        if amount <= 0:
            print("Error: Amount must be greater than zero.")
            return
        fee_percentage = Decimal(input("Enter the percentage of transaction fee (or '0' for dynamic): "))    
        amount_satoshis = int(amount * 100000000)
        if fee_percentage == 0:
            fee_satoshis = estimate_fee(amount_satoshis)
        else:
            fee_satoshis = int(amount_satoshis * (fee_percentage / 100))
        total_amount_satoshis = amount_satoshis + fee_satoshis
        balance = Decimal(key.get_balance('btc'))
        balance_satoshis = balance * 100000000
        if balance_satoshis < total_amount_satoshis:
            print(f"Error: Insufficient funds. You need {total_amount_satoshis / 100000000} BTC, but only have {balance} BTC.")
            return
        print(f"Creating a transaction for {amount} BTC with a fee of {fee_satoshis / 100000000} BTC.")
        try:
            tx = key.send([(to_address, amount_satoshis, 'satoshi')], fee=fee_satoshis)
            print(f"Transaction successfully sent.")
        except Exception as e:
            print(f"Error: Failed to create/send transaction. {e}")
    create_transaction()

def try_transaction():
    try:
        transaction_system()
    except Exception as e:
        print(f"Error: {e}")

def check_balance(address):
    balance = NetworkAPI.get_balance(address)
    btc_balance = balance / 1e8
    print(f"Your balance is: {btc_balance} BTC")

def try_check():
    try:
        address = input("Enter your Bitcoin Address to check balance. ").strip()
        check_balance(address)
    except Exception as e:
        print(f"Error: {e}")

def clear_screen():
    import os
    import platform
    methods = [
        'cls' if platform.system() == 'Windows' else 'clear',
        'tput clear',
        'reset'
    ]
    for method in methods:
        try:
            os.system(method)
            break
        except Exception as e:
            continue
    else:
        print(f"Error: {e}")
        print("\033[H\033[J", end="")

def knexyce_command_line_help():
    print("Note: Do not include ' or ' in the command when typing. Do not include anything beyond : in the command.")
    print("Commands: ")
    print("'help': Provides a list of commands.")
    print("'create': Creates a Knexyce Bitcoin Wallet.")
    print("'check': Checks how much Bitcoin is in a wallet.")
    print("'send': Makes a Bitcoin transaction.")
    print("'clear': Clears the screen.")
    print("'exit': Exits KBTC.")

def ask_clear():
    clear_ask = input("Clear screen? [y/n] ")
    if clear_ask == "y":
        clear_screen()
    else:
        pass

print("Upgrade/update system and install needed KBTC dependencies?")
upgrade_ask = input("[y/n]: ")
if upgrade_ask.lower() == "y":
    handle_pip()
    ask_clear()
else:
    print("")

try:
    import hashlib
    import base64
    import base58
    from bit import Key
    from bit.network import NetworkAPI
    from decimal import Decimal
    import secp256k1
    import os
    from secp256k1 import PrivateKey
    import requests
    import re
    import getpass
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("Error: Missing dependencies.")

print("KnexyceBTC")
print("")
print("Software Info: ")
print("Name: Knexyce Bitcoin (KnexyceBTC/KBTC) Command Line Interface")
print("This is a shell-agnostic script. The main requirement is internet access.")
print("This script is a lightweight Bitcoin wallet designed for a command line interface. The script itself is coded in Python-v3.")
print("This software is owned by an entity/group known as Knexyce. All rights to KBTC are reserved by Knexyce. This code was created by Ayan Alam/Knexyce-001/Administrator.")
print("")
print("Advice: ")
print("It's generally good practice to use KBTC with a VPN, firewall, and antivirus for extra security, along with full encryption for all internet actions/data. Save as little data as possible.")
print("It's also generally recommended to research what Bitcoin is, how it works, and as much information about it as possible before using this software.")
print("Along with that, some research on how coding, software, and scripts work is generally needed to understand how this software works.")
print("")
print("To Begin: ")
print("Enter 'help' without any quotations for a list of KBTC commands.")
print("")

while True:
    knexyce_input = input("<KnexyceBTC> ")
    if knexyce_input.lower() == "help":
        knexyce_command_line_help()
    elif knexyce_input.lower() == "create":
        try_create_wallet()
    elif knexyce_input.lower() == "check":
        try_check()
    elif knexyce_input.lower() == "send":
        try_transaction()
    elif knexyce_input.lower() == "decrypt":
        try_decrypt_keys()
    elif knexyce_input.lower() == "clear":
        clear_screen()
    elif knexyce_input.lower() == "exit":
        break
    else:
        print("Error: Invalid command.")

# This software was created by the Administrator of Knexyce.
# All rights to this software are reserved by Knexyce.