
import os
import requests
import random
import hashlib
import ecdsa
import base58
import time
from colorama import Fore, init

init(autoreset=True)

def banner():
    os.system("clear")
    print(Fore.CYAN + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.GREEN + "        T E R M U X  L A B  P R O")
    print(Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

def generate_private_key():
    return ''.join(random.choice('0123456789abcdef') for _ in range(64))

def wif_from_private_key(priv_hex, compressed=True):
    extended = '80' + priv_hex
    if compressed:
        extended += '01'
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(extended)).digest()).digest()[:4]
    final_key = bytes.fromhex(extended) + checksum
    return base58.b58encode(final_key).decode()

def public_key_from_private(priv_hex, compressed=True):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return (b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03') + vk.to_string()[:32] if compressed else b'\x04' + vk.to_string()

def p2pkh_address(pubkey_bytes):
    pub_sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', pub_sha).digest()
    payload = b'\x00' + ripemd
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def get_balance_blockchair(address):
    try:
        url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
        res = requests.get(url, timeout=10)
        data = res.json()
        return data['data'][address]['address']['balance'] / 1e8
    except Exception as e:
        print(Fore.RED + f"[!] Blockchair API error: {e}")
        return 0.0

def get_balance_sochain(address):
    try:
        url = f"https://sochain.com/api/v2/get_address_balance/BTC/{address}"
        res = requests.get(url, timeout=10)
        data = res.json()
        return float(data['data']['confirmed_balance'])
    except Exception as e:
        print(Fore.RED + f"[!] SoChain API error: {e}")
        return 0.0

def main():
    banner()
    while True:
        priv = generate_private_key()
        print(Fore.YELLOW + "[+] Private Key:", priv)

        wif_c = wif_from_private_key(priv, True)
        wif_u = wif_from_private_key(priv, False)
        print(Fore.MAGENTA + "[+] WIF (Compressed):", wif_c)
        print(Fore.CYAN + "[+] WIF (Uncompressed):", wif_u)

        pub_c = public_key_from_private(priv, True)
        pub_u = public_key_from_private(priv, False)

        addr_c = p2pkh_address(pub_c)
        addr_u = p2pkh_address(pub_u)

        bal_c = get_balance_blockchair(addr_c)
        bal_u = get_balance_sochain(addr_u)

        print(Fore.LIGHTBLUE_EX + f"[Legacy (Compressed)] {addr_c}")
        print(Fore.LIGHTBLUE_EX + f" └─ Balance (Blockchair): {bal_c} BTC")
        print(Fore.LIGHTGREEN_EX + f"[Legacy (Uncompressed)] {addr_u}")
        print(Fore.LIGHTGREEN_EX + f" └─ Balance (SoChain): {bal_u} BTC\n")

        if bal_c > 0 or bal_u > 0:
            with open("found_keys.txt", "a") as f:
                f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                f.write(f"Private Key: {priv}\n")
                f.write(f"WIF Compressed: {wif_c}\n")
                f.write(f"WIF Uncompressed: {wif_u}\n")
                f.write(f"Legacy (Compressed): {addr_c} ─ {bal_c} BTC\n")
                f.write(f"Legacy (Uncompressed): {addr_u} ─ {bal_u} BTC\n")
                f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

        print(Fore.BLUE + "🔁 Scanning next key...\n")
        time.sleep(1.5)

if __name__ == "__main__":
    main()
