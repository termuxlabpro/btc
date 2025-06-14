import os
import requests
import random
import hashlib
import ecdsa
import base58
import time
from colorama import Fore, init

init(autoreset=True)

# Stylish banner
def banner():
    os.system("clear")
    art = [
        Fore.GREEN + "████████╗██╗     ██████╗ ",
        "╚══██╔══╝██║     ██╔══██╗",
        "   ██║   ██║     ██████╔╝",
        "   ██║   ██║     ██╔═══╝ ",
        "   ██║   ███████╗██║     ",
        "   ╚═╝   ╚══════╝╚═╝     ",
        Fore.CYAN + "     T E R M U X   L A B   P R O",
        Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        Fore.YELLOW + "📺 YouTube : https://youtube.com/@termuxlabpro",
        Fore.YELLOW + "💬 Telegram: https://t.me/termuxlabpro",
        Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    ]
    for line in art:
        print(line)
        time.sleep(0.07)

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

def get_balance_blockchaininfo(addr):
    try:
        res = requests.get(f'https://blockchain.info/q/addressbalance/{addr}', timeout=10)
        if res.status_code == 200:
            return int(res.text) / 1e8
    except:
        pass
    return -1

def get_balance_blockcypher(addr):
    try:
        res = requests.get(f'https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance', timeout=10)
        if res.status_code == 200:
            return res.json().get("final_balance", 0) / 1e8
    except:
        pass
    return -1

def save_found_key(priv, wif_c, wif_u, addresses, balances):
    with open("found_keys.txt", "a") as f:
        f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        f.write(f"Private Key     : {priv}\n")
        f.write(f"WIF Compressed  : {wif_c}\n")
        f.write(f"WIF Uncompressed: {wif_u}\n")
        for label in addresses:
            f.write(f"{label}: {addresses[label]}\n")
            f.write(f" └─ Balance: {balances[label]} BTC\n")
        f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

def main():
    banner()
    priv = generate_private_key()
    wif_c = wif_from_private_key(priv, True)
    wif_u = wif_from_private_key(priv, False)
    pub_c = public_key_from_private(priv, True)
    pub_u = public_key_from_private(priv, False)
    addr_c = p2pkh_address(pub_c)
    addr_u = p2pkh_address(pub_u)

    addresses = {
        "Legacy (Compressed)": addr_c,
        "Legacy (Uncompressed)": addr_u
    }

    balances = {}
    any_balance = False

    print(Fore.YELLOW + f"[+] Private Key: {priv}")
    print(Fore.CYAN + f"[+] WIF Compressed  : {wif_c}")
    print(Fore.CYAN + f"[+] WIF Uncompressed: {wif_u}\n")

    for label, addr in addresses.items():
        if "Compressed" in label:
            balance = get_balance_blockcypher(addr)
        else:
            balance = get_balance_blockchaininfo(addr)

        balances[label] = balance
        color = Fore.GREEN if balance > 0 else Fore.RED
        print(color + f"[{label}] {addr}")
        print(color + f" └─ Balance: {balance} BTC\n")
        if balance > 0:
            any_balance = True

        time.sleep(2)  # Delay between API calls

    if any_balance:
        save_found_key(priv, wif_c, wif_u, addresses, balances)
        print(Fore.LIGHTGREEN_EX + "\n🔥 Wallet with balance found! Saved to found_keys.txt")

    print(Fore.LIGHTBLUE_EX + "\n🔁 Scanning next key...\n")
    time.sleep(2)

if __name__ == "__main__":
    while True:
        main()
