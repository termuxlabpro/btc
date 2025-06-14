"""
MIT License (c) 2025 Termux Lab Pro
YouTube: https://youtube.com/@termuxlabpro
Telegram: https://t.me/termuxlabpro
"""

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
    art = [
        Fore.GREEN + "████████╗██╗     ██████╗ ",
        "╚══██╔══╝██║     ██╔══██╗",
        "   ██║   ██║     ██████╔╝",
        "   ██║   ██║     ██╔═══╝ ",
        "   ██║   ███████╗██║     ",
        "   ╚═╝   ╚══════╝╚═╝     ",
        Fore.CYAN + "\n╔═══════════════════════════════╗",
        Fore.CYAN + "║         " + Fore.MAGENTA + "T . L . P" + Fore.CYAN + "             ║",
        Fore.CYAN + "║     Termux Lab Pro            ║",
        Fore.CYAN + "╠═══════════════════════════════╣",
        Fore.CYAN + "║ " + Fore.YELLOW + "📺 YouTube : " + Fore.WHITE + "youtube.com/@termuxlabpro" + Fore.CYAN + " ║",
        Fore.CYAN + "║ " + Fore.YELLOW + "💬 Telegram: " + Fore.WHITE + "t.me/termuxlabpro         " + Fore.CYAN + " ║",
        Fore.CYAN + "╚═══════════════════════════════╝",
        Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    ]
    for line in art:
        print(line)
        time.sleep(0.05)

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

def get_balance_blockchain_info(addr):
    try:
        res = requests.get(f'https://blockchain.info/q/addressbalance/{addr}', timeout=10)
        return int(res.text) / 1e8
    except:
        return -1

def get_balance_blockcypher(addr):
    try:
        res = requests.get(f'https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance', timeout=10)
        return res.json()['final_balance'] / 1e8
    except:
        return -1

def save_found_key(priv, wif_c, wif_u, addresses, balances):
    with open("found_keys.txt", "a") as f:
        f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        f.write(f"Private Key     : {priv}\n")
        f.write(f"WIF Compressed : {wif_c}\n")
        f.write(f"WIF Uncompressed : {wif_u}\n")
        for label in addresses:
            f.write(f"{label}: {addresses[label]}\n")
            f.write(f" └─ Balance: {balances[label]} BTC\n")
        f.write("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

def scan_once():
    priv = generate_private_key()
    wif_c = wif_from_private_key(priv, True)
    wif_u = wif_from_private_key(priv, False)

    print(Fore.YELLOW + "[+] Private Key:", priv)
    print(Fore.MAGENTA + "[+] WIF (Compressed):", wif_c)
    print(Fore.CYAN + "[+] WIF (Uncompressed):", wif_u)
    print()

    pub_u = public_key_from_private(priv, False)
    pub_c = public_key_from_private(priv, True)

    addr_u = p2pkh_address(pub_u)
    addr_c = p2pkh_address(pub_c)

    balance_u = get_balance_blockchain_info(addr_u)
    balance_c = get_balance_blockcypher(addr_c)

    addresses = {
        "Legacy (Uncompressed)": addr_u,
        "Legacy (Compressed)": addr_c
    }

    balances = {
        "Legacy (Uncompressed)": balance_u,
        "Legacy (Compressed)": balance_c
    }

    any_balance = False

    for label in addresses:
        addr = addresses[label]
        bal = balances[label]
        color = Fore.GREEN if bal > 0 else Fore.RED
        print(color + f"[{label}] {addr}")
        print(color + f" └─ Balance: {bal} BTC\n")
        if bal > 0:
            any_balance = True

    if any_balance:
        save_found_key(priv, wif_c, wif_u, addresses, balances)
        print(Fore.CYAN + "\n🔥 T.L.P Script by Termux Lab Pro")
        print(Fore.CYAN + "📺 YouTube : https://youtube.com/@termuxlabpro")
        print(Fore.CYAN + "💬 Telegram: https://t.me/termuxlabpro\n")
    else:
        print(Fore.LIGHTBLACK_EX + "[x] No balances found.\n")

    print(Fore.BLUE + "🔁 Scanning next key...\n")
    time.sleep(1)

def main():
    banner()
    while True:
        scan_once()

if __name__ == "__main__":
    main()
