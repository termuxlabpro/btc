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
        Fore.CYAN + "╚═══════════════════════════════╝",
        Fore.YELLOW + "📺 YouTube : https://youtube.com/@termuxlabpro",
        Fore.YELLOW + "💬 Telegram: https://t.me/termuxlabpro",
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

# Compressed address APIs
def balance_api_blockchain(addr):
    r = requests.get(f"https://blockchain.info/q/addressbalance/{addr}", timeout=10)
    return int(r.text) / 1e8

def balance_api_btcscan(addr):
    r = requests.get(f"https://btcscan.org/api/v1/balance/{addr}", timeout=10)
    return float(r.json()["balance"]) / 1e8

def balance_api_blockcypher(addr):
    r = requests.get(f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance", timeout=10)
    return float(r.json()["final_balance"]) / 1e8

# Uncompressed address APIs
def balance_api_blockstream(addr):
    r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=10)
    j = r.json()
    return (j["chain_stats"]["funded_txo_sum"] - j["chain_stats"]["spent_txo_sum"]) / 1e8

def balance_api_btccom(addr):
    r = requests.get(f"https://chain.api.btc.com/v3/address/{addr}", timeout=10)
    return float(r.json()["data"]["balance"]) / 1e8

def balance_api_nownodes(addr):
    r = requests.get(f"https://btcbook.nownodes.io/api/v2/address/{addr}", timeout=10)
    return float(r.json()["balance"]) / 1e8

def balance_api_bitaps(addr):
    r = requests.get(f"https://btc.bitaps.com/api/address/state/{addr}", timeout=10)
    return float(r.json()["data"]["balance"]) / 1e8

def get_balance(addr, apis):
    for api in apis:
        try:
            balance = api(addr)
            return balance
        except:
            continue
    return -1  # All failed

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

    pub_c = public_key_from_private(priv, True)
    pub_u = public_key_from_private(priv, False)

    addr_c = p2pkh_address(pub_c)
    addr_u = p2pkh_address(pub_u)

    addresses = {
        "Compressed": addr_c,
        "Uncompressed": addr_u
    }

    # Assign correct APIs
    apis_c = [balance_api_blockchain, balance_api_btcscan, balance_api_blockcypher]
    apis_u = [balance_api_blockstream, balance_api_btccom, balance_api_nownodes, balance_api_bitaps]

    balances = {}
    any_balance = False

    for label in addresses:
        addr = addresses[label]
        apis = apis_c if label == "Compressed" else apis_u
        bal = get_balance(addr, apis)
        balances[label] = bal

        if bal == -1:
            print(Fore.YELLOW + f"[{label}] {addr}")
            print(Fore.YELLOW + " └─ Balance: API Error ❌\n")
        else:
            color = Fore.GREEN if bal > 0 else Fore.RED
            print(color + f"[{label}] {addr}")
            print(color + f" └─ Balance: {bal} BTC\n")
            if bal > 0:
                any_balance = True
        time.sleep(1)

    if any_balance:
        save_found_key(priv, wif_c, wif_u, addresses, balances)
        print(Fore.CYAN + "\n🔥 T.L.P Script by Termux Lab Pro")
        print(Fore.CYAN + "📺 YouTube : https://youtube.com/@termuxlabpro")
        print(Fore.CYAN + "💬 Telegram: https://t.me/termuxlabpro\n")
    else:
        print(Fore.LIGHTBLACK_EX + "[x] No balances found.\n")

    print(Fore.BLUE + "🔁 Scanning next key...\n")
    time.sleep(2)

def main():
    banner()
    while True:
        scan_once()

if __name__ == "__main__":
    main()
