import os
import time
import random
import hashlib
import ecdsa
import base58
import requests
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
        Fore.CYAN + "      T E R M U X  L A B  P R O",
        Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        Fore.CYAN + "📺 YouTube : https://youtube.com/@termuxlabpro",
        Fore.CYAN + "💬 Telegram: https://t.me/termuxlabpro",
        Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
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
    if compressed:
        return (b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03') + vk.to_string()[:32]
    else:
        return b'\x04' + vk.to_string()

def p2pkh_address(pubkey_bytes):
    pub_sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', pub_sha).digest()
    payload = b'\x00' + ripemd
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def get_balance_blockchaininfo(address):
    try:
        time.sleep(1)
        res = requests.get(f'https://blockchain.info/q/addressbalance/{address}')
        return int(res.text) / 1e8
    except Exception as e:
        return f"Error: {e}"

def get_balance_blockcypher(address):
    try:
        time.sleep(1)
        res = requests.get(f'https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance')
        data = res.json()
        return data.get('final_balance', 0) / 1e8
    except Exception as e:
        return f"Error: {e}"

def main():
    banner()
    priv = generate_private_key()
    print(Fore.YELLOW + f"[+] Private Key: {priv}")
    
    wif_c = wif_from_private_key(priv, True)
    wif_u = wif_from_private_key(priv, False)
    print(Fore.MAGENTA + f"[+] WIF (Compressed): {wif_c}")
    print(Fore.CYAN + f"[+] WIF (Uncompressed): {wif_u}\n")

    pub_c = public_key_from_private(priv, True)
    pub_u = public_key_from_private(priv, False)

    addr_c = p2pkh_address(pub_c)
    addr_u = p2pkh_address(pub_u)

    bal_c = get_balance_blockchaininfo(addr_c)
    bal_u = get_balance_blockcypher(addr_u)

    print(Fore.LIGHTBLUE_EX + f"[Compressed Address] {addr_c}")
    print(Fore.LIGHTBLUE_EX + f" └─ Balance (blockchain.info): {bal_c} BTC\n")

    print(Fore.LIGHTGREEN_EX + f"[Uncompressed Address] {addr_u}")
    print(Fore.LIGHTGREEN_EX + f" └─ Balance (blockcypher): {bal_u} BTC\n")

if __name__ == "__main__":
    main()
