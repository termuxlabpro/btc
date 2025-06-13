import os
import requests
import random
import hashlib
import ecdsa
import base58
import bech32
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
        Fore.CYAN + "      T E R M U X  L A B  P R O",
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

def p2sh_p2wpkh_address(pubkey_bytes):
    pub_sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', pub_sha).digest()
    redeem_script = b'\x00\x14' + ripemd
    hash160 = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
    payload = b'\x05' + hash160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def bech32_address(pubkey_bytes):
    pub_sha = hashlib.sha256(pubkey_bytes).digest()
    ripemd = hashlib.new('ripemd160', pub_sha).digest()
    five_bit = bech32.convertbits(ripemd, 8, 5)
    return bech32.encode('bc', 0, five_bit)

def get_balance(addr):
    try:
        res = requests.get(f'https://blockchain.info/q/addressbalance/{addr}')
        return int(res.text) / 1e8
    except:
        return -1

def main():
    banner()
    priv = generate_private_key()
    print(Fore.YELLOW + "[+] Private Key:", priv)
    print(Fore.MAGENTA + "[+] WIF (Compressed):", wif_from_private_key(priv, True))
    print(Fore.CYAN + "[+] WIF (Uncompressed):", wif_from_private_key(priv, False))
    print()

    pub_uncompressed = public_key_from_private(priv, False)
    pub_compressed = public_key_from_private(priv, True)

    addresses = {
        "Legacy (Uncompressed)": p2pkh_address(pub_uncompressed),
        "Legacy (Compressed)": p2pkh_address(pub_compressed),
        "SegWit (P2SH)": p2sh_p2wpkh_address(pub_compressed),
        "Bech32 (Native SegWit)": bech32_address(pub_compressed)
    }

    any_balance = False
    for label, addr in addresses.items():
        bal = get_balance(addr)
        color = Fore.GREEN if bal > 0 else Fore.RED
        print(color + f"[{label}] {addr}")
        print(color + f" └─ Balance: {bal} BTC\n")
        if bal > 0:
            any_balance = True

    if any_balance:
        print(Fore.CYAN + "\n🔥 T.L.P Script by Termux Lab Pro")
        print(Fore.CYAN + "📺 YouTube : https://youtube.com/@termuxlabpro")
        print(Fore.CYAN + "💬 Telegram: https://t.me/termuxlabpro\n")
    else:
        print(Fore.LIGHTBLACK_EX + "[x] No balances found in any derived address.\n")

if __name__ == "__main__":
    main()
