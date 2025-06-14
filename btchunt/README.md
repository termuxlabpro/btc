
# 🧠 T.L.P Bitcoin Private Key Scanner
A stylish, Termux-ready Python script that randomly generates Bitcoin private keys, derives all major address types, checks balances, and saves any hits with balance. Built for educational purposes by **Termux Lab Pro**.

---

## 📌 Features

- ✅ Random **private key** generation
- ✅ Derives all major address types:
  - Legacy (Compressed & Uncompressed)
  - P2SH (SegWit Compatible)
  - Bech32 (Native SegWit)
- ✅ Real-time **balance checking** via `blockchain.info`
- ✅ Infinite key scanning (looped)
- ✅ Stylish ASCII art banner with T.L.P
- ✅ Saves any key with balance to `found_keys.txt`
- ✅ Designed to run on **Termux** (Android terminal)
- ✅ Prints branding **only if** balance is found

---

## ⚙️ Installation & Usage

### 🛠️ Step-by-step for Termux

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install ecdsa base58 bech32 colorama
git clone https://github.com/termuxlabpro/btc.git
cd btc/btchunt
python tlp_btc_scanner.py
```

> Use `python3` if `python` doesn’t work on your system.

---

## 📁 Output

- Shows all generated addresses and balances in terminal.
- If **any address has balance**, logs are saved in `found_keys.txt` with:
  - Private Key
  - WIF (Compressed & Uncompressed)
  - All addresses with labels
  - Their BTC balances

---

## ⚠️ Legal Disclaimer

> This tool is provided for **educational and research purposes only**.  
> Bitcoin address collision is **mathematically infeasible** — the chance of hitting an active wallet is astronomically small.

By using this script, you agree that the author is **not responsible for any misuse** or legal consequences.

---

## 🔗 Stay Connected

- 📺 YouTube: [Termux Lab Pro](https://youtube.com/@termuxlabpro)
- 💬 Telegram: [t.me/termuxlabpro](https://t.me/termuxlabpro)

---

## 🪪 License

MIT License © 2025 Termux Lab Pro  
Feel free to fork, but **credit is appreciated**.
