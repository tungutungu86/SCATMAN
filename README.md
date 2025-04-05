# 🛡️ SCATMAN Secure Terminal
_Brought to you by Belacom Technologies // NaanStop Defense Division_  
_“When silence isn't stealthy enough...”_

## 🔥 Overview
SCATMAN is a paranoid-and-self-torture-grade encrypted terminal communication system built with layered cryptographic defenses. Designed for secure, peer-to-peer messaging over TCP, this tool is ideal for 
red teams, covert sysadmins, and anyone allergic to plaintext.

**Built-in technologies:**
- AES-256-GCM symmetric encryption  
- RSA-PSS digital signatures  
- Ephemeral Diffie-Hellman key exchange  
- HMAC integrity verification  
- Forward secrecy with HKDF

## 🧪 Features
- 🔐 End-to-end encrypted socket communication
- 💥 Replay attack protection (timestamp & sequence validation)
- 🧬 Ephemeral key exchange via Diffie-Hellman
- 🧾 Message authenticity via RSA signatures
- 🧠 MAC validation via SHA-256 HMAC
- 🔁 Full-duplex communication with threading

## 🛠️ Usage

1. **Run `SCATMAN.py` on both endpoints.**

2. Choose your role:
   - `[1] Host` to wait for inbound connections
   - `[2] Connect to peer` to connect to a target IP and port

3. Chat securely.  
   Type `/exit` to bail out like a ghost in the shell.

## 💡 Example
```bash
$ python3 SCATMAN.py
