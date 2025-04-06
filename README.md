# 🔒 SCATMAN - Secure Chat Application
*"Powered by paranoia and self-torture" - Apache 2.0 License*

## 🌟 Features
- **Military-grade encryption** (AES-256-GCM)
- **Secure key exchange** (Diffie-Hellman)
- **File transfer** with user confirmation
- **Version compatibility** (v3/v4)
- **Replay attack protection**

## 🚀 Quick Start
### Prerequisites
- Python 3.6+
- Windows 10/11 (macOS/Linux compatible)

```bash
# Install dependencies
pip install cryptography pyDH
```

### Basic Usage
1. **Host Mode**:
   ```bash
   python SCATMAN.py
   [1] Host
   Enter port: 5000
   ```

2. **Client Mode**:
   ```bash
   python SCATMAN.py
   [2] Connect
   IP: 192.168.1.x
   Port: 5000
   ```

3. **Commands**:
   - Regular chat: Just type messages
   - File transfer: `!sendfile C:\path\to\file`
   - Exit: `/exit`

## 🔧 Technical Details
| Component           | Implementation              |
|---------------------|-----------------------------|
| Key Exchange        | Diffie-Hellman (pyDH)       |
| Encryption          | AES-256-GCM                 |
| Key Derivation      | HKDF-SHA256                 |
| Authentication      | HMAC-SHA256 (v3)            |

## 🛠️ Troubleshooting
```bash
# Common fixes
python -m pip install --upgrade pip  # Update pip
set PYTHONUTF8=1                    # Fix encoding issues
```

## 📜 License
Apache 2.0 - See Licence.md

---
> **Warning**  
> This is for educational purposes only. Belacom Technologies assumes no liability for data breaches.

