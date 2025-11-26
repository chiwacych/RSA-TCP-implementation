# 🔐 RSA over TCP Implementation

> **Manual RSA encryption (1024-bit) with TCP socket communication**  
> Zero dependencies • Pure Python • Educational implementation

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-green.svg)](requirements.txt)
[![License: Educational](https://img.shields.io/badge/license-Educational-orange.svg)](#)

---

## 📖 About

A complete implementation of RSA encryption from scratch with TCP networking for secure message exchange between Alice (server) and Bob (client). Built for educational purposes with multiple interfaces: GUI, CLI, and automated launchers.

### ✨ Key Features

- 🔒 **Manual RSA Implementation** - 1024-bit keys with 512-bit primes
- 🌐 **TCP Communication** - Bidirectional encrypted messaging
- 🎨 **Multiple Interfaces** - GUI and CLI options
- 🚀 **Auto Launchers** - One-command setup for Windows/Linux/macOS
- 📊 **Educational Tools** - Visual demonstrators and decryption tools
- ⚡ **Zero Dependencies** - Pure Python standard library only

---

## 🚀 Quick Start

### One-Command Launch

**Windows:**
```powershell
.\scripts\run_demo.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh  # Linux
./scripts/run_demo_mac.sh  # macOS
```

Both Alice and Bob GUIs launch automatically in separate windows!

### Manual Setup

```bash
# Clone repository
git clone https://github.com/chiwacych/RSA-TCP-implementation.git
cd RSA-TCP-implementation

# Run Alice (server)
python alice_gui.py

# Run Bob (client) in another terminal
python bob_gui.py
```

**No installation needed!** Python 3.7+ with tkinter is all you need.

---

## 📁 Project Structure

```
RSA-TCP-implementation/
├── alice_gui.py           # GUI Server with encryption toggle
├── bob_gui.py             # GUI Client with encryption toggle
├── rsa_manual.py          # Core RSA implementation
├── Alice.py               # CLI Server
├── Bob.py                 # CLI Client
└── scripts/               # Auto-launchers (Windows/Linux/macOS)
```

---

## 🔧 How It Works

### RSA Algorithm
1. Generate two 512-bit primes (p, q) using Miller-Rabin test
2. Calculate n = p × q (1024-bit modulus)
3. Compute φ(n) = (p-1)(q-1)
4. Choose e = 65537, calculate d = e⁻¹ mod φ(n)
5. Encrypt: C = M^e mod n
6. Decrypt: M = C^d mod n

### TCP Communication
- **Alice** generates keys → starts server → exchanges public keys
- **Bob** generates keys → connects → exchanges public keys
- Both encrypt messages with recipient's public key
- Both decrypt received messages with their private key

### Security Features
- ✅ Miller-Rabin primality test (50 iterations, certainty 1-2⁻⁵⁰)
- ✅ Cryptographically secure random (`secrets` module)
- ✅ Efficient modular exponentiation
- ✅ Private keys never shared over network
- ✅ Optional unencrypted mode for demonstration

---

## 🎯 Usage Examples

### Network GUI (Recommended)

**Alice's Window:**
1. Click "Generate Keys" (wait 5-30 seconds)
2. Click "Start Server" (default port: 3000)
3. Wait for Bob to connect

**Bob's Window:**
1. Click "Generate Keys"
2. Enter Alice's IP and port
3. Click "Connect to Alice"
4. Send encrypted/unencrypted messages

### Command Line

**Terminal 1 (Alice):**
```bash
python Alice.py
```

**Terminal 2 (Bob):**
```bash
python Bob.py
```

Messages are encrypted automatically with recipient's public key!

---

## 📊 Technical Specifications

| Component | Specification |
|-----------|---------------|
| Key Size | 1024-bit (512-bit primes) |
| Public Exponent | 65537 |
| Primality Test | Miller-Rabin (k=50) |
| Random Generator | `secrets` module (CSPRNG) |
| Network Protocol | TCP sockets |
| Dependencies | **None** (stdlib only) |

---

## 🎓 Educational Use

Perfect for learning:
- RSA encryption algorithm internals
- TCP socket programming
- Public-key cryptography concepts
- Secure communication protocols
- Python GUI development with tkinter

### Available Interfaces
- **Network GUI** - Real-time encrypted chat
- **Educational GUI** - Step-by-step RSA demonstration
- **CLI** - Terminal-based implementation

---

## 🛠️ Requirements

- Python 3.7 or higher
- Standard library only (no pip install needed)
- Tkinter (usually pre-installed with Python)

---

## 📝 Notes

- Key generation takes 5-30 seconds (finding large primes)
- Message size limited to <128 bytes (< modulus size)
- Default port 3000 (configurable in GUI)
- Works on localhost or LAN

---

## 👨‍💻 Author

**Course:** APT3090 Cryptography and Network Security  
**Semester:** Fall 2025  
**Project Type:** Educational Implementation

---

