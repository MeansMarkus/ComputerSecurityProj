# Secure P2P Instant Messaging Tool

A secure, GUI-based peer-to-peer chat application built in Python using `tkinter` and the `pycryptodome` library.

## Features
- **Strong Encryption**: AES-256-CBC and an optional Double-Cipher mode (AES-256-CBC XOR ChaCha20).
- **Key Derivation**: PBKDF2-HMAC-SHA256 for secure password-to-key conversion.
- **Key Rotation**: Epoch-counter ratchet that rotates keys periodically.
- **Randomized IVs**: Every message gets a random 16-byte IV to ensure the same plaintext produces different ciphertexts.
- **Diffie-Hellman Key Exchange**: Negotiate shared secrets securely over the network.

## Project Structure

The codebase is split into four modules:

- **`crypto.py`** — Cryptographic primitives: PBKDF2 key derivation, AES-256-CBC encrypt/decrypt, the double-cipher (AES + ChaCha20) mode, and Diffie-Hellman key exchange. Also defines `KEY_ROTATION_SECS`.
- **`net.py`** — Length-prefixed framed TCP messaging (`send_framed` / `recv_framed`).
- **`gui.py`** — `SecureChatApp`, the Tkinter UI. Wires the user controls to the crypto and network layers, and runs the receive loop and key-rotation watcher on background threads.
- **`main.py`** — Entry point; constructs the Tk root and launches `SecureChatApp`.

## Prerequisites

- Python 3.x installed on your system.
- `pip` package manager.

This application requires the `pycryptodome` library for its cryptographic functions. 

Install the required dependency using pip:
```bash
pip install pycryptodome
```

## How to Run

Because this is a P2P messaging tool, you will need to run the application on two different terminals (or two different machines on the same network) to simulate a conversation.

1. **Start the application**:
   ```bash
   python main.py
   ```

2. **Connect**:
   - The application provides a graphical interface.
   - On the first instance, select the option to start/listen as a **Server** on a specific IP/Port.
   - On the second instance, enter the Server's IP address and Port, and click to connect as a **Client**.

3. **Secure Chat**:
   - Both clients need to establish or enter the same shared password, or leverage the Diffie-Hellman key exchange built-in.
   - Begin sending secure messages instantly.
