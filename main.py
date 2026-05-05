"""
Secure P2P Instant Messaging Tool
-----------------------------------
Cipher      : AES-256-CBC  (key = 256 bits > 56-bit requirement)
Key Deriv   : PBKDF2-HMAC-SHA256 (password -> key, never raw password)
IV          : Random 16 bytes per message  (same msg -> different ciphertext)
Padding     : PKCS7
Key Rotation: Every 60 seconds via epoch-counter ratchet
Transport   : TCP sockets (server listens, client connects)
Extra #1    : Double-cipher mode: AES-256-CBC XOR ChaCha20 output
Extra #2    : Diffie-Hellman key exchange (no pre-shared password needed)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import os
import time
import base64
import hashlib
import struct
import json

from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


# ─────────────────────────────────────────────
#  CRYPTO LAYER
# ─────────────────────────────────────────────

FIXED_SALT = b"SecureP2PChat_v1_SALT_2024"   # shared constant; same on both ends

def derive_key(password: str, rotation_epoch: int, length: int = 32) -> bytes:
    """
    PBKDF2-HMAC-SHA256 key derivation.
    - password  : shared passphrase (never used directly as a key)
    - rotation_epoch : integer that increments every KEY_ROTATION_SECS seconds
                       ensures keys rotate periodically
    - Returns 256-bit (32-byte) key by default.
    """
    salt = FIXED_SALT + struct.pack(">Q", rotation_epoch)
    key = PBKDF2(
        password.encode(),
        salt,
        dkLen=length,
        count=200_000,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )
    return key

def current_epoch(rotation_secs: int = 60) -> int:
    """Returns which rotation window we are currently in."""
    return int(time.time()) // rotation_secs

def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC encryption with PKCS7 padding.
    Prepends a random 16-byte IV to the ciphertext.
    Because IV is random, identical plaintexts produce different ciphertexts.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))  # PKCS7 padding
    return iv + ct

def decrypt_aes_cbc(key: bytes, data: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ── Extra Credit #1: Double-Cipher mode ─────────────────────────────────────

def derive_chacha_key(password: str, rotation_epoch: int) -> tuple[bytes, bytes]:
    """Derive a separate 256-bit key + 96-bit nonce for ChaCha20."""
    material = PBKDF2(
        password.encode(),
        FIXED_SALT + b"_CHACHA" + struct.pack(">Q", rotation_epoch),
        dkLen=44,   # 32 key + 12 nonce
        count=200_000,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest()
    )
    return material[:32], material[32:44]

def encrypt_double(password: str, rotation_epoch: int, plaintext: bytes) -> bytes:
    """
    Extra-credit double encryption:
      1. Encrypt plaintext with AES-256-CBC  → ct_aes  (same length as padded PT)
      2. Encrypt plaintext with ChaCha20     → ct_cha  (same length as PT, stream cipher)
      3. XOR ct_aes[0:len(ct_cha)] with ct_cha
      Structure: [1 byte flag=0xEC] [AES-IV 16B] [XOR'd ciphertext]
    Security rationale: attacker must break BOTH ciphers simultaneously;
    XOR with independent keystream adds an additional layer of confusion.
    """
    aes_key = derive_key(password, rotation_epoch)
    cha_key, cha_nonce = derive_chacha_key(password, rotation_epoch)

    # AES-CBC with random IV
    iv = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ct_aes = aes_cipher.encrypt(pad(plaintext, AES.block_size))

    # ChaCha20 keystream: encrypt zeros with a fresh random nonce
    # Security: XOR-ing ct_aes with an independent keystream means
    # an attacker must break both AES-256-CBC AND recover the ChaCha20 keystream.
    cha_nonce_rand = get_random_bytes(12)
    cha_cipher = ChaCha20.new(key=cha_key, nonce=cha_nonce_rand)
    cha_ks = cha_cipher.encrypt(bytes(len(ct_aes)))  # keystream

    # XOR ct_aes with ChaCha20 keystream
    xored = bytes(a ^ b for a, b in zip(ct_aes, cha_ks))

    return b"\xEC" + iv + cha_nonce_rand + xored

def decrypt_double(password: str, rotation_epoch: int, data: bytes) -> bytes:
    assert data[0:1] == b"\xEC", "Not a double-cipher packet"
    iv           = data[1:17]
    cha_nonce_r  = data[17:29]
    xored        = data[29:]

    aes_key = derive_key(password, rotation_epoch)
    cha_key, _ = derive_chacha_key(password, rotation_epoch)

    # Re-generate ChaCha20 ciphertext of padded plaintext.
    # We need the same ct_cha that was used during encryption.
    # During encryption: ct_cha = ChaCha20(padded_pt)
    # During decryption: we first recover ct_aes from XOR, then decrypt with AES.
    # BUT we need ct_cha to unXOR. Since ct_cha = XOR ^ ct_aes, we need ct_aes first.
    # Strategy: XOR = ct_aes XOR ct_cha  =>  ct_aes = XOR XOR ct_cha
    # We know ct_cha was ChaCha20 encryption of padded_pt.
    # Instead: re-derive same ct_cha by encrypting zeros (keystream) then xoring to get ct_aes.
    # Actually during encryption ct_cha = encrypt(padded_pt) and we XOR ct_aes ^ ct_cha.
    # For decryption without knowing pt: note ChaCha20 is a stream cipher so:
    #   ct_cha = cha_key_stream XOR padded_pt
    #   xored  = ct_aes XOR ct_cha = ct_aes XOR cha_ks XOR padded_pt
    # Simpler fix: store ct_cha separately or change the design to XOR with keystream only.
    # Redesign: encrypt zeros with ChaCha20 = pure keystream, XOR with ct_aes.
    # Decrypt: XOR xored with keystream -> ct_aes -> AES decrypt -> pt.
    cha_cipher = ChaCha20.new(key=cha_key, nonce=cha_nonce_r)
    cha_ks = cha_cipher.encrypt(bytes(len(xored)))  # keystream (encrypt zeros)

    # XOR to recover ct_aes
    ct_aes = bytes(a ^ b for a, b in zip(xored, cha_ks))

    # Decrypt AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(aes_cipher.decrypt(ct_aes), AES.block_size)


# ── Extra Credit #2: Diffie-Hellman key exchange ─────────────────────────────

# RFC 3526 Group 14 (2048-bit MODP)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)
DH_G = 2

def dh_generate_private() -> int:
    return int.from_bytes(get_random_bytes(256), "big") % (DH_P - 2) + 2

def dh_public(private: int) -> int:
    return pow(DH_G, private, DH_P)

def dh_shared_secret(their_public: int, my_private: int) -> bytes:
    shared = pow(their_public, my_private, DH_P)
    raw = shared.to_bytes(256, "big")
    return hashlib.sha256(raw).digest()   # 256-bit key from shared secret


# ─────────────────────────────────────────────
#  NETWORK LAYER
# ─────────────────────────────────────────────

MSG_SIZE_PREFIX = 4   # 4-byte big-endian length header

def send_framed(sock: socket.socket, data: bytes):
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)

def recv_framed(sock: socket.socket) -> bytes:
    raw_len = _recv_exact(sock, MSG_SIZE_PREFIX)
    if not raw_len:
        return b""
    length = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, length)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ─────────────────────────────────────────────
#  GUI APPLICATION
# ─────────────────────────────────────────────

COLORS = {
    "bg":        "#0a0e17",
    "panel":     "#111827",
    "border":    "#1e3a5f",
    "accent":    "#00d4ff",
    "accent2":   "#7c3aed",
    "sent_ct":   "#f59e0b",
    "recv_ct":   "#f97316",
    "plaintext": "#34d399",
    "system":    "#6b7280",
    "text":      "#e2e8f0",
    "entry_bg":  "#1a2235",
    "btn":       "#1e3a5f",
    "btn_hover": "#00d4ff",
}

KEY_ROTATION_SECS = 60   # rotate key every 60 seconds


class SecureChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureChat P2P")
        self.root.configure(bg=COLORS["bg"])
        self.root.geometry("1000x780")
        self.root.minsize(800, 600)

        self.sock: socket.socket | None = None
        self.conn: socket.socket | None = None  # server-side accepted connection
        self.password: str = ""
        self.double_cipher: bool = False
        self.use_dh: bool = False          # extra credit #2
        self.dh_key: bytes | None = None   # derived from DH exchange
        self.connected: bool = False
        self.last_epoch: int = -1

        self._build_ui()

    # ──────────────────────── UI BUILD ────────────────────────

    def _build_ui(self):
        # ── Title bar ──
        title_frame = tk.Frame(self.root, bg=COLORS["bg"], pady=10)
        title_frame.pack(fill="x", padx=20)

        tk.Label(title_frame, text="🔐 SecureChat P2P",
                 font=("Courier New", 20, "bold"),
                 fg=COLORS["accent"], bg=COLORS["bg"]).pack(side="left")

        self.status_lbl = tk.Label(title_frame, text="● OFFLINE",
                                    font=("Courier New", 11),
                                    fg=COLORS["system"], bg=COLORS["bg"])
        self.status_lbl.pack(side="right")

        self.epoch_lbl = tk.Label(title_frame, text="",
                                   font=("Courier New", 9),
                                   fg=COLORS["system"], bg=COLORS["bg"])
        self.epoch_lbl.pack(side="right", padx=20)

        # ── Config panel ──
        cfg = tk.LabelFrame(self.root, text=" Connection Setup ",
                            font=("Courier New", 10, "bold"),
                            fg=COLORS["accent"], bg=COLORS["panel"],
                            bd=1, relief="solid")
        cfg.pack(fill="x", padx=20, pady=4)

        # row 1: role + host + port + password
        row1 = tk.Frame(cfg, bg=COLORS["panel"])
        row1.pack(fill="x", padx=10, pady=6)

        tk.Label(row1, text="Role:", fg=COLORS["text"], bg=COLORS["panel"],
                 font=("Courier New", 10)).pack(side="left")
        self.role_var = tk.StringVar(value="Server")
        rb_s = tk.Radiobutton(row1, text="Server (Alice)", variable=self.role_var,
                               value="Server", fg=COLORS["accent"], bg=COLORS["panel"],
                               selectcolor=COLORS["bg"], font=("Courier New", 10),
                               command=self._on_role_change)
        rb_c = tk.Radiobutton(row1, text="Client (Bob)", variable=self.role_var,
                               value="Client", fg=COLORS["accent2"], bg=COLORS["panel"],
                               selectcolor=COLORS["bg"], font=("Courier New", 10),
                               command=self._on_role_change)
        rb_s.pack(side="left", padx=6)
        rb_c.pack(side="left", padx=6)

        tk.Label(row1, text="  Host:", fg=COLORS["text"], bg=COLORS["panel"],
                 font=("Courier New", 10)).pack(side="left")
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(row1, textvariable=self.host_var, width=14,
                 bg=COLORS["entry_bg"], fg=COLORS["text"],
                 insertbackground=COLORS["accent"],
                 font=("Courier New", 10), relief="flat").pack(side="left", padx=4)

        tk.Label(row1, text="Port:", fg=COLORS["text"], bg=COLORS["panel"],
                 font=("Courier New", 10)).pack(side="left")
        self.port_var = tk.StringVar(value="9999")
        tk.Entry(row1, textvariable=self.port_var, width=7,
                 bg=COLORS["entry_bg"], fg=COLORS["text"],
                 insertbackground=COLORS["accent"],
                 font=("Courier New", 10), relief="flat").pack(side="left", padx=4)

        tk.Label(row1, text="  Password:", fg=COLORS["text"], bg=COLORS["panel"],
                 font=("Courier New", 10)).pack(side="left")
        self.pw_var = tk.StringVar()
        self.pw_entry = tk.Entry(row1, textvariable=self.pw_var, show="*", width=18,
                                  bg=COLORS["entry_bg"], fg=COLORS["text"],
                                  insertbackground=COLORS["accent"],
                                  font=("Courier New", 10), relief="flat")
        self.pw_entry.pack(side="left", padx=4)

        # row 2: options + connect button
        row2 = tk.Frame(cfg, bg=COLORS["panel"])
        row2.pack(fill="x", padx=10, pady=(0, 8))

        self.double_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Double-Cipher (AES⊕ChaCha20) [Extra Credit]",
                        variable=self.double_var,
                        fg=COLORS["accent2"], bg=COLORS["panel"],
                        selectcolor=COLORS["bg"],
                        font=("Courier New", 9)).pack(side="left")

        self.dh_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Diffie-Hellman Key Exchange (no shared password) [Extra Credit]",
                        variable=self.dh_var,
                        fg=COLORS["sent_ct"], bg=COLORS["panel"],
                        selectcolor=COLORS["bg"],
                        font=("Courier New", 9)).pack(side="left", padx=12)

        self.conn_btn = tk.Button(row2, text="CONNECT",
                                   font=("Courier New", 10, "bold"),
                                   fg=COLORS["bg"], bg=COLORS["accent"],
                                   activebackground=COLORS["accent2"],
                                   relief="flat", padx=14, pady=3,
                                   command=self._connect)
        self.conn_btn.pack(side="right", padx=4)

        self.disc_btn = tk.Button(row2, text="DISCONNECT",
                                   font=("Courier New", 10, "bold"),
                                   fg=COLORS["text"], bg=COLORS["system"],
                                   relief="flat", padx=10, pady=3,
                                   state="disabled",
                                   command=self._disconnect)
        self.disc_btn.pack(side="right", padx=4)

        # ── Chat log ──
        log_frame = tk.Frame(self.root, bg=COLORS["bg"])
        log_frame.pack(fill="both", expand=True, padx=20, pady=4)

        tk.Label(log_frame, text="Message Log",
                 font=("Courier New", 10, "bold"),
                 fg=COLORS["system"], bg=COLORS["bg"]).pack(anchor="w")

        self.chat_log = scrolledtext.ScrolledText(
            log_frame, state="disabled",
            bg=COLORS["panel"], fg=COLORS["text"],
            font=("Courier New", 10),
            insertbackground=COLORS["accent"],
            relief="flat", bd=0,
            selectbackground=COLORS["border"]
        )
        self.chat_log.pack(fill="both", expand=True)

        # configure text tags
        self.chat_log.tag_config("sent_label",  foreground=COLORS["accent"],   font=("Courier New", 10, "bold"))
        self.chat_log.tag_config("recv_label",  foreground=COLORS["accent2"],  font=("Courier New", 10, "bold"))
        self.chat_log.tag_config("ct_sent",     foreground=COLORS["sent_ct"],  font=("Courier New", 9))
        self.chat_log.tag_config("ct_recv",     foreground=COLORS["recv_ct"],  font=("Courier New", 9))
        self.chat_log.tag_config("plaintext",   foreground=COLORS["plaintext"],font=("Courier New", 10))
        self.chat_log.tag_config("system",      foreground=COLORS["system"],   font=("Courier New", 9, "italic"))
        self.chat_log.tag_config("key_rotate",  foreground=COLORS["accent2"],  font=("Courier New", 9, "bold"))

        # ── Input row ──
        input_frame = tk.Frame(self.root, bg=COLORS["bg"])
        input_frame.pack(fill="x", padx=20, pady=(0, 14))

        self.msg_entry = tk.Entry(input_frame,
                                   bg=COLORS["entry_bg"], fg=COLORS["text"],
                                   insertbackground=COLORS["accent"],
                                   font=("Courier New", 12), relief="flat",
                                   state="disabled")
        self.msg_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        self.send_btn = tk.Button(input_frame, text="SEND ▶",
                                   font=("Courier New", 11, "bold"),
                                   fg=COLORS["bg"], bg=COLORS["accent"],
                                   activebackground=COLORS["accent2"],
                                   relief="flat", padx=18, pady=6,
                                   state="disabled",
                                   command=self._send_message)
        self.send_btn.pack(side="right")

        # legend
        legend = tk.Frame(self.root, bg=COLORS["bg"])
        legend.pack(fill="x", padx=20, pady=(0, 8))
        for color, label in [
            (COLORS["sent_ct"],   "■ Sent ciphertext"),
            (COLORS["recv_ct"],   "■ Recv ciphertext"),
            (COLORS["plaintext"], "■ Decrypted plaintext"),
            (COLORS["system"],    "■ System events"),
        ]:
            tk.Label(legend, text=label, fg=color, bg=COLORS["bg"],
                     font=("Courier New", 8)).pack(side="left", padx=8)

        self._on_role_change()

    def _on_role_change(self):
        if self.role_var.get() == "Server":
            self.host_var.set("0.0.0.0")
        else:
            self.host_var.set("127.0.0.1")

    # ──────────────────────── LOGGING ────────────────────────

    def _log(self, text: str, tag: str = "system"):
        self.chat_log.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_log.insert("end", f"[{ts}] ", "system")
        self.chat_log.insert("end", text + "\n", tag)
        self.chat_log.config(state="disabled")
        self.chat_log.see("end")

    def _log_multi(self, parts: list[tuple[str, str]]):
        """Log multiple (text, tag) pairs on the same 'line block'."""
        self.chat_log.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_log.insert("end", f"[{ts}] ", "system")
        for text, tag in parts:
            self.chat_log.insert("end", text, tag)
        self.chat_log.insert("end", "\n")
        self.chat_log.config(state="disabled")
        self.chat_log.see("end")

    # ──────────────────────── CONNECTION ────────────────────────

    def _connect(self):
        role     = self.role_var.get()
        host     = self.host_var.get()
        port     = int(self.port_var.get())
        password = self.pw_var.get()
        self.double_cipher = self.double_var.get()
        self.use_dh        = self.dh_var.get()

        if not self.use_dh and not password:
            messagebox.showerror("Error", "Enter a shared password (or enable DH mode).")
            return

        self.password = password
        self.conn_btn.config(state="disabled")
        self._log(f"Attempting {role} connection on {host}:{port}...", "system")

        threading.Thread(target=self._connect_thread,
                         args=(role, host, port), daemon=True).start()

    def _connect_thread(self, role: str, host: str, port: int):
        try:
            if role == "Server":
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((host, port))
                server_sock.listen(1)
                self.root.after(0, lambda: self._log(f"Listening on port {port}... waiting for peer.", "system"))
                conn, addr = server_sock.accept()
                server_sock.close()
                self.conn = conn
                active_sock = conn
                peer = addr
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                self.conn = s
                active_sock = s
                peer = (host, port)

            # ── DH key exchange (Extra Credit #2) ──
            if self.use_dh:
                self.root.after(0, lambda: self._log("Initiating Diffie-Hellman key exchange...", "system"))
                dh_priv  = dh_generate_private()
                dh_pub   = dh_public(dh_priv)
                pub_bytes = dh_pub.to_bytes(256, "big")
                send_framed(active_sock, pub_bytes)
                their_bytes = recv_framed(active_sock)
                their_pub   = int.from_bytes(their_bytes, "big")
                self.dh_key = dh_shared_secret(their_pub, dh_priv)
                # Use DH shared secret as the "password" material
                self.password = self.dh_key.hex()
                self.root.after(0, lambda: self._log(
                    f"DH exchange complete. Shared key (SHA-256): {self.dh_key.hex()[:32]}...", "system"))

            self.sock = active_sock
            self.connected = True
            self.root.after(0, lambda: self._on_connected(peer))
            self._recv_loop()
        except Exception as e:
            self.root.after(0, lambda: self._log(f"Connection error: {e}", "system"))
            self.root.after(0, lambda: self.conn_btn.config(state="normal"))

    def _on_connected(self, peer):
        self.status_lbl.config(text=f"● CONNECTED  {peer[0]}:{peer[1]}", fg=COLORS["accent"])
        self.msg_entry.config(state="normal")
        self.send_btn.config(state="normal")
        self.disc_btn.config(state="normal")
        mode = "Double-Cipher (AES⊕ChaCha20)" if self.double_cipher else "AES-256-CBC"
        kd   = "Diffie-Hellman" if self.use_dh else "PBKDF2-HMAC-SHA256"
        self._log(f"Connected! Cipher: {mode} | Key derivation: {kd} | Rotation: {KEY_ROTATION_SECS}s", "system")
        self._update_epoch_label()
        threading.Thread(target=self._key_rotation_watcher, daemon=True).start()

    def _disconnect(self):
        self.connected = False
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn = None
        self.sock = None
        self.status_lbl.config(text="● OFFLINE", fg=COLORS["system"])
        self.msg_entry.config(state="disabled")
        self.send_btn.config(state="disabled")
        self.disc_btn.config(state="disabled")
        self.conn_btn.config(state="normal")
        self._log("Disconnected.", "system")

    # ──────────────────────── SEND ────────────────────────

    def _send_message(self):
        if not self.connected or not self.conn:
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        self.msg_entry.delete(0, "end")

        epoch = current_epoch(KEY_ROTATION_SECS)
        plaintext = msg.encode("utf-8")

        try:
            if self.double_cipher:
                ct_raw = encrypt_double(self.password, epoch, plaintext)
            else:
                key = derive_key(self.password, epoch)
                ct_raw = encrypt_aes_cbc(key, plaintext)

            # Wire format: JSON {"epoch": N, "ct": <base64>}
            packet = json.dumps({
                "epoch": epoch,
                "ct": base64.b64encode(ct_raw).decode()
            }).encode()

            send_framed(self.conn, packet)
            ct_b64 = base64.b64encode(ct_raw).decode()

            self._log_multi([
                ("YOU ▶ ", "sent_label"),
                (f'"{msg}"', "plaintext"),
            ])
            self._log_multi([
                ("  CIPHERTEXT: ", "sent_label"),
                (ct_b64[:80] + ("…" if len(ct_b64) > 80 else ""), "ct_sent"),
            ])
        except Exception as e:
            self._log(f"Send error: {e}", "system")

    # ──────────────────────── RECEIVE ────────────────────────

    def _recv_loop(self):
        while self.connected:
            try:
                raw = recv_framed(self.conn)
                if not raw:
                    break
                packet = json.loads(raw.decode())
                epoch  = packet["epoch"]
                ct_raw = base64.b64decode(packet["ct"])

                try:
                    if self.double_cipher:
                        pt = decrypt_double(self.password, epoch, ct_raw).decode("utf-8")
                    else:
                        key = derive_key(self.password, epoch)
                        # Try current and adjacent epochs (grace period for rotation boundary)
                        decrypted = False
                        for ep in [epoch, epoch - 1, epoch + 1]:
                            try:
                                k = derive_key(self.password, ep)
                                pt = decrypt_aes_cbc(k, ct_raw).decode("utf-8")
                                decrypted = True
                                break
                            except Exception:
                                continue
                        if not decrypted:
                            pt = "[DECRYPTION FAILED]"

                    ct_b64 = packet["ct"]
                    self.root.after(0, lambda ct=ct_b64, p=pt: self._display_recv(ct, p))
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self._log(f"Decrypt error: {err}", "system"))
            except Exception:
                break

        self.root.after(0, self._disconnect)

    def _display_recv(self, ct_b64: str, plaintext: str):
        self._log_multi([
            ("PEER ◀ ", "recv_label"),
            (f'CIPHERTEXT: {ct_b64[:80]}' + ("…" if len(ct_b64) > 80 else ""), "ct_recv"),
        ])
        self._log_multi([
            ("  DECRYPTED: ", "recv_label"),
            (f'"{plaintext}"', "plaintext"),
        ])

    # ──────────────────────── KEY ROTATION WATCHER ────────────────────────

    def _key_rotation_watcher(self):
        while self.connected:
            ep = current_epoch(KEY_ROTATION_SECS)
            if ep != self.last_epoch:
                self.last_epoch = ep
                key_preview = derive_key(self.password, ep).hex()[:16]
                self.root.after(0, lambda kp=key_preview, e=ep: (
                    self._log(f"🔑 KEY ROTATED — epoch {e} | new key prefix: {kp}...", "key_rotate"),
                    self._update_epoch_label()
                ))
            time.sleep(2)

    def _update_epoch_label(self):
        ep = current_epoch(KEY_ROTATION_SECS)
        remaining = KEY_ROTATION_SECS - (int(time.time()) % KEY_ROTATION_SECS)
        self.epoch_lbl.config(text=f"Epoch {ep} | next rotation: {remaining}s")
        self.root.after(2000, self._update_epoch_label)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()