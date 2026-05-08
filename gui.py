"""
Tkinter GUI for the Secure P2P Instant Messaging Tool.

Wires the user-facing controls (role/host/port/password, double-cipher and
Diffie-Hellman toggles, connect/disconnect, message entry, chat log) to the
crypto and network layers, and runs the receive loop and key-rotation
watcher on background threads.
"""

import base64
import json
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox

from crypto import (
    KEY_ROTATION_SECS,
    current_epoch,
    decrypt_aes_cbc,
    decrypt_double,
    derive_key,
    dh_generate_private,
    dh_public,
    dh_shared_secret,
    encrypt_aes_cbc,
    encrypt_double,
)
from net import recv_framed, send_framed


class SecureChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureChat P2P")
        self.root.geometry("720x560")
        self.root.minsize(600, 400)

        self.sock: socket.socket | None = None
        self.conn: socket.socket | None = None  # server-side accepted connection
        self.password: str = ""
        self.double_cipher: bool = False
        self.use_dh: bool = False          # extra credit #2
        self.dh_key: bytes | None = None   # derived from DH exchange
        self.connected: bool = False
        self.last_epoch: int = -1

        self._build_ui()

    def _build_ui(self):
        # Title row
        title = tk.Frame(self.root)
        title.pack(fill="x", padx=10, pady=4)
        tk.Label(title, text="SecureChat P2P").pack(side="left")
        self.status_lbl = tk.Label(title, text="OFFLINE")
        self.status_lbl.pack(side="right")
        self.epoch_lbl = tk.Label(title, text="")
        self.epoch_lbl.pack(side="right", padx=10)

        # Connection setup
        cfg = tk.LabelFrame(self.root, text="Connection Setup")
        cfg.pack(fill="x", padx=10, pady=4)

        row1 = tk.Frame(cfg)
        row1.pack(fill="x", padx=6, pady=4)

        tk.Label(row1, text="Role:").pack(side="left")
        self.role_var = tk.StringVar(value="Server")
        tk.Radiobutton(row1, text="Server (Alice)", variable=self.role_var,
                       value="Server", command=self._on_role_change).pack(side="left", padx=4)
        tk.Radiobutton(row1, text="Client (Bob)", variable=self.role_var,
                       value="Client", command=self._on_role_change).pack(side="left", padx=4)

        tk.Label(row1, text="Host:").pack(side="left", padx=(8, 0))
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(row1, textvariable=self.host_var, width=14).pack(side="left", padx=4)

        tk.Label(row1, text="Port:").pack(side="left")
        self.port_var = tk.StringVar(value="9999")
        tk.Entry(row1, textvariable=self.port_var, width=7).pack(side="left", padx=4)

        tk.Label(row1, text="Password:").pack(side="left", padx=(8, 0))
        self.pw_var = tk.StringVar()
        self.pw_entry = tk.Entry(row1, textvariable=self.pw_var, show="*", width=18)
        self.pw_entry.pack(side="left", padx=4)

        row2 = tk.Frame(cfg)
        row2.pack(fill="x", padx=6, pady=4)

        self.double_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Double-Cipher (AES+ChaCha20)",
                       variable=self.double_var).pack(side="left")

        self.dh_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="Diffie-Hellman key exchange",
                       variable=self.dh_var).pack(side="left", padx=10)

        self.disc_btn = tk.Button(row2, text="Disconnect",
                                  state="disabled", command=self._disconnect)
        self.disc_btn.pack(side="right", padx=4)
        self.conn_btn = tk.Button(row2, text="Connect", command=self._connect)
        self.conn_btn.pack(side="right", padx=4)

        # Chat log
        log_frame = tk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=10, pady=4)
        tk.Label(log_frame, text="Message Log").pack(anchor="w")
        self.chat_log = scrolledtext.ScrolledText(log_frame, state="disabled")
        self.chat_log.pack(fill="both", expand=True)

        # Input row
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill="x", padx=10, pady=4)
        self.msg_entry = tk.Entry(input_frame, state="disabled")
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.msg_entry.bind("<Return>", lambda e: self._send_message())
        self.send_btn = tk.Button(input_frame, text="Send",
                                  state="disabled", command=self._send_message)
        self.send_btn.pack(side="right")

        self._on_role_change()

    def _on_role_change(self):
        if self.role_var.get() == "Server":
            self.host_var.set("0.0.0.0")
        else:
            self.host_var.set("127.0.0.1")

    def _log(self, text: str):
        self.chat_log.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self.chat_log.insert("end", f"[{ts}] {text}\n")
        self.chat_log.config(state="disabled")
        self.chat_log.see("end")

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
        self._log(f"Attempting {role} connection on {host}:{port}...")

        threading.Thread(target=self._connect_thread,
                         args=(role, host, port), daemon=True).start()

    def _connect_thread(self, role: str, host: str, port: int):
        try:
            if role == "Server":
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((host, port))
                server_sock.listen(1)
                self.root.after(0, lambda: self._log(f"Listening on port {port}... waiting for peer."))
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

            # DH key exchange (Extra Credit #2)
            if self.use_dh:
                self.root.after(0, lambda: self._log("Initiating Diffie-Hellman key exchange..."))
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
                    f"DH exchange complete. Shared key (SHA-256): {self.dh_key.hex()[:32]}..."))

            self.sock = active_sock
            self.connected = True
            self.root.after(0, lambda: self._on_connected(peer))
            self._recv_loop()
        except Exception as e:
            self.root.after(0, lambda: self._log(f"Connection error: {e}"))
            self.root.after(0, lambda: self.conn_btn.config(state="normal"))

    def _on_connected(self, peer):
        self.status_lbl.config(text=f"CONNECTED {peer[0]}:{peer[1]}")
        self.msg_entry.config(state="normal")
        self.send_btn.config(state="normal")
        self.disc_btn.config(state="normal")
        mode = "Double-Cipher (AES+ChaCha20)" if self.double_cipher else "AES-256-CBC"
        kd   = "Diffie-Hellman" if self.use_dh else "PBKDF2-HMAC-SHA256"
        self._log(f"Connected. Cipher: {mode} | Key derivation: {kd} | Rotation: {KEY_ROTATION_SECS}s")
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
        self.status_lbl.config(text="OFFLINE")
        self.msg_entry.config(state="disabled")
        self.send_btn.config(state="disabled")
        self.disc_btn.config(state="disabled")
        self.conn_btn.config(state="normal")
        self._log("Disconnected.")

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
            ct_display = ct_b64[:80] + ("..." if len(ct_b64) > 80 else "")

            self._log(f'YOU: "{msg}"')
            self._log(f"  ciphertext: {ct_display}")
        except Exception as e:
            self._log(f"Send error: {e}")

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
                    self.root.after(0, lambda err=str(e): self._log(f"Decrypt error: {err}"))
            except Exception:
                break

        self.root.after(0, self._disconnect)

    def _display_recv(self, ct_b64: str, plaintext: str):
        ct_display = ct_b64[:80] + ("..." if len(ct_b64) > 80 else "")
        self._log(f"PEER: ciphertext: {ct_display}")
        self._log(f'  decrypted: "{plaintext}"')

    def _key_rotation_watcher(self):
        while self.connected:
            ep = current_epoch(KEY_ROTATION_SECS)
            if ep != self.last_epoch:
                self.last_epoch = ep
                key_preview = derive_key(self.password, ep).hex()[:16]
                self.root.after(0, lambda kp=key_preview, e=ep: (
                    self._log(f"Key rotated - epoch {e} | new key prefix: {kp}..."),
                    self._update_epoch_label()
                ))
            time.sleep(2)

    def _update_epoch_label(self):
        ep = current_epoch(KEY_ROTATION_SECS)
        remaining = KEY_ROTATION_SECS - (int(time.time()) % KEY_ROTATION_SECS)
        self.epoch_lbl.config(text=f"Epoch {ep} | next rotation: {remaining}s")
        self.root.after(2000, self._update_epoch_label)
