"""
Network layer: length-prefixed framed TCP messaging.

Each frame is sent as a 4-byte big-endian length header followed by `length`
bytes of payload, so the receiver can reassemble exact message boundaries
even when TCP coalesces or splits the underlying segments.
"""

import socket
import struct


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
