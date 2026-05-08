"""
Crypto layer for the Secure P2P Instant Messaging Tool.

Cipher      : AES-256-CBC  (key = 256 bits > 56-bit requirement)
Key Deriv   : PBKDF2-HMAC-SHA256 (password -> key, never raw password)
IV          : Random 16 bytes per message  (same msg -> different ciphertext)
Padding     : PKCS7
Key Rotation: Every 60 seconds via epoch-counter ratchet
Extra #1    : Double-cipher mode: AES-256-CBC XOR ChaCha20 output
Extra #2    : Diffie-Hellman key exchange (no pre-shared password needed)
"""

import hashlib
import struct
import time

from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


FIXED_SALT = b"SecureP2PChat_v1_SALT_2024"   # shared constant; same on both ends
KEY_ROTATION_SECS = 60   # rotate key every 60 seconds


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
