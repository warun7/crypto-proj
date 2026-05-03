"""
openssl_crypto.py — Cryptographic primitives via OpenSSL CLI subprocess calls.

Implements:
  (a) Authenticated Key Exchange  : ECDH (P-256) + ECDSA (P-256) signatures
  (b) Authenticated Encryption    : AES-128-CBC (Encrypt) + HMAC-SHA256 (MAC)
                                    following the Encrypt-then-MAC paradigm.

All heavy-lifting is delegated to the system `openssl` binary so that the
implementation truly uses the OpenSSL library (through its CLI front-end),
matching the pattern established in the existing "01 Messenger" codebase.
"""

import subprocess
import os
import struct
import hashlib
import hmac as _hmac_mod   # Python stdlib hmac used only for compare_digest


# ──────────────────────────────────────────────────────────────────────────────
# Key Generation
# ──────────────────────────────────────────────────────────────────────────────

def generate_identity_keypair(key_dir):
    """
    Generate an ephemeral ECDSA P-256 identity keypair used to sign the ECDH
    public key during the handshake (prevents MITM).

    Returns:
        (identity_priv_path : str, identity_pub_pem : bytes)
    """
    os.makedirs(key_dir, exist_ok=True)
    priv = os.path.join(key_dir, "identity_private.pem")
    pub  = os.path.join(key_dir, "identity_public.pem")

    # Generate private key on the NIST P-256 curve
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv],
        check=True, capture_output=True
    )
    # Export the corresponding public key in PEM format
    subprocess.run(
        ["openssl", "ec", "-in", priv, "-pubout", "-out", pub],
        check=True, capture_output=True
    )

    with open(pub, "rb") as f:
        return priv, f.read()


def generate_ephemeral_keypair(key_dir):
    """
    Generate an ephemeral ECDH P-256 keypair for the key-exchange step.

    Returns:
        (ecdh_priv_path : str, ecdh_pub_pem : bytes)
    """
    os.makedirs(key_dir, exist_ok=True)
    priv = os.path.join(key_dir, "ecdh_private.pem")
    pub  = os.path.join(key_dir, "ecdh_public.pem")

    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv],
        check=True, capture_output=True
    )
    subprocess.run(
        ["openssl", "ec", "-in", priv, "-pubout", "-out", pub],
        check=True, capture_output=True
    )

    with open(pub, "rb") as f:
        return priv, f.read()


# ──────────────────────────────────────────────────────────────────────────────
# ECDSA Sign / Verify
# ──────────────────────────────────────────────────────────────────────────────

def sign_data(data_bytes, identity_priv_path, key_dir):
    """
    Sign data_bytes with ECDSA-SHA256 using the given identity private key.

    Returns:
        signature : bytes  (DER-encoded ECDSA signature)
    """
    data_path = os.path.join(key_dir, "to_sign.bin")
    sig_path  = os.path.join(key_dir, "signature.bin")

    with open(data_path, "wb") as f:
        f.write(data_bytes)

    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", identity_priv_path,
         "-out", sig_path, data_path],
        check=True, capture_output=True
    )

    with open(sig_path, "rb") as f:
        return f.read()


def verify_signature(data_bytes, sig_bytes, peer_identity_pub_pem, key_dir):
    """
    Verify an ECDSA-SHA256 signature against the peer's identity public key.

    Returns:
        True if valid, False otherwise.
    """
    data_path = os.path.join(key_dir, "to_verify.bin")
    sig_path  = os.path.join(key_dir, "peer_sig.bin")
    pub_path  = os.path.join(key_dir, "peer_identity_pub.pem")

    with open(data_path, "wb") as f:
        f.write(data_bytes)
    with open(sig_path, "wb") as f:
        f.write(sig_bytes)
    with open(pub_path, "wb") as f:
        f.write(peer_identity_pub_pem)

    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", pub_path,
         "-signature", sig_path, data_path],
        capture_output=True
    )
    return result.returncode == 0


# ──────────────────────────────────────────────────────────────────────────────
# ECDH Key Exchange
# ──────────────────────────────────────────────────────────────────────────────

def perform_ecdh(key_dir, peer_ecdh_pub_pem):
    """
    Derive the ECDH shared secret using our ephemeral private key and the
    peer's ephemeral public key.

    Returns:
        shared_secret : bytes
    """
    priv_path       = os.path.join(key_dir, "ecdh_private.pem")
    peer_pub_path   = os.path.join(key_dir, "peer_ecdh_pub.pem")
    secret_path     = os.path.join(key_dir, "shared_secret.bin")

    with open(peer_pub_path, "wb") as f:
        f.write(peer_ecdh_pub_pem)

    subprocess.run(
        ["openssl", "pkeyutl", "-derive",
         "-inkey", priv_path,
         "-peerkey", peer_pub_path,
         "-out", secret_path],
        check=True, capture_output=True
    )

    with open(secret_path, "rb") as f:
        return f.read()


# ──────────────────────────────────────────────────────────────────────────────
# Key Derivation  (SHA-256 with domain-separation labels)
# ──────────────────────────────────────────────────────────────────────────────

def derive_keys(shared_secret):
    """
    Derive enc_key (16 bytes, AES-128) and mac_key (32 bytes, HMAC-SHA256)
    from the raw ECDH shared secret using SHA-256 with distinct labels.

    Returns:
        (enc_key : bytes[16], mac_key : bytes[32])
    """
    enc_key = hashlib.sha256(shared_secret + b"AES-128-CBC-ENC-KEY").digest()[:16]
    mac_key = hashlib.sha256(shared_secret + b"HMAC-SHA256-MAC-KEY").digest()
    return enc_key, mac_key


# ──────────────────────────────────────────────────────────────────────────────
# AES-128-CBC  Encryption / Decryption
# ──────────────────────────────────────────────────────────────────────────────

def aes_cbc_encrypt(plaintext, enc_key, key_dir):
    """
    Encrypt plaintext with AES-128-CBC using a freshly generated random IV.

    Returns:
        (iv : bytes[16], ciphertext : bytes)
    """
    iv_path = os.path.join(key_dir, "iv.bin")
    pt_path = os.path.join(key_dir, "plaintext.bin")
    ct_path = os.path.join(key_dir, "ciphertext.bin")

    # Random 16-byte IV via OpenSSL's CSPRNG
    subprocess.run(
        ["openssl", "rand", "-out", iv_path, "16"],
        check=True, capture_output=True
    )
    with open(iv_path, "rb") as f:
        iv_bytes = f.read()

    with open(pt_path, "wb") as f:
        f.write(plaintext)

    subprocess.run(
        ["openssl", "enc", "-aes-128-cbc",
         "-K",  enc_key.hex(),
         "-iv", iv_bytes.hex(),
         "-in", pt_path, "-out", ct_path],
        check=True, capture_output=True
    )

    with open(ct_path, "rb") as f:
        return iv_bytes, f.read()


def aes_cbc_decrypt(ciphertext, enc_key, iv_bytes, key_dir):
    """
    Decrypt ciphertext with AES-128-CBC.

    Returns:
        plaintext : bytes
    """
    ct_path = os.path.join(key_dir, "recv_ct.bin")
    pt_path = os.path.join(key_dir, "recv_pt.bin")

    with open(ct_path, "wb") as f:
        f.write(ciphertext)

    subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc",
         "-K",  enc_key.hex(),
         "-iv", iv_bytes.hex(),
         "-in", ct_path, "-out", pt_path],
        check=True, capture_output=True
    )

    with open(pt_path, "rb") as f:
        return f.read()


# ──────────────────────────────────────────────────────────────────────────────
# HMAC-SHA256
# ──────────────────────────────────────────────────────────────────────────────

def compute_hmac(data, mac_key, key_dir):
    """
    Compute HMAC-SHA256 of data using the given mac_key via OpenSSL.

    Returns:
        tag : bytes[32]
    """
    data_path = os.path.join(key_dir, "hmac_input.bin")
    hmac_path = os.path.join(key_dir, "hmac.bin")

    with open(data_path, "wb") as f:
        f.write(data)

    subprocess.run(
        ["openssl", "dgst", "-sha256",
         "-mac", "HMAC",
         "-macopt", f"hexkey:{mac_key.hex()}",
         "-binary",
         "-out", hmac_path,
         data_path],
        check=True, capture_output=True
    )

    with open(hmac_path, "rb") as f:
        return f.read()


def verify_hmac(data, mac_key, expected_tag, key_dir):
    """
    Verify HMAC-SHA256 in constant time (prevents timing attacks).

    Returns:
        True if the tag is valid.
    """
    computed = compute_hmac(data, mac_key, key_dir)
    return _hmac_mod.compare_digest(computed, expected_tag)


# ──────────────────────────────────────────────────────────────────────────────
# Wire-framing helpers
# ──────────────────────────────────────────────────────────────────────────────

def pack_fields(*fields):
    """Serialize several byte strings as consecutive [4-byte-len][data] frames."""
    result = b""
    for field in fields:
        result += struct.pack(">I", len(field)) + field
    return result


def recv_exact(conn, n):
    """Block until exactly n bytes have been received from conn."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf


def send_framed(conn, data):
    """Send data prefixed by its 4-byte big-endian length."""
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(conn):
    """Receive a single length-prefixed frame and return the payload."""
    raw_len = recv_exact(conn, 4)
    length  = struct.unpack(">I", raw_len)[0]
    return recv_exact(conn, length)
