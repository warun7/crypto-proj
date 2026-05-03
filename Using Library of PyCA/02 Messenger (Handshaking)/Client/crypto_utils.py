from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def load_public_key(pem_bytes):
    """Loads and returns a PEM public key."""
    return serialization.load_pem_public_key(pem_bytes)
    
    

# ---------- Key Generation ----------

def generate_ephemeral_keypair():
    """Generates ECDSA keypair (P-256) for key exchange."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pub_bytes


# ---------- Key Exchange (ECDH) ----------

def perform_key_exchange(my_private_key, peer_public_pem):
    """Derives shared session key using ECDH and HKDF."""
    peer_public_key = serialization.load_pem_public_key(peer_public_pem)
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

    # Use HKDF to derive a symmetric key from the shared secret
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p chat'
    ).derive(shared_secret)

    return session_key  # 32 bytes for AES-256-GCM



    

