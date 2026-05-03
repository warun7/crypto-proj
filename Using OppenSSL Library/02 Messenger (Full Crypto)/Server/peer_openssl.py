"""
peer_openssl.py  —  Server side

Full-crypto messenger peer implementing:
  (a) Authenticated Key Exchange : ECDH (P-256) key agreement authenticated
                                   with ECDSA (P-256) signatures.
  (b) Authenticated Encryption   : Encrypt-then-MAC
                                     • Encrypt  : AES-128-CBC  (random IV)
                                     • MAC      : HMAC-SHA256  over IV‖ciphertext

Handshake protocol:
    Client sends first, server receives first — then server sends, client receives.
    Each handshake message contains three length-prefixed fields:
        [identity_pub_pem | ecdh_pub_pem | ecdsa_sig_of_ecdh_pub]
    After exchange, each peer:
        1. Verifies the peer's ECDSA signature over their ECDH public key.
        2. Computes the ECDH shared secret.
        3. Derives enc_key and mac_key via SHA-256 KDF.

Message wire format (Encrypt-then-MAC):
    [4B IV_len][16B IV][4B CT_len][CT bytes][32B HMAC-SHA256(IV‖CT)]
"""

import socket
import struct
import threading
from openssl_crypto import (
    generate_identity_keypair, generate_ephemeral_keypair,
    sign_data, verify_signature,
    perform_ecdh, derive_keys,
    aes_cbc_encrypt, aes_cbc_decrypt,
    compute_hmac, verify_hmac,
    pack_fields, recv_exact, send_framed, recv_framed,
)

HMAC_LEN = 32   # HMAC-SHA256 output length in bytes


class Peer:
    def __init__(self, is_server, host="0.0.0.0", port=5001):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.is_server = is_server
        self.host      = host
        self.port      = port
        self.conn      = None

        # Working directory for key files and temp crypto blobs
        self.key_dir = "Server_keys" if is_server else "Client_keys"

        # Session key material — filled after handshake
        self.enc_key = None
        self.mac_key = None

    # ──────────────────────────────────────────────────────────────────────────
    # Handshake Phase — Authenticated Key Exchange (ECDH + ECDSA)
    # ──────────────────────────────────────────────────────────────────────────

    def _build_handshake_msg(self):
        """
        Generate identity + ephemeral keypairs, sign the ECDH public key with
        the identity key, and pack everything into a single framed payload.
        """
        # ECDSA identity key (sign-only, ephemeral per session)
        id_priv_path, id_pub_pem = generate_identity_keypair(self.key_dir)

        # Ephemeral ECDH key (key-exchange)
        _, ecdh_pub_pem = generate_ephemeral_keypair(self.key_dir)

        # Sign the ECDH public key → proves ownership / prevents MITM
        signature = sign_data(ecdh_pub_pem, id_priv_path, self.key_dir)

        # Pack: [id_pub | ecdh_pub | sig]
        return pack_fields(id_pub_pem, ecdh_pub_pem, signature)

    def _parse_handshake_msg(self, frame):
        """
        Unpack a peer handshake message into its three fields.

        Returns:
            (identity_pub_pem, ecdh_pub_pem, signature)
        """
        offset = 0
        fields = []
        for _ in range(3):
            length = struct.unpack(">I", frame[offset:offset + 4])[0]
            offset += 4
            fields.append(frame[offset:offset + length])
            offset += length
        return fields  # [identity_pub_pem, ecdh_pub_pem, signature]

    def _handshake(self):
        """
        Authenticated key-exchange handshake.

        Server receives first (client sends first), then server sends.
        """
        print("[*] Starting authenticated handshake...")

        # --- Receive client's handshake message first ---
        peer_frame = recv_framed(self.conn)
        peer_id_pub, peer_ecdh_pub, peer_sig = self._parse_handshake_msg(peer_frame)
        print("[*] Received peer handshake message")

        # --- Verify client's ECDSA signature over their ECDH public key ---
        if not verify_signature(peer_ecdh_pub, peer_sig, peer_id_pub, self.key_dir):
            raise ValueError("[!] ECDSA verification FAILED — possible MITM attack!")
        print("[+] ECDSA signature verified — peer authenticated")

        # --- Build and send our handshake message ---
        my_msg = self._build_handshake_msg()
        send_framed(self.conn, my_msg)
        print("[*] Sent: identity_pub | ecdh_pub | ECDSA-signature")

        # --- ECDH shared secret ---
        shared_secret = perform_ecdh(self.key_dir, peer_ecdh_pub)
        print(f"[+] ECDH shared secret derived ({len(shared_secret)} bytes)")

        # --- Key derivation ---
        self.enc_key, self.mac_key = derive_keys(shared_secret)
        print("[+] Session keys derived:")
        print(f"    enc_key (AES-128-CBC) : {self.enc_key.hex()}")
        print(f"    mac_key (HMAC-SHA256) : {self.mac_key.hex()}")
        print("[+] Handshake complete — secure session established.")

    # ──────────────────────────────────────────────────────────────────────────
    # Connection Phase
    # ──────────────────────────────────────────────────────────────────────────

    def start(self):
        """Bind, listen, accept, run handshake, then start messaging."""
        # Bind to 0.0.0.0 so clients from any network can connect
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"[*] Server listening on {self.host}:{self.port}  (all interfaces)")

        conn, addr = self.sock.accept()
        print(f"[*] Connection accepted from {addr[0]}:{addr[1]}")
        self.conn = conn

        self._handshake()
        self._start_threads()

    def _start_threads(self):
        threading.Thread(target=self._receive_loop, daemon=True).start()
        print("[*] Ready to chat (type 'exit' to quit)\n")
        self._send_loop()

    # ──────────────────────────────────────────────────────────────────────────
    # Messaging — Encrypt-then-MAC (AES-128-CBC + HMAC-SHA256)
    # ──────────────────────────────────────────────────────────────────────────

    def _encrypt_and_mac(self, plaintext_bytes):
        """
        Encrypt plaintext then compute MAC over the ciphertext.

        Wire format:
            [4B IV_len][IV][4B CT_len][CT][32B HMAC(IV‖CT)]

        Returns:
            frame : bytes
        """
        iv, ciphertext = aes_cbc_encrypt(plaintext_bytes, self.enc_key, self.key_dir)
        mac_input = iv + ciphertext
        tag = compute_hmac(mac_input, self.mac_key, self.key_dir)

        frame  = struct.pack(">I", len(iv))         + iv
        frame += struct.pack(">I", len(ciphertext)) + ciphertext
        frame += tag  # always 32 bytes, no length prefix needed
        return frame

    def _verify_and_decrypt(self, frame):
        """
        Verify the MAC first, then decrypt (Encrypt-then-MAC).

        Returns:
            plaintext : bytes  (or raises ValueError on MAC failure)
        """
        offset = 0

        # Parse IV
        iv_len = struct.unpack(">I", frame[offset:offset + 4])[0]
        offset += 4
        iv = frame[offset:offset + iv_len]
        offset += iv_len

        # Parse ciphertext
        ct_len = struct.unpack(">I", frame[offset:offset + 4])[0]
        offset += 4
        ciphertext = frame[offset:offset + ct_len]
        offset += ct_len

        # Parse HMAC tag (last 32 bytes)
        received_tag = frame[offset:offset + HMAC_LEN]

        # ── Verify MAC BEFORE decrypting (Encrypt-then-MAC) ──
        mac_input = iv + ciphertext
        if not verify_hmac(mac_input, self.mac_key, received_tag, self.key_dir):
            raise ValueError("[!] HMAC verification FAILED — message tampered!")

        # Decrypt
        return aes_cbc_decrypt(ciphertext, self.enc_key, iv, self.key_dir)

    def _receive_loop(self):
        """Receive encrypted frames, verify MAC, decrypt, and display."""
        while True:
            try:
                frame = recv_framed(self.conn)
                if not frame:
                    print("\n[Peer disconnected]")
                    break
                plaintext = self._verify_and_decrypt(frame)
                message   = plaintext.decode()
                if message.strip().lower() == "exit":
                    print("\n[Peer exited]")
                    break
                print(f"\n[Peer]: {message}")
            except ValueError as e:
                print(f"\n{e}")
                break
            except Exception as e:
                print(f"\n[Receive error]: {e}")
                break

    def _send_loop(self):
        """Read user input, encrypt, MAC, and send."""
        while True:
            try:
                msg = input("You: ").strip()
                if not msg:
                    continue
                frame = self._encrypt_and_mac(msg.encode())
                send_framed(self.conn, frame)
                if msg.lower() == "exit":
                    break
            except Exception as e:
                print(f"[Send error]: {e}")
                break

        self.conn.close()
        self.sock.close()
        print("[*] Connection closed.")
