# Cryptographic Messenger — Full Crypto Suite (OpenSSL)

## Overview

Extend the existing OpenSSL-based messenger (`01 Messenger (Plain Handshaking)`) by creating a new folder `02 Messenger (Full Crypto)` that adds:

**(a) Authenticated Key Exchange** — ECDH (P-256) for shared secret + ECDSA (P-256) signatures to authenticate the exchanged keys (prevents MITM).

**(b) Authenticated Encryption** — Encrypt-then-MAC paradigm:
  - Encryption: AES-128-CBC (key = first 16 bytes of HKDF-derived key)
  - MAC: HMAC-SHA256 (key = next 32 bytes of HKDF-derived key)

**(c) Proxy support** — Server binds to `0.0.0.0` so anyone on the internet can connect (via the server's public IP or a SOCKS5 proxy). Client accepts a `--proxy` flag for SOCKS5 tunneling.

---

## Proposed Changes

### [NEW] `Using OppenSSL Library/02 Messenger (Full Crypto)/`

New directory mirroring the `01` structure with `Client/` and `Server/` subdirectories.

---

#### [NEW] `openssl_crypto.py` (shared, one copy per role)

Core cryptographic operations using `subprocess` calls to the `openssl` CLI (same pattern as existing code):

| Function | OpenSSL commands used |
|---|---|
| `generate_identity_keypair()` | `ecparam -name prime256v1 -genkey`, `ec -pubout` |
| `sign_data(data, priv_key_path)` | `dgst -sha256 -sign` |
| `verify_signature(data, sig, pub_key_path)` | `dgst -sha256 -verify` |
| `generate_ephemeral_keypair()` | same as existing |
| `perform_ecdh(peer_pub_path)` | `pkeyutl -derive` |
| `derive_keys(shared_secret)` | `dgst -sha256` (HKDF-like KDF: SHA-256 of shared secret + label) |
| `aes_cbc_encrypt(plaintext, key)` | `enc -aes-128-cbc -K -iv` (random IV) |
| `aes_cbc_decrypt(ciphertext, key, iv)` | `enc -d -aes-128-cbc -K -iv` |
| `hmac_sha256(data, key)` | `dgst -sha256 -hmac` |

**Key derivation:** HKDF via `openssl dgst -sha256` chained with labels:
- `enc_key = SHA256(shared_secret || "enc")[:16]`  → 16 bytes for AES-128
- `mac_key = SHA256(shared_secret || "mac")`       → 32 bytes for HMAC-SHA256

**Wire format for each message:**
```
[4-byte IV length][IV][4-byte ciphertext length][ciphertext][32-byte HMAC]
```
MAC covers: `IV || ciphertext` (Encrypt-then-MAC).

---

#### [NEW] `peer_openssl.py` (Client + Server versions)

**Handshake protocol (authenticated key exchange):**

```
Client                              Server
  |-- ECDH_pub + ECDSA_sig(ECDH_pub) -->|   (client sends ephemeral pub + signature)
  |<- ECDH_pub + ECDSA_sig(ECDH_pub) --|   (server replies same)
  Both verify the other's signature
  Both derive: shared_secret = ECDH(my_priv, peer_pub)
  Both derive: enc_key, mac_key = KDF(shared_secret)
```

Identity keys (for signing) are generated fresh per session (ephemeral identity — no PKI needed for a course project). The public key is sent alongside the signature so the other party can verify it.

**Message send/receive:**
- Send: `encrypt(msg, enc_key)` → `(iv, ciphertext)`, compute `HMAC(iv||ciphertext, mac_key)`, send wire frame
- Receive: parse wire frame, verify HMAC first, then decrypt (Encrypt-then-MAC)

---

#### [NEW] `alt_run_server.py`

- Binds to `0.0.0.0` (all interfaces) so it's reachable from any network
- Prints the public IP and local IP for convenience

#### [NEW] `alt_run_client.py`

- Usage: `python3 alt_run_client.py client <server_ip> [--proxy socks5://host:port]`
- When `--proxy` is provided, uses Python's `socks` library (`PySocks`) for SOCKS5 tunneling

---

## Open Questions

> [!IMPORTANT]
> **Identity keys**: Should the identity keypair (for ECDSA signing) be persistent (saved to disk, reused across sessions) or ephemeral (regenerated each run)? For the project, **ephemeral** is simpler and still demonstrates ECDSA correctly — I'll go with ephemeral unless you need persistence.

> [!NOTE]
> **Proxy**: Your prof mentioned public IP access. The simplest approach is to just bind the server to `0.0.0.0` (already handled), and have the client connect to the server's public IP directly. The `--proxy` flag for SOCKS5 is a bonus if you're behind a restrictive firewall. Should I include the SOCKS5 proxy option, or is just binding to `0.0.0.0` sufficient?

---

## Verification Plan

1. Run server: `python3 alt_run_server.py server`
2. Run client (same machine): `python3 alt_run_client.py client 127.0.0.1`
3. Verify handshake logs show: key generation, signature, verification, session key
4. Send messages — verify they are encrypted on the wire (no plaintext visible in logs)
5. Verify HMAC check triggers if data is tampered
