"""
alt_run_server.py — Launch the server peer.

Usage:
    python3 alt_run_server.py [server]

The server binds to 0.0.0.0 (all interfaces) so that clients from any
network — including different Wi-Fi networks / public IPs — can connect
directly using this machine's public IP address and port 5001.

To find your public IP run:
    curl -s ifconfig.me
or:
    curl -s https://api.ipify.org
"""

import sys
import socket
import urllib.request
from peer_openssl import Peer


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0], socket.gethostname()
    except Exception:
        return "127.0.0.1", "unknown"
    finally:
        s.close()


def get_public_ip():
    """Try to fetch the public IP from a simple API (requires internet)."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as r:
            return r.read().decode()
    except Exception:
        return "(unavailable — check ifconfig.me manually)"


def main():
    local_ip, hostname = get_local_ip()
    public_ip = get_public_ip()

    print(f"[INFO] Hostname   : {hostname}")
    print(f"[INFO] Local IP   : {local_ip}")
    print(f"[INFO] Public IP  : {public_ip}")
    print(f"[INFO] Port       : 5001")
    print()
    print("[INFO] Share your PUBLIC IP with the client:")
    print(f"         python3 alt_run_client.py client {public_ip}")
    print()

    # Bind to all interfaces so both LAN and WAN clients can connect.
    # Port 5050: unprivileged (no sudo needed), generally open on college LAN.
    peer = Peer(is_server=True, host="0.0.0.0", port=5050)
    peer.start()


if __name__ == "__main__":
    main()
