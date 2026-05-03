"""
alt_run_client.py — Launch the client peer.

Usage:
    python3 alt_run_client.py client <server_ip>
"""

import sys
import socket
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


def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() != "client":
        print("Usage: python3 alt_run_client.py client <server_ip>")
        sys.exit(1)

    server_ip = sys.argv[2]

    local_ip, hostname = get_local_ip()
    print(f"[INFO] Local IP   : {local_ip}")
    print(f"[INFO] Hostname   : {hostname}")
    print(f"[INFO] Server IP  : {server_ip}:5050")

    peer = Peer(is_server=False, host=server_ip)
    peer.start()


if __name__ == "__main__":
    main()
