"""
alt_run_client.py — Launch the client peer.

Usage:
    python3 alt_run_client.py client <server_ip>
    python3 alt_run_client.py client <server_ip> --proxy socks5://<proxy_host>:<proxy_port>

The --proxy flag lets you tunnel through a SOCKS5 proxy when you are behind a
restrictive firewall (requires: pip install PySocks).
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


def apply_socks5_proxy(proxy_url):
    """
    Monkey-patch the socket module to route connections through a SOCKS5 proxy.
    Requires PySocks:  pip install PySocks
    """
    try:
        import socks  # PySocks
    except ImportError:
        print("[ERROR] PySocks is not installed. Run:  pip install PySocks")
        sys.exit(1)

    # Parse  socks5://host:port
    url = proxy_url.replace("socks5://", "")
    host, port_str = url.rsplit(":", 1)
    port = int(port_str)

    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket
    print(f"[*] SOCKS5 proxy configured: {host}:{port}")


def main():
    if len(sys.argv) < 3 or sys.argv[1].lower() != "client":
        print("Usage: python3 alt_run_client.py client <server_ip> [--proxy socks5://host:port]")
        sys.exit(1)

    server_ip = sys.argv[2]

    # Optional SOCKS5 proxy
    if "--proxy" in sys.argv:
        idx = sys.argv.index("--proxy")
        if idx + 1 >= len(sys.argv):
            print("[ERROR] --proxy requires an argument, e.g. socks5://127.0.0.1:1080")
            sys.exit(1)
        apply_socks5_proxy(sys.argv[idx + 1])

    local_ip, hostname = get_local_ip()
    print(f"[INFO] Local IP   : {local_ip}")
    print(f"[INFO] Hostname   : {hostname}")
    print(f"[INFO] Server IP  : {server_ip}")

    peer = Peer(is_server=False, host=server_ip)
    peer.start()


if __name__ == "__main__":
    main()
