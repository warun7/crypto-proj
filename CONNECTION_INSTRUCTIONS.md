# Connection Instructions (Full Crypto Messenger)

This guide explains how to connect the app in two ways:

1. With Tailscale (recommended for different Wi-Fi networks)
2. Without Tailscale (same LAN direct)

These commands assume the OpenSSL full-crypto version:

- Server folder: `Using OppenSSL Library/02 Messenger (Full Crypto)/Server`
- Client folder: `Using OppenSSL Library/02 Messenger (Full Crypto)/Client`

---

## 1) With Tailscale (recommended)

Use this when devices are on different Wi-Fi networks.
Both devices can use different Tailscale accounts as long as they are in the same tailnet.

### Steps

1. Install Tailscale on both devices.
2. Add both devices to the same tailnet.
3. If the devices use different accounts, invite the other account to your tailnet or share the device in Tailscale admin.
4. Start server on server device.
5. Find server Tailscale IP (usually `100.x.x.x`).
6. Start client using that Tailscale IP.

### Server command

```powershell
cd "Using OppenSSL Library/02 Messenger (Full Crypto)/Server"
python .\alt_run_server.py
```

### Client command

```powershell
cd "Using OppenSSL Library/02 Messenger (Full Crypto)/Client"
python .\alt_run_client.py client <TAILSCALE_SERVER_IP>
```

Example:

```powershell
python .\alt_run_client.py client 100.101.102.103
```

### Notes

- No proxy is required when using Tailscale.
- No router port forwarding is required.
- If it fails, test from client:

```powershell
Test-NetConnection <TAILSCALE_SERVER_IP> -Port 5050
```

---

## 2) Without Tailscale

There are two sub-cases.

### 2A) Same Wi-Fi / Same LAN (direct)

Use server local IPv4 from server output.

#### Server

```powershell
cd "Using OppenSSL Library/02 Messenger (Full Crypto)/Server"
python .\alt_run_server.py
```

#### Client

```powershell
cd "Using OppenSSL Library/02 Messenger (Full Crypto)/Client"
python .\alt_run_client.py client <SERVER_LOCAL_IP>
```

Example:

```powershell
python .\alt_run_client.py client 192.168.1.25
```

---

---

## Quick troubleshooting checklist

1. Confirm server is listening on port 5050.
2. Confirm client is using correct host and port.
3. Confirm firewall allows Python/inbound 5050 on server.
4. For Tailscale mode, confirm both devices are connected to same tailnet.
