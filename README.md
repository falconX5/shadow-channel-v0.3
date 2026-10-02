# Shadow Channel v0.3

Adds integrated ngrok support to the v0.2 admin/allowlist build.

## Features

- End-to-end encrypted room messages
- Persistent Ed25519 identities
- Admin identity
- Approved-user allowlist
- Unapproved users rejected before joining
- Signed messages
- Optional automatic ngrok TCP tunnel
- Remote users can connect from different networks

## Install Python dependencies

Linux/Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## ngrok requirement

ngrok itself is an external executable and must be installed on the relay machine.

Verify:

```bash
ngrok version
```

If your ngrok account requires an auth token, configure it once:

```bash
ngrok config add-authtoken YOUR_TOKEN
```

## Start relay + ngrok automatically

```bash
python3 server.py --host 0.0.0.0 --port 8765 --ngrok
```

The server prints something like:

```text
NGROK TUNNEL
------------
Public TCP URL : tcp://0.tcp.ngrok.io:15432
Client WS URL  : ws://0.tcp.ngrok.io:15432

Remote clients should use:
  --server ws://0.tcp.ngrok.io:15432
```

Remote client:

```bash
python3 client.py \
  --server ws://0.tcp.ngrok.io:15432 \
  --room dark-room \
  --secret "ROOM_SECRET" \
  --name raven
```

## Custom ngrok executable path

If ngrok is not in PATH:

```bash
python3 server.py \
  --host 0.0.0.0 \
  --port 8765 \
  --ngrok \
  --ngrok-bin "/path/to/ngrok"
```

Windows example:

```powershell
python server.py `
  --host 0.0.0.0 `
  --port 8765 `
  --ngrok `
  --ngrok-bin "C:\Tools\ngrok.exe"
```

## Admin setup

Create admin identity:

```bash
python3 client.py \
  --identity admin.identity.json \
  --show-identity \
  --name admin
```

Configure admin public key:

```bash
python3 access_admin.py set-admin \
  --public-key "ADMIN_PUBLIC_KEY"
```

## Approve a user

User creates their identity:

```bash
python3 client.py --show-identity --name raven
```

Admin adds their public key:

```bash
python3 access_admin.py add \
  --name raven \
  --public-key "USER_PUBLIC_KEY"
```

List users:

```bash
python3 access_admin.py list
```

Remove user:

```bash
python3 access_admin.py remove --name raven
```

## Security note

The room payload is encrypted before reaching the relay, but `ws://` over an
ngrok TCP tunnel is not the same as a fully TLS-terminated `wss://` deployment.
For a production system, use TLS, hardened enrollment/revocation, rate limiting,
and a professionally reviewed forward-secret messaging protocol.
