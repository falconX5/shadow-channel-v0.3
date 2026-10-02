from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import time
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import websockets
from websockets.asyncio.server import ServerConnection

F = Path("access.json")
ROOMS = defaultdict(set)
CLIENTS = {}


@dataclass
class State:
    name: str
    room: str
    public_key: str
    role: str


def access():
    return json.loads(F.read_text()) if F.exists() else {
        "admin_public_key": "",
        "allowed_users": []
    }


def authorize(name, key):
    d = access()

    if d.get("admin_public_key") and key == d["admin_public_key"]:
        return True, "admin"

    for u in d.get("allowed_users", []):
        if u.get("public_key") == key:
            if u.get("name") == name:
                return True, "user"
            return False, "name-mismatch"

    return False, "denied"


async def broadcast(room, payload, exclude=None):
    raw = json.dumps(payload)

    for ws in list(ROOMS.get(room, set())):
        if ws is exclude:
            continue
        try:
            await ws.send(raw)
        except Exception:
            pass


async def users(room):
    await broadcast(
        room,
        {
            "type": "users",
            "room": room,
            "users": [
                {
                    "name": CLIENTS[w].name,
                    "public_key": CLIENTS[w].public_key,
                    "role": CLIENTS[w].role,
                }
                for w in ROOMS.get(room, set())
                if w in CLIENTS
            ],
        },
    )


async def handler(ws: ServerConnection):
    st = None

    try:
        hello = json.loads(await asyncio.wait_for(ws.recv(), 15))

        if hello.get("type") != "hello":
            return

        name = str(hello.get("name", "")).strip()
        room = str(hello.get("room", "")).strip()
        key = str(hello.get("public_key", "")).strip()

        ok, role = authorize(name, key)

        if not ok:
            reason = (
                "identity is not approved"
                if role == "denied"
                else "approved key/name mismatch"
            )

            await ws.send(
                json.dumps({
                    "type": "access_denied",
                    "reason": reason,
                })
            )
            await ws.close(code=4003, reason="access denied")
            print(f"[DENIED] {name}")
            return

        st = State(name, room, key, role)
        CLIENTS[ws] = st
        ROOMS[room].add(ws)

        print(f"[+] {name} ({role}) joined #{room}")

        await ws.send(
            json.dumps({
                "type": "system",
                "event": "connected",
                "room": room,
                "role": role,
            })
        )

        await broadcast(
            room,
            {
                "type": "presence",
                "event": "join",
                "name": name,
                "public_key": key,
                "role": role,
            },
            exclude=ws,
        )

        await users(room)

        async for raw in ws:
            p = json.loads(raw)

            if (
                p.get("type") == "message"
                and p.get("room") == room
                and p.get("sender_key") == key
                and p.get("sender_name") == name
            ):
                await broadcast(room, p, exclude=ws)

            elif p.get("type") == "users_request":
                await users(room)

    except (websockets.ConnectionClosed, asyncio.TimeoutError):
        pass

    finally:
        if st:
            CLIENTS.pop(ws, None)
            ROOMS[st.room].discard(ws)

            await broadcast(
                st.room,
                {
                    "type": "presence",
                    "event": "leave",
                    "name": st.name,
                    "public_key": st.public_key,
                    "role": st.role,
                },
            )

            await users(st.room)


def find_ngrok_binary(custom=None):
    if custom:
        p = Path(custom).expanduser()
        if p.exists():
            return str(p)
        raise FileNotFoundError(f"ngrok executable not found: {p}")

    found = shutil.which("ngrok")
    if found:
        return found

    raise FileNotFoundError(
        "ngrok was not found in PATH. Install ngrok first or use --ngrok-bin."
    )


def get_ngrok_tcp_url(timeout=20):
    deadline = time.time() + timeout
    url = "http://127.0.0.1:4040/api/tunnels"

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.loads(response.read().decode("utf-8"))

            for tunnel in data.get("tunnels", []):
                public_url = tunnel.get("public_url", "")
                if public_url.startswith("tcp://"):
                    return public_url

        except Exception:
            pass

        time.sleep(0.5)

    return None


def start_ngrok(port, ngrok_bin=None):
    binary = find_ngrok_binary(ngrok_bin)

    print("[*] Starting ngrok TCP tunnel...")

    process = subprocess.Popen(
        [binary, "tcp", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    public_url = get_ngrok_tcp_url()

    if not public_url:
        process.terminate()
        raise RuntimeError(
            "ngrok started but no TCP public URL was detected. "
            "Check ngrok authentication/configuration."
        )

    ws_url = "ws://" + public_url.removeprefix("tcp://")

    print()
    print("NGROK TUNNEL")
    print("------------")
    print("Public TCP URL :", public_url)
    print("Client WS URL  :", ws_url)
    print()
    print("Remote clients should use:")
    print(f"  --server {ws_url}")
    print()

    return process, ws_url


async def run(host, port):
    d = access()

    print()
    print("SHADOW CHANNEL RELAY v0.3")
    print("-------------------------")
    print(f"Listening on ws://{host}:{port}")
    print("Access control   : ENABLED")
    print("Admin configured :", "YES" if d.get("admin_public_key") else "NO")
    print("Approved users   :", len(d.get("allowed_users", [])))
    print("Message storage  : disabled")
    print("Room keys        : never sent to relay")
    print()

    async with websockets.serve(
        handler,
        host,
        port,
        max_size=1024 * 1024,
        ping_interval=20,
        ping_timeout=20,
    ):
        await asyncio.Future()


def main():
    p = argparse.ArgumentParser(
        description="Shadow Channel relay server"
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument(
        "--ngrok",
        action="store_true",
        help="Automatically start an ngrok TCP tunnel.",
    )
    p.add_argument(
        "--ngrok-bin",
        help="Optional path to the ngrok executable.",
    )

    a = p.parse_args()

    ngrok_process = None

    try:
        if a.ngrok:
            if a.host == "127.0.0.1":
                # localhost is sufficient for ngrok, but 0.0.0.0 also allows LAN use.
                pass

            ngrok_process, _ = start_ngrok(
                a.port,
                a.ngrok_bin,
            )

        asyncio.run(run(a.host, a.port))

    except KeyboardInterrupt:
        print("\nRelay stopped.")

    except Exception as exc:
        print(f"\n[ERROR] {exc}")

    finally:
        if ngrok_process and ngrok_process.poll() is None:
            print("[*] Stopping ngrok...")
            ngrok_process.terminate()
            try:
                ngrok_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ngrok_process.kill()


if __name__ == "__main__":
    main()
