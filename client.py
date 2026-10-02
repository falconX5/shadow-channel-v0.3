from __future__ import annotations
import argparse, asyncio, json, time
from datetime import datetime
from pathlib import Path
import websockets
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from shadowchannel.crypto import Identity,b64d,decode_room_secret,encrypt_and_sign,fingerprint,generate_room_secret,verify_and_decrypt
C=Console(); DEFAULT=Path.home()/".shadowchannel"/"identity.json"
class Client:
    def __init__(self,a):
        self.a=a; self.key=decode_room_secret(a.secret); self.id=Identity.load_or_create(a.identity); self.users=[]; self.role="unknown"
    async def recv(self,ws):
        async for raw in ws:
            p=json.loads(raw); t=p.get("type")
            if t=="access_denied": C.print(f"[bold red]ACCESS DENIED:[/bold red] {p.get('reason')}"); await ws.close(); return
            if t=="system" and p.get("event")=="connected": self.role=p.get("role","user"); C.print(f"[green]✓[/green] connected as {self.role}")
            elif t=="users": self.users=p.get("users",[])
            elif t=="presence": C.print(f"[dim]{p.get('name')} {p.get('event')} ({p.get('role','user')})[/dim]")
            elif t=="message":
                try:
                    txt=verify_and_decrypt(p,self.key); ts=datetime.fromtimestamp(int(p["timestamp"])).strftime("%H:%M:%S")
                    C.print(f"[dim][{ts}][/dim] [cyan]{p.get('sender_name')}[/cyan] {txt}")
                except Exception as e: C.print("[red]Rejected:[/red]",e)
    def show_users(self):
        t=Table(title=f"USERS IN #{self.a.room}"); t.add_column("Name"); t.add_column("Role"); t.add_column("Fingerprint")
        for u in self.users:
            t.add_row(u.get("name","?"),u.get("role","user"),fingerprint(b64d(u["public_key"])))
        C.print(t)
    async def input(self,ws):
        while True:
            txt=(await asyncio.to_thread(Prompt.ask,f"[green]{self.a.name}@{self.a.room}[/green]")).strip()
            if txt=="/quit": await ws.close(); return
            if txt=="/users": await ws.send(json.dumps({"type":"users_request"})); await asyncio.sleep(.15); self.show_users(); continue
            if txt=="/role": C.print("Role:",self.role); continue
            if txt=="/fingerprint": C.print("Fingerprint:",self.id.fingerprint); continue
            if txt=="/whoami": C.print(Panel.fit(f"Name: {self.a.name}\nRole: {self.role}\nPublic key: {self.id.public_key_b64}\nFingerprint: {self.id.fingerprint}")); continue
            if not txt: continue
            p=encrypt_and_sign(self.id,self.key,self.a.room,self.a.name,int(time.time()),txt); await ws.send(json.dumps(p))
            C.print(f"[green]{self.a.name}[/green] {txt}")
    async def run(self):
        C.print(Panel.fit(f"SHADOW CHANNEL v0.2\nuser: {self.a.name}\nroom: #{self.a.room}\nfingerprint: {self.id.fingerprint}"))
        async with websockets.connect(self.a.server) as ws:
            await ws.send(json.dumps({"type":"hello","room":self.a.room,"name":self.a.name,"public_key":self.id.public_key_b64}))
            r=asyncio.create_task(self.recv(ws)); i=asyncio.create_task(self.input(ws))
            done,pending=await asyncio.wait({r,i},return_when=asyncio.FIRST_COMPLETED)
            for x in pending: x.cancel()
if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--server",default="ws://127.0.0.1:8765"); p.add_argument("--room",default="ops"); p.add_argument("--secret"); p.add_argument("--name",default="ghost"); p.add_argument("--identity",default=str(DEFAULT)); p.add_argument("--create-secret",action="store_true"); p.add_argument("--show-identity",action="store_true")
    a=p.parse_args()
    if a.create_secret: C.print(Panel.fit(generate_room_secret(),title="ROOM SECRET")); raise SystemExit
    ident=Identity.load_or_create(a.identity)
    if a.show_identity:
        C.print(Panel.fit(f"Name: {a.name}\nPublic key: {ident.public_key_b64}\nFingerprint: {ident.fingerprint}\nIdentity file: {Path(a.identity).expanduser()}",title="PERSISTENT IDENTITY")); raise SystemExit
    if not a.secret: p.error("--secret is required")
    try: asyncio.run(Client(a).run())
    except KeyboardInterrupt: pass
