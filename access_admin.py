import argparse, json
from pathlib import Path
from shadowchannel.crypto import b64d, fingerprint
F=Path("access.json")
def load():
    return json.loads(F.read_text()) if F.exists() else {"admin_public_key":"","allowed_users":[]}
def save(d): F.write_text(json.dumps(d,indent=2))
def fp(k): return fingerprint(b64d(k))
p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
a=s.add_parser("set-admin"); a.add_argument("--public-key",required=True)
a=s.add_parser("add"); a.add_argument("--name",required=True); a.add_argument("--public-key",required=True)
a=s.add_parser("remove"); a.add_argument("--name",required=True)
s.add_parser("list")
args=p.parse_args(); d=load()
if args.cmd=="set-admin":
    d["admin_public_key"]=args.public_key.strip(); save(d); print("Admin configured:",fp(d["admin_public_key"]))
elif args.cmd=="add":
    d["allowed_users"]=[u for u in d["allowed_users"] if u.get("name")!=args.name and u.get("public_key")!=args.public_key]
    d["allowed_users"].append({"name":args.name,"public_key":args.public_key.strip()}); save(d)
    print("Approved:",args.name,fp(args.public_key.strip()))
elif args.cmd=="remove":
    d["allowed_users"]=[u for u in d["allowed_users"] if u.get("name")!=args.name]; save(d); print("Removed:",args.name)
else:
    print("ADMIN:", fp(d["admin_public_key"]) if d.get("admin_public_key") else "not configured")
    print("USERS:")
    for u in d["allowed_users"]: print(" ",u["name"],fp(u["public_key"]))
