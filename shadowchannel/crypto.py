from __future__ import annotations
import base64, hashlib, json
from dataclasses import dataclass
from pathlib import Path
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as random_bytes

def b64e(data: bytes) -> str: return base64.urlsafe_b64encode(data).decode("ascii")
def b64d(text: str) -> bytes: return base64.urlsafe_b64decode(text.encode("ascii"))
def generate_room_secret() -> str: return b64e(random_bytes(SecretBox.KEY_SIZE))
def decode_room_secret(secret: str) -> bytes:
    key=b64d(secret)
    if len(key)!=SecretBox.KEY_SIZE: raise ValueError("Room secret must decode to 32 bytes.")
    return key
def fingerprint(key: bytes) -> str:
    h=hashlib.sha256(key).hexdigest().upper()
    return ":".join(h[i:i+4] for i in range(0,32,4))

@dataclass
class Identity:
    signing_key: SigningKey
    @classmethod
    def load_or_create(cls, path):
        p=Path(path).expanduser(); p.parent.mkdir(parents=True,exist_ok=True)
        if p.exists():
            d=json.loads(p.read_text()); return cls(SigningKey(b64d(d["signing_seed"])))
        obj=cls(SigningKey.generate())
        p.write_text(json.dumps({
            "version":1,
            "signing_seed":b64e(obj.signing_key.encode()),
            "public_key":obj.public_key_b64,
            "fingerprint":obj.fingerprint
        },indent=2))
        try: p.chmod(0o600)
        except OSError: pass
        return obj
    @property
    def verify_key(self): return self.signing_key.verify_key
    @property
    def public_key_b64(self): return b64e(bytes(self.verify_key))
    @property
    def fingerprint(self): return fingerprint(bytes(self.verify_key))

def canonical_message_bytes(version,msg_type,room,sender_name,sender_key,timestamp,nonce,ciphertext):
    return json.dumps({
        "version":version,"type":msg_type,"room":room,"sender_name":sender_name,
        "sender_key":sender_key,"timestamp":timestamp,"nonce":nonce,"ciphertext":ciphertext
    },sort_keys=True,separators=(",",":")).encode()

def encrypt_and_sign(identity,room_key,room,sender_name,timestamp,plaintext):
    box=SecretBox(room_key); nonce=random_bytes(SecretBox.NONCE_SIZE)
    ct=box.encrypt(plaintext.encode(),nonce).ciphertext
    payload={"version":1,"type":"message","room":room,"sender_name":sender_name,
             "sender_key":identity.public_key_b64,"timestamp":timestamp,
             "nonce":b64e(nonce),"ciphertext":b64e(ct)}
    sig=identity.signing_key.sign(canonical_message_bytes(
        payload["version"],payload["type"],payload["room"],payload["sender_name"],
        payload["sender_key"],payload["timestamp"],payload["nonce"],payload["ciphertext"]
    )).signature
    payload["signature"]=b64e(sig); return payload

def verify_and_decrypt(payload,room_key):
    vk=VerifyKey(b64d(payload["sender_key"]))
    data=canonical_message_bytes(payload["version"],payload["type"],payload["room"],
        payload["sender_name"],payload["sender_key"],payload["timestamp"],
        payload["nonce"],payload["ciphertext"])
    try: vk.verify(data,b64d(payload["signature"]))
    except BadSignatureError as e: raise ValueError("Invalid signature") from e
    try: pt=SecretBox(room_key).decrypt(b64d(payload["ciphertext"]),b64d(payload["nonce"]))
    except CryptoError as e: raise ValueError("Unable to decrypt") from e
    return pt.decode()
