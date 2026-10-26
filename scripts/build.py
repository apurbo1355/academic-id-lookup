"""Build an encrypted lookup index: no raw email/phone/name stored in output.
Each (type,value) -> PBKDF2 -> 16B lookup key + 32B AES-GCM key that encrypts [{name,id}]."""
import csv, json, os, re, sys, hashlib, base64
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 150000
src, out = sys.argv[1], sys.argv[2]
salt = os.urandom(16)

def n_email(s): return s.strip().lower()
def n_phone(s):
    d = re.sub(r"\D", "", s)
    if d.startswith("880"): d = d[3:]
    d = d.lstrip("0")
    return d if len(d) == 10 else None
def n_name(s): return " ".join(re.sub(r"[^a-z0-9]+", " ", s.lower()).split())

groups = defaultdict(list)
rows = list(csv.reader(open(src, encoding="utf-8")))[1:]
count = 0
for r in rows:
    if not r or not r[0].strip(): continue
    rid, email, name = r[0].strip(), r[1], r[2]
    disp = re.sub(r"[`]+", "", name).strip()
    rec = {"name": disp, "id": rid}
    count += 1
    keys = set()
    if email.strip():
        e = n_email(email); keys.add("e:" + e)
        if e.startswith("."): keys.add("e:" + e.lstrip("."))
    if n_name(name): keys.add("n:" + n_name(name))
    for k in keys:
        if rec not in groups[k]: groups[k].append(rec)

index = {}
for k, recs in groups.items():
    dk = hashlib.pbkdf2_hmac("sha256", k.encode(), salt, ITER, 48)
    look, key = dk[:16].hex(), dk[16:]
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(recs, ensure_ascii=False).encode(), None)
    index[look] = base64.b64encode(iv + ct).decode()

json.dump({"v": 1, "iter": ITER, "salt": base64.b64encode(salt).decode(), "d": index},
          open(out, "w"), separators=(",", ":"))
dups = {k: v for k, v in groups.items() if len(v) > 1}
print("people:", count, "keys:", len(index), "shared keys:", dups)
