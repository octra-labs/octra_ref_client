#!/usr/bin/env python3

import json, base64, sys, os, time
import requests
from nacl.signing import SigningKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cli import PvacClient

wallet_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet.json")
if not os.path.exists(wallet_path):
    print("wallet.json not found")
    sys.exit(1)

with open(wallet_path) as f:
    d = json.load(f)

addr = d["addr"]
priv = d["priv"]
rpc_url = d.get("rpc", "https://devnet.octra.com")
if not rpc_url.endswith("/rpc"):
    rpc_url += "/rpc"

print(f"address: {addr}")
print(f"rpc: {rpc_url}")

sk = SigningKey(base64.b64decode(priv))
pub = base64.b64encode(sk.verify_key.encode()).decode()

pvac = PvacClient(priv)

print("serializing pubkey...")
pk_bytes = pvac.serialize_pubkey()
pk_b64 = base64.b64encode(pk_bytes).decode()
print(f"pubkey size: {len(pk_bytes)} bytes ({len(pk_b64)} b64)")

reg_msg = f"register_pvac|{addr}".encode()
reg_sig = base64.b64encode(sk.sign(reg_msg).signature).decode()

print("sending registration...")
t0 = time.time()
try:
    r = requests.post(rpc_url, json={
        "jsonrpc": "2.0",
        "method": "octra_registerPvacPubkey",
        "params": [addr, pk_b64, reg_sig, pub],
        "id": 1
    }, timeout=120)
    dt = time.time() - t0
    print(f"response ({dt:.1f}s): {r.text[:300]}")

    j = r.json()
    if "result" in j:
        print("\npvac pubkey registered!")
    elif "error" in j:
        print(f"\nerror: {j['error']}")
except Exception as e:
    print(f"\nfailed: {e}")
