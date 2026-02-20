#!/usr/bin/env python3
"""
lambda0xe
2026
octra labs 
for ref only
"""


import json, base64, hashlib, time, sys, re, os, shutil, asyncio, aiohttp, threading, ctypes, struct
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import nacl.signing
from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ssl
import signal


def extract_error(j, fallback="unknown error"):
    if not j:
        return fallback
    err = j.get('error', fallback)
    if isinstance(err, dict):
        etype = err.get('type', 'unknown')
        reason = err.get('reason', '')
        return f"{etype}: {reason}" if reason else etype
    return str(err)



class PvacClient:
    HFHE_PREFIX = "hfhe_v1|"
    RP_PREFIX = "rp_v1|"
    ZP_PREFIX = "zp_v1|"
    ZKZP_PREFIX = "zkzp_v2|"

    def __init__(self, wallet_priv_b64):
        _dir = os.path.dirname(os.path.abspath(__file__))
        _ext = 'dylib' if sys.platform == 'darwin' else 'so'
        lib_paths = [
            os.path.join(_dir, 'pvac', 'build', f'libpvac.{_ext}'),
            os.path.join(_dir, f'libpvac.{_ext}'),
            f'libpvac.{_ext}',
        ]
        lib = None
        for p in lib_paths:
            p = os.path.abspath(p)
            if os.path.exists(p):
                try:
                    lib = ctypes.CDLL(p)
                    break
                except OSError:
                    continue
        if lib is None:
            raise RuntimeError(f"libpvac.{_ext} not found. Run: cd pvac && make")
        self._lib = lib
        self._setup_ffi()

        raw_priv = base64.b64decode(wallet_priv_b64)
        seed = (ctypes.c_uint8 * 32)(*raw_priv[:32])
        prm = self._lib.pvac_default_params()
        pk_ptr = ctypes.c_void_p()
        sk_ptr = ctypes.c_void_p()
        self._lib.pvac_keygen_from_seed(prm, seed, ctypes.byref(pk_ptr), ctypes.byref(sk_ptr))
        self._lib.pvac_free_params(prm)
        self.pk = pk_ptr
        self.sk = sk_ptr

    def _setup_ffi(self):
        L = self._lib

        # params
        L.pvac_default_params.restype = ctypes.c_void_p
        L.pvac_keygen_from_seed.argtypes = [ctypes.c_void_p, ctypes.c_uint8 * 32,
                                             ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p)]

    
        L.pvac_enc_value_seeded.restype = ctypes.c_void_p
        L.pvac_enc_value_seeded.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint8 * 32]
        L.pvac_enc_zero_seeded.restype = ctypes.c_void_p
        L.pvac_enc_zero_seeded.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8 * 32]
        L.pvac_dec_value.restype = ctypes.c_uint64
        L.pvac_dec_value.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        L.pvac_dec_value_fp.restype = None
        L.pvac_dec_value_fp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
        L.pvac_enc_value_fp_seeded.restype = ctypes.c_void_p
        L.pvac_enc_value_fp_seeded.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8 * 32]

        # arithmetic
        L.pvac_ct_add.restype = ctypes.c_void_p
        L.pvac_ct_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        L.pvac_ct_sub.restype = ctypes.c_void_p
        L.pvac_ct_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        L.pvac_ct_scale.restype = ctypes.c_void_p
        L.pvac_ct_scale.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64]
        L.pvac_ct_add_const.restype = ctypes.c_void_p
        L.pvac_ct_add_const.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64]
        L.pvac_ct_sub_const.restype = ctypes.c_void_p
        L.pvac_ct_sub_const.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]

        # commit
        L.pvac_commit_ct.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8 * 32]

        # range proof
        L.pvac_make_range_proof.restype = ctypes.c_void_p
        L.pvac_make_range_proof.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
        L.pvac_verify_range.restype = ctypes.c_int
        L.pvac_verify_range.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        # zero proof (Bulletproofs R1CS circuit)
        L.pvac_make_zero_proof.restype = ctypes.c_void_p
        L.pvac_make_zero_proof.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        L.pvac_verify_zero.restype = ctypes.c_int
        L.pvac_verify_zero.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        # bound zero proof
        L.pvac_make_zero_proof_bound.restype = ctypes.c_void_p
        L.pvac_make_zero_proof_bound.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.c_uint64, ctypes.c_uint8 * 32]
        L.pvac_verify_zero_bound.restype = ctypes.c_int
        L.pvac_verify_zero_bound.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_uint8 * 32]

        L.pvac_pedersen_commit.restype = None
        L.pvac_pedersen_commit.argtypes = [ctypes.c_uint64, ctypes.c_uint8 * 32, ctypes.c_uint8 * 32]

        L.pvac_serialize_cipher.restype = ctypes.POINTER(ctypes.c_uint8)
        L.pvac_serialize_cipher.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        L.pvac_deserialize_cipher.restype = ctypes.c_void_p
        L.pvac_deserialize_cipher.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.pvac_serialize_pubkey.restype = ctypes.POINTER(ctypes.c_uint8)
        L.pvac_serialize_pubkey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]

        L.pvac_serialize_range_proof.restype = ctypes.POINTER(ctypes.c_uint8)
        L.pvac_serialize_range_proof.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        L.pvac_deserialize_range_proof.restype = ctypes.c_void_p
        L.pvac_deserialize_range_proof.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.pvac_serialize_zero_proof.restype = ctypes.POINTER(ctypes.c_uint8)
        L.pvac_serialize_zero_proof.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        L.pvac_deserialize_zero_proof.restype = ctypes.c_void_p
        L.pvac_deserialize_zero_proof.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.pvac_free_params.argtypes = [ctypes.c_void_p]
        L.pvac_free_cipher.argtypes = [ctypes.c_void_p]
        L.pvac_free_bytes.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        L.pvac_free_zero_proof.argtypes = [ctypes.c_void_p]
        L.pvac_free_range_proof.argtypes = [ctypes.c_void_p]



    @staticmethod
    def make_seed(tx_hash, epoch_id, purpose):
        buf = f"OCTRA_FHE_SEED_V1|{tx_hash}|{epoch_id}|{purpose}"
        return hashlib.sha256(buf.encode()).digest()



    def encrypt(self, value, seed_bytes):
        seed_arr = (ctypes.c_uint8 * 32)(*seed_bytes[:32])
        return self._lib.pvac_enc_value_seeded(self.pk, self.sk, ctypes.c_uint64(value), seed_arr)

    def encrypt_zero(self, seed_bytes):
        seed_arr = (ctypes.c_uint8 * 32)(*seed_bytes[:32])
        return self._lib.pvac_enc_zero_seeded(self.pk, self.sk, seed_arr)

    def decrypt(self, ct_handle):
        return int(self._lib.pvac_dec_value(self.pk, self.sk, ct_handle))

    def decrypt_fp(self, ct_handle):
        """Decrypt returning full Fp (lo, hi) — no truncation."""
        lo = ctypes.c_uint64(0)
        hi = ctypes.c_uint64(0)
        self._lib.pvac_dec_value_fp(self.pk, self.sk, ct_handle,
                                     ctypes.byref(lo), ctypes.byref(hi))
        return (lo.value, hi.value)

    def encrypt_fp(self, lo, hi, seed_bytes):
        """Encrypt a full Fp value (lo, hi) — for RecryptOp."""
        seed_arr = (ctypes.c_uint8 * 32)(*seed_bytes[:32])
        return self._lib.pvac_enc_value_fp_seeded(
            self.pk, self.sk, ctypes.c_uint64(lo), ctypes.c_uint64(hi), seed_arr)


    def ct_add(self, ct_a, ct_b):
        return self._lib.pvac_ct_add(self.pk, ct_a, ct_b)

    def ct_sub(self, ct_a, ct_b):
        return self._lib.pvac_ct_sub(self.pk, ct_a, ct_b)

    def ct_sub_const(self, ct, value):
        """ct_sub_const(pk, ct, k) → ct - k in Fp. pk-only, no sk needed."""
        return self._lib.pvac_ct_sub_const(self.pk, ct, ctypes.c_uint64(value))

    def ct_scale(self, ct, scalar):
        return self._lib.pvac_ct_scale(self.pk, ct, ctypes.c_int64(scalar))


    def commit(self, ct_handle):
        """commit_ct(pk, ct) → 32 bytes."""
        out = (ctypes.c_uint8 * 32)()
        self._lib.pvac_commit_ct(self.pk, ct_handle, out)
        return bytes(out)


    def make_range_proof(self, ct_handle, value):
        """Prove ct encrypts value ∈ [0, 2^64).  Requires sk (client only)."""
        return self._lib.pvac_make_range_proof(self.pk, self.sk, ct_handle, ctypes.c_uint64(value))

    def verify_range(self, ct_handle, rp_handle):
        """Verify range proof (pk only, no sk needed)."""
        return bool(self._lib.pvac_verify_range(self.pk, ct_handle, rp_handle))

    def make_zero_proof(self, ct_handle):
        """Prove ct encrypts 0 using Bulletproofs R1CS circuit. Requires sk (client only)."""
        return self._lib.pvac_make_zero_proof(self.pk, self.sk, ct_handle)

    def verify_zero(self, ct_handle, zp_handle):
        """Verify zero proof (pk only, no sk needed)."""
        return bool(self._lib.pvac_verify_zero(self.pk, ct_handle, zp_handle))


    def make_zero_proof_bound(self, ct_handle, amount, blinding_bytes):
        """Prove ct encrypts `amount` with Pedersen binding. Requires sk (client only).
        blinding_bytes: 32-byte random blinding factor."""
        blind_arr = (ctypes.c_uint8 * 32)(*blinding_bytes[:32])
        return self._lib.pvac_make_zero_proof_bound(self.pk, self.sk, ct_handle,
                                                     ctypes.c_uint64(amount), blind_arr)

    def pedersen_commit(self, amount, blinding_bytes):
        """Compute Pedersen commitment: amount * G + blinding * H → 32 bytes."""
        blind_arr = (ctypes.c_uint8 * 32)(*blinding_bytes[:32])
        out = (ctypes.c_uint8 * 32)()
        self._lib.pvac_pedersen_commit(ctypes.c_uint64(amount), blind_arr, out)
        return bytes(out)


    def _serialize_ptr(self, func, handle):
        sz = ctypes.c_size_t()
        ptr = func(handle, ctypes.byref(sz))
        data = bytes(ptr[i] for i in range(sz.value))
        self._lib.pvac_free_bytes(ptr)
        return data

    def serialize_cipher(self, ct_handle):
        return self._serialize_ptr(self._lib.pvac_serialize_cipher, ct_handle)

    def deserialize_cipher(self, data):
        arr = (ctypes.c_uint8 * len(data))(*data)
        result = self._lib.pvac_deserialize_cipher(arr, ctypes.c_size_t(len(data)))
        if not result:
            return None
        return result

    def serialize_pubkey(self):
        return self._serialize_ptr(self._lib.pvac_serialize_pubkey, self.pk)

    def serialize_range_proof(self, rp_handle):
        return self._serialize_ptr(self._lib.pvac_serialize_range_proof, rp_handle)

    def deserialize_range_proof(self, data):
        arr = (ctypes.c_uint8 * len(data))(*data)
        return self._lib.pvac_deserialize_range_proof(arr, ctypes.c_size_t(len(data)))

    def serialize_zero_proof(self, zp_handle):
        return self._serialize_ptr(self._lib.pvac_serialize_zero_proof, zp_handle)

    def deserialize_zero_proof(self, data):
        arr = (ctypes.c_uint8 * len(data))(*data)
        return self._lib.pvac_deserialize_zero_proof(arr, ctypes.c_size_t(len(data)))

    def encode_cipher(self, ct_handle):
        raw = self.serialize_cipher(ct_handle)
        return self.HFHE_PREFIX + base64.b64encode(raw).decode()

    def decode_cipher(self, cipher_str):
        if not cipher_str.startswith(self.HFHE_PREFIX):
            return None
        b64 = cipher_str[len(self.HFHE_PREFIX):]
        raw = base64.b64decode(b64)
        return self.deserialize_cipher(raw)

    def encode_range_proof(self, rp_handle):
        raw = self.serialize_range_proof(rp_handle)
        return self.RP_PREFIX + base64.b64encode(raw).decode()

    def encode_zero_proof(self, zp_handle):
        raw = self.serialize_zero_proof(zp_handle)
        return self.ZKZP_PREFIX + base64.b64encode(raw).decode()

    def free_cipher(self, ct_handle):
        if ct_handle:
            self._lib.pvac_free_cipher(ct_handle)

    def free_range_proof(self, rp_handle):
        if rp_handle:
            self._lib.pvac_free_range_proof(rp_handle)

    def free_zero_proof(self, zp_handle):
        if zp_handle:
            self._lib.pvac_free_zero_proof(zp_handle)

    def get_balance(self, cipher_str):
        """Decrypt an encoded cipher string to an integer value.
           Returns the correct value even when Fp.hi != 0 (negative in field).
           p = 2^127 - 1.  If value > p/2, treat as negative: -(p - value)."""
        if not cipher_str or cipher_str == "0" or cipher_str == "":
            return 0
        ct = self.decode_cipher(cipher_str)
        if ct is None:
            return 0
        lo, hi = self.decrypt_fp(ct)
        self.free_cipher(ct)
        if hi == 0:
            return lo
        # Full Fp value: val = hi * 2^64 + lo,  p = 2^127 - 1
        p = (1 << 127) - 1
        val = (hi << 64) | lo
        if val > p // 2:
            # Negative in field: true value = -(p - val)
            return -(p - val)
        return val



STEALTH_TAG_DOMAIN = "OCTRA_STEALTH_TAG_V1"

def derive_view_keypair(priv_b64):
    raw_seed = base64.b64decode(priv_b64)
    signing_key = nacl.signing.SigningKey(raw_seed)
    curve25519_sk = signing_key.to_curve25519_private_key()
    view_sk = bytes(curve25519_sk)
    view_pub = bytes(signing_key.verify_key.to_curve25519_public_key())
    return view_sk, view_pub

def ecdh_shared_secret(our_sk, their_pub):
    raw_shared = crypto_scalarmult(our_sk, their_pub)
    return hashlib.sha256(raw_shared).digest()

def compute_stealth_tag(shared_secret):
    h = hashlib.sha256(shared_secret + STEALTH_TAG_DOMAIN.encode()).digest()
    return h[:16]

def stealth_tag_to_hex(tag):
    return tag.hex()

def stealth_tag_of_hex(hex_str):
    return bytes.fromhex(hex_str)

CLAIM_SECRET_DOMAIN = "OCTRA_CLAIM_SECRET_V1"
CLAIM_BIND_DOMAIN = "OCTRA_CLAIM_BIND_V1"

def compute_claim_secret(shared_secret):
    return hashlib.sha256(shared_secret + CLAIM_SECRET_DOMAIN.encode()).digest()

def compute_claim_pub(claim_secret, recipient_addr):
    return hashlib.sha256(claim_secret + recipient_addr.encode() + CLAIM_BIND_DOMAIN.encode()).digest()


def encrypt_stealth_amount(shared_secret, amount, blinding):
    """AES-GCM encrypt amount + blinding for receiver.
    Payload: uint64_le(amount) || blinding(32 bytes) → 40 bytes plaintext."""
    key = shared_secret[:32]
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    payload = int(amount).to_bytes(8, "little") + blinding
    ct = aesgcm.encrypt(nonce, payload, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_stealth_amount(shared_secret, enc_b64):
    """Decrypt stealth amount envelope → (amount, blinding_bytes)."""
    raw = base64.b64decode(enc_b64)
    nonce = raw[:12]
    ct = raw[12:]
    key = shared_secret[:32]
    aesgcm = AESGCM(key)
    plain = aesgcm.decrypt(nonce, ct, None)
    amount = int.from_bytes(plain[:8], "little")
    blinding = plain[8:]
    return amount, blinding



BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data):
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(BASE58_ALPHABET[r])
    for i, b in enumerate(data):
        if b != 0:
            return "1" * i + "".join(reversed(result))
    return "1" * len(data)

def _wallet_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "wallet.json")

def create_wallet():
    for _ in range(100):
        new_sk = nacl.signing.SigningKey.generate()
        pub_bytes = new_sk.verify_key.encode()
        h = hashlib.sha256(pub_bytes).digest()
        new_addr = "oct" + base58_encode(h)
        if len(new_addr) == 47:
            wp = _wallet_path()
            wallet_data = {
                "priv": base64.b64encode(bytes(new_sk)).decode(),
                "addr": new_addr,
                "rpc": "https://devnet.octra.com"
            }
            old_umask = os.umask(0o077)
            with open(wp, 'w') as f:
                json.dump(wallet_data, f, indent=2)
            os.umask(old_umask)
            os.chmod(wp, 0o600)
            return wp, new_addr
    raise RuntimeError("failed to generate valid address")


c = {'r': '\033[0m', 'b': '\033[34m', 'c': '\033[36m', 'g': '\033[32m', 'y': '\033[33m', 'R': '\033[31m', 'B': '\033[1m', 'bg': '\033[44m', 'bgr': '\033[41m', 'bgg': '\033[42m', 'w': '\033[37m'}

priv, addr, rpc = None, None, None
pvac = None
sk, pub = None, None
pending_encrypted_debits = 0
b58 = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
μ = 1_000_000
h = []
cb, cn, lu, lh = None, None, 0, 0
session = None
executor = ThreadPoolExecutor(max_workers=1)
stop_flag = threading.Event()
spinner_frames = ['-', '\\', '|', '/']
spinner_idx = 0

def cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def sz():
    return shutil.get_terminal_size((80, 25))

def at(x, y, t, cl=''):
    print(f"\033[{y};{x}H{c['bg']}{cl}{t}{c['bg']}", end='')

def inp(x, y):
    print(f"\033[{y};{x}H", end='', flush=True)
    return input()

async def ainp(x, y):
    print(f"\033[{y};{x}H", end='', flush=True)
    try:
        return await asyncio.get_event_loop().run_in_executor(executor, input)
    except:
        stop_flag.set()
        return ''

def wait():
    cr = sz()
    msg = "press enter to continue..."
    msg_len = len(msg)
    y_pos = cr[1] - 2
    x_pos = max(2, (cr[0] - msg_len) // 2)
    at(x_pos, y_pos, msg, c['y'])
    print(f"\033[{y_pos};{x_pos + msg_len}H", end='', flush=True)
    input()

async def awaitkey():
    cr = sz()
    msg = "press enter to continue..."
    msg_len = len(msg)
    y_pos = cr[1] - 2
    x_pos = max(2, (cr[0] - msg_len) // 2)
    at(x_pos, y_pos, msg, c['y'])
    print(f"\033[{y_pos};{x_pos + msg_len}H{c['bg']}", end='', flush=True)
    try:
        await asyncio.get_event_loop().run_in_executor(executor, input)
    except:
        stop_flag.set()

def ld():
    global priv, addr, rpc, sk, pub
    try:
        wallet_path = _wallet_path()
        if not os.path.exists(wallet_path):
            wp, new_addr = create_wallet()
            print(f"new wallet created: {new_addr}")
            print(f"saved to: {wp}")
            time.sleep(2)
            wallet_path = wp

        with open(wallet_path, 'r') as f:
            d = json.load(f)

        priv = d.get('priv')
        addr = d.get('addr')
        rpc = d.get('rpc', 'https://devnet.octra.com')

        if not priv or not addr:
            return False

        if not rpc.startswith('https://') and 'localhost' not in rpc:
            print(f"{c['R']}WARNING: Using insecure HTTP connection!{c['r']}")
            time.sleep(2)

        sk = nacl.signing.SigningKey(base64.b64decode(priv))
        pub = base64.b64encode(sk.verify_key.encode()).decode()

        return True
    except:
        return False

def fill():
    cr = sz()
    print(f"{c['bg']}", end='')
    for _ in range(cr[1]):
        print(" " * cr[0])
    print("\033[H", end='')

def box(x, y, w, h, t=""):
    print(f"\033[{y};{x}H{c['bg']}{c['w']}┌{'─' * (w - 2)}┐{c['bg']}")
    if t:
        print(f"\033[{y};{x}H{c['bg']}{c['w']}┤ {c['B']}{t} {c['w']}├{c['bg']}")
    for i in range(1, h - 1):
        print(f"\033[{y + i};{x}H{c['bg']}{c['w']}│{' ' * (w - 2)}│{c['bg']}")
    print(f"\033[{y + h - 1};{x}H{c['bg']}{c['w']}└{'─' * (w - 2)}┘{c['bg']}")

async def spin_animation(x, y, msg):
    global spinner_idx
    try:
        while True:
            at(x, y, f"{c['c']}{spinner_frames[spinner_idx]} {msg}", c['c'])
            spinner_idx = (spinner_idx + 1) % len(spinner_frames)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        at(x, y, " " * (len(msg) + 3), "")



_rpc_id = 0
async def rpc_call(method, params=None, t=10):
    global session, _rpc_id
    if not session:
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context, force_close=True)
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=t),
            connector=connector,
            json_serialize=json.dumps
        )
    _rpc_id += 1
    payload = {"jsonrpc": "2.0", "method": method, "params": params or [], "id": _rpc_id}
    try:
        async with session.post(f"{rpc}/rpc", json=payload) as resp:
            j = json.loads(await resp.text())
            if "result" in j:
                return True, j["result"]
            elif "error" in j:
                e = j["error"]
                return False, e.get("message", "rpc error")
            return False, "unknown rpc response"
    except asyncio.TimeoutError:
        return False, "timeout"
    except Exception as e:
        return False, str(e)

async def st():
   global cb, cn, lu, pending_encrypted_debits
   now = time.time()

   if cb is not None and (now - lu) < 30:
       try:
           ok_p, pool = await rpc_call("pool_view", [], 5)
           if ok_p and isinstance(pool, dict):
               our = [tx for tx in pool.get("transactions", []) if tx.get("from") == addr]
               if our:
                   staging_nonce = max(int(tx.get("nonce", 0)) for tx in our)
                   cn = max(cn, staging_nonce)
       except:
           pass
       return cn, cb

   results = await asyncio.gather(
       rpc_call("octra_balance", [addr]),
       rpc_call("pool_view", [], 5),
       return_exceptions=True
   )

   r_bal = results[0] if not isinstance(results[0], Exception) else (False, str(results[0]))
   r_pool = results[1] if not isinstance(results[1], Exception) else (False, str(results[1]))

   ok_b, bal = r_bal
   ok_p, pool = r_pool

   if ok_b and isinstance(bal, dict):
       cn = int(bal.get("nonce", 0))
       cb = float(bal.get("balance", 0))
       lu = now
       pending_encrypted_debits = 0
       if ok_p and isinstance(pool, dict):
           our = [tx for tx in pool.get("transactions", []) if tx.get("from") == addr]
           if our:
               cn = max(cn, max(int(tx.get("nonce", 0)) for tx in our))
   elif not ok_b:
       cn, cb, lu = 0, 0.0, now
   return cn, cb


async def get_encrypted_balance():
    msg = f"octra_encryptedBalance|{addr}".encode()
    signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
    sig = signing_key.sign(msg).signature
    sig_b64 = base64.b64encode(sig).decode()
    ok, result = await rpc_call("octra_encryptedBalance", [addr, sig_b64, pub])
    if ok and isinstance(result, dict):
        cipher = result.get("cipher", "0")
        if pvac and cipher and cipher != "0":
            try:
                dec = pvac.get_balance(cipher)
                return {"cipher": cipher, "decrypted": dec, "formatted": f"{dec / μ:.6f} OCT"}
            except:
                return {"cipher": cipher, "decrypted": 0, "formatted": "0.000000 OCT"}
        return {"cipher": "0", "decrypted": 0, "formatted": "0.000000 OCT"}
    return None

async def ensure_pvac_registered():
    if not pvac:
        return
    signing_key = nacl.signing.SigningKey(base64.b64decode(priv))

    # Always ensure view pubkey is registered (needed for stealth receives).
    # Check if our view pubkey is available on the node:
    ok_vp, vp_result = await rpc_call("octra_viewPubkey", [addr])
    need_pubkey = not (ok_vp and isinstance(vp_result, dict) and vp_result.get("view_pubkey"))

    # Check if PVAC pubkey is registered:
    need_pvac = True
    ok, result = await rpc_call("octra_encryptedCipher", [addr])
    if ok and isinstance(result, dict) and result.get("cipher_type") == "hfhe_v1":
        need_pvac = False
    else:
        msg = f"octra_encryptedBalance|{addr}".encode()
        sig = signing_key.sign(msg).signature
        sig_b64 = base64.b64encode(sig).decode()
        ok2, result2 = await rpc_call("octra_encryptedBalance", [addr, sig_b64, pub])
        if ok2 and isinstance(result2, dict) and result2.get("has_pvac_pubkey"):
            need_pvac = False

    if need_pvac or need_pubkey:
        try:
            pk_b64 = base64.b64encode(pvac.serialize_pubkey()).decode()
            reg_msg = f"register_pvac|{addr}".encode()
            reg_sig = signing_key.sign(reg_msg).signature
            reg_sig_b64 = base64.b64encode(reg_sig).decode()
            await rpc_call("octra_registerPvacPubkey", [addr, pk_b64, reg_sig_b64, pub])
        except:
            pass

async def admin_reset_enc_balance(target_addr):
    signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
    msg = f"octra_adminResetEncBalance|{target_addr}".encode()
    sig = signing_key.sign(msg).signature
    sig_b64 = base64.b64encode(sig).decode()
    ok, result = await rpc_call("octra_adminResetEncBalance", [target_addr, sig_b64, pub])
    return ok, result


async def gh():
    global h, lh
    now = time.time()
    if now - lh < 60 and h:
        return
    ok, j = await rpc_call("octra_account", [addr, 20])
    if not ok:
        if not h:
            h.clear()
            lh = now
        return

    refs = j.get("recent_txs", [])
    if not refs:
        h.clear()
        lh = now
        return

    tx_hashes = [ref["hash"] for ref in refs]
    tx_results = await asyncio.gather(
        *[rpc_call("octra_transaction", [txh], 5) for txh in tx_hashes],
        return_exceptions=True
    )

    nh = []
    for ref, result in zip(refs, tx_results):
        if isinstance(result, Exception):
            continue
        ok2, p = result
        if not ok2 or not isinstance(p, dict):
            continue
        tx_hash = ref["hash"]
        ii = p.get("to") == addr
        op_type = p.get("op_type", "")
        ar = p.get("amount_raw", p.get("amount", "0"))
        a = float(ar) if "." in str(ar) else int(ar) / μ
        msg = p.get("message")
        if msg and msg == "null":
            msg = None
        tx_type = "in" if ii else "out"
        if op_type in ("decrypt", "stealth"):
            tx_type = "out"
        nh.append({
            "time": datetime.fromtimestamp(p.get("timestamp", 0)),
            "hash": tx_hash,
            "amt": a,
            "to": p.get("to") if not ii else p.get("from"),
            "type": tx_type,
            "ok": True,
            "nonce": p.get("nonce", 0),
            "epoch": ref.get("epoch", 0),
            "msg": msg
        })

    api_hashes = {tx["hash"] for tx in nh}
    pending_local = [tx for tx in h if tx["hash"] not in api_hashes and tx.get("epoch", 0) == 0]
    h[:] = sorted(nh + pending_local, key=lambda x: x["time"], reverse=True)[:50]
    lh = now

def mk(to, a, n, msg=None, op_type=None, encrypted_data=None):
    tx = {
        "from": addr,
        "to_": to,
        "amount": str(int(a * μ)),
        "nonce": int(n),
        "ou": str(10_000 if a < 1000 else 30_000),
        "timestamp": time.time()
    }
    if msg:
        tx["message"] = msg
    sign_fields = {
        "from": tx["from"], "to_": tx["to_"],
        "amount": tx["amount"], "nonce": tx["nonce"],
        "ou": tx["ou"], "timestamp": tx["timestamp"],
        "op_type": op_type if op_type else "standard",
    }
    if encrypted_data:
        sign_fields["encrypted_data"] = encrypted_data
    bl = json.dumps(sign_fields, separators=(",", ":"))
    sig = base64.b64encode(sk.sign(bl.encode()).signature).decode()
    tx.update(signature=sig, public_key=pub)
    if op_type:
        tx["op_type"] = op_type
    if encrypted_data:
        tx["encrypted_data"] = encrypted_data
    return tx, hashlib.sha256(bl.encode()).hexdigest()

async def snd(tx):
    t0 = time.time()
    ok, result = await rpc_call("octra_submit", [tx])
    dt = time.time() - t0
    if ok:
        return True, result.get("tx_hash", ""), dt, result
    return False, result if isinstance(result, str) else json.dumps(result), dt, None


async def expl(x, y, w, hb):
    box(x, y, w, hb, "wallet explorer")
    n, b = await st()
    await gh()
    bstr = f"{b:.6f} oct" if b is not None else "---"
    at(x + 2, y + 2, f"address: {addr}", c['w'])
    at(x + 2, y + 3, f"balance: {bstr}", c['B'] + c['g'] if b else c['w'])
    at(x + 2, y + 4, f"nonce: {n if n is not None else '---'}", c['w'])
    at(x + 2, y + 5, f"public: {pub[:40]}...", c['w'])

    try:
        ebal = await get_encrypted_balance()
        if ebal:
            at(x + 2, y + 6, f"encrypted: {ebal.get('formatted', '0 OCT')}", c['B'] + c['y'])
    except:
        pass

    ok_p, pool = await rpc_call("pool_view", [], 2)
    sc = len([tx for tx in pool.get("transactions", []) if tx.get("from") == addr]) if ok_p and isinstance(pool, dict) else 0
    at(x + 2, y + 7, f"staging: {f'{sc} pending' if sc else 'none'}", c['y'] if sc else c['w'])
    at(x + 1, y + 8, "─" * (w - 2), c['w'])

    at(x + 2, y + 9, "recent transactions:", c['B'] + c['c'])
    if not h:
        at(x + 2, y + 11, "no transactions yet", c['y'])
    else:
        at(x + 2, y + 11, "time     type  amount      address", c['c'])
        at(x + 2, y + 12, "─" * (w - 4), c['w'])
        seen_hashes = set()
        display_count = 0
        sorted_h = sorted(h, key=lambda x: x['time'], reverse=True)
        for tx in sorted_h:
            if tx['hash'] in seen_hashes:
                continue
            seen_hashes.add(tx['hash'])
            if display_count >= min(len(h), hb - 16):
                break
            is_pending = not tx.get('epoch')
            time_color = c['y'] if is_pending else c['w']
            at(x + 2, y + 13 + display_count, tx['time'].strftime('%H:%M:%S'), time_color)
            at(x + 11, y + 13 + display_count, " in" if tx['type'] == 'in' else "out", c['g'] if tx['type'] == 'in' else c['R'])
            at(x + 16, y + 13 + display_count, f"{float(tx['amt']):>10.6f}", c['w'])
            at(x + 28, y + 13 + display_count, str(tx.get('to', '---')), c['y'])
            if tx.get('msg'):
                at(x + 77, y + 13 + display_count, "msg", c['c'])
            status_text = "pen" if is_pending else f"e{tx.get('epoch', 0)}"
            status_color = c['y'] + c['B'] if is_pending else c['c']
            at(x + w - 6, y + 13 + display_count, status_text, status_color)
            display_count += 1

def menu(x, y, w, h):
    box(x, y, w, h, "commands")
    at(x + 2, y + 2, "[1] send tx", c['w'])
    at(x + 2, y + 3, "[2] refresh", c['w'])
    at(x + 2, y + 4, "[3] multi send", c['w'])
    at(x + 2, y + 5, "[4] encrypt (deposit)", c['y'])
    at(x + 2, y + 6, "[5] decrypt (withdraw)", c['y'])
    at(x + 2, y + 7, "[6] stealth transfer", c['g'])
    at(x + 2, y + 8, "[7] scan & claim", c['g'])
    at(x + 2, y + 9, "[8] export keys", c['w'])
    at(x + 2, y + 10, "[9] clear hist", c['w'])
    at(x + 2, y + 11, "[0] exit", c['w'])
    at(x + 2, y + h - 2, "command: ", c['B'] + c['y'])

async def scr():
    cr = sz()
    cls()
    fill()
    t = f" octra devnet │ PVAC-HFHE (PoC) │ {datetime.now().strftime('%H:%M:%S')} "
    at((cr[0] - len(t)) // 2, 1, t, c['B'] + c['w'])

    sidebar_w = 28
    menu(2, 3, sidebar_w, 15)

    info_y = 19
    box(2, info_y, sidebar_w, 11)
    at(4, info_y + 2, "DEVNET", c['R'])
    at(4, info_y + 3, "", c['y'])
    at(4, info_y + 4, "Core: PVAC-FHE (PoC)", c['g'])
    at(4, info_y + 5, "ZK: R1CS + range proof ", c['g'])
    at(4, info_y + 6, "X25519 ECDH + AES-GCM", c['g'])
    at(4, info_y + 7, "Pedersen commitments", c['g'])
    at(4, info_y + 8, "", c['y'])
    at(4, info_y + 9, "tokens: no value", c['R'])

    explorer_x = sidebar_w + 4
    explorer_w = cr[0] - explorer_x - 2
    await expl(explorer_x, 3, explorer_w, cr[1] - 6)

    at(2, cr[1] - 1, " " * (cr[0] - 4), c['bg'])
    at(2, cr[1] - 1, "ready", c['bgg'] + c['w'])
    return await ainp(12, 16)



async def tx():
    cr = sz()
    cls()
    fill()
    w, hb = 85, 26
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "send transaction")
    at(x + 2, y + 2, "to address: (or [esc] to cancel)", c['y'])
    at(x + 2, y + 3, "─" * (w - 4), c['w'])
    to = await ainp(x + 2, y + 4)
    if not to or to.lower() == 'esc':
        return
    if not b58.match(to):
        at(x + 2, y + 14, "invalid address!", c['bgr'] + c['w'])
        at(x + 2, y + 15, "press enter to go back...", c['y'])
        await ainp(x + 2, y + 16)
        return
    at(x + 2, y + 5, f"to: {to}", c['g'])
    at(x + 2, y + 7, "amount: (or [esc] to cancel)", c['y'])
    at(x + 2, y + 8, "─" * (w - 4), c['w'])
    a = await ainp(x + 2, y + 9)
    if not a or a.lower() == 'esc':
        return
    if not re.match(r"^\d+(\.\d+)?$", a) or float(a) <= 0:
        at(x + 2, y + 14, "invalid amount!", c['bgr'] + c['w'])
        at(x + 2, y + 15, "press enter to go back...", c['y'])
        await ainp(x + 2, y + 16)
        return
    a = float(a)
    at(x + 2, y + 10, f"amount: {a:.6f} oct", c['g'])
    msg = None

    global lu
    lu = 0
    n, b = await st()
    if n is None:
        at(x + 2, y + 12, "failed to get nonce!", c['bgr'] + c['w'])
        at(x + 2, y + 13, "press enter to go back...", c['y'])
        await ainp(x + 2, y + 14)
        return
    if not b or b < a:
        at(x + 2, y + 12, f"insufficient balance ({b:.6f} < {a})", c['bgr'] + c['w'])
        at(x + 2, y + 13, "press enter to go back...", c['y'])
        await ainp(x + 2, y + 14)
        return
    at(x + 2, y + 12, "─" * (w - 4), c['w'])
    at(x + 2, y + 13, f"send {a:.6f} oct", c['B'] + c['g'])
    at(x + 2, y + 14, f"to: {to}", c['g'])
    at(x + 2, y + 15, f"fee: {'0.001' if a < 1000 else '0.003'} oct (nonce: {n + 1})", c['y'])
    at(x + 2, y + 16, "[y]es / [n]o: ", c['B'] + c['y'])
    if (await ainp(x + 16, y + 16)).strip().lower() != 'y':
        return

    spin_task = asyncio.create_task(spin_animation(x + 2, y + 22, "sending transaction"))

    lu = 0
    n, _ = await st()
    t, _ = mk(to, a, n + 1, msg)
    ok, hs, dt, r = await snd(t)

    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass

    if ok:
        for i in range(17, 25):
            at(x + 2, y + i, " " * (w - 4), c['bg'])
        at(x + 2, y + 20, f"transaction accepted", c['bgg'] + c['w'])
        at(x + 2, y + 21, f"hash: {hs}", c['g'])
        finality = r.get('finality', 'pending') if r else 'pending'
        at(x + 2, y + 22, f"time: {dt:.2f}s finality: {finality}", c['w'])
        if r and 'pool_info' in r:
            at(x + 2, y + 23, f"pool: {r['pool_info'].get('total_pool_size', 0)} txs pending", c['y'])
        h.append({
            'time': datetime.now(),
            'hash': hs,
            'amt': a,
            'to': to,
            'type': 'out',
            'ok': True,
            'msg': msg
        })
        lu = 0
    else:
        err_msg = extract_error(r, str(hs))[:w - 10]
        at(x + 2, y + 20, f"transaction failed: {err_msg}"[:w-4], c['bgr'] + c['w'])
        lu = 0
    await awaitkey()

async def multi():
    cr = sz()
    cls()
    fill()
    w, hb = 70, cr[1] - 4
    x = (cr[0] - w) // 2
    y = 2
    box(x, y, w, hb, "multi send")
    at(x + 2, y + 2, "enter recipients (address amount), empty line to finish:", c['y'])
    at(x + 2, y + 3, "type [esc] to cancel", c['c'])
    at(x + 2, y + 4, "─" * (w - 4), c['w'])
    rcp = []
    tot = 0
    ly = y + 5
    while ly < y + hb - 8:
        at(x + 2, ly, f"[{len(rcp) + 1}] ", c['c'])
        l = await ainp(x + 7, ly)
        if l.lower() == 'esc':
            return
        if not l:
            break
        p = l.split()
        if len(p) == 2 and b58.match(p[0]) and re.match(r"^\d+(\.\d+)?$", p[1]) and float(p[1]) > 0:
            a = float(p[1])
            rcp.append((p[0], a))
            tot += a
            at(x + 7, ly, " " * (w - 9), c['bg'])
            at(x + 7, ly, f"{p[0][:20]}..{p[0][-6:]}", c['w'])
            at(x + w - 14, ly, f"+{a:.6f}", c['g'])
            ly += 1
        else:
            at(x + 7, ly, " " * (w - 9), c['bg'])
            at(x + 7, ly, l[:w - 22], c['w'])
            at(x + w - 12, ly, "invalid!", c['R'])
    if not rcp:
        return
    at(x + 2, y + hb - 7, "─" * (w - 4), c['w'])
    at(x + 2, y + hb - 6, f"total: {tot:.6f} oct to {len(rcp)} addresses", c['B'] + c['y'])
    global lu
    lu = 0
    n, b = await st()
    if n is None:
        at(x + 2, y + hb - 5, "failed to get nonce!", c['bgr'] + c['w'])
        at(x + 2, y + hb - 4, "press enter to go back...", c['y'])
        await ainp(x + 2, y + hb - 3)
        return
    if not b or b < tot:
        at(x + 2, y + hb - 5, f"insufficient balance! ({b:.6f} < {tot})", c['bgr'] + c['w'])
        at(x + 2, y + hb - 4, "press enter to go back...", c['y'])
        await ainp(x + 2, y + hb - 3)
        return
    at(x + 2, y + hb - 5, f"send all? [y/n] (starting nonce: {n + 1}): ", c['y'])
    if (await ainp(x + 48, y + hb - 5)).strip().lower() != 'y':
        return

    spin_task = asyncio.create_task(spin_animation(x + 2, y + hb - 3, "sending transactions"))

    batch_size = 5
    batches = [rcp[i:i+batch_size] for i in range(0, len(rcp), batch_size)]
    s_total, f_total = 0, 0

    for batch_idx, batch in enumerate(batches):
        tasks = []
        for i, (to, a) in enumerate(batch):
            idx = batch_idx * batch_size + i
            at(x + 2, y + hb - 2, f"[{idx + 1}/{len(rcp)}] preparing batch...", c['c'])
            t, _ = mk(to, a, n + 1 + idx)
            tasks.append(snd(t))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, (result, (to, a)) in enumerate(zip(results, batch)):
            idx = batch_idx * batch_size + i
            if isinstance(result, Exception):
                f_total += 1
                at(x + 55, y + hb - 2, "fail   ", c['R'])
            else:
                ok, hs, _, _ = result
                if ok:
                    s_total += 1
                    at(x + 55, y + hb - 2, "ok     ", c['g'])
                    h.append({
                        'time': datetime.now(),
                        'hash': hs,
                        'amt': a,
                        'to': to,
                        'type': 'out',
                        'ok': True
                    })
                else:
                    f_total += 1
                    at(x + 55, y + hb - 2, "fail   ", c['R'])
            at(x + 2, y + hb - 2, f"[{idx + 1}/{len(rcp)}] {a:.6f} to {to[:20]}...", c['c'])
            await asyncio.sleep(0.05)

    spin_task.cancel()
    try:
        await spin_task
    except asyncio.CancelledError:
        pass

    lu = 0
    at(x + 2, y + hb - 2, " " * 65, c['bg'])
    at(x + 2, y + hb - 2, f"completed: {s_total} success, {f_total} failed", c['bgg'] + c['w'] if f_total == 0 else c['bgr'] + c['w'])
    await awaitkey()



async def encrypt_deposit_ui():
    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "encrypt balance (deposit)")

    if not pvac:
        at(x + 2, y + 2, "FHE not available (libpvac.dylib missing)", c['R'])
        await awaitkey()
        return

    n, b = await st()
    at(x + 2, y + 2, f"public balance: {b:.6f} oct", c['g'])

    ebal = await get_encrypted_balance()
    ebal_fmt = ebal.get('formatted', '0 OCT') if ebal else '0 OCT'
    at(x + 2, y + 3, f"encrypted balance: {ebal_fmt}", c['y'])
    at(x + 2, y + 4, "─" * (w - 4), c['w'])

    at(x + 2, y + 6, "amount to encrypt:", c['y'])
    amount = await ainp(x + 22, y + 6)
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return

    amount_raw = int(float(amount) * μ)
    if amount_raw > b * μ:
        at(x + 2, y + 8, "insufficient public balance", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 8, f"encrypt {float(amount):.6f} oct? [y/n]:", c['B'])
    if (await ainp(x + 38, y + 8)).strip().lower() != 'y':
        return

    spin_task = asyncio.create_task(spin_animation(x + 2, y + 10, "encrypting (client-side FHE)"))

    try:
        global lu
        lu = 0
        n, _ = await st()
        seed = os.urandom(32)
        ct_delta = pvac.encrypt(amount_raw, seed)
        delta_cipher_str = pvac.encode_cipher(ct_delta)

        commitment_bytes = pvac.commit(ct_delta)
        pvac.free_cipher(ct_delta)
        commitment_b64 = base64.b64encode(commitment_bytes).decode()

        tx_obj = {
            "from": addr,
            "to_": addr,
            "amount": str(amount_raw),
            "nonce": n + 1,
            "ou": "10000",
            "timestamp": time.time(),
            "signature": "",
            "op_type": "encrypt",
            "encrypted_data": delta_cipher_str,
            "message": commitment_b64,
        }
        signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
        sign_fields = {
            "from": tx_obj["from"], "to_": tx_obj["to_"],
            "amount": tx_obj["amount"], "nonce": tx_obj["nonce"],
            "ou": tx_obj["ou"], "timestamp": tx_obj["timestamp"],
            "op_type": tx_obj["op_type"],
        }
        if tx_obj.get("encrypted_data"):
            sign_fields["encrypted_data"] = tx_obj["encrypted_data"]
        if tx_obj.get("message"):
            sign_fields["message"] = tx_obj["message"]
        msg_to_sign = json.dumps(sign_fields, separators=(',', ':'))
        sig = signing_key.sign(msg_to_sign.encode()).signature
        tx_obj["signature"] = base64.b64encode(sig).decode()
        tx_obj["public_key"] = pub

        ok, result = await rpc_call("octra_submit", [tx_obj], 30)
    except Exception as e:
        ok, result = False, str(e)

    spin_task.cancel()
    try: await spin_task
    except asyncio.CancelledError: pass

    if ok:
        at(x + 2, y + 10, f"encrypted {float(amount):.6f} oct (client-side FHE)", c['bgg'] + c['w'])
        tx_hash = result.get('tx_hash', '') if isinstance(result, dict) else ''
        if tx_hash:
            at(x + 2, y + 11, f"tx: {tx_hash[:60]}", c['g'])
        lu = 0
    else:
        at(x + 2, y + 10, f"error: {result}"[:w-4], c['bgr'] + c['w'])
        lu = 0
    await awaitkey()


async def decrypt_withdraw_ui():
    cr = sz()
    cls()
    fill()
    w, hb = 70, 20
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "decrypt balance (withdraw)")

    if not pvac:
        at(x + 2, y + 2, "FHE not available (libpvac.dylib missing)", c['R'])
        await awaitkey()
        return

    ebal = await get_encrypted_balance()
    ebal_dec = int(ebal.get('decrypted', 0)) if ebal else 0
    ebal_fmt = ebal.get('formatted', '0 OCT') if ebal else '0 OCT'
    at(x + 2, y + 2, f"encrypted balance: {ebal_fmt}", c['y'])
    at(x + 2, y + 3, "─" * (w - 4), c['w'])

    if ebal_dec == 0:
        at(x + 2, y + 6, "no encrypted balance to withdraw", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 5, "amount to decrypt:", c['y'])
    amount = await ainp(x + 22, y + 5)
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return

    amount_raw = int(float(amount) * μ)
    if amount_raw > ebal_dec:
        at(x + 2, y + 7, "insufficient encrypted balance", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 7, f"decrypt {float(amount):.6f} oct? [y/n]:", c['B'])
    if (await ainp(x + 38, y + 7)).strip().lower() != 'y':
        return

    spin_task = asyncio.create_task(spin_animation(x + 2, y + 9, "decrypting (client-side)"))

    try:
        seed = os.urandom(32)
        ct_delta = pvac.encrypt(amount_raw, seed)
        delta_cipher_str = pvac.encode_cipher(ct_delta)

        # V4: pure commitment
        commitment_bytes = pvac.commit(ct_delta)
        pvac.free_cipher(ct_delta)
        commitment_b64 = base64.b64encode(commitment_bytes).decode()

        global lu
        lu = 0
        n, _ = await st()
        tx_obj = {
            "from": addr,
            "to_": addr,
            "amount": str(amount_raw),
            "nonce": n + 1,
            "ou": "10000",
            "timestamp": time.time(),
            "signature": "",
            "op_type": "decrypt",
            "encrypted_data": delta_cipher_str,
            "message": commitment_b64,
        }
        signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
        sign_fields = {
            "from": tx_obj["from"], "to_": tx_obj["to_"],
            "amount": tx_obj["amount"], "nonce": tx_obj["nonce"],
            "ou": tx_obj["ou"], "timestamp": tx_obj["timestamp"],
            "op_type": tx_obj["op_type"],
        }
        if tx_obj.get("encrypted_data"):
            sign_fields["encrypted_data"] = tx_obj["encrypted_data"]
        if tx_obj.get("message"):
            sign_fields["message"] = tx_obj["message"]
        msg_to_sign = json.dumps(sign_fields, separators=(',', ':'))
        sig = signing_key.sign(msg_to_sign.encode()).signature
        tx_obj["signature"] = base64.b64encode(sig).decode()
        tx_obj["public_key"] = pub

        ok, result = await rpc_call("octra_submit", [tx_obj], 30)
    except Exception as e:
        ok, result = False, str(e)

    spin_task.cancel()
    try: await spin_task
    except asyncio.CancelledError: pass

    if ok:
        at(x + 2, y + 9, f"decrypted {float(amount):.6f} oct to public", c['bgg'] + c['w'])
        tx_hash = result.get('tx_hash', '') if isinstance(result, dict) else ''
        if tx_hash:
            at(x + 2, y + 10, f"tx: {tx_hash[:60]}", c['g'])
        lu = 0
    else:
        at(x + 2, y + 9, f"error: {result}"[:w-4], c['bgr'] + c['w'])
        lu = 0
    await awaitkey()


async def stealth_transfer_ui():
    global lu, pending_encrypted_debits
    cr = sz()
    cls()
    fill()
    w, hb = 80, 28
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "stealth FHE transfer (hidden recipient + amount)")

    if not pvac:
        at(x + 2, y + 2, "FHE not available (libpvac.dylib missing)", c['R'])
        await awaitkey()
        return

    ebal = await get_encrypted_balance()
    ebal_dec = int(ebal.get('decrypted', 0)) if ebal else 0
    ebal_fmt = ebal.get('formatted', '0 OCT') if ebal else '0 OCT'
    ebal_cipher = ebal.get('cipher', '0') if ebal else '0'
    at(x + 2, y + 2, f"encrypted balance: {ebal_fmt}", c['y'])
    at(x + 2, y + 3, "─" * (w - 4), c['w'])

    if ebal_dec == 0:
        at(x + 2, y + 6, "no encrypted balance — encrypt (deposit) first", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 5, "recipient address:", c['y'])
    to_addr = await ainp(x + 22, y + 5)
    if not to_addr or not b58.match(to_addr):
        at(x + 2, y + 7, "invalid address", c['R'])
        await awaitkey()
        return
    if to_addr == addr:
        at(x + 2, y + 7, "cannot send to yourself", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 7, "fetching recipient's view pubkey...", c['c'])
    ok_vp, vp_result = await rpc_call("octra_viewPubkey", [to_addr])
    if not ok_vp or not isinstance(vp_result, dict) or not vp_result.get("view_pubkey"):
        at(x + 2, y + 7, "recipient has no view pubkey registered             ", c['R'])
        at(x + 2, y + 8, "they need to register first (auto on login)", c['y'])
        await awaitkey()
        return
    recipient_view_pub = base64.b64decode(vp_result["view_pubkey"])
    at(x + 2, y + 7, f"recipient view pubkey: {vp_result['view_pubkey'][:24]}...", c['g'])

    at(x + 2, y + 9, "amount:", c['y'])
    amount = await ainp(x + 10, y + 9)
    if not amount or not re.match(r"^\d+(\.\d+)?$", amount) or float(amount) <= 0:
        return

    amount_raw = int(float(amount) * μ)
    available = ebal_dec - pending_encrypted_debits
    if amount_raw > available:
        at(x + 2, y + 11, f"insufficient encrypted balance (available: {available / μ:.6f})", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 11, "─" * (w - 4), c['w'])
    at(x + 2, y + 12, f"stealth send {float(amount):.6f} oct? [y/n]:", c['B'])
    at(x + 2, y + 13, "dual range proof + Pedersen commitment (fully private)", c['c'])
    if (await ainp(x + 44, y + 12)).strip().lower() != 'y':
        return

    mx = w - 6
    zy = y + 15
    row = [0]
    spin_task = asyncio.create_task(spin_animation(x + 2, zy + 10, "generating proofs — do not close"))

    def zl(txt, color=c['w']):
        at(x + 3, zy + row[0], str(txt)[:mx], color)
        sys.stdout.flush()
        row[0] += 1

    try:
        t_start = time.time()
        zl("[1/6] ECDH x25519", c['B'] + c['c'])
        eph_sk = os.urandom(32)
        eph_pub = crypto_scalarmult_base(eph_sk)
        shared = ecdh_shared_secret(eph_sk, recipient_view_pub)
        zl(f"eph = {base64.b64encode(eph_pub).decode()[:32]}.. shared = {hashlib.sha256(shared).hexdigest()[:16]}..", c['g'])

        zl("[2/6] stealth tag + claim key", c['B'] + c['c'])
        tag = compute_stealth_tag(shared)
        tag_hex = stealth_tag_to_hex(tag)
        claim_secret = compute_claim_secret(shared)
        claim_pub_hex = compute_claim_pub(claim_secret, to_addr).hex()
        zl(f"tag = {tag_hex[:24]}.. claim = {claim_pub_hex[:24]}..", c['g'])

        zl("[3/6] FHE encrypt (PVAC-HFHE)", c['B'] + c['c'])
        r_blind = os.urandom(32)
        enc_amount = encrypt_stealth_amount(shared, amount_raw, r_blind)
        seed = os.urandom(32)
        ct_delta = pvac.encrypt(amount_raw, seed)
        delta_cipher_str = pvac.encode_cipher(ct_delta)
        commitment_bytes = pvac.commit(ct_delta)
        commitment_b64 = base64.b64encode(commitment_bytes).decode()
        zl(f"cipher = {len(delta_cipher_str)}B  PC = {commitment_b64[:28]}..", c['g'])

        t_rp1 = time.time()
        zl("[4/6] range proof (amount) — 65 R1CS circuits...", c['B'] + c['y'])
        rp_delta = pvac.make_range_proof(ct_delta, amount_raw)
        rp_delta_str = pvac.encode_range_proof(rp_delta)
        pvac.free_range_proof(rp_delta)
        dt1 = time.time() - t_rp1
        zl(f"range_proof_1 = {len(rp_delta_str)}B ({dt1:.1f}s)", c['g'])

        t_rp2 = time.time()
        zl("[5/6] range proof (balance) — 65 R1CS circuits...", c['B'] + c['y'])
        current_ct = pvac.decode_cipher(ebal_cipher)
        if current_ct is None:
            raise RuntimeError("cannot decode current encrypted balance")
        new_balance_ct = pvac.ct_sub(current_ct, ct_delta)
        new_balance_val = ebal_dec - amount_raw
        rp_balance = pvac.make_range_proof(new_balance_ct, new_balance_val)
        rp_balance_str = pvac.encode_range_proof(rp_balance)
        pvac.free_range_proof(rp_balance)
        dt2 = time.time() - t_rp2
        zl(f"range_proof_2 = {len(rp_balance_str)}B ({dt2:.1f}s)", c['g'])

        zl("[6/6] Pedersen commitment + AES-GCM envelope", c['B'] + c['c'])
        pvac.free_cipher(ct_delta)
        pvac.free_cipher(current_ct)
        pvac.free_cipher(new_balance_ct)
        amount_commitment = pvac.pedersen_commit(amount_raw, r_blind)
        amount_commitment_b64 = base64.b64encode(amount_commitment).decode()
        dt_total = time.time() - t_start
        zl(f"done! total = {dt_total:.1f}s", c['B'] + c['g'])
        stealth_data = {
            "version": 5,
            "delta_cipher": delta_cipher_str,
            "commitment": commitment_b64,
            "range_proof_delta": rp_delta_str,
            "range_proof_balance": rp_balance_str,
            "eph_pub": base64.b64encode(eph_pub).decode(),
            "stealth_tag": tag_hex,
            "enc_amount": enc_amount,
            "claim_pub": claim_pub_hex,
            "amount_commitment": amount_commitment_b64,
        }

        lu = 0
        n, _ = await st()

        tx_obj = {
            "from": addr,
            "to_": "stealth",
            "amount": "0",
            "nonce": n + 1,
            "ou": "5000",
            "timestamp": time.time(),
            "signature": "",
            "op_type": "stealth",
            "encrypted_data": json.dumps(stealth_data),
        }

        signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
        sign_fields = {
            "from": tx_obj["from"], "to_": tx_obj["to_"],
            "amount": tx_obj["amount"], "nonce": tx_obj["nonce"],
            "ou": tx_obj["ou"], "timestamp": tx_obj["timestamp"],
            "op_type": tx_obj["op_type"],
        }
        if tx_obj.get("encrypted_data"):
            sign_fields["encrypted_data"] = tx_obj["encrypted_data"]
        msg_to_sign = json.dumps(sign_fields, separators=(',', ':'))
        sig = signing_key.sign(msg_to_sign.encode()).signature
        tx_obj["signature"] = base64.b64encode(sig).decode()
        tx_obj["public_key"] = pub

        zl("submitting stealth tx...", c['c'])
        ok, result = await rpc_call("octra_submit", [tx_obj], 60)
    except Exception as e:
        ok, result = False, str(e)

    spin_task.cancel()
    try: await spin_task
    except asyncio.CancelledError: pass

    for rl in range(zy, y + hb - 2):
        at(x + 1, rl, " " * (w - 2), c['w'])

    if ok:
        tx_hash = result.get('tx_hash', 'unknown') if isinstance(result, dict) else str(result)
        at(x + 2, zy, "stealth transfer accepted!", c['bgg'] + c['w'])
        at(x + 2, zy + 1, f"tx: {tx_hash[:w-8]}", c['g'])
        at(x + 2, zy + 2, f"tag: {tag_hex}", c['c'])
        at(x + 2, zy + 3, f"proofs verified by node ({dt_total:.0f}s)", c['c'])
        pending_encrypted_debits += amount_raw
        lu = 0
    else:
        err_msg = result if isinstance(result, str) else str(result)
        at(x + 2, zy, f"error: {err_msg}"[:w-4], c['bgr'] + c['w'])
        lu = 0
    sys.stdout.flush()
    await awaitkey()



async def scan_and_claim_stealth():
    cr = sz()
    cls()
    fill()
    w, hb = 80, 28
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "scan & claim stealth outputs (zero-knowledge)")

    if not pvac:
        at(x + 2, y + 2, "FHE not available", c['R'])
        await awaitkey()
        return

    at(x + 2, y + 2, "scanning stealth outputs...", c['c'])

    view_sk, view_pub = derive_view_keypair(priv)

    ok, result = await rpc_call("octra_stealthOutputs", [0])
    if not ok:
        at(x + 2, y + 4, f"error: {result}", c['R'])
        await awaitkey()
        return

    outputs = result.get("outputs", [])
    at(x + 2, y + 3, f"total outputs: {len(outputs)}", c['w'])

    mine = []
    for out in outputs:
        if out.get("claimed", 0) != 0:
            continue
        try:
            eph_pub = base64.b64decode(out["eph_pub"])
            shared = ecdh_shared_secret(view_sk, eph_pub)
            my_tag = stealth_tag_to_hex(compute_stealth_tag(shared))
            if my_tag == out["stealth_tag"]:
                amt, blinding = decrypt_stealth_amount(shared, out["enc_amount"])
                if blinding is None:
                    continue
                cs = compute_claim_secret(shared)
                mine.append({
                    "id": out["id"],
                    "amount": amt,
                    "tag": my_tag,
                    "epoch": out["epoch_id"],
                    "claim_secret": cs.hex(),
                    "blinding": blinding,
                })
        except:
            continue

    if not mine:
        at(x + 2, y + 5, "no unclaimed stealth outputs found for you", c['y'])
        await awaitkey()
        return

    total_amt = sum(m["amount"] for m in mine)
    at(x + 2, y + 5, f"found {len(mine)} unclaimed outputs, total {total_amt / μ:.6f} oct", c['g'])
    at(x + 2, y + 6, "─" * (w - 4), c['w'])

    for i, m in enumerate(mine[:10]):
        at(x + 2, y + 7 + i, f"  #{m['id']} : {m['amount'] / μ:.6f} oct (epoch {m['epoch']})", c['w'])

    claim_y = y + 7 + min(len(mine), 10) + 1
    at(x + 2, claim_y, f"claim all {len(mine)} outputs (bound proof, private)?", c['B'])
    at(x + 2, claim_y + 1, "[y/n]:", c['y'])
    if (await ainp(x + 9, claim_y + 1)).strip().lower() != 'y':
        return

    claimed = 0
    try:
        global lu
        lu = 0
        n, _ = await st()

        for i, m in enumerate(mine):
            t_cl = time.time()
            at(x + 2, claim_y + 3, f"claiming [{i+1}/{len(mine)}] output #{m['id']}", c['B'] + c['c'])
            at(x + 2, claim_y + 4, f"[1/3] FHE encrypt (PVAC-HFHE)...", c['y'])
            sys.stdout.flush()

            seed = os.urandom(32)
            claim_amount = m["amount"]
            ct_claim = pvac.encrypt(claim_amount, seed)
            claim_cipher_str = pvac.encode_cipher(ct_claim)

            commitment_bytes = pvac.commit(ct_claim)
            commitment_b64 = base64.b64encode(commitment_bytes).decode()
            at(x + 2, claim_y + 5, f"cipher = {len(claim_cipher_str)}B  PC = {commitment_b64[:28]}..", c['g'])
            sys.stdout.flush()

            at(x + 2, claim_y + 4, f"[2/3] Bulletproofs R1CS bound proof (Pedersen)...", c['y'])
            sys.stdout.flush()
            zkp = pvac.make_zero_proof_bound(ct_claim, claim_amount, m["blinding"])
            zero_proof_str = pvac.encode_zero_proof(zkp)
            pvac.free_cipher(ct_claim)
            pvac.free_zero_proof(zkp)
            dt_cl = time.time() - t_cl
            at(x + 2, claim_y + 6, f"bound_proof = {len(zero_proof_str)}B ({dt_cl:.1f}s)", c['g'])
            sys.stdout.flush()

            at(x + 2, claim_y + 4, f"[3/3] submitting claim tx...", c['y'])
            sys.stdout.flush()

            claim_data = {
                "version": 5,
                "output_id": m["id"],
                "claim_cipher": claim_cipher_str,
                "commitment": commitment_b64,
                "claim_secret": m["claim_secret"],
                "zero_proof": zero_proof_str,
            }

            tx_obj = {
                "from": addr,
                "to_": addr,
                "amount": "0",
                "nonce": n + 1,
                "ou": "3000",
                "timestamp": time.time(),
                "signature": "",
                "op_type": "claim",
                "encrypted_data": json.dumps(claim_data),
            }

            signing_key = nacl.signing.SigningKey(base64.b64decode(priv))
            sign_fields = {
                "from": tx_obj["from"], "to_": tx_obj["to_"],
                "amount": tx_obj["amount"], "nonce": tx_obj["nonce"],
                "ou": tx_obj["ou"], "timestamp": tx_obj["timestamp"],
                "op_type": tx_obj["op_type"],
            }
            if tx_obj.get("encrypted_data"):
                sign_fields["encrypted_data"] = tx_obj["encrypted_data"]
            msg_to_sign = json.dumps(sign_fields, separators=(',', ':'))
            sig = signing_key.sign(msg_to_sign.encode()).signature
            tx_obj["signature"] = base64.b64encode(sig).decode()
            tx_obj["public_key"] = pub

            ok_c, result_c = await rpc_call("octra_submit", [tx_obj], 60)
            if not ok_c:
                err_msg = str(result_c)[:50] if result_c else "unknown"
                at(x + 2, claim_y + 4, f"submit failed: {err_msg}", c['R'])
                sys.stdout.flush()
                err_str = result_c if isinstance(result_c, str) else (result_c.get("message", "") if isinstance(result_c, dict) else "")
                if "duplicate" in err_str or "nonce" in err_str:
                    at(x + 2, claim_y + 4, f"waiting for epoch to clear pool...", c['y'])
                    sys.stdout.flush()
                    await asyncio.sleep(15)
                    lu = 0
                    n, _ = await st()
                continue

            tx_hash = result_c.get("tx_hash", "") if isinstance(result_c, dict) else ""

            confirmed = False
            rejected = False
            reject_reason = ""
            for attempt in range(24):
                await asyncio.sleep(5)
                at(x + 2, claim_y + 4, f"waiting for confirmation... {(attempt+1)*5}s", c['y'])
                sys.stdout.flush()
                ok_t, tx_info = await rpc_call("octra_transaction", [tx_hash], 10)
                if ok_t and isinstance(tx_info, dict):
                    if tx_info.get("status") == "confirmed":
                        confirmed = True
                        break
                    elif tx_info.get("status") == "rejected":
                        rejected = True
                        err = tx_info.get("error", {})
                        reject_reason = err.get("reason", "") if isinstance(err, dict) else str(err)
                        break

            if confirmed:
                claimed += 1
                n += 1
                at(x + 2, claim_y + 4, f"output #{m['id']} confirmed (bound proof)!", c['g'])
                sys.stdout.flush()
            elif rejected:
                lu = 0
                n, _ = await st()
                reason_short = reject_reason[:40] if reject_reason else "rejected"
                at(x + 2, claim_y + 4, f"#{m['id']} skipped: {reason_short}", c['y'])
                sys.stdout.flush()
                await asyncio.sleep(1)
            else:
                at(x + 2, claim_y + 4, f"output #{m['id']} timeout, skipping rest", c['R'])
                sys.stdout.flush()
                break

    except Exception as e:
        pass

    at(x + 2, claim_y + 3, f"claimed {claimed}/{len(mine)} outputs (bound proof, private)!",
       c['bgg'] + c['w'] if claimed > 0 else c['bgr'] + c['w'])
    at(x + 2, claim_y + 4, " " * (w - 4), c['w'])
    sys.stdout.flush()
    lu = 0
    await awaitkey()



async def exp():
    cr = sz()
    cls()
    fill()
    w, hb = 70, 15
    x = (cr[0] - w) // 2
    y = (cr[1] - hb) // 2
    box(x, y, w, hb, "export keys")

    at(x + 2, y + 2, "current wallet info:", c['c'])
    at(x + 2, y + 4, "address:", c['c'])
    at(x + 11, y + 4, addr[:32] + "...", c['w'])
    at(x + 2, y + 5, "balance:", c['c'])
    n, b = await st()
    at(x + 11, y + 5, f"{b:.6f} oct" if b is not None else "---", c['g'])

    at(x + 2, y + 7, "export options:", c['y'])
    at(x + 2, y + 8, "[1] show private key", c['w'])
    at(x + 2, y + 9, "[2] save full wallet to file", c['w'])
    at(x + 2, y + 10, "[3] copy address to clipboard", c['w'])
    at(x + 2, y + 11, "[0] cancel", c['w'])
    at(x + 2, y + 13, "choice: ", c['B'] + c['y'])

    choice = await ainp(x + 10, y + 13)
    choice = choice.strip()

    if choice == '1':
        at(x + 2, y + 7, " " * (w - 4), c['bg'])
        at(x + 2, y + 8, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, " " * (w - 4), c['bg'])
        at(x + 2, y + 10, " " * (w - 4), c['bg'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        at(x + 2, y + 13, " " * (w - 4), c['bg'])

        at(x + 2, y + 7, "private key (keep secret!):", c['R'])
        at(x + 2, y + 8, priv[:32], c['R'])
        at(x + 2, y + 9, priv[32:], c['R'])
        at(x + 2, y + 11, "public key:", c['g'])
        at(x + 2, y + 12, pub[:44] + "...", c['g'])
        await awaitkey()

    elif choice == '2':
        fn = f"octra_wallet_{int(time.time())}.json"
        wallet_data = {
            'priv': priv,
            'addr': addr,
            'rpc': rpc
        }
        os.umask(0o077)
        with open(fn, 'w') as f:
            json.dump(wallet_data, f, indent=2)
        os.chmod(fn, 0o600)
        at(x + 2, y + 7, " " * (w - 4), c['bg'])
        at(x + 2, y + 8, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, " " * (w - 4), c['bg'])
        at(x + 2, y + 10, " " * (w - 4), c['bg'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        at(x + 2, y + 13, " " * (w - 4), c['bg'])
        at(x + 2, y + 9, f"saved to {fn}", c['g'])
        at(x + 2, y + 11, "file contains private key - keep safe!", c['R'])
        await awaitkey()

    elif choice == '3':
        try:
            import pyperclip
            pyperclip.copy(addr)
            at(x + 2, y + 7, " " * (w - 4), c['bg'])
            at(x + 2, y + 9, "address copied to clipboard!", c['g'])
        except:
            at(x + 2, y + 7, " " * (w - 4), c['bg'])
            at(x + 2, y + 9, "clipboard not available", c['R'])
        at(x + 2, y + 11, " " * (w - 4), c['bg'])
        await awaitkey()



def signal_handler(sig, frame):
    stop_flag.set()
    if session:
        asyncio.create_task(session.close())
    sys.exit(0)

async def main():
    global session, pvac

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if not ld():
        sys.exit("[!] wallet.json error")
    if not addr:
        sys.exit("[!] wallet.json not configured")

    try:
        pvac = PvacClient(priv)
    except Exception:
        pvac = None

    try:
        await st()
        await gh()

        if pvac:
            await ensure_pvac_registered()

        while not stop_flag.is_set():
            cmd = await scr()

            if cmd == '1':
                await tx()
            elif cmd == '2':
                global lu, lh
                lu = lh = 0
                await st()
                await gh()
            elif cmd == '3':
                await multi()
            elif cmd == '4':
                await encrypt_deposit_ui()
            elif cmd == '5':
                await decrypt_withdraw_ui()
            elif cmd == '6':
                await stealth_transfer_ui()
            elif cmd == '7':
                await scan_and_claim_stealth()
            elif cmd == '8':
                await exp()
            elif cmd == '9':
                h.clear()
                lh = 0
            elif cmd in ['0', 'q', '']:
                break
    except Exception:
        pass
    finally:
        if session:
            await session.close()
        executor.shutdown(wait=False)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        cls()
        print(f"{c['r']}")
        os._exit(0)

"""
it was fucking difficult :D 
"""