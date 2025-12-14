import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import List, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# ---------- helpers ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def pad_to(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise ValueError("message too long for fixed padding size")
    return data + b"\x00" * (size - len(data))


def unpad_zeros(data: bytes) -> bytes:
    return data.rstrip(b"\x00")


# ---------- Shamir Secret Sharing over a prime field ----------
# A large prime > 2^256; fine for demo. (Not “provably best”, but works.)
P = (1 << 521) - 1  # Mersenne prime (2^521 - 1)


def _mod_inv(a: int, p: int = P) -> int:
    return pow(a, p - 2, p)


def _eval_poly(coeffs: List[int], x: int, p: int = P) -> int:
    # coeffs: [a0, a1, a2, ...] => a0 + a1*x + a2*x^2 ...
    y = 0
    xp = 1
    for c in coeffs:
        y = (y + c * xp) % p
        xp = (xp * x) % p
    return y


def shamir_split(secret: bytes, n: int = 5, k: int = 3) -> List[Tuple[int, int]]:
    if k < 2 or k > n:
        raise ValueError("bad (n,k)")
    s_int = int.from_bytes(secret, "big")
    if s_int >= P:
        raise ValueError("secret too large for field")

    # random polynomial degree k-1 with constant term = secret
    coeffs = [s_int] + [int.from_bytes(os.urandom(66), "big") % P for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = _eval_poly(coeffs, x)
        shares.append((x, y))
    return shares


def shamir_combine(shares: List[Tuple[int, int]]) -> bytes:
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    # Lagrange interpolation at x=0
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, (xj, _yj) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % P
            den = (den * (xi - xj)) % P
        li = (num * _mod_inv(den)) % P
        secret = (secret + yi * li) % P

    # convert back to 32 bytes (master key size in this demo)
    secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, "big") or b"\x00"
    return secret_bytes.rjust(32, b"\x00")[-32:]


# ---------- RSA blind signature (textbook RSA over SHA-256 digest) ----------
# For lab/demo only. In real systems: use RSA-PSS + proper blind signature scheme.
@dataclass
class RSAPub:
    n: int
    e: int


@dataclass
class RSAPriv:
    n: int
    d: int


def rsa_generate(bits: int = 3072) -> Tuple[RSAPub, RSAPriv]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = priv.private_numbers()
    pubn = numbers.public_numbers.n
    pube = numbers.public_numbers.e
    d = numbers.d
    return RSAPub(pubn, pube), RSAPriv(pubn, d)


def rsa_blind(msg_hash: bytes, pub: RSAPub) -> Tuple[int, int]:
    m = int.from_bytes(msg_hash, "big")
    if m >= pub.n:
        m = m % pub.n
    # choose random r coprime to n
    while True:
        r = int.from_bytes(os.urandom(64), "big") % pub.n
        if r > 1 and os.path.exists("/dev/null"):  # no-op to avoid lint whining
            pass
        if r > 1 and (pow(r, 1, pub.n) != 0) and (hashlib.gcd(r, pub.n) == 1):
            break
    blinded = (m * pow(r, pub.e, pub.n)) % pub.n
    return blinded, r


def rsa_sign_int(blinded: int, priv: RSAPriv) -> int:
    return pow(blinded, priv.d, priv.n)


def rsa_unblind(sig_blinded: int, r: int, pub: RSAPub) -> int:
    rinv = _mod_inv(r, pub.n) if pub.n != P else pow(r, -1, pub.n)  # fallback
    # correct modular inverse for RSA modulus:
    rinv = pow(r, -1, pub.n)
    return (sig_blinded * rinv) % pub.n


def rsa_verify_hash(sig: int, msg_hash: bytes, pub: RSAPub) -> bool:
    m = int.from_bytes(msg_hash, "big") % pub.n
    check = pow(sig, pub.e, pub.n)
    return check == m


# ---------- ECDH P-384 + HKDF to AEAD key ----------
def gen_ec_keypair():
    sk = ec.generate_private_key(ec.SECP384R1())
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return sk, pk_bytes


def ecdh_derive(sk: ec.EllipticCurvePrivateKey, peer_pk_bytes: bytes, context: bytes) -> bytes:
    peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), peer_pk_bytes)
    shared = sk.exchange(ec.ECDH(), peer_pk)
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=b"lab2-ecdh-p384|" + context,
    )
    return hkdf.derive(shared)  # 32-byte session key


def aead_encrypt(plaintext: bytes, key: bytes, aad: bytes, algo: str = "AESGCM") -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    if algo.upper() == "CHACHA20":
        aead = ChaCha20Poly1305(key)
    else:
        aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes, algo: str = "AESGCM") -> bytes:
    if algo.upper() == "CHACHA20":
        aead = ChaCha20Poly1305(key)
    else:
        aead = AESGCM(key)
    return aead.decrypt(nonce, ciphertext, aad)


# ---------- persistence ----------
def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
