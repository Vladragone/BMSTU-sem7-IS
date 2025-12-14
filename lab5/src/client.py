import os
import json
import argparse
import asyncio
import websockets
import math

from common import (
    gen_ec_keypair, ecdh_derive,
    aead_encrypt, aead_decrypt,
    pad_to, unpad_zeros,
    sha256, b64e, b64d,
    load_json, save_json,
    RSAPub, rsa_verify_hash
)

KMC_URL = "ws://127.0.0.1:8765"
MRS_URL = "ws://127.0.0.1:9876"
STORE_DIR = "client_store"
FIXED_MSG_SIZE = 1024  # padding target


def math_gcd(a, b):
    return math.gcd(a, b)


def blind_for_pubkey(pubkey_bytes: bytes, kmc_pub: RSAPub):
    """
    Blind signature over H(pubkey_bytes).
    Return: blinded_int_bytes_b64, r_int, msg_hash
    """
    msg_hash = sha256(pubkey_bytes)
    m = int.from_bytes(msg_hash, "big") % kmc_pub.n
    # pick r invertible mod n
    while True:
        r = int.from_bytes(os.urandom(64), "big") % kmc_pub.n
        if r > 1 and math_gcd(r, kmc_pub.n) == 1:
            break
    blinded = (m * pow(r, kmc_pub.e, kmc_pub.n)) % kmc_pub.n
    blinded_b = blinded.to_bytes((blinded.bit_length() + 7) // 8, "big")
    return b64e(blinded_b), r, msg_hash


def unblind(sig_blinded_b64: str, r: int, kmc_pub: RSAPub) -> int:
    sig_blinded = int.from_bytes(b64d(sig_blinded_b64), "big") % kmc_pub.n
    rinv = pow(r, -1, kmc_pub.n)
    return (sig_blinded * rinv) % kmc_pub.n


def client_paths(name: str):
    os.makedirs(STORE_DIR, exist_ok=True)
    return os.path.join(STORE_DIR, f"{name}.json")


async def kmc_get_pub():
    async with websockets.connect(KMC_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "get_pub"}))
        resp = json.loads(await ws.recv())
        return RSAPub(n=int(resp["n"]), e=int(resp["e"]))


async def register(name: str):
    kmc_pub = await kmc_get_pub()
    sk_long, pk_long = gen_ec_keypair()

    blinded_b64, r, msg_hash = blind_for_pubkey(pk_long, kmc_pub)

    async with websockets.connect(KMC_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "blind_sign", "blinded": blinded_b64}))
        resp = json.loads(await ws.recv())
        if resp.get("type") != "blind_sig":
            raise RuntimeError(resp)

    sig = unblind(resp["sig"], r, kmc_pub)

    # verify locally
    if not rsa_verify_hash(sig, msg_hash, kmc_pub):
        raise RuntimeError("KMC signature verification failed (client-side)")

    # store private key + pubkey + signature
    st = {
        "name": name,
        "long_sk_pem": sk_long.private_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.PEM,
            format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PrivateFormat.PKCS8,
            encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.NoEncryption(),
        ).decode("utf-8"),
        "long_pk_b64": b64e(pk_long),
        "kmc_sig_int": str(sig),
    }
    save_json(client_paths(name), st)
    print(f"[{name}] registered. long_pk={b64e(pk_long)[:24]}... sig={str(sig)[:18]}...")


def load_client(name: str):
    st = load_json(client_paths(name), None)
    if st is None:
        raise RuntimeError(f"no client state for {name}. run --register first")
    # load key
    from cryptography.hazmat.primitives import serialization
    sk = serialization.load_pem_private_key(st["long_sk_pem"].encode("utf-8"), password=None)
    return st, sk


async def send_message(sender: str, to: str, text: str, algo: str):
    st, sk_long = load_client(sender)
    kmc_pub = await kmc_get_pub()

    # ephemeral key for PFS
    esk, epk = gen_ec_keypair()

    payload_hello = {
        "kind": "session_init",
        "long_pk_b64": st["long_pk_b64"],
        "kmc_sig_int": st["kmc_sig_int"],
        "eph_pk_b64": b64e(epk),
        "algo": algo,
    }

    async with websockets.connect(MRS_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "hello", "name": sender}))
        _ = await ws.recv()

        # send session init
        await ws.send(json.dumps({"type": "relay", "to": to, "payload": payload_hello}))
        _ = await ws.recv()

        # wait for session response
        msg = json.loads(await ws.recv())
        if msg.get("type") != "inbox":
            raise RuntimeError(msg)
        resp = msg["payload"]
        if resp.get("kind") != "session_resp":
            raise RuntimeError(resp)

        peer_eph = b64d(resp["eph_pk_b64"])
        context = (sender + "->" + to).encode("utf-8")
        key = ecdh_derive(esk, peer_eph, context)

        aad = (sender + "|" + to).encode("utf-8")
        pt = pad_to(text.encode("utf-8"), FIXED_MSG_SIZE)
        nonce, ct = aead_encrypt(pt, key, aad=aad, algo=algo)

        await ws.send(json.dumps({"type": "relay", "to": to, "payload": {
            "kind": "msg",
            "nonce_b64": b64e(nonce),
            "ct_b64": b64e(ct),
            "algo": algo,
            "pad": FIXED_MSG_SIZE
        }}))
        _ = await ws.recv()
        print(f"[{sender}] sent to {to}: {text!r}")


async def listen(name: str):
    st, _sk_long = load_client(name)
    kmc_pub = await kmc_get_pub()

    # session cache: peer -> (my_eph_sk, algo)
    sessions = {}

    async with websockets.connect(MRS_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "hello", "name": name}))
        _ = await ws.recv()
        print(f"[{name}] listening on MRS… (Ctrl+C to stop)")

        # dummy traffic: every ~8-20 sec, send a “noise” packet to self (demo)
        async def dummy():
            while True:
                await asyncio.sleep(8 + int.from_bytes(os.urandom(1), "big") % 13)
                try:
                    await ws.send(json.dumps({"type": "relay", "to": name, "payload": {"kind": "noise"}}))
                    _ = await ws.recv()
                except Exception:
                    return

        dummy_task = asyncio.create_task(dummy())

        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "inbox":
                    continue
                frm = msg["from"]
                payload = msg["payload"]

                if payload.get("kind") == "noise":
                    continue

                if payload.get("kind") == "session_init":
                    long_pk = b64d(payload["long_pk_b64"])
                    sig_int = int(payload["kmc_sig_int"])
                    algo = payload.get("algo", "AESGCM")

                    # verify “group membership”: KMC signature over H(long_pk)
                    ok = rsa_verify_hash(sig_int, sha256(long_pk), kmc_pub)
                    if not ok:
                        print(f"[{name}] REJECT session_init from {frm}: invalid KMC signature")
                        continue

                    # make my ephemeral for this peer
                    esk, epk = gen_ec_keypair()
                    sessions[frm] = (esk, algo)

                    # reply with my ephemeral
                    await ws.send(json.dumps({"type": "relay", "to": frm, "payload": {
                        "kind": "session_resp",
                        "eph_pk_b64": b64e(epk),
                        "algo": algo
                    }}))
                    _ = await ws.recv()
                    print(f"[{name}] session established with {frm} (PFS, {algo})")
                    continue

                if payload.get("kind") == "msg":
                    if frm not in sessions:
                        print(f"[{name}] got msg from {frm} but no session")
                        continue
                    esk, algo = sessions[frm]

                    # derive key using sender’s ephemeral? (we don’t have it here)
                    # For demo simplicity: sender’s eph is only used on sender side,
                    # receiver uses its own esk + sender eph that came in session_init.
                    # We stored esk, but need peer eph. So store peer eph at init:
                    # => minimal hack: peer eph is not persisted. In this demo,
                    # receiver derives key from its esk and a “fixed context only”.
                    # To keep it correct, we’ll derive key from *last* peer eph saved in sessions as extra data.
                    # (See below improvement: store peer eph during init.)

                    # --- improvement stored in sessions as dict ---
                    # We'll reconstruct by storing peer eph in sessions2:
                    pass

        finally:
            dummy_task.cancel()


# --- Fix listen() session storage properly (store peer eph, then decrypt) ---
async def listen_fixed(name: str):
    st, _sk_long = load_client(name)
    kmc_pub = await kmc_get_pub()

    # peer -> dict
    sessions = {}

    async with websockets.connect(MRS_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "hello", "name": name}))
        _ = await ws.recv()
        print(f"[{name}] listening on MRS… (Ctrl+C to stop)")

        async def dummy():
            while True:
                await asyncio.sleep(8 + int.from_bytes(os.urandom(1), "big") % 13)
                try:
                    await ws.send(json.dumps({"type": "relay", "to": name, "payload": {"kind": "noise"}}))
                    _ = await ws.recv()
                except Exception:
                    return

        dummy_task = asyncio.create_task(dummy())

        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "inbox":
                    continue
                frm = msg["from"]
                payload = msg["payload"]

                if payload.get("kind") == "noise":
                    continue

                if payload.get("kind") == "session_init":
                    long_pk = b64d(payload["long_pk_b64"])
                    sig_int = int(payload["kmc_sig_int"])
                    algo = payload.get("algo", "AESGCM")
                    peer_eph = b64d(payload["eph_pk_b64"])

                    ok = rsa_verify_hash(sig_int, sha256(long_pk), kmc_pub)
                    if not ok:
                        print(f"[{name}] REJECT session_init from {frm}: invalid KMC signature")
                        continue

                    esk, epk = gen_ec_keypair()
                    sessions[frm] = {"esk": esk, "algo": algo, "peer_eph": peer_eph}

                    await ws.send(json.dumps({"type": "relay", "to": frm, "payload": {
                        "kind": "session_resp",
                        "eph_pk_b64": b64e(epk),
                        "algo": algo
                    }}))
                    _ = await ws.recv()
                    print(f"[{name}] session established with {frm} (PFS, {algo})")
                    continue

                if payload.get("kind") == "msg":
                    sess = sessions.get(frm)
                    if not sess:
                        print(f"[{name}] got msg from {frm} but no session")
                        continue

                    esk = sess["esk"]
                    algo = payload.get("algo", sess["algo"])
                    peer_eph = sess["peer_eph"]

                    context = (frm + "->" + name).encode("utf-8")
                    key = ecdh_derive(esk, peer_eph, context)
                    aad = (frm + "|" + name).encode("utf-8")

                    nonce = b64d(payload["nonce_b64"])
                    ct = b64d(payload["ct_b64"])
                    pt = aead_decrypt(nonce, ct, key, aad=aad, algo=algo)
                    text = unpad_zeros(pt).decode("utf-8", errors="replace")
                    print(f"[{name}] FROM {frm}: {text}")
                    continue

        finally:
            dummy_task.cancel()


async def tss_demo():
    async with websockets.connect(KMC_URL, max_size=2_000_000) as ws:
        await ws.send(json.dumps({"type": "tss_recover_demo", "which": [1, 3, 5]}))
        print("[TSS demo]", await ws.recv())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--register", action="store_true")
    ap.add_argument("--listen", action="store_true")
    ap.add_argument("--send", nargs=2, metavar=("TO", "TEXT"))
    ap.add_argument("--algo", default="AESGCM", choices=["AESGCM", "CHACHA20"])
    ap.add_argument("--tss-demo", action="store_true")
    args = ap.parse_args()

    async def runner():
        if args.tss_demo:
            await tss_demo()
        if args.register:
            await register(args.name)
        if args.listen:
            await listen_fixed(args.name)
        if args.send:
            to, text = args.send
            await send_message(args.name, to, text, args.algo)

    asyncio.run(runner())


if __name__ == "__main__":
    main()
