import os
import json
import asyncio
import websockets

from common import (
    rsa_generate, RSAPub, RSAPriv,
    shamir_split, shamir_combine,
    sha256, b64e, b64d,
    load_json, save_json
)

KMC_STATE = "kmc_state.json"
SHARE_DIR = "kmc_shares"
HOST = "127.0.0.1"
PORT = 8765


def init_state():
    st = load_json(KMC_STATE, None)
    if st is None:
        pub, priv = rsa_generate(3072)
        master = os.urandom(32)
        shares = shamir_split(master, n=5, k=3)

        os.makedirs(SHARE_DIR, exist_ok=True)
        for (x, y) in shares:
            save_json(os.path.join(SHARE_DIR, f"share_{x}.json"), {"x": x, "y": str(y)})

        st = {
            "rsa_pub": {"n": str(pub.n), "e": pub.e},
            "rsa_priv": {"n": str(priv.n), "d": str(priv.d)},
            "master_sha256": b64e(sha256(master)),  # контроль восстановления TSS
        }
        save_json(KMC_STATE, st)
    return st


STATE = init_state()
PUB = RSAPub(n=int(STATE["rsa_pub"]["n"]), e=int(STATE["rsa_pub"]["e"]))
PRIV = RSAPriv(n=int(STATE["rsa_priv"]["n"]), d=int(STATE["rsa_priv"]["d"]))


async def handler(ws):
    """
    Protocol (JSON):
    - {"type":"get_pub"} -> {"type":"pub","n":"...","e":65537}
    - {"type":"blind_sign","blinded":"<b64 int bytes>"} -> {"type":"blind_sig","sig":"<b64 int bytes>"}
    - {"type":"tss_recover_demo","which":[1,3,5]} -> {"type":"tss_ok","master_sha256":"..."}  (demo)
    """
    async for msg in ws:
        try:
            req = json.loads(msg)
            t = req.get("type")

            if t == "get_pub":
                await ws.send(json.dumps({"type": "pub", "n": str(PUB.n), "e": PUB.e}))
                continue

            if t == "blind_sign":
                blinded_b = b64d(req["blinded"])
                blinded_int = int.from_bytes(blinded_b, "big") % PUB.n
                sig_int = pow(blinded_int, PRIV.d, PRIV.n)
                sig_b = sig_int.to_bytes((sig_int.bit_length() + 7) // 8, "big")
                await ws.send(json.dumps({"type": "blind_sig", "sig": b64e(sig_b)}))
                continue

            if t == "tss_recover_demo":
                which = req.get("which", [])
                shares = []
                for idx in which:
                    p = os.path.join(SHARE_DIR, f"share_{int(idx)}.json")
                    js = load_json(p, None)
                    if js is None:
                        raise ValueError("missing share file")
                    shares.append((int(js["x"]), int(js["y"])))
                master = shamir_combine(shares)
                await ws.send(json.dumps({
                    "type": "tss_ok",
                    "master_sha256": b64e(sha256(master)),
                    "expected_master_sha256": STATE["master_sha256"],
                    "match": b64e(sha256(master)) == STATE["master_sha256"]
                }))
                continue

            await ws.send(json.dumps({"type": "error", "error": "unknown type"}))

        except Exception as e:
            await ws.send(json.dumps({"type": "error", "error": str(e)}))


async def main():
    print(f"[KMC] listening on ws://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT, max_size=2_000_000):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
