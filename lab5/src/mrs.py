import json
import asyncio
import websockets

HOST = "127.0.0.1"
PORT = 9876

# simple in-memory “presence”
CLIENTS = {}  # name -> websocket


async def handler(ws):
    """
    Client messages:
    - {"type":"hello","name":"A"}  (register connection on relay)
    - {"type":"relay","to":"B","payload":{...}} (forward payload)
    """
    name = None
    try:
        async for msg in ws:
            req = json.loads(msg)
            t = req.get("type")

            if t == "hello":
                name = req["name"]
                CLIENTS[name] = ws
                await ws.send(json.dumps({"type": "hello_ok"}))
                continue

            if t == "relay":
                to = req["to"]
                payload = req["payload"]
                if to not in CLIENTS:
                    await ws.send(json.dumps({"type": "error", "error": f"{to} not connected"}))
                    continue
                await CLIENTS[to].send(json.dumps({"type": "inbox", "from": name, "payload": payload}))
                await ws.send(json.dumps({"type": "relay_ok"}))
                continue

            await ws.send(json.dumps({"type": "error", "error": "unknown type"}))

    except websockets.ConnectionClosed:
        pass
    finally:
        if name and CLIENTS.get(name) is ws:
            del CLIENTS[name]


async def main():
    print(f"[MRS] listening on ws://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT, max_size=2_000_000):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
