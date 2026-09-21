"""
Relay server for the encrypted chat app.

This server never decrypts anything, and it never learns the room ID or
the room password either. The browser hashes them together
(SHA-256 of roomId + NUL + password) and sends only that hash as the
room key. Clients whose hashes match land in the same bucket; anyone
else lands in a disjoint one and never sees that the first room exists.
That is the entire membership check - a wrong password isn't rejected,
it just puts you somewhere else.

Otherwise the server only knows display names, connection ids, avatars
and RSA public keys - all public by definition. Session keys, messages
and shared files pass through as opaque blobs. Dump the traffic here
and you get ciphertext.

Call signaling (WebRTC offer/answer/ICE) is relayed point-to-point
inside a room. The audio and video never touch this process; they flow
directly between browsers, encrypted by the browser via DTLS-SRTP.

Run with: python server.py
Needs: pip install websockets
"""

import asyncio
import json
import websockets

# a shared file is encrypted then hex-encoded, so the frame is roughly
# 2x the original. 16 MB covers the 4 MB client-side cap comfortably.
MAX_FRAME_BYTES = 16 * 1024 * 1024

clients = {}   # id -> {"ws", "username", "pubkey", "avatar", "room"}
rooms = {}     # room hash -> set of client ids
next_id = 1

DIRECT_RELAY_TYPES = {
    "key_exchange": "encKey",
    "call_offer": "sdp",
    "call_answer": "sdp",
    "call_ice": "candidate",
    "call_end": None,
    "call_reject": None,
}


async def handler(ws):
    global next_id
    client_id = next_id
    next_id += 1

    try:
        data = json.loads(await ws.recv())
        if data.get("type") != "join":
            await ws.close(reason="expected join message")
            return

        username = data["username"]
        pubkey = data["pubkey"]
        avatar = data.get("avatar")
        room = data.get("room")
        if not room:
            await ws.close(reason="missing room")
            return

        clients[client_id] = {
            "ws": ws, "username": username, "pubkey": pubkey,
            "avatar": avatar, "room": room,
        }
        rooms.setdefault(room, set()).add(client_id)

        existing = [
            {
                "id": cid,
                "username": clients[cid]["username"],
                "pubkey": clients[cid]["pubkey"],
                "avatar": clients[cid]["avatar"],
            }
            for cid in rooms[room] if cid != client_id
        ]
        await ws.send(json.dumps({"type": "welcome", "id": client_id, "users": existing}))

        await broadcast(client_id, {
            "type": "user_joined",
            "id": client_id,
            "username": username,
            "pubkey": pubkey,
            "avatar": avatar,
        })

        async for raw in ws:
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type in DIRECT_RELAY_TYPES:
                target = clients.get(data.get("to"))
                # only relay inside the same room - an id from another
                # room must never be reachable
                if not target or target["room"] != clients[client_id]["room"]:
                    continue
                out = {"type": msg_type, "from": client_id}
                field = DIRECT_RELAY_TYPES[msg_type]
                if field and field in data:
                    out[field] = data[field]
                if msg_type == "call_offer":
                    out["video"] = data.get("video", False)
                await target["ws"].send(json.dumps(out))

            elif msg_type in ("msg", "file", "edit"):
                # filename and mime type are encrypted alongside the file
                # bytes on the client, so this relay is as blind for
                # files as it is for text
                await broadcast(client_id, {
                    "type": msg_type,
                    "from": client_id,
                    "username": username,
                    "id": data["id"],
                    "iv": data["iv"],
                    "ciphertext": data["ciphertext"],
                })

            elif msg_type == "delete":
                # the server can't verify authorship - it never saw the
                # plaintext. the client only offers edit/delete on your
                # own messages; that's the enforcement boundary here.
                await broadcast(client_id, {
                    "type": "delete",
                    "from": client_id,
                    "id": data["id"],
                })

    except websockets.exceptions.ConnectionClosed:
        pass
    except (KeyError, json.JSONDecodeError):
        pass
    finally:
        info = clients.pop(client_id, None)
        if info:
            room = info["room"]
            members = rooms.get(room)
            if members:
                members.discard(client_id)
                if not members:
                    rooms.pop(room, None)
            await broadcast(client_id, {"type": "user_left", "id": client_id}, room=room)


async def broadcast(sender_id, message, room=None):
    if room is None:
        info = clients.get(sender_id)
        if not info:
            return
        room = info["room"]
    dead = []
    payload = json.dumps(message)
    for cid in list(rooms.get(room, set())):
        if cid == sender_id:
            continue
        c = clients.get(cid)
        if not c:
            continue
        try:
            await c["ws"].send(payload)
        except websockets.exceptions.ConnectionClosed:
            dead.append(cid)
    for cid in dead:
        clients.pop(cid, None)
        rooms.get(room, set()).discard(cid)


async def main():
    print("chat server listening on port 10000")
    async with websockets.serve(handler, "0.0.0.0", 10000, max_size=MAX_FRAME_BYTES):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())