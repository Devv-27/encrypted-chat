"""
Relay server for the encrypted chat app.

Important design point: this server never decrypts anything. It only
knows usernames, connection ids, avatars and RSA public keys (all
public by definition). AES session keys and chat messages pass through
as opaque blobs - if you dumped the traffic at this layer you'd just
see ciphertext. All the actual crypto lives in the browser (aes.js
and rsa.js).

Room password: the server stores only a SHA-256 hash of the room
password, never the password itself. The first client to join with
mode="create" sets that hash. Everyone after that must join with
mode="enter" and a password whose hash matches, or they're rejected
before being added to the room. When the room empties out, the hash
is cleared so the next person in can create a fresh password. This is
a plain admission check - it is NOT what encrypts the chat, that's the
AES/RSA layer above.

Call signaling (WebRTC offer/answer/ICE candidates) is also just
relayed point-to-point between two clients - the server never touches
the actual audio/video, that flows directly between browsers once the
connection is set up. WebRTC media itself is encrypted by the browser
via DTLS-SRTP, separately from the message encryption this project
implements by hand.

Run with: python server.py
Needs: pip install websockets
"""

import asyncio
import hashlib
import json
import websockets

clients = {}   # id -> {"ws", "username", "pubkey", "avatar"}
next_id = 1
room_password_hash = None  # SHA-256 hex digest, or None if room has no password yet

# message types that are just "forward this to one specific client"
# and don't need any special handling beyond stamping who it's from
DIRECT_RELAY_TYPES = {
    "key_exchange": "encKey",
    "call_offer": "sdp",
    "call_answer": "sdp",
    "call_ice": "candidate",
    "call_end": None,
    "call_reject": None,
}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


async def handler(ws):
    global next_id, room_password_hash
    client_id = next_id
    next_id += 1

    try:
        raw = await ws.recv()
        data = json.loads(raw)
        if data.get("type") != "join":
            await ws.close(reason="expected join message")
            return

        username = data["username"]
        pubkey = data["pubkey"]
        avatar = data.get("avatar")  # small base64 data URL or None
        mode = data.get("mode")
        password = data.get("password", "")

        if mode == "create":
            if room_password_hash is not None:
                await ws.send(json.dumps({
                    "type": "join_error",
                    "message": "This room already has a password - use \"Enter password\" instead.",
                }))
                await ws.close()
                return
            if not password:
                await ws.send(json.dumps({"type": "join_error", "message": "Password can't be empty."}))
                await ws.close()
                return
            room_password_hash = hash_password(password)

        elif mode == "enter":
            if room_password_hash is None:
                await ws.send(json.dumps({
                    "type": "join_error",
                    "message": "No room password has been created yet - ask someone to \"Create password\" first.",
                }))
                await ws.close()
                return
            if hash_password(password) != room_password_hash:
                await ws.send(json.dumps({"type": "join_error", "message": "Incorrect room password."}))
                await ws.close()
                return

        else:
            await ws.send(json.dumps({"type": "join_error", "message": "Invalid join mode."}))
            await ws.close()
            return

        clients[client_id] = {
            "ws": ws, "username": username, "pubkey": pubkey, "avatar": avatar,
        }

        existing_users = [
            {"id": cid, "username": c["username"], "pubkey": c["pubkey"], "avatar": c["avatar"]}
            for cid, c in clients.items() if cid != client_id
        ]
        await ws.send(json.dumps({
            "type": "welcome",
            "id": client_id,
            "users": existing_users,
        }))

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
                if not target:
                    continue
                out = {"type": msg_type, "from": client_id}
                field = DIRECT_RELAY_TYPES[msg_type]
                if field and field in data:
                    out[field] = data[field]
                if msg_type == "call_offer":
                    out["video"] = data.get("video", False)
                await target["ws"].send(json.dumps(out))

            elif msg_type == "msg":
                await broadcast(client_id, {
                    "type": "msg",
                    "from": client_id,
                    "username": username,
                    "id": data["id"],
                    "iv": data["iv"],
                    "ciphertext": data["ciphertext"],
                })

            elif msg_type == "edit":
                # server can't verify this is really the original author
                # (it never saw the plaintext to begin with) - the client
                # only shows edit controls on your own messages, that's
                # the enforcement boundary for this project
                await broadcast(client_id, {
                    "type": "edit",
                    "from": client_id,
                    "username": username,
                    "id": data["id"],
                    "iv": data["iv"],
                    "ciphertext": data["ciphertext"],
                })

            elif msg_type == "delete":
                await broadcast(client_id, {
                    "type": "delete",
                    "from": client_id,
                    "id": data["id"],
                })

            elif msg_type == "avatar_update":
                new_avatar = data.get("avatar")
                if client_id in clients:
                    clients[client_id]["avatar"] = new_avatar
                await broadcast(client_id, {
                    "type": "avatar_update",
                    "from": client_id,
                    "avatar": new_avatar,
                })

    except websockets.exceptions.ConnectionClosed:
        pass
    except (KeyError, json.JSONDecodeError):
        pass
    finally:
        if client_id in clients:
            del clients[client_id]
            await broadcast(client_id, {"type": "user_left", "id": client_id})
            if not clients:
                # room is empty - clear the password so the next person
                # in can create a fresh one
                room_password_hash = None


async def broadcast(sender_id, message):
    dead = []
    payload = json.dumps(message)
    for cid, c in clients.items():
        if cid == sender_id:
            continue
        try:
            await c["ws"].send(payload)
        except websockets.exceptions.ConnectionClosed:
            dead.append(cid)
    for cid in dead:
        clients.pop(cid, None)


async def main():
    print("chat server listening on port 10000")
    async with websockets.serve(handler, "0.0.0.0", 10000):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())