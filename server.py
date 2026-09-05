"""
Relay server for the encrypted chat app.

Important design point: this server never decrypts anything. It only
knows usernames, connection ids, avatars and RSA public keys (all
public by definition). AES session keys and chat messages pass through
as opaque blobs - if you dumped the traffic at this layer you'd just
see ciphertext. All the actual crypto lives in the browser (aes.js
and rsa.js).

Multiple rooms: the server now keeps a dict of independently-named
rooms, each with its own members and its own password. A room is
created the moment someone joins with mode="create" (they become that
room's "creator" - shown with a crown in the UI); everyone after that
joins with mode="join" and must supply the matching password. The
server stores only a SHA-256 hash of each room's password, never the
password itself. When a room's last member leaves, the room is
deleted, so the name and password are free to be reused/recreated.
This is a plain admission check - it is NOT what encrypts the chat,
that's the AES/RSA layer implemented in the browser.

"presence" messages (online / in_call) are just relayed to the room so
everyone's sidebar status dot stays accurate - no message content ever
passes through this path.

Call signaling (WebRTC offer/answer/ICE candidates) is also just
relayed point-to-point between two clients in the same room - the
server never touches the actual audio/video, that flows directly
between browsers once the connection is set up. WebRTC media itself is
encrypted by the browser via DTLS-SRTP, separately from the message
encryption this project implements by hand.

Run with: python server.py
Needs: pip install websockets
"""

import asyncio
import hashlib
import json
import websockets

# rooms: room_name -> {"password_hash": str, "creator_id": int, "clients": {id: {...}}}
rooms = {}
next_id = 1

# message types that are just "forward this to one specific client in
# the same room" and don't need any special handling beyond stamping
# who it's from
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
    global next_id
    client_id = next_id
    next_id += 1
    room_name = None

    try:
        raw = await ws.recv()
        data = json.loads(raw)
        if data.get("type") != "join":
            await ws.close(reason="expected join message")
            return

        room_name = (data.get("room") or "").strip()
        username = data["username"]
        pubkey = data["pubkey"]
        avatar = data.get("avatar")  # small base64 data URL, an emoji string, or None
        mode = data.get("mode")
        password = data.get("password", "")

        if not room_name:
            await ws.send(json.dumps({"type": "join_error", "message": "Room name can't be empty."}))
            await ws.close()
            return
        if not username:
            await ws.send(json.dumps({"type": "join_error", "message": "Username can't be empty."}))
            await ws.close()
            return

        room = rooms.get(room_name)

        if mode == "create":
            if room is not None:
                await ws.send(json.dumps({
                    "type": "join_error",
                    "message": f'Room "{room_name}" already exists - use "Join Room" instead.',
                }))
                await ws.close()
                return
            if not password:
                await ws.send(json.dumps({"type": "join_error", "message": "Password can't be empty."}))
                await ws.close()
                return
            room = {"password_hash": hash_password(password), "creator_id": client_id, "clients": {}}
            rooms[room_name] = room

        elif mode == "join":
            if room is None:
                await ws.send(json.dumps({
                    "type": "join_error",
                    "message": f'Room "{room_name}" doesn\'t exist yet - create it first.',
                }))
                await ws.close()
                return
            if hash_password(password) != room["password_hash"]:
                await ws.send(json.dumps({"type": "join_error", "message": "Incorrect room password."}))
                await ws.close()
                return

        else:
            await ws.send(json.dumps({"type": "join_error", "message": "Invalid join mode."}))
            await ws.close()
            return

        room["clients"][client_id] = {
            "ws": ws, "username": username, "pubkey": pubkey, "avatar": avatar, "status": "online",
        }

        existing_users = [
            {
                "id": cid, "username": c["username"], "pubkey": c["pubkey"], "avatar": c["avatar"],
                "status": c.get("status", "online"), "creator": cid == room["creator_id"],
            }
            for cid, c in room["clients"].items() if cid != client_id
        ]
        await ws.send(json.dumps({
            "type": "welcome",
            "id": client_id,
            "room": room_name,
            "isCreator": client_id == room["creator_id"],
            "users": existing_users,
        }))

        await broadcast(room, client_id, {
            "type": "user_joined",
            "id": client_id,
            "username": username,
            "pubkey": pubkey,
            "avatar": avatar,
            "status": "online",
            "creator": client_id == room["creator_id"],
        })

        async for raw in ws:
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type in DIRECT_RELAY_TYPES:
                target = room["clients"].get(data.get("to"))
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
                await broadcast(room, client_id, {
                    "type": "msg",
                    "from": client_id,
                    "username": username,
                    "id": data["id"],
                    "iv": data["iv"],
                    "ciphertext": data["ciphertext"],
                    "sentAt": data.get("sentAt"),
                })

            elif msg_type == "edit":
                # server can't verify this is really the original author
                # (it never saw the plaintext to begin with) - the client
                # only shows edit controls on your own messages, that's
                # the enforcement boundary for this project
                await broadcast(room, client_id, {
                    "type": "edit",
                    "from": client_id,
                    "username": username,
                    "id": data["id"],
                    "iv": data["iv"],
                    "ciphertext": data["ciphertext"],
                })

            elif msg_type == "delete":
                await broadcast(room, client_id, {
                    "type": "delete",
                    "from": client_id,
                    "id": data["id"],
                })

            elif msg_type == "avatar_update":
                new_avatar = data.get("avatar")
                if client_id in room["clients"]:
                    room["clients"][client_id]["avatar"] = new_avatar
                await broadcast(room, client_id, {
                    "type": "avatar_update",
                    "from": client_id,
                    "avatar": new_avatar,
                })

            elif msg_type == "presence":
                status = data.get("status", "online")
                if client_id in room["clients"]:
                    room["clients"][client_id]["status"] = status
                await broadcast(room, client_id, {
                    "type": "presence",
                    "from": client_id,
                    "status": status,
                })

    except websockets.exceptions.ConnectionClosed:
        pass
    except (KeyError, json.JSONDecodeError):
        pass
    finally:
        if room_name and room_name in rooms:
            room = rooms[room_name]
            if client_id in room["clients"]:
                del room["clients"][client_id]
                await broadcast(room, client_id, {"type": "user_left", "id": client_id})
            if not room["clients"]:
                # room is empty - drop it so the name+password can be
                # freely recreated by the next person
                del rooms[room_name]


async def broadcast(room, sender_id, message):
    dead = []
    payload = json.dumps(message)
    for cid, c in room["clients"].items():
        if cid == sender_id:
            continue
        try:
            await c["ws"].send(payload)
        except websockets.exceptions.ConnectionClosed:
            dead.append(cid)
    for cid in dead:
        room["clients"].pop(cid, None)


async def main():
    print("chat server listening on port 10000")
    async with websockets.serve(handler, "0.0.0.0", 10000):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())