import asyncio
import json
import os
import websockets

clients = {}
rooms = set()
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
        raw = await ws.recv()
        data = json.loads(raw)

        if data.get("type") != "join":
            await ws.close(reason="expected join message")
            return

        username = data["username"]
        pubkey = data["pubkey"]
        avatar = data.get("avatar")
        room = data.get("room")
        mode = data.get("mode", "enter")

        if not room:
            await ws.send(json.dumps({
                "type": "room_error",
                "message": "Room password is required."
            }))
            await ws.close()
            return

        if mode == "create":
            if room in rooms:
                await ws.send(json.dumps({
                    "type": "room_error",
                    "message": "This password already exists. Use Enter Password."
                }))
                await ws.close()
                return
            rooms.add(room)

        elif mode == "enter":
            if room not in rooms:
                await ws.send(json.dumps({
                    "type": "room_error",
                    "message": "Room not found. Use Create Password first."
                }))
                await ws.close()
                return

        else:
            await ws.send(json.dumps({
                "type": "room_error",
                "message": "Invalid room mode."
            }))
            await ws.close()
            return

        clients[client_id] = {
            "ws": ws,
            "username": username,
            "pubkey": pubkey,
            "avatar": avatar,
            "room": room,
        }

        existing_users = [
            {
                "id": cid,
                "username": c["username"],
                "pubkey": c["pubkey"],
                "avatar": c.get("avatar"),
            }
            for cid, c in clients.items()
            if cid != client_id and c["room"] == room
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
                sender = clients.get(client_id)

                if not target or not sender or target["room"] != sender["room"]:
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

    except websockets.exceptions.ConnectionClosed:
        pass
    except (KeyError, json.JSONDecodeError) as e:
        print("bad client message:", e)
    except Exception as e:
        print("client error:", e)
    finally:
        if client_id in clients:
            room = clients[client_id]["room"]
            del clients[client_id]
            await broadcast(client_id, {"type": "user_left", "id": client_id}, room=room)


async def broadcast(sender_id, message, room=None):
    if room is None:
        sender = clients.get(sender_id)
        if not sender:
            return
        room = sender["room"]

    dead = []
    payload = json.dumps(message)

    for cid, client in clients.items():
        if cid == sender_id or client["room"] != room:
            continue
        try:
            await client["ws"].send(payload)
        except websockets.exceptions.ConnectionClosed:
            dead.append(cid)

    for cid in dead:
        clients.pop(cid, None)


async def main():
    port = int(os.environ.get("PORT", "8765"))
    print(f"chat server listening on port {port}")

    async with websockets.serve(handler, "0.0.0.0", port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())