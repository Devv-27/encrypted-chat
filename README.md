# Encrypted Chat

A real-time chat app where messages are actually end-to-end encrypted —
the server relays bytes but can never read them. Both RSA and AES are
implemented from scratch (no `pycryptodome`, no `crypto-js`, no Web
Crypto API) so the crypto fundamentals are visible instead of hidden
behind a library call.

## Stack

- **Server**: Python + `websockets`, pure message relay
- **Client**: plain HTML/CSS/JS, all crypto runs in the browser

## Features

- Group chat, AES-128-CBC encrypted, RSA-1024 key exchange, both
  implemented from scratch (no crypto libraries)
- **Edit** your own messages (hover a message you sent → pencil icon)
- **Delete for everyone** (hover → trash icon → confirms, then removes
  it from every client's screen)
- **Profile pictures** — pick an image on the login screen, it's
  resized to a small thumbnail client-side and shown next to your
  name/messages
- **Voice and video calls** (📞 / 🎥 buttons next to each online user)
  — real WebRTC peer-to-peer calls, not a chat "feature" mockup

## How the encryption actually works

1. When you connect, your browser generates its own RSA-1024 keypair
   (`rsa.js`, using native `BigInt`, Miller-Rabin for primality). Your
   private key never leaves the browser.
2. Whoever is first in the room generates a random 128-bit AES key —
   this becomes the shared "session key" for that room.
3. Whenever someone new joins, an existing member encrypts the session
   key with the newcomer's RSA public key and sends it over. The
   server just forwards this blob; since it's RSA-encrypted, only the
   intended recipient can decrypt it with their private key.
4. Every chat message is encrypted with AES-128 in CBC mode
   (`aes.js`), with a fresh random IV per message, before it's sent.
   The server only ever sees `{iv, ciphertext}` pairs. Each message
   gets a random id so edits/deletes can reference it later.
5. **Edit** re-encrypts the new text under the same message id and
   broadcasts it; everyone else decrypts and swaps the text in place,
   tagged "(edited)".
6. **Delete** broadcasts just the message id; every client (including
   the sender) replaces that bubble with "this message was deleted".
   The server never stores messages, so it can't enforce who's
   allowed to edit/delete what — the client only shows those controls
   on your own messages. Fine for a class project, not for anything
   where a malicious client is a real threat.
7. **Calls** are a separate system: WebRTC. The websocket server only
   relays the SDP offer/answer and ICE candidates between two specific
   clients (like `key_exchange`, it's a blind relay). Once connected,
   audio/video flows directly between the two browsers, encrypted by
   WebRTC itself (DTLS-SRTP) — that encryption is handled by the
   browser, not hand-rolled like the chat messages are.

There's a "Wire traffic" panel in the UI that shows exactly what's
going over the socket, so you can see it's all ciphertext / RSA blobs
/ call signaling and never plaintext chat.

## Running it

```
pip install websockets
python server.py
```

Then open `static/index.html` directly in two or more browser tabs
(or windows). Pick a username in each and hit Connect. The first tab
to connect mints the session key; everyone after that gets it handed
to them over RSA.

## Honest limitations

This is built to demonstrate the algorithms, not to be a secure
product. Things a real system would need that this skips:

- RSA here uses no OAEP padding (textbook RSA) — fine for a demo,
  not fine for production
- No forward secrecy — if the session key ever leaks, all past
  messages decrypt
- No authentication of who "owns" a public key (no cert / trust
  model), so a malicious relay could in theory pull off a
  man-in-the-middle by swapping keys in transit
- AES-CBC has no message authentication (no MAC/AEAD), so tampering
  with ciphertext isn't detected — a real system would use
  AES-GCM or CBC+HMAC
- Key size (1024-bit RSA) is chosen for demo speed, not real-world
  security margins

For an actual product you'd reach for the Signal protocol, or at
minimum the Web Crypto API / a vetted library with AES-GCM and RSA-OAEP.
The point of this project was building AES and RSA by hand to
understand what those libraries are actually doing underneath.

## Files

```
server.py           websocket relay - chat, edit/delete, avatars, and call signaling
static/index.html   UI, including call modal/overlay
static/style.css    styling
static/rsa.js       RSA keygen/encrypt/decrypt from scratch (BigInt)
static/aes.js       AES-128-CBC from scratch (S-box, MixColumns, key schedule, etc)
static/app.js       chat logic: websocket, key exchange, edit/delete, avatars
static/call.js      WebRTC voice/video calling + signaling handlers
```

## Notes on calling

- Needs microphone (and camera, for video calls) permission in the
  browser — it'll prompt you.
- Uses a public Google STUN server (`stun.l.google.com:19302`) for NAT
  traversal. That's the only outside dependency in the whole project;
  everything else runs entirely between your machine(s) and `server.py`.
- Works great for two tabs on the same machine or two devices on the
  same network. Calling across the open internet may need a TURN
  server too if both sides are behind strict NATs — out of scope here,
  but worth knowing if a demo call doesn't connect on a weird network.
