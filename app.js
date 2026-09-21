/*
 * Ties the crypto together with the actual chat. The general idea:
 *
 * - the room you land in is decided by a password. Your browser hashes
 *   it (SHA-256 via the browser's built-in digest - this is only an
 *   opaque room id, not "the encryption", so it's fine to use the
 *   platform hash here even though AES/RSA are hand-rolled) and sends
 *   only the hash. Two people share a room only if the hashes match.
 * - every client generates its own RSA keypair on connect (private key
 *   never leaves the browser)
 * - the room shares one AES-128 session key. whoever's already in the
 *   room encrypts that key with the new person's RSA public key and
 *   sends it over - the server just relays the ciphertext
 * - every chat message is AES-CBC encrypted with a fresh random IV
 * - shared files are encrypted the same way: the filename, mime type
 *   and the bytes all go into one AES-CBC blob, so the server sees an
 *   opaque payload and not even the file name
 * - each message gets a random id so it can later be edited or deleted
 * - voice/video calls are handled separately in call.js (WebRTC)
 */

// files are hex-encoded after encryption, so the websocket payload is
// about 2x this. keep it well under the server's 16 MB frame cap.
const MAX_FILE_BYTES = 4 * 1024 * 1024;

let ws = null;
let myId = null;
let myKeys = null;
let sessionKey = null;
let myAvatar = null;
let joinMode = null;
const users = {};
const messageEls = {};

const $ = (id) => document.getElementById(id);

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToBigInt(bytes) { return BigInt('0x' + bytesToHex(bytes)); }
function bigIntToBytes(num, len) {
  let hex = num.toString(16);
  while (hex.length < len * 2) hex = '0' + hex;
  return hexToBytes(hex);
}
function pubKeyToJSON(pub) { return { e: pub.e.toString(), n: pub.n.toString() }; }
function pubKeyFromJSON(o) { return { e: BigInt(o.e), n: BigInt(o.n) }; }
function newMsgId() {
  return (crypto.randomUUID ? crypto.randomUUID() : Date.now() + '-' + Math.random());
}
function encryptText(text) {
  return aesCbcEncrypt(new TextEncoder().encode(text), sessionKey);
}
function decryptText(ivHex, cipherHex) {
  const plain = aesCbcDecrypt(hexToBytes(cipherHex), sessionKey, hexToBytes(ivHex));
  return new TextDecoder().decode(plain);
}

// one-way hash of the room password. the server (and the wire log)
// only ever see this, never the password itself.
async function roomIdFromPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
  return bytesToHex(new Uint8Array(buf));
}

// getUserMedia and crypto.subtle both require a secure context
// (https:// or http://localhost). Opening index.html straight off the
// disk gives you file://, where they're unavailable - warn up front
// instead of failing mysteriously when someone hits the call button.
function checkSecureContext() {
  const ok = window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
  $('insecureWarning').classList.toggle('hidden', !!ok);
  return !!ok;
}

function log(msg) {
  const div = document.createElement('div');
  div.className = 'system-line';
  div.textContent = msg;
  $('messages').appendChild(div);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function avatarNode(username, avatarDataUrl) {
  if (avatarDataUrl) {
    const img = document.createElement('img');
    img.className = 'avatar';
    img.src = avatarDataUrl;
    return img;
  }
  const div = document.createElement('div');
  div.className = 'avatar avatar-fallback';
  div.textContent = (username || '?').trim().charAt(0).toUpperCase();
  return div;
}

// shared skeleton for both text and file messages: avatar, bubble,
// and the edit/delete controls when it's yours.
function buildRow(id, username, avatarDataUrl, mine, allowEdit) {
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' mine' : '');
  row.dataset.id = id;
  row.appendChild(avatarNode(username, avatarDataUrl));

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  row.appendChild(bubble);

  if (mine) {
    const actions = document.createElement('span');
    actions.className = 'msg-actions';
    if (allowEdit) {
      const editBtn = document.createElement('button');
      editBtn.className = 'editBtn';
      editBtn.title = 'edit';
      editBtn.textContent = '✎';
      editBtn.addEventListener('click', () => startEdit(id));
      actions.appendChild(editBtn);
    }
    const delBtn = document.createElement('button');
    delBtn.className = 'delBtn';
    delBtn.title = 'delete';
    delBtn.textContent = '🗑';
    delBtn.addEventListener('click', () => deleteMessage(id));
    actions.appendChild(delBtn);
    row.appendChild(actions);
  }

  $('messages').appendChild(row);
  $('messages').scrollTop = $('messages').scrollHeight;
  messageEls[id] = row;
  return bubble;
}

function addMessage(id, username, avatarDataUrl, text, mine) {
  const bubble = buildRow(id, username, avatarDataUrl, mine, true);
  bubble.innerHTML = `<span class="msg-user"></span><span class="msg-text"></span><span class="msg-edited hidden"> (edited)</span>`;
  bubble.querySelector('.msg-user').textContent = username + ': ';
  bubble.querySelector('.msg-text').textContent = text;
}

// file is { name, mime, bytes } - already decrypted by the time we
// get here. images render inline, anything else becomes a download.
function addFileMessage(id, username, avatarDataUrl, file, mine) {
  const bubble = buildRow(id, username, avatarDataUrl, mine, false);

  const who = document.createElement('span');
  who.className = 'msg-user';
  who.textContent = username + ': ';
  bubble.appendChild(who);

  const blob = new Blob([file.bytes], { type: file.mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);

  const wrap = document.createElement('div');
  wrap.className = 'file-att';

  if ((file.mime || '').startsWith('image/')) {
    const img = document.createElement('img');
    img.className = 'file-img';
    img.src = url;
    img.alt = file.name;
    wrap.appendChild(img);
  }

  const link = document.createElement('a');
  link.className = 'file-link';
  link.href = url;
  link.download = file.name;
  link.textContent = `⬇ ${file.name} (${formatSize(file.bytes.length)})`;
  wrap.appendChild(link);

  bubble.appendChild(wrap);
}

function formatSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function startEdit(id) {
  const row = messageEls[id];
  if (!row) return;
  const textSpan = row.querySelector('.msg-text');
  if (!textSpan) return;
  const current = textSpan.textContent;

  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'edit-input';
  input.value = current;
  textSpan.replaceWith(input);
  input.focus();

  const finish = (save) => {
    const newText = input.value;
    input.replaceWith(textSpan);
    if (save && newText.trim() && newText !== current) {
      textSpan.textContent = newText;
      row.querySelector('.msg-edited').classList.remove('hidden');
      const { iv, cipher } = encryptText(newText);
      const payload = { type: 'edit', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) };
      ws.send(JSON.stringify(payload));
      showWireTraffic('→', payload);
    }
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') finish(true);
    if (e.key === 'Escape') finish(false);
  });
  input.addEventListener('blur', () => finish(true));
}

function deleteMessage(id) {
  if (!confirm('delete this message for everyone?')) return;
  applyDelete(id);
  const payload = { type: 'delete', id };
  ws.send(JSON.stringify(payload));
  showWireTraffic('→', payload);
}

function applyDelete(id) {
  const row = messageEls[id];
  if (!row) return;
  const bubble = row.querySelector('.bubble');
  bubble.innerHTML = `<span class="msg-deleted">this message was deleted</span>`;
  const actions = row.querySelector('.msg-actions');
  if (actions) actions.remove();
}

function applyEdit(id, text) {
  const row = messageEls[id];
  if (!row) return;
  const textSpan = row.querySelector('.msg-text');
  if (!textSpan) return; // deleted, or a file message
  textSpan.textContent = text;
  row.querySelector('.msg-edited').classList.remove('hidden');
}

function showWireTraffic(direction, obj) {
  const s = JSON.stringify(obj);
  const line = document.createElement('div');
  line.className = 'wire-line';
  line.textContent = `${direction} ${s.slice(0, 140)}${s.length > 140 ? '…' : ''}`;
  $('wire').prepend(line);
  while ($('wire').children.length > 12) $('wire').removeChild($('wire').lastChild);
}

function refreshUserList() {
  const list = $('userList');
  list.innerHTML = '';

  const meLi = document.createElement('li');
  meLi.appendChild(avatarNode($('username').value.trim() || 'me', myAvatar));
  const meLabel = document.createElement('span');
  meLabel.textContent = `${$('username').value.trim() || 'me'} (you)`;
  meLi.appendChild(meLabel);
  list.appendChild(meLi);

  for (const cid in users) {
    const u = users[cid];
    const li = document.createElement('li');
    li.appendChild(avatarNode(u.username, u.avatar));
    const label = document.createElement('span');
    label.textContent = u.username;
    li.appendChild(label);

    const callBtns = document.createElement('span');
    callBtns.className = 'call-btns';
    const audioBtn = document.createElement('button');
    audioBtn.textContent = '📞';
    audioBtn.title = 'voice call';
    audioBtn.addEventListener('click', () => startCall(Number(cid), false));
    const videoBtn = document.createElement('button');
    videoBtn.textContent = '🎥';
    videoBtn.title = 'video call';
    videoBtn.addEventListener('click', () => startCall(Number(cid), true));
    callBtns.appendChild(audioBtn);
    callBtns.appendChild(videoBtn);
    li.appendChild(callBtns);

    list.appendChild(li);
  }
}

function handleAvatarPick(file) {
  return new Promise((resolve) => {
    if (!file) { resolve(null); return; }
    const img = new Image();
    const reader = new FileReader();
    reader.onload = () => {
      img.onload = () => {
        const size = 64;
        const canvas = document.createElement('canvas');
        canvas.width = size; canvas.height = size;
        const ctx = canvas.getContext('2d');
        const side = Math.min(img.width, img.height);
        ctx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, size, size);
        resolve(canvas.toDataURL('image/jpeg', 0.7));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

$('avatarInput').addEventListener('change', async (e) => {
  myAvatar = await handleAvatarPick(e.target.files[0]);
  $('avatarPreview').src = myAvatar || '';
  $('avatarPreview').classList.toggle('hidden', !myAvatar);
});

/* ---------- file sending ---------- */

function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

// layout inside the AES blob:
//   [2-byte header length][utf8 JSON header {name, mime}][raw file bytes]
// so the filename is encrypted too, not just the contents.
function packFile(name, mime, bytes) {
  const header = new TextEncoder().encode(JSON.stringify({ name, mime }));
  const out = new Uint8Array(2 + header.length + bytes.length);
  out[0] = (header.length >> 8) & 0xff;
  out[1] = header.length & 0xff;
  out.set(header, 2);
  out.set(bytes, 2 + header.length);
  return out;
}

function unpackFile(blobBytes) {
  const headerLen = (blobBytes[0] << 8) | blobBytes[1];
  const header = JSON.parse(new TextDecoder().decode(blobBytes.slice(2, 2 + headerLen)));
  return {
    name: header.name || 'file',
    mime: header.mime || 'application/octet-stream',
    bytes: blobBytes.slice(2 + headerLen),
  };
}

async function sendFile(file) {
  if (!file) return;
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (!sessionKey) { alert('still waiting on the session key from another member'); return; }
  if (file.size > MAX_FILE_BYTES) {
    alert(`that file is ${formatSize(file.size)} - the limit here is ${formatSize(MAX_FILE_BYTES)}. Encrypting in pure JS and hex-encoding it makes bigger files very slow.`);
    return;
  }

  log(`encrypting ${file.name}...`);
  const bytes = await readFileBytes(file);
  const packed = packFile(file.name, file.type, bytes);
  const { iv, cipher } = aesCbcEncrypt(packed, sessionKey);

  const id = newMsgId();
  const payload = { type: 'file', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) };
  ws.send(JSON.stringify(payload));
  showWireTraffic('→', { type: 'file', id, iv: payload.iv, ciphertext: `[${payload.ciphertext.length} hex chars of ciphertext]` });

  addFileMessage(id, $('username').value.trim(), myAvatar, { name: file.name, mime: file.type, bytes }, true);
}

$('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = ''; // let the same file be picked again later
  await sendFile(file);
});

/* ---------- connection ---------- */

// mode is 'create' or 'enter' - cosmetic only. room membership is
// decided entirely by whether the password hashes match.
async function connect(mode) {
  const username = $('username').value.trim();
  const password = $('roomPassword').value;
  if (!username) { alert('pick a username first'); return; }
  if (!password) { alert('enter a room password first'); return; }
  if (!window.crypto || !crypto.subtle) {
    alert('this page needs to run on http://localhost or https - run `python serve.py` and open http://localhost:8000');
    return;
  }

  joinMode = mode;
  $('createPasswordBtn').disabled = true;
  $('enterPasswordBtn').disabled = true;
  $('status').textContent = 'generating RSA-1024 keypair...';
  await new Promise(r => setTimeout(r, 30));
  myKeys = generateRSAKeyPair(1024);

  $('status').textContent = 'connecting...';
  const roomId = await roomIdFromPassword(password);

  ws = new WebSocket('wss://encrypted-chat-sx9o.onrender.com');
  ws.onopen = () => {
    const joinMsg = {
      type: 'join', username, room: roomId,
      pubkey: pubKeyToJSON(myKeys.publicKey),
      avatar: myAvatar,
    };
    ws.send(JSON.stringify(joinMsg));
    showWireTraffic('→', { ...joinMsg, room: roomId.slice(0, 8) + '…', avatar: myAvatar ? '[image data]' : null });
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    showWireTraffic('←', data.type === 'welcome' || data.type === 'user_joined'
      ? { ...data, avatar: data.avatar ? '[image data]' : (data.users ? '[...]' : undefined) }
      : (data.type === 'file' ? { ...data, ciphertext: `[${data.ciphertext.length} hex chars]` } : data));
    handleMessage(data);
  };

  ws.onclose = () => {
    $('status').textContent = 'disconnected';
    $('createPasswordBtn').disabled = false;
    $('enterPasswordBtn').disabled = false;
    log('connection closed');
  };
  ws.onerror = () => { $('status').textContent = 'connection error - is the server running?'; };
}

function handleMessage(data) {
  if (['call_offer', 'call_answer', 'call_ice', 'call_reject', 'call_end'].includes(data.type)) {
    handleCallSignal(data);
    return;
  }

  switch (data.type) {
    case 'welcome': {
      myId = data.id;
      $('loginScreen').classList.add('hidden');
      $('chatScreen').classList.remove('hidden');
      $('status').textContent = `connected as id ${myId}`;

      if (data.users.length === 0) {
        sessionKey = randomBytes(16);
        if (joinMode === 'enter') {
          log("nobody's in this room yet - you're first in, so a new AES-128 session key was generated locally");
        } else {
          log('room created - a new AES-128 session key was generated locally. share the password so others can join.');
        }
      } else {
        for (const u of data.users) {
          users[u.id] = { username: u.username, pubkey: pubKeyFromJSON(u.pubkey), avatar: u.avatar };
        }
        if (joinMode === 'create') {
          log('this password already has people in it - joining them instead');
        } else {
          log('waiting for an existing member to share the session key...');
        }
      }
      refreshUserList();
      break;
    }

    case 'user_joined': {
      users[data.id] = { username: data.username, pubkey: pubKeyFromJSON(data.pubkey), avatar: data.avatar };
      refreshUserList();
      log(`${data.username} joined`);

      if (sessionKey) {
        const keyInt = bytesToBigInt(sessionKey);
        const encInt = rsaEncryptInt(keyInt, users[data.id].pubkey);
        const payload = { type: 'key_exchange', to: data.id, encKey: encInt.toString() };
        ws.send(JSON.stringify(payload));
        showWireTraffic('→', payload);
      }
      break;
    }

    case 'key_exchange': {
      if (!sessionKey) {
        const encInt = BigInt(data.encKey);
        const keyInt = rsaDecryptInt(encInt, myKeys.privateKey);
        sessionKey = bigIntToBytes(keyInt, 16);
        log('received the room session key, decrypted locally with your private RSA key');
      }
      break;
    }

    case 'msg': {
      if (!sessionKey) {
        addMessage(data.id, data.username, users[data.from] && users[data.from].avatar, '[cannot decrypt yet - no session key]', false);
        break;
      }
      const text = decryptText(data.iv, data.ciphertext);
      addMessage(data.id, data.username, users[data.from] && users[data.from].avatar, text, false);
      break;
    }

    case 'file': {
      const avatar = users[data.from] && users[data.from].avatar;
      if (!sessionKey) {
        addMessage(data.id, data.username, avatar, '[a file arrived but there is no session key yet]', false);
        break;
      }
      try {
        const packed = aesCbcDecrypt(hexToBytes(data.ciphertext), sessionKey, hexToBytes(data.iv));
        addFileMessage(data.id, data.username, avatar, unpackFile(packed), false);
      } catch (err) {
        addMessage(data.id, data.username, avatar, '[could not decrypt that file]', false);
      }
      break;
    }

    case 'edit': {
      if (!sessionKey) break;
      const text = decryptText(data.iv, data.ciphertext);
      applyEdit(data.id, text);
      break;
    }

    case 'delete': {
      applyDelete(data.id);
      break;
    }

    case 'user_left': {
      const u = users[data.id];
      if (u) log(`${u.username} left`);
      delete users[data.id];
      refreshUserList();
      if (typeof callPeerId !== 'undefined' && callPeerId === data.id) {
        teardownCall();
      }
      break;
    }
  }
}

function sendMessage() {
  const input = $('messageInput');
  const text = input.value;
  if (!text.trim() || !ws || ws.readyState !== WebSocket.OPEN) return;
  if (!sessionKey) { alert('still waiting on the session key from another member'); return; }

  const id = newMsgId();
  const { iv, cipher } = encryptText(text);
  const payload = { type: 'msg', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) };
  ws.send(JSON.stringify(payload));
  showWireTraffic('→', payload);

  addMessage(id, $('username').value.trim(), myAvatar, text, true);
  input.value = '';
}

$('createPasswordBtn').addEventListener('click', () => connect('create'));
$('enterPasswordBtn').addEventListener('click', () => connect('enter'));
$('sendBtn').addEventListener('click', sendMessage);
$('messageInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
$('roomPassword').addEventListener('keydown', (e) => { if (e.key === 'Enter') connect('enter'); });
$('username').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('roomPassword').focus(); });

checkSecureContext();