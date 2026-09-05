/*
 * Ties the crypto together with the actual chat. The general idea:
 *
 * - every client generates its own RSA keypair on connect (private key
 *   never leaves the browser)
 * - the room shares one AES-128 session key. whoever's already in the
 *   room encrypts that key with the new person's RSA public key and
 *   sends it over - the server just relays the ciphertext, it can't
 *   read the key
 * - every chat message is AES-CBC encrypted with a fresh random IV
 *   before it goes over the wire
 * - each message gets a random id so it can later be edited or deleted
 * - the room is also gated by a plain password: the first person to
 *   connect "creates" it (server stores only a SHA-256 hash of the
 *   password, never the password itself), everyone after that "enters"
 *   it and the server checks the hash matches before letting them in.
 *   this is separate from the AES/RSA message encryption above - it's
 *   just an admission check, not what protects the chat content.
 * - voice/video calls are handled separately in call.js (WebRTC, not
 *   our hand-rolled crypto - see the note at the top of that file)
 */

let ws = null;
let myId = null;
let myKeys = null;
let sessionKey = null;
let myAvatar = null;
let joinMode = null;        // 'create' | 'enter'
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

function setStatus(msg, isError) {
  $('status').textContent = msg;
  $('status').classList.toggle('error', !!isError);
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

function addMessage(id, username, avatarDataUrl, text, mine) {
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' mine' : '');
  row.dataset.id = id;

  row.appendChild(avatarNode(username, avatarDataUrl));

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.innerHTML = `<span class="msg-user"></span><span class="msg-text"></span><span class="msg-edited hidden"> (edited)</span>`;
  bubble.querySelector('.msg-user').textContent = username + ': ';
  bubble.querySelector('.msg-text').textContent = text;
  row.appendChild(bubble);

  if (mine) {
    const actions = document.createElement('span');
    actions.className = 'msg-actions';
    actions.innerHTML = `<button class="editBtn" title="edit">✎</button><button class="delBtn" title="delete">🗑</button>`;
    actions.querySelector('.editBtn').addEventListener('click', () => startEdit(id));
    actions.querySelector('.delBtn').addEventListener('click', () => deleteMessage(id));
    row.appendChild(actions);
  }

  $('messages').appendChild(row);
  $('messages').scrollTop = $('messages').scrollHeight;
  messageEls[id] = row;
}

function startEdit(id) {
  const row = messageEls[id];
  if (!row) return;
  const textSpan = row.querySelector('.msg-text');
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
  if (!textSpan) return; // already deleted
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

// avatar picker on the login screen
$('avatarInput').addEventListener('change', async (e) => {
  myAvatar = await handleAvatarPick(e.target.files[0]);
  $('avatarPreview').src = myAvatar || '';
  $('avatarPreview').classList.toggle('hidden', !myAvatar);
});

// "change photo" while already in the room - updates live and tells everyone
$('changeAvatarBtn').addEventListener('click', () => $('avatarInputChat').click());
$('avatarInputChat').addEventListener('change', async (e) => {
  const newAvatar = await handleAvatarPick(e.target.files[0]);
  if (!newAvatar) return;
  myAvatar = newAvatar;
  refreshUserList();
  if (ws && ws.readyState === WebSocket.OPEN) {
    const payload = { type: 'avatar_update', avatar: myAvatar };
    ws.send(JSON.stringify(payload));
    showWireTraffic('→', { type: 'avatar_update', avatar: '[image data]' });
  }
});

// ---- room password mode selection ----
function selectMode(mode) {
  joinMode = mode;
  $('createPasswordBtn').classList.toggle('selected', mode === 'create');
  $('enterPasswordBtn').classList.toggle('selected', mode === 'enter');
  $('connectBtn').disabled = false;
  setStatus(mode === 'create'
    ? 'Will create a new room with this password.'
    : 'Will join the room if this password matches.');
}
$('createPasswordBtn').addEventListener('click', () => selectMode('create'));
$('enterPasswordBtn').addEventListener('click', () => selectMode('enter'));

async function connect() {
  const username = $('username').value.trim();
  const password = $('roomPassword').value;

  if (!username) { alert('pick a username first'); return; }
  if (!joinMode) { alert('choose "Create password" or "Enter password" first'); return; }
  if (!password) { alert('type a room password'); return; }

  $('connectBtn').disabled = true;
  $('createPasswordBtn').disabled = true;
  $('enterPasswordBtn').disabled = true;
  setStatus('generating RSA-1024 keypair...');
  await new Promise(r => setTimeout(r, 30));
  myKeys = generateRSAKeyPair(1024);

  setStatus('connecting...');
  ws = new WebSocket('wss://encrypted-chat-sx9o.onrender.com');
  ws.onopen = () => {
    const joinMsg = {
      type: 'join', username,
      pubkey: pubKeyToJSON(myKeys.publicKey),
      avatar: myAvatar,
      mode: joinMode,
      password,
    };
    ws.send(JSON.stringify(joinMsg));
    showWireTraffic('→', { ...joinMsg, avatar: myAvatar ? '[image data]' : null, password: '[not shown]' });
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    showWireTraffic('←', data.type === 'welcome' || data.type === 'user_joined'
      ? { ...data, avatar: data.avatar ? '[image data]' : (data.users ? '[...]' : undefined) }
      : data);
    handleMessage(data);
  };

  ws.onclose = () => {
    setStatus('disconnected');
    if ($('chatScreen').classList.contains('hidden')) {
      // never made it into the chat - let them retry
      $('connectBtn').disabled = false;
      $('createPasswordBtn').disabled = false;
      $('enterPasswordBtn').disabled = false;
    } else {
      log('connection closed');
    }
  };
  ws.onerror = () => { setStatus('connection error - is server.py running?', true); };
}

function handleMessage(data) {
  if (['call_offer', 'call_answer', 'call_ice', 'call_reject', 'call_end'].includes(data.type)) {
    handleCallSignal(data);
    return;
  }

  switch (data.type) {
    case 'join_error': {
      setStatus(data.message || 'could not join the room', true);
      $('connectBtn').disabled = false;
      $('createPasswordBtn').disabled = false;
      $('enterPasswordBtn').disabled = false;
      break;
    }

    case 'welcome': {
      myId = data.id;
      $('loginScreen').classList.add('hidden');
      $('chatScreen').classList.remove('hidden');
      setStatus(`connected as id ${myId}`);

      if (data.users.length === 0) {
        sessionKey = randomBytes(16);
        log('you are the first one here - a new AES-128 session key was generated locally');
      } else {
        for (const u of data.users) {
          users[u.id] = { username: u.username, pubkey: pubKeyFromJSON(u.pubkey), avatar: u.avatar };
        }
        log('waiting for an existing member to share the session key...');
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

    case 'avatar_update': {
      if (users[data.from]) {
        users[data.from].avatar = data.avatar;
        refreshUserList();
      }
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

$('connectBtn').addEventListener('click', connect);
$('sendBtn').addEventListener('click', sendMessage);
$('messageInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
$('roomPassword').addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(); });