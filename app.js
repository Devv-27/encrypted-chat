/*
 * Chat logic: identity, room entry, key exchange, messages, files.
 *
 * How a room works
 *   A room is identified by SHA-256(roomId + NUL + password). That hash
 *   is the only thing the server sees - not the id, not the password.
 *   Two people share a room only if both halves match, so a wrong
 *   password doesn't "fail", it just puts you somewhere else entirely.
 *
 * How the crypto works
 *   - each client mints its own RSA-1024 keypair in-tab; the private
 *     half never leaves the browser
 *   - the room shares one AES-128 session key. an existing member wraps
 *     it with the newcomer's RSA public key; the server relays the
 *     ciphertext and can't read it
 *   - messages and files are AES-CBC encrypted with a fresh IV each time
 *   - every peer gets a key fingerprint (first 8 hex of SHA-256 of their
 *     modulus) shown in the room list. Read it aloud to the other person
 *     to catch a relay that swapped keys on you - that's the one hole
 *     this design otherwise can't close.
 */

// Served from localhost (python serve.py) → talk to your local
// server.py. Served from anywhere else → talk to the deployed one.
// Change either side if you host it somewhere different.
const LOCAL_SERVER  = 'ws://localhost:10000';
const HOSTED_SERVER = 'wss://encrypted-chat-sx9o.onrender.com';
const SERVER_URL =
  ['localhost', '127.0.0.1'].includes(location.hostname) ? LOCAL_SERVER : HOSTED_SERVER;

// files get hex-encoded after encryption, so the frame is ~2x this
const MAX_FILE_BYTES = 4 * 1024 * 1024;

let ws = null;
let myId = null;
let myKeys = null;
let myFingerprint = '';
let sessionKey = null;
let myAvatar = null;
let myName = '';
let currentRoomId = '';
let joinMode = null;
let lastSender = null;

const users = {};
const messageEls = {};

const $ = (id) => document.getElementById(id);

/* ───────────── byte helpers ───────────── */

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
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToHex(new Uint8Array(buf));
}

// the room the server buckets you into. one-way, so the id and the
// password both stay in this tab.
function roomKey(roomId, password) {
  return sha256Hex(roomId.trim().toLowerCase() + '\u0000' + password);
}

// short, human-readable identity for a public key. two people reading
// these aloud can confirm nobody swapped keys in transit.
async function fingerprint(pub) {
  const hex = await sha256Hex(pub.n.toString(16));
  return hex.slice(0, 4) + ' ' + hex.slice(4, 8);
}

function encryptText(text) {
  return aesCbcEncrypt(new TextEncoder().encode(text), sessionKey);
}
function decryptText(ivHex, cipherHex) {
  return new TextDecoder().decode(
    aesCbcDecrypt(hexToBytes(cipherHex), sessionKey, hexToBytes(ivHex))
  );
}

function formatSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(1) + ' MB';
}
function clockTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// stable colour per name so avatars stay recognisable without a picture
function colorFor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
  return `hsl(${h} 46% 66%)`;
}

let toastTimer = null;
function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2400);
}

/* ───────────── secure-context check ─────────────
   getUserMedia and crypto.subtle only exist on https:// or
   http://localhost. Opened straight off disk you get file://, where
   both are missing - say so up front rather than failing later. */

function checkSecureContext() {
  const ok = window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
  $('insecureWarning').classList.toggle('hidden', !!ok);
  return !!ok;
}

/* ───────────── keygen readout ───────────── */

function setReadout(stage, ticker, caption) {
  $('readoutStage').textContent = stage;
  if (ticker !== undefined) $('readoutTicker').textContent = ticker;
  if (caption !== undefined) $('readoutCaption').textContent = caption;
}

// the numbered steps are a preview of what's about to happen; once it
// actually starts, the live readout replaces them
function hideReadoutSteps() { $('readoutSteps').classList.add('hidden'); }

function showModulus(n) {
  const hex = n.toString(16);
  const el = $('readoutHex');
  el.textContent = hex.replace(/(.{4})/g, '$1 ').trim();
  el.classList.remove('live');
  void el.offsetWidth;   // restart the reveal
  el.classList.add('live');
}

/* Same algorithm as rsa.js, just sliced up so the tab stays responsive
   and can report how many candidates primality testing actually
   rejected. rsa.js itself is left untouched. */
async function mintKeyPair(bits, onCandidate) {
  const half = bits / 2;
  let tested = 0;

  const findPrime = async () => {
    for (;;) {
      const candidate = bigRandomBits(half);
      tested++;
      if (tested % 4 === 0) {
        onCandidate(tested);
        await new Promise(r => setTimeout(r, 0));
      }
      if (millerRabin(candidate)) { onCandidate(tested); return candidate; }
    }
  };

  let p, q, n, phi;
  do {
    p = await findPrime();
    q = await findPrime();
    n = p * q;
    phi = (p - 1n) * (q - 1n);
  } while (p === q || n.toString(2).length < bits - 4);

  const e = 65537n;
  return { publicKey: { e, n }, privateKey: { d: modInverse(e, phi), n } };
}

/* ───────────── messages ───────────── */

function avatarNode(username, avatarDataUrl) {
  const name = (username || '?').trim();
  if (avatarDataUrl) {
    const img = document.createElement('img');
    img.className = 'avatar';
    img.src = avatarDataUrl;
    img.alt = '';
    return img;
  }
  const div = document.createElement('div');
  div.className = 'avatar avatar-fallback';
  div.style.background = colorFor(name);
  div.textContent = name.charAt(0).toUpperCase() || '?';
  return div;
}

function iconButton(cls, title, path) {
  const b = document.createElement('button');
  b.className = cls;
  b.title = title;
  b.type = 'button';
  b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${path}</svg>`;
  return b;
}
const PENCIL = '<path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"/>';
const TRASH  = '<path d="M4 7h16M9 7V5h6v2M7 7l1 13h8l1-13"/>';

function scrollDown() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}

function buildRow(id, username, avatarDataUrl, mine, allowEdit) {
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' mine' : '');
  if (lastSender === username) row.classList.add('grouped');
  lastSender = username;
  row.dataset.id = id;
  row.appendChild(avatarNode(username, avatarDataUrl));

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  row.appendChild(bubble);

  if (mine) {
    const actions = document.createElement('span');
    actions.className = 'msg-actions';
    if (allowEdit) {
      const edit = iconButton('editBtn', 'Edit', PENCIL);
      edit.addEventListener('click', () => startEdit(id));
      actions.appendChild(edit);
    }
    const del = iconButton('delBtn', 'Delete for everyone', TRASH);
    del.addEventListener('click', () => deleteMessage(id));
    actions.appendChild(del);
    row.appendChild(actions);

    // no hover on a phone, so tapping your own bubble reveals the
    // edit/delete controls instead of them always crowding the message
    bubble.addEventListener('click', () => {
      if (!window.matchMedia('(max-width: 760px)').matches) return;
      document.querySelectorAll('.msg-row.show-actions')
        .forEach(r => { if (r !== row) r.classList.remove('show-actions'); });
      row.classList.toggle('show-actions');
    });
  }

  $('messages').appendChild(row);
  scrollDown();
  messageEls[id] = row;
  return bubble;
}

function addMessage(id, username, avatarDataUrl, text, mine) {
  const bubble = buildRow(id, username, avatarDataUrl, mine, true);

  const who = document.createElement('span');
  who.className = 'msg-user';
  who.textContent = username;
  bubble.appendChild(who);

  const body = document.createElement('span');
  body.className = 'msg-text';
  body.textContent = text;
  bubble.appendChild(body);

  const meta = document.createElement('span');
  meta.className = 'msg-meta';
  meta.textContent = clockTime();
  bubble.appendChild(meta);
}

// file: { name, mime, bytes } — already decrypted
function addFileMessage(id, username, avatarDataUrl, file, mine) {
  const bubble = buildRow(id, username, avatarDataUrl, mine, false);

  const who = document.createElement('span');
  who.className = 'msg-user';
  who.textContent = username;
  bubble.appendChild(who);

  const url = URL.createObjectURL(
    new Blob([file.bytes], { type: file.mime || 'application/octet-stream' })
  );

  const wrap = document.createElement('div');
  wrap.className = 'file-att';

  if ((file.mime || '').startsWith('image/')) {
    const img = document.createElement('img');
    img.className = 'file-img';
    img.src = url;
    img.alt = file.name;
    img.addEventListener('load', scrollDown);
    wrap.appendChild(img);
  }

  const link = document.createElement('a');
  link.className = 'file-link';
  link.href = url;
  link.download = file.name;
  link.innerHTML = '<span></span><span class="file-size"></span>';
  link.querySelector('span').textContent = file.name;
  link.querySelector('.file-size').textContent = formatSize(file.bytes.length);
  wrap.appendChild(link);

  bubble.appendChild(wrap);
}

function log(msg, crypto_) {
  const div = document.createElement('div');
  div.className = 'system-line' + (crypto_ ? ' crypto' : '');
  div.textContent = msg;
  $('messages').appendChild(div);
  lastSender = null;
  scrollDown();
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
  input.setSelectionRange(current.length, current.length);

  let done = false;
  const finish = (save) => {
    if (done) return;
    done = true;
    const next = input.value;
    input.replaceWith(textSpan);
    if (!save || !next.trim() || next === current) return;
    textSpan.textContent = next;
    markEdited(row);
    const { iv, cipher } = encryptText(next);
    send({ type: 'edit', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) });
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') finish(true);
    if (e.key === 'Escape') finish(false);
  });
  input.addEventListener('blur', () => finish(true));
}

function markEdited(row) {
  const meta = row.querySelector('.msg-meta');
  if (meta && !meta.textContent.includes('edited')) meta.textContent += ' · edited';
}

function deleteMessage(id) {
  if (!confirm('Delete this message for everyone in the room?')) return;
  applyDelete(id);
  send({ type: 'delete', id });
}

function applyDelete(id) {
  const row = messageEls[id];
  if (!row) return;
  row.querySelector('.bubble').innerHTML = '<span class="msg-deleted">Message deleted</span>';
  const actions = row.querySelector('.msg-actions');
  if (actions) actions.remove();
}

function applyEdit(id, text) {
  const row = messageEls[id];
  if (!row) return;
  const textSpan = row.querySelector('.msg-text');
  if (!textSpan) return;   // deleted, or a file
  textSpan.textContent = text;
  markEdited(row);
}

/* ───────────── wire tape ───────────── */

function showWireTraffic(direction, obj) {
  const s = JSON.stringify(obj);
  const line = document.createElement('div');
  line.className = 'wire-line' + (direction === 'in' ? ' in' : '');
  line.dataset.dir = direction === 'in' ? '<' : '>';
  line.textContent = s.slice(0, 150) + (s.length > 150 ? '…' : '');
  $('wire').prepend(line);
  while ($('wire').children.length > 14) $('wire').removeChild($('wire').lastChild);
}

function send(payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(payload));
  showWireTraffic('out', payload);
}

/* ───────────── room list ───────────── */

const PHONE = '<path d="M6.5 3h3l1.5 4-2 1.5a12 12 0 0 0 6.5 6.5L17 13l4 1.5v3a2 2 0 0 1-2.2 2A16.5 16.5 0 0 1 4 5.2 2 2 0 0 1 6.5 3"/>';
const CAM   = '<rect x="3" y="6" width="12" height="12" rx="2"/><path d="m15 11 6-3.5v9L15 13"/>';

function refreshUserList() {
  const list = $('userList');
  list.innerHTML = '';
  const total = Object.keys(users).length + 1;
  $('userCount').textContent = total;
  $('topbarPeople').textContent = total === 1 ? 'Only you here' : `${total} people here`;

  const meLi = document.createElement('li');
  meLi.appendChild(avatarNode(myName, myAvatar));
  const meId = document.createElement('span');
  meId.className = 'user-id';
  meId.innerHTML = '<span class="user-name"></span><span class="user-fp mono"></span>';
  meId.querySelector('.user-name').innerHTML =
    `${escapeHtml(myName)} <span class="you-tag">you</span>`;
  meId.querySelector('.user-fp').textContent = myFingerprint;
  meLi.appendChild(meId);
  list.appendChild(meLi);

  for (const cid in users) {
    const u = users[cid];
    const li = document.createElement('li');
    li.appendChild(avatarNode(u.username, u.avatar));

    const id = document.createElement('span');
    id.className = 'user-id';
    id.innerHTML = '<span class="user-name"></span><span class="user-fp mono"></span>';
    id.querySelector('.user-name').textContent = u.username;
    id.querySelector('.user-fp').textContent = u.fp || '';
    li.appendChild(id);

    const btns = document.createElement('span');
    btns.className = 'call-btns';
    const a = iconButton('', `Voice call ${u.username}`, PHONE);
    a.addEventListener('click', () => { closeRail(); startCall(Number(cid), false); });
    const v = iconButton('', `Video call ${u.username}`, CAM);
    v.addEventListener('click', () => { closeRail(); startCall(Number(cid), true); });
    btns.append(a, v);
    li.appendChild(btns);

    list.appendChild(li);
  }
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/* ───────────── profile picture ───────────── */

function shrinkAvatar(file) {
  return new Promise((resolve) => {
    if (!file) { resolve(null); return; }
    const img = new Image();
    const reader = new FileReader();
    reader.onload = () => {
      img.onload = () => {
        const size = 64;
        const canvas = document.createElement('canvas');
        canvas.width = canvas.height = size;
        const ctx = canvas.getContext('2d');
        const side = Math.min(img.width, img.height);
        ctx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, size, size);
        resolve(canvas.toDataURL('image/jpeg', 0.7));
      };
      img.onerror = () => resolve(null);
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

$('avatarInput').addEventListener('change', async (e) => {
  myAvatar = await shrinkAvatar(e.target.files[0]);
  $('avatarPreview').src = myAvatar || '';
  $('avatarPreview').classList.toggle('hidden', !myAvatar);
  $('avatarInitial').classList.toggle('hidden', !!myAvatar);
});

$('username').addEventListener('input', (e) => {
  const v = e.target.value.trim();
  $('avatarInitial').textContent = v ? v.charAt(0).toUpperCase() : '?';
});

/* ───────────── files ───────────── */

function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result));
    r.onerror = () => reject(r.error);
    r.readAsArrayBuffer(file);
  });
}

// inside the AES blob: [2-byte header length][JSON {name,mime}][raw bytes]
// so the filename is encrypted too, not just the contents
function packFile(name, mime, bytes) {
  const header = new TextEncoder().encode(JSON.stringify({ name, mime }));
  const out = new Uint8Array(2 + header.length + bytes.length);
  out[0] = (header.length >> 8) & 0xff;
  out[1] = header.length & 0xff;
  out.set(header, 2);
  out.set(bytes, 2 + header.length);
  return out;
}
function unpackFile(blob) {
  const len = (blob[0] << 8) | blob[1];
  const h = JSON.parse(new TextDecoder().decode(blob.slice(2, 2 + len)));
  return {
    name: h.name || 'file',
    mime: h.mime || 'application/octet-stream',
    bytes: blob.slice(2 + len),
  };
}

async function sendFile(file) {
  if (!file) return;
  if (!sessionKey) { toast('Still waiting for the session key'); return; }
  if (file.size > MAX_FILE_BYTES) {
    toast(`${formatSize(file.size)} is over the ${formatSize(MAX_FILE_BYTES)} limit`);
    return;
  }

  toast(`Encrypting ${file.name}`);
  const bytes = await readFileBytes(file);
  const { iv, cipher } = aesCbcEncrypt(packFile(file.name, file.type, bytes), sessionKey);
  const id = newMsgId();

  ws.send(JSON.stringify({ type: 'file', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) }));
  showWireTraffic('out', { type: 'file', id, iv: bytesToHex(iv), ciphertext: `<${cipher.length} bytes>` });

  addFileMessage(id, myName, myAvatar, { name: file.name, mime: file.type, bytes }, true);
}

$('fileInput').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  e.target.value = '';
  await sendFile(f);
});

// drag a file anywhere over the chat, or paste a screenshot
const stage = () => document.querySelector('.stage');
['dragenter', 'dragover'].forEach(ev =>
  document.addEventListener(ev, (e) => {
    if (!sessionKey || $('chatScreen').classList.contains('hidden')) return;
    if (![...(e.dataTransfer?.types || [])].includes('Files')) return;
    e.preventDefault();
    $('dropHint').classList.remove('hidden');
  })
);
['dragleave', 'drop'].forEach(ev =>
  document.addEventListener(ev, (e) => {
    if (ev === 'dragleave' && e.relatedTarget) return;
    $('dropHint').classList.add('hidden');
  })
);
document.addEventListener('drop', async (e) => {
  if (!sessionKey || $('chatScreen').classList.contains('hidden')) return;
  if (!e.dataTransfer?.files?.length) return;
  e.preventDefault();
  await sendFile(e.dataTransfer.files[0]);
});
document.addEventListener('paste', async (e) => {
  if (!sessionKey || $('chatScreen').classList.contains('hidden')) return;
  const item = [...(e.clipboardData?.items || [])].find(i => i.kind === 'file');
  if (!item) return;
  await sendFile(item.getAsFile());
});

/* ───────────── room panel (drawer on phones) ───────────── */

function openRail()  { $('rail').classList.add('open');    $('railScrim').classList.remove('hidden'); }
function closeRail() { $('rail').classList.remove('open'); $('railScrim').classList.add('hidden'); }

$('railToggle').addEventListener('click', openRail);
$('railScrim').addEventListener('click', closeRail);

$('copyRoomBtn').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(currentRoomId);
    toast('Room ID copied');
  } catch {
    toast(currentRoomId);
  }
});

$('leaveBtn').addEventListener('click', () => {
  if (!confirm('Leave this room? Messages are not stored anywhere, so this clears them.')) return;
  location.reload();
});

/* ───────────── connect ───────────── */

$('diceBtn').addEventListener('click', () => {
  const words = ['amber', 'cipher', 'delta', 'ember', 'harbor', 'indigo', 'jasper', 'kite',
                 'lantern', 'meridian', 'onyx', 'quartz', 'relay', 'sable', 'tundra', 'vector'];
  const pick = () => words[Math.floor(Math.random() * words.length)];
  $('roomId').value = `${pick()}-${pick()}-${Math.floor(Math.random() * 90 + 10)}`;
});

$('revealBtn').addEventListener('click', () => {
  const f = $('roomPassword');
  const show = f.type === 'password';
  f.type = show ? 'text' : 'password';
  $('revealBtn').textContent = show ? 'Hide' : 'Show';
});

async function connect(mode) {
  const username = $('username').value.trim();
  const roomId = $('roomId').value.trim();
  const password = $('roomPassword').value;

  if (!username) { toast('Pick a display name first'); $('username').focus(); return; }
  if (!roomId)   { toast('Enter a room ID'); $('roomId').focus(); return; }
  if (!password) { toast('Enter the room password'); $('roomPassword').focus(); return; }
  if (!window.crypto || !crypto.subtle) {
    toast('Open this on http://localhost:8000, not the file:// path');
    return;
  }

  myName = username;
  currentRoomId = roomId;
  joinMode = mode;
  $('createPasswordBtn').disabled = true;
  $('enterPasswordBtn').disabled = true;

  hideReadoutSteps();
  setReadout('Minting keypair', 'testing candidates…',
    'Two 512-bit primes, found by Miller-Rabin in this tab. Nothing is sent yet.');
  await new Promise(r => setTimeout(r, 40));

  myKeys = await mintKeyPair(1024, (tested) => {
    $('readoutTicker').textContent = `${tested} candidates tested`;
  });
  myFingerprint = await fingerprint(myKeys.publicKey);
  showModulus(myKeys.publicKey.n);
  setReadout('Key ready', `fingerprint ${myFingerprint}`,
    'That is your public modulus. The matching private exponent stays in this tab and is never sent.');

  const key = await roomKey(roomId, password);

  setReadout('Connecting', `room ${key.slice(0, 8)}…`,
    'The server only ever sees this hash — not the room ID, not the password.');

  ws = new WebSocket(SERVER_URL);

  ws.onopen = () => {
    const join = {
      type: 'join', username, room: key,
      pubkey: pubKeyToJSON(myKeys.publicKey),
      avatar: myAvatar,
    };
    ws.send(JSON.stringify(join));
    showWireTraffic('out', { ...join, room: key.slice(0, 12) + '…',
      pubkey: '<RSA-1024 public key>', avatar: myAvatar ? '<image>' : null });
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    showWireTraffic('in', summariseForWire(data));
    handleMessage(data);
  };

  ws.onclose = () => {
    $('createPasswordBtn').disabled = false;
    $('enterPasswordBtn').disabled = false;
    setReadout('Disconnected', '', 'The connection closed. Reload to try again.');
    if (!$('chatScreen').classList.contains('hidden')) {
      log('Disconnected from the server');
      $('railRoomState').textContent = 'Disconnected';
    }
  };

  ws.onerror = () => {
    setReadout('Cannot reach server', '', 'Check that server.py is running and the URL in app.js matches it.');
  };
}

function summariseForWire(data) {
  if (data.type === 'file') return { ...data, ciphertext: `<${data.ciphertext.length / 2} bytes>` };
  if (data.type === 'welcome') return { ...data, users: `<${data.users.length} peers>` };
  if (data.type === 'user_joined') return { ...data, pubkey: '<RSA-1024 public key>', avatar: data.avatar ? '<image>' : null };
  if (data.type === 'call_offer' || data.type === 'call_answer') return { ...data, sdp: '<SDP>' };
  return data;
}

/* ───────────── incoming ───────────── */

function handleMessage(data) {
  if (['call_offer', 'call_answer', 'call_ice', 'call_reject', 'call_end'].includes(data.type)) {
    handleCallSignal(data);
    return;
  }

  switch (data.type) {
    case 'welcome': {
      myId = data.id;
      enterChat();

      if (data.users.length === 0) {
        sessionKey = randomBytes(16);
        $('railRoomState').textContent = 'You hold the session key';
        log(joinMode === 'create'
          ? 'Room created. A fresh AES-128 session key was generated in this tab — share the room ID and password to let others in.'
          : 'Nobody here yet, so you are first in and a fresh AES-128 session key was generated in this tab.', true);
      } else {
        $('railRoomState').textContent = 'Waiting for the session key';
        Promise.all(data.users.map(async (u) => {
          const pub = pubKeyFromJSON(u.pubkey);
          users[u.id] = { username: u.username, pubkey: pub, avatar: u.avatar, fp: await fingerprint(pub) };
        })).then(refreshUserList);
        log('Waiting for someone already in the room to hand over the session key…', true);
      }
      refreshUserList();
      break;
    }

    case 'user_joined': {
      const pub = pubKeyFromJSON(data.pubkey);
      fingerprint(pub).then((fp) => {
        users[data.id] = { username: data.username, pubkey: pub, avatar: data.avatar, fp };
        refreshUserList();
      });
      log(`${data.username} joined`);

      if (sessionKey) {
        const encInt = rsaEncryptInt(bytesToBigInt(sessionKey), pub);
        send({ type: 'key_exchange', to: data.id, encKey: encInt.toString() });
        log(`Session key wrapped with ${data.username}'s public key and sent`, true);
      }
      break;
    }

    case 'key_exchange': {
      if (!sessionKey) {
        sessionKey = bigIntToBytes(rsaDecryptInt(BigInt(data.encKey), myKeys.privateKey), 16);
        $('railRoomState').textContent = 'Session key received';
        log('Session key arrived RSA-wrapped and was unwrapped with your private key', true);
      }
      break;
    }

    case 'msg': {
      const av = users[data.from] && users[data.from].avatar;
      if (!sessionKey) {
        addMessage(data.id, data.username, av, '[no session key yet — cannot decrypt]', false);
        break;
      }
      addMessage(data.id, data.username, av, decryptText(data.iv, data.ciphertext), false);
      break;
    }

    case 'file': {
      const av = users[data.from] && users[data.from].avatar;
      if (!sessionKey) {
        addMessage(data.id, data.username, av, '[a file arrived before the session key]', false);
        break;
      }
      try {
        const packed = aesCbcDecrypt(hexToBytes(data.ciphertext), sessionKey, hexToBytes(data.iv));
        addFileMessage(data.id, data.username, av, unpackFile(packed), false);
      } catch {
        addMessage(data.id, data.username, av, '[that file would not decrypt]', false);
      }
      break;
    }

    case 'edit': {
      if (sessionKey) applyEdit(data.id, decryptText(data.iv, data.ciphertext));
      break;
    }

    case 'delete': applyDelete(data.id); break;

    case 'user_left': {
      const u = users[data.id];
      if (u) log(`${u.username} left`);
      delete users[data.id];
      refreshUserList();
      if (typeof callPeerId !== 'undefined' && callPeerId === data.id) teardownCall();
      break;
    }
  }
}

function enterChat() {
  $('loginScreen').classList.add('hidden');
  $('chatScreen').classList.remove('hidden');
  $('railRoomId').textContent = currentRoomId;
  $('topbarRoom').textContent = currentRoomId;
  $('messageInput').focus();
}

/* ───────────── sending ───────────── */

$('composer').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('messageInput');
  const text = input.value;
  if (!text.trim() || !ws || ws.readyState !== WebSocket.OPEN) return;
  if (!sessionKey) { toast('Still waiting for the session key'); return; }

  const id = newMsgId();
  const { iv, cipher } = encryptText(text);
  send({ type: 'msg', id, iv: bytesToHex(iv), ciphertext: bytesToHex(cipher) });
  addMessage(id, myName, myAvatar, text, true);
  input.value = '';
});

$('createPasswordBtn').addEventListener('click', () => connect('create'));
$('enterPasswordBtn').addEventListener('click', () => connect('join'));
$('username').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('roomId').focus(); });
$('roomId').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('roomPassword').focus(); });
$('roomPassword').addEventListener('keydown', (e) => { if (e.key === 'Enter') connect('join'); });

checkSecureContext();
setReadout('Before you connect', '', 'Nothing has been sent yet.');