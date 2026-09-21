/*
 * Helpers shared by the chat page (app.js)
 * and the secretary console (secretary.js).
 * Loaded after rsa.js and aes.js.
 *
 * Crypto split:
 * Hand-written RSA (rsa.js) and AES-128-CBC (aes.js)
 * encrypt messages, files, photos and session keys.
 *
 * Browser crypto.subtle is used only for SHA-256
 * and PBKDF2 to derive the room hash and wrapping key.
 */

const $ = (id) => document.getElementById(id);

/* ───────────── byte helpers ───────────── */

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return out;
}

function bytesToBigInt(bytes) {
  return BigInt('0x' + bytesToHex(bytes));
}

function bigIntToBytes(num, len) {
  let hex = num.toString(16);

  while (hex.length < len * 2) {
    hex = '0' + hex;
  }

  return hexToBytes(hex);
}

function pubKeyToJSON(pub) {
  return {
    e: pub.e.toString(),
    n: pub.n.toString()
  };
}

function pubKeyFromJSON(o) {
  return {
    e: BigInt(o.e),
    n: BigInt(o.n)
  };
}

function newMsgId() {
  return (
    crypto.randomUUID
      ? crypto.randomUUID()
      : Date.now() + '-' + Math.random().toString(16).slice(2)
  );
}

/* ───────────── hashing and key derivation ───────────── */

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(str)
  );

  return bytesToHex(new Uint8Array(buf));
}

async function pbkdf2(secret, salt, iterations, byteLength) {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(salt),
      iterations
    },
    base,
    byteLength * 8
  );

  return new Uint8Array(bits);
}

/*
 * One password -> two unrelated outputs:
 *
 * hash:
 *   What the server sees.
 *
 * wrapKey:
 *   Never leaves the browser.
 *   Used to wrap the room session key.
 */

async function deriveRoom(roomId, password) {
  const secret =
    roomId.trim().toLowerCase() +
    '\u0000' +
    password;

  const [hash, wrapKey] = await Promise.all([
    pbkdf2(
      secret,
      'encchat/room-id/v2',
      120000,
      32
    ),

    pbkdf2(
      secret,
      'encchat/room-key/v2',
      120000,
      16
    )
  ]);

  return {
    hash: bytesToHex(hash),
    wrapKey
  };
}

/* ───────────── key checking ───────────── */

async function keyCheck(key) {
  return (
    await sha256Hex(bytesToHex(key))
  ).slice(0, 8);
}

/* ───────────── public-key fingerprint ───────────── */

async function fingerprint(pub) {
  const hex = await sha256Hex(
    pub.n.toString(16)
  );

  return (
    hex.slice(0, 4) +
    ' ' +
    hex.slice(4, 8)
  );
}

/* ───────────── AES wrappers ───────────── */

function wrapWithKey(bytes, key) {
  const { iv, cipher } = aesCbcEncrypt(
    bytes,
    key
  );

  return {
    iv: bytesToHex(iv),
    ct: bytesToHex(cipher)
  };
}

function unwrapWithKey(blob, key) {
  return aesCbcDecrypt(
    hexToBytes(blob.ct),
    key,
    hexToBytes(blob.iv)
  );
}

function encryptStringWith(key, text) {
  return wrapWithKey(
    new TextEncoder().encode(text),
    key
  );
}

function decryptStringWith(key, blob) {
  return new TextDecoder().decode(
    unwrapWithKey(blob, key)
  );
}

/* ───────────── RSA key generation with progress ───────────── */

/*
 * Same algorithm as rsa.js, but split into async
 * chunks so the browser stays responsive and can
 * report how many prime candidates were tested.
 */

async function mintKeyPair(bits, onCandidate) {
  const half = bits / 2;
  let tested = 0;

  const findPrime = async () => {
    for (;;) {
      const candidate = bigRandomBits(half);

      tested++;

      if (tested % 4 === 0) {
        if (onCandidate) {
          onCandidate(tested);
        }

        await new Promise(r => setTimeout(r, 0));
      }

      if (millerRabin(candidate)) {
        if (onCandidate) {
          onCandidate(tested);
        }

        return candidate;
      }
    }
  };

  let p, q, n, phi;

  do {
    p = await findPrime();
    q = await findPrime();

    n = p * q;
    phi = (p - 1n) * (q - 1n);

  } while (
    p === q ||
    n.toString(2).length < bits - 4
  );

  const e = 65537n;

  return {
    publicKey: {
      e,
      n
    },

    privateKey: {
      d: modInverse(e, phi),
      n
    }
  };
}

/* ───────────── UI helpers ───────────── */

function formatSize(n) {
  if (n < 1024) {
    return n + ' B';
  }

  if (n < 1024 * 1024) {
    return (n / 1024).toFixed(1) + ' KB';
  }

  return (
    n / (1024 * 1024)
  ).toFixed(1) + ' MB';
}

function clockTime(ts) {
  const d = ts
    ? new Date(ts * 1000)
    : new Date();

  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit'
  });
}

function dayKey(ts) {
  const d = ts
    ? new Date(ts * 1000)
    : new Date();

  return (
    d.getFullYear() +
    '-' +
    d.getMonth() +
    '-' +
    d.getDate()
  );
}

function dayLabel(ts) {
  const d = ts
    ? new Date(ts * 1000)
    : new Date();

  const today = new Date();

  const yest = new Date();
  yest.setDate(today.getDate() - 1);

  if (
    dayKey(ts) ===
    dayKey(today.getTime() / 1000)
  ) {
    return 'Today';
  }

  if (
    dayKey(ts) ===
    dayKey(yest.getTime() / 1000)
  ) {
    return 'Yesterday';
  }

  return d.toLocaleDateString([], {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric'
  });
}

function dateTimeLabel(ts) {
  return new Date(ts * 1000)
    .toLocaleString([], {
      day: 'numeric',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit'
    });
}

/* ───────────── stable colour per username ───────────── */

function colorFor(name) {
  let h = 0;

  for (let i = 0; i < name.length; i++) {
    h =
      (h * 31 +
        name.charCodeAt(i)) %
      360;
  }

  return `hsl(${h} 52% 68%)`;
}

/* ───────────── HTML escaping ───────────── */

function escapeHtml(s) {
  const d = document.createElement('div');

  d.textContent = s;

  return d.innerHTML;
}

/* ───────────── toast ───────────── */

let toastTimer = null;

function toast(msg) {
  const el = $('toast');

  if (!el) return;

  el.textContent = msg;
  el.classList.remove('hidden');

  clearTimeout(toastTimer);

  toastTimer = setTimeout(
    () => el.classList.add('hidden'),
    2600
  );
}

/* ───────────── safe localStorage ───────────── */

const safeStore = {
  get(k) {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },

  set(k, v) {
    try {
      localStorage.setItem(k, v);
    } catch {
      /* ignore */
    }
  },

  del(k) {
    try {
      localStorage.removeItem(k);
    } catch {
      /* ignore */
    }
  }
};

/* ───────────── browser identity ───────────── */

/*
 * Random ID that stays with this browser.
 *
 * The server stores only its SHA-256 hash,
 * allowing it to recognise the browser after
 * reload without requiring an account.
 */

function browserKey() {
  let k =
    safeStore.get('encchat.browserKey');

  if (!k || k.length < 16) {
    k = bytesToHex(
      randomBytes(16)
    );

    safeStore.set(
      'encchat.browserKey',
      k
    );
  }

  return k;
}

/* ───────────── wax seal ───────────── */

const SEAL_PATH =
  'M108.4 60C107.5 67.2 104.9 73.6 102.2 80.3C99.5 87 97.3 96 92 100.2C86.7 104.3 77.5 103.5 70.3 105C63.1 106.5 55.6 110.2 48.8 109.1C42 107.9 34.6 103 29.6 98.1C24.5 93.3 21.8 86.3 18.5 80C15.3 73.6 9.9 66.6 9.9 60C10 53.4 15.5 46.5 18.7 40.1C21.9 33.7 24 25.6 29.2 21.4C34.4 17.2 42.9 16.1 49.7 15C56.6 13.9 63.5 13.8 70.3 14.8C77.1 15.9 84.5 17.7 90.8 21.4C97 25.1 104.8 30.6 107.7 37C110.6 43.5 109.3 52.8 108.4 60Z';

/*
 * Two identical halves stacked.
 * Whole = sealed.
 * `.broken` slides them apart.
 */

function sealMarkup() {
  const face =
    `<svg viewBox="0 0 120 120" aria-hidden="true">` +

    `<path d="${SEAL_PATH}" fill="var(--wax)"/>` +

    `<path d="${SEAL_PATH}"
      fill="none"
      stroke="rgba(255,255,255,.18)"
      stroke-width="1.5"
      transform="translate(-1 -1)"/>` +

    `<circle
      cx="60"
      cy="60"
      r="35"
      fill="none"
      stroke="rgba(40,8,2,.32)"
      stroke-width="2.5"/>` +

    `<g
      fill="none"
      stroke="rgba(52,10,3,.62)"
      stroke-width="4.2"
      stroke-linecap="round"
      stroke-linejoin="round">` +

    `<rect
      x="46"
      y="58"
      width="28"
      height="19"
      rx="4"/>` +

    `<path d="M52 58v-6.5a8 8 0 0 1 16 0V58"/>` +

    `</g>` +

    `</svg>`;

  return `
    <span class="seal">
      <span class="seal-half a">${face}</span>
      <span class="seal-half b">${face}</span>
    </span>
  `;
}