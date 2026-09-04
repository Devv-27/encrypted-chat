/*
 * AES-128 implemented from the spec (FIPS-197), not pulled from a library.
 * State is a flat 16-byte array laid out column-major, same as the spec:
 * index = row + 4*col.
 *
 * Only the pieces we actually need are here: key expansion, single block
 * encrypt/decrypt, and CBC mode with PKCS7 padding on top. This is fine
 * for a learning project but skips things a real implementation needs
 * (constant-time ops, authenticated encryption, key derivation from a
 * password, etc). See README for the honest list of what's missing.
 */

const SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

// build the inverse table from SBOX instead of typing out a second
// 256-entry table by hand and risking a transcription error somewhere
const INV_SBOX = new Array(256);
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

const RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]; // index 0 unused

function rotWord(w) { return [w[1], w[2], w[3], w[0]]; }
function subWord(w) { return w.map(b => SBOX[b]); }

function keyExpansion(key) {
  const Nk = 4, Nr = 10, Nb = 4;
  const w = new Array(Nb * (Nr + 1));
  for (let i = 0; i < Nk; i++) {
    w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
  }
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1].slice();
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp));
      temp[0] ^= RCON[i / Nk];
    }
    w[i] = w[i - Nk].map((b, idx) => b ^ temp[idx]);
  }
  return w;
}

function addRoundKey(state, w, round) {
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      state[r + 4*c] ^= w[4*round + c][r];
    }
  }
}

function subBytes(state)    { for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]]; }
function invSubBytes(state) { for (let i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]]; }

function shiftRows(state) {
  const s = state.slice();
  for (let r = 1; r < 4; r++)
    for (let c = 0; c < 4; c++)
      state[r + 4*c] = s[r + 4*((c + r) % 4)];
}

function invShiftRows(state) {
  const s = state.slice();
  for (let r = 1; r < 4; r++)
    for (let c = 0; c < 4; c++)
      state[r + 4*c] = s[r + 4*((c - r + 4) % 4)];
}

// multiply in GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1
function gmul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

function mixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const a0 = state[4*c], a1 = state[1+4*c], a2 = state[2+4*c], a3 = state[3+4*c];
    state[4*c]   = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
    state[1+4*c] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
    state[2+4*c] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
    state[3+4*c] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
  }
}

function invMixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const a0 = state[4*c], a1 = state[1+4*c], a2 = state[2+4*c], a3 = state[3+4*c];
    state[4*c]   = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
    state[1+4*c] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
    state[2+4*c] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
    state[3+4*c] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
  }
}

function encryptBlock(input, w) {
  const state = Uint8Array.from(input);
  addRoundKey(state, w, 0);
  for (let round = 1; round < 10; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, w, round);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, w, 10);
  return state;
}

function decryptBlock(input, w) {
  const state = Uint8Array.from(input);
  addRoundKey(state, w, 10);
  for (let round = 9; round >= 1; round--) {
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, w, round);
    invMixColumns(state);
  }
  invShiftRows(state);
  invSubBytes(state);
  addRoundKey(state, w, 0);
  return state;
}

function pkcs7Pad(bytes) {
  const padLen = 16 - (bytes.length % 16);
  const out = new Uint8Array(bytes.length + padLen);
  out.set(bytes);
  out.fill(padLen, bytes.length);
  return out;
}

function pkcs7Unpad(bytes) {
  const padLen = bytes[bytes.length - 1];
  if (padLen < 1 || padLen > 16) return bytes; // not padded how we expect, bail out safely
  return bytes.slice(0, bytes.length - padLen);
}

function randomBytes(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return arr;
}

// returns { iv, cipher } as Uint8Arrays. fresh random IV every call.
function aesCbcEncrypt(plainBytes, key) {
  const w = keyExpansion(key);
  const iv = randomBytes(16);
  const padded = pkcs7Pad(plainBytes);
  const cipher = new Uint8Array(padded.length);
  let prev = iv;
  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.slice(i, i + 16);
    const xored = block.map((b, idx) => b ^ prev[idx]);
    const enc = encryptBlock(xored, w);
    cipher.set(enc, i);
    prev = enc;
  }
  return { iv, cipher };
}

function aesCbcDecrypt(cipherBytes, key, iv) {
  const w = keyExpansion(key);
  const plain = new Uint8Array(cipherBytes.length);
  let prev = iv;
  for (let i = 0; i < cipherBytes.length; i += 16) {
    const block = cipherBytes.slice(i, i + 16);
    const dec = decryptBlock(block, w);
    const xored = dec.map((b, idx) => b ^ prev[idx]);
    plain.set(xored, i);
    prev = block;
  }
  return pkcs7Unpad(plain);
}
