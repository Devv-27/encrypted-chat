/*
 * Minimal RSA, built on native BigInt. This is NOT used to encrypt chat
 * messages directly - it's only used once per new member to wrap the
 * 16-byte AES session key so it can be handed over safely. Real RSA
 * implementations use OAEP padding and constant-time modpow; this one
 * doesn't, so don't reuse it for anything beyond this project.
 */

function bigRandomBits(bits) {
  const bytes = new Uint8Array(bits / 8);
  crypto.getRandomValues(bytes);
  bytes[0] |= 0x80; // force top bit so the number actually has `bits` bits
  bytes[bytes.length - 1] |= 1; // make it odd, saves a few iterations later
  let hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return BigInt('0x' + hex);
}

function modPow(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function randomInRange(min, max) {
  const range = max - min;
  const bits = range.toString(2).length;
  let r;
  do {
    r = bigRandomBits(Math.ceil(bits / 8) * 8) % (range + 1n);
  } while (r > range);
  return min + r;
}

function millerRabin(n, rounds = 20) {
  if (n < 2n) return false;
  for (const p of [2n,3n,5n,7n,11n,13n,17n,19n,23n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let r = 0n, d = n - 1n;
  while (d % 2n === 0n) { d /= 2n; r++; }
  witnessLoop:
  for (let i = 0; i < rounds; i++) {
    const a = randomInRange(2n, n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function randomPrime(bits) {
  while (true) {
    const candidate = bigRandomBits(bits);
    if (millerRabin(candidate)) return candidate;
  }
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

function modInverse(a, m) {
  const [g, x] = egcd(a % m, m);
  if (g !== 1n) throw new Error('modInverse: not coprime');
  return ((x % m) + m) % m;
}

// bits = total modulus size (e.g. 1024). Runs entirely client-side.
function generateRSAKeyPair(bits = 1024) {
  const half = bits / 2;
  let p, q, n, phi;
  do {
    p = randomPrime(half);
    q = randomPrime(half);
    n = p * q;
    phi = (p - 1n) * (q - 1n);
  } while (p === q || n.toString(2).length < bits - 4);
  const e = 65537n;
  const d = modInverse(e, phi);
  return {
    publicKey: { e, n },
    privateKey: { d, n },
  };
}

function rsaEncryptInt(m, pub) { return modPow(m, pub.e, pub.n); }
function rsaDecryptInt(c, priv) { return modPow(c, priv.d, priv.n); }
