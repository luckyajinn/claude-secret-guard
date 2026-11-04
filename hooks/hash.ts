// A small SHA-256, because the hooks module has no Node and no crypto. It is
// used for one thing: a short fingerprint that tells two findings apart (and
// lets the person allowlist one) without the mod ever storing or printing the
// value itself.

const primes = (count: number): number[] => {
  const found: number[] = []

  for (let n = 2; found.length < count; n += 1) {
    if (found.every(p => n % p !== 0)) {
      found.push(n)
    }
  }

  return found
}

const frac = (x: number): number => Math.floor((x - Math.floor(x)) * 4294967296)

// The standard constants: the first 32 bits of the fractional parts of the
// cube roots (K) and square roots (H0) of the first primes.
const K = primes(64).map(p => frac(Math.cbrt(p)))
const H0 = primes(8).map(p => frac(Math.sqrt(p)))

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n))

// Reads a number out of a list that is known to be long enough.
const at = (list: readonly number[], index: number): number => list[index] ?? 0

const utf8 = (text: string): number[] => {
  const out: number[] = []

  for (let i = 0; i < text.length; i += 1) {
    let c = text.charCodeAt(i)

    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1)

      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00)
        i += 1
      }
    }

    if (c < 0x80) {
      out.push(c)
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
    } else if (c < 0x10000) {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    } else {
      out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
    }
  }

  return out
}

/** The SHA-256 of the text's UTF-8 bytes, as 64 lowercase hex digits. */
export const sha256 = (text: string): string => {
  const bytes = utf8(text)
  const bitLength = bytes.length * 8

  bytes.push(0x80)

  while (bytes.length % 64 !== 56) {
    bytes.push(0)
  }

  const high = Math.floor(bitLength / 4294967296)
  const low = bitLength >>> 0

  for (let shift = 24; shift >= 0; shift -= 8) {
    bytes.push((high >>> shift) & 255)
  }

  for (let shift = 24; shift >= 0; shift -= 8) {
    bytes.push((low >>> shift) & 255)
  }

  const h = H0.slice()
  const w = new Array<number>(64).fill(0)

  for (let offset = 0; offset < bytes.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 4

      w[i] = (at(bytes, j) << 24) | (at(bytes, j + 1) << 16) | (at(bytes, j + 2) << 8) | at(bytes, j + 3)
    }

    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(at(w, i - 15), 7) ^ rotr(at(w, i - 15), 18) ^ (at(w, i - 15) >>> 3)
      const s1 = rotr(at(w, i - 2), 17) ^ rotr(at(w, i - 2), 19) ^ (at(w, i - 2) >>> 10)

      w[i] = (at(w, i - 16) + s0 + at(w, i - 7) + s1) | 0
    }

    let a = at(h, 0)
    let b = at(h, 1)
    let c = at(h, 2)
    let d = at(h, 3)
    let e = at(h, 4)
    let f = at(h, 5)
    let g = at(h, 6)
    let hh = at(h, 7)

    for (let i = 0; i < 64; i += 1) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + at(K, i) + at(w, i)) | 0
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0

      hh = g
      g = f
      f = e
      e = (d + t1) | 0
      d = c
      c = b
      b = a
      a = (t1 + t2) | 0
    }

    const mixed = [a, b, c, d, e, f, g, hh]

    for (let i = 0; i < 8; i += 1) {
      h[i] = (at(h, i) + at(mixed, i)) | 0
    }
  }

  return h.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('')
}

/**
 * A short, salted fingerprint of a value: 8 hex digits. It is how a finding is
 * named in messages, the log and the allowlist. It is not reversible in
 * practice, but it is not a secret store either: it is only ever kept next to
 * a per-install salt, and only 32 bits of it, so many values share each one.
 */
export const fingerprint = (value: string, salt: string): string =>
  sha256(`${salt}\u0000${value}`).slice(0, 8)

/** A fresh random salt, 32 hex digits. Not cryptographic: it only keeps fingerprints from matching across installs. */
export const newSalt = (): string => {
  let salt = ''

  while (salt.length < 32) {
    salt += Math.floor(Math.random() * 4294967296).toString(16).padStart(8, '0')
  }

  return salt.slice(0, 32)
}
