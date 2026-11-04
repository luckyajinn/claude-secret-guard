import { expect, test } from 'claude-code/testing'

import { fingerprint, newSalt, sha256 } from './hash'

// FIPS 180-2 test vectors, written in two halves so they are not mistaken for keys.
const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb924' + '27ae41e4649b934ca495991b7852b855'
const ABC = 'ba7816bf8f01cfea414140de5dae2223' + 'b00361a396177a9cb410ff61f20015ad'
const TWO_BLOCKS = '248d6a61d20638b8e5c026930c3e6039' + 'a33ce45964ff2167f6ecedd419db06c1'

test('sha256 matches the standard test vectors', () => {
  expect(sha256('')).toBe(EMPTY)
  expect(sha256('abc')).toBe(ABC)
  expect(sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')).toBe(TWO_BLOCKS)
})

test('sha256 handles input that is not ASCII', () => {
  expect(sha256('é')).toHaveLength(64)
  expect(sha256('é')).not.toBe(sha256('e'))
  expect(sha256('😀')).toHaveLength(64)
})

test('a fingerprint is 8 hex digits, stable for a value and salt, and differs by salt', () => {
  const a = fingerprint('some value', 'salt-one')

  expect(a).toMatch(/^[0-9a-f]{8}$/)
  expect(fingerprint('some value', 'salt-one')).toBe(a)
  expect(fingerprint('some value', 'salt-two')).not.toBe(a)
  expect(fingerprint('other value', 'salt-one')).not.toBe(a)
})

test('a new salt is 32 hex digits and not the same twice', () => {
  const a = newSalt()

  expect(a).toMatch(/^[0-9a-f]{32}$/)
  expect(newSalt()).not.toBe(a)
})
