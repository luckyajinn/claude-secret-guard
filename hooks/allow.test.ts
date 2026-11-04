import { expect, test } from 'claude-code/testing'

import { compileAllow, isPathAllowed, isTextAllowed, parseEntry } from './allow'

const entry = (input: string): string => {
  const parsed = parseEntry(input)

  if (!parsed.ok) {
    throw new Error(parsed.reason)
  }

  return parsed.entry
}

test('parseEntry infers the kind from what was typed', () => {
  expect(entry('3FA91C2B')).toBe('fp:3fa91c2b')
  expect(entry('fp:3fa91c2b')).toBe('fp:3fa91c2b')
  expect(entry('docs/**')).toBe('path:docs/**')
  expect(entry('*.test.ts')).toBe('path:*.test.ts')
  expect(entry('src\\fixtures\\*.json')).toBe('path:src/fixtures/*.json')
  expect(entry('my-test-token')).toBe('text:my-test-token')
  expect(entry('"quoted text value"')).toBe('text:quoted text value')
})

test('parseEntry refuses what would hide too much or is not usable', () => {
  for (const input of ['', '   ', 'fp:zzzz', 'fp:abc', 'text:short', 'path:**', 'path:*', 'path:/', `text:${'x'.repeat(201)}`]) {
    const parsed = parseEntry(input)

    expect(parsed.ok).toBe(false)
  }
})

test('a text entry needs enough characters to be safe', () => {
  expect(parseEntry('text:abcde').ok).toBe(false)
  expect(parseEntry('text:abcdef').ok).toBe(true)
})

test('path globs match like a .gitignore line', () => {
  const allow = compileAllow(['path:docs/**', 'path:*.test.ts', 'path:src/*.fixture.json'])

  expect(isPathAllowed(allow, 'docs/guide.md')).toBe(true)
  expect(isPathAllowed(allow, '/home/me/project/docs/deep/guide.md')).toBe(true)
  expect(isPathAllowed(allow, 'src/a.test.ts')).toBe(true)
  expect(isPathAllowed(allow, 'a.test.ts')).toBe(true)
  expect(isPathAllowed(allow, 'src/a.ts')).toBe(false)
  expect(isPathAllowed(allow, 'src/a.test.tsx')).toBe(false)
  expect(isPathAllowed(allow, '/p/src/x.fixture.json')).toBe(true)
  expect(isPathAllowed(allow, '/p/src/deep/x.fixture.json')).toBe(false)
  expect(isPathAllowed(allow, 'mydocs/guide.md')).toBe(false)
})

test('path globs match Windows paths and ignore case there', () => {
  const allow = compileAllow(['path:fixtures/**', 'path:*.test.ts'])

  expect(isPathAllowed(allow, 'C:\\proj\\Fixtures\\data.json')).toBe(true)
  expect(isPathAllowed(allow, 'C:\\proj\\src\\a.test.ts')).toBe(true)
  expect(isPathAllowed(allow, 'C:\\proj\\src\\a.ts')).toBe(false)
})

test('dots and other regex characters in a glob are literal', () => {
  const allow = compileAllow(['path:v1.2/**', 'path:a+b.txt'])

  expect(isPathAllowed(allow, 'v1.2/x')).toBe(true)
  expect(isPathAllowed(allow, 'v1x2/x')).toBe(false)
  expect(isPathAllowed(allow, 'a+b.txt')).toBe(true)
  expect(isPathAllowed(allow, 'aab.txt')).toBe(false)
})

test('compileAllow keeps fingerprints and texts apart and skips junk', () => {
  const allow = compileAllow(['fp:3fa91c2b', 'text:placeholder-token', 42, null, 'fp:nothex', 'text:no'])

  expect(allow.fingerprints.has('3fa91c2b')).toBe(true)
  expect(allow.fingerprints.size).toBe(1)
  expect(allow.texts).toEqual(['placeholder-token'])
  expect(isTextAllowed(allow, 'a-placeholder-token-here')).toBe(true)
  expect(isTextAllowed(allow, 'something else')).toBe(false)
})
