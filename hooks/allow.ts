// The allowlist: what the person has said is safe. Three kinds of entry, kept
// as `kind:value` strings so they survive in the store as plain JSON.
//
//   fp:3fa91c2b      one specific value, named by the fingerprint a block shows
//   path:docs/**     findings in files whose path matches the glob are ignored
//   text:my-test-key any value containing this literal is ignored
//
// The allowlist is kept in the mod's own store, in the user's Claude config,
// not in the project: a repository (or an agent working in one) cannot widen
// what the guard lets through by editing a file.

export type Allow = {
  fingerprints: ReadonlySet<string>
  texts: readonly string[]
  paths: readonly PathRule[]
}

type PathRule = { glob: string; test: (path: string) => boolean }

export const MAX_ENTRIES = 200
const MAX_ENTRY_LENGTH = 200
const MIN_TEXT_LENGTH = 6

export const EMPTY_ALLOW: Allow = { fingerprints: new Set(), texts: [], paths: [] }

export type ParsedEntry = { ok: true; entry: string } | { ok: false; reason: string }

const normalizePath = (path: string): string => path.replace(/\\/g, '/')

const escapeRegExp = (text: string): string => text.replace(/[.+^${}()|[\]\\]/g, '\\$&')

/** A glob as a RegExp source: `**` crosses folders, `*` and `?` stay inside one. */
const globSource = (glob: string): string => {
  let out = ''

  for (let i = 0; i < glob.length; i += 1) {
    const c = glob.charAt(i)

    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') {
        out += '(?:.*/)?'
        i += 2
      } else {
        out += '.*'
        i += 1
      }
    } else if (c === '*') {
      out += '[^/]*'
    } else if (c === '?') {
      out += '[^/]'
    } else {
      out += escapeRegExp(c)
    }
  }

  return out
}

const pathRule = (glob: string): PathRule => {
  const cleaned = normalizePath(glob).replace(/^\.\//, '').replace(/^\/+/, '')
  const source = globSource(cleaned)
  // A glob with no folder in it (`*.test.ts`) matches a file name anywhere, as
  // a .gitignore line does; one with a folder matches from any folder boundary.
  const hasFolder = cleaned.includes('/')
  const re = new RegExp(hasFolder ? `(?:^|/)${source}$` : `^${source}$`, 'i')

  return {
    glob,
    test: (path: string) => {
      const normal = normalizePath(path)

      return re.test(hasFolder ? normal : normal.slice(normal.lastIndexOf('/') + 1))
    },
  }
}

/** Turns what the person typed into a stored entry, or says why not. */
export const parseEntry = (input: string): ParsedEntry => {
  let raw = input.trim()

  if (raw.length >= 2 && ((raw[0] === '"' && raw.endsWith('"')) || (raw[0] === "'" && raw.endsWith("'")))) {
    raw = raw.slice(1, -1).trim()
  }

  if (raw === '') {
    return { ok: false, reason: 'Say what to allow: fp:<fingerprint>, path:<glob> or text:<literal>.' }
  }

  if (raw.length > MAX_ENTRY_LENGTH) {
    return { ok: false, reason: `That entry is longer than ${MAX_ENTRY_LENGTH} characters.` }
  }

  const named = /^(fp|path|text):(.*)$/s.exec(raw)
  let kind: 'fp' | 'path' | 'text'
  let value: string

  if (named) {
    kind = named[1] as 'fp' | 'path' | 'text'
    value = (named[2] ?? '').trim()
  } else if (/^[0-9a-f]{8}$/i.test(raw)) {
    kind = 'fp'
    value = raw
  } else if (/[/\\*?]/.test(raw)) {
    kind = 'path'
    value = raw
  } else {
    kind = 'text'
    value = raw
  }

  if (kind === 'fp') {
    return /^[0-9a-f]{8}$/i.test(value)
      ? { ok: true, entry: `fp:${value.toLowerCase()}` }
      : { ok: false, reason: 'A fingerprint is 8 hex digits, as a block message shows it (id 3fa91c2b).' }
  }

  if (kind === 'path') {
    return value === '' || /^[*/\\.]*$/.test(value)
      ? { ok: false, reason: 'That path glob would match everything. Name a folder or a file pattern.' }
      : { ok: true, entry: `path:${normalizePath(value)}` }
  }

  return value.length < MIN_TEXT_LENGTH
    ? { ok: false, reason: `A text entry needs at least ${MIN_TEXT_LENGTH} characters, or it would hide too much.` }
    : { ok: true, entry: `text:${value}` }
}

/** Compiles stored entries. An entry that does not parse is skipped, never thrown on. */
export const compileAllow = (entries: readonly unknown[]): Allow => {
  const fingerprints = new Set<string>()
  const texts: string[] = []
  const paths: PathRule[] = []

  for (const item of entries) {
    if (typeof item !== 'string') {
      continue
    }

    const parsed = parseEntry(item)

    if (!parsed.ok) {
      continue
    }

    const colon = parsed.entry.indexOf(':')
    const kind = parsed.entry.slice(0, colon)
    const value = parsed.entry.slice(colon + 1)

    if (kind === 'fp') {
      fingerprints.add(value)
    } else if (kind === 'text') {
      texts.push(value)
    } else {
      paths.push(pathRule(value))
    }
  }

  return { fingerprints, texts, paths }
}

/** True when the file's path matches a `path:` entry: nothing in it is scanned. */
export const isPathAllowed = (allow: Allow, path: string): boolean => allow.paths.some(rule => rule.test(path))

/** True when a `text:` entry is contained in the value. */
export const isTextAllowed = (allow: Allow, value: string): boolean => allow.texts.some(text => value.includes(text))
