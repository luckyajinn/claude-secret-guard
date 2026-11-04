// What the mod keeps between sessions, in its own `$.store`: a salt for the
// fingerprints, the allowlist, a short log of recent blocks, and running
// totals. None of it holds a secret value: the log has rules, places and
// fingerprints.

import type { BlockRecord } from '../types'
import { compileAllow, MAX_ENTRIES, parseEntry } from './allow'
import type { Allow } from './allow'
import { newSalt } from './hash'

export type KV = {
  get: (key: string) => Promise<unknown>
  set: (key: string, value: unknown) => Promise<void>
}

export type Totals = { blocked: number; warned: number }

export const MAX_RECENT = 50

const asStrings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [])

const isRecord = (value: unknown): value is BlockRecord => {
  if (value === null || typeof value !== 'object') {
    return false
  }

  const r = value as Record<string, unknown>

  return (
    typeof r.at === 'number' &&
    (r.guard === 'file' || r.guard === 'command' || r.guard === 'commit' || r.guard === 'prompt') &&
    (r.action === 'blocked' || r.action === 'warned') &&
    typeof r.rule === 'string' &&
    typeof r.location === 'string' &&
    typeof r.fingerprint === 'string'
  )
}

/** The per-install salt, made on first use. */
export const loadSalt = async (kv: KV): Promise<string> => {
  const stored = await kv.get('salt')

  if (typeof stored === 'string' && stored.length >= 16) {
    return stored
  }

  const salt = newSalt()

  await kv.set('salt', salt)

  return salt
}

export const loadEntries = async (kv: KV): Promise<string[]> => asStrings(await kv.get('allow'))

export const loadAllow = async (kv: KV): Promise<Allow> => compileAllow(await loadEntries(kv))

export type AddResult = { ok: true; entry: string; isNew: boolean } | { ok: false; reason: string }

/** Adds an entry to the allowlist (typed text in, stored `kind:value` out). */
export const addEntry = async (kv: KV, input: string): Promise<AddResult> => {
  const parsed = parseEntry(input)

  if (!parsed.ok) {
    return parsed
  }

  const entries = await loadEntries(kv)

  if (entries.includes(parsed.entry)) {
    return { ok: true, entry: parsed.entry, isNew: false }
  }

  if (entries.length >= MAX_ENTRIES) {
    return { ok: false, reason: `The allowlist holds ${MAX_ENTRIES} entries already. Remove one first.` }
  }

  await kv.set('allow', [...entries, parsed.entry])

  return { ok: true, entry: parsed.entry, isNew: true }
}

/** Removes an entry, named by its text or by its number in the list. Returns what was removed. */
export const removeEntry = async (kv: KV, input: string): Promise<string | undefined> => {
  const entries = await loadEntries(kv)
  const trimmed = input.trim()
  let target: string | undefined

  if (/^\d+$/.test(trimmed)) {
    target = entries[Number(trimmed) - 1]
  } else {
    const parsed = parseEntry(trimmed)

    target = parsed.ok && entries.includes(parsed.entry) ? parsed.entry : entries.find(entry => entry === trimmed)
  }

  if (target === undefined) {
    return undefined
  }

  await kv.set('allow', entries.filter(entry => entry !== target))

  return target
}

export const loadRecent = async (kv: KV): Promise<BlockRecord[]> => {
  const stored = await kv.get('recent')

  return Array.isArray(stored) ? stored.filter(isRecord) : []
}

export const clearRecent = async (kv: KV): Promise<void> => {
  await kv.set('recent', [])
}

export const loadTotals = async (kv: KV): Promise<Totals> => {
  const stored = await kv.get('totals')
  const t = stored !== null && typeof stored === 'object' ? (stored as Record<string, unknown>) : {}

  return {
    blocked: typeof t.blocked === 'number' ? t.blocked : 0,
    warned: typeof t.warned === 'number' ? t.warned : 0,
  }
}

/** Adds records to the log (newest last, the last MAX_RECENT kept) and to the running totals. */
export const record = async (kv: KV, records: readonly BlockRecord[]): Promise<void> => {
  if (records.length === 0) {
    return
  }

  const recent = await loadRecent(kv)
  const totals = await loadTotals(kv)

  for (const r of records) {
    totals[r.action] += 1
  }

  await kv.set('recent', [...recent, ...records].slice(-MAX_RECENT))
  await kv.set('totals', totals)
}
