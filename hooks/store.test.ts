import { expect, test } from 'claude-code/testing'

import type { BlockRecord } from '../types'
import { MAX_ENTRIES } from './allow'
import { addEntry, clearRecent, loadAllow, loadEntries, loadRecent, loadSalt, loadTotals, MAX_RECENT, record, removeEntry } from './store'
import type { KV } from './store'

const memory = (initial: Record<string, unknown> = {}): KV & { data: Record<string, unknown> } => {
  const data: Record<string, unknown> = { ...initial }

  return {
    data,
    get: async key => data[key],
    set: async (key, value) => {
      data[key] = JSON.parse(JSON.stringify(value))
    },
  }
}

const rec = (n: number, action: BlockRecord['action'] = 'blocked'): BlockRecord => ({
  at: n,
  guard: 'file',
  action,
  rule: 'github-token',
  location: `/p/a.ts:${n}:1`,
  fingerprint: '3fa91c2b',
})

test('the salt is made once and kept', async () => {
  const kv = memory()
  const first = await loadSalt(kv)

  expect(first).toMatch(/^[0-9a-f]{32}$/)
  expect(await loadSalt(kv)).toBe(first)
  expect(await loadSalt(memory({ salt: 'short' }))).not.toBe('short')
})

test('allowlist entries are normalized, de-duplicated and removable by number or text', async () => {
  const kv = memory()

  expect(await addEntry(kv, '3FA91C2B')).toEqual({ ok: true, entry: 'fp:3fa91c2b', isNew: true })
  expect(await addEntry(kv, 'fp:3fa91c2b')).toEqual({ ok: true, entry: 'fp:3fa91c2b', isNew: false })
  expect(await addEntry(kv, 'docs/**')).toEqual({ ok: true, entry: 'path:docs/**', isNew: true })
  expect((await addEntry(kv, 'nope')).ok).toBe(false)
  expect(await loadEntries(kv)).toEqual(['fp:3fa91c2b', 'path:docs/**'])

  const allow = await loadAllow(kv)

  expect(allow.fingerprints.has('3fa91c2b')).toBe(true)
  expect(allow.paths).toHaveLength(1)

  expect(await removeEntry(kv, '1')).toBe('fp:3fa91c2b')
  expect(await removeEntry(kv, 'docs/**')).toBe('path:docs/**')
  expect(await removeEntry(kv, 'docs/**')).toBeUndefined()
  expect(await removeEntry(kv, '7')).toBeUndefined()
  expect(await loadEntries(kv)).toEqual([])
})

test('the allowlist has a size limit', async () => {
  const kv = memory({ allow: Array.from({ length: MAX_ENTRIES }, (_, i) => `text:placeholder-${i}`) })
  const result = await addEntry(kv, 'text:one-too-many')

  expect(result.ok).toBe(false)
  expect(await loadEntries(kv)).toHaveLength(MAX_ENTRIES)
})

test('the log keeps the last records and counts blocks and warnings', async () => {
  const kv = memory()

  await record(kv, [])
  expect(await loadRecent(kv)).toEqual([])

  await record(kv, [rec(1), rec(2, 'warned')])
  await record(kv, Array.from({ length: MAX_RECENT }, (_, i) => rec(i + 10)))

  const recent = await loadRecent(kv)

  expect(recent).toHaveLength(MAX_RECENT)
  expect(recent[0]?.at).toBe(10)
  expect(recent[MAX_RECENT - 1]?.at).toBe(MAX_RECENT + 9)
  expect(await loadTotals(kv)).toEqual({ blocked: MAX_RECENT + 1, warned: 1 })

  await clearRecent(kv)
  expect(await loadRecent(kv)).toEqual([])
  expect((await loadTotals(kv)).blocked).toBe(MAX_RECENT + 1)
})

test('what the store holds is never trusted: junk is skipped, not thrown on', async () => {
  const kv = memory({
    allow: ['fp:3fa91c2b', 7, { x: 1 }, null],
    recent: [rec(1), { at: 'x' }, 'nope', null, { ...rec(2), guard: 'nowhere' }],
    totals: { blocked: 'many', warned: 3 },
  })

  expect(await loadEntries(kv)).toEqual(['fp:3fa91c2b'])
  expect(await loadRecent(kv)).toEqual([rec(1)])
  expect(await loadTotals(kv)).toEqual({ blocked: 0, warned: 3 })
  expect(await loadEntries(memory({ allow: 'not a list' }))).toEqual([])
  expect(await loadRecent(memory({ recent: 5 }))).toEqual([])
  expect(await loadTotals(memory({ totals: 5 }))).toEqual({ blocked: 0, warned: 0 })
})

test('a record holds exactly the fields that name a place and a rule, no value', async () => {
  const kv = memory()

  await record(kv, [rec(1)])

  expect(Object.keys((await loadRecent(kv))[0] ?? {}).sort()).toEqual(['action', 'at', 'fingerprint', 'guard', 'location', 'rule'])
})
