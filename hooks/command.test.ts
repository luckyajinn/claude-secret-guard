import { expect, test } from 'claude-code/testing'

import type { BlockRecord } from '../types'
import { HELP, parseSub, renderAllowlist, renderRecent, renderRules, renderStatus } from './command'
import { readConfig } from './config'

test('parseSub reads what follows /secret-guard', () => {
  expect(parseSub('')).toEqual({ name: 'status' })
  expect(parseSub('  STATUS ')).toEqual({ name: 'status' })
  expect(parseSub('rules')).toEqual({ name: 'rules' })
  expect(parseSub('recent')).toEqual({ name: 'recent', count: 10 })
  expect(parseSub('recent 3')).toEqual({ name: 'recent', count: 3 })
  expect(parseSub('recent 9999')).toEqual({ name: 'recent', count: 50 })
  expect(parseSub('recent nonsense')).toEqual({ name: 'recent', count: 10 })
  expect(parseSub('allowlist')).toEqual({ name: 'allowlist' })
  expect(parseSub('allow')).toEqual({ name: 'allowlist' })
  expect(parseSub('allow fp:3fa91c2b')).toEqual({ name: 'allow', arg: 'fp:3fa91c2b' })
  expect(parseSub('allow   path:docs/** ')).toEqual({ name: 'allow', arg: 'path:docs/**' })
  expect(parseSub('unallow 2')).toEqual({ name: 'unallow', arg: '2' })
  expect(parseSub('clear')).toEqual({ name: 'clear' })
  expect(parseSub('help')).toEqual({ name: 'help' })
  expect(parseSub('frobnicate now')).toEqual({ name: 'unknown', text: 'frobnicate' })
})

test('the help text names every command', () => {
  for (const word of ['rules', 'recent', 'allow', 'allowlist', 'unallow', 'clear', 'fp:', 'path:', 'text:']) {
    expect(HELP).toContain(word)
  }
})

test('the status says what is on, what blocks and whether git can be scanned', () => {
  const base = {
    config: readConfig({}),
    session: { blocked: 2, warned: 1 },
    totals: { blocked: 9, warned: 4 },
    allowCount: 3,
    git: { isReady: true, detail: 'git version 2.50.0' },
  }
  const ready = renderStatus(base)

  expect(ready).toContain('mode block')
  expect(ready).toContain('file writes and edits  on, blocks')
  expect(ready).toContain('git scan ready (git version 2.50.0)')
  expect(ready).toContain('This session: 2 blocked, 1 warned. All time: 9 blocked, 4 warned.')
  expect(ready).toContain('Allowlist: 3 entries.')
  expect(ready).toContain('heuristic')

  const degraded = renderStatus({
    ...base,
    config: readConfig({ mode: 'warn', guardPrompts: false }),
    allowCount: 1,
    git: { isReady: false, detail: 'this session cannot run host commands' },
  })

  expect(degraded).toContain('mode warn')
  expect(degraded).toContain('on, warns only')
  expect(degraded).toContain('your prompts           off')
  expect(degraded).toContain('commits are not scanned (this session cannot run host commands)')
  expect(degraded).toContain('Allowlist: 1 entry.')
})

test('the rules listing names each rule and the placeholder policy', () => {
  const text = renderRules()

  for (const id of ['private-key', 'aws-access-key-id', 'github-token', 'anthropic-api-key', 'stripe-key', 'slack-token', 'google-api-key', 'jwt', 'generic-secret']) {
    expect(text).toContain(id)
  }

  expect(text).toContain('placeholder')
})

const RECORDS: BlockRecord[] = [
  { at: 1_000_000, guard: 'file', action: 'blocked', rule: 'github-token', location: '/p/a.ts:3:9', fingerprint: '3fa91c2b' },
  { at: 1_060_000, guard: 'command', action: 'warned', rule: 'jwt', location: 'command line 1, column 5', fingerprint: 'abcdef01' },
  { at: 1_300_000, guard: 'prompt', action: 'blocked', rule: 'generic-secret', location: 'prompt line 2, column 1', fingerprint: '0123abcd' },
]

test('the recent log lists newest first with rule, place and id, and nothing else', () => {
  const text = renderRecent(RECORDS, 10, 1_300_000 + 5_000)
  const lines = text.split('\n')

  expect(lines[0]).toBe('Last 3 of 3 recorded (newest first; values are never stored):')
  expect(lines[1]).toContain('5s ago')
  expect(lines[1]).toContain('blocked')
  expect(lines[1]).toContain('prompt')
  expect(lines[1]).toContain('generic-secret at prompt line 2, column 1 (id 0123abcd)')
  expect(lines[3]).toContain('github-token at /p/a.ts:3:9 (id 3fa91c2b)')
  expect(lines[3]).toContain('5m ago')
})

test('the recent log honours the count and handles an empty log', () => {
  expect(renderRecent(RECORDS, 1, 2_000_000).split('\n')).toHaveLength(2)
  expect(renderRecent([], 10, 0)).toBe('No blocks or warnings recorded yet.')
})

test('the allowlist is numbered so an entry can be removed by number', () => {
  expect(renderAllowlist([])).toContain('empty')
  expect(renderAllowlist(['fp:3fa91c2b', 'path:docs/**'])).toContain('  2. path:docs/**')
  expect(renderAllowlist(['fp:3fa91c2b'])).toContain('/secret-guard unallow <number>')
})

test('readConfig defaults to everything on and blocking, and reads each option', () => {
  expect(readConfig({})).toEqual({ mode: 'block', guardFiles: true, guardCommands: true, guardCommits: true, guardPrompts: true })
  expect(readConfig({ mode: 'warn', guardFiles: false, guardCommands: false, guardCommits: false, guardPrompts: false })).toEqual({
    mode: 'warn',
    guardFiles: false,
    guardCommands: false,
    guardCommits: false,
    guardPrompts: false,
  })
  expect(readConfig({ mode: 'nonsense', guardFiles: 'no' }).mode).toBe('block')
  expect(readConfig({ guardFiles: 'no' }).guardFiles).toBe(true)
})
