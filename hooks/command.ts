// The `/secret-guard` command: reading what was typed, and the text it prints.
// Every renderer is a pure function of what it is given; nothing here holds or
// prints a secret value.

import type { BlockRecord } from '../types'
import type { Config } from './config'
import { describeRules } from './detect'

export type Sub =
  | { name: 'status' }
  | { name: 'rules' }
  | { name: 'recent'; count: number }
  | { name: 'allowlist' }
  | { name: 'allow'; arg: string }
  | { name: 'unallow'; arg: string }
  | { name: 'clear' }
  | { name: 'help' }
  | { name: 'unknown'; text: string }

const DEFAULT_RECENT = 10
const MAX_RECENT_SHOWN = 50

/** What follows `/secret-guard`. */
export const parseSub = (args: string): Sub => {
  const trimmed = args.trim()

  if (trimmed === '') {
    return { name: 'status' }
  }

  const space = trimmed.search(/\s/)
  const word = (space < 0 ? trimmed : trimmed.slice(0, space)).toLowerCase()
  const rest = space < 0 ? '' : trimmed.slice(space + 1).trim()

  switch (word) {
    case 'status':
      return { name: 'status' }
    case 'rules':
      return { name: 'rules' }
    case 'recent':
    case 'log': {
      const n = Number(rest)

      return { name: 'recent', count: Number.isInteger(n) && n > 0 ? Math.min(n, MAX_RECENT_SHOWN) : DEFAULT_RECENT }
    }
    case 'allowlist':
    case 'list':
      return { name: 'allowlist' }
    case 'allow':
      return rest === '' ? { name: 'allowlist' } : { name: 'allow', arg: rest }
    case 'unallow':
    case 'remove':
      return { name: 'unallow', arg: rest }
    case 'clear':
      return { name: 'clear' }
    case 'help':
    case '--help':
    case '-h':
      return { name: 'help' }
    default:
      return { name: 'unknown', text: word }
  }
}

export const HELP = [
  '/secret-guard                  status: which guards are on, counts, git scan',
  '/secret-guard rules            the detection rules and what is ignored as a placeholder',
  '/secret-guard recent [n]       the last blocks and warnings (rule and place only, never the value)',
  '/secret-guard allow <entry>    ignore something known to be safe:',
  '                                 fp:<id>      one value, by the id a block shows',
  '                                 path:<glob>  every finding in matching files (docs/**, *.test.ts)',
  '                                 text:<text>  any value containing this literal (6+ characters)',
  '/secret-guard allowlist        show the allowlist',
  '/secret-guard unallow <n|entry> remove an entry',
  '/secret-guard clear            empty the recent-blocks log',
].join('\n')

export type Status = {
  config: Config
  session: { blocked: number; warned: number }
  totals: { blocked: number; warned: number }
  allowCount: number
  /** What the git scan can do: a git version string, or why it cannot run. */
  git: { isReady: boolean; detail: string }
}

const onOff = (isOn: boolean, mode: Config['mode']): string => (isOn ? (mode === 'block' ? 'on, blocks' : 'on, warns only') : 'off')

export const renderStatus = (status: Status): string => {
  const { config } = status
  const git = status.git.isReady ? `ready (${status.git.detail})` : `unavailable, so commits are not scanned (${status.git.detail})`

  return [
    `secret-guard: mode ${config.mode}`,
    `  file writes and edits  ${onOff(config.guardFiles, config.mode)}`,
    `  shell commands         ${onOff(config.guardCommands, config.mode)}`,
    `  git add / git commit   ${onOff(config.guardCommits, config.mode)}; git scan ${git}`,
    `  your prompts           ${onOff(config.guardPrompts, config.mode)}`,
    `This session: ${status.session.blocked} blocked, ${status.session.warned} warned. All time: ${status.totals.blocked} blocked, ${status.totals.warned} warned.`,
    `Allowlist: ${status.allowCount} ${status.allowCount === 1 ? 'entry' : 'entries'}. Detection is heuristic: it will miss secrets with no recognizable shape. /secret-guard help lists the commands.`,
  ].join('\n')
}

export const renderRules = (): string =>
  [
    'Detection rules (most specific first):',
    ...describeRules().map(rule => `  ${rule.id.padEnd(26)} ${rule.label}`),
    '',
    'The generic rule needs a name that says credential (password, secret, token, api key...) and a value that is',
    'long enough, high enough in entropy and not a reference ($VAR, process.env.X, a path). Values with placeholder',
    'words (example, changeme, dummy, xxxx, <your-key>...) are ignored everywhere.',
  ].join('\n')

const ago = (ms: number): string => {
  const seconds = Math.max(0, Math.round(ms / 1000))

  if (seconds < 90) {
    return `${seconds}s ago`
  }

  const minutes = Math.round(seconds / 60)

  if (minutes < 90) {
    return `${minutes}m ago`
  }

  const hours = Math.round(minutes / 60)

  return hours < 48 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`
}

export const renderRecent = (records: readonly BlockRecord[], count: number, now: number): string => {
  if (records.length === 0) {
    return 'No blocks or warnings recorded yet.'
  }

  const shown = records.slice(-count).reverse()

  return [
    `Last ${shown.length} of ${records.length} recorded (newest first; values are never stored):`,
    ...shown.map(r => `  ${ago(now - r.at).padEnd(8)} ${r.action.padEnd(7)} ${r.guard.padEnd(7)} ${r.rule} at ${r.location} (id ${r.fingerprint})`),
  ].join('\n')
}

export const renderAllowlist = (entries: readonly string[]): string =>
  entries.length === 0
    ? 'The allowlist is empty. Add one with /secret-guard allow fp:<id>, path:<glob> or text:<text>.'
    : ['Allowlist:', ...entries.map((entry, i) => `  ${i + 1}. ${entry}`), 'Remove one with /secret-guard unallow <number>.'].join('\n')
