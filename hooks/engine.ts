// The part of the mod that talks to the engine (`$`): load what the guards
// need, run a check, decide what it comes to, and keep count. `register.tsx`
// wires these to the hooks; the tests call them directly.

import { atom, read, update } from 'claude-code'
import type { EngineInterface } from 'claude-code'

import type { BlockRecord, GuardAction, GuardPoint } from '../types'
import { EMPTY_ALLOW, parseEntry } from './allow'
import { parseSub, renderAllowlist, renderRecent, renderRules, renderStatus, HELP } from './command'
import type { Config } from './config'
import { scan } from './detect'
import { blockedSummary, checkAttachedFile, checkCommandText, checkGit, checkPromptText, denyMessage, isPersonPrompt, promptMessage, warnMessage } from './guard'
import type { Checked, Hit, Runner, ScanContext } from './guard'
import { addEntry, clearRecent, loadAllow, loadEntries, loadRecent, loadSalt, loadTotals, record, removeEntry } from './store'
import type { KV } from './store'

// What the mod's session counters are called in `$.state` (see types/index.d.ts).
const blocked = atom({ plugin: 'secret-guard', key: 'blocked' } as const, 0)
const warned = atom({ plugin: 'secret-guard', key: 'warned' } as const, 0)

// The mod's own store, as the store helpers want it. `$.store` is spelled out at
// each call because the engine reads `$` by its calls, never as a value to pass.
function kv($: EngineInterface): KV {
  return {
    get: key => $.store.get(key),
    set: (key, value) => $.store.set(key, value),
  }
}

async function loadContext($: EngineInterface): Promise<ScanContext> {
  const [salt, allow] = await Promise.all([loadSalt(kv($)), loadAllow(kv($))])

  return { salt, allow }
}

// The engine's own `git` and file reads, as the git check wants them. Git is run
// with the repository's config switched off where it could run a command (a
// textconv or fsmonitor program), and without taking optional locks.
function runner($: EngineInterface): Runner {
  return {
    git: async (args, dir) => {
      const out = await $.process.run(
        ['git', '-c', 'core.quotePath=false', '-c', 'core.fsmonitor=false', ...(dir === undefined ? [] : ['-C', dir]), ...args],
        { timeoutMs: 20_000, env: { GIT_OPTIONAL_LOCKS: '0' } },
      )

      return { exitCode: out.exitCode, stdout: out.stdout, stderr: out.stderr, isTruncated: out.isStdoutTruncated }
    },
    readFile: path => $.fs.read(path),
  }
}

// Where the guard cannot block (warn mode, or a scan that could not run) it is
// loud instead: a toast, and a line that stays in the transcript.
function shout($: EngineInterface, text: string): void {
  $.ui.toast(text.split('\n')[0] ?? text, { timeoutMs: 12_000 })
  $.ui.log(text)
}

async function report($: EngineInterface, guard: GuardPoint, action: GuardAction, hits: readonly Hit[]): Promise<void> {
  try {
    const at = await $.clock.now()
    const records: BlockRecord[] = hits.map(hit => ({
      at,
      guard,
      action,
      rule: hit.rule,
      location: hit.location,
      fingerprint: hit.fingerprint,
    }))

    await record(kv($), records)

    // Spelled out per atom: the engine reads which state a hook touches from the source.
    if (action === 'blocked') {
      await update($, blocked, n => n + hits.length)
    } else {
      await update($, warned, n => n + hits.length)
    }

    const total = await read($, blocked)

    $.ui.status(total > 0 ? `secret-guard: ${total} blocked` : undefined)
  } catch {
    // Keeping count must never be the reason a block does not happen.
  }
}

/**
 * Decides what one check comes to. Returns the text to refuse with, or
 * undefined to let the action go ahead (nothing found, warn mode, or only notes).
 */
async function decide(
  $: EngineInterface,
  config: Config,
  guard: GuardPoint,
  subject: string,
  checked: Checked,
  refusal: (hits: readonly Hit[]) => string,
): Promise<string | undefined> {
  if (checked.hits.length === 0) {
    if (checked.notes.length > 0) {
      shout($, warnMessage(subject, [], checked.notes))
    }

    return undefined
  }

  if (config.mode === 'warn') {
    shout($, warnMessage(subject, checked.hits, checked.notes))
    await report($, guard, 'warned', checked.hits)

    return undefined
  }

  await report($, guard, 'blocked', checked.hits)
  $.ui.toast(blockedSummary(subject, checked.hits))

  return refusal(checked.hits)
}

/** (a) What a file write, edit or notebook edit is about to put in a file. Returns the refusal, or undefined. */
export async function guardFile(
  $: EngineInterface,
  config: Config,
  subject: string,
  check: (ctx: ScanContext) => Checked,
): Promise<string | undefined> {
  if (!config.guardFiles) {
    return undefined
  }

  return decide($, config, 'file', subject, check(await loadContext($)), hits => denyMessage(subject, 'Nothing was written.', hits))
}

/** (b) A shell command: its text, then the git add / git commit inside it. Returns the refusal, or undefined. */
export async function guardCommand($: EngineInterface, config: Config, command: string): Promise<string | undefined> {
  if (!config.guardCommands && !config.guardCommits) {
    return undefined
  }

  const ctx = await loadContext($)

  if (config.guardCommands) {
    const denied = await decide($, config, 'command', 'this shell command', checkCommandText(command, ctx), hits =>
      denyMessage('this shell command', 'The command did not run.', hits),
    )

    if (denied !== undefined) {
      return denied
    }
  }

  if (config.guardCommits) {
    return decide($, config, 'commit', 'this git command', await checkGit(command, ctx, runner($)), hits =>
      denyMessage('this git command', 'Nothing was staged or committed.', hits),
    )
  }

  return undefined
}

/**
 * (c) A prompt that may hold the person's own words (see `isPersonPrompt`): a
 * prompt a background task, a schedule, a peer session or another plugin raised
 * is not theirs to edit and is left alone. Returns the text to drop it with, or undefined.
 */
export async function guardPrompt(
  $: EngineInterface,
  config: Config,
  text: string,
  origin: { kind: string; asUser?: boolean } | undefined,
  isMeta?: boolean,
): Promise<string | undefined> {
  if (!config.guardPrompts || !isPersonPrompt(origin, isMeta)) {
    return undefined
  }

  return decide($, config, 'prompt', 'your prompt', checkPromptText(text, await loadContext($)), promptMessage)
}

/**
 * (c) A file the person named with `@`, as the engine is about to hand it to the
 * model. Returns the text the model reads in its place, or undefined to let it
 * through. The file is not scanned when the person asked for it to be left alone
 * (`guardPrompts` off); in warn mode it goes through, loudly.
 */
export async function guardAttachedFile($: EngineInterface, config: Config, text: string): Promise<string | undefined> {
  if (!config.guardPrompts) {
    return undefined
  }

  return decide($, config, 'prompt', 'this attached file', checkAttachedFile(text, await loadContext($)), hits =>
    denyMessage('this attached file', 'None of the file was sent to the model.', hits),
  )
}

// ---------------------------------------------------------------------------
// /secret-guard

/** What an allowlist entry typed by the person means, refusing one that is itself a secret. */
async function allow($: EngineInterface, input: string): Promise<string> {
  const parsed = parseEntry(input)

  if (!parsed.ok) {
    return parsed.reason
  }

  if (parsed.entry.startsWith('text:')) {
    const { findings } = scan(parsed.entry.slice(5), { salt: await loadSalt(kv($)), allow: EMPTY_ALLOW })
    const found = findings[0]

    if (found !== undefined) {
      return `That value looks like a real secret (${found.label}), so it was not stored as text. Allow it by fingerprint instead: /secret-guard allow fp:${found.fingerprint}`
    }
  }

  const added = await addEntry(kv($), parsed.entry)

  if (!added.ok) {
    return added.reason
  }

  return added.isNew ? `Allowed ${added.entry}.` : `${added.entry} was already allowed.`
}

async function gitStatus($: EngineInterface): Promise<{ isReady: boolean; detail: string }> {
  try {
    const out = await $.process.run(['git', '--version'], { timeoutMs: 5_000 })

    return out.exitCode === 0
      ? { isReady: true, detail: out.stdout.trim() || 'git' }
      : { isReady: false, detail: `git exited with ${out.exitCode}` }
  } catch {
    return { isReady: false, detail: 'this session cannot run host commands' }
  }
}

/** Runs `/secret-guard <args>` and returns what it prints. */
export async function runCommand($: EngineInterface, config: Config, args: string): Promise<string> {
  const sub = parseSub(args)

  switch (sub.name) {
    case 'status':
      return renderStatus({
        config,
        session: { blocked: await read($, blocked), warned: await read($, warned) },
        totals: await loadTotals(kv($)),
        allowCount: (await loadEntries(kv($))).length,
        git: await gitStatus($),
      })
    case 'rules':
      return renderRules()
    case 'recent':
      return renderRecent(await loadRecent(kv($)), sub.count, await $.clock.now())
    case 'allowlist':
      return renderAllowlist(await loadEntries(kv($)))
    case 'allow':
      return allow($, sub.arg)
    case 'unallow': {
      const removed = await removeEntry(kv($), sub.arg)

      return removed === undefined ? 'No such entry. /secret-guard allowlist shows them.' : `Removed ${removed}.`
    }
    case 'clear':
      await clearRecent(kv($))

      return 'Recent-blocks log cleared.'
    case 'help':
      return HELP
    default:
      return `Unknown option "${sub.text}".\n${HELP}`
  }
}
