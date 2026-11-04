// What each guard point looks at, how a finding is named, and what the person
// and the model are told. No secret value is ever put in a message: a hit is a
// rule, a place and an 8-digit fingerprint, nothing from the value itself.

import type { Allow } from './allow'
import { scan } from './detect'
import type { Finding } from './detect'
import { addedByFile, parseGitOps, splitNull } from './git'
import type { GitOp } from './git'

export type ScanContext = { salt: string; allow: Allow }

export type Hit = {
  rule: string
  label: string
  location: string
  fingerprint: string
}

export type Checked = {
  hits: Hit[]
  /** Things the person should know that are not findings: text too long to scan, a git scan that could not run. */
  notes: string[]
}

const toHit = (finding: Finding, location: string): Hit => ({
  rule: finding.rule,
  label: finding.label,
  location,
  fingerprint: finding.fingerprint,
})

const TRUNCATED = 'The text was longer than 4,000,000 characters, so only its start was scanned.'

// ---------------------------------------------------------------------------
// The text guards: file contents, a shell command, a prompt

/** A file write: the whole new content, located as `path:line:column`. */
export const checkWrite = (path: string, content: string, ctx: ScanContext): Checked => {
  const { findings, isTruncated } = scan(content, { ...ctx, path })

  return {
    hits: findings.map(f => toHit(f, `${path}:${f.line}:${f.column}`)),
    notes: isTruncated ? [TRUNCATED] : [],
  }
}

/** An edit: only the new text is scanned, so what a file already holds never blocks an unrelated change. */
export const checkEdit = (path: string, newText: string, ctx: ScanContext): Checked => {
  const { findings, isTruncated } = scan(newText, { ...ctx, path })

  return {
    hits: findings.map(f => toHit(f, `${path} (new text, line ${f.line})`)),
    notes: isTruncated ? [TRUNCATED] : [],
  }
}

/** The text of a shell command. */
export const checkCommandText = (command: string, ctx: ScanContext): Checked => {
  const { findings, isTruncated } = scan(command, ctx)

  return {
    hits: findings.map(f => toHit(f, `command line ${f.line}, column ${f.column}`)),
    notes: isTruncated ? [TRUNCATED] : [],
  }
}

/** A prompt the person typed. */
export const checkPromptText = (text: string, ctx: ScanContext): Checked => {
  const { findings, isTruncated } = scan(text, ctx)

  return {
    hits: findings.map(f => toHit(f, `prompt line ${f.line}, column ${f.column}`)),
    notes: isTruncated ? [TRUNCATED] : [],
  }
}

// Prompts that are raised by something other than the person: a task finishing,
// a schedule, another session, a channel's sender, a coordinator, an observer.
const MACHINE_ORIGINS = new Set([
  'task-notification',
  'scheduled-trigger',
  'peer',
  'peer-send-message',
  'projects-relay',
  'channel',
  'coordinator',
  'observer',
  'observer-activity',
  'auto-continuation',
])

/**
 * True for a prompt that may hold the person's own words, which is what the
 * prompt guard checks: what they typed, sent from the Remote Control bridge, or
 * a plugin submitted `asUser` (the model reads it bare, as if typed); also one
 * the engine could not attribute (`unclassified`, `sdk`, no origin), because a
 * guard that is unsure should look. Not one the engine says is a task's
 * notification, a schedule, a peer session's message or a plugin's own, and not
 * one the person does not see as typed (`isMeta`).
 */
export const isPersonPrompt = (origin: { kind: string; asUser?: boolean } | undefined, isMeta?: boolean): boolean => {
  if (isMeta === true) {
    return false
  }

  if (origin === undefined) {
    return true
  }

  return origin.kind === 'plugin' ? origin.asUser === true : !MACHINE_ORIGINS.has(origin.kind)
}

// ---------------------------------------------------------------------------
// git: what `git add` and `git commit` would stage

/** What the git check needs from the engine; the hooks give it `$.process.run` and `$.fs.read`. */
export type Runner = {
  git: (args: string[], dir: string | undefined) => Promise<{ exitCode: number; stdout: string; stderr: string; isTruncated: boolean }>
  readFile: (path: string) => Promise<string>
}

// --no-ext-diff and --no-textconv: a repository's config must not get to run a program during the scan.
const DIFF = ['diff', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '--no-renames', '--diff-filter=ACMRT']
const MAX_NEW_FILES = 100
const MAX_OPS = 5

const diffHits = (diff: string, ctx: ScanContext): Hit[] => {
  const hits: Hit[] = []

  for (const file of addedByFile(diff)) {
    const { findings } = scan(file.text, { ...ctx, path: file.file })

    for (const f of findings) {
      hits.push(toHit(f, `${file.file}:${file.lines[f.line - 1] ?? '?'}`))
    }
  }

  return hits
}

const pathspec = (paths: readonly string[]): string[] => (paths.length > 0 ? ['--', ...paths] : [])

const joinPath = (dir: string | undefined, file: string): string => (dir === undefined ? file : `${dir}/${file}`)

const errorName = (error: unknown): string =>
  error !== null && typeof error === 'object' && 'name' in error ? String((error as { name: unknown }).name) : 'Error'

/** Scans the changes that the `git add` and `git commit` inside a command would stage or commit. */
export const checkGit = async (command: string, ctx: ScanContext, runner: Runner): Promise<Checked> => {
  const hits: Hit[] = []
  const notes: string[] = []
  const seen = new Set<string>()
  const ops: GitOp[] = parseGitOps(command).filter(op => !op.isSkipped)

  if (ops.length > MAX_OPS) {
    notes.push(`The command has ${ops.length} git add/commit steps; only the first ${MAX_OPS} were scanned.`)
  }

  const add = (more: Hit[]) => {
    for (const hit of more) {
      const key = `${hit.rule}\u0000${hit.location}`

      if (!seen.has(key)) {
        seen.add(key)
        hits.push(hit)
      }
    }
  }

  const diff = async (args: string[], dir: string | undefined): Promise<string> => {
    const out = await runner.git(args, dir)

    if (out.exitCode !== 0) {
      // Not being in a repository is git's own error to give; anything else is worth saying.
      if (!/not a git repository/i.test(out.stderr)) {
        notes.push(`git exited with ${out.exitCode} while the changes were read, so they were not scanned.`)
      }

      return ''
    }

    if (out.isTruncated) {
      notes.push('The changes were larger than 4 MiB, so only the start of them was scanned.')
    }

    return out.stdout
  }

  try {
    for (const op of ops.slice(0, MAX_OPS)) {
      const spec = pathspec(op.paths)

      if (op.kind === 'commit') {
        add(diffHits(await diff([...DIFF, '--cached'], op.dir), ctx))

        if (op.isCommitAll || op.paths.length > 0) {
          add(diffHits(await diff([...DIFF, ...spec], op.dir), ctx))
        }

        continue
      }

      if (!op.isEverything && op.paths.length === 0 && !op.isTrackedOnly) {
        continue
      }

      add(diffHits(await diff([...DIFF, ...spec], op.dir), ctx))

      if (op.isTrackedOnly) {
        continue
      }

      const listed = new Set(splitNull(await diff(['ls-files', '--others', '--exclude-standard', '-z', ...spec], op.dir)))

      if (op.isForce) {
        for (const file of splitNull(await diff(['ls-files', '--others', '--ignored', '--exclude-standard', '-z', ...spec], op.dir))) {
          listed.add(file)
        }
      }

      const files = [...listed]

      if (files.length > MAX_NEW_FILES) {
        notes.push(`${files.length} new files would be added; only the first ${MAX_NEW_FILES} were scanned.`)
      }

      for (const file of files.slice(0, MAX_NEW_FILES)) {
        let text: string

        try {
          text = await runner.readFile(joinPath(op.dir, file))
        } catch {
          // Gone, unreadable or over the read limit: nothing to scan.
          continue
        }

        if (text.includes('\u0000')) {
          continue
        }

        const { findings } = scan(text, { ...ctx, path: file })

        add(findings.map(f => toHit(f, `${file}:${f.line} (new file)`)))
      }
    }
  } catch (error) {
    notes.push(`The git changes could not be read (${errorName(error)}), so they were not scanned.`)
  }

  return { hits, notes }
}

// ---------------------------------------------------------------------------
// Messages

const MAX_LISTED = 8

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? '' : 's'}`

const list = (hits: readonly Hit[]): string[] => {
  const lines = hits.slice(0, MAX_LISTED).map(hit => `  - ${hit.label} [${hit.rule}] at ${hit.location} (id ${hit.fingerprint})`)

  if (hits.length > MAX_LISTED) {
    lines.push(`  - and ${hits.length - MAX_LISTED} more`)
  }

  return lines
}

const allowHint = (hits: readonly Hit[]): string =>
  `${hits.length === 1 ? 'If it is a harmless placeholder' : 'If they are harmless placeholders'}, the user can run /secret-guard allow fp:${hits[0]?.fingerprint ?? ''} (one value) or /secret-guard allow path:<glob> (a whole file).`

/**
 * The text a refused tool call carries back to the model. `subject` says what
 * was refused ("this Write", "this shell command"); `outcome` what did not happen.
 */
export const denyMessage = (subject: string, outcome: string, hits: readonly Hit[]): string =>
  [
    `secret-guard blocked ${subject}: ${plural(hits.length, 'possible secret')} found. The values are hidden on purpose.`,
    ...list(hits),
    `${outcome} Do not retry with the same value. Keep secrets out of files, commands and commits: read them from an environment variable or a secrets manager and refer to them by name.`,
    allowHint(hits),
  ].join('\n')

/**
 * The text shown to the person when their prompt is dropped. One line on
 * purpose: the app shows it in a banner after "Prompt dropped by a hook:", and
 * that banner turns a line break into a "�". So it opens with what was found,
 * not with "stopped this prompt" (the banner already says that).
 */
export const promptMessage = (hits: readonly Hit[]): string => {
  const found = hits.slice(0, MAX_LISTED).map(hit => `${hit.label} [${hit.rule}] at ${hit.location} (id ${hit.fingerprint})`)

  if (hits.length > MAX_LISTED) {
    found.push(`and ${hits.length - MAX_LISTED} more`)
  }

  return [
    `secret-guard found ${plural(hits.length, 'possible secret')} in your prompt, so nothing was sent. The values are hidden on purpose.`,
    `Found: ${found.join('; ')}.`,
    'Remove the value (describe it, or use a placeholder) and send again.',
    `${hits.length === 1 ? 'If it is a harmless placeholder' : 'If they are harmless placeholders'}, run /secret-guard allow fp:${hits[0]?.fingerprint ?? ''} first.`,
  ].join(' ')
}

/** What warn mode, or a guard that could not scan, shows loudly instead of blocking. */
export const warnMessage = (subject: string, hits: readonly Hit[], notes: readonly string[]): string =>
  [
    ...(hits.length > 0
      ? [`secret-guard WARNING: ${plural(hits.length, 'possible secret')} in ${subject} (values hidden). It was NOT blocked.`, ...list(hits)]
      : [`secret-guard WARNING: ${subject} was not fully scanned.`]),
    ...notes.map(note => `  ${note}`),
  ].join('\n')
