// Reading git out of a shell command, and reading a unified diff. Pure
// functions: the hooks run git itself (through `$.process.run`) and hand the
// text to these.
//
// The command parser is a best effort, not a shell. It understands quotes,
// `&&` `||` `;` `|` and newlines, `git -C <dir>`, and the flags of `add` and
// `commit` that change what gets staged. It does not follow `cd`, variables,
// aliases or scripts: a commit made some other way is a commit this does not see.

export type GitOp = {
  kind: 'add' | 'commit'
  /** From `git -C <dir>`; absent means the session's folder. */
  dir?: string
  /** The pathspecs named on the command line. */
  paths: string[]
  /** `git add -A` with no path: the whole tree. */
  isEverything: boolean
  /** `git add -u`: tracked files only, no new ones. */
  isTrackedOnly: boolean
  /** `git add -f`: ignored files are added as well. */
  isForce: boolean
  /** `git commit -a`, `-p` or `--interactive`: working-tree changes are staged as part of the commit. */
  isCommitAll: boolean
  /** `--dry-run`, or an interactive add: nothing gets staged by this command. */
  isSkipped: boolean
}

const SEPARATORS = new Set([';', '&', '|', '\n', '\r', '(', ')'])

/** Splits a command line into simple commands, each a list of words with the quotes taken off. */
export const splitCommand = (command: string): string[][] => {
  const segments: string[][] = []
  let tokens: string[] = []
  let word = ''
  let hasWord = false
  let quote: '"' | "'" | null = null

  const endWord = () => {
    if (hasWord) {
      tokens.push(word)
    }

    word = ''
    hasWord = false
  }

  const endSegment = () => {
    endWord()

    if (tokens.length > 0) {
      segments.push(tokens)
    }

    tokens = []
  }

  for (let i = 0; i < command.length; i += 1) {
    const c = command.charAt(i)

    if (quote !== null) {
      if (c === quote) {
        quote = null
      } else if (c === '\\' && quote === '"' && (command[i + 1] === '"' || command[i + 1] === '\\')) {
        i += 1
        word += command[i]
      } else {
        word += c
      }

      continue
    }

    if (c === '"' || c === "'") {
      quote = c
      hasWord = true
    } else if (c === '\\' && (command[i + 1] === '"' || command[i + 1] === "'" || command[i + 1] === ' ')) {
      // A backslash is a path separator on Windows; it only escapes a quote or a space.
      i += 1
      word += command[i]
      hasWord = true
    } else if (SEPARATORS.has(c)) {
      endSegment()
    } else if (c === ' ' || c === '\t') {
      endWord()
    } else {
      word += c
      hasWord = true
    }
  }

  endSegment()

  return segments
}

const GIT_ARG_OPTIONS = new Set(['-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--config-env'])
const PREFIXES = new Set(['sudo', 'command', 'time', 'env', 'nohup', 'exec', 'builtin'])
const COMMIT_SHORT_WITH_ARG = new Set(['m', 'F', 'C', 'c', 't'])
const COMMIT_LONG_WITH_ARG = new Set([
  '--message',
  '--file',
  '--author',
  '--date',
  '--reuse-message',
  '--reedit-message',
  '--template',
  '--fixup',
  '--squash',
  '--cleanup',
  '--trailer',
])

const isGit = (word: string): boolean => /(?:^|[\\/])git(?:\.exe)?$/i.test(word)

const joinDir = (base: string | undefined, next: string): string =>
  base === undefined || /^(?:[A-Za-z]:)?[\\/]/.test(next) ? next : `${base}/${next}`

const parseAdd = (args: readonly string[], op: GitOp): void => {
  let isRest = false

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? ''

    if (isRest) {
      op.paths.push(a)
    } else if (a === '--') {
      isRest = true
    } else if (a.startsWith('--')) {
      if (a === '--all') {
        op.isEverything = true
      } else if (a === '--update') {
        op.isTrackedOnly = true
      } else if (a === '--force') {
        op.isForce = true
      } else if (a === '--dry-run' || a === '--patch' || a === '--interactive' || a === '--edit') {
        op.isSkipped = true
      } else if (a.startsWith('--pathspec-from-file')) {
        // The paths are in a file this does not read: look at everything.
        op.isEverything = true
        i += a.includes('=') ? 0 : 1
      }
    } else if (a.startsWith('-') && a.length > 1) {
      for (const ch of a.slice(1)) {
        if (ch === 'A') {
          op.isEverything = true
        } else if (ch === 'u') {
          op.isTrackedOnly = true
        } else if (ch === 'f') {
          op.isForce = true
        } else if (ch === 'n' || ch === 'p' || ch === 'i' || ch === 'e') {
          op.isSkipped = true
        }
      }
    } else {
      op.paths.push(a)
    }
  }

  // `git add -A src` adds what changed under src; only a bare -A means the whole tree.
  op.isEverything = op.isEverything && op.paths.length === 0
}

const parseCommit = (args: readonly string[], op: GitOp): void => {
  let isRest = false

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? ''

    if (isRest) {
      op.paths.push(a)
    } else if (a === '--') {
      isRest = true
    } else if (a.startsWith('--')) {
      if (a === '--all' || a === '--patch' || a === '--interactive') {
        op.isCommitAll = true
      } else if (a === '--dry-run') {
        op.isSkipped = true
      } else if (COMMIT_LONG_WITH_ARG.has(a)) {
        i += 1
      }
    } else if (a.startsWith('-') && a.length > 1) {
      for (let k = 1; k < a.length; k += 1) {
        const ch = a.charAt(k)

        if (ch === 'a' || ch === 'p') {
          op.isCommitAll = true
        } else if (COMMIT_SHORT_WITH_ARG.has(ch)) {
          // `-mmessage` carries its argument; `-m message` takes the next word.
          i += k === a.length - 1 ? 1 : 0
          break
        }
      }
    } else {
      op.paths.push(a)
    }
  }
}

/** The `git add` and `git commit` commands inside a shell command line, in order. */
export const parseGitOps = (command: string): GitOp[] => {
  const ops: GitOp[] = []

  for (const tokens of splitCommand(command)) {
    let at = 0

    const word = (i: number): string => tokens[i] ?? ''

    while (at < tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word(at)) || PREFIXES.has(word(at)))) {
      at += 1
    }

    if (at >= tokens.length || !isGit(word(at))) {
      continue
    }

    at += 1

    let dir: string | undefined

    while (at < tokens.length && word(at).startsWith('-')) {
      if (word(at) === '-C') {
        const next = tokens[at + 1]

        if (next !== undefined) {
          dir = joinDir(dir, next)
        }

        at += 2
      } else {
        at += GIT_ARG_OPTIONS.has(word(at)) ? 2 : 1
      }
    }

    const sub = tokens[at]

    if (sub !== 'add' && sub !== 'commit') {
      continue
    }

    const op: GitOp = {
      kind: sub,
      paths: [],
      isEverything: false,
      isTrackedOnly: false,
      isForce: false,
      isCommitAll: false,
      isSkipped: false,
    }

    if (dir !== undefined) {
      op.dir = dir
    }

    if (sub === 'add') {
      parseAdd(tokens.slice(at + 1), op)
    } else {
      parseCommit(tokens.slice(at + 1), op)
    }

    ops.push(op)
  }

  return ops
}

// ---------------------------------------------------------------------------
// Diffs

/** What a diff adds to one file: its text, and for each line of it, the line number it will have in the file. */
export type AddedFile = {
  file: string
  text: string
  lines: number[]
}

const diffPath = (raw: string): string | null => {
  let path = raw.replace(/\t.*$/, '')

  if (path === '/dev/null') {
    return null
  }

  if (path.startsWith('"') && path.endsWith('"') && path.length >= 2) {
    path = path.slice(1, -1)
  }

  return path.replace(/^b\//, '')
}

/**
 * The added lines of a `git diff -U0` per file, joined, so a secret that spans
 * lines (a private key) is seen whole, with each line's real line number kept.
 */
export const addedByFile = (diff: string): AddedFile[] => {
  const files: AddedFile[] = []
  let current: AddedFile | null = null
  let oldLeft = 0
  let newLeft = 0
  let newLine = 0

  for (const raw of diff.split('\n')) {
    if (oldLeft > 0 || newLeft > 0) {
      if (raw.startsWith('+')) {
        newLeft -= 1

        if (current !== null) {
          current.text += current.lines.length > 0 ? `\n${raw.slice(1)}` : raw.slice(1)
          current.lines.push(newLine)
        }

        newLine += 1
        continue
      }

      if (raw.startsWith('-')) {
        oldLeft -= 1
        continue
      }

      if (raw.startsWith('\\')) {
        continue
      }

      if (raw.startsWith(' ')) {
        oldLeft -= 1
        newLeft -= 1
        newLine += 1
        continue
      }

      oldLeft = 0
      newLeft = 0
    }

    if (raw.startsWith('+++ ')) {
      const file = diffPath(raw.slice(4))

      current = file === null ? null : { file, text: '', lines: [] }

      if (current !== null) {
        files.push(current)
      }

      continue
    }

    const hunk = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(raw)

    if (hunk) {
      oldLeft = hunk[1] === undefined ? 1 : Number(hunk[1])
      newLine = Number(hunk[2])
      newLeft = hunk[3] === undefined ? 1 : Number(hunk[3])
    }
  }

  return files.filter(file => file.lines.length > 0)
}

/** Splits `git ... -z` output into its paths. */
export const splitNull = (output: string): string[] => output.split('\0').filter(path => path !== '')
