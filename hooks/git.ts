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
  // A backslash (or, in PowerShell, a backtick) before a line break continues the line.
  const text = command.split('\\\r\n').join(' ').split('\\\n').join(' ').split('`\r\n').join(' ').split('`\n').join(' ')

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

  for (let i = 0; i < text.length; i += 1) {
    const c = text.charAt(i)

    if (quote !== null) {
      if (c === quote) {
        quote = null
      } else if (c === '\\' && quote === '"' && (text[i + 1] === '"' || text[i + 1] === '\\')) {
        i += 1
        word += text[i]
      } else {
        word += c
      }

      continue
    }

    if (c === '"' || c === "'") {
      quote = c
      hasWord = true
    } else if (c === '\\' && (text[i + 1] === '"' || text[i + 1] === "'" || text[i + 1] === ' ')) {
      // A backslash is a path separator on Windows; it only escapes a quote or a space.
      i += 1
      word += text[i]
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

// Words that run another command (or open a shell construct) and are then followed by it.
const PREFIXES = new Set([
  'sudo',
  'command',
  'time',
  'env',
  'nohup',
  'exec',
  'builtin',
  'doas',
  'nice',
  'stdbuf',
  'if',
  'then',
  'else',
  'elif',
  'do',
  'while',
  'until',
  '!',
  '{',
])

const SHELLS = /^(?:bash|sh|zsh|dash|ksh|fish|pwsh|powershell|cmd)(?:\.exe)?$/i
const SHELL_COMMAND_FLAG = /^(?:-[A-Za-z]*c|-co\w*|\/[ck])$/i
const CD_COMMANDS = /^(?:cd|pushd|chdir|set-location|sl)$/i

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

// Every long option of the two commands. Git takes any unambiguous prefix of one
// (`--upd` is `--update`), so a flag is matched against these before it is read.
const ADD_LONG = [
  '--dry-run',
  '--verbose',
  '--interactive',
  '--patch',
  '--edit',
  '--force',
  '--update',
  '--renormalize',
  '--intent-to-add',
  '--all',
  '--no-all',
  '--ignore-removal',
  '--no-ignore-removal',
  '--refresh',
  '--ignore-errors',
  '--ignore-missing',
  '--sparse',
  '--chmod',
  '--pathspec-from-file',
  '--pathspec-file-nul',
]
const COMMIT_LONG = [
  '--all',
  '--patch',
  '--interactive',
  '--dry-run',
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
  '--amend',
  '--no-verify',
  '--no-post-rewrite',
  '--signoff',
  '--no-signoff',
  '--verbose',
  '--no-verbose',
  '--quiet',
  '--edit',
  '--no-edit',
  '--allow-empty',
  '--allow-empty-message',
  '--reset-author',
  '--short',
  '--branch',
  '--porcelain',
  '--long',
  '--null',
  '--status',
  '--no-status',
  '--gpg-sign',
  '--no-gpg-sign',
  '--include',
  '--only',
  '--untracked-files',
  '--pathspec-from-file',
  '--pathspec-file-nul',
  '--verify',
  '--post-rewrite',
]

/** A long flag as git would read it: the full option for an exact or unambiguous-prefix match, else the flag as typed. */
const canon = (flag: string, options: readonly string[]): string => {
  const name = flag.split('=')[0] ?? flag

  if (options.includes(name)) {
    return name
  }

  const matches = options.filter(option => option.startsWith(name))

  return matches.length === 1 ? (matches[0] ?? name) : name
}

/** A word with the shell's escapes taken off (`g\it`, PowerShell's g`it), for matching the words that name a command. */
const unescape = (word: string): string => word.split('\\').join('').split('`').join('')

const isGit = (word: string): boolean => /(?:^|[\\/])git(?:\.exe)?$/i.test(word) || /(?:^|[\\/])git(?:\.exe)?$/i.test(unescape(word))

const baseName = (word: string): string => word.split('\\').join('/').split('/').pop() ?? word

const isAssignment = (word: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)

const isAbsolute = (path: string): boolean => /^(?:[A-Za-z]:)?[\\/]/.test(path)

const joinDir = (base: string | undefined, next: string | undefined): string | undefined => {
  if (next === undefined || next === '') {
    return base
  }

  return base === undefined || isAbsolute(next) ? next : `${base}/${next}`
}

const parseAdd = (args: readonly string[], op: GitOp): void => {
  let isRest = false

  for (let i = 0; i < args.length; i += 1) {
    const a = args[i] ?? ''

    if (isRest) {
      op.paths.push(a)
    } else if (a === '--') {
      isRest = true
    } else if (a.startsWith('--')) {
      const flag = canon(a, ADD_LONG)

      if (flag === '--all') {
        op.isEverything = true
      } else if (flag === '--update') {
        op.isTrackedOnly = true
      } else if (flag === '--force') {
        op.isForce = true
      } else if (flag === '--dry-run' || flag === '--patch' || flag === '--interactive' || flag === '--edit') {
        op.isSkipped = true
      } else if (flag === '--pathspec-from-file') {
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
      const flag = canon(a, COMMIT_LONG)

      if (flag === '--all' || flag === '--patch' || flag === '--interactive') {
        op.isCommitAll = true
      } else if (flag === '--dry-run') {
        op.isSkipped = true
      } else if (flag === '--pathspec-from-file') {
        // The paths are in a file this does not read: look at every change.
        op.isCommitAll = true
        i += a.includes('=') ? 0 : 1
      } else if (COMMIT_LONG_WITH_ARG.has(flag) && !a.includes('=')) {
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

const newOp = (kind: 'add' | 'commit', dir: string | undefined): GitOp => {
  const op: GitOp = { kind, paths: [], isEverything: false, isTrackedOnly: false, isForce: false, isCommitAll: false, isSkipped: false }

  if (dir !== undefined) {
    op.dir = dir
  }

  return op
}

// A command whose own word is a variable (`$G commit`) cannot be read, so the
// widest reading is taken: every staged and tracked change, and every new file.
const guessOps = (words: readonly string[], dir: string | undefined): GitOp[] => {
  const ops: GitOp[] = []

  if (words.some(w => unescape(w) === 'commit')) {
    const op = newOp('commit', dir)

    op.isCommitAll = true
    ops.push(op)
  }

  if (words.some(w => unescape(w) === 'add')) {
    const op = newOp('add', dir)

    op.isEverything = true
    ops.push(op)
  }

  return ops
}

const MAX_DEPTH = 3

const parseOps = (command: string, depth: number, startDir: string | undefined): GitOp[] => {
  const ops: GitOp[] = []
  let cwd = startDir
  let hasMoved = false

  // After a `cd` the command may be in the new folder or, if that `cd` was in a
  // subshell or failed, still in the old one: both are looked at.
  const emit = (make: (base: string | undefined) => GitOp): void => {
    ops.push(make(cwd))

    if (hasMoved) {
      ops.push(make(startDir))
    }
  }

  for (const tokens of splitCommand(command)) {
    let at = 0
    let hasPrefix = false
    let envDir: string | undefined

    while (at < tokens.length) {
      const w = tokens[at] ?? ''

      if (isAssignment(w)) {
        // GIT_WORK_TREE and GIT_DIR point git somewhere else for this command.
        const [name = '', ...value] = w.split('=')

        if (name === 'GIT_WORK_TREE') {
          envDir = value.join('=')
        } else if (name === 'GIT_DIR' && envDir === undefined) {
          envDir = value.join('=').replace(/[\\/]\.git[\\/]?$/, '')
        }
      } else if (PREFIXES.has(unescape(w).toLowerCase())) {
        hasPrefix = true
      } else if (!(hasPrefix && w.startsWith('-'))) {
        break
      }

      at += 1
    }

    if (at >= tokens.length) {
      continue
    }

    const first = unescape(tokens[at] ?? '')

    if (CD_COMMANDS.test(first)) {
      const target = tokens.slice(at + 1).find(t => !t.startsWith('-'))

      // A target the shell would have to expand (`~`, `$HOME`, `-`) cannot be followed.
      if (target !== undefined && !/^-$|[$`~%]/.test(target)) {
        cwd = joinDir(cwd, target)
        hasMoved = true
      }

      continue
    }

    if (depth < MAX_DEPTH && (SHELLS.test(baseName(tokens[at] ?? '')) || SHELLS.test(first))) {
      const flag = tokens.findIndex((t, i) => i > at && SHELL_COMMAND_FLAG.test(t))

      if (flag >= 0) {
        ops.push(...parseOps(tokens.slice(flag + 1).join(' '), depth + 1, cwd))
      }

      continue
    }

    if (depth < MAX_DEPTH && first.toLowerCase() === 'eval') {
      ops.push(...parseOps(tokens.slice(at + 1).join(' '), depth + 1, cwd))

      continue
    }

    if (/^[$`]/.test(tokens[at] ?? '')) {
      for (const guess of guessOps(tokens.slice(at + 1), cwd)) {
        ops.push(guess)
      }

      continue
    }

    // `sudo -u me git ...`, `env -i git ...`: with a prefix word first, git may be a few words along.
    let gitAt = at

    if (!isGit(tokens[at] ?? '')) {
      if (!hasPrefix) {
        continue
      }

      gitAt = -1

      for (let j = at; j < Math.min(tokens.length, at + 6); j += 1) {
        if (isGit(tokens[j] ?? '')) {
          gitAt = j
          break
        }
      }

      if (gitAt < 0) {
        continue
      }
    }

    at = gitAt + 1

    let dir: string | undefined
    let tree: string | undefined

    while (at < tokens.length && (tokens[at] ?? '').startsWith('-')) {
      const w = tokens[at] ?? ''

      if (w === '-C') {
        dir = joinDir(dir, tokens[at + 1])
        at += 2
      } else if (w.startsWith('--work-tree=')) {
        tree = w.slice('--work-tree='.length)
        at += 1
      } else if (w === '--work-tree') {
        tree = tokens[at + 1]
        at += 2
      } else if (w.startsWith('--git-dir=') || w === '--git-dir') {
        const value = w === '--git-dir' ? (tokens[at + 1] ?? '') : w.slice('--git-dir='.length)

        // A `.git` folder stands for the working tree around it, unless --work-tree says otherwise.
        if (tree === undefined) {
          tree = value.replace(/[\\/]\.git[\\/]?$/, '')
        }

        at += w === '--git-dir' ? 2 : 1
      } else {
        at += GIT_ARG_OPTIONS.has(w) ? 2 : 1
      }
    }

    const sub = unescape(tokens[at] ?? '')

    if (sub !== 'add' && sub !== 'commit') {
      continue
    }

    const args = tokens.slice(at + 1)

    emit(base => {
      const op = newOp(sub, joinDir(joinDir(joinDir(base, envDir), dir), tree))

      if (sub === 'add') {
        parseAdd(args, op)
      } else {
        parseCommit(args, op)
      }

      return op
    })
  }

  return ops
}

/** The `git add` and `git commit` commands inside a shell command line, in order. */
export const parseGitOps = (command: string): GitOp[] => parseOps(command, 0, undefined)

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

/**
 * The files a diff reports as "Binary files ... differ" (a `.gitattributes` with
 * `-diff` or `binary`, UTF-16 text, a real binary), leaving out a file that was deleted.
 */
export const binaryPaths = (diff: string): string[] => {
  const paths: string[] = []

  for (const raw of diff.split('\n')) {
    const m = /^Binary files .* and b\/(.+) differ\r?$/.exec(raw)

    if (m?.[1] !== undefined) {
      paths.push(m[1])
    }
  }

  return paths
}

// A file git or a reader took for UTF-8 that is really UTF-16 (Windows PowerShell's
// `>` writes it) has a NUL after nearly every letter. Real binaries have far fewer.
const WIDE_NUL_RATIO = 0.3

/** The text with its NULs taken out when it is UTF-16 read as UTF-8; the text itself when it has none; undefined for a real binary. */
export const unwide = (text: string): string | undefined => {
  if (!text.includes('\0')) {
    return text
  }

  const bare = text.split('\0').join('')

  return text.length - bare.length >= text.length * WIDE_NUL_RATIO ? bare : undefined
}
