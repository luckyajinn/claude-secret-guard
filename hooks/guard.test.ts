import { expect, test } from 'claude-code/testing'

import { compileAllow, EMPTY_ALLOW } from './allow'
import { fake, SALT } from './fixtures'
import { fingerprint } from './hash'
import {
  checkCommandText,
  checkEdit,
  checkGit,
  checkPromptText,
  checkWrite,
  denyMessage,
  isPersonPrompt,
  promptMessage,
  blockedSummary,
  commonDir,
  warnMessage,
} from './guard'
import type { Hit, Runner, ScanContext } from './guard'

const ctx: ScanContext = { salt: SALT, allow: EMPTY_ALLOW }

// What a message may never contain: any piece of the value.
const leaks = (message: string, secret: string): boolean =>
  message.includes(secret) || message.includes(secret.slice(0, 8)) || message.includes(secret.slice(-8)) || message.includes(secret.slice(8, 20))

// ---------------------------------------------------------------------------
// The text guards

test('a write is located as path:line:column and a clean one is clean', () => {
  const token = fake.githubToken()
  const hit = checkWrite('/p/src/config.ts', `line one\nconst token = "${token}"\n`, ctx).hits

  expect(hit).toEqual([
    { rule: 'github-token', label: 'GitHub token', location: '/p/src/config.ts:2:16', fingerprint: fingerprint(token, SALT), file: '/p/src/config.ts' },
  ])
  expect(checkWrite('/p/src/config.ts', 'const x = 1\n', ctx)).toEqual({ hits: [], notes: [] })
})

test('a write to an allowlisted path is not scanned', () => {
  const text = `token = "${fake.githubToken()}"`
  const allow = compileAllow(['path:fixtures/**'])

  expect(checkWrite('/p/fixtures/a.json', text, { salt: SALT, allow }).hits).toEqual([])
  expect(checkWrite('/p/src/a.json', text, { salt: SALT, allow }).hits).toHaveLength(1)
})

test('an edit scans only the new text, so an old secret in the file never blocks it', () => {
  const token = fake.githubToken()

  expect(checkEdit('/p/a.ts', 'const x = 2', ctx).hits).toEqual([])
  expect(checkEdit('/p/a.ts', `a\nb ${token}`, ctx).hits[0]?.location).toBe('/p/a.ts (new text, line 2)')
})

test('a command and a prompt are located by line and column', () => {
  const token = fake.githubToken()

  expect(checkCommandText(`echo hi\ncurl -H "X: ${token}" x`, ctx).hits[0]?.location).toBe('command line 2, column 13')
  expect(checkPromptText(`here it is: ${token}`, ctx).hits[0]?.location).toBe('prompt line 1, column 13')
  expect(checkCommandText('git status', ctx).hits).toEqual([])
})

test('a prompt that may hold the person’s words is guarded; one a machine raised is not', () => {
  for (const kind of ['composer', 'bridge', 'sdk', 'unclassified', 'slack-ping', 'some-future-kind']) {
    expect(isPersonPrompt({ kind }), kind).toBe(true)
  }

  expect(isPersonPrompt({ kind: 'plugin', asUser: true })).toBe(true)
  expect(isPersonPrompt(undefined)).toBe(true)

  for (const kind of ['task-notification', 'scheduled-trigger', 'peer', 'peer-send-message', 'channel', 'coordinator', 'observer', 'auto-continuation']) {
    expect(isPersonPrompt({ kind }), kind).toBe(false)
  }

  expect(isPersonPrompt({ kind: 'plugin' })).toBe(false)
  expect(isPersonPrompt({ kind: 'plugin', asUser: false })).toBe(false)
})

test('a prompt the person does not see as typed is never guarded', () => {
  expect(isPersonPrompt({ kind: 'composer' }, true)).toBe(false)
  expect(isPersonPrompt(undefined, true)).toBe(false)
  expect(isPersonPrompt({ kind: 'unclassified' }, true)).toBe(false)
  expect(isPersonPrompt({ kind: 'composer' }, false)).toBe(true)
})

// ---------------------------------------------------------------------------
// Messages

test('no message holds any part of the value', () => {
  const secrets = [fake.githubToken(), fake.awsKeyId(), fake.jwt(), fake.privateKey(), fake.anthropicKey()]
  const text = secrets.map((s, i) => `line ${i}: ${s}`).join('\n')
  const hits = checkWrite('/p/x.ts', text, ctx).hits

  expect(hits).toHaveLength(secrets.length)

  const messages = [
    denyMessage('this Write', 'Nothing was written.', hits),
    promptMessage(hits),
    warnMessage('this Write', hits, ['a note']),
    JSON.stringify(hits),
  ]

  for (const message of messages) {
    for (const secret of secrets) {
      expect(leaks(message, secret), message.slice(0, 40)).toBe(false)
    }
  }
})

test('a deny message names the rule and place and says how to allow a false positive', () => {
  const hits = checkWrite('/p/src/a.ts', `const t = "${fake.githubToken()}"`, ctx).hits
  const message = denyMessage('this Write', 'Nothing was written.', hits)

  expect(message).toContain('secret-guard blocked this Write: 1 possible secret found')
  expect(message).toContain('GitHub token [github-token] at /p/src/a.ts:1:12')
  expect(message).toContain(`(id ${hits[0]?.fingerprint})`)
  expect(message).toContain('Nothing was written.')
  expect(message).toContain(`/secret-guard allow fp:${hits[0]?.fingerprint}`)
})

test('a long list is cut with a count', () => {
  const hit: Hit = { rule: 'jwt', label: 'JSON Web Token', location: 'x:1', fingerprint: 'abcdef01' }
  const hits = Array.from({ length: 12 }, () => hit)
  const message = denyMessage('this Write', 'Nothing was written.', hits)

  expect(message.split('\n').filter(line => line.startsWith('  - '))).toHaveLength(9)
  expect(message).toContain('and 4 more')
  expect(message).toContain('12 possible secrets')
})

test('a warning says it was not blocked, and a notes-only warning says it was not fully scanned', () => {
  const hit: Hit = { rule: 'jwt', label: 'JSON Web Token', location: 'x:1', fingerprint: 'abcdef01' }

  expect(warnMessage('this Write', [hit], [])).toContain('It was NOT blocked.')
  expect(warnMessage('this git command', [], ['git exited with 2'])).toContain('was not fully scanned')
  expect(warnMessage('this git command', [], ['git exited with 2'])).toContain('git exited with 2')
})

// ---------------------------------------------------------------------------
// git

type Call = { args: string[]; dir: string | undefined }

const fakeRunner = (
  replies: Record<string, { exitCode?: number; stdout?: string; stderr?: string; isTruncated?: boolean }>,
  files: Record<string, string> = {},
) => {
  const calls: Call[] = []
  const reads: string[] = []
  const runner: Runner = {
    git: async (args, dir) => {
      calls.push({ args, dir })

      const key =
        args[0] === 'rev-parse'
          ? 'toplevel'
          : args.includes('--cached')
            ? 'cached'
            : args[0] === 'ls-files'
              ? args.includes('--ignored')
                ? 'ignored'
                : 'others'
              : 'worktree'
      const reply = replies[key] ?? {}

      return { exitCode: reply.exitCode ?? 0, stdout: reply.stdout ?? '', stderr: reply.stderr ?? '', isTruncated: reply.isTruncated ?? false }
    },
    readFile: async path => {
      reads.push(path)

      if (!(path in files)) {
        throw new Error('missing')
      }

      return files[path] ?? ''
    },
  }

  return { runner, calls, reads }
}

const diffAdding = (file: string, line: number, text: string): string =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -${line - 1},0 +${line},1 @@`, `+${text}`].join('\n')

test('git commit scans the staged changes and names file and line', async () => {
  const token = fake.githubToken()
  const { runner, calls } = fakeRunner({ cached: { stdout: diffAdding('src/app.ts', 14, `const t = "${token}"`) } })
  const out = await checkGit('git commit -m "add config"', ctx, runner)

  expect(out.hits).toEqual([
    { rule: 'github-token', label: 'GitHub token', location: 'src/app.ts:14', fingerprint: fingerprint(token, SALT), file: 'src/app.ts' },
  ])
  expect(out.notes).toEqual([])
  // The diff, then one rev-parse to say which folder the finding is in.
  expect(calls.map(c => c.args[0])).toEqual(['diff', 'rev-parse'])
  expect(calls[0]?.args).toContain('--cached')
  expect(calls[0]?.args).toContain('--no-textconv')
  expect(calls[0]?.args).toContain('--no-ext-diff')
})

test('git commit -a also scans the working-tree changes, and a path limits them', async () => {
  const token = fake.githubToken()
  const { runner, calls } = fakeRunner({ worktree: { stdout: diffAdding('b.ts', 3, `x = "${token}"`) } })
  const out = await checkGit('git commit -am "wip"', ctx, runner)

  expect(out.hits.map(h => h.location)).toEqual(['b.ts:3'])
  expect(calls.filter(c => c.args[0] === 'diff').map(c => c.args.includes('--cached'))).toEqual([true, false])

  const scoped = fakeRunner({})

  await checkGit('git commit -m x src/a.ts', ctx, scoped.runner)
  expect(scoped.calls[1]?.args.slice(-2)).toEqual(['--', 'src/a.ts'])
})

test('git add scans tracked changes and the new files it would add', async () => {
  const token = fake.githubToken()
  const { runner, calls, reads } = fakeRunner(
    {
      worktree: { stdout: diffAdding('old.ts', 7, `const t = "${token}"`) },
      others: { stdout: 'new.env\0notes.md\0bin.dat\0' },
    },
    { 'new.env': `TOKEN=${fake.awsKeyId()}\n`, 'notes.md': '# notes\n', 'bin.dat': 'ab\u0000cd' },
  )
  const out = await checkGit('git add .', ctx, runner)

  expect(out.hits.map(h => `${h.rule}@${h.location}`)).toEqual(['github-token@old.ts:7', 'aws-access-key-id@new.env:1 (new file)'])
  expect(reads).toEqual(['new.env', 'notes.md', 'bin.dat'])
  expect(calls[0]?.args.slice(-2)).toEqual(['--', '.'])
})

test('git add -u looks at tracked files only, and git add -f also at ignored ones', async () => {
  const tracked = fakeRunner({})

  await checkGit('git add -u', ctx, tracked.runner)
  expect(tracked.calls.map(c => c.args[0])).toEqual(['diff'])

  const forced = fakeRunner({ ignored: { stdout: '.env\0' } }, { '.env': `X=${fake.awsKeyId()}` })
  const out = await checkGit('git add -f .env', ctx, forced.runner)

  expect(forced.calls.some(c => c.args.includes('--ignored'))).toBe(true)
  expect(out.hits.map(h => h.location)).toEqual(['.env:1 (new file)'])
})

test('git -C reads the other folder, and reads files from it', async () => {
  const { runner, calls, reads } = fakeRunner({ others: { stdout: 'a.txt\0' } }, { 'sub/a.txt': 'nothing here\n' })

  await checkGit('git -C sub add .', ctx, runner)
  expect(calls.every(c => c.dir === 'sub')).toBe(true)
  expect(reads).toEqual(['sub/a.txt'])
})

test('a git add with nothing to add, a dry run and a command with no git read nothing', async () => {
  for (const command of ['git add', 'git add --dry-run .', 'git commit --dry-run', 'ls -la', 'git status', 'echo git add .']) {
    const { runner, calls } = fakeRunner({})

    expect(await checkGit(command, ctx, runner), command).toEqual({ hits: [], notes: [] })
    expect(calls, command).toEqual([])
  }
})

test('the allowlist applies to what git would commit', async () => {
  const token = fake.githubToken()
  const { runner } = fakeRunner({ cached: { stdout: diffAdding('fixtures/a.json', 1, `"t": "${token}"`) } })
  const byPath = await checkGit('git commit -m x', { salt: SALT, allow: compileAllow(['path:fixtures/**']) }, runner)
  const byPrint = await checkGit('git commit -m x', { salt: SALT, allow: compileAllow([`fp:${fingerprint(token, SALT)}`]) }, runner)

  expect(byPath.hits).toEqual([])
  expect(byPrint.hits).toEqual([])
})

test('a secret in the same place is reported once, not twice', async () => {
  const token = fake.githubToken()
  const { runner } = fakeRunner({ cached: { stdout: diffAdding('a.ts', 2, `x = "${token}"`) }, worktree: { stdout: diffAdding('a.ts', 2, `x = "${token}"`) } })
  const out = await checkGit('git commit -a -m x', ctx, runner)

  expect(out.hits).toHaveLength(1)
})

test('a git failure is a note, except not being in a repository', async () => {
  const failing = fakeRunner({ cached: { exitCode: 2, stderr: 'fatal: something broke' } })
  const out = await checkGit('git commit -m x', ctx, failing.runner)

  expect(out.hits).toEqual([])
  expect(out.notes[0]).toContain('git exited with 2')

  const outside = fakeRunner({ cached: { exitCode: 128, stderr: 'fatal: not a git repository (or any parent)' } })

  expect(await checkGit('git commit -m x', ctx, outside.runner)).toEqual({ hits: [], notes: [] })
})

test('a git finding is named by its full path: the repository folder for a diff, the folder git ran in for a new file', async () => {
  const token = fake.githubToken()
  const { runner } = fakeRunner(
    {
      toplevel: { stdout: 'C:/work/app\nweb/\n' },
      worktree: { stdout: diffAdding('web/old.ts', 7, `const t = "${token}"`) },
      others: { stdout: 'page.html\0' },
    },
    { 'page.html': `<script>const k = "${fake.githubToken()}"</script>\n` },
  )
  const out = await checkGit('git add .', ctx, runner)

  // The diff names the file from the repository root; ls-files names it from where git ran (web/).
  expect(out.hits.map(h => h.location)).toEqual(['C:/work/app/web/old.ts:7', 'C:/work/app/web/page.html:1 (new file)'])
  expect(out.hits.map(h => h.file)).toEqual(['C:/work/app/web/old.ts', 'C:/work/app/web/page.html'])
})

test('without a repository folder from git a finding keeps the path git gave', async () => {
  const token = fake.githubToken()
  const { runner } = fakeRunner({ cached: { stdout: diffAdding('src/app.ts', 3, `t = "${token}"`) }, toplevel: { exitCode: 128 } })

  expect((await checkGit('git commit -m x', ctx, runner)).hits.map(h => h.location)).toEqual(['src/app.ts:3'])
})

test('the same line in two repositories is two findings', async () => {
  const token = fake.githubToken()
  const { runner } = fakeRunner({ cached: { stdout: diffAdding('a.ts', 2, `x = "${token}"`) } })
  const out = await checkGit('git -C one commit -m x && git -C two commit -m y', ctx, runner)

  expect(out.hits).toHaveLength(2)
})

test('commonDir finds the folder a set of files share', () => {
  expect(commonDir(['C:/work/app/web/a.ts', 'C:/work/app/web/b/c.ts'])).toBe('C:/work/app/web')
  expect(commonDir(['C:\\work\\app\\a.ts', 'C:/work/app/src/b.ts'])).toBe('C:/work/app')
  expect(commonDir(['/a/x.ts', '/b/y.ts'])).toBe('')
  expect(commonDir(['/a/b/x.ts'])).toBe('/a/b')
  expect(commonDir([])).toBe('')
})

test('the toast says what and where for one finding, and how many files and under which folder for many', () => {
  const at = (file: string, line: number): Hit => ({ rule: 'jwt', label: 'JSON Web Token', location: `${file}:${line}`, fingerprint: 'abcdef01', file })
  const one = [at('/r/src/a.ts', 4)]
  const many = [at('/r/src/a.ts', 4), at('/r/src/a.ts', 9), at('/r/docs/b.md', 2)]

  expect(blockedSummary('this git command', one)).toBe('secret-guard blocked this git command: JSON Web Token at /r/src/a.ts:4')
  expect(blockedSummary('this git command', many)).toBe('secret-guard blocked this git command: 3 possible secrets in 2 files under /r')
  expect(blockedSummary('this git command', [at('/r/src/a.ts', 4), at('/r/src/a.ts', 9)])).toBe(
    'secret-guard blocked this git command: 2 possible secrets in /r/src/a.ts',
  )
  // A command or a prompt has no file.
  const typed: Hit = { rule: 'jwt', label: 'JSON Web Token', location: 'prompt line 2, column 5', fingerprint: 'abcdef01' }

  expect(blockedSummary('your prompt', [typed])).toBe('secret-guard blocked your prompt: JSON Web Token at prompt line 2, column 5')
  expect(blockedSummary('your prompt', [typed, typed])).toBe('secret-guard blocked your prompt: 2 possible secrets')
})

test('many findings over files are listed one line per file, with rules and lines', () => {
  const at = (file: string, line: number, rule: string): Hit => ({ rule, label: rule, location: `${file}:${line}`, fingerprint: 'abcdef01', file })
  const hits = [
    ...Array.from({ length: 7 }, (_, i) => at('/r/a.ts', i + 1, 'jwt')),
    at('/r/b/c.ts', 40, 'github-token'),
    at('/r/b/c.ts', 41, 'jwt'),
    ...Array.from({ length: 9 }, (_, i) => at(`/r/many/f${i}.ts`, 1, 'jwt')),
  ]
  const lines = denyMessage('this git command', 'Nothing was staged or committed.', hits)
    .split('\n')
    .filter(line => line.startsWith('  - '))

  expect(lines[0]).toBe('  - /r/a.ts: 7 findings (jwt) at line 1, 2, 3, 4, 5, 6 ...')
  expect(lines[1]).toBe('  - /r/b/c.ts: 2 findings (github-token, jwt) at line 40, 41')
  expect(lines).toHaveLength(9)
  expect(lines[8]).toBe('  - and 3 more files')
})

test('a runner that cannot run git degrades to a note and never throws', async () => {
  const runner: Runner = {
    git: async () => {
      throw Object.assign(new Error('no process here /secret/path'), { name: 'ProcessUnavailable' })
    },
    readFile: async () => '',
  }
  const out = await checkGit('git commit -m x', ctx, runner)

  expect(out.hits).toEqual([])
  expect(out.notes).toEqual(['The git changes could not be read (ProcessUnavailable), so they were not scanned.'])
  expect(out.notes.join()).not.toContain('/secret/path')
})

test('truncated git output is a note, and many new files are capped', async () => {
  const truncated = fakeRunner({ cached: { stdout: '', isTruncated: true } })

  expect((await checkGit('git commit -m x', ctx, truncated.runner)).notes[0]).toContain('larger than 4 MiB')

  const many = Array.from({ length: 600 }, (_, i) => `f${i}.txt`)
  const files = Object.fromEntries(many.map(f => [f, 'plain text\n']))
  const capped = fakeRunner({ others: { stdout: `${many.join('\0')}\0` } }, files)
  const out = await checkGit('git add .', ctx, capped.runner)

  expect(capped.reads).toHaveLength(500)
  expect(out.notes[0]).toContain('600 new files')
  // Part of it was not scanned, so a guard in block mode refuses it.
  expect(out.isIncomplete).toBe(true)
})

test('a file that git reports as binary but is text is read again with --text', async () => {
  const token = fake.githubToken()
  const calls: string[][] = []
  const runner: Runner = {
    git: async args => {
      calls.push(args)

      const stdout = args.includes('--text')
        ? diffAdding('conf/app.cfg', 3, `t = "${token}"`)
        : args[0] === 'diff'
          ? 'Binary files a/conf/app.cfg and b/conf/app.cfg differ\nBinary files a/logo.png and b/logo.png differ\n'
          : ''

      return { exitCode: 0, stdout, stderr: '', isTruncated: false }
    },
    readFile: async () => '',
  }
  const out = await checkGit('git commit -m x', ctx, runner)
  const again = calls.filter(c => c.includes('--text'))

  expect(out.hits.map(h => h.location)).toEqual(['conf/app.cfg:3'])
  // The image is not read again.
  expect(again).toHaveLength(1)
  expect(again[0]?.slice(-2)).toEqual(['--', ':(top,literal)conf/app.cfg'])
})

test('a new UTF-16 file is read as text, and a real binary is skipped', async () => {
  const token = fake.githubToken()
  const wide = `${`TOKEN = ${token}\n`.split('').join('\0')}\0`
  const { runner } = fakeRunner({ others: { stdout: 'wide.txt\0blob.bin\0' } }, { 'wide.txt': wide, 'blob.bin': 'ab\0cdefghijklmnopqrstuvwxyz' })
  const out = await checkGit('git add .', ctx, runner)

  expect(out.hits.map(h => h.rule)).toEqual(['github-token'])
  expect(out.hits[0]?.location).toContain('wide.txt')
})

test('git steps past the cap make the scan incomplete', async () => {
  const { runner } = fakeRunner({})
  const out = await checkGit(Array.from({ length: 21 }, () => 'git commit -m x').join(' && '), ctx, runner)

  expect(out.isIncomplete).toBe(true)
  expect(out.notes[0]).toContain('21 git add/commit steps')
  expect(await checkGit('git commit -m x', ctx, runner)).toEqual({ hits: [], notes: [] })
})
