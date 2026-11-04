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
    { rule: 'github-token', label: 'GitHub token', location: '/p/src/config.ts:2:16', fingerprint: fingerprint(token, SALT) },
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

      const key = args.includes('--cached') ? 'cached' : args[0] === 'ls-files' ? (args.includes('--ignored') ? 'ignored' : 'others') : 'worktree'
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
    { rule: 'github-token', label: 'GitHub token', location: 'src/app.ts:14', fingerprint: fingerprint(token, SALT) },
  ])
  expect(out.notes).toEqual([])
  expect(calls).toHaveLength(1)
  expect(calls[0]?.args).toContain('--cached')
  expect(calls[0]?.args).toContain('--no-textconv')
  expect(calls[0]?.args).toContain('--no-ext-diff')
})

test('git commit -a also scans the working-tree changes, and a path limits them', async () => {
  const token = fake.githubToken()
  const { runner, calls } = fakeRunner({ worktree: { stdout: diffAdding('b.ts', 3, `x = "${token}"`) } })
  const out = await checkGit('git commit -am "wip"', ctx, runner)

  expect(out.hits.map(h => h.location)).toEqual(['b.ts:3'])
  expect(calls.map(c => c.args.includes('--cached'))).toEqual([true, false])

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

  const many = Array.from({ length: 130 }, (_, i) => `f${i}.txt`)
  const files = Object.fromEntries(many.map(f => [f, 'plain text\n']))
  const capped = fakeRunner({ others: { stdout: `${many.join('\0')}\0` } }, files)
  const out = await checkGit('git add .', ctx, capped.runner)

  expect(capped.reads).toHaveLength(100)
  expect(out.notes[0]).toContain('130 new files')
})
