import { expect, mock, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

import { fake } from './fixtures'

// `/secret-guard <args>` and a prompt the person sends. The kit stamps what the
// engine stamps (a command's origin and presentation, a prompt's origin), but its
// types still ask for those fields, hence the casts.
const slash = ($: Engine, args: string) => $.command.run({ command: 'secret-guard', args } as never)
const typed = ($: Engine, text: string) => $.prompt.submit({ text } as never)

// What the engine beneath the mod does in every test: a tool call that gets
// through is answered `ran`; a git command is answered from `git`; the store
// and the clock are in memory.
type Git = { staged?: string; worktree?: string; others?: string; exitCode?: number; isUnavailable?: boolean; isStoreBroken?: boolean }

const engine = (on: On, git: Git = {}, store: Record<string, unknown> = {}) => {
  const argv: string[][] = []
  const logs: string[] = []
  const registered: string[] = []

  if (git.isStoreBroken) {
    on('store.get', () => ({ deny: 'the store is broken' }))
  } else {
    mock.store(on, store)
  }

  mock.clock(on, { now: 1_000_000 })
  on('tool.call', () => ({ result: { ran: true } }))
  on('command.register', (_, e) => {
    registered.push(e.name)

    return { value: { command: e.name } }
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.status', () => ({ value: undefined }))
  on('ui.log', (_, e) => {
    logs.push(e.text)

    return { value: undefined }
  })
  on('process.run', (_, e) => {
    if (git.isUnavailable) {
      return { deny: 'no host commands here' }
    }

    argv.push([...e.argv])

    const args = e.argv
    const stdout = args.includes('--version')
      ? 'git version 2.50.0'
      : args.includes('--cached')
        ? (git.staged ?? '')
        : args.includes('ls-files')
          ? (git.others ?? '')
          : args.includes('diff')
            ? (git.worktree ?? '')
            : ''

    return { value: { exitCode: git.exitCode ?? 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })

  return { argv, logs, registered }
}

const diffAdding = (file: string, line: number, text: string): string =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -${line - 1},0 +${line},1 @@`, `+${text}`].join('\n')

// The reason a call was refused, or undefined when it ran.
const refusal = (result: { deny?: string; isError?: true; text?: string; result?: unknown }): string | undefined =>
  result.deny ?? (result.isError === true ? result.text : undefined)

const ran = (result: { deny?: string; isError?: true; result?: unknown }): boolean =>
  refusal(result) === undefined && JSON.stringify(result.result) === JSON.stringify({ ran: true })

const idOf = (message: string): string => /\(id ([0-9a-f]{8})\)/.exec(message)?.[1] ?? ''

test('a Write that holds a secret is refused, naming the rule and place but not the value', async ($, on) => {
  engine(on)

  const token = fake.githubToken()
  const result = await $.tool.call({ tool: 'Write', file_path: '/p/src/config.ts', content: `export const t = "${token}"\n` })
  const why = refusal(result)

  expect(why).toContain('secret-guard blocked this Write')
  expect(why).toContain('GitHub token [github-token] at /p/src/config.ts:1:19')
  expect(why).toContain('Nothing was written.')
  expect(why).not.toContain(token)
  expect(why).not.toContain(token.slice(4, 16))
})

test('a clean Write goes through to the engine', async ($, on) => {
  engine(on)

  expect(ran(await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content: 'export const x = 1\n' }))).toBe(true)
})

test('an Edit is judged on its new text only', async ($, on) => {
  engine(on)

  const token = fake.githubToken()
  const bad = await $.tool.call({ tool: 'Edit', file_path: '/p/a.ts', old_string: 'x', new_string: `y = "${token}"` })
  const fine = await $.tool.call({ tool: 'Edit', file_path: '/p/a.ts', old_string: `y = "${token}"`, new_string: 'y = process.env.TOKEN' })

  expect(refusal(bad)).toContain('secret-guard blocked this Edit')
  expect(refusal(bad)).toContain('/p/a.ts (new text, line 1)')
  expect(ran(fine)).toBe(true)
})

test('a notebook edit is guarded too, and deleting a cell is not', async ($, on) => {
  engine(on)

  const token = fake.githubToken()
  const bad = await $.tool.call({ tool: 'NotebookEdit', notebook_path: '/p/n.ipynb', new_source: `t = "${token}"`, cell_type: 'code' })
  const del = await $.tool.call({ tool: 'NotebookEdit', notebook_path: '/p/n.ipynb', new_source: `t = "${token}"`, edit_mode: 'delete' })

  expect(refusal(bad)).toContain('secret-guard blocked this notebook edit')
  expect(ran(del)).toBe(true)
})

test('a Bash command with a secret in it does not run; a clean one does', async ($, on) => {
  engine(on)

  const token = fake.awsKeyId()
  const bad = await $.tool.call({ tool: 'Bash', command: `aws s3 ls --access-key ${token}` })
  const fine = await $.tool.call({ tool: 'Bash', command: 'aws s3 ls --profile work' })

  expect(refusal(bad)).toContain('secret-guard blocked this shell command')
  expect(refusal(bad)).toContain('AWS access key ID [aws-access-key-id] at command line 1, column 24')
  expect(refusal(bad)).toContain('The command did not run.')
  expect(refusal(bad)).not.toContain(token)
  expect(ran(fine)).toBe(true)
})

test('PowerShell commands are guarded the same way', async ($, on) => {
  engine(on)

  const bad = await $.tool.call({ tool: 'PowerShell', command: `$env:X = "${fake.githubToken()}"` })

  expect(refusal(bad)).toContain('secret-guard blocked this shell command')
})

test('git commit is refused when what is staged holds a secret, and the secret is not echoed', async ($, on) => {
  const token = fake.githubToken()

  engine(on, { staged: diffAdding('src/app.ts', 14, `const t = "${token}"`) })

  const result = await $.tool.call({ tool: 'Bash', command: 'git commit -m "add config"' })
  const why = refusal(result)

  expect(why).toContain('secret-guard blocked this git command')
  expect(why).toContain('src/app.ts:14')
  expect(why).toContain('Nothing was staged or committed.')
  expect(why).not.toContain(token)
})

test('git add . is refused when a changed file holds a secret', async ($, on) => {
  const token = fake.githubToken()

  engine(on, { worktree: diffAdding('src/app.ts', 3, `token: "${token}"`) })

  expect(refusal(await $.tool.call({ tool: 'Bash', command: 'git add .' }))).toContain('src/app.ts:3')
})

test('git commit with a clean stage goes through', async ($, on) => {
  const { argv } = engine(on, { staged: diffAdding('src/app.ts', 1, 'const x = 1') })

  expect(ran(await $.tool.call({ tool: 'Bash', command: 'git commit -m "tidy"' }))).toBe(true)
  expect(argv.some(args => args.includes('--cached'))).toBe(true)
  expect(argv.every(args => args[0] === 'git')).toBe(true)
})

test('git is run with the repository config that could run programs switched off', async ($, on) => {
  const { argv } = engine(on)

  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })

  const diff = argv.find(args => args.includes('diff')) ?? []

  expect(diff).toContain('core.fsmonitor=false')
  expect(diff).toContain('--no-textconv')
  expect(diff).toContain('--no-ext-diff')
})

test('a command that is not git runs no process at all', async ($, on) => {
  const { argv } = engine(on)

  await $.tool.call({ tool: 'Bash', command: 'ls -la && echo done' })
  expect(argv).toEqual([])
})

test('the allowlist lets a value through, by the id a block showed', async ($, on) => {
  engine(on)

  const content = `t = "${fake.githubToken()}"`
  const first = refusal(await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content }))

  expect(first).toBeDefined()

  const id = idOf(first ?? '')

  expect(id).toMatch(/^[0-9a-f]{8}$/)

  const added = await slash($, `allow fp:${id}`)

  expect(added.text).toBe(`Allowed fp:${id}.`)
  expect(ran(await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content }))).toBe(true)

  const removed = await slash($, 'unallow 1')

  expect(removed.text).toBe(`Removed fp:${id}.`)
  expect(refusal(await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content }))).toBeDefined()
})

test('a path allowlist entry exempts a whole file', async ($, on) => {
  engine(on)

  const content = `t = "${fake.githubToken()}"`

  await slash($, 'allow path:fixtures/**')

  expect(ran(await $.tool.call({ tool: 'Write', file_path: '/p/fixtures/a.json', content }))).toBe(true)
  expect(refusal(await $.tool.call({ tool: 'Write', file_path: '/p/src/a.json', content }))).toBeDefined()
})

test('the allowlist will not store a value that is itself a secret, and does not echo it', async ($, on) => {
  engine(on)

  const token = fake.githubToken()
  const out = await slash($, `allow ${token}`)

  expect(out.text).toContain('looks like a real secret')
  expect(out.text).toMatch(/allow fp:[0-9a-f]{8}/)
  expect(out.text).not.toContain(token)
  expect((await slash($, 'allowlist')).text).toContain('empty')
})

test('/secret-guard shows status, the rules and recent blocks, masked', async ($, on) => {
  engine(on)

  const token = fake.githubToken()

  await $.tool.call({ tool: 'Write', file_path: '/p/src/a.ts', content: `t = "${token}"` })
  await $.tool.call({ tool: 'Bash', command: `echo ${fake.awsKeyId()}` })

  const status = (await slash($, '')).text ?? ''

  expect(status).toContain('secret-guard: mode block')
  expect(status).toContain('This session: 2 blocked, 0 warned. All time: 2 blocked, 0 warned.')
  expect(status).toContain('git scan ready (git version 2.50.0)')

  expect((await slash($, 'rules')).text).toContain('github-token')

  const recent = (await slash($, 'recent')).text ?? ''

  expect(recent).toContain('github-token at /p/src/a.ts:1:6')
  expect(recent).toContain('aws-access-key-id at command line 1, column 6')
  expect(recent).not.toContain(token)

  await slash($, 'clear')
  expect((await slash($, 'recent')).text).toContain('No blocks')
})

test('the mod registers its command when the session starts', async ($, on) => {
  const { registered } = engine(on)

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(registered).toEqual(['secret-guard'])
})

test('in warn mode a secret is let through, loudly', { options: { mode: 'warn' } }, async ($, on) => {
  const { logs } = engine(on)
  const result = await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content: `t = "${fake.githubToken()}"` })

  expect(ran(result)).toBe(true)
  expect(logs.join('\n')).toContain('secret-guard WARNING: 1 possible secret in this Write')
  expect(logs.join('\n')).toContain('It was NOT blocked.')
  expect((await slash($, '')).text).toContain('on, warns only')
  expect((await slash($, 'recent')).text).toContain('warned')
})

test('each guard can be switched off on its own', { options: { guardFiles: false, guardCommands: false, guardCommits: false } }, async ($, on) => {
  engine(on, { staged: diffAdding('a.ts', 1, `t = "${fake.githubToken()}"`) })

  const secret = fake.githubToken()

  expect(ran(await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content: secret }))).toBe(true)
  expect(ran(await $.tool.call({ tool: 'Bash', command: `echo ${secret}` }))).toBe(true)
  expect(ran(await $.tool.call({ tool: 'Bash', command: 'git commit -m x' }))).toBe(true)
})

test('when git cannot be run the commit goes ahead with a loud warning, not a block', async ($, on) => {
  const { logs } = engine(on, { isUnavailable: true })
  const result = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })

  expect(ran(result)).toBe(true)
  expect(logs.join('\n')).toContain('was not fully scanned')
  expect(logs.join('\n')).toContain('could not be read')
})



// ---------------------------------------------------------------------------
// Prompts. The test kit raises a prompt with no origin stamped, as a prompt the
// guard cannot attribute, and a guard that is unsure looks. Which origins are
// the person's and which a machine's is covered where `isPersonPrompt` is.

const prompts = (on: On) => on('prompt.submit', (_, e) => ({ text: e.text }))

test('a prompt that holds a secret is dropped, and the secret is not echoed', async ($, on) => {
  engine(on)
  prompts(on)

  const token = fake.githubToken()
  const result = await typed($, `please deploy with this token\n${token}`)
  const why = result.drop ?? ''

  expect(result.text).toBeUndefined()
  expect(why).toContain('secret-guard stopped this prompt before it was sent: 1 possible secret found')
  expect(why).toContain('GitHub token [github-token] at prompt line 2, column 1')
  expect(why).toContain('/secret-guard allow fp:')
  expect(why).not.toContain(token)
  expect(why).not.toContain(token.slice(4, 16))

  const recent = (await slash($, 'recent')).text ?? ''

  expect(recent).toContain('github-token at prompt line 2, column 1')
  expect(recent).not.toContain(token)
})

test('a clean prompt goes through to the engine unchanged', async ($, on) => {
  engine(on)
  prompts(on)

  const result = await typed($, 'refactor the login form and add tests')

  expect(result.drop).toBeUndefined()
  expect(result.text).toBe('refactor the login form and add tests')
})

test('an allowlisted value is let through in a prompt', async ($, on) => {
  engine(on)
  prompts(on)

  const text = `use ${fake.githubToken()} here`
  const first = (await typed($, text)).drop ?? ''

  await slash($, `allow fp:${idOf(first)}`)
  expect((await typed($, text)).text).toBe(text)
})

test('in warn mode a prompt with a secret goes through, loudly', { options: { mode: 'warn' } }, async ($, on) => {
  const { logs } = engine(on)

  prompts(on)

  const text = `key ${fake.awsKeyId()}`
  const result = await typed($, text)

  expect(result.text).toBe(text)
  expect(logs.join('\n')).toContain('secret-guard WARNING: 1 possible secret in your prompt')
})

test('prompts are not scanned when that guard is off', { options: { guardPrompts: false } }, async ($, on) => {
  const { logs } = engine(on)

  prompts(on)

  const text = `key ${fake.awsKeyId()}`

  expect((await typed($, text)).text).toBe(text)
  expect(logs).toEqual([])
})

// ---------------------------------------------------------------------------
// A guard that fails refuses; it does not wave the action through.

test('when the guard itself fails, a file write, a command and a prompt are refused, not let through', async ($, on) => {
  engine(on, { isStoreBroken: true })
  prompts(on)

  const write = await $.tool.call({ tool: 'Write', file_path: '/p/a.ts', content: 'export const x = 1\n' })
  const bash = await $.tool.call({ tool: 'Bash', command: 'ls' })
  const prompt = await typed($, 'a perfectly clean prompt')

  expect(refusal(write)).toContain('secret-guard could not check this Write (an internal error), so it was blocked as a precaution')
  expect(refusal(bash)).toContain('secret-guard could not check this shell command')
  expect(prompt.text).toBeUndefined()
  expect(prompt.drop).toContain('secret-guard could not check your prompt (an internal error), so it was not sent')
  expect(ran(write)).toBe(false)
})
