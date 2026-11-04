import type { Register } from 'claude-code'

import { checkEdit, checkWrite } from './guard'
import { readConfig } from './config'
import { guardAttachedFile, guardCommand, guardFile, guardPrompt, runCommand } from './engine'

// What a guard that fails (a bug, a timeout) says. It refuses rather than waves
// the call through: a guard that quietly stops guarding is worse than one that
// is loudly in the way.
const FAILED = (subject: string): string =>
  `secret-guard could not check ${subject} (an internal error), so it was blocked as a precaution. Nothing was shown or stored. If this keeps happening, turn the mod off with: claude plugin disable secret-guard`

export const register: Register = (on, options) => {
  const config = readConfig(options)

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'secret-guard',
      description: 'Secret guard: status, rules, recent blocks, allowlist',
    })

    return next(e)
  })

  on('command.run', { command: 'secret-guard' }, async ($, e) => ({ text: await runCommand($, config, e.args) }))

  // (a) File writes and edits. Each guard judges before it calls `next`.
  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    const denied = await guardFile($, config, 'this Write', ctx => checkWrite(String(e.file_path), String(e.content), ctx))

    return denied === undefined ? next(e) : { deny: denied }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: FAILED('this Write') }))

  on('tool.call', { tool: 'Edit' }, async ($, e, next) => {
    const denied = await guardFile($, config, 'this Edit', ctx => checkEdit(String(e.file_path), String(e.new_string), ctx))

    return denied === undefined ? next(e) : { deny: denied }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: FAILED('this Edit') }))

  on('tool.call', { tool: 'NotebookEdit' }, async ($, e, next) => {
    const denied =
      e.edit_mode === 'delete'
        ? undefined
        : await guardFile($, config, 'this notebook edit', ctx => checkEdit(String(e.notebook_path), String(e.new_source), ctx))

    return denied === undefined ? next(e) : { deny: denied }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: FAILED('this notebook edit') }))

  // (b) Shell commands, and the git add / git commit inside them.
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const denied = await guardCommand($, config, String(e.command))

    return denied === undefined ? next(e) : { deny: denied }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: FAILED('this shell command') }))

  on('tool.call', { tool: 'PowerShell' }, async ($, e, next) => {
    const denied = await guardCommand($, config, String(e.command))

    return denied === undefined ? next(e) : { deny: denied }
  }).catch(($, e, next) => (next.called ? next(e) : { deny: FAILED('this shell command') }))

  // (c) Prompts the person types.
  on('prompt.submit', async ($, e, next) => {
    const denied = await guardPrompt($, config, e.text, e.origin, e.isMeta)

    return denied === undefined ? next(e) : { drop: denied }
  }).catch(($, e, next) =>
    next.called ? next(e) : { drop: 'secret-guard could not check your prompt (an internal error), so it was not sent. Nothing was stored.' },
  )

  // (c) Files the person names with `@`. The engine reads the file, then hands the
  // model its text as an attachment; this is where that text is judged, and a file
  // with a secret in it reaches the model as a notice instead.
  on('prompt.attachment', { type: 'file' }, async ($, e, next) => {
    const withheld = await guardAttachedFile($, config, e.text)

    return withheld === undefined ? next(e) : { text: withheld }
  }).catch(($, e, next) => (next.called ? next(e) : { text: FAILED('this attached file') }))

  on('prompt.attachment', { type: 'edited_text_file' }, async ($, e, next) => {
    const withheld = await guardAttachedFile($, config, e.text)

    return withheld === undefined ? next(e) : { text: withheld }
  }).catch(($, e, next) => (next.called ? next(e) : { text: FAILED('this attached file') }))
}
