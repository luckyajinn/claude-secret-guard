# claude-secret-guard

A Claude Code mod that blocks API keys, tokens and passwords from reaching files, commands, commits or prompts. When it stops something it tells you which rule fired and where, and never shows the secret itself.

It is a safety net with holes, not a vault. It finds secrets by their shape (known key formats, plus names like `password=` with a high-entropy value), so it will miss some and flag a few harmless things. [Limits](#limits-read-this) says exactly what it cannot see.

## Install

```
claude plugin marketplace add luckyajinn/claude-secret-guard
claude plugin install secret-guard@claude-secret-guard --scope user
```

In a terminal session the same thing is `/plugin install secret-guard --marketplace luckyajinn/claude-secret-guard`. In the desktop app, where `/plugin` does not run: click + next to the prompt box, then Plugins, Add marketplace with `luckyajinn/claude-secret-guard`, then Add plugin.

It uses Claude Code's early-access mod API, which can change between releases.

## What it guards

Every guard point has a real veto in the mod API, so each one blocks rather than only warns.

| Where | Hook | What is checked | When it finds a secret |
| --- | --- | --- | --- |
| File writes and edits | `tool.call` on `Write`, `Edit`, `NotebookEdit` | The content about to be written. For an edit, only the new text, so a secret already in a file never blocks an unrelated change. | **Blocked.** The tool call is refused and nothing is written. |
| Shell commands | `tool.call` on `Bash`, `PowerShell` | The text of the command. | **Blocked.** The command does not run. |
| `git add` and `git commit` | the same `tool.call` | The changes the command would stage or commit, read with `git diff` and `git ls-files` (see below). | **Blocked.** Nothing is staged or committed. |
| Your prompts | `prompt.submit` | What you type, before it is sent to the model. | **Blocked.** The prompt is dropped and you are told why. |
| Files you name with `@` | `prompt.attachment` | The text of the file, as the engine is about to hand it to the model. | **Withheld.** The model gets a notice (rule, place, id) instead of the file. |

**Where it only warns.** Two cases degrade from a block to a loud warning (a toast plus a line that stays in the transcript), and say so:

- **Warn mode.** Set the `mode` option to `warn` and every guard warns instead of blocking. Useful for a trial week.
- **git cannot be scanned.** The git check runs `git` on the host through the mod API's `$.process.run`. If a session cannot run host commands, or git fails, the command still runs and a warning says the changes were not scanned. `/secret-guard status` shows whether git scanning is ready.

**How a git check works.** For `git commit` it scans the staged diff (plus the working-tree diff for `-a`, `-p` or named paths). For `git add` it scans the tracked changes under the paths you named and the new files it would add (and ignored files, for `-f`). A block names each file by its full path, so a commit over a folder says where the problem is; over many files it lists one line per file (how many findings, which rules, which lines), and the pop-up gives the count and the folder they share. It reads `git -C <dir>`, `--git-dir`, `--work-tree` and `GIT_DIR`, follows `cd` (and looks at the folder it left too), and understands `&&`, `;`, pipes, quotes, line continuations, escaped words (`g\it`), `if`/`then`/`!`/`{`, `sudo`/`env`, `bash -c`, `powershell -Command`, `cmd /c`, `eval`, and abbreviated options (`--upd`). A command that is itself a variable (`$G commit`) is read the widest way: every staged and tracked change. It does not follow aliases or scripts. A file git reports as binary but that is text (a `.gitattributes` `-diff`, or UTF-16 as PowerShell's `>` writes) is read as text. Git is run with `core.fsmonitor` off and `--no-textconv --no-ext-diff`, so a repository's own config cannot make the scan run a program.

**If the guard itself fails** (a bug, a timeout) it refuses the action with a message rather than waving it through. The way out is `claude plugin disable secret-guard`.

## What a block looks like

The model (for a tool call) or you (for a prompt) sees this. Nothing from the value is in it, not a prefix, not a length:

```
secret-guard blocked this Write: 1 possible secret found. The values are hidden on purpose.
  - GitHub token [github-token] at /project/src/config.ts:12:19 (id 3fa91c2b)
Nothing was written. Do not retry with the same value. Keep secrets out of files, commands and commits: read them from an environment variable or a secrets manager and refer to them by name.
If it is a harmless placeholder, the user can run /secret-guard allow fp:3fa91c2b (one value) or /secret-guard allow path:<glob> (a whole file).
```

The `id` is the first 8 hex digits of a SHA-256 of the value with a per-install random salt. It tells findings apart and is how you allowlist one. It is not the secret, and only 32 bits of it are kept, so many values share each id.

## What it detects

| Rule | Looks for |
| --- | --- |
| `private-key` | A PEM private key block (`BEGIN … PRIVATE KEY`) with key material after the header, also when written as one JSON string with `\n`. A header alone (in prose, or in code that parses PEM) is ignored. Public keys and certificates are not secrets. |
| `aws-access-key-id` | AWS key IDs: `AKIA`, `ASIA` and the other four-letter prefixes, plus 16 characters. |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens. |
| `github-fine-grained-token` | `github_pat_` tokens. |
| `anthropic-api-key` | `sk-ant-` keys. |
| `openai-api-key` | `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-` keys, with an entropy check so `risk-assessment-of-…` is left alone. |
| `stripe-key` | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` and `whsec_` secrets. Test-mode keys are still keys. |
| `slack-token`, `slack-webhook` | `xoxb-`, `xoxp-`, `xapp-` and similar tokens; `hooks.slack.com/services/…` URLs. |
| `google-api-key`, `google-oauth-secret` | `AIza…` keys; `GOCSPX-` client secrets. |
| `sendgrid-key`, `npm-token`, `huggingface-token` | `SG.…`, `npm_…`, `hf_…`. |
| Other vendor tokens | GitLab (`glpat-`), PyPI (`pypi-AgEI…`), Shopify (`shpat_`), DigitalOcean (`dop_v1_`), Databricks (`dapi…`), Sentry (`sntrys_`), Supabase (`sbp_`), HashiCorp Vault (`hvs.`), Terraform Cloud (`….atlasv1.…`), Grafana (`glsa_`), Postman (`PMAK-`), Atlassian (`ATATT3`), Google OAuth (`ya29.`), age (`AGE-SECRET-KEY-1`), Twilio (`SK…`), Telegram and Discord bot tokens, Discord webhooks, Mailgun (`key-`), Doppler (`dp.pt.`), Azure AD (`…8Q~…`), Notion (`secret_`, `ntn_`), Linear (`lin_api_`), Groq (`gsk_`), xAI (`xai-`), Perplexity (`pplx-`), Replicate (`r8_`), Docker (`dckr_pat_`), Netlify (`nfp_`), Square (`sq0atp-`); more Slack prefixes (`xoxe`, `xoxc`, `xoxd`). Each has its own rule id, listed by `/secret-guard rules`. |
| `jwt` | Three-part tokens whose first two parts are base64url JSON (`eyJ…`). |
| `bearer-token` | `Bearer <token>` with a digit in it and high entropy. |
| `url-credentials` | A password inside a URL (`scheme://user:password@host`), except stock ones like `postgres:postgres@localhost`. |
| `generic-secret` | A hard-coded value after a name that says credential: `password`, `passwd`, `secret`, `token`, `api key`, `access key`, `client secret`, `PGPASSWORD`, `--password`, and so on. The last word of the name decides, so `GITHUB_TOKEN` matches and `max_tokens`, `tokenizer` and `password_file` do not. The value must be 8+ characters and high enough in entropy (about 2.5 bits per character for a password, 3 for the rest). |

`/secret-guard rules` lists them in the order they are tried. Where two overlap, the most specific wins, so a token assigned to `GITHUB_TOKEN=` is one finding, not two.

**Placeholders are ignored by every rule** (except the private-key one, whose body is long enough to contain a word by chance): a value with `example`, `changeme`, `dummy`, `fake`, `sample`, `redacted`, `your-key`, `xxxx`, `<token>`, `${…}`, a run of one repeated character, or `…`/`***`. The AWS documentation key is ignored because it says `EXAMPLE`.

**What the generic rule also leaves alone, to limit false positives:** references (`$VAR`, `${VAR}`, `%VAR%`, `process.env.X`, `os.environ["X"]`, `fn()`, `op://…`), paths and URLs, values that are a bare identifier (`password=correcthorse` could be a variable name), and values that read like a fixture (`test`, `demo`, `default`, `password`, `secret`, `token`, `admin`, `12345`…). That last list applies to the generic rule only: a real `sk_test_…` key is still caught by its own rule.

## Allowlist

When a block is wrong, tell the guard once:

```
/secret-guard allow fp:3fa91c2b        one specific value, by the id the block showed
/secret-guard allow path:docs/**       every finding in matching files (also *.test.ts, fixtures/**)
/secret-guard allow text:my-test-key   any value containing this literal (6+ characters)
/secret-guard allowlist                show the list, numbered
/secret-guard unallow 2                remove an entry
```

Paths match like a `.gitignore` line: a glob with no folder (`*.test.ts`) matches a file name anywhere, one with a folder (`docs/**`) matches from any folder boundary; `\` and `/` both work.

The allowlist is kept in the mod's own store in your Claude configuration, **not in the project**, on purpose: a repository, or an agent working in one, cannot widen what the guard lets through by editing a file. `/secret-guard allow` will not store a value that is itself a secret as `text:`; it gives you its `fp:` id instead, and it never echoes the value.

## `/secret-guard`

| Command | Shows |
| --- | --- |
| `/secret-guard` | Status: mode, which guards are on, whether git can be scanned, counts for this session and all time, allowlist size. |
| `/secret-guard rules` | The detection rules. |
| `/secret-guard recent [n]` | The last blocks and warnings: when, guard, rule, place and id. Never the value. Kept: the last 50. |
| `/secret-guard allow …`, `allowlist`, `unallow …` | The allowlist, above. |
| `/secret-guard clear` | Empties the recent log. |
| `/secret-guard help` | The list above. |

## Options

Each is a row in the plugin's config.

| Option | Default | |
| --- | --- | --- |
| `mode` | `block` | `block` refuses; `warn` only warns loudly and lets the action through. |
| `guardFiles` | on | Write, Edit, NotebookEdit. |
| `guardCommands` | on | Bash and PowerShell command text. |
| `guardCommits` | on | The git add / git commit scan. |
| `guardPrompts` | on | Your prompts, and files you name with `@`. |

## Privacy

The mod makes no network calls and writes no secret anywhere: not in messages, the log, the allowlist, `$.state`, debug output or the tests. It keeps, in its own store, a random salt, the allowlist you typed, the last 50 blocks (rule, place, id) and two counters. A scan runs in memory and what it finds is a rule, offsets and an id.

## Limits (read this)

**Detection is heuristic.** Expect both kinds of mistake.

- **It will miss secrets with no recognizable shape.** A random password in the middle of a sentence; a password shorter than 8 characters, or one that is a plain word; a value in an unlisted vendor format; anything encoded, split across strings or lines, URL-escaped or base64-wrapped; secrets inside real binary files. Text is scanned to its end, in windows, up to 40,000,000 characters; past that only the start is scanned and, in block mode, the action is refused rather than let through unchecked. The same holds for a command with more than 20 git steps and a `git add` over more than 500 new files.
- **It will sometimes flag something harmless.** That is what the [allowlist](#allowlist) is for, and what `warn` mode is for while you tune.

**It only guards the four points above.** It does not look at:

- **What the model reads.** Apart from a file you name with `@`, which is scanned, `Read`, `Grep`, `cat .env`, MCP results, web pages and command output are not scanned or redacted. If a secret is in your project, this mod does not stop the model from seeing it.
- **Pasted or dropped images and PDFs.** A file you name with `@` is scanned, and a withheld one is replaced by a notice before the model sees it. An image or a PDF attached to a prompt is not read for secrets. The engine's own transcript record of an `@` file is not changed by the guard.
- **Other tools' arguments.** `Agent` prompts, MCP tool calls, `WebFetch` URLs and the like are not scanned.
- **Files written by a command.** `echo "$KEY" > file`, a script that generates a config, a `curl -o`: the text of the command is scanned, what it writes is not. That includes a file a command creates and then `git add`s in the same line (`echo … > f && git add f`): the git scan runs before the command does, so the file is not there to see yet. Run the `git add` or `git commit` as its own command and it is scanned.
- **`git push`**, commits made outside Claude Code, commits made by a script, a commit in a folder other than the session's after `cd` (use `git -C`, which it follows), and secrets already in history.
- **Prompts that are not yours.** Task notifications, scheduled runs, messages from a peer session or a channel, and prompts another plugin raised on its own are left alone, because they are not yours to edit. Everything it cannot attribute is scanned.
- **Other plugins.** Hooks run in a chain. A plugin that sits above this one can change or skip its checks.

**Blocking is not an undo.** It stops the action in front of it. It cannot take back what is already in the transcript or on disk.

## Status

v0.1.2. 156 tests run through Claude Code's mod test kit (`claude plugin test .`), `claude plugin validate .` passes, and the code type-checks under `strict` with `noUncheckedIndexedAccess`. File writes, `git add`, prompts and `@` files have been tried in live Claude Code sessions, but it is early, so treat the first week as a trial and consider starting in `warn` mode.

## Develop

```
claude plugin validate .
claude plugin test .
```

The test fixtures are fake secrets built at run time from a seeded generator (`hooks/fixtures.ts`), so no complete key-shaped string is written anywhere in this repository.

| File | |
| --- | --- |
| `hooks/register.tsx` | Registers the hooks and the command. |
| `hooks/engine.ts` | The part that talks to the engine: runs a check, decides block or warn, keeps count. |
| `hooks/detect.ts` | Detection. Pure functions: text in, findings out. No value is ever kept in a finding. |
| `hooks/guard.ts` | What each guard point scans, location naming, the messages, the git scan. |
| `hooks/git.ts` | Reads `git add` / `git commit` out of a command, and reads a `git diff`. |
| `hooks/allow.ts`, `hooks/store.ts`, `hooks/command.ts`, `hooks/config.ts`, `hooks/hash.ts` | Allowlist, persistence, the `/secret-guard` command, options, the fingerprint hash. |

## License

MIT, see [LICENSE](LICENSE).
