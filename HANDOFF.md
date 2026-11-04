# claude-secret-guard: handoff

Written 2026-11-04 from the machine that built it. Facts below were checked against git and the CLI at that time; anything marked **not verified** was not.

## 1. What this is

A Claude Code "mod" (early-access plugin API, hooks module in TypeScript) that stops API keys, tokens and passwords from reaching files, commands, commits or prompts. A block names the rule and the place (`path:line:col`) and never shows the value, not even a prefix. MIT, author CJ (GitHub `luckyajinn`). Plugin name `secret-guard`, version `0.1.0`.

**Blocks (veto hooks, so each really stops the action):**
- File writes and edits: `Write`, `Edit` (new text only), `NotebookEdit` (not cell deletes) via `tool.call` `{ deny }`.
- Shell commands: `Bash`, `PowerShell` command text via `tool.call` `{ deny }`.
- `git add` / `git commit`: the same hook runs `git diff` / `git ls-files` through `$.process.run` and scans what would be staged or committed. Follows `git -C <dir>`.
- Your prompts: `prompt.submit` `{ drop }` for prompts that may hold your own words.

**Only warns:** `mode=warn`; git cannot be run (commit proceeds with a loud warning); nothing else. If the guard itself throws it fails closed (refuses). Way out: `claude plugin disable secret-guard`.

**Does not scan:** what the model reads (`Read`, `Grep`, `cat .env`, MCP results, command output); `Agent`/MCP/`WebFetch` arguments; files a command writes (`echo "$KEY" > f`); `git push`; commits made outside Claude Code; history; `cd` then `git` (use `git -C`); prompts raised by machines (task notifications, schedules, peers, channels, other plugins).

**Command `/secret-guard`:** `status` (default), `rules`, `recent [n]`, `allow <fp:|path:|text:>`, `allowlist`, `unallow <n|text>`, `clear`, `help`.
**Options (userConfig):** `mode` (`block`|`warn`, default `block`), `guardFiles`, `guardCommands`, `guardCommits`, `guardPrompts` (booleans, default on).

## 2. Repo state (checked with git)

| | |
| --- | --- |
| GitHub | https://github.com/luckyajinn/claude-secret-guard |
| Branch | `main`, one commit: `ceb3c68` "Initial release of secret-guard v0.1.0" |
| HEAD | `ceb3c683f07694cbc6d2847c3847800b66674a73` |
| Pushed | Yes. `git ls-remote origin` returned the same hash for `HEAD` and `refs/heads/main`; `git status -sb` showed `main...origin/main`, no ahead/behind |
| Uncommitted | Only this `HANDOFF.md` (untracked, deliberately not committed). Nothing else; no stash, no tags |
| Other repos | Sibling mods `claude-usage-guard`, `claude-audit-trail`, `claude-agent-monitor`, `usage-hud` are separate; do not edit them from here |

## 3. Verified and not verified

**Verified** (CLI 2.1.316, plugin API docs from the 2.1.317 bundle):
- `claude plugin validate .` passes. One warning: no icon (`.claude-plugin/icon.png` or `icon` in plugin.json).
- `claude plugin test .`: 125 tests pass across 8 files (about 1.4 s).
- Strict `tsc` (`strict` + `noUncheckedIndexedAccess`) was clean, using a scratch tsconfig outside the repo.
- `scan_secrets` (the plugin-authoring tool) found nothing in the 27 committed files; a regex pass over the staged diff hit only two ordinary hyphenated words in a negative fixture.
- No network calls anywhere in the code; no raw secret in messages, store, logs or tests (asserted by tests).

**NOT verified:**
- **It has not run in a live Claude Code session.** The hooks were exercised only through the engine's test kit.
- The real `origin` the engine stamps on prompts. The prompt policy is unit-tested, not tested end to end.
- The git scan against a real repository through the engine. Tests stub `$.process.run`.
- Hot-reload via `--plugin-dir`, `/reload-plugins`, toast/status/log rendering.
- `claude plugin marketplace add` / `install` from GitHub. It is pushed now but nobody has tried it. On the build machine `claude plugin list` showed `agent-monitor` and `usage-guard`, not `secret-guard`.
- macOS/Linux. Everything was developed and tested on Windows 11; the git command parser has not met bash there.
- The README's desktop-app install steps came from the skill docs, not from trying them.

## 4. Set up on a new machine

```
git clone https://github.com/luckyajinn/claude-secret-guard
cd claude-secret-guard
claude plugin validate .        # run: passes
claude plugin test .            # run: 125 pass
claude --plugin-dir .           # flag exists in `claude --help`; NOT run
claude plugin marketplace add luckyajinn/claude-secret-guard
claude plugin install secret-guard@claude-secret-guard --scope user
```
The terminal form `/plugin install secret-guard --marketplace luckyajinn/claude-secret-guard` also exists (`--marketplace` is in `claude plugin install --help`). `/plugin` does not run in the desktop app; use + next to the prompt box, Plugins, Add marketplace.

**Windows PATH:** `claude` did not resolve in PowerShell or Git Bash here. The binary used was `C:\Users\Administrator\.local\bin\claude.exe` (2.1.316). The desktop app also bundles one under `...\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\2.1.317\<hash>\claude.exe`. Use the full path if `claude` is not found.

**Updating an installed copy.** The docs say an installed plugin runs the copy made at install time and a change reaches a session "as a new version or commit" via `claude plugin update <plugin>` then `/reload-plugins` (`update --help` says restart to apply). `plugin.json` pins `"version": "0.1.0"` and the marketplace entry has no version, so **bump `version` in `.claude-plugin/plugin.json` for every change you want installed copies to get**. I did not test whether a commit without a bump is enough. `claude plugin tag` makes a `secret-guard--v<version>` tag and checks plugin.json and marketplace.json agree.

**Type-check:** `tsconfig.json` extends `.claude-plugin/types/tsconfig.json`, which the engine writes (gitignored) the first time it loads the folder, so `tsc -p .` should work after a `--plugin-dir` session (not verified). Without it, the API declarations are `claude-code.d.ts`, written to `%TEMP%\claude\bundled-skills\<ver>\<hash>\plugin-authoring\types\` when the plugin-authoring skill loads.

## 5. Design decisions and why

**Hook points used:** `session.start` (registers the command), `command.run{command=secret-guard}`, `tool.call` for Write/Edit/NotebookEdit/Bash/PowerShell, `prompt.submit`. Each gating hook has `.catch(($, e, next) => next.called ? next(e) : { deny | drop })` so an internal error refuses instead of letting a secret through. `types/index.d.ts` is only the `$.state` contract (two counters), not the mod API.

**Detection (`hooks/detect.ts`, pure: text in, findings out):**
- Ordered rules, most specific first; where matches overlap the earlier rule wins, so `GITHUB_TOKEN=<token>` is one finding.
- Specific formats: PEM private keys (needs key material after the header, so prose is ignored), AWS key ids, GitHub, Anthropic, OpenAI-style `sk-`, Stripe, Slack, Google, SendGrid, npm, Hugging Face, JWT, bearer tokens, URL credentials.
- Generic rule: finds a name first, then reads the value. The last word of the name decides (`GITHUB_TOKEN` yes; `max_tokens`, `tokenizer`, `password_file` no). Value must be 8+ chars with Shannon entropy about 2.5 bits/char when the name says password, 3.0 otherwise.
- Filters: placeholder words on every rule except private-key; fixture words (`test`, `demo`, `admin`...) on the generic rule only, so a real `sk_test_` key is still caught by its own rule; references (`$VAR`, `process.env.X`, `fn()`, paths, URLs) and bare identifiers are skipped.
- Findings hold rule, offsets, line/col, length and an 8-hex fingerprint, never the value. Fingerprint = first 8 hex digits of SHA-256(salt + value) with a per-install random salt, pure-JS so it is synchronous. Only 32 bits are kept, so ids can collide.
- Text over 4,000,000 chars is cut and the result says so.

**Allowlist (`hooks/allow.ts`, `store.ts`):** entries `fp:<8hex>`, `path:<glob>` (gitignore-like, `\` and `/` both), `text:<literal, 6+ chars>`; max 200. Kept in the plugin's user store, **not in the project**, so a repo or an agent cannot widen it by editing a file. `allow text:` refuses a value that scans as a secret and offers its `fp:` id instead.

**Prompt policy (`isPersonPrompt`):** scan unless the origin is a known machine origin or the prompt is meta. Unknown or missing origin is scanned (fail-safe). A plugin-origin prompt is scanned only if it asks to be treated as the user's. Chosen because the test kit supplies no origin.

**Git scan (`hooks/git.ts`, `guard.ts`):** quote-aware command splitter, flag parsing for add/commit (`-C -A -u -f -a -p --dry-run`, paths), `git diff -U0` parser that keeps real line numbers. Git runs with `-c core.fsmonitor=false --no-textconv --no-ext-diff` and `GIT_OPTIONAL_LOCKS=0` so a repo's config cannot run a program. Caps: 5 git ops and 100 new files per command.

**Trade-offs:** precision over recall on the generic rule (a harmless block trains people to turn the guard off), high recall on known formats. It will miss secrets with no recognisable shape and sometimes flag a harmless one; `warn` mode and the allowlist are the escape valves. Fail-closed on internal errors was chosen over fail-open; Christian may want to revisit.

## 6. Limits, open questions, next steps (priority order)

1. **Run it live.** In a throwaway folder: `claude --plugin-dir .`, start in `mode=warn`, then `block`. Try a Write, an Edit, a Bash command, a PowerShell command, `git add`/`git commit` in a real repo, and a prompt, each with a fake secret. Check the toast and transcript line, `/secret-guard recent`, and that the value never appears. Record what differs from the tests.
2. **Install from GitHub** and run the update flow (`claude plugin update`, `/reload-plugins`), including whether a version bump is required. Fix the README if it differs.
3. **Prompt origins.** See what origin real typed, bridge and machine prompts carry; tighten `MACHINE_ORIGINS` in `guard.ts` if needed.
4. **macOS/Linux.** Run the suite and a live git check there.
5. **Close gaps:** look in `claude-code.d.ts` for any hook on tool results (nothing in this repo uses one), the arguments of `Agent`/MCP/`WebFetch`, and typed assignments like `password: str = "..."`.
6. **Tune on real use:** collect false positives from a week of `warn`; consider more vendors (Twilio, Azure, service-account JSON, database URLs).
7. Add an icon (validator warning); add a CHANGELOG; bump to `0.1.1` with the first fixes.

**Open questions:** fail-closed vs fail-open; whether prompts should be blocked at all by default; whether the allowlist should also be allowed per project (currently not, on purpose); whether `warn` should be the default for a first release.

## 7. Conventions

- Marketplace name is the repo name, **`claude-secret-guard`** (not `cj-mods`, which the sibling repos used and would clash). Plugin name stays `secret-guard`, so the install id is `secret-guard@claude-secret-guard`.
- Commit trailer, exactly: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (ASCII `@`; a full-width `＠` crept into earlier briefs). No push without Christian asking. Do not touch global git config or skip hooks.
- No network calls from the mod. Never log, print or store a raw secret, including in tests and debug output. Never read `~/.claude/settings.json` or `~/.claude/.credentials.json`.
- **Test fixtures:** `hooks/fixtures.ts` assembles fake secrets at run time from a seeded generator plus provider prefixes, so no complete key-shaped string exists in the repo. Keep it that way: it keeps `scan_secrets` clean, and a secret-guard you have installed will block you from writing a real-looking one.
- **Layout:** `hooks/register.tsx` is thin wiring. `engine.ts` is everything that touches `$`; `detect.ts`, `guard.ts`, `git.ts`, `allow.ts`, `command.ts`, `config.ts`, `hash.ts` are pure; `store.ts` takes a `KV` object. Tests sit beside the code as `*.test.ts`. `.claude-plugin/types/` is engine-written and gitignored.
- **Validator rules that shape the code:** `$` and its nouns may not be used as a value (write `{ get: k => $.store.get(k) }`, never `kv($.store)`); across files `$` may only be passed to function declarations, not const arrows; `update($, cond ? a : b, ...)` is refused (use if/else on literal atoms).
- **Test kit quirks:** the test `$` has no `$.store`/`$.process`, so drive helpers through hooks; registering the same event twice throws; prompts arrive without `origin`; ops are answered `{ value }`.

## 8. Resume prompt

> I'm continuing work on `claude-secret-guard`, a Claude Code mod that blocks secrets in file writes, shell commands, git add/commit and prompts. Repo: https://github.com/luckyajinn/claude-secret-guard (clone it, read `HANDOFF.md` first, then `README.md`). State: v0.1.0 is pushed on `main` at `ceb3c68`; 125 tests pass and `claude plugin validate .` passes; it has never been run in a live Claude Code session. Marketplace name is `claude-secret-guard`; commit with the Co-Authored-By trailer in HANDOFF section 7, and do not push unless I ask. First job: run it live with `claude --plugin-dir .`, starting in warn mode, work through next step 1, and report what differs from the tests before changing anything. Do not touch the sibling repos, make network calls from the mod, or print any secret value.
