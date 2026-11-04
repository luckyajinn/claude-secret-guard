// Secret detection. Pure functions: text in, findings out.
//
// A finding says which rule matched and where (offsets, line, column) and
// carries a short salted fingerprint. It never carries the matched value, so a
// finding is safe to log, store and show. The value only exists inside `scan`,
// long enough to be checked against the allowlist and fingerprinted.
//
// This is regex-and-entropy heuristics. It will miss secrets that have no
// recognizable shape, and it will occasionally flag something harmless; the
// allowlist is for the second, and the README is honest about the first.

import { isPathAllowed, isTextAllowed, EMPTY_ALLOW } from './allow'
import type { Allow } from './allow'
import { fingerprint } from './hash'

/**
 * Text past this many characters is not scanned (the result says so, and a guard
 * in block mode then refuses it rather than let it through unchecked).
 */
export const MAX_SCAN_CHARS = 40_000_000

// Long text is scanned in windows, each with some text on either side so that a
// secret on a seam is seen whole: a window reports only what starts inside it.
const WINDOW_CHARS = 4_000_000
const LEFT_CONTEXT = 512
// Wide enough for the longest thing a rule reads past its start (a private key's body).
const RIGHT_OVERLAP = 32_768

export type Finding = {
  /** The rule's id, `github-token`. */
  rule: string
  /** The rule's plain name, `GitHub token`. */
  label: string
  /** Offsets into the scanned text, end exclusive. */
  start: number
  end: number
  /** 1-based. */
  line: number
  column: number
  /** Characters in the value. */
  length: number
  /** 8 hex digits of a salted hash of the value. */
  fingerprint: string
}

export type ScanOptions = {
  /** The per-install salt the fingerprints are made with. */
  salt: string
  allow?: Allow
  /** The file the text is going into, matched against `path:` allowlist entries. */
  path?: string
  /** Where scanning stops (default MAX_SCAN_CHARS) and how big a window is (default 4,000,000); the tests turn these down. */
  maxChars?: number
  windowChars?: number
}

export type ScanResult = {
  findings: Finding[]
  /** True when the text was longer than the scan limit and only its start was scanned. */
  isTruncated: boolean
}

type Span = { start: number; end: number }

type Rule = {
  id: string
  label: string
  find: (text: string) => Span[]
}

// ---------------------------------------------------------------------------
// Small checks

/** Shannon entropy in bits per character. */
export const entropy = (value: string): number => {
  const counts = new Map<string, number>()
  let total = 0

  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1)
    total += 1
  }

  let bits = 0

  for (const n of counts.values()) {
    const p = n / total

    bits -= p * Math.log2(p)
  }

  return bits
}

// Words that mean "this is not a real secret", wherever they sit in a value.
// "test" is deliberately not here: test-mode keys are still keys.
const PLACEHOLDER_WORDS = [
  'example',
  'placeholder',
  'changeme',
  'change_me',
  'change-me',
  'replaceme',
  'replace_me',
  'replace-me',
  'redacted',
  'censored',
  'dummy',
  'fake',
  'sample',
  'yourkey',
  'your_',
  'your-',
  'your ',
  'insert',
  'xxxx',
  'todo',
  'fixme',
  'notasecret',
  'not-a-secret',
  'not_a_secret',
  'undefined',
  '<',
  '>',
  '${',
  '{{',
]

/** True for a value that is obviously a stand-in: EXAMPLE, xxxx, <your-key>, a long run of one character. */
export const isPlaceholder = (value: string): boolean => {
  const lower = value.toLowerCase()

  return (
    PLACEHOLDER_WORDS.some(word => lower.includes(word)) ||
    /(.)\1{7,}/.test(value) ||
    /\*{3}|\.{3}|…/.test(value) ||
    /^[x*.\-_0]+$/i.test(value)
  )
}

// Words that, in a hand-typed password or secret, say the author was writing a
// fixture, not a credential. Only the generic rule uses these.
const WEAK_WORDS = [
  'test',
  'demo',
  'default',
  'password',
  'passwd',
  'secret',
  'token',
  'admin',
  'letmein',
  'qwerty',
  '12345',
  'abcde',
]

/** True for what is a reference to a secret rather than the secret: $VAR, ${VAR}, process.env.X, fn(), a path, a URL. */
const isReference = (value: string): boolean =>
  /^\$(?:[A-Za-z_{(]|\d)/.test(value) ||
  /^%[^%\s]+%$/.test(value) ||
  /\$\{|\$\(|\{\{|`/.test(value) ||
  // A call is a reference: a name of letters (no digits) then `(` (the value is cut at
  // a quote or `)`, so `load_key("x")` arrives as `load_key(`), or a complete call.
  // A password that merely holds a parenthesis, `Xk9(2fLq!zz`, is not one.
  /^[A-Za-z_$][A-Za-z_$.]*\(/.test(value) ||
  /^[A-Za-z_$][\w$.]*\(.*\)$/.test(value) ||
  /^[A-Za-z_$][\w$.]*\([A-Za-z_$][\w$.,]*$/.test(value) ||
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value) ||
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\[/.test(value) ||
  /^(?:op|vault|ssm|secretsmanager|ref\+\w+|env|file|k8s|aws-sm|gcp-sm):/i.test(value) ||
  /^(?:[~.]{0,2}[/\\]|[A-Za-z]:[\\/]|https?:\/\/)/.test(value)

// ---------------------------------------------------------------------------
// Finding spans

/**
 * A finder over a regex. `pick` returns the secret from the match, which the
 * pattern must put at the very end of the match (use a lookahead for whatever
 * follows it), so its span is known without the `d` flag. `accept` can veto.
 */
const fromRegex =
  (
    pattern: RegExp,
    pick: (m: RegExpExecArray) => string | undefined,
    accept?: (value: string, m: RegExpExecArray) => boolean,
  ) =>
  (text: string): Span[] => {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`)
    const out: Span[] = []
    let m: RegExpExecArray | null

    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1
        continue
      }

      const value = pick(m)

      if (value === undefined || value.length === 0 || (accept && !accept(value, m))) {
        continue
      }

      const end = m.index + m[0].length

      out.push({ start: end - value.length, end })
    }

    return out
  }

/** A token whose whole match is the secret. */
const token = (pattern: RegExp, minEntropy = 0) =>
  fromRegex(pattern, m => m[0], value => minEntropy === 0 || entropy(value) >= minEntropy)

const PEM_BEGIN = /-----BEGIN (?:[A-Z0-9]{2,12} ){0,3}PRIVATE KEY(?: BLOCK)?-----/g
// What a real key has right after its header: optional header lines
// (Proc-Type, DEK-Info), then base64. A header named in prose, or in code that
// parses PEM, has no key material after it.
const PEM_BODY = /^(?:\s|\\[nr])*(?:[A-Za-z-]+:[^\n\\]*(?:\r?\n|\\n)(?:\s|\\[nr])*)*([A-Za-z0-9+/=]{24,})/

const findPrivateKeys = (text: string): Span[] => {
  const out: Span[] = []
  const re = new RegExp(PEM_BEGIN.source, 'g')
  let m: RegExpExecArray | null

  while ((m = re.exec(text)) !== null) {
    const afterHeader = m.index + m[0].length
    const tail = text.slice(afterHeader, afterHeader + 20_000)
    const body = PEM_BODY.exec(tail)

    if (!body || entropy(body[1] ?? '') < 3) {
      continue
    }

    let end = afterHeader + body[0].length
    const endMarker = tail.indexOf('-----END ')

    if (endMarker >= 0) {
      const close = tail.indexOf('-----', endMarker + 9)

      end = afterHeader + (close >= 0 ? close + 5 : endMarker + 9)
    }

    out.push({ start: m.index, end })
    re.lastIndex = Math.max(re.lastIndex, end)
  }

  return out
}

// Names that mean "a credential": the last word of the name decides, so
// `GITHUB_TOKEN`, `clientSecret` and `PGPASSWORD` match while `max_tokens`,
// `tokenizer`, `password_file` and `secret_name` do not.
const STRONG_SUFFIXES = [
  'password',
  'passwd',
  'passphrase',
  'secret',
  'token',
  'credential',
  'credentials',
  'apikey',
  // Run together (`secretkey=`, `accesskey=`): the name has no word break to split on.
  'secretkey',
  'accesskey',
  'privatekey',
  'authkey',
  'signingkey',
  'encryptionkey',
  'masterkey',
]
// Short names that are a credential only as the whole last word (`DB_PASS`), not as the end of `bypass`.
const EXACT_STRONG = ['pwd', 'pass', 'pw', 'pswd']
const KEY_PREFIXES = ['api', 'access', 'auth', 'private', 'signing', 'encryption', 'master', 'client', 'secret', 'app', 'license', 'jwt', 'hmac', 'shared']
const VALUE_WORDS = ['key', 'value', 'str', 'string', 'b64', 'base64']

const nameWords = (name: string): string[] =>
  name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(word => word !== '')

const isStrongWord = (word: string): boolean => EXACT_STRONG.includes(word) || STRONG_SUFFIXES.some(suffix => word.endsWith(suffix))

/** True when a variable or key name says its value is a credential. */
export const isSecretName = (name: string): boolean => {
  const words = nameWords(name)
  const last = words[words.length - 1]

  if (last === undefined) {
    return false
  }

  if (isStrongWord(last)) {
    return true
  }

  const before = words[words.length - 2]

  if (before === undefined) {
    return false
  }

  if (last === 'key') {
    return KEY_PREFIXES.includes(before) || isStrongWord(before)
  }

  return VALUE_WORDS.includes(last) && isStrongWord(before)
}

const isPasswordName = (name: string): boolean => {
  const last = nameWords(name).filter(word => !VALUE_WORDS.includes(word)).pop() ?? ''

  return last === 'pwd' || last === 'pass' || last === 'pw' || last === 'pswd' || /pass(?:word|wd|phrase)$/.test(last)
}

/** The value after `name =` is believable as a hard-coded credential. */
const isBelievableValue = (value: string, name: string, isQuoted: boolean): boolean => {
  if (value.length < 8 || isPlaceholder(value) || isReference(value)) {
    return false
  }

  const lower = value.toLowerCase()

  if (WEAK_WORDS.some(word => lower.includes(word))) {
    return false
  }

  // `password=correcthorse` in code is as likely a variable as a literal; a
  // quoted string, or anything with a digit or symbol in it, is a literal.
  if (!isQuoted && /^[A-Za-z_$][A-Za-z_$.-]*$/.test(value)) {
    return false
  }

  return entropy(value) >= (isPasswordName(name) ? 2.5 : 3)
}

// A name and what joins it to its value: `password =`, `"token":`, `--api-key `.
// The name is found and judged first; only a credential's name has its value
// read, so a value is never swallowed by a name that was not one (the
// `https:` in `https://host/?token=...` is a name followed by a long run).
// A type annotation may sit between the name and the `=` (a Python or Kotlin
// declaration with a type); it is only read as one when a value follows the `=`,
// so a YAML value that ends in base64 padding is still read the plain way.
const NAME_THEN_OPERATOR =
  /(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,63})["']?\s*(?::=|=>|:[ \t]*[A-Za-z_][\w.<>[\], |?]{0,40}[ \t]*=(?![=>])[ \t]*(?=\S)|[:=])[ \t]*/g
const NAME_THEN_FLAG = /(?<![A-Za-z0-9-])--([A-Za-z][A-Za-z0-9-]{0,40})(?:=|[ \t]+)/g

// What follows: a quoted string (its closing quote is a lookahead, so the value
// ends the match) or a bare run, which stops at `&` (the next query parameter).
// A quoted value may hold escapes (`\"`, `\\`) and run to 2000 characters.
const ASSIGNED_VALUE = /"((?:[^"\\\r\n]|\\.){8,2000})(?=")|'((?:[^'\\\r\n]|\\.){8,2000})(?=')|([^\s"'`,;)}\]<>&]{8,200})/y
const FLAG_VALUE = /"([^"\r\n]{8,2000})(?=")|'([^'\r\n]{8,2000})(?=')|([^\s"'`<>&]{8,200})/y

const credentialValues = (text: string, names: RegExp, values: RegExp): Span[] => {
  const out: Span[] = []
  const nameRe = new RegExp(names.source, 'g')
  const valueRe = new RegExp(values.source, 'y')
  let m: RegExpExecArray | null

  while ((m = nameRe.exec(text)) !== null) {
    const name = m[1] ?? ''

    if (!isSecretName(name)) {
      continue
    }

    valueRe.lastIndex = nameRe.lastIndex

    const v = valueRe.exec(text)

    if (v === null) {
      continue
    }

    const value = v[1] ?? v[2] ?? v[3]
    const isQuoted = v[3] === undefined

    if (value !== undefined && isBelievableValue(value, name, isQuoted)) {
      const end = nameRe.lastIndex + v[0].length

      out.push({ start: end - value.length, end })
      nameRe.lastIndex = end
    }
  }

  return out
}

const findAssignments = (text: string): Span[] => [
  ...credentialValues(text, NAME_THEN_OPERATOR, ASSIGNED_VALUE),
  ...credentialValues(text, NAME_THEN_FLAG, FLAG_VALUE),
]

const hasDigit = (value: string): boolean => /\d/.test(value)

// A password in a URL is a secret unless it is the stock one of a dev database.
const STOCK_URL_PASSWORDS = /^(?:pass|password|passwd|secret|postgres|root|admin|user|test|guest|mysql|redis|changeme)$/i

// ---------------------------------------------------------------------------
// Vendor tokens with a fixed prefix. Each is `prefix + body` with a known
// length, behind a boundary so a longer word does not match, and a modest
// entropy floor so a prefix followed by a plain word is left alone.

const vendor = (id: string, label: string, pattern: RegExp, minEntropy = 3): Rule => ({ id, label, find: token(pattern, minEntropy) })

const VENDOR_RULES: readonly Rule[] = [
  vendor('gitlab-token', 'GitLab token', /(?<![A-Za-z0-9])gl(?:pat|ptt|rt|dt)-[A-Za-z0-9_-]{20,50}(?![A-Za-z0-9_-])/g),
  vendor('pypi-token', 'PyPI upload token', /(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])/g),
  vendor('shopify-token', 'Shopify token', /(?<![A-Za-z0-9])shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}(?![A-Za-z0-9])/g),
  vendor('digitalocean-token', 'DigitalOcean token', /(?<![A-Za-z0-9])do[por]_v1_[a-f0-9]{64}(?![A-Za-z0-9])/g),
  vendor('databricks-token', 'Databricks token', /(?<![A-Za-z0-9])dapi[a-h0-9]{32}(?![A-Za-z0-9])/g),
  vendor('sentry-token', 'Sentry auth token', /(?<![A-Za-z0-9])sntrys_[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9+/=_-])/g),
  vendor('supabase-token', 'Supabase access token', /(?<![A-Za-z0-9])sbp_[a-f0-9]{40}(?![A-Za-z0-9])/g),
  vendor('vault-token', 'HashiCorp Vault token', /(?<![A-Za-z0-9])hv[sbr]\.[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])/g),
  vendor('terraform-token', 'Terraform Cloud token', /(?<![A-Za-z0-9])[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,70}(?![A-Za-z0-9_-])/g),
  vendor('grafana-token', 'Grafana service account token', /(?<![A-Za-z0-9])glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?![A-Za-z0-9])/g),
  vendor('postman-key', 'Postman API key', /(?<![A-Za-z0-9])PMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9])/g),
  vendor('atlassian-token', 'Atlassian API token', /(?<![A-Za-z0-9])ATATT3[A-Za-z0-9_=-]{50,}(?![A-Za-z0-9_=-])/g),
  vendor('google-access-token', 'Google OAuth access token', /(?<![A-Za-z0-9])ya29\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g),
  vendor('age-secret-key', 'age secret key', /(?<![A-Za-z0-9-])AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Za-z0-9])/g),
  vendor('twilio-key', 'Twilio API key', /(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])/g),
  vendor('telegram-bot-token', 'Telegram bot token', /(?<![A-Za-z0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])/g),
  vendor('discord-bot-token', 'Discord bot token', /(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}(?![A-Za-z0-9_-])/g, 4),
  vendor(
    'discord-webhook',
    'Discord webhook URL',
    /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{60,}/g,
  ),
  vendor('mailgun-key', 'Mailgun API key', /(?<![A-Za-z0-9])key-[0-9a-f]{32}(?![A-Za-z0-9])/g),
  vendor('doppler-token', 'Doppler token', /(?<![A-Za-z0-9])dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}(?![A-Za-z0-9])/g),
  vendor('azure-ad-secret', 'Azure AD client secret', /(?<![A-Za-z0-9_.~-])[A-Za-z0-9_.~-]{3}8Q~[A-Za-z0-9_.~-]{34,}(?![A-Za-z0-9_.~-])/g, 3.3),
  vendor('notion-token', 'Notion integration token', /(?<![A-Za-z0-9])(?:secret|ntn)_[A-Za-z0-9]{40,50}(?![A-Za-z0-9])/g, 3.3),
  vendor('linear-key', 'Linear API key', /(?<![A-Za-z0-9])lin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])/g),
  vendor('groq-key', 'Groq API key', /(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{52}(?![A-Za-z0-9])/g),
  vendor('xai-key', 'xAI API key', /(?<![A-Za-z0-9])xai-[A-Za-z0-9]{80}(?![A-Za-z0-9])/g),
  vendor('perplexity-key', 'Perplexity API key', /(?<![A-Za-z0-9])pplx-[A-Za-z0-9]{48}(?![A-Za-z0-9])/g),
  vendor('replicate-token', 'Replicate API token', /(?<![A-Za-z0-9])r8_[A-Za-z0-9]{37}(?![A-Za-z0-9])/g),
  vendor('docker-token', 'Docker personal access token', /(?<![A-Za-z0-9])dckr_pat_[A-Za-z0-9_-]{27}(?![A-Za-z0-9_-])/g),
  vendor('netlify-token', 'Netlify personal access token', /(?<![A-Za-z0-9])nfp_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g),
  vendor('square-token', 'Square token', /(?<![A-Za-z0-9])sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}(?![A-Za-z0-9_-])/g),
]

// ---------------------------------------------------------------------------
// The rules, most specific first: where two overlap, the earlier one wins.

const RULES: readonly Rule[] = [
  { id: 'private-key', label: 'Private key block', find: findPrivateKeys },
  {
    id: 'aws-access-key-id',
    label: 'AWS access key ID',
    find: token(/(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[A-Z0-9]{16}(?![A-Za-z0-9])/g),
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    find: token(/(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])/g),
  },
  {
    id: 'github-fine-grained-token',
    label: 'GitHub fine-grained token',
    find: token(/(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{50,255}(?![A-Za-z0-9_])/g),
  },
  {
    id: 'anthropic-api-key',
    label: 'Anthropic API key',
    find: token(/(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g),
  },
  {
    id: 'openai-api-key',
    label: 'OpenAI-style sk- key',
    find: token(/(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])/g, 3.3),
  },
  {
    id: 'stripe-key',
    label: 'Stripe key',
    find: token(/(?<![A-Za-z0-9])(?:(?:sk|rk)_(?:live|test)|whsec)_[A-Za-z0-9]{16,99}(?![A-Za-z0-9])/g),
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    find: token(/(?<![A-Za-z0-9])(?:xox[a-z]|xapp)-[A-Za-z0-9%+/=_-]{10,200}(?![A-Za-z0-9%+/=_-])/g),
  },
  {
    id: 'slack-webhook',
    label: 'Slack webhook URL',
    find: token(/https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]{6,}\/B[A-Za-z0-9]{6,}\/[A-Za-z0-9]{16,}/g),
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    find: token(/(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g),
  },
  {
    id: 'google-oauth-secret',
    label: 'Google OAuth client secret',
    find: token(/(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g),
  },
  {
    id: 'sendgrid-key',
    label: 'SendGrid API key',
    find: token(/(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g),
  },
  {
    id: 'npm-token',
    label: 'npm access token',
    find: token(/(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g),
  },
  {
    id: 'huggingface-token',
    label: 'Hugging Face token',
    find: token(/(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])/g, 3.5),
  },
  ...VENDOR_RULES,
  {
    id: 'jwt',
    label: 'JSON Web Token',
    find: token(/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g),
  },
  {
    id: 'bearer-token',
    label: 'Bearer token',
    find: fromRegex(
      /\bBearer[ \t]+([A-Za-z0-9._~+/-]{20,}=*)/gi,
      m => m[1],
      value => hasDigit(value) && entropy(value) >= 3.3,
    ),
  },
  {
    id: 'url-credentials',
    label: 'Password inside a URL',
    find: fromRegex(
      /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@"'<>]{1,64}:([^\s:/@"'<>]{3,128})(?=@[^\s/"'<>]+)/gi,
      m => m[1],
      value => !STOCK_URL_PASSWORDS.test(value) && !isReference(value),
    ),
  },
  { id: 'generic-secret', label: 'Hard-coded password, secret or token', find: findAssignments },
]

/** The rules, in the order they are tried, for `/secret-guard rules`. */
export const describeRules = (): { id: string; label: string }[] => RULES.map(({ id, label }) => ({ id, label }))

// ---------------------------------------------------------------------------
// Scanning

const lineStarts = (text: string): number[] => {
  const starts = [0]

  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {
      starts.push(i + 1)
    }
  }

  return starts
}

/** Index of the last line that starts at or before `offset`. */
const lineOf = (starts: readonly number[], offset: number): number => {
  let low = 0
  let high = starts.length - 1

  while (low < high) {
    const mid = (low + high + 1) >> 1

    if ((starts[mid] ?? 0) <= offset) {
      low = mid
    } else {
      high = mid - 1
    }
  }

  return low
}

/**
 * Scans text for secrets. Findings come back in the order they appear, with no
 * value in them. A file whose path matches a `path:` allowlist entry is not
 * scanned; a value matching a `fp:` or `text:` entry, or a placeholder, is not
 * reported.
 */
export const scan = (input: string, options: ScanOptions): ScanResult => {
  const allow = options.allow ?? EMPTY_ALLOW

  if (options.path !== undefined && isPathAllowed(allow, options.path)) {
    return { findings: [], isTruncated: false }
  }

  const maxChars = options.maxChars ?? MAX_SCAN_CHARS
  const windowChars = options.windowChars ?? WINDOW_CHARS
  const isTruncated = input.length > maxChars
  const text = isTruncated ? input.slice(0, maxChars) : input
  const found: { rule: Rule; span: Span; fingerprint: string }[] = []

  for (let from = 0; from === 0 || from < text.length; from += windowChars) {
    const to = Math.min(from + windowChars, text.length)
    const base = Math.max(0, from - LEFT_CONTEXT)
    const chunk = text.slice(base, Math.min(text.length, to + RIGHT_OVERLAP))
    const taken: Span[] = []

    for (const rule of RULES) {
      for (const local of rule.find(chunk)) {
        const span = { start: local.start + base, end: local.end + base }

        if (taken.some(other => span.start < other.end && other.start < span.end)) {
          continue
        }

        const value = text.slice(span.start, span.end)
        const print = fingerprint(value, options.salt)

        // A private key's body is long enough to contain a placeholder word by
        // chance, so it is judged by its own check (real base64 after the header).
        const isStandIn = rule.id !== 'private-key' && isPlaceholder(value)

        if (isStandIn || allow.fingerprints.has(print) || isTextAllowed(allow, value)) {
          continue
        }

        taken.push(span)

        // What starts in the text around the window is another window's to report.
        if (span.start >= from && span.start < to) {
          found.push({ rule, span, fingerprint: print })
        }
      }
    }
  }

  const starts = lineStarts(text)
  const findings = found
    .sort((a, b) => a.span.start - b.span.start)
    .map(({ rule, span, fingerprint: print }): Finding => {
      const line = lineOf(starts, span.start)

      return {
        rule: rule.id,
        label: rule.label,
        start: span.start,
        end: span.end,
        line: line + 1,
        column: span.start - (starts[line] ?? 0) + 1,
        length: span.end - span.start,
        fingerprint: print,
      }
    })

  return { findings, isTruncated }
}
