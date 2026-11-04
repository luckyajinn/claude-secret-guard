import { expect, test } from 'claude-code/testing'

import { compileAllow, EMPTY_ALLOW } from './allow'
import { describeRules, entropy, isPlaceholder, isSecretName, MAX_SCAN_CHARS, scan } from './detect'
import type { Finding } from './detect'
import { body, fake, SALT } from './fixtures'
import { fingerprint } from './hash'

const run = (text: string, extra: { path?: string; allow?: ReturnType<typeof compileAllow> } = {}) =>
  scan(text, { salt: SALT, allow: extra.allow ?? EMPTY_ALLOW, path: extra.path })

const rules = (text: string): string[] => run(text).findings.map(f => f.rule)

const only = (text: string, name = 'text'): Finding => {
  const { findings } = run(text)

  expect(findings.length, `${name}: expected one finding, got ${findings.length}`).toBe(1)

  const [finding] = findings

  if (finding === undefined) {
    throw new Error(`${name}: no finding`)
  }

  return finding
}

// ---------------------------------------------------------------------------
// What is detected

const FORMATS: [string, string, () => string][] = [
  ['aws-access-key-id', 'AWS access key ID', fake.awsKeyId],
  ['github-token', 'GitHub token', fake.githubToken],
  ['github-fine-grained-token', 'GitHub fine-grained token', fake.githubPat],
  ['anthropic-api-key', 'Anthropic API key', fake.anthropicKey],
  ['openai-api-key', 'OpenAI-style sk- key', fake.openaiKey],
  ['stripe-key', 'Stripe key', fake.stripeKey],
  ['stripe-key', 'Stripe key', fake.stripeWebhook],
  ['slack-token', 'Slack token', fake.slackToken],
  ['slack-webhook', 'Slack webhook URL', fake.slackWebhook],
  ['google-api-key', 'Google API key', fake.googleKey],
  ['google-oauth-secret', 'Google OAuth client secret', fake.googleOauthSecret],
  ['sendgrid-key', 'SendGrid API key', fake.sendgridKey],
  ['npm-token', 'npm access token', fake.npmToken],
  ['huggingface-token', 'Hugging Face token', fake.huggingfaceToken],
  ['jwt', 'JSON Web Token', fake.jwt],
]

for (const [rule, label, make] of FORMATS) {
  test(`detects ${label} (${rule}) wherever it sits`, () => {
    const secret = make()

    for (const text of [secret, `value = "${secret}"`, `curl -H "X: ${secret}" https://api.example.org`, `a\nb ${secret}\nc`]) {
      const f = only(text)

      expect(f.rule).toBe(rule)
      expect(f.label).toBe(label)
      expect(text.slice(f.start, f.end)).toBe(secret)
      expect(f.length).toBe(secret.length)
    }
  })
}

test('detects a PEM private key block and spans the whole block', () => {
  const key = fake.privateKey()
  const text = `before\n${key}\nafter`
  const f = only(text)

  expect(f.rule).toBe('private-key')
  expect(f.line).toBe(2)
  expect(f.column).toBe(1)
  expect(text.slice(f.start, f.end)).toBe(key)
})

test('detects a private key written as one JSON string with escaped newlines', () => {
  const key = fake.privateKey().split('\n').join('\\n')
  const text = `{"type":"service_account","private_key":"${key}\\n"}`
  const f = only(text)

  expect(f.rule).toBe('private-key')
})

test('a private key header with no key material after it is only prose', () => {
  expect(rules(`the file starts with ${fake.privateKeyHeader()} and ends with a footer`)).toEqual([])
  expect(rules(`${fake.privateKeyHeader()}\n...\n-----END RSA PRIVATE KEY-----`)).toEqual([])
  expect(rules(`const HEADER = "${fake.privateKeyHeader()}"\nconst x = 1`)).toEqual([])
})

test('a public key or certificate is not a secret', () => {
  const cert = ['-----BEGIN ' + 'CERTIFICATE-----', body(64, 31), '-----END ' + 'CERTIFICATE-----'].join('\n')

  expect(rules(cert)).toEqual([])
})

test('detects hard-coded password, secret and token assignments in the usual syntaxes', () => {
  const password = fake.password()
  const secret = fake.secretValue()

  const cases: [string, string][] = [
    ['dotenv', `DB_PASSWORD=${password}`],
    ['shell export', `export API_TOKEN=${secret}`],
    ['quoted dotenv', `CLIENT_SECRET="${secret}"`],
    ['JSON', `{"password": "${password}"}`],
    ['YAML', `secret: ${secret}`],
    ['JS', `const apiKey = '${secret}'`],
    ['Go', `password := "${password}"`],
    ['Ruby hash', `'password' => '${password}'`],
    ['property chain name', `config.auth.token = "${secret}"`],
    ['HTTP header', `X-Api-Key: ${secret}`],
    ['URL query', `https://api.example.org/v1?token=${secret}&x=1`],
    ['CLI flag with equals', `tool --password=${password}`],
    ['CLI flag with space', `tool --api-key ${secret} --verbose`],
    ['PGPASSWORD prefix', `PGPASSWORD=${password} psql -h db`],
    ['camelCase', `clientSecret: "${secret}"`],
  ]

  for (const [name, text] of cases) {
    const f = only(text, name)

    expect(f.rule, name).toBe('generic-secret')
    expect(text.slice(f.start, f.end), name).toBe(text.includes(password) ? password : secret)
  }
})

test('detects a bearer token and a password inside a URL', () => {
  const token = fake.secretValue() + '9'
  const password = fake.password().replace(/[^A-Za-z0-9]/g, 'k')

  const bearer = only(`curl -H "Authorization: Bearer ${token}" https://api.example.org`)

  expect(bearer.rule).toBe('bearer-token')

  const url = `postgres://app:${password}@db.internal.example.org:5432/prod`
  const f = only(url)

  expect(f.rule).toBe('url-credentials')
  expect(url.slice(f.start, f.end)).toBe(password)
})

test('a JWT after Bearer is one finding, named jwt', () => {
  const f = only(`Authorization: Bearer ${fake.jwt()}`)

  expect(f.rule).toBe('jwt')
})

test('a token assigned to a variable is one finding, from the most specific rule', () => {
  const f = only(`GITHUB_TOKEN=${fake.githubToken()}`)

  expect(f.rule).toBe('github-token')
})

test('several secrets in one text are all found, in order', () => {
  const text = [`aws=${fake.awsKeyId()}`, 'nothing here', `gh=${fake.githubToken()}`].join('\n')
  const found = run(text).findings

  expect(found.map(f => f.rule)).toEqual(['aws-access-key-id', 'github-token'])
  expect(found.map(f => f.line)).toEqual([1, 3])
})

// ---------------------------------------------------------------------------
// What is not

test('placeholders and documentation values are ignored', () => {
  const placeholders = [
    'AK' + 'IA' + 'IOSFODNN7' + 'EXAMPLE',
    'gh' + 'p_' + 'x'.repeat(36),
    'DB_PASSWORD=changeme',
    'DB_PASSWORD="change-me-please-1"',
    'API_TOKEN=<your-api-token>',
    'API_TOKEN=your_token_goes_here',
    'password: "xxxxxxxxxxxx"',
    'secret = "************"',
    'token = "..........."',
    'SECRET=redacted-redacted',
    'sk' + '-' + 'x'.repeat(40),
    'api_key = "dummy-api-key-value"',
    `Bearer ${'a1'.repeat(15)}`,
  ]

  for (const text of placeholders) {
    expect(rules(text), text).toEqual([])
  }
})

test('references to a secret are not the secret', () => {
  const references = [
    'DB_PASSWORD=$DB_PASSWORD',
    'DB_PASSWORD="${DB_PASSWORD}"',
    'password: ${{ secrets.DB_PASSWORD }}',
    'const token = process.env.GITHUB_TOKEN',
    'const secret = config.auth.clientSecret',
    'password = os.environ["DB_PASSWORD"]',
    'password = getPassword()',
    'api_key = load_key("prod")',
    'API_KEY=%API_KEY%',
    'token: op://vault/item/field',
    'GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/credentials.json',
    'secret = "./secrets/db.txt"',
    'token = https://example.org/token/refresh',
    'Authorization: Bearer $TOKEN',
    'Authorization: Bearer ${API_TOKEN_VALUE_FROM_ENV}',
    'postgres://app:${DB_PASSWORD}@db.internal/prod',
  ]

  for (const text of references) {
    expect(rules(text), text).toEqual([])
  }
})

test('names that only contain a keyword are not credentials', () => {
  const harmless = [
    'max_tokens = 4096000000',
    'token_count = 123456789012',
    'tokenizer = "bert-base-uncased-model-name"',
    'secret_name = "database-credentials-prod"',
    'password_file = "database-credentials-prod"',
    'password_hash = "aG9wZWZ1bGx5bm90YXJlYWxvbmU="',
    'passwordless = "enabled-for-everyone"',
    'const secretary = "Ms. Henderson-Whitfield"',
  ]

  for (const text of harmless) {
    expect(rules(text), text).toEqual([])
  }
})

test('ordinary code and prose are left alone', () => {
  const ordinary = [
    'password: string',
    'const password = props.password',
    'password=correcthorse',
    'token: Token = Token.new()',
    'the password is stored hashed, never in plain text',
    'git commit -m "fix password handling in the login form"',
    'risk-assessment-of-something-quite-long-and-hyphenated',
    'task-queue-handler-factory-for-background-jobs',
    'const key = "short"',
    'const url = "https://example.org/a/b/c?page=2"',
    'See https://user:pass@example.org for the demo',
    'postgres://postgres:postgres@localhost:5432/dev',
    'sk-learn is the old name of scikit-learn',
  ]

  for (const text of ordinary) {
    expect(rules(text), text).toEqual([])
  }
})

test('values with low entropy are not credentials', () => {
  expect(rules('DB_PASSWORD="abababababab"')).toEqual([])
  expect(rules('API_TOKEN=aaaabbbbccccdddd')).toEqual([])
  expect(entropy('aaaaaaaa')).toBe(0)
  expect(entropy(fake.password())).toBeGreaterThan(3)
})

test('a weak human password is still caught when the name says password', () => {
  expect(rules('DB_PASSWORD=hunter22x')).toEqual(['generic-secret'])
})

// ---------------------------------------------------------------------------
// The allowlist

test('an allowlisted fingerprint, text or path silences a finding', () => {
  const secret = fake.githubToken()
  const text = `token = "${secret}"`
  const print = fingerprint(secret, SALT)

  expect(rules(text)).toEqual(['github-token'])
  expect(run(text, { allow: compileAllow([`fp:${print}`]) }).findings).toEqual([])
  expect(run(text, { allow: compileAllow([`text:${secret.slice(0, 12)}`]) }).findings).toEqual([])
  expect(run(text, { allow: compileAllow(['path:fixtures/**']), path: 'src/fixtures/a.json' }).findings).toEqual([])
  expect(run(text, { allow: compileAllow(['path:fixtures/**']), path: 'src/real/a.json' }).findings).toHaveLength(1)
  expect(run(text, { allow: compileAllow([`fp:${fingerprint('some other value', SALT)}`]) }).findings).toHaveLength(1)
})

test('an allowlisted fingerprint silences the same value under every rule', () => {
  const secret = fake.githubToken()
  const allow = compileAllow([`fp:${fingerprint(secret, SALT)}`])

  expect(run(`GITHUB_TOKEN=${secret}`, { allow }).findings).toEqual([])
})

// ---------------------------------------------------------------------------
// What a finding carries

test('a finding holds a rule, a place and a fingerprint, and never the value', () => {
  const secret = fake.githubToken()
  const text = `first line\n  token = "${secret}"\n`
  const f = only(text)

  expect(f.line).toBe(2)
  expect(f.column).toBe(12)
  expect(f.fingerprint).toBe(fingerprint(secret, SALT))
  expect(Object.keys(f).sort()).toEqual(['column', 'end', 'fingerprint', 'label', 'length', 'line', 'rule', 'start'])
  expect(JSON.stringify(f)).not.toContain(secret)
  expect(JSON.stringify(f)).not.toContain(secret.slice(4, 20))
})

test('the same value gets the same fingerprint wherever it appears, and the salt changes it', () => {
  const secret = fake.githubToken()
  const a = only(`a ${secret}`)
  const b = only(`a much longer line ${secret} with more`)

  expect(a.fingerprint).toBe(b.fingerprint)
  expect(scan(secret, { salt: 'another-salt-value-123456' }).findings[0]?.fingerprint).not.toBe(a.fingerprint)
})

test('line and column are right across Windows line endings and tabs', () => {
  const secret = fake.githubToken()
  const f = only(`one\r\ntwo\r\n\t${secret}`)

  expect(f.line).toBe(3)
  expect(f.column).toBe(2)
})

// ---------------------------------------------------------------------------
// Names, placeholders, limits

test('isSecretName reads the last word of a name', () => {
  for (const name of ['password', 'DB_PASSWORD', 'PGPASSWORD', 'clientSecret', 'APIKey', 'api_key', 'AWS_SECRET_ACCESS_KEY', 'auth_token', 'x-api-key', 'private_key', 'MYSQL_PWD']) {
    expect(isSecretName(name), name).toBe(true)
  }

  for (const name of ['key', 'max_tokens', 'tokenizer', 'secret_name', 'public_key', 'session_key', 'password_file', 'username']) {
    expect(isSecretName(name), name).toBe(false)
  }
})

test('the PWD variable is a folder, not a password', () => {
  expect(rules('PWD=/home/someone/projects/example-app')).toEqual([])
})

test('isPlaceholder knows stand-ins', () => {
  for (const value of ['EXAMPLEKEY123', 'xxxxxxxxxx', '<token>', '${TOKEN}', 'changeme', '1111111111111', 'abc...xyz', 'YOUR_API_KEY']) {
    expect(isPlaceholder(value), value).toBe(true)
  }

  expect(isPlaceholder(fake.githubToken())).toBe(false)
  expect(isPlaceholder(fake.password())).toBe(false)
})

test('describeRules lists every rule once, generic last', () => {
  const list = describeRules()
  const ids = list.map(rule => rule.id)

  expect(new Set(ids).size).toBe(ids.length)
  expect(ids[0]).toBe('private-key')
  expect(ids[ids.length - 1]).toBe('generic-secret')
  expect(ids).toContain('github-token')
  expect(ids).toContain('jwt')
})

test('text past the limit is cut and the result says so', () => {
  const long = `${'ab cd '.repeat(Math.ceil(MAX_SCAN_CHARS / 6))}\n${fake.githubToken()}`
  const result = run(long)

  expect(result.isTruncated).toBe(true)
  expect(result.findings).toEqual([])
  expect(run(`short ${fake.githubToken()}`).isTruncated).toBe(false)
})

test('pathological input does not hang the scan', () => {
  const inputs = [
    'a'.repeat(200_000),
    'a='.repeat(100_000),
    `${'password '.repeat(20_000)}=`,
    `${'-'.repeat(100_000)}`,
    `${fake.privateKeyHeader()}${'A'.repeat(100_000)}`,
    `://${'a:'.repeat(50_000)}`,
    'Bearer ' + 'a'.repeat(100_000),
  ]

  for (const text of inputs) {
    expect(Array.isArray(run(text).findings)).toBe(true)
  }
})
