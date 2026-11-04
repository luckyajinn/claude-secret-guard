// Fake secrets for the tests, built at run time so that no complete key-shaped
// string is written anywhere in this repository (a secret scanner reading the
// source finds prefixes and recipes, never a key). Every value is made from a
// seeded generator: the same fixture every run, none of them a real credential.

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const UPPER_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const DIGITS = '0123456789'
const B64URL = `${ALNUM}-_`
const B64 = `${ALNUM}+/`
const PASSWORD = `${ALNUM}!#%^*`

/** `length` characters of `alphabet`, the same ones every time for the same seed. */
export const body = (length: number, seed: number, alphabet: string = ALNUM): string => {
  let state = (Math.imul(seed, 2654435761) + 12345) >>> 0
  let out = ''

  for (let i = 0; i < length; i += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0
    out += alphabet[(state >>> 12) % alphabet.length]
  }

  return out
}

const BEGIN = '-----BEGIN '
const END = '-----END '
const DASHES = '-----'

export const fake = {
  awsKeyId: (): string => 'AK' + 'IA' + body(16, 1, UPPER_DIGITS),
  githubToken: (): string => 'gh' + 'p_' + body(36, 2),
  githubPat: (): string => 'github' + '_pat_' + body(82, 3, `${ALNUM}_`),
  anthropicKey: (): string => 'sk' + '-ant-' + 'api03-' + body(90, 4, B64URL),
  openaiKey: (): string => 'sk' + '-proj-' + body(48, 5),
  stripeKey: (): string => 'sk' + '_live_' + body(24, 6),
  stripeWebhook: (): string => 'whsec' + '_' + body(32, 7),
  slackToken: (): string => 'xox' + 'b-' + body(12, 8, DIGITS) + '-' + body(13, 9, DIGITS) + '-' + body(24, 10),
  slackWebhook: (): string => 'https://hooks.slack' + '.com/services/T' + body(8, 11, UPPER_DIGITS) + '/B' + body(8, 12, UPPER_DIGITS) + '/' + body(24, 13),
  googleKey: (): string => 'AI' + 'za' + body(35, 14, B64URL),
  googleOauthSecret: (): string => 'GOCSPX' + '-' + body(28, 15, B64URL),
  sendgridKey: (): string => 'SG' + '.' + body(22, 16, B64URL) + '.' + body(43, 17, B64URL),
  npmToken: (): string => 'npm' + '_' + body(36, 18),
  huggingfaceToken: (): string => 'hf' + '_' + body(34, 19),
  jwt: (): string => 'ey' + 'J' + body(20, 20, B64URL) + '.' + 'ey' + 'J' + body(30, 21, B64URL) + '.' + body(43, 22, B64URL),
  password: (): string => body(16, 23, PASSWORD),
  secretValue: (): string => body(32, 24),
  /** A PEM private key block: header, two lines of base64, footer. */
  privateKey: (): string =>
    [BEGIN + 'RSA PRIVATE ' + 'KEY' + DASHES, body(64, 25, B64), body(64, 26, B64), END + 'RSA PRIVATE ' + 'KEY' + DASHES].join('\n'),
  /** Just the header line, as it appears in prose or in code that parses PEM. */
  privateKeyHeader: (): string => BEGIN + 'RSA PRIVATE ' + 'KEY' + DASHES,
}

const HEX = '0123456789abcdef'
const AGE = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'

/**
 * One fake token per vendor rule added in 0.1.2, each `{ rule, value }`, assembled
 * from split prefixes so that no complete key-shaped string sits in the source.
 */
export const vendorTokens = (): { rule: string; value: string }[] => [
  { rule: 'gitlab-token', value: 'gl' + 'pat-' + body(20, 30, B64URL) },
  { rule: 'pypi-token', value: 'py' + 'pi-' + 'AgEIcHlwaS5' + 'vcmc' + body(60, 31, B64URL) },
  { rule: 'shopify-token', value: 'shp' + 'at_' + body(32, 32, HEX) },
  { rule: 'digitalocean-token', value: 'do' + 'p_v1_' + body(64, 33, HEX) },
  { rule: 'databricks-token', value: 'dap' + 'i' + body(32, 34, 'abcdefgh0123456789') },
  { rule: 'sentry-token', value: 'sntr' + 'ys_' + body(60, 35, B64URL) },
  { rule: 'supabase-token', value: 'sb' + 'p_' + body(40, 36, HEX) },
  { rule: 'vault-token', value: 'hv' + 's.' + body(40, 37, B64URL) },
  { rule: 'terraform-token', value: body(14, 61) + '.atlas' + 'v1.' + body(66, 62, B64URL) },
  { rule: 'grafana-token', value: 'gl' + 'sa_' + body(32, 38) + '_' + body(8, 39, HEX) },
  { rule: 'postman-key', value: 'PM' + 'AK-' + body(24, 40, HEX) + '-' + body(34, 41, HEX) },
  { rule: 'atlassian-token', value: 'ATAT' + 'T3' + body(70, 42, B64URL) },
  { rule: 'google-access-token', value: 'ya' + '29.' + body(60, 43, B64URL) },
  { rule: 'age-secret-key', value: 'AGE-SECRET-' + 'KEY-1' + body(58, 44, AGE) },
  { rule: 'twilio-key', value: 'S' + 'K' + body(32, 45, HEX) },
  { rule: 'telegram-bot-token', value: body(9, 46, DIGITS) + ':A' + 'A' + body(33, 47, B64URL) },
  { rule: 'discord-bot-token', value: 'M' + body(24, 68, B64URL) + '.' + body(6, 69, B64URL) + '.' + body(30, 70, B64URL) },
  { rule: 'discord-webhook', value: 'https://discord' + '.com/api/webhooks/' + body(18, 48, DIGITS) + '/' + body(68, 49, B64URL) },
  { rule: 'mailgun-key', value: 'ke' + 'y-' + body(32, 50, HEX) },
  { rule: 'doppler-token', value: 'dp' + '.pt.' + body(42, 51) },
  { rule: 'azure-ad-secret', value: body(3, 52) + '8Q' + '~' + body(34, 53, `${ALNUM}_.~-`) },
  { rule: 'notion-token', value: 'sec' + 'ret_' + body(43, 54) },
  { rule: 'linear-key', value: 'lin' + '_api_' + body(40, 55) },
  { rule: 'groq-key', value: 'gs' + 'k_' + body(52, 56) },
  { rule: 'xai-key', value: 'xa' + 'i-' + body(80, 57) },
  { rule: 'perplexity-key', value: 'pp' + 'lx-' + body(48, 58) },
  { rule: 'replicate-token', value: 'r' + '8_' + body(37, 59) },
  { rule: 'docker-token', value: 'dckr' + '_pat_' + body(27, 60, B64URL) },
  { rule: 'netlify-token', value: 'nf' + 'p_' + body(36, 63) },
  { rule: 'square-token', value: 'sq0' + 'atp-' + body(30, 64, B64URL) },
  { rule: 'slack-token', value: 'xox' + 'c-' + body(12, 65, DIGITS) + '-' + body(24, 66) },
  { rule: 'slack-token', value: 'xox' + 'e-1-' + body(40, 67) },
]

export const SALT = 'test-salt-0123456789abcdef0123'
