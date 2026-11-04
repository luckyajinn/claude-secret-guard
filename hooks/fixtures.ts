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

export const SALT = 'test-salt-0123456789abcdef0123'
