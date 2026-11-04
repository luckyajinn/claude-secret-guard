/** The four places the mod stands guard. */
export type GuardPoint = 'file' | 'command' | 'commit' | 'prompt'

/** What the mod did about a finding. */
export type GuardAction = 'blocked' | 'warned'

/**
 * One entry of the recent-blocks log. It names the rule and the place; it
 * never holds the secret. `fingerprint` is the first 8 hex digits of a salted
 * SHA-256 of the value, enough to tell findings apart or to allowlist one.
 */
export type BlockRecord = {
  /** Epoch milliseconds. */
  at: number
  guard: GuardPoint
  action: GuardAction
  rule: string
  /** A file and line, `command line 2`, `prompt line 1`, and so on. */
  location: string
  fingerprint: string
}

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': {
      /** Findings blocked in this session. */
      blocked: number
      /** Findings only warned about in this session (warn mode, or a guard that could not scan). */
      warned: number
    }
  }
}
