// The mod's options, from the fields plugin.json's `userConfig` declares.

export type Config = {
  mode: 'block' | 'warn'
  guardFiles: boolean
  guardCommands: boolean
  guardCommits: boolean
  guardPrompts: boolean
}

type Options = Readonly<Record<string, unknown>>

const flag = (options: Options, key: string): boolean => options[key] !== false

/** Reads the options, with everything on and blocking where a value is missing or not what was declared. */
export const readConfig = (options: Options): Config => ({
  mode: options.mode === 'warn' ? 'warn' : 'block',
  guardFiles: flag(options, 'guardFiles'),
  guardCommands: flag(options, 'guardCommands'),
  guardCommits: flag(options, 'guardCommits'),
  guardPrompts: flag(options, 'guardPrompts'),
})
