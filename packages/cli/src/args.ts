import { parseArgs } from 'node:util'

// Argument parsing for the commands, on node:util's parseArgs (strict: an unknown option is an error), and the two
// errors the CLI raises itself. Every other error comes from the core or the edge and carries its own code.

/** An error of the CLI with a code of its own: `usage` for arguments, or a word such as `unhealthy`. */
export class CliError extends Error {
  readonly code: string

  constructor(code: string, detail: string) {
    super(`${code}: ${detail}`)
    this.name = 'CliError'
    this.code = code
  }
}

/** Arguments the command does not take, or a value it cannot read. */
export class UsageError extends CliError {
  constructor(detail: string) {
    super('usage', detail)
    this.name = 'UsageError'
  }
}

/** A word as the shell reads it: as is when it holds only safe characters, else in single quotes. */
export const shq = (s: string): string => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`)

/** An option: a string (repeatable with `multiple`) or a boolean flag. */
export interface OptionSpec {
  readonly type: 'string' | 'boolean'
  readonly multiple?: boolean
}

export interface Spec {
  /** The names of the positionals, exactly this many, for the usage message. */
  readonly positionals: readonly string[]
  readonly options: Readonly<Record<string, OptionSpec>>
  readonly required?: readonly string[]
}

type Value = string | boolean | (string | boolean)[] | undefined

/** What parse returns: the positionals, and the options by name. */
export interface Parsed {
  readonly positionals: readonly string[]
  readonly values: Readonly<Record<string, Value>>
}

/** Parses `args` against `spec`; UsageError for an unknown option, a missing value, or a positional too many or few. */
export function parse(args: readonly string[], spec: Spec): Parsed {
  let parsed: { positionals: string[]; values: Record<string, Value> }
  try {
    parsed = parseArgs({
      args: [...args],
      options: { ...spec.options },
      allowPositionals: true,
      strict: true,
    })
  } catch (e) {
    throw new UsageError((e as Error).message)
  }
  if (parsed.positionals.length !== spec.positionals.length) {
    const want = spec.positionals.map((p) => `<${p}>`).join(' ')
    throw new UsageError(
      want === '' ? `no positional argument, not ${parsed.positionals.join(' ')}` : `expected ${want}`,
    )
  }
  for (const name of spec.required ?? []) {
    if (parsed.values[name] === undefined) throw new UsageError(`--${name} is required`)
  }
  return parsed
}

/** A string option, or undefined. */
export function str(p: Parsed, name: string): string | undefined {
  const v = p.values[name]
  return typeof v === 'string' ? v : undefined
}

/** A required string option (parse has checked it is there). */
export function req(p: Parsed, name: string): string {
  return str(p, name) as string
}

/** A repeatable string option, in the order given; [] when absent. */
export function list(p: Parsed, name: string): string[] {
  const v = p.values[name]
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

/** A boolean flag. */
export function flag(p: Parsed, name: string): boolean {
  return p.values[name] === true
}

/** A positive integer option, or undefined when absent; UsageError for anything but decimal digits from 1 on. */
export function int(p: Parsed, name: string): number | undefined {
  const v = str(p, name)
  if (v === undefined) return undefined
  const n = Number(v)
  if (!/^[1-9][0-9]*$/.test(v) || !Number.isSafeInteger(n)) {
    throw new UsageError(`--${name} is a positive integer, not ${JSON.stringify(v)}`)
  }
  return n
}

/** A relay URL argument: http or https; UsageError otherwise. Returned without a trailing slash. */
export function relayUrl(text: string): string {
  let url: URL
  try {
    url = new URL(text)
  } catch {
    throw new UsageError(`${JSON.stringify(text)} is not a URL`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new UsageError(`${JSON.stringify(text)} is not an http or https URL`)
  }
  return text.replace(/\/+$/, '')
}
