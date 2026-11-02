import type { SecurityResult, SecurityRunner } from '../../src/adapters/keychain.ts'

// A fake /usr/bin/security for the Keychain custody's unit tests: items in memory, read and written as the
// real one answers (`security -i` returns its command's status, 44 for an item or a keychain that is not
// there, 45 for a duplicate), every call recorded; and the detector that counts secrets in text (L3).

/** One call: its arguments and its stdin as text (null without one). */
export interface Call {
  readonly args: readonly string[]
  readonly input: string | null
}

/** The words of a `security -i` line: split at spaces, double quotes holding spaces (`""` is an empty word). */
export function words(line: string): string[] {
  const out: string[] = []
  for (const m of line.trim().matchAll(/"([^"]*)"|(\S+)/g)) out.push(m[1] ?? (m[2] as string))
  return out
}

/** An item: its data, and whether `-T ""` left no application trusted. */
export interface Item {
  readonly data: Uint8Array
  readonly noApplication: boolean
}

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text)
const ok = (stdout = ''): SecurityResult => ({ status: 0, stdout: bytes(stdout), stderr: new Uint8Array() })
const status = (n: number, stderr = ''): SecurityResult => ({
  status: n,
  stdout: new Uint8Array(),
  stderr: bytes(stderr),
})

/** The fake: `run` is a SecurityRunner; `next` answers the next calls before the fake's own behaviour. */
export class FakeSecurity {
  readonly calls: Call[] = []
  readonly items = new Map<string, Item>()
  readonly next: (SecurityResult | Error)[] = []
  /** The stdout buffers the fake gave to find -w, to see that the custody zeroed them. */
  readonly given: Uint8Array[] = []

  readonly run: SecurityRunner = (args, input) => {
    this.calls.push({ args: [...args], input: input === undefined ? null : new TextDecoder().decode(input) })
    const queued = this.next.shift()
    if (queued instanceof Error) throw queued
    if (queued !== undefined) return queued
    if (args[0] === '-i') return this.#line(words(new TextDecoder().decode(input)))
    return this.#command([...args])
  }

  /** The item's key in the store: its keychain (`default` for none), service and account. */
  static key(keychain: string | null, service: string, account: string): string {
    return `${keychain ?? 'default'}|${service}|${account}`
  }

  #line(w: string[]): SecurityResult {
    if (w[0] !== 'add-generic-password') return status(2, `unknown command ${w[0]}`)
    let service = ''
    let account = ''
    let hex = ''
    let noApplication = false
    let update = false
    const rest: string[] = []
    for (let i = 1; i < w.length; i++) {
      const word = w[i] as string
      if (word === '-s') service = w[++i] as string
      else if (word === '-a') account = w[++i] as string
      else if (word === '-X') hex = w[++i] as string
      else if (word === '-T') noApplication = w[++i] === ''
      else if (word === '-U') update = true
      else rest.push(word)
    }
    const key = FakeSecurity.key(rest[0] ?? null, service, account)
    if (this.items.has(key) && !update)
      return status(45, 'The specified item already exists in the keychain.')
    const kept = update ? this.items.get(key)?.noApplication : undefined // an update keeps the item's access
    this.items.set(key, {
      data: Uint8Array.from(Buffer.from(hex, 'hex')),
      noApplication: kept ?? noApplication,
    })
    return ok()
  }

  #command(args: string[]): SecurityResult {
    if (args[0] !== 'find-generic-password') return status(2, 'unknown command')
    const at = (flag: string): string => args[args.indexOf(flag) + 1] as string
    const keychain = args.at(-1) === '-w' ? null : (args.at(-1) as string)
    const item = this.items.get(FakeSecurity.key(keychain, at('-s'), at('-a')))
    if (item === undefined) return status(44, 'The specified item could not be found in the keychain.')
    const out = Uint8Array.from([...item.data, 0x0a])
    this.given.push(out)
    return { status: 0, stdout: out, stderr: new Uint8Array() }
  }
}

/** The text forms a 32-byte secret could take: hex, upper hex, base64, base64url, decimal lists. */
export function forms(secret: Uint8Array): string[] {
  const b = Buffer.from(secret)
  return [
    b.toString('hex'),
    b.toString('hex').toUpperCase(),
    b.toString('base64'),
    b.toString('base64url'),
    [...b].join(', '),
    [...b].join(','),
  ]
}

/** Occurrences of any needle in a text: a count, never the text, so a failure prints no secret. */
export function occurrences(text: string, needles: readonly string[]): number {
  let n = 0
  for (const needle of needles) {
    for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) n++
  }
  return n
}
