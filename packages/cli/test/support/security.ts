import type { SecurityResult, SecurityRunner } from '@usebag/edge'

// A fake /usr/bin/security for the CLI's tests: items in memory, written by a `security -i` line and read
// by find-generic-password -w, as the real one answers (L0), every call recorded; and the secret detector.

export interface Call {
  readonly args: readonly string[]
  readonly input: string | null
}

const text = (s: string): Uint8Array => new TextEncoder().encode(s)
const status = (n: number): SecurityResult => ({
  status: n,
  stdout: new Uint8Array(),
  stderr: new Uint8Array(),
})

export class FakeSecurity {
  readonly calls: Call[] = []
  readonly items = new Map<string, Uint8Array>()

  readonly run: SecurityRunner = (args, input) => {
    const line = input === undefined ? null : new TextDecoder().decode(input)
    this.calls.push({ args: [...args], input: line })
    if (args[0] === '-i') {
      const w = [...(line ?? '').trim().matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? (m[2] as string))
      const at = (flag: string): string => w[w.indexOf(flag) + 1] as string
      const key = `${at('-s')} ${at('-a')}`
      if (this.items.has(key) && !w.includes('-U')) return status(45)
      this.items.set(key, Uint8Array.from(Buffer.from(at('-X'), 'hex')))
      return status(0)
    }
    const at = (flag: string): string => args[args.indexOf(flag) + 1] as string
    const item = this.items.get(`${at('-s')} ${at('-a')}`)
    if (item === undefined) return status(44)
    return { status: 0, stdout: Uint8Array.from([...item, ...text('\n')]), stderr: new Uint8Array() }
  }

  /** The seeds of every item, as the key text holds them in hex. */
  seeds(): Uint8Array[] {
    return [...this.items.values()].flatMap((data) => {
      const o = JSON.parse(new TextDecoder().decode(data)) as { sign_seed: string; seal_priv: string }
      return [Buffer.from(o.sign_seed, 'hex'), Buffer.from(o.seal_priv, 'hex')]
    })
  }
}

/** The text forms of a 32-byte secret. */
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

/** Occurrences of any needle in a text: a count, never the text. */
export function occurrences(haystack: string, needles: readonly string[]): number {
  let n = 0
  for (const needle of needles) {
    for (let i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) n++
  }
  return n
}
