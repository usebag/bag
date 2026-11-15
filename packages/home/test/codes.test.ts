import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

// Every code a home act throws is one the command line already reports, so telemetry's closed set of codes (the cli
// family counts each command by its code) does not move: a code in that set, or one of the command line's own codes
// that the set leaves out, which telemetry counts as other. Read as text, since this package imports no telemetry.

const SRC = fileURLToPath(new URL('../src/', import.meta.url))
const SCHEMA = fileURLToPath(new URL('../../edge/src/telemetry-schema.ts', import.meta.url))

/** The command line's codes before these acts moved here that telemetry's set leaves out (counted as other). */
const CLI_ONLY = [
  'EEXIST',
  'ENOENT',
  'EXDEV',
  'accept-all',
  'held',
  'identities-in-project',
  'last-identity',
  'not-trusted',
]

/** The codes not written in the source: another error's code, carried on (a relay's, or a key read's own). */
const CARRIED = ['code', 'failed(e)']

function telemetryCodes(): Set<string> {
  const text = readFileSync(SCHEMA, 'utf8')
  const block = /\bcode: words\(`([^`]*)`\)/.exec(text)?.[1]
  if (block === undefined) throw new Error('no code set in telemetry-schema.ts')
  return new Set(block.split(/\s+/).filter(Boolean))
}

function thrown(): { file: string; code: string }[] {
  return readdirSync(SRC)
    .filter((f) => f.endsWith('.ts'))
    .flatMap((file) =>
      [...readFileSync(`${SRC}${file}`, 'utf8').matchAll(/new HomeError\(\s*([^,]+),/g)].map((m) => ({
        file,
        code: (m[1] as string).trim(),
      })),
    )
}

describe('the codes of a HomeError', () => {
  it('are read from the source: every act module throws some', () => {
    const files = new Set(thrown().map((t) => t.file))
    for (const f of [
      'custody.ts',
      'identity.ts',
      'keygen.ts',
      'unpair.ts',
      'local.ts',
      'identities.ts',
      'ports.ts',
      'changes.ts',
      'host-common.ts',
      'host-install.ts',
      'host-migrate.ts',
      'host-user.ts',
      'stage.ts',
    ])
      expect(files).toContain(f)
  })

  it("are each a code of telemetry's set or one the command line reported already; carried codes stay carried", () => {
    const set = telemetryCodes()
    expect(set.has('ok')).toBe(true)
    for (const c of CLI_ONLY) expect(set.has(c), c).toBe(false)
    for (const { file, code } of thrown()) {
      if (code.startsWith("'")) {
        const word = code.slice(1, -1)
        expect(set.has(word) || CLI_ONLY.includes(word), `${file}: ${word}`).toBe(true)
      } else expect(CARRIED, `${file}: ${code}`).toContain(code)
    }
  })
})
