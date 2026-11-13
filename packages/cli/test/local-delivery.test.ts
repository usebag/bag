import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { dropLocalPairs, LOCAL_DELIVERY_DEFAULT, pairedLocally, readWord } from '../src/commands/local.ts'
import { tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli } from './support/run.ts'

// bag local-delivery on|off (spec/SPEC.md 9.2, M5): the home word, written only by this command on a terminal after
// one y, and nothing else; and unpair of an own identity paired locally, which drops the pair and calls no relay (M6).

const tmp = tempDir('local-delivery')
afterAll(() => tmp.cleanup())
let n = 0

function world(answers: boolean[], tty = true) {
  const net = new Network()
  const io = testIo(net)
  io.tty = tty
  io.answers.push(...answers)
  const dir = join(tmp.dir, `h${n++}`)
  mkdirSync(dir, { recursive: true })
  return { net, io, dir }
}

describe('local-delivery on|off', () => {
  it('asks y on a terminal, then writes only run/local.json, 0600 in a 0700 run directory', async () => {
    const w = world([true, true])
    const on = await cli(w.io, 'local-delivery', 'on', '--dir', w.dir)
    expect([on.code, on.out]).toEqual([0, [`local_delivery on: ${join(w.dir, 'run', 'local.json')}`]])
    expect(w.io.asked[0]).toContain('and any identity you add later, find and')
    expect(w.io.asked[0]).toContain('never go to a relay')
    expect(w.io.asked[0]).toContain('On Codex and omp a command your agent runs can')
    expect(JSON.parse(readFileSync(join(w.dir, 'run', 'local.json'), 'utf8'))).toEqual({
      version: 2,
      local_delivery: 'on',
      hidden: [],
    })
    expect(statSync(join(w.dir, 'run', 'local.json')).mode & 0o777).toBe(0o600)
    expect(statSync(join(w.dir, 'run')).mode & 0o777).toBe(0o700)
    expect(readdirSync(w.dir)).toEqual(['run'])
    expect(readdirSync(join(w.dir, 'run'))).toEqual(['local.json'])
    // off is the brake: no question, and no terminal needed.
    const asked = w.io.asked.length
    w.io.tty = false
    const off = await cli(w.io, 'local-delivery', 'off', '--dir', w.dir)
    expect(off.code).toBe(0)
    expect(w.io.asked.length).toBe(asked)
    expect(JSON.parse(readFileSync(join(w.dir, 'run', 'local.json'), 'utf8')).local_delivery).toBe('off')
  })

  it('hide at once with no question, keeping the word; show only after a y on a terminal', async () => {
    const w = world([true])
    const file = join(w.dir, 'run', 'local.json')
    w.io.tty = false
    const hide = await cli(w.io, 'local-delivery', 'hide', 'research', '--dir', w.dir)
    expect([hide.code, hide.out, w.io.asked]).toEqual([0, [`hidden research: ${file}`], []])
    // No file before: the default (on) is kept, with research hidden.
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({
      version: 2,
      local_delivery: 'on',
      hidden: ['research'],
    })
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect((await cli(w.io, 'local-delivery', 'show', 'research', '--dir', w.dir)).err[0]).toContain('no-tty')
    w.io.tty = true
    const show = await cli(w.io, 'local-delivery', 'show', 'research', '--dir', w.dir)
    expect([show.code, show.out]).toEqual([0, [`shown research: ${file}`]])
    expect(w.io.asked).toEqual([
      "show research to this home's other identities again? They can then message it on this machine.",
    ])
    expect(JSON.parse(readFileSync(file, 'utf8')).hidden).toEqual([])
    expect((await cli(w.io, 'local-delivery', 'hide', '--dir', w.dir)).err[0]).toContain('bag: usage:')
  })

  it('without a terminal is no-tty and writes nothing; a no is declined; another word is usage', async () => {
    const quiet = world([true], false)
    const r = await cli(quiet.io, 'local-delivery', 'on', '--dir', quiet.dir)
    expect(r.code).toBe(1)
    expect(r.err[0]).toContain('bag: no-tty:')
    expect(existsSync(join(quiet.dir, 'run'))).toBe(false)
    const no = world([false])
    expect((await cli(no.io, 'local-delivery', 'on', '--dir', no.dir)).err[0]).toContain('bag: declined:')
    expect(existsSync(join(no.dir, 'run', 'local.json'))).toBe(false)
    const bad = world([true])
    expect((await cli(bad.io, 'local-delivery', 'yes', '--dir', bad.dir)).err[0]).toContain('bag: usage:')
  })
})

describe('the word as read (falsifier GAP 3)', () => {
  it('reads as the bag service does: absent the default; a broken, linked or open file off, with why', () => {
    const { dir } = world([])
    const file = join(dir, 'run', 'local.json')
    expect(readWord(dir)).toEqual({ on: LOCAL_DELIVERY_DEFAULT, hidden: [], why: null })
    mkdirSync(join(dir, 'run'), { mode: 0o700 })
    writeFileSync(file, '{"version":2,"local_delivery":"on","hidden":["x"]}', { mode: 0o600 })
    expect(readWord(dir)).toEqual({ on: true, hidden: ['x'], why: null })
    for (const text of ['{not json', '{"version":3,"local_delivery":"on"}']) {
      writeFileSync(file, text, { mode: 0o600 })
      expect(readWord(dir)).toEqual({ on: false, hidden: [], why: 'run/local.json does not read' })
    }
    writeFileSync(file, '{"version":1,"local_delivery":"on"}', { mode: 0o600 })
    chmodSync(file, 0o644)
    const loose = 'run/local.json is not a 0600 regular file of this user'
    expect(readWord(dir)).toEqual({ on: false, hidden: [], why: loose })
    writeFileSync(join(dir, 'real.json'), '{"version":1,"local_delivery":"on"}', { mode: 0o600 })
    rmSync(file)
    symlinkSync(join(dir, 'real.json'), file)
    expect(readWord(dir)).toEqual({ on: false, hidden: [], why: loose })
  })

  it("the CLI's LOCAL_DELIVERY_DEFAULT is the bag service's (read as text: check-imports keeps cli off mcp)", () => {
    const text = readFileSync(fileURLToPath(new URL('../../mcp/src/local.ts', import.meta.url)), 'utf8')
    const theirs = /^export const LOCAL_DELIVERY_DEFAULT = (true|false)$/m.exec(text)?.[1]
    expect(theirs).toBe(String(LOCAL_DELIVERY_DEFAULT))
  })
})

describe('keygen with the word on (C4)', () => {
  it('says the new identity is visible and how to keep it apart; with the word off, nothing', async () => {
    const w = world([], false)
    // A bag service home: install/<name>.env names its relay, so keygen adds the identity to identities.json.
    mkdirSync(join(w.dir, 'install'), { recursive: true, mode: 0o700 })
    for (const n of ['research', 'side'])
      writeFileSync(join(w.dir, 'install', `${n}.env`), `NAME="${n}"\nRELAYS="https://relay.test"\n`)
    const keygen = (n: string) => cli(w.io, 'keygen', n, '--custody', 'file', '--dir', w.dir)
    const r = await keygen('research')
    expect(r.err).toContain(
      'research is visible to your other identities on this machine; to keep it apart: ' +
        'bag local-delivery hide research',
    )
    await cli(w.io, 'local-delivery', 'off', '--dir', w.dir)
    const off = await keygen('side')
    expect(off.err.join('\n')).toContain('added side')
    expect(off.err.join('\n')).not.toContain('is visible')
  })
})

describe('unpair of an own identity paired locally', () => {
  it('drops that pair from run/local-peers.json after one y and calls no relay', async () => {
    const w = world([true])
    const key = async (name: string) => (await cli(w.io, 'keygen', name, '--dir', w.dir)).out[0] as string
    const [a, b, c] = [await key('a'), await key('b'), await key('c')]
    mkdirSync(join(w.dir, 'run'), { recursive: true })
    const pair = (x: string, y: string, xa: string, ya: string) => ({
      a: x,
      b: y,
      a_addr: xa,
      b_addr: ya,
      added_at: 1,
      state: 'allowed',
    })
    const table = { version: 1, pairs: [pair('a', 'b', a, b), pair('c', 'a', c, a)] }
    writeFileSync(join(w.dir, 'run', 'local-peers.json'), JSON.stringify(table), { mode: 0o600 })
    const r = await cli(w.io, 'unpair', b, '--as', 'a', '--relay', 'http://127.0.0.1:1', '--dir', w.dir)
    expect([r.code, r.out, r.err]).toEqual([0, [`unpaired locally ${b}`], []])
    expect(w.io.asked).toEqual([`unpair a and ${b} on this machine (run/local-peers.json)?`])
    expect(JSON.parse(readFileSync(join(w.dir, 'run', 'local-peers.json'), 'utf8')).pairs).toEqual([
      pair('c', 'a', c, a),
    ])
    expect([w.net.relays.size, w.net.log]).toEqual([0, []])
  })
})

describe('identity remove', () => {
  it('drops every local pair of the identity, and its spool leaves with state/<name> (M6)', async () => {
    const w = world([true])
    const key = async (name: string) => (await cli(w.io, 'keygen', name, '--dir', w.dir)).out[0] as string
    const [a, b] = [await key('a'), await key('b')]
    mkdirSync(join(w.dir, 'run'), { recursive: true })
    mkdirSync(join(w.dir, 'state', 'a', 'local-spool'), { recursive: true })
    writeFileSync(join(w.dir, 'state', 'a', 'local-spool', `${'c'.repeat(64)}.env`), 'x')
    const row = { a: 'a', b: 'b', a_addr: a, b_addr: b, added_at: 1, state: 'allowed' }
    const table = { version: 1, pairs: [row] }
    writeFileSync(join(w.dir, 'run', 'local-peers.json'), JSON.stringify(table), { mode: 0o600 })
    const to = join(w.dir, '..', `left-${n}`)
    const r = await cli(
      w.io,
      'identity',
      'remove',
      'a',
      '--relay',
      'http://127.0.0.1:1',
      '--to',
      to,
      '--dir',
      w.dir,
    )
    expect(r.code, r.err.join('\n')).toBe(0)
    expect(w.io.asked[0]).toContain('run/local-peers.json: its local pairs leave')
    expect(r.out).toContain('dropped the local pairs of a')
    expect(JSON.parse(readFileSync(join(w.dir, 'run', 'local-peers.json'), 'utf8')).pairs).toEqual([])
    expect(existsSync(join(w.dir, 'state', 'a'))).toBe(false)
  })
})

describe('a refused local pair table (q3)', () => {
  /** A home with identities a and b and a table holding their pair, written `how`. */
  async function refused(how: '0644' | 'a symlink') {
    const w = world([true, true])
    const key = async (name: string) => (await cli(w.io, 'keygen', name, '--dir', w.dir)).out[0] as string
    const [a, b] = [await key('a'), await key('b')]
    mkdirSync(join(w.dir, 'run'), { recursive: true, mode: 0o700 })
    const text = `${JSON.stringify({ version: 1, pairs: [{ a: 'a', b: 'b', a_addr: a, b_addr: b, added_at: 1, state: 'allowed' }] })}\n`
    const file = join(w.dir, 'run', 'local-peers.json')
    if (how === '0644') writeFileSync(file, text, { mode: 0o644 })
    else {
      writeFileSync(join(w.dir, 'run', 'elsewhere.json'), text, { mode: 0o600 })
      symlinkSync(join(w.dir, 'run', 'elsewhere.json'), file)
    }
    return { w, a, b, file, text }
  }

  for (const how of ['0644', 'a symlink'] as const) {
    it(`as ${how}: unpair of an own identity says it is refused and how to fix it, and changes nothing`, async () => {
      const { w, b, file, text } = await refused(how)
      const r = await cli(w.io, 'unpair', b, '--as', 'a', '--relay', 'http://127.0.0.1:1', '--dir', w.dir)
      expect(r.code).not.toBe(0)
      expect(r.err.join('\n')).toContain('run/local-peers.json is not a 0600 regular file of this user')
      expect(r.err.join('\n')).toContain(`chmod 600 ${file}`)
      expect(readFileSync(file, 'utf8')).toBe(text)
      expect(lstatSync(file).isSymbolicLink()).toBe(how === 'a symlink')
      expect([w.net.relays.size, w.net.log]).toEqual([0, []])
    })

    it(`as ${how}: identity remove says it is refused and changes nothing`, async () => {
      const { w, file, text } = await refused(how)
      const to = join(w.dir, '..', `refused-${n++}`)
      const r = await cli(
        w.io,
        'identity',
        'remove',
        'a',
        '--relay',
        'http://127.0.0.1:1',
        '--to',
        to,
        '--dir',
        w.dir,
      )
      expect(r.code).not.toBe(0)
      expect(r.err.join('\n')).toContain('run/local-peers.json is not a 0600 regular file of this user')
      expect(readFileSync(file, 'utf8')).toBe(text)
      expect(existsSync(join(w.dir, 'keys', 'a.json'))).toBe(true)
      expect(existsSync(to)).toBe(false)
    })
  }

  it('a null or malformed entry in the table is skipped by pairedLocally and dropLocalPairs, never a throw (s3)', async () => {
    const w = world([])
    const key = async (name: string) => (await cli(w.io, 'keygen', name, '--dir', w.dir)).out[0] as string
    const [a, b] = [await key('a'), await key('b')]
    mkdirSync(join(w.dir, 'run'), { recursive: true, mode: 0o700 })
    const ab = { a: 'a', b: 'b', a_addr: a, b_addr: b, added_at: 1, state: 'allowed' }
    const file = join(w.dir, 'run', 'local-peers.json')
    writeFileSync(file, JSON.stringify({ version: 1, pairs: [null, 7, { a: 'x' }, ab] }), { mode: 0o600 })
    expect(pairedLocally(w.dir, a, b)).toBe(true)
    expect(pairedLocally(w.dir, b, 'ed25519:00')).toBe(false)
    expect(dropLocalPairs(w.dir, (p) => p.a === 'a')).toBe(1)
    expect(JSON.parse(readFileSync(file, 'utf8')).pairs).toEqual([])
  })

  it('pairedLocally and dropLocalPairs never read or rewrite a refused table', async () => {
    const { w, a, b, file, text } = await refused('0644')
    expect(pairedLocally(w.dir, a, b)).toBe(false)
    expect(() => dropLocalPairs(w.dir, () => true)).toThrow('chmod 600')
    expect(readFileSync(file, 'utf8')).toBe(text)
    expect(statSync(file).mode & 0o777).toBe(0o644)
  })

  it('an unpair writes every surviving row back byte for byte as the service wrote it', async () => {
    const w = world([true])
    const key = async (name: string) => (await cli(w.io, 'keygen', name, '--dir', w.dir)).out[0] as string
    const [a, b, c] = [await key('a'), await key('b'), await key('c')]
    mkdirSync(join(w.dir, 'run'), { recursive: true, mode: 0o700 })
    // Rows in the service's own shape and key order, one with the requested fields after it.
    const ab = { a: 'a', b: 'b', a_addr: a, b_addr: b, added_at: 1, state: 'allowed' }
    const ca = {
      a: 'c',
      b: 'a',
      a_addr: c,
      b_addr: a,
      added_at: 2,
      state: 'requested',
      at: 2,
      held: ['f'.repeat(64)],
    }
    const file = join(w.dir, 'run', 'local-peers.json')
    writeFileSync(file, `${JSON.stringify({ version: 1, pairs: [ab, ca] })}\n`, { mode: 0o600 })
    const r = await cli(w.io, 'unpair', b, '--as', 'a', '--relay', 'http://127.0.0.1:1', '--dir', w.dir)
    expect(r.code, r.err.join('\n')).toBe(0)
    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify({ version: 1, pairs: [ca] })}\n`)
    expect(statSync(file).mode & 0o777).toBe(0o600)
  })
})
