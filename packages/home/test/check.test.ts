import { chmodSync, mkdirSync, renameSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  askWithRecheck,
  CHANGED_WHILE_ASKED,
  changedWhileAsked,
  HomeError,
  namedStates,
  shortName,
  stateOf,
  statesOf,
} from '../src/index.ts'
import { fakeIo, folder } from './support.ts'

// The check an act makes around its question: what it read, as a plain value, compared after the yes.

describe('stateOf', () => {
  it('is null for a path that is not there, and the error code for one that cannot be read', () => {
    const d = folder()
    expect(stateOf(join(d, 'none'))).toBeNull()
    writeFileSync(join(d, 'f'), 'x')
    expect(stateOf(join(d, 'f', 'under'))).toEqual({ error: 'ENOTDIR' })
  })

  it('changes when a file is written, renamed over or re-moded, and lists a folder sorted', () => {
    const d = folder()
    const f = join(d, 'f')
    writeFileSync(f, 'one')
    const first = stateOf(f)
    expect(stateOf(f)).toEqual(first)
    writeFileSync(f, 'longer')
    expect(stateOf(f)).not.toEqual(first)
    const second = stateOf(f)
    writeFileSync(join(d, 'g'), 'longer')
    renameSync(join(d, 'g'), f)
    expect(stateOf(f)).not.toEqual(second)
    const third = stateOf(f)
    chmodSync(f, 0o600)
    chmodSync(f, 0o640)
    expect(stateOf(f)).not.toEqual(third)
    mkdirSync(join(d, 'sub'))
    writeFileSync(join(d, 'sub', 'b'), '')
    writeFileSync(join(d, 'sub', 'a'), '')
    expect(stateOf(join(d, 'sub'))).toEqual({ dir: ['a', 'b'] })
    expect(statesOf([join(d, 'none'), join(d, 'sub')])).toEqual([null, { dir: ['a', 'b'] }])
  })
})

describe('askWithRecheck', () => {
  it('a yes with nothing changed is true; a no is false', async () => {
    let reads = 0
    const check = () => {
      reads++
      return { 'trust.json': 'same' }
    }
    expect(await askWithRecheck(fakeIo({ answer: true }), 'go?', check)).toBe(true)
    expect(reads).toBe(2)
    expect(await askWithRecheck(fakeIo({ answer: false }), 'go?', check)).toBe(false)
    expect(reads).toBe(3)
  })

  it('a dialog that fails is its own error; a change while asked is busy, naming exactly what changed', async () => {
    await expect(askWithRecheck(fakeIo({ answer: 'throw' }), 'go?', () => ({}))).rejects.toThrow(
      'the dialog failed',
    )
    let n = 0
    const check = () => ({
      'trust.json': 1,
      holder: null,
      'run/local-peers.json': n++,
      'keys/jane.json': n > 1,
    })
    await expect(askWithRecheck(fakeIo({ answer: true }), 'go?', check)).rejects.toThrow(
      'busy: it changed while you were asked: keys/jane.json, run/local-peers.json; nothing was changed, ask again',
    )
    let first = true
    const gone = (): Record<string, unknown> => {
      if (!first) return {}
      first = false
      return { service: true }
    }
    await expect(askWithRecheck(fakeIo({ answer: true }), 'go?', gone)).rejects.toThrow(
      new HomeError('busy', changedWhileAsked(['service'])).message,
    )
    expect(changedWhileAsked(['b', 'a'])).toBe(`${CHANGED_WHILE_ASKED}: a, b; nothing was changed, ask again`)
  })
})

describe('shortName and namedStates', () => {
  it("names a path relative to the home, under ~/ in the person's home, else whole", () => {
    expect(shortName('/h/home/trust.json', '/h/home', '/h')).toBe('trust.json')
    expect(shortName('/h/.codex/config.toml', '/h/home', '/h')).toBe('~/.codex/config.toml')
    expect(shortName('/elsewhere/x', '/h/home', '/h')).toBe('/elsewhere/x')
    expect(shortName('/h/x', '/h/home')).toBe('/h/x')
    expect(shortName('/h/home', '/h/home', '/h')).toBe('~/home')
    const d = folder()
    expect(namedStates(d, undefined, [join(d, 'none')])).toEqual({ none: null })
  })
})

describe('stateOf of a link, and of a chmod that keeps size and mtime', () => {
  it('a link is itself and what it points to: a rewritten target differs, a dangling one says so', () => {
    const d = folder()
    const target = join(d, 'target')
    writeFileSync(target, 'one')
    symlinkSync(target, join(d, 'link'))
    const first = stateOf(join(d, 'link')) as { link: string; target: unknown }
    expect(first.link).toBe(target)
    writeFileSync(target, 'two two')
    expect(stateOf(join(d, 'link'))).not.toEqual(first)
    symlinkSync(join(d, 'none'), join(d, 'dangling'))
    expect((stateOf(join(d, 'dangling')) as { target: unknown }).target).toBe('dangling')
  })

  it('a chmod to the same mode with the mtime put back still differs, by its ctime', async () => {
    const d = folder()
    const f = join(d, 'f')
    writeFileSync(f, 'same', { mode: 0o600 })
    const { atime, mtime } = statSync(f)
    const before = stateOf(f)
    await new Promise((done) => setTimeout(done, 20))
    chmodSync(f, 0o600)
    utimesSync(f, atime, mtime)
    expect(stateOf(f)).not.toEqual(before)
  })
})
