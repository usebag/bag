import {
  existsSync,
  lstatSync,
  readFileSync,
  readlinkSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { applyChange, backup, pathState, restore, stateAfter, View } from '../src/index.ts'
import { folder } from './support.ts'

// One change to one path of a host's wiring: the view that works the changes out before anything is written, and the
// write, backup and restore of each path.

describe('View', () => {
  it('reads a file as the edits leave it, lists only what differs from the disk, and records each path it read', () => {
    const dir = folder()
    const [a, b] = [join(dir, 'a.json'), join(dir, 'b.json')]
    writeFileSync(b, '{"x":1}')
    const view = new View()
    expect(view.text(a)).toBeNull()
    view.json(a, 'a: x', (d) => {
      d.x = 1
      return true
    })
    view.json(b, 'b: nothing', () => false)
    expect(view.text(a)).toBe('{\n  "x": 1\n}\n')
    expect(view.changes().map((c) => c.path)).toEqual([a])
    expect([...view.read].sort()).toEqual([a, b].sort())
    view.set({ path: a, text: '{}\n', note: 'a: again' })
    expect(view.changes()[0]?.note).toBe('a: x; a: again')
    view.set({ path: b, text: '{"x":1}', note: 'b: the same bytes' })
    expect(view.changes().map((c) => c.path)).toEqual([a])
  })

  it('refuses a file that is not a JSON object, host-file-invalid, and reads a link or a gone path as null', () => {
    const dir = folder()
    const bad = join(dir, 'bad.json')
    writeFileSync(bad, '[1]')
    const view = new View()
    expect(() => view.json(bad, '', () => true)).toThrow(`host-file-invalid: ${bad} is not a JSON object`)
    writeFileSync(bad, 'not json')
    expect(() => view.json(bad, '', () => true)).toThrow('host-file-invalid')
    const link = join(dir, 'l')
    view.set({ path: link, link: '/x', note: '' })
    expect(view.text(link)).toBeNull()
    view.set({ path: bad, gone: true, note: '' })
    expect(view.text(bad)).toBeNull()
    expect(view.changes().map((c) => c.path)).toEqual([link, bad])
  })
})

describe('applyChange, backup and restore', () => {
  it('writes a text with its mode, keeps the mode of a file there, makes a link and removes a path', () => {
    const dir = folder()
    const [file, kept, link] = [join(dir, 'sub', 'f'), join(dir, 'k'), join(dir, 'link')]
    applyChange({ path: file, text: 'one', mode: 0o640, note: '' }, 7)
    expect(readFileSync(file, 'utf8')).toBe('one')
    expect(statSync(file).mode & 0o777).toBe(0o640)
    writeFileSync(kept, 'x', { mode: 0o644 })
    applyChange({ path: kept, text: 'y', note: '' }, 7)
    expect(statSync(kept).mode & 0o777).toBe(0o644)
    applyChange({ path: link, link: '/somewhere', note: '' }, 7)
    expect(readlinkSync(link)).toBe('/somewhere')
    expect(pathState(link)).toBe(stateAfter({ path: link, link: '/somewhere', note: '' }))
    expect(pathState(file)).toBe(stateAfter({ path: file, text: 'one', note: '' }))
    applyChange({ path: link, gone: true, note: '' }, 7)
    applyChange({ path: link, gone: true, note: '' }, 7)
    expect(existsSync(link)).toBe(false)
    expect(pathState(link)).toBe('absent')
    expect(stateAfter({ path: link, gone: true, note: '' })).toBe('absent')
    expect(existsSync(`${file}.7.tmp`)).toBe(false)
  })

  it('backs up a file, a link or nothing, and puts each back as it was', () => {
    const dir = folder()
    const store = join(dir, 'backup')
    const [file, link, none] = [join(dir, 'f'), join(dir, 'l'), join(dir, 'n')]
    writeFileSync(file, 'before', { mode: 0o600 })
    symlinkSync('/target', link)
    const [f, l, n] = [backup(file, store, 0), backup(link, store, 1), backup(none, store, 2)]
    expect(f).toEqual({ kind: 'file', backup: join(store, '0-f'), mode: 0o600 })
    expect(l).toEqual({ kind: 'link', target: '/target' })
    expect(n).toEqual({ kind: 'absent' })
    applyChange({ path: file, text: 'after', note: '' }, 9)
    applyChange({ path: link, link: '/other', note: '' }, 9)
    writeFileSync(none, 'new')
    restore(file, f, 9)
    restore(link, l, 9)
    restore(none, n, 9)
    expect(readFileSync(file, 'utf8')).toBe('before')
    expect(readlinkSync(link)).toBe('/target')
    expect(() => lstatSync(none)).toThrow()
  })
})

describe('a change with no text, and a path that is no file', () => {
  it('writes and names an empty file for a change without text; a folder or a link on disk reads as no text', () => {
    const dir = folder()
    const file = join(dir, 'empty')
    const c = { path: file, note: 'empty' }
    expect(stateAfter(c)).toBe(stateAfter({ path: file, text: '', note: '' }))
    applyChange(c, 3)
    expect(readFileSync(file, 'utf8')).toBe('')
    expect(pathState(file)).toBe(stateAfter(c))
    const view = new View()
    const other = join(dir, 'other')
    view.set({ path: other, note: 'no text' })
    expect(view.text(other)).toBe('')
    expect(view.text(dir)).toBeNull()
    const link = join(dir, 'link')
    symlinkSync(file, link)
    expect(view.text(link)).toBeNull()
  })
})
