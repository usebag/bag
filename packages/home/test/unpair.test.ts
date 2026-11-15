import { existsSync, readFileSync, renameSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { generateEdgeKeys, keepAcceptCopy, RelayError, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  addTrust,
  failed,
  heldBy,
  ownAddresses,
  peersPath,
  readTrust,
  unpairRoot,
  writeWhole,
} from '../src/index.ts'
import { type Answer, acceptFrom, FakeRelay, fakeIo, homeWith, publishAt, signer } from './support.ts'

// unpair: a pairing ended after one yes, in trust.json and the accept-from at each relay, or in the local table.

const R1 = 'https://r1.example'
const R2 = 'https://r2.example'
const bob = generateEdgeKeys(systemRng).signing.address
const carol = generateEdgeKeys(systemRng).signing.address

/** jane's home with bob trusted and jane's accept-from naming `roots` at R1 and R2. */
async function world(roots: string[] = [bob, carol], answer: Answer = true) {
  const { home, keys } = homeWith('jane', 'kim')
  const jane = keys.jane?.signing.address as string
  const net = new FakeRelay()
  addTrust(home, bob, 1)
  if (roots.length > 0) await publishAt(net, acceptFrom(signer(keys, 'jane'), roots, 100), R1, R2)
  const io = fakeIo({ answer, relay: net })
  const run = (root = bob, relays = [R1, R2]) => unpairRoot(io, { home, as: 'jane', root, relays })
  return { home, keys, jane, net, io, run }
}

describe('unpairRoot at the relays', () => {
  it('after the yes: untrusted, then the accept-from without the root at every relay, and the home copy', async () => {
    const w = await world()
    await w.run()
    expect(w.io.asked).toEqual([
      `unpair ${bob} from jane (${w.jane}): remove it from ${w.home}/trust.json and the accept-from at ${R1} ${R2}?`,
    ])
    expect(w.io.said).toEqual([
      `untrusted ${bob}`,
      `published accept-from ${w.jane} ${R1}`,
      `published accept-from ${w.jane} ${R2}`,
    ])
    expect(readTrust(w.home)).toEqual({})
    expect([w.net.rootsAt(R1, w.jane), w.net.rootsAt(R2, w.jane)]).toEqual([[carol], [carol]])
    expect(existsSync(join(w.home, 'records', 'jane.accept.json'))).toBe(true)
  })

  it('a no, a dialog that fails, or a file changed while asked writes nothing', async () => {
    for (const [answer, err] of [
      [false, 'declined: nothing was changed'],
      ['throw', 'the dialog failed'],
    ] as const) {
      const w = await world([bob, carol], answer)
      const published = w.net.published.length
      await expect(w.run()).rejects.toThrow(err)
      expect(readTrust(w.home)).toEqual({ [bob]: { added_at: 1 } })
      expect(w.net.published).toHaveLength(published)
    }
    let home = ''
    const w = await world([bob, carol], () => {
      addTrust(home, carol, 2)
      return true
    })
    home = w.home
    const published = w.net.published.length
    await expect(w.run()).rejects.toThrow(
      'busy: it changed while you were asked: trust.json; nothing was changed, ask again',
    )
    expect(Object.keys(readTrust(w.home)).sort()).toEqual([bob, carol].sort())
    expect(w.net.published).toHaveLength(published)
  })

  it('a trust.json that is a link: its target rewritten while asked is busy, naming trust.json', async () => {
    let target = ''
    const w = await world([bob, carol], () => {
      writeFileSync(target, `${readFileSync(target, 'utf8')} `)
      return true
    })
    target = join(dirname(w.home), 'trust-target.json')
    renameSync(join(w.home, 'trust.json'), target)
    symlinkSync(target, join(w.home, 'trust.json'))
    const published = w.net.published.length
    await expect(w.run()).rejects.toThrow(
      'busy: it changed while you were asked: trust.json; nothing was changed',
    )
    expect(w.net.published).toHaveLength(published)
  })

  it('a record published while asked is stale-record, nothing written', async () => {
    let w: Awaited<ReturnType<typeof world>> | null = null
    w = await world([bob, carol], async () => {
      const own = w as Awaited<ReturnType<typeof world>>
      await publishAt(own.net, acceptFrom(signer(own.keys, 'jane'), [bob], 200), R1)
      return true
    })
    await expect(w.run()).rejects.toThrow(`stale-record: the accept-from of ${w.jane} changed while asking`)
    expect(readTrust(w.home)).toEqual({ [bob]: { added_at: 1 } })
  })

  it('refuses before the question: its own address (usage), accept-all, a root nowhere, every relay silent', async () => {
    const w = await world()
    await expect(w.run(w.jane)).rejects.toThrow(`usage: ${w.jane} is jane itself`)
    const all = await world(['*'])
    await expect(all.run()).rejects.toThrow(`accept-all: the accept-from of ${all.jane} is *`)
    const none = await world([])
    const stranger = generateEdgeKeys(systemRng).signing.address
    await expect(none.run(stranger)).rejects.toThrow(`not-trusted: ${stranger} is in neither`)
    none.net.down.add(R1)
    await expect(none.run(stranger, [R1])).rejects.toBeInstanceOf(RelayError)
    expect(none.io.asked).toEqual([])
  })

  it('a trusted root no record names: untrusted, not accepted, and a silent relay may still hold it (unreachable)', async () => {
    const w = await world([])
    w.net.down.add(R2)
    await expect(w.run()).rejects.toThrow(`unreachable: ${R2} may still hold ${bob}: run unpair again`)
    expect(w.io.said).toEqual([
      `untrusted ${bob}`,
      `not accepted ${bob}`,
      `failed accept-from ${w.jane} ${R2} unreachable`,
    ])
    const quiet = await world([])
    await quiet.run()
    expect(quiet.io.said).toEqual([`untrusted ${bob}`, `not accepted ${bob}`])
  })

  it('the last root leaves the record naming only its owner; a relay that refuses is said, then thrown', async () => {
    const w = await world([bob])
    w.net.refuse.set(R2, 'stale-record')
    await expect(w.run()).rejects.toThrow(`stale-record: ${R2} did not take the accept-from`)
    expect(w.io.said).toEqual([
      `untrusted ${bob}`,
      `last root: the accept-from of ${w.jane} now names only ${w.jane}, its owner`,
      `published accept-from ${w.jane} ${R1}`,
      `unchanged accept-from ${w.jane} ${R2} stale-record`,
    ])
    expect(w.net.rootsAt(R1, w.jane)).toEqual([w.jane])
  })

  it("keeps a root another identity's copy names, and warns when the home copy cannot be written", async () => {
    const w = await world([bob])
    keepAcceptCopy(w.home, 'kim', acceptFrom(signer(w.keys, 'kim'), [bob], 50))
    await w.run(bob, [R1])
    expect(w.io.asked[0]).toContain(
      `remove it from the accept-from at ${R1}? (it stays in ${w.home}/trust.json for kim)`,
    )
    expect(w.io.said[0]).toBe(`kept trust ${bob}: the accept-from of kim still names it`)
    expect(readTrust(w.home)).toEqual({ [bob]: { added_at: 1 } })
    const v = await world([])
    keepAcceptCopy(v.home, 'kim', acceptFrom(signer(v.keys, 'kim'), [bob], 50))
    await v.run(bob, [R1])
    expect(v.io.asked[0]).toContain('nothing to remove (it stays in')
    expect(v.io.said).toEqual([
      `kept trust ${bob}: the accept-from of kim still names it`,
      `not accepted ${bob}`,
    ])
    const s = await world([bob])
    writeFileSync(join(s.home, 'records'), 'a file where the folder goes')
    await s.run(bob, [R1])
    expect(s.io.warned).toEqual([
      expect.stringContaining(`the home copy ${s.home}/records/jane.accept.json is stale (`),
    ])
  })
})

describe('unpairRoot of an own identity paired locally', () => {
  const local = (answer: Answer = true) => {
    const { home, keys } = homeWith('jane', 'kim')
    const [jane, kim] = [keys.jane?.signing.address as string, keys.kim?.signing.address as string]
    writeWhole(home, peersPath(home), {
      version: 1,
      pairs: [{ a: 'jane', b: 'kim', a_addr: jane, b_addr: kim, added_at: 1 }],
    })
    const io = fakeIo({ answer })
    return { home, jane, kim, io, run: () => unpairRoot(io, { home, as: 'jane', root: kim, relays: [R1] }) }
  }

  it('drops the pair from the table after the yes; no relay is read', async () => {
    const w = local()
    await w.run()
    expect(w.io.asked).toEqual([`unpair jane and ${w.kim} on this machine (run/local-peers.json)?`])
    expect(w.io.said).toEqual([`unpaired locally ${w.kim}`])
    expect(JSON.parse(readFileSync(peersPath(w.home), 'utf8')).pairs).toEqual([])
  })

  it('a no, a failed dialog, or the table changed while asked leaves it as it was', async () => {
    for (const [answer, err] of [
      [false, 'declined'],
      ['throw', 'the dialog failed'],
    ] as const) {
      const w = local(answer)
      const before = readFileSync(peersPath(w.home), 'utf8')
      await expect(w.run()).rejects.toThrow(err)
      expect(readFileSync(peersPath(w.home), 'utf8')).toBe(before)
    }
    let home = ''
    const w = local(() => {
      writeWhole(home, peersPath(home), JSON.parse(readFileSync(peersPath(home), 'utf8')))
      return true
    })
    home = w.home
    await expect(w.run()).rejects.toMatchObject({ code: 'busy' })
    expect(JSON.parse(readFileSync(peersPath(w.home), 'utf8')).pairs).toHaveLength(1)
  })
})

describe('heldBy, failed and ownAddresses', () => {
  it("names the other identities whose verified copy still names the root, not an orphan's or an unreadable one", () => {
    const { home, keys } = homeWith('jane', 'kim')
    const jane = keys.jane?.signing.address as string
    expect(heldBy(home, 'jane', jane, bob)).toEqual([])
    keepAcceptCopy(home, 'kim', acceptFrom(signer(keys, 'kim'), [bob], 5))
    const gone = generateEdgeKeys(systemRng).signing
    keepAcceptCopy(home, 'gone', acceptFrom(gone, [bob], 5))
    writeFileSync(join(home, 'records', 'jane.accept.json'), 'x')
    expect(heldBy(home, 'jane', jane, bob)).toEqual(['kim'])
    expect(heldBy(home, 'jane', jane, carol)).toEqual([])
    expect(heldBy(home, 'jane', keys.kim?.signing.address as string, bob)).toEqual([])
  })

  it("names a relay's failure as the command line does", () => {
    expect(failed(new Error('x'))).toBe('error')
    expect(failed(new RelayError(null, 0, null, 'x'))).toBe('unreachable')
    expect(failed(new RelayError(null, 503, null, 'x'))).toBe('http-503')
    expect(failed(new RelayError('stale-record', 409, null, 'x'))).toBe('stale-record')
  })

  it('lists the addresses of the home, none when its keys do not list', () => {
    const { home, keys } = homeWith('jane')
    expect(ownAddresses(undefined, home)).toEqual([keys.jane?.signing.address])
    writeFileSync(join(home, 'keys', 'broken.json'), '{')
    expect(ownAddresses(undefined, home)).toEqual([])
  })
})
