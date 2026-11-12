import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  discover,
  MAX_ENVELOPE_BYTES,
  openSealed,
  parseHandleRecord,
  parseRecord,
  parseTxtPresentation,
  type SealedEnvelope,
  toHex,
  verifyHandleRecord,
  verifyRecord,
} from '@usebag/core'
import { HomeCustody, RelayError } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { USAGE } from '../src/cli.ts'
import { epochStore } from '../src/home.ts'
import { stableNode } from '../src/packaged.ts'
import { addTrust, readTrust } from '../src/trust.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'
import { forms } from './support/security.ts'

// onboard: one command puts an agent on its org's domain. The domain's origin and DNS are the test io's
// maps: empty, the self-check is pending (exit 3); filled with the files onboard wrote and the TXT record it printed,
// the same command with --check resolves the handle end to end (exit 0). No network, no DNS.

const tmp = tempDir('onboard')
afterAll(() => tmp.cleanup())
// A public address literal (TEST-NET-3): onboard's private-relay warning must not fire in the other tests.
const RELAY = 'http://203.0.113.9'
const DOMAIN = 'acme.test'
const HANDLE = `jane@${DOMAIN}`
const ORG = `org-${DOMAIN}`
const AC = `${stableNode()} ${fileURLToPath(new URL('../src/main.ts', import.meta.url))}`
let n = 0

/** A fresh home and relay, an inviter's address, and onboard's arguments for jane at acme.test. */
async function world() {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const elsewhere = join(tmp.dir, `inviter-${n}`)
  const inviter = (await cli(io, 'keygen', 'inviter', '--dir', elsewhere)).out[0] as string
  const accept = ['--accept', inviter, '--accept', 'domain:usuals.test']
  const args = ['jane', '--domain', DOMAIN, '--relay', RELAY, ...accept, '--dir', dir]
  const tree = join(dir, 'serve', DOMAIN, '.well-known', 'bag')
  const orgFile = join(tree, 'address.json')
  const handleFile = join(tree, 'handles', 'jane.json')
  return { relay, io, dir, inviter, elsewhere, args, tree, orgFile, handleFile }
}

/** An address of a key made in a home of its own: a peer of jane's. */
async function other(io: TestIo, name: string): Promise<string> {
  return (await cli(io, 'keygen', name, '--dir', join(tmp.dir, `${name}-${n++}`))).out[0] as string
}

type World = Awaited<ReturnType<typeof world>>

/**
 * Publishes jane's accept-from of `roots` at the relay one second on, signed by `record accept-from` and
 * sent by `publish`, as a peer pairing (the edge's admit: the newest record with the peer appended) or a
 * person by hand would.
 */
async function hold(w: World, roots: readonly string[], size = 65_536, keep = 604_800) {
  w.io.time.now += 1
  const file = join(w.dir, `held-${n++}.json`)
  const given = roots.flatMap((r) => ['--root', r])
  const sizes = ['--max-bytes', `${size}`, '--ttl', `${keep}`, '--out', file, '--dir', w.dir]
  expect((await cli(w.io, 'record', 'accept-from', 'jane', ...given, ...sizes)).code).toBe(0)
  expect((await cli(w.io, 'publish', RELAY, file, '--dir', w.dir)).code).toBe(0)
}

/** Jane's accept-from record at the relay, parsed. */
function acceptAt(w: World, jane: string) {
  return parseRecord(w.relay.records.get(`${jane} accept-from`) as Uint8Array)
}

/** The sealing key, in hex, of jane's epoch `n` in her home's store. */
function epochKey(w: World, jane: string, n: number): string {
  return toHex(epochStore(w.dir).epoch(jane, n).key.publicKey)
}

/** The inviter's chat message to jane's address, sent from the inviter's own home; returns its id. */
async function fromInviter(w: World, jane: string, text: string): Promise<string> {
  const to = ['--to', jane, '--relay', RELAY, '--type', 'chat.v1', '--body', JSON.stringify({ text })]
  const sent = await cli(w.io, 'send', '--as', 'inviter', ...to, '--dir', w.elsewhere)
  expect([sent.code, sent.out[1], sent.err]).toEqual([0, `published ${RELAY} tries=1`, []])
  return sent.out[0] as string
}

/**
 * Serves the tree onboard wrote (`tree`, its .well-known/bag) at `host`, and the TXT record of its `dns` line,
 * as a static host and the DNS would; returns the key the TXT record names, read back by the core.
 */
function serve(io: TestIo, printed: readonly string[], tree: string, host: string, handle: string) {
  const dns = printed.find((l) => l.startsWith('dns ')) as string
  const strings = parseTxtPresentation(dns.slice(dns.indexOf(' TXT ') + 5).trim())
  io.txt.set(`_bag.${DOMAIN}`, [strings])
  io.wellKnown.set(host, readFileSync(join(tree, 'address.json')))
  io.handles.set(`${host} ${handle}`, readFileSync(join(tree, 'handles', `${handle.split('@')[0]}.json`)))
  return discover([strings], DOMAIN).key
}

/** Every text form of the seeds of the key files `names` of a home, which no output may hold. */
function secrets(dir: string, ...names: string[]): string[] {
  return names.flatMap((name) => {
    const text = readFileSync(join(dir, 'keys', `${name}.json`), 'utf8')
    const f = JSON.parse(text) as { sign_seed: string; seal_priv: string }
    return [f.sign_seed, f.seal_priv].flatMap((hex) => forms(Buffer.from(hex, 'hex')))
  })
}

describe('onboard <name> --domain <host>: the tree to serve, the records, the chain, the steps and the self-check', () => {
  it('on a fresh home and domain writes the tree, publishes, prints the TXT and exits 3, then 0 once served', async () => {
    const w = await world()
    const ran = await cli(w.io, 'onboard', ...w.args)
    expect(ran.code).toBe(3)
    const org = (await cli(w.io, 'address', ORG, '--dir', w.dir)).out[0] as string
    const jane = (await cli(w.io, 'address', 'jane', '--dir', w.dir)).out[0] as string
    const root = join(w.dir, 'serve', DOMAIN)
    const chain = join(w.dir, 'jane.chain.json')
    expect(ran.out.slice(0, 20)).toEqual([
      `key ${ORG} ${org} new`,
      `key jane ${jane} new`,
      `wrote ${w.orgFile}`,
      `wrote ${w.handleFile}`,
      `published key ${jane} ${RELAY}`,
      `published address ${jane} ${RELAY}`,
      `published accept-from ${jane} ${RELAY}`,
      `trust ${w.inviter}`,
      'trust domain:usuals.test',
      `chain ${chain} root ${org} exp ${T0 + 604_800}`,
      `step 1: serve ${root} as the root of https://${DOMAIN}/ (HTTPS on port 443; each file a 200 with no redirect, as application/json), so that these answer:`,
      `url https://${DOMAIN}/.well-known/bag/address.json`,
      `url https://${DOMAIN}/.well-known/bag/handles/jane.json`,
      `step 2: add this TXT record to the DNS of ${DOMAIN}:`,
      `dns _bag.${DOMAIN}.  IN  TXT  "v=ac1; key=${org}"`,
      `next an inviter accepts ${HANDLE} by root domain:${DOMAIN} (send with --auth ${chain}) or by ${jane} (send without it)`,
      `next ${AC} send --as jane --auth ${chain} --to <handle|address> --relay ${RELAY} --type <type> --body <json> --dir ${w.dir}`,
      `next ${AC} inbox --as jane --relay ${RELAY} --dir ${w.dir}`,
      'next run this command again every 43200 s at most (records live 86400 s); nothing installs it:',
      `cron 0 */12 * * * ${AC} onboard ${w.args.slice(0, -2).join(' ')} --out ${root} --dir ${w.dir}`,
    ])
    expect(ran.out.slice(20, -1).every((l) => l.startsWith('check '))).toBe(true)
    expect(ran.out.at(-1)).toBe(
      `self-check pending ${HANDLE}: not resolving yet; do steps 1 and 2, then run again with --check`,
    )
    expect(ran.err).toEqual([])
    // A first run: no accept-from held at the relay, so the typed roots alone, and no `kept` line.
    expect(ran.out.filter((l) => l.startsWith('kept '))).toEqual([])

    // The tree a static host serves: two files, 0644, each verified by the core.
    expect(readdirSync(root, { recursive: true, encoding: 'utf8' }).sort()).toEqual([
      '.well-known',
      '.well-known/bag',
      '.well-known/bag/address.json',
      '.well-known/bag/handles',
      '.well-known/bag/handles/jane.json',
    ])
    for (const f of [w.orgFile, w.handleFile]) expect(statSync(f).mode & 0o777).toBe(0o644)
    expect(verifyRecord(parseRecord(readFileSync(w.orgFile)), T0)).toMatchObject({
      kind: 'address',
      key: org,
      sealing_key: expect.stringMatching(/^[0-9a-f]{64}$/),
      relays: [RELAY],
      rotation_key: null,
      revoked: [],
      ttl: 86_400,
      iat: T0,
    })
    const expected = { org, handle: HANDLE, revoked: [] }
    const handle = verifyHandleRecord(parseHandleRecord(readFileSync(w.handleFile)), expected, T0)
    expect(handle).toMatchObject({ address: jane, iat: T0, ttl: 86_400 })

    // The agent's records at the relay, the inviter trusted by address and usuals.test by its domain root
    // (inbox and the MCP server read it as --trust-root usuals.test), the chain from the org key.
    const accept = parseRecord(w.relay.records.get(`${jane} accept-from`) as Uint8Array)
    expect(accept).toMatchObject({
      roots: [w.inviter, 'domain:usuals.test'],
      max_bytes: MAX_ENVELOPE_BYTES,
      ttl: 604_800,
    })
    // Forward secrecy: the agent's address record names no sealing key; its key record, epoch 1, does.
    const address = parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array)
    expect(address).toMatchObject({ key: jane, sealing_key: null, relays: [RELAY], iat: T0 })
    const key = verifyRecord(parseRecord(w.relay.records.get(`${jane} key`) as Uint8Array), T0)
    expect(key).toMatchObject({ kind: 'key', key: jane, iat: T0, exp: T0 + 86_400 })
    expect(epochStore(w.dir).epochs(jane)).toEqual([1])
    expect(key).toMatchObject({ sealing_key: epochKey(w, jane, 1) })
    const trusted = { [w.inviter]: { added_at: T0 }, 'domain:usuals.test': { added_at: T0 } }
    expect(readTrust(w.dir)).toEqual(trusted)
    const hops = JSON.parse(readFileSync(chain, 'utf8')) as unknown
    expect(hops).toMatchObject([{ iss: org, sub: jane, caveats: [], exp: T0 + 604_800 }])

    // Served as printed, the TXT record round-trips through the core, and the check resolves end to end.
    expect(serve(w.io, ran.out, w.tree, DOMAIN, HANDLE)).toBe(org)
    const check = await cli(w.io, 'onboard', ...w.args, '--check')
    expect([check.code, check.out.at(-1), check.err]).toEqual([0, `self-check ok ${HANDLE}`, []])
    expect(check.out.slice(0, -1).every((l) => l.startsWith('check '))).toBe(true)
    const txt = `check _bag.${DOMAIN} found kind=txt key=${org} origin https://${DOMAIN}`
    expect(check.out).toContain(txt)
    expect(check.out.some((l) => / found kind=handle /.test(l))).toBe(true)
    expect(check.out.some((l) => / found kind=key /.test(l))).toBe(true)

    // With no key record at the relay a peer has nothing to seal to: the self-check is pending, and names
    // the step that publishes one (steps 1 and 2 are done; running --check again would never end it).
    w.relay.records.delete(`${jane} key`)
    const keyless = await cli(w.io, 'onboard', ...w.args, '--check')
    expect([keyless.code, keyless.out.at(-1)]).toEqual([
      3,
      `self-check pending ${HANDLE}: no key record at the relays; run onboard again, without --check`,
    ])

    // Nothing printed holds a key.
    const printed = [...ran.out, ...ran.err, ...check.out, ...check.err].join('\n')
    expect(secrets(w.dir, ORG, 'jane').filter((s) => printed.includes(s))).toEqual([])
  })

  it('run again is the refresh: the same files, the keys existing, every record signed anew', async () => {
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    serve(w.io, first.out, w.tree, DOMAIN, HANDLE)
    const tree = () => readdirSync(join(w.dir, 'serve'), { recursive: true, encoding: 'utf8' }).sort()
    const before = { tree: tree(), org: parseRecord(readFileSync(w.orgFile)) }
    const [org, jane] = [first.out[0], first.out[1]].map((l) => (l as string).split(' ')[2] as string)
    w.io.time.now += 60
    const again = await cli(w.io, 'onboard', ...w.args)
    expect(again.code).toBe(0)
    expect(again.out.slice(0, 2)).toEqual([`key ${ORG} ${org} existing`, `key jane ${jane} existing`])
    expect(again.out.at(-1)).toBe(`self-check ok ${HANDLE}`)
    // The same files and no temporary one left; the records' iat is the new now, their signatures new.
    expect(tree()).toEqual(before.tree)
    expect(readdirSync(join(w.dir, 'records')).sort()).toEqual(['jane.accept-from.json', 'jane.address.json'])
    const now = T0 + 60
    const orgRecord = verifyRecord(parseRecord(readFileSync(w.orgFile)), now)
    expect(orgRecord).toMatchObject({ key: org, iat: now })
    expect(orgRecord.sig).not.toBe(before.org.sig)
    const expected = { org: org as string, handle: HANDLE, revoked: [] }
    expect(verifyHandleRecord(parseHandleRecord(readFileSync(w.handleFile)), expected, now).iat).toBe(now)
    expect(parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array).iat).toBe(now)
    // A minute on no epoch is due: epoch 1's key record (iat T0) goes out again, before the address one.
    const keyAt = () => w.relay.records.get(`${jane} key`) as Uint8Array
    expect(epochStore(w.dir).epochs(jane as string)).toEqual([1])
    expect(parseRecord(keyAt())).toMatchObject({ iat: T0, sealing_key: epochKey(w, jane as string, 1) })
    const sent = again.out.filter((l) => l.startsWith('published '))
    expect(sent.slice(0, 2)).toEqual([`published key ${jane} ${RELAY}`, `published address ${jane} ${RELAY}`])
    expect(again.out).toContain(`chain ${join(w.dir, 'jane.chain.json')} root ${org} exp ${now + 604_800}`)
    // The trust file gains nothing: the same two roots, added at the first run; the same two trust lines.
    const trusted = { [w.inviter]: { added_at: T0 }, 'domain:usuals.test': { added_at: T0 } }
    expect(readTrust(w.dir)).toEqual(trusted)
    const trust = (out: readonly string[]) => out.filter((l) => l.startsWith('trust '))
    expect(trust(again.out)).toEqual([`trust ${w.inviter}`, 'trust domain:usuals.test'])
    expect(trust(again.out)).toEqual(trust(first.out))

    // Within the same second the address record is dated one second past the one held, so it is newer.
    const second = await cli(w.io, 'onboard', ...w.args)
    expect(second.out).toContain(`published address ${jane} ${RELAY}`)
    expect(parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array).iat).toBe(now + 1)
    // A relay that keeps the record it holds (stale-record: the key record as published, an accept-from of
    // the same second, an address record another writer dated later) is no failure.
    w.relay.failRecordPublish.set(RELAY, new RelayError('stale-record', 409, null, 'not newer'))
    const same = await cli(w.io, 'onboard', ...w.args)
    expect(same.code).toBe(0)
    expect(same.out.filter((l) => /^(published|unchanged) /.test(l))).toEqual([
      `unchanged key ${jane} ${RELAY}`,
      `unchanged address ${jane} ${RELAY}`,
      `unchanged accept-from ${jane} ${RELAY}`,
    ])
  })

  it('a peer seals to the key record; a refresh 11 h on rotates; the old epoch opens', async () => {
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    expect(first.code).toBe(3)
    const jane = (first.out[1] as string).split(' ')[2] as string
    // The inviter, from its own home, sends to jane's address: the address record names no sealing
    // key, so the wrap is sealed to the key record's, epoch 1's: it opens with that key, not the
    // long-term one.
    const before = await fromInviter(w, jane, 'before the refresh')
    const env = JSON.parse(new TextDecoder().decode(w.relay.envelopes.get(before))) as SealedEnvelope
    const epoch1 = epochStore(w.dir).epoch(jane, 1).key
    const body = { text: 'before the refresh' }
    expect(openSealed(env, { address: jane, key: epoch1 })).toMatchObject({ body })
    const longTerm = new HomeCustody(w.dir).keys('jane').sealing
    expect(() => openSealed(env, { address: jane, key: longTerm })).toThrow()

    // A second short of 11 hours no epoch is due: epoch 1 is published again, no epoch 2.
    w.io.time.now = T0 + 11 * 3600 - 1
    expect((await cli(w.io, 'onboard', ...w.args)).code).toBe(3)
    expect(epochStore(w.dir).epochs(jane)).toEqual([1])
    // 11 hours on (EPOCH_DUE less onboard's hour of slack) the refresh publishes epoch 2, before the address
    // record; epoch 1 stays in the store until its horizon (exp + retention + skew).
    w.io.time.now = T0 + 11 * 3600
    const refresh = await cli(w.io, 'onboard', ...w.args)
    expect(refresh.code).toBe(3)
    expect(refresh.out.filter((l) => l.startsWith('published ')).slice(0, 2)).toEqual([
      `published key ${jane} ${RELAY}`,
      `published address ${jane} ${RELAY}`,
    ])
    expect(epochStore(w.dir).epochs(jane)).toEqual([2, 1])
    const key = parseRecord(w.relay.records.get(`${jane} key`) as Uint8Array)
    expect(key).toMatchObject({ iat: T0 + 11 * 3600, sealing_key: epochKey(w, jane, 2) })
    expect(epochKey(w, jane, 2)).not.toBe(epochKey(w, jane, 1))
    const address = parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array)
    expect(address).toMatchObject({ sealing_key: null, iat: T0 + 11 * 3600 })

    // jane's inbox, trusting the inviter from the trust file onboard wrote, opens the mail sealed to epoch 1.
    const inbox = await cli(w.io, 'inbox', '--as', 'jane', '--relay', RELAY, '--once', '--dir', w.dir)
    expect(inbox).toEqual({
      code: 0,
      out: [`accept ${before} ${w.inviter} ${w.inviter} chat.v1 {"text":"before the refresh"}`],
      err: [],
    })
  })

  it('trusts only the typed --accept roots: nothing else, after a re-run and after --check', async () => {
    // Ruled 2026-10-28: no root is ever written from an incoming message, a
    // resolved record or a default; only the roots the person typed.
    const w = await world()
    const given = ['--accept', 'domain:example.net', '--accept', w.inviter]
    const args = [...w.args.slice(0, 5), ...given, '--dir', w.dir]
    const first = await cli(w.io, 'onboard', ...args)
    expect(first.code).toBe(3)
    const [org, jane] = [first.out[0], first.out[1]].map((l) => (l as string).split(' ')[2] as string)
    expect(first.out.filter((l) => l.startsWith('trust '))).toEqual([
      `trust ${w.inviter}`,
      'trust domain:example.net',
    ])
    const held = () => Object.keys(readTrust(w.dir)).sort()
    const exactly = () => {
      expect(held()).toEqual(['domain:example.net', w.inviter].sort())
      for (const x of [org, jane, `domain:${DOMAIN}`, DOMAIN, RELAY]) expect(held()).not.toContain(x)
    }
    exactly()
    serve(w.io, first.out, w.tree, DOMAIN, HANDLE)
    const check = await cli(w.io, 'onboard', ...args, '--check')
    expect(check.code).toBe(0)
    exactly()
    w.io.time.now += 60
    const again = await cli(w.io, 'onboard', ...args)
    expect(again.code).toBe(0)
    exactly()
  })

  it('a refresh keeps the roots a pairing added to the accept-from; trusts only typed roots', async () => {
    // The seam: onboard replaced the accept-from roots, so the cron refresh dropped
    // a peer a pairing had added. Now it publishes the held roots, then the typed ones; trust.json gains
    // only typed roots.
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    expect(first.code).toBe(3)
    const jane = (first.out[1] as string).split(' ')[2] as string
    const carol = await other(w.io, 'carol')
    // A pairing with carol: her address appended to the held roots, and (after the y) added to the trust
    // file. A root added by hand, not trusted: onboard must not trust it either.
    await hold(w, [w.inviter, 'domain:usuals.test', carol, 'domain:by-hand.test'])
    addTrust(w.dir, carol, w.io.time.now)
    const trusted = readTrust(w.dir)
    expect(Object.keys(trusted).sort()).toEqual([w.inviter, 'domain:usuals.test', carol].sort())
    w.io.time.now += 60
    const again = await cli(w.io, 'onboard', ...w.args)
    expect(again.code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({
      roots: [w.inviter, 'domain:usuals.test', carol, 'domain:by-hand.test'],
      max_bytes: MAX_ENVELOPE_BYTES,
      ttl: 604_800,
      iat: w.io.time.now,
    })
    const file = parseRecord(readFileSync(join(w.dir, 'records', 'jane.accept-from.json')))
    expect(file).toEqual(acceptAt(w, jane))
    const lines = (word: string) => again.out.filter((l) => l.startsWith(`${word} `))
    expect(lines('kept')).toEqual([`kept ${carol}`, 'kept domain:by-hand.test'])
    expect(lines('trust')).toEqual([`trust ${w.inviter}`, 'trust domain:usuals.test'])
    // The trust file is as the pairing left it: the held roots are published, never trusted by onboard.
    expect(readTrust(w.dir)).toEqual(trusted)
    expect(readTrust(w.dir)).not.toHaveProperty(['domain:by-hand.test'])

    // After a cron lapse a relay sweeps the address record, never the accept-from (the reviewer's B1): no
    // address record is found, the accept-from is read all the same, and no root is dropped.
    w.relay.records.delete(`${jane} address`)
    w.io.time.now += 86_400
    const lapsed = await cli(w.io, 'onboard', ...w.args)
    expect(lapsed.code).toBe(3)
    const all = [w.inviter, 'domain:usuals.test', carol, 'domain:by-hand.test']
    expect(acceptAt(w, jane)).toMatchObject({ roots: all, iat: w.io.time.now })
    const address = parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array)
    expect(address).toMatchObject({ key: jane, iat: w.io.time.now })
  })

  it('lifts a held max_bytes of exactly 65,536 to the envelope cap, keeps 32,768, and writes a typed 65,536', async () => {
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    const jane = (first.out[1] as string).split(' ')[2] as string
    const roots = [w.inviter, 'domain:usuals.test']
    for (const [held, signed] of [
      [65_536, MAX_ENVELOPE_BYTES],
      [32_768, 32_768],
    ] as const) {
      await hold(w, roots, held, 3600)
      w.io.time.now += 60
      expect((await cli(w.io, 'onboard', ...w.args)).code).toBe(3)
      expect(acceptAt(w, jane), `${held}`).toMatchObject({ roots, max_bytes: signed, ttl: 3600 })
    }
    // A typed --max-bytes is written as typed, 65,536 too: the lift is of a held value, never of a flag.
    w.io.time.now += 60
    expect((await cli(w.io, 'onboard', ...w.args, '--max-bytes', '65536')).code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots, max_bytes: 65_536 })
  })

  it('a typed root the held accept-from has is not repeated; a new one follows; sizes stay', async () => {
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    const jane = (first.out[1] as string).split(' ')[2] as string
    const carol = await other(w.io, 'carol')
    // Held in another order, with another largest envelope and retention: the order and sizes are kept.
    await hold(w, ['domain:usuals.test', carol, w.inviter], 4096, 3600)
    w.io.time.now += 60
    const args = [...w.args.slice(0, -2), '--accept', 'domain:new.test', '--accept', carol, '--dir', w.dir]
    const again = await cli(w.io, 'onboard', ...args)
    expect(again.code).toBe(3)
    const roots = ['domain:usuals.test', carol, w.inviter, 'domain:new.test']
    expect(acceptAt(w, jane)).toMatchObject({ roots, max_bytes: 4096, ttl: 3600 })
    expect(again.out.filter((l) => l.startsWith('kept '))).toEqual([])
    const typed = [w.inviter, carol, 'domain:usuals.test', 'domain:new.test']
    expect(Object.keys(readTrust(w.dir)).sort()).toEqual(typed.sort())
    // A typed --max-bytes or --retention names the size again.
    w.io.time.now += 60
    const sized = await cli(w.io, 'onboard', ...args, '--max-bytes', '2048', '--retention', '7200')
    expect(sized.code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots, max_bytes: 2048, ttl: 7200 })

    // Held, trusted and typed roots over the cap of 1,024 are refused before the tree is written or anything
    // published: 1,023 held and the trust file's 4 make 1,027.
    await hold(
      w,
      Array.from({ length: 1023 }, (_, i) => `domain:h${i}.test`),
      4096,
      3600,
    )
    const held = acceptAt(w, jane)
    const tree = [readFileSync(w.orgFile), readFileSync(w.handleFile)]
    w.io.time.now += 60
    const over = await cli(w.io, 'onboard', ...w.args)
    expect([over.code, over.out.slice(2)]).toEqual([1, []])
    const said = `the accept-from of ${jane} would hold 1027 roots (1023 held at its relays, 4 in the`
    expect(over.err).toEqual([
      `bag: too-many-roots: ${said} trust file, then the typed --accept ones); the cap is 1024`,
    ])
    expect(acceptAt(w, jane)).toEqual(held)
    expect([readFileSync(w.orgFile), readFileSync(w.handleFile)]).toEqual(tree)
  })

  it('a held * gives way to typed roots; a typed * beside held roots is refused (accept-held)', async () => {
    const w = await world()
    const star = [...w.args.slice(0, 5), '--accept', '*', '--dir', w.dir]
    const first = await cli(w.io, 'onboard', ...star)
    expect(first.code).toBe(3)
    const jane = (first.out[1] as string).split(' ')[2] as string
    expect(acceptAt(w, jane)).toMatchObject({ roots: ['*'] })
    w.io.time.now += 60
    expect((await cli(w.io, 'onboard', ...star)).code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: ['*'], iat: w.io.time.now })
    // The typed roots replace a held *: it stands alone, and no pairing adds a root to it.
    w.io.time.now += 60
    const narrowed = await cli(w.io, 'onboard', ...w.args)
    expect(narrowed.code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: [w.inviter, 'domain:usuals.test'] })
    expect(narrowed.out.filter((l) => l.startsWith('kept '))).toEqual([])

    // A pairing adds carol; a typed * then would drop her unseen, so it is refused and nothing is written.
    const carol = await other(w.io, 'carol')
    await hold(w, [w.inviter, 'domain:usuals.test', carol])
    const held = acceptAt(w, jane)
    const tree = readFileSync(w.orgFile)
    w.io.time.now += 60
    const refused = await cli(w.io, 'onboard', ...star)
    expect([refused.code, refused.out.slice(2)]).toEqual([1, []])
    const holds = `holds ${w.inviter} domain:usuals.test ${carol}`
    expect(refused.err).toEqual([
      `bag: accept-held: --accept * stands alone, and the accept-from of ${jane} at its relays ` +
        `${holds}: to accept every sender, publish one of --root '*' by hand ` +
        '(record accept-from, then publish), then run onboard again',
    ])
    expect(acceptAt(w, jane)).toEqual(held)
    expect(readFileSync(w.orgFile)).toEqual(tree)
    // The hand step: a record of * published; then the typed * refreshes it.
    await hold(w, ['*'])
    w.io.time.now += 60
    expect((await cli(w.io, 'onboard', ...star)).code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: ['*'], iat: w.io.time.now })
  })

  it('publishes the trust file roots: a peer paired under a held * stays after a narrowing', async () => {
    // Rule (b): accept-from = held roots, then the trust file's (a pairing's y is a typed
    // --accept), then the typed ones; the trust file itself still gains only the typed roots.
    const w = await world()
    const star = [...w.args.slice(0, 5), '--accept', '*', '--dir', w.dir]
    const first = await cli(w.io, 'onboard', ...star)
    const jane = (first.out[1] as string).split(' ')[2] as string
    // Two pairings under the held *: admit adds nothing to it; each y writes the trust file.
    const carol = await other(w.io, 'carol')
    addTrust(w.dir, carol, w.io.time.now)
    addTrust(w.dir, 'domain:paired.test', w.io.time.now)
    const inFile = Object.keys(readTrust(w.dir))
    expect([...inFile].sort()).toEqual([carol, 'domain:paired.test'].sort())
    // With * typed again the record stays * (it admits both); typed roots then narrow it, keeping both.
    w.io.time.now += 60
    expect((await cli(w.io, 'onboard', ...star)).code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: ['*'] })
    w.io.time.now += 60
    const narrowed = await cli(w.io, 'onboard', ...w.args)
    expect(narrowed.code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: [...inFile, w.inviter, 'domain:usuals.test'] })
    expect(narrowed.out.filter((l) => l.startsWith('kept '))).toEqual(inFile.map((r) => `kept ${r}`))
    const typed = [w.inviter, 'domain:usuals.test']
    expect(Object.keys(readTrust(w.dir)).sort()).toEqual([...inFile, ...typed].sort())

    // An address record held with no accept-from at the relay: the trust file's roots, then the typed ones.
    w.relay.records.delete(`${jane} accept-from`)
    const now = Object.keys(readTrust(w.dir))
    w.io.time.now += 60
    expect((await cli(w.io, 'onboard', ...w.args)).code).toBe(3)
    expect(acceptAt(w, jane)).toMatchObject({ roots: [...new Set([...now, ...typed])] })

    // A trust file that does not read stops onboard before anything is written.
    const bad = await world()
    mkdirSync(bad.dir, { recursive: true })
    writeFileSync(join(bad.dir, 'trust.json'), 'not json\n')
    const refused = await cli(bad.io, 'onboard', ...bad.args)
    expect([refused.code, refused.out]).toEqual([1, []])
    expect(refused.err[0]).toMatch(/^bag: trust-invalid: /)
    expect(readdirSync(bad.dir)).toEqual(['trust.json'])
  })

  it('after a lapse at two relays, takes the newer accept-from, whichever relay holds it', async () => {
    // newestAccept over two relays, each with its own records (MemoryRelay's recordsAt, as login.test.ts
    // does): the newer record on the first relay, then on the second.
    const B = 'http://203.0.113.8'
    for (const newerAt of [RELAY, B]) {
      const w = await world()
      const args = [...w.args.slice(0, 5), '--relay', B, ...w.args.slice(5)]
      for (const url of [RELAY, B]) w.relay.recordsAt.set(url, new Map())
      const first = await cli(w.io, 'onboard', ...args)
      expect(first.code).toBe(3)
      const jane = (first.out[1] as string).split(' ')[2] as string
      const [carol, dave] = [await other(w.io, 'carol'), await other(w.io, 'dave')]
      const signed = async (peer: string): Promise<Uint8Array> => {
        w.io.time.now += 1
        const file = join(w.dir, `signed-${n++}.json`)
        const roots = ['--root', w.inviter, '--root', 'domain:usuals.test', '--root', peer]
        const sizes = ['--max-bytes', '65536', '--ttl', '604800', '--out', file, '--dir', w.dir]
        expect((await cli(w.io, 'record', 'accept-from', 'jane', ...roots, ...sizes)).code).toBe(0)
        return readFileSync(file)
      }
      const [older, newer] = [await signed(carol), await signed(dave)]
      const at = (url: string) => w.relay.recordsAt.get(url) as Map<string, Uint8Array>
      at(newerAt).set(`${jane} accept-from`, newer)
      at(newerAt === RELAY ? B : RELAY).set(`${jane} accept-from`, older)
      for (const url of [RELAY, B]) at(url).delete(`${jane} address`)
      w.io.time.now += 86_400
      const lapsed = await cli(w.io, 'onboard', ...args)
      expect(lapsed.code, newerAt).toBe(3)
      expect(
        lapsed.out.filter((l) => l.startsWith('kept ')),
        newerAt,
      ).toEqual([`kept ${dave}`])
      for (const url of [RELAY, B]) {
        const published = parseRecord(at(url).get(`${jane} accept-from`) as Uint8Array)
        const roots = [w.inviter, 'domain:usuals.test', dave]
        expect(published, `${newerAt} ${url}`).toMatchObject({ roots, iat: w.io.time.now })
      }
    }
  })

  it('with no address record at the relay, keeps the rotation key and revoked list written', async () => {
    // A lapse swept the address record; <home>/records/<name>.address.json carries
    // its rotation key and revoked list when the core verifies it, it is the agent's and names no
    // rotated_from.
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    const jane = (first.out[1] as string).split(' ')[2] as string
    const rot = (await cli(w.io, 'keygen', 'rot', '--dir', w.dir)).out[0] as string
    const gone = (await cli(w.io, 'keygen', 'gone', '--dir', w.dir)).out[0] as string
    const last = join(w.dir, 'records', 'jane.address.json')
    const at = ['--relay', RELAY, '--sealing-key', '--out', last, '--dir', w.dir]
    w.io.time.now += 1
    await cli(w.io, 'record', 'address', 'jane', '--rotation-key', rot, '--revoke', gone, ...at)
    const swept = async () => {
      w.relay.records.delete(`${jane} address`)
      w.io.time.now += 86_400
      expect((await cli(w.io, 'onboard', ...w.args)).code).toBe(3)
      return parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array)
    }
    // The record written there names a sealing key; the one published names none.
    expect(await swept()).toMatchObject({ key: jane, sealing_key: null, rotation_key: rot, revoked: [gone] })

    // A record of another key there is no copy of jane's, and she has published: nothing goes out, never an empty list.
    await cli(w.io, 'record', 'address', 'gone', ...at)
    const before = w.relay.records.get(`${jane} address`)
    w.relay.records.delete(`${jane} address`)
    w.io.time.now += 86_400
    const refused = await cli(w.io, 'onboard', ...w.args)
    expect(refused.code).toBe(1)
    expect(refused.err[0]).toMatch(/^bag: no-held-record: no relay holds the address record of /)
    expect(before).toBeDefined()
    expect(w.relay.records.get(`${jane} address`)).toBeUndefined()
  })

  it('keeps the rotation key and revoked list of the served record; refuses another key and a link', async () => {
    const w = await world()
    const org = (await cli(w.io, 'keygen', ORG, '--dir', w.dir)).out[0] as string
    const rot = (await cli(w.io, 'keygen', 'rot', '--dir', w.dir)).out[0] as string
    const gone = (await cli(w.io, 'keygen', 'gone', '--dir', w.dir)).out[0] as string
    mkdirSync(dirname(w.orgFile), { recursive: true })
    const at = ['--relay', RELAY, '--out', w.orgFile, '--dir', w.dir]
    await cli(w.io, 'record', 'address', ORG, '--rotation-key', rot, '--revoke', gone, ...at)
    const kept = await cli(w.io, 'onboard', ...w.args)
    expect([kept.code, kept.out[0]]).toEqual([3, `key ${ORG} ${org} existing`])
    const served = parseRecord(readFileSync(w.orgFile))
    expect(served).toMatchObject({ key: org, rotation_key: rot, revoked: [gone] })

    // A served record edited on the host (here its rotation key) fails the core's check, and nothing is carried.
    const evil = (await cli(w.io, 'keygen', 'evil', '--dir', w.dir)).out[0] as string
    writeFileSync(w.orgFile, readFileSync(w.orgFile, 'utf8').replace(rot, evil))
    const forged = await cli(w.io, 'onboard', ...w.args)
    expect([forged.code, forged.out.slice(2)]).toEqual([1, []])
    expect(forged.err[0]).toMatch(/^bag: bad-record-sig: /)
    expect(parseRecord(readFileSync(w.orgFile))).toMatchObject({ rotation_key: evil })

    // A served record that names rotated_from is refused, as record keep refuses one, and the file stays as it is.
    const old = (await cli(w.io, 'keygen', 'old', '--dir', w.dir)).out[0] as string
    await cli(w.io, 'record', 'address', ORG, '--rotated-from', 'old', ...at)
    const rotation = readFileSync(w.orgFile)
    const rotated = await cli(w.io, 'onboard', ...w.args)
    expect(rotated.code).toBe(1)
    expect(rotated.err[0]).toContain(`bag: rotation: ${w.orgFile} names rotated_from ${old}, `)
    expect(readFileSync(w.orgFile)).toEqual(rotation)

    // A record of another key at the org record's path is not replaced.
    await cli(w.io, 'record', 'address', 'gone', ...at)
    const other = await cli(w.io, 'onboard', ...w.args)
    expect([other.code, other.err]).toEqual([
      1,
      [
        `bag: org-key-mismatch: ${w.orgFile} is a record of ${gone}, not of ${ORG} (${org}): move it, or give the --org-key that signed it`,
      ],
    ])

    // A link on the way is refused: a directory of the tree, or the handle record's file.
    const linked = join(w.dir, 'linked')
    mkdirSync(join(linked, '.well-known'), { recursive: true })
    symlinkSync(join(w.dir, 'elsewhere'), join(linked, '.well-known', 'bag'))
    const dirLink = await cli(w.io, 'onboard', ...w.args, '--out', linked)
    const link = join(linked, '.well-known', 'bag')
    expect([dirLink.code, dirLink.err]).toEqual([
      1,
      [`bag: unsafe-path: ${link} is a link or not a directory`],
    ])
    const handles = join(w.dir, 'file-linked', '.well-known', 'bag', 'handles')
    mkdirSync(handles, { recursive: true })
    symlinkSync(join(w.dir, 'nowhere.json'), join(handles, 'jane.json'))
    const fileLink = await cli(w.io, 'onboard', ...w.args, '--out', join(w.dir, 'file-linked'))
    expect([fileLink.code, fileLink.err]).toEqual([
      1,
      [`bag: unsafe-path: ${join(handles, 'jane.json')} is a link or not a regular file`],
    ])
    expect(readdirSync(dirname(handles))).toEqual(['handles'])
  })

  it('one relay of two down stops nothing: the other takes the records, and the later steps run', async () => {
    const w = await world()
    const other = 'http://203.0.113.10'
    w.relay.failRecordPublish.set(other, new RelayError(null, 0, null, 'connect ECONNREFUSED'))
    const ran = await cli(w.io, 'onboard', ...w.args, '--relay', other)
    const jane = (ran.out.find((l) => l.startsWith('published address ')) as string).split(' ')[2] as string
    expect(ran.out).toContain(`published address ${jane} ${RELAY}`)
    expect(ran.out).toContain(`failed address ${jane} ${other} unreachable`)
    expect(ran.out).toContain(`failed accept-from ${jane} ${other} unreachable`)
    expect(ran.out).toContain(`trust ${w.inviter}`)
    expect(ran.out.some((l) => l.startsWith('chain '))).toBe(true)
  })

  it('a relay down fails after the files are written, and running it again completes the publish', async () => {
    const w = await world()
    w.relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'connect ECONNREFUSED'))
    const down = await cli(w.io, 'onboard', ...w.args)
    expect(down.code).toBe(1)
    expect([existsSync(w.orgFile), existsSync(w.handleFile)]).toEqual([true, true])
    // The key record goes first: epoch 1 is stored unpublished, and the error names onboard again.
    const jane = (down.out[1] as string).split(' ')[2] as string
    expect(down.err[0]).toMatch(/^bag: unreachable: \S+ did not take the key record of /)
    expect(down.err[0]).toContain(`; publish it again: ${AC} onboard ${w.args.slice(0, -2).join(' ')} --out `)
    const stored = epochKey(w, jane, 1)
    w.relay.failRecordPublish.clear()
    const up = await cli(w.io, 'onboard', ...w.args)
    expect(up.code).toBe(3)
    // An unpublished newest epoch is due: rotate publishes that same key again, minting none, then the
    // address and accept-from records go out.
    expect(up.out.filter((l) => l.startsWith('published ')).map((l) => l.split(' ')[1])).toEqual([
      'key',
      'address',
      'accept-from',
    ])
    expect(epochStore(w.dir).epochs(jane)).toEqual([1])
    expect(epochKey(w, jane, 1)).toBe(stored)
    const key = parseRecord(w.relay.records.get(`${jane} key`) as Uint8Array)
    expect(key).toMatchObject({ kind: 'key', sealing_key: stored })
    // Not due, the key record goes out through put: a refusal other than stale-record fails with the relay's code.
    w.relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'connect ECONNREFUSED'))
    w.io.time.now += 60
    const later = await cli(w.io, 'onboard', ...w.args)
    expect([later.code, later.err[0]?.startsWith('bag: unreachable: ')]).toEqual([1, true])
    expect(epochStore(w.dir).epochs(jane)).toEqual([1])
  })

  it('--origin bag names the host in the TXT record; a short ttl runs every few minutes; a home is quoted', async () => {
    const relay = new MemoryRelay()
    const home = join(tmp.dir, 'home with a space')
    const io = testIo(relay, { AC_HOME: home })
    const what = ['--accept', '*', '--handle', 'j.doe', '--origin', 'bag', '--ttl', '600']
    const sizes = ['--chain-exp', '3600', '--max-bytes', '1024', '--retention', '7200']
    const args = ['jane', '--domain', DOMAIN, '--relay', RELAY, ...what, ...sizes, '--allow-private-relays']
    const ran = await cli(io, 'onboard', ...args)
    expect(ran.code).toBe(3)
    const org = (await cli(io, 'address', ORG)).out[0] as string
    const jane = (await cli(io, 'address', 'jane')).out[0] as string
    const host = `bag.${DOMAIN}`
    expect(ran.out).toContain(`dns _bag.${DOMAIN}.  IN  TXT  "v=ac1; key=${org}; host=bag"`)
    expect(ran.out).toContain(`url https://${host}/.well-known/bag/handles/j.doe.json`)
    expect(ran.out).toContain(`chain ${join(home, 'jane.chain.json')} root ${org} exp ${T0 + 3600}`)
    expect(ran.out).toContain(`next ${AC} inbox --as jane --relay ${RELAY} --dir '${home}'`)
    const named = "--accept '*' --handle j.doe --origin bag --ttl 600"
    const again = `jane --domain ${DOMAIN} --relay ${RELAY} ${named}`
    const more = `--chain-exp 3600 --max-bytes 1024 --retention 7200 --allow-private-relays --out '${home}/serve/${DOMAIN}' --dir '${home}'`
    expect(ran.out).toContain(`cron */5 * * * * ${AC} onboard ${again} ${more}`)
    expect(ran.out.filter((l) => l.startsWith('trust '))).toEqual([])
    const accept = parseRecord(relay.records.get(`${jane} accept-from`) as Uint8Array)
    expect(accept).toMatchObject({ roots: ['*'], max_bytes: 1024, ttl: 7200 })
    const tree = join(home, 'serve', DOMAIN, '.well-known', 'bag')
    expect(serve(io, ran.out, tree, host, `j.doe@${DOMAIN}`)).toBe(org)
    const check = await cli(io, 'onboard', ...args, '--check')
    expect([check.code, check.out.at(-1)]).toEqual([0, `self-check ok j.doe@${DOMAIN}`])
  })

  it("keeps the rotation key and revoked list of the agent's newest record at its relays; refuses its rotated_from", async () => {
    const w = await world()
    const first = await cli(w.io, 'onboard', ...w.args)
    expect(first.code).toBe(3)
    const jane = (first.out[1] as string).split(' ')[2] as string
    const rot = (await cli(w.io, 'keygen', 'rot', '--dir', w.dir)).out[0] as string
    const gone = (await cli(w.io, 'keygen', 'gone', '--dir', w.dir)).out[0] as string
    const byHand = join(w.dir, 'by-hand.json')
    const at = ['--relay', RELAY, '--sealing-key', '--out', byHand, '--dir', w.dir]
    w.io.time.now += 1
    await cli(w.io, 'record', 'address', 'jane', '--rotation-key', rot, '--revoke', gone, ...at)
    expect((await cli(w.io, 'publish', RELAY, byHand, '--dir', w.dir)).code).toBe(0)
    w.io.time.now += 60
    const again = await cli(w.io, 'onboard', ...w.args)
    expect(again.code).toBe(3)
    // Held with a sealing key (pre-FS), signed again with none, its rotation key and revoked list kept.
    const kept = parseRecord(w.relay.records.get(`${jane} address`) as Uint8Array)
    expect(kept).toMatchObject({
      key: jane,
      sealing_key: null,
      rotation_key: rot,
      revoked: [gone],
      iat: T0 + 61,
    })
    const file = parseRecord(readFileSync(join(w.dir, 'records', 'jane.address.json')))
    expect(file).toMatchObject({ rotation_key: rot, revoked: [gone], iat: T0 + 61 })

    // One that names rotated_from is not signed again: its countersignature covers its iat (as record keep refuses).
    await cli(w.io, 'keygen', 'old', '--dir', w.dir)
    w.io.time.now += 1
    await cli(w.io, 'record', 'address', 'jane', '--rotated-from', 'old', ...at)
    await cli(w.io, 'publish', RELAY, byHand, '--dir', w.dir)
    const rotated = await cli(w.io, 'onboard', ...w.args)
    expect([rotated.code, rotated.out.slice(2)]).toEqual([1, []])
    const said = `bag: rotation: the address record of ${jane} names rotated_from `
    expect(rotated.err[0]).toContain(said)
  })

  it('replaces a handle bound to another agent, printing the address it bound; that agent no longer checks ok', async () => {
    const w = await world()
    // A file there that is no handle record binds no one: it is replaced without a `replaced` line.
    mkdirSync(dirname(w.handleFile), { recursive: true })
    writeFileSync(w.handleFile, 'not a record\n')
    const first = await cli(w.io, 'onboard', ...w.args)
    const jane = (first.out[1] as string).split(' ')[2] as string
    expect([first.code, first.out.some((l) => l.startsWith('replaced '))]).toEqual([3, false])
    const bob = ['bob', ...w.args.slice(1), '--handle', 'jane']
    w.io.time.now += 60
    const moved = await cli(w.io, 'onboard', ...bob)
    expect(moved.out.indexOf(`replaced ${jane}`)).toBe(moved.out.indexOf(`wrote ${w.handleFile}`) + 1)
    serve(w.io, moved.out, w.tree, DOMAIN, HANDLE)
    // The handle resolves, and to an address record, but not to jane's: pending for jane, ok for bob.
    const janes = await cli(w.io, 'onboard', ...w.args, '--check')
    expect([janes.code, janes.out.at(-1)]).toEqual([
      3,
      `self-check pending ${HANDLE}: not resolving yet; do steps 1 and 2, then run again with --check`,
    ])
    expect(janes.out.some((l) => / found kind=handle /.test(l))).toBe(true)
    const bobs = await cli(w.io, 'onboard', ...bob, '--check')
    expect([bobs.code, bobs.out.at(-1)]).toEqual([0, `self-check ok ${HANDLE}`])
  })

  it('puts a relative --dir and --out in the cron line as absolute paths; the tree is 0755 under umask 077', async () => {
    const w = await world()
    const base = relative(process.cwd(), tmp.dir)
    const [home, out] = [join(tmp.dir, 'rel-home'), join(tmp.dir, 'rel-out')]
    const args = [...w.args.slice(0, -2), `--dir=${join(base, 'rel-home')}`, '--out', join(base, 'rel-out')]
    const mask = process.umask(0o077)
    const ran = await cli(w.io, 'onboard', ...args).finally(() => process.umask(mask))
    expect(ran.code).toBe(3)
    const given = w.args.slice(0, -2).join(' ')
    expect(ran.out).toContain(`cron 0 */12 * * * ${AC} onboard ${given} --out ${out} --dir ${home}`)
    const tree = join(out, '.well-known', 'bag')
    expect(ran.out).toContain(`wrote ${join(tree, 'address.json')}`)
    for (const d of [out, dirname(tree), tree, join(tree, 'handles')]) {
      expect(statSync(d).mode & 0o777, d).toBe(0o755)
    }
  })

  it('warns on stderr for a private IP literal or localhost relay, exit code unchanged', async () => {
    // lookup treats every --relay as the edge's own, so the self-check needs no flag. No DNS: only a
    // literal or a localhost name is judged; a public name and a public literal are not warned.
    const warning = (url: string, kind: string) =>
      `bag: warning: relay ${url} is a private address (${kind}); ` +
      "peers' edges refuse to deliver there unless they pass --allow-private-relays"
    const cases: [string, string | null][] = [
      ['http://127.0.0.1:9', 'loopback'],
      ['http://10.1.2.3', 'private'],
      ['http://[fd12:3456::1]:9', 'ula'],
      ['http://[fe80::1]', 'link-local'],
      ['http://localhost:9', 'loopback'],
      ['http://relay.localhost:9', 'loopback'],
      ['https://relay.example.net', null],
      ['http://203.0.113.7', null],
    ]
    for (const [url, kind] of cases) {
      const w = await world()
      const ran = await cli(w.io, 'onboard', ...w.args.map((a) => (a === RELAY ? url : a)))
      expect([url, ran.code, ran.err], url).toEqual([url, 3, kind === null ? [] : [warning(url, kind)]])
    }
  })

  it('does not warn with --allow-private-relays or under --check, whatever the relay', async () => {
    const w = await world()
    const args = w.args.map((a) => (a === RELAY ? 'http://127.0.0.1:9' : a))
    const allowed = await cli(w.io, 'onboard', ...args, '--allow-private-relays')
    expect([allowed.code, allowed.err]).toEqual([3, []])
    // The record is not written under --check, so there is nothing to warn about, flag or no flag.
    const checked = await cli(w.io, 'onboard', ...args, '--check')
    expect([checked.code, checked.err]).toEqual([3, []])
    const both = await cli(w.io, 'onboard', ...args, '--check', '--allow-private-relays')
    expect([both.code, both.err]).toEqual([3, []])
  })

  it('refuses a bad --domain, a one-label domain and a missing --relay or --accept: exit 1, nothing written', async () => {
    const io = testIo(new MemoryRelay())
    const dir = join(tmp.dir, 'refused')
    const b = `--relay ${RELAY} --accept * --dir ${dir}`
    const many = Array.from({ length: 64 }, (_, i) => `--relay http://127.0.0.1:${i + 1}`).join(' ')
    const roots = Array.from({ length: 1024 }, (_, i) => `--accept domain:h${i}.test`).join(' ')
    const cases: [string, string, string][] = [
      [`--domain ${DOMAIN} ${b} --accept domain:usuals.test`, 'usage', '--accept * stands alone'],
      [`--domain ${DOMAIN} ${b} ${many}`, 'usage', '--relay names more than 64 relays'],
      [`--domain ${DOMAIN} ${b} ${roots}`, 'usage', '--accept names more than 1024 roots'],
      [`--domain ${DOMAIN} ${b} --out ${dir}`, 'usage', `--out ${dir} holds the home ${dir}: its keys`],
      [`--domain ${DOMAIN} ${b} --out ${tmp.dir}`, 'usage', `--out ${tmp.dir} holds the home ${dir}: `],
      [`--domain Acme.test ${b}`, 'usage', '--domain: "Acme.test" is not a domain root: lowercase only'],
      [`--domain acme ${b}`, 'usage', '--domain: "acme" is not a domain root: two or more labels'],
      [`--domain acme.test. ${b}`, 'usage', '--domain: "acme.test." is not a domain root: no trailing dot'],
      [`--domain ${DOMAIN} --accept * --dir ${dir}`, 'usage', '--relay is required'],
      [`--domain ${DOMAIN} --relay ${RELAY} --dir ${dir}`, 'usage', '--accept is required'],
      [`--domain ${DOMAIN} ${b} --accept acme.test`, 'bad-record', '"acme.test" is not an address'],
      [`--domain ${DOMAIN} ${b} --handle Jane`, 'usage', `"Jane@${DOMAIN}" is not a handle`],
      [`--domain ${DOMAIN} ${b} --origin www`, 'usage', '--origin is apex or bag, not "www"'],
      [`--domain ${DOMAIN} ${b} --ttl 86401`, 'usage', '--ttl is at most 86400 seconds, not 86401'],
      [`--domain ${DOMAIN} ${b} --chain-exp 2592001`, 'usage', '--chain-exp is at most 2592000 seconds'],
      [`--domain ${DOMAIN} ${b} --org-key jane`, 'usage', '--org-key names the agent itself'],
      [`--domain ${DOMAIN} ${b} --org-key ${'o'.repeat(65)}`, 'usage', 'give --org-key'],
    ]
    for (const [args, code, detail] of cases) {
      const r = await cli(io, 'onboard', 'jane', ...args.split(' '))
      expect([r.code, r.out], args).toEqual([1, []])
      expect(r.err[0], args).toContain(`bag: ${code}: `)
      expect(r.err[0], args).toContain(detail)
    }
    expect(existsSync(dir)).toBe(false)
    expect(USAGE).toContain('  onboard <name> --domain <host> --relay <url>... --accept ')
  })
})
