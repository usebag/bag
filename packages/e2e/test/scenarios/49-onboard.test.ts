import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join, resolve, sep } from 'node:path'
import { type Io, processIo, run, short } from '@usebag/cli'
import { parseTxtPresentation } from '@usebag/core'
import { createRecordSource, httpGet, type OriginGet } from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import { homeSecrets, withSpawnedRelays, world } from '../harness.ts'

// e2e scenario 49: two orgs onboard on their own domains with `onboard` alone,
// then exchange messages by handle, against the release relay. The CLI runs in-process (`run(argv, io)`); its io's
// record source is the edge's createRecordSource, whose GET maps https://<host>/<path> to a node:http server of
// this scenario that serves, by Host header, the directory onboard wrote (its --out, by default
// <home>/serve/<host>), and whose DNS answers the TXT record parsed from onboard's own `dns` line. Before the
// owner's two steps (host the tree; add the TXT) the first run exits 3, `self-check pending`; after them
// `onboard --check` exits 0, `self-check ok`. The relay reaches the same server through --well-known-resolve and
// asks no DNS (a test-only flag gives it the fixed table, empty here), so it reads each domain's record at the
// apex. Only onboard, send, inbox and lookup run: no deploy script, and no record, publish, keygen or delegate by
// hand. The send and inbox lines are the `next` lines onboard printed, filled in.

const ORGS = [
  { host: 'alpha.test', name: 'ana' },
  { host: 'beta.test', name: 'ben' },
] as const

/** One CLI run's exit code and lines. */
interface Ran {
  readonly code: number
  readonly out: string[]
  readonly err: string[]
}

/** An org once onboarded: what onboard printed and the paths it named. */
interface Org {
  readonly host: string
  readonly name: string
  readonly home: string
  readonly handle: string
  readonly org: string
  readonly agent: string
  readonly chain: string
  readonly next: readonly string[]
}

/** A static host for the trees onboard wrote: GET of a file under a host's root, by Host; else 404. */
async function staticHost(): Promise<{
  readonly port: number
  readonly roots: Map<string, string>
  readonly asked: string[]
}> {
  const roots = new Map<string, string>()
  const asked: string[] = []
  const served = (host: string, path: string): Buffer | null => {
    const root = roots.get(host)
    if (root === undefined) return null
    const file = resolve(root, `.${path}`)
    if (!file.startsWith(`${root}${sep}`)) return null
    return lstatSync(file, { throwIfNoEntry: false })?.isFile() === true ? readFileSync(file) : null
  }
  const server = createServer((req, res) => {
    const host = String(req.headers.host).replace(/:\d+$/, '')
    const path = decodeURIComponent((req.url ?? '/').split('?')[0] as string)
    asked.push(`${host} ${path}`)
    const body = req.method === 'GET' ? served(host, path) : null
    if (body === null) res.writeHead(404).end()
    else res.writeHead(200, { 'content-type': 'application/json' }).end(body)
  })
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  onTestFinished(
    () =>
      new Promise<void>((done) => {
        server.closeAllConnections()
        server.close(() => done())
      }),
  )
  return { port: (server.address() as AddressInfo).port, roots, asked }
}

/** The one line of `lines` that starts with `prefix`. */
function line(lines: readonly string[], prefix: string): string {
  const found = lines.filter((l) => l.startsWith(prefix))
  expect(found, prefix).toHaveLength(1)
  return found[0] as string
}

/** The group `n` of `pattern` in `text`. */
function group(text: string, pattern: RegExp, n = 1): string {
  const m = text.match(pattern)
  expect(m, `${text} ${pattern}`).not.toBeNull()
  return (m as RegExpMatchArray)[n] as string
}

describe('e2e scenario 49: onboard on two domains, then a first exchange by handle', () => {
  it('(49) each org: onboard exits 3 pending; the owner serves the tree and adds the printed TXT; --check exits 0; the trust file of each home holds the domain root of the other; then each agent sends to the other by handle under the printed chain and inbox accepts it with no --trust-root, both ways; only onboard, send, inbox and lookup ran; no key printed', async () => {
    const site = await staticHost()
    const relayArgs = [
      '--bind',
      '127.0.0.1',
      '--well-known-insecure-http',
      ...ORGS.flatMap((o) => ['--well-known-resolve', `${o.host}=127.0.0.1:${site.port}`]),
    ]
    const w = await withSpawnedRelays(() => world('s49', { relayArgs }))
    const R = w.url

    // The DNS of the test domains: empty until a step adds the TXT record onboard printed.
    const zone = new Map<string, string[][]>()
    const dns = { txt: async (name: string) => zone.get(name.replace(/\.$/, '')) ?? [] }
    // https://<host>/<path> at the static host, through the edge's own GET (no redirect, a size cap).
    const get: OriginGet = (url, _connect, timeoutMs, cap) => {
      const u = new URL(url)
      if (u.protocol !== 'https:' || u.port !== '' || u.search !== '') {
        return Promise.reject(new Error(`the CLI asked ${url}, not an https origin on 443`))
      }
      return httpGet(`http://${u.hostname}:${site.port}${u.pathname}`, '127.0.0.1', timeoutMs, cap)
    }
    const base = processIo()
    const commands: string[] = []
    const outputs: string[] = []
    const ac = async (...argv: string[]): Promise<Ran> => {
      const out: string[] = []
      const err: string[] = []
      const io: Io = {
        ...base,
        env: {},
        idleMs: 2000,
        out: (l) => {
          out.push(l)
        },
        err: (l) => {
          err.push(l)
        },
        records: (client) => createRecordSource(client, { get, dns }),
      }
      commands.push(argv[0] as string)
      const code = await run(argv, io)
      outputs.push(...out, ...err)
      return { code, out, err }
    }

    const started = Date.now()
    const orgs: Org[] = []
    for (const [i, { host, name }] of ORGS.entries()) {
      const other = ORGS[1 - i]?.host as string
      const home = resolve(w.dir, `home-${host}`)
      expect(existsSync(home)).toBe(false)
      const handle = `${name}@${host}`
      const accept = ['--accept', `domain:${other}`, '--allow-private-relays', '--dir', home]
      const args = ['onboard', name, '--domain', host, '--relay', R, ...accept]

      // The first run: everything written and published; the domain serves nothing yet.
      const first = await ac(...args)
      expect([first.code, first.err, first.out.at(-1)]).toEqual([
        3,
        [],
        `self-check pending ${handle}: not resolving yet; do steps 1 and 2, then run again with --check`,
      ])
      const org = group(line(first.out, `key org-${host} `), /^key \S+ (\S+) new$/)
      const agent = group(line(first.out, `key ${name} `), /^key \S+ (\S+) new$/)
      const out = join(home, 'serve', host)
      const tree = join(out, '.well-known', 'bag')
      const chain = join(home, `${name}.chain.json`)
      expect(first.out.slice(2, 7)).toEqual([
        `wrote ${join(tree, 'address.json')}`,
        `wrote ${join(tree, 'handles', `${name}.json`)}`,
        `published key ${agent} ${R}`,
        `published address ${agent} ${R}`,
        `published accept-from ${agent} ${R}`,
      ])
      // The typed domain root is stored in the trust file (domain:<host>, no port); nothing by address.
      expect(first.out.filter((l) => l.startsWith('trust '))).toEqual([`trust domain:${other}`])
      const trustFile = JSON.parse(readFileSync(join(home, 'trust.json'), 'utf8')) as { roots: object }
      expect(Object.keys(trustFile.roots)).toEqual([`domain:${other}`])
      const exp = Number(group(line(first.out, 'chain '), /^chain \S+ root \S+ exp (\d+)$/))
      expect(line(first.out, 'chain ')).toBe(`chain ${chain} root ${org} exp ${exp}`)
      expect(exp - Math.floor(started / 1000)).toBeGreaterThanOrEqual(604_800)
      expect(line(first.out, 'step 1: ')).toBe(
        `step 1: serve ${out} as the root of https://${host}/ (HTTPS on port 443; each file a 200 with no redirect, as application/json), so that these answer:`,
      )
      const urls = first.out.filter((l) => l.startsWith('url '))
      expect(urls).toEqual([
        `url https://${host}/.well-known/bag/address.json`,
        `url https://${host}/.well-known/bag/handles/${name}.json`,
      ])
      expect(line(first.out, 'step 2: ')).toBe(`step 2: add this TXT record to the DNS of ${host}:`)
      const txt = line(first.out, 'dns ')
      expect(txt).toBe(`dns _bag.${host}.  IN  TXT  "v=ac1; key=${org}"`)
      expect(first.out).toContain(`check _bag.${host} none kind=txt origin https://${host}`)
      expect(site.asked).toContain(`${host} /.well-known/bag/address.json`)

      // The tree a static host serves: the two records, nothing else.
      expect(readdirSync(out, { recursive: true, encoding: 'utf8' }).sort()).toEqual([
        '.well-known',
        '.well-known/bag',
        '.well-known/bag/address.json',
        '.well-known/bag/handles',
        `.well-known/bag/handles/${name}.json`,
      ])

      // The owner's two steps, read from what onboard printed: serve <out> at https://<host>/; add the TXT.
      const step1 = line(first.out, 'step 1: ')
      const served = /^step 1: serve (\S+) as the root of https:\/\/([^/]+)\/ /
      site.roots.set(group(step1, served, 2), group(step1, served, 1))
      const record = /^dns (\S+)\s+IN\s+TXT\s+(.+)$/
      zone.set(group(txt, record, 1).replace(/\.$/, ''), [parseTxtPresentation(group(txt, record, 2))])

      const check = await ac(...args, '--check')
      expect([check.code, check.err, check.out.at(-1)]).toEqual([0, [], `self-check ok ${handle}`])
      const found = `check _bag.${host} found kind=txt key=${org} origin https://${host}`
      expect(check.out).toContain(found)
      expect(check.out.some((l) => / found kind=handle /.test(l))).toBe(true)
      // Forward secrecy: the agent's address record names no sealing key; its key record is served.
      expect(check.out.some((l) => / found kind=key /.test(l))).toBe(true)
      for (const url of urls) expect(site.asked).toContain(`${host} ${new URL(url.slice(4)).pathname}`)
      const next = first.out.filter((l) => l.startsWith('next '))
      orgs.push({ host, name, home, handle, org, agent, chain, next })
    }
    const [A, B] = orgs as [Org, Org]

    // The inviter's side resolves the partner's domain root (P5's `domain:` run).
    const lookupAs = ['--as', B.name, '--relay', R, '--allow-private-relays', '--dir', B.home]
    const looked = await ac('lookup', `domain:${A.host}`, ...lookupAs)
    expect([looked.code, looked.err]).toEqual([0, []])
    const viaTxt = `_bag.${A.host} found kind=txt key=${A.org} origin https://${A.host}`
    expect(looked.out).toContain(viaTxt)
    const wellKnown = `https://${A.host}/.well-known/bag/address.json found kind=address `
    expect(line(looked.out, wellKnown)).toContain(`key=${A.org}`)

    /** The send onboard printed for `from`, filled in: to a handle, a type and a body. */
    const sendAs = (from: Org, to: Org, body: string): string[] => {
      const words = (from.next.find((l) => l.includes(' send --as ')) as string).split(' ')
      const fill: Record<string, string> = {
        '<handle|address>': to.handle,
        '<type>': 'chat.v1',
        '<json>': body,
      }
      const argv = words.slice(words.indexOf('send')).map((x) => fill[x] ?? x)
      expect(argv).toEqual([
        'send',
        '--as',
        from.name,
        '--auth',
        from.chain,
        '--to',
        to.handle,
        '--relay',
        R,
        '--type',
        'chat.v1',
        '--body',
        body,
        '--dir',
        from.home,
      ])
      return [...argv, '--allow-private-relays']
    }
    /** The inbox onboard printed for `of`, once: no --trust-root, the trust file holds the domain root. */
    const inboxOf = (of: Org): string[] => {
      const words = (of.next.find((l) => l.includes(' inbox --as ')) as string).split(' ')
      const argv = words.slice(words.indexOf('inbox'))
      const want = ['inbox', '--as', of.name, '--relay', R, '--dir', of.home]
      expect(argv).toEqual(want)
      return [...argv, '--once', '--allow-private-relays']
    }

    // B to A by handle, under B's chain; A's inbox, trusting B's domain root from its trust file, accepts
    // it. A has not resolved B's handle, so A's line names B by address.
    const there = JSON.stringify({ text: `hello ${A.handle}` })
    const sent = await ac(...sendAs(B, A, there))
    expect([sent.code, sent.err, sent.out.length]).toEqual([0, [], 2])
    expect(sent.out[1]).toMatch(/^published /)
    const atA = await ac(...inboxOf(A))
    expect([atA.code, atA.err]).toEqual([0, []])
    expect(atA.out).toEqual([`accept ${sent.out[0]} ${B.agent} ${B.org} chat.v1 ${there}`])

    // A replies to B by handle; B resolved A's handle to send, so B's line names A by that handle, then A's
    // short address (inbox's label: the sender's handle under onboard's one-hop chain, signed by its root).
    const back = JSON.stringify({ text: `hello ${B.handle}` })
    const replied = await ac(...sendAs(A, B, back))
    expect([replied.code, replied.err, replied.out.length]).toEqual([0, [], 2])
    expect(replied.out[1]).toMatch(/^published /)
    const atB = await ac(...inboxOf(B))
    expect([atB.code, atB.err]).toEqual([0, []])
    const named = `${A.handle} (${short(A.agent)})`
    expect(atB.out).toEqual([`accept ${replied.out[0]} ${named} ${A.org} chat.v1 ${back}`])
    const wall = Date.now() - started

    // Only onboard, send, inbox and lookup ran: no keygen, record, publish or delegate, no script.
    const ran = [...new Set(commands)].sort()
    expect(ran).toEqual(['inbox', 'lookup', 'onboard', 'send'])
    // No output holds a private key of either home.
    const secrets = orgs.flatMap((o) => homeSecrets(o.home, [`org-${o.host}`, o.name]))
    const all = outputs.join('\n')
    expect(secrets.filter((s) => all.includes(s))).toEqual([])
    console.log(
      `MEASURE (scenario 49): 2 orgs onboarded by onboard alone (exit 3 pending, then --check exit 0) and a first exchange by handle both ways, ${commands.length} commands (${ran.join(', ')}), wall ${wall} ms`,
    )
  }, 90_000)
})
