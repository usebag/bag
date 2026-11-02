import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'
import { ElicitRequestSchema, type ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { serializeRecord } from '@usebag/core'
import { FsKeyStore } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  cliProcess,
  type Party,
  party,
  REPO,
  rawPublish,
  world,
} from '../harness.ts'

// Scenario 52: two MCP servers as child processes on one real relay,
// each driven by an SDK client that declares form elicitation and answers its dialogs as a person would. Bob reads his
// six check digits out; Alice's dialog never shows them, and seeded wrong digits typed three times refuse to pair:
// digits-mismatch for her, nothing written, the relay still refusing Bob, and for him only the no-answer of an inviter
// who never answered. Then the same two pair on a new invitation with the digits he read out. Case b: a name the book
// holds stops at the first call, before a code goes out or a person is asked, where its baseline was the peer's whole
// ceremony; the same peer pairs again under for. Case c: a name
// another process adds to either book during a pairing stays there.

const MAIN = join(REPO, 'packages', 'mcp', 'src', 'main.ts')
/** The first invitation's life in seconds: Bob's no-answer waits for its end, and the request must fit inside it. */
const TTL = 8

type Json = Record<string, unknown>
type Person = (message: string) => ElicitResult

interface Side {
  readonly home: string
  /** Every dialog's message, in order: what the person saw. */
  readonly dialogs: string[]
  /** The person's answers to the next dialogs, in order; with none left a dialog is cancelled. */
  readonly person: Person[]
  /** Every tool result's text, to prove that none holds the digits. */
  readonly results: string[]
  call(tool: string, args: Json): Promise<{ readonly isError: boolean; readonly value: Json }>
  close(): Promise<void>
}

/** A party's key and records in a home of its own, and its server with a client that shows dialogs to `person`. */
async function side(p: Party, dir: string, url: string): Promise<Side> {
  const home = join(dir, `${p.name}-home`)
  new FsKeyStore(join(home, 'keys')).save(p.name, p.keys)
  for (const record of [addressRecord(p, { relays: [url] }), acceptFrom(p, [p.address])]) {
    expect((await rawPublish(url, serializeRecord(record))).status).toBe(200)
  }
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [MAIN, '--as', p.name, '--dir', home, '--relay', url],
    cwd: REPO,
    stderr: 'ignore',
  })
  const client = new Client(
    { name: `e2e-${p.name}`, version: '0.0.0' },
    { capabilities: { elicitation: { form: {} } } },
  )
  const dialogs: string[] = []
  const person: Person[] = []
  client.setRequestHandler(ElicitRequestSchema, async (r) => {
    // pair_invite's address question, left empty: first contact.
    if (
      'requestedSchema' in r.params &&
      Object.keys(r.params.requestedSchema.properties).join() === 'address'
    )
      return { action: 'accept', content: {} }
    dialogs.push(r.params.message)
    return person.shift()?.(r.params.message) ?? { action: 'cancel' }
  })
  await client.connect(transport)
  const results: string[] = []
  return {
    home,
    dialogs,
    person,
    results,
    async call(tool, args) {
      const r = await client.callTool({ name: tool, arguments: args }, undefined, { timeout: 60_000 })
      const text = (r.content as { text: string }[])[0]?.text ?? ''
      results.push(text)
      return { isError: r.isError === true, value: JSON.parse(text) as Json }
    },
    close: () => client.close(),
  }
}

const typed = (digits: string): Person => {
  return () => ({ action: 'accept', content: { digits } })
}

/** Alice invites; Bob's person pastes, reads the digits out and confirms: the digits, and each side's resume. */
async function requested(alice: Side, bob: Side, ttl: number, inviting: Json = {}, accepting: Json = {}) {
  const opened = await alice.call('pair_invite', { name: 'bob', ttl, ...inviting })
  const invite = (opened.value.code ?? opened.value.invite) as string
  let digits = ''
  bob.person.push(
    () => ({ action: 'accept', content: { invite } }),
    (message) => {
      digits = /^Check digits: (\d{3} \d{3})$/m.exec(message)?.[1] as string
      return { action: 'accept', content: { confirm: true } }
    },
  )
  const asked = await bob.call('pair_accept', { name: 'alice', ...accepting })
  expect(asked.value.requested).toBe(true)
  return { invite, digits, inviting: opened.value.resume, accepting: asked.value.resume }
}

/** I's records as anyone may read them from the relay, the invitation found through its nameplate. */
async function publicRecords(url: string, code: string): Promise<string[]> {
  const claim = await fetch(`${url}/v0/pair/claim/${code.split('-')[0]}`)
  const { invitation } = (await claim.json()) as { invitation: string }
  const read = async (kind: string) => (await fetch(`${url}/v0/fetch/record/${invitation}/${kind}`)).text()
  return Promise.all([read('address'), read('accept-from')])
}

/** Writes the name book of `s`: `name` is `address`. */
const holds = (s: Side, name: string, address: string): void => {
  const names = { [name]: { address, added_at: 1 } }
  writeFileSync(join(s.home, 'names.json'), JSON.stringify({ version: 1, names }))
}

/** The first call of `s` that is not pending. */
async function ended(s: Side, tool: string, resume: unknown): Promise<Json> {
  for (;;) {
    const { value } = await s.call(tool, { resume })
    if (value.pending !== true) return value
  }
}

describe('e2e scenario 52: typed check digits, one real relay', () => {
  it('(52) seeded wrong digits refuse to pair and reveal nothing; the digits read out pair', async () => {
    const w = await world('s52')
    const [A, B] = [party('alice'), party('bob')]
    const alice = await side(A, w.dir, w.url)
    const bob = await side(B, w.dir, w.url)
    try {
      const first = await requested(alice, bob, TTL)
      const open = await publicRecords(w.url, first.invite)
      const seeded = first.digits.replace(/^\d/, (d) => String((Number(d) + 1) % 10))
      alice.person.push(typed(seeded), typed(seeded), typed(seeded))
      const out = await alice.call('pair_invite', { resume: first.inviting })
      expect(out).toEqual({
        isError: true,
        value: { error: 'digits-mismatch', detail: 'the typed digits did not match: nothing was written' },
      })
      expect(alice.dialogs).toHaveLength(3)

      // No oracle in the relay's public reads either (ruling 9): the refusal changes none of I's records.
      expect(await publicRecords(w.url, first.invite)).toEqual(open)

      // No oracle: Bob's end is the no-answer of an inviter who never answered, and the relay still refuses him.
      expect((await ended(bob, 'pair_accept', first.accepting)).error).toBe('no-answer')
      const lapsed = JSON.parse(open[1] as string) as { roots: string[]; iat: number; ttl: number }
      expect(lapsed.roots).toEqual(['*'])
      expect(lapsed.iat + lapsed.ttl).toBeLessThanOrEqual(Math.ceil(Date.now() / 1000))
      const refused = await bob.call('send', { to: [A.address], type: 'chat.v1', body: 'hello' })
      expect([refused.isError, refused.value.error]).toEqual([true, 'root-not-accepted'])
      for (const s of [alice, bob]) {
        for (const f of ['names.json', 'trust.json']) expect(existsSync(join(s.home, f))).toBe(false)
      }

      // The audit keeps the tripwire; no dialog of Alice's, no result and no audit line holds the digits.
      const audit = readFileSync(join(alice.home, 'state', 'alice', 'audit.jsonl'), 'utf8')
      expect(audit).toContain('digits-mismatch')
      const seen = [...alice.dialogs, ...alice.results, ...bob.results, audit].join('\n')
      for (const d of [first.digits, first.digits.replace(' ', '')]) expect(seen).not.toContain(d)

      // The control: a new invitation, and the digits Bob reads out this time.
      const second = await requested(alice, bob, 600)
      alice.person.push(typed(second.digits))
      const [a, b] = await Promise.all([
        ended(alice, 'pair_invite', second.inviting),
        ended(bob, 'pair_accept', second.accepting),
      ])
      expect(a).toEqual({ paired: true, peer: B.address, name: 'bob' })
      expect(b).toEqual({ paired: true, peer: A.address, name: 'alice' })
      const hello = await bob.call('send', { to: ['alice'], type: 'chat.v1', body: 'hello' })
      expect(hello.isError).toBe(false)
    } finally {
      await Promise.all([alice.close(), bob.close()])
    }
  }, 60_000)

  it('(52b) a held name stops at the first call on either side; the same peer pairs again under for', async () => {
    const w = await world('s52b')
    const [A, B, C] = [party('alice'), party('bob'), party('carol')]
    const alice = await side(A, w.dir, w.url)
    const bob = await side(B, w.dir, w.url)
    try {
      holds(alice, 'bob', C.address)
      holds(bob, 'alice', C.address)
      const taken = async (s: Side, tool: string, name: string): Promise<void> => {
        const out = await s.call(tool, { name })
        expect(out.isError).toBe(true)
        expect(out.value.error).toBe('name-exists')
        expect(out.value.detail).toContain(`${name} is ${C.address}`)
      }
      await taken(alice, 'pair_invite', 'bob')
      await taken(bob, 'pair_accept', 'alice')
      expect([alice.dialogs, bob.dialogs]).toEqual([[], []])

      holds(alice, 'bob', B.address)
      holds(bob, 'alice', A.address)
      const again = await requested(alice, bob, 600, { for: B.address }, { for: A.address })
      alice.person.push(typed(again.digits))
      const [a, b] = await Promise.all([
        ended(alice, 'pair_invite', again.inviting),
        ended(bob, 'pair_accept', again.accepting),
      ])
      expect(a).toEqual({ paired: true, peer: B.address, name: 'bob' })
      expect(b).toEqual({ paired: true, peer: A.address, name: 'alice' })
    } finally {
      await Promise.all([alice.close(), bob.close()])
    }
  }, 60_000)

  it('(52c) a name another process adds during a pairing stays in both books', async () => {
    const w = await world('s52c')
    const [A, B, C] = [party('alice'), party('bob'), party('carol')]
    const alice = await side(A, w.dir, w.url)
    const bob = await side(B, w.dir, w.url)
    try {
      const pairing = await requested(alice, bob, 600)
      for (const s of [alice, bob]) {
        const added = await cliProcess(['name', 'add', 'dave', C.address, '--dir', s.home])
        expect(added.code).toBe(0)
      }
      alice.person.push(typed(pairing.digits))
      await Promise.all([
        ended(alice, 'pair_invite', pairing.inviting),
        ended(bob, 'pair_accept', pairing.accepting),
      ])
      const names = (s: Side): string[] => {
        const book = JSON.parse(readFileSync(join(s.home, 'names.json'), 'utf8')) as { names: Json }
        return Object.keys(book.names)
      }
      expect(names(alice)).toEqual(['bob', 'dave'])
      expect(names(bob)).toEqual(['alice', 'dave'])
    } finally {
      await Promise.all([alice.close(), bob.close()])
    }
  }, 60_000)
})
