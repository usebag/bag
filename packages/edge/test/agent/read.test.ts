import { createCipheriv } from 'node:crypto'
import {
  assembleEnvelope,
  concatBytes,
  contentAad,
  envelopeId,
  fromHex,
  MAX_ENVELOPE_BYTES,
  newThread,
  type OpenerLike,
  replyThread,
  signHop,
  toHex,
  type UnsignedEnvelope,
  utf8,
} from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { OPENS_PER_MINUTE, THREADS_PER_SESSION } from '../../src/agent/index.ts'
import { P, T0 } from '../support/fixtures.ts'
import {
  coreRng,
  EXP,
  envelope,
  grant,
  JANE_KEYS,
  lines,
  refusal,
  Session,
  session,
  setup,
  text,
  threadId,
} from './support.ts'

// What the agent opens and releases: the envelope checks before any opening, the read rule
// (a registered thread, or a root message the caveats admit) with one code for every withheld read, the registered
// threads' lifetime, the `open` audit and the caps on openings and threads.

const J = P.jane.address
const S = P.session.address
const B = P.bob.address
const BOB_KEY_FOR_JANE = { address: J, sealingKey: P.bob.sealing.publicKey }

function lastLine(sink: Parameters<typeof lines>[0]): Record<string, unknown> | undefined {
  return lines(sink).at(-1)
}

describe('the envelope checks before opening', () => {
  it("opens the principal's own mailbox only, not-authorized for another, audited with no limb", () => {
    const { agent, sink } = setup()
    const env = envelope()
    expect(session(agent).open(env, B)).toEqual(refusal('not-authorized'))
    expect(lastLine(sink)).toMatchObject({
      event: 'open',
      decision: 'reject',
      reason: 'not-authorized',
      id: env.envelope.id,
      from: S,
      root: J,
      detail: JSON.stringify({ mailbox: B }),
    })
  })

  it('refuses each envelope failure with its own code', () => {
    const { agent } = setup()
    const s = session(agent)
    const env = envelope()
    const id = env.envelope.id
    const t = text(env)
    expect(s.send('open', [J, id], { envelope: 'nope' })).toEqual(refusal('bad-json'))
    expect(s.send('open', [J, threadId(9)], { envelope: t })).toEqual(refusal('bad-shape'))
    const forgedId = threadId(7)
    expect(s.send('open', [J, forgedId], { envelope: t.replace(id, forgedId) })).toEqual(refusal('bad-id'))
    const badSig = t.replace(env.envelope.sig, '00'.repeat(64))
    expect(s.send('open', [J, id], { envelope: badSig })).toEqual(refusal('bad-sig'))
    const toBob = envelope({ to: [{ address: B, sealingKey: P.bob.sealing.publicKey }] })
    expect(s.open(toBob)).toEqual(refusal('not-recipient'))
    expect(s.open(envelope({ to: [BOB_KEY_FOR_JANE] }))).toEqual(refusal('open-failed'))
    // refused while parsing, so it spends no seq and is the last request here
    expect(s.send('open', [J, id], { envelope: ' '.repeat(MAX_ENVELOPE_BYTES + 1) })).toEqual(
      refusal('envelope-too-large'),
    )
  })

  it('refuses a content whose type holds a control character bad-content', () => {
    const key = new Uint8Array(32).fill(7)
    const opener: OpenerLike = { open: () => key }
    const { agent } = setup({ sealing: opener })
    const nonce = new Uint8Array(12).fill(1)
    const type = `coding${String.fromCharCode(0x85)}task`
    const plaintext = utf8(JSON.stringify({ type, thread: { id: threadId(1), prev: [] }, body: 1 }))
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
    cipher.setAAD(contentAad([J], B))
    const ct = concatBytes(cipher.update(plaintext), cipher.final(), cipher.getAuthTag())
    const wraps = [{ to: J, enc: '11'.repeat(32), ct: '22'.repeat(48) }]
    const sealed = { wraps, nonce: toHex(nonce), ct: toHex(ct) }
    const unsigned: UnsignedEnvelope = { v: 1, to: [J], from: B, auth: [], suite: 1, ts: T0, sealed }
    const built = assembleEnvelope(unsigned, toHex(P.bob.signing.sign(fromHex(envelopeId(unsigned)))))
    expect(session(agent).open(built)).toEqual(refusal('bad-content'))
  })

  it('lets an opener that fails with other than a code propagate, a fault and not a verdict', () => {
    const opener: OpenerLike = {
      open: () => {
        throw new Error('the keychain went away')
      },
    }
    const { agent } = setup({ sealing: opener })
    const s = session(agent)
    expect(() => s.open(envelope())).toThrow('the keychain went away')
  })
})

describe('the read rule', () => {
  it('releases a root message the caveats admit, and audits the limb', () => {
    const { agent, sink } = setup()
    const env = envelope()
    const reply = session(agent).open(env)
    expect(reply).toMatchObject({
      ok: true,
      op: 'open',
      content: { type: 'coding.task.v1', body: { repo: 'r' } },
    })
    const detail = JSON.stringify({ mailbox: J, rule: 'root' })
    expect(lastLine(sink)).toMatchObject({ decision: 'accept', reason: 'ok', id: env.envelope.id, detail })
  })

  it('withholds a root message the caveats refuse as not-in-grant, the precise reason in the audit alone', () => {
    const { agent, sink } = setup()
    const chat = envelope({ type: 'chat.v1' })
    expect(session(agent).open(chat)).toEqual(refusal('not-in-grant'))
    expect(lastLine(sink)).toMatchObject({
      reason: 'caveat-failed',
      detail: JSON.stringify({ mailbox: J, rule: 'root' }),
    })
    const odd = session(agent, P.mallory.signing, [grant(agent, P.mallory.address, ['zzz=1'])])
    expect(odd.open(envelope())).toEqual(refusal('not-in-grant'))
    expect(lastLine(sink)).toMatchObject({ reason: 'unknown-caveat' })
    expect(sink.lines.join('\n')).not.toContain('chat.v1')
  })

  it('releases a reply on a registered thread and withholds one on any other', () => {
    const { agent, sink } = setup()
    const s = session(agent)
    const thread = newThread(coreRng('task'))
    const reply = envelope({ type: 'coding.result.v1', thread: replyThread(thread, [threadId(3)]) })
    expect(s.open(reply)).toEqual(refusal('not-in-grant'))
    expect(lastLine(sink)).toMatchObject({
      reason: 'not-in-grant',
      detail: JSON.stringify({ mailbox: J, rule: 'thread' }),
    })
    expect(s.register(thread.id)).toEqual({ ok: true, op: 'register' })
    expect(s.open(reply)).toMatchObject({ ok: true, content: { type: 'coding.result.v1' } })
    expect(lastLine(sink)).toMatchObject({
      reason: 'ok',
      detail: JSON.stringify({ mailbox: J, rule: 'thread' }),
    })
    expect(sink.lines.join('\n')).not.toContain(thread.id)
  })

  it('keeps registered threads across a reconnect and drops them at logout', () => {
    const { agent } = setup()
    const s = session(agent)
    const thread = newThread(coreRng('kept'))
    const reply = envelope({ thread: replyThread(thread, [threadId(4)]) })
    expect(s.register(thread.id)).toEqual({ ok: true, op: 'register' })
    agent.disconnect(s.conn)
    expect(new Session(agent, P.session.signing, s.chain).open(reply)).toMatchObject({ ok: true })
    agent.logout()
    agent.login(JANE_KEYS)
    expect(session(agent).open(reply)).toEqual(refusal('not-in-grant'))
  })

  it("opens an envelope whose sender acts through a chain, judged against that chain's root", () => {
    const { agent } = setup()
    const auth = [signHop(P.bob.signing, P.carol.address, [], EXP)]
    expect(session(agent).open(envelope({ from: P.carol, auth }))).toMatchObject({ ok: true })
  })
})

describe('the caps on openings and threads', () => {
  it('opens 600 a minute per session, rate-limited after', () => {
    const { agent } = setup()
    const s = session(agent)
    const env = envelope()
    for (let i = 0; i < OPENS_PER_MINUTE; i++) expect(s.open(env, B)).toEqual(refusal('not-authorized'))
    expect(s.open(env, B)).toEqual(refusal('rate-limited'))
  })

  it('registers 4,096 threads per session, rate-limited after, a known one still taken', () => {
    const { agent } = setup()
    const s = session(agent)
    for (let i = 0; i < THREADS_PER_SESSION; i++) expect(s.register(threadId(i)).ok).toBe(true)
    expect(s.register(threadId(THREADS_PER_SESSION))).toEqual(refusal('rate-limited'))
    expect(s.register(threadId(0))).toEqual({ ok: true, op: 'register' })
  })
})
