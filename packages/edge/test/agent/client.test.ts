import { type Hop, hopPreimage, signHop, verifyPreimage } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { type AgentClient, AgentOpener, AgentSigner } from '../../src/agent/client.ts'
import { P } from '../support/fixtures.ts'
import { CAVEAT, EXP, envelope, text } from './support.ts'

// The client's signer and opener, over a stub of the connection: what they ask the
// agent, and what they refuse before asking.

const J = P.jane.address
const S = P.session.address
const HOP = hopPreimage({ iss: J, sub: S, caveats: [CAVEAT], exp: EXP })

/** A connection that answers `sign` with `hop` (the jane-signed hop asked for by default) and counts its calls. */
function stub(hop?: (sub: string, caveats: readonly string[], exp: number) => Hop) {
  const calls: unknown[][] = []
  const client = {
    sign: async (sub: string, caveats: readonly string[], exp: number) => {
      calls.push(['sign', sub, caveats, exp])
      return hop === undefined ? signHop(P.jane.signing, sub, caveats, exp) : hop(sub, caveats, exp)
    },
    open: async (mailbox: string, id: string, envelope: string) => {
      calls.push(['open', mailbox, id, envelope])
      return { type: 't', thread: { id: 'a'.repeat(64), prev: [] }, body: 1 }
    },
  } as unknown as AgentClient
  return { calls, client: () => client }
}

describe('AgentSigner: the principal signs a hop preimage and nothing else', () => {
  it('returns the signature of the hop it asked the agent for, and never signs a digest', async () => {
    const { calls, client } = stub()
    const signer = new AgentSigner(J, client)
    const sig = await signer.signPreimage(HOP)
    expect(verifyPreimage(J, HOP, sig)).toBe(true)
    expect(calls).toEqual([['sign', S, [CAVEAT], EXP]])
    expect(signer.address).toBe(J)
    expect(() => signer.sign()).toThrow('never a digest')
  })

  it('refuses any other preimage without asking the agent', async () => {
    const { calls, client } = stub()
    const signer = new AgentSigner(J, client)
    const bad = [
      'text',
      ['ac/fetch/1', J, S, [CAVEAT], EXP],
      ['ac/hop/1', P.bob.address, S, [CAVEAT], EXP],
      ['ac/hop/1', J, S, [CAVEAT], EXP, 'more'],
      ['ac/hop/1', J, 5, [CAVEAT], EXP],
      ['ac/hop/1', J, S, 'caveat', EXP],
      ['ac/hop/1', J, S, [CAVEAT], 'exp'],
    ]
    for (const preimage of bad) {
      await expect(signer.signPreimage(preimage)).rejects.toMatchObject({ code: 'not-authorized' })
    }
    expect(calls).toEqual([])
  })

  it("refuses a hop another key issued, and a signature that is not the principal's", async () => {
    const bobs = stub((sub, caveats, exp) => signHop(P.bob.signing, sub, caveats, exp))
    await expect(new AgentSigner(J, bobs.client).signPreimage(HOP)).rejects.toMatchObject({ code: 'bad-hop' })
    const forged = stub((sub, caveats, exp) => ({
      ...signHop(P.jane.signing, sub, caveats, exp),
      sig: signHop(P.bob.signing, sub, caveats, exp).sig,
    }))
    await expect(new AgentSigner(J, forged.client).signPreimage(HOP)).rejects.toMatchObject({
      code: 'bad-sig',
    })
  })

  it('refuses a signature for another hop than the one asked', async () => {
    const other = stub((sub, caveats, exp) => signHop(P.jane.signing, sub, caveats, exp - 1))
    await expect(new AgentSigner(J, other.client).signPreimage(HOP)).rejects.toMatchObject({
      code: 'bad-hop',
    })
  })
})

describe('AgentOpener: whole envelopes, through the read rule', () => {
  it('opens an envelope by its id and exact text, and never a bare wrap', async () => {
    const { calls, client } = stub()
    const opener = new AgentOpener(J, P.jane.sealing.publicKey, client)
    const env = envelope()
    expect((await opener.openEnvelope(env.bytes)).type).toBe('t')
    expect(calls).toEqual([['open', J, env.envelope.id, text(env)]])
    expect(opener.publicKey).toBe(P.jane.sealing.publicKey)
    expect(() => opener.open()).toThrow('never a bare wrap')
  })
})
