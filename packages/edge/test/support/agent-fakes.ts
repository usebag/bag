import { openSealed, parseEnvelope, type SealedContent, type SealingKey } from '@usebag/core'
import type { EnvelopeOpener } from '../../src/ports.ts'

// The agent's opener, as a fake over a real sealing key (AgentOpener's shape): it opens a whole envelope and no bare
// wrap. It logs what it was asked, and `fail` makes the call throw. Public test data only.

export interface FakeOpener extends EnvelopeOpener {
  readonly log: Uint8Array[]
  /** `openEnvelope` waits for it: a test holds the open by replacing it with a promise it settles later. */
  gate: Promise<void>
  fail: Error | null
}

/** An EnvelopeOpener over `sealing`: `open` throws; `openEnvelope` logs the bytes, waits for `gate`, then opens. */
export function envelopeOpener(sealing: SealingKey, address: string): FakeOpener {
  const opener: FakeOpener = {
    publicKey: sealing.publicKey,
    log: [],
    gate: Promise.resolve(),
    fail: null,
    open(): never {
      throw new Error('an envelope opener opens no bare wrap')
    },
    async openEnvelope(bytes: Uint8Array): Promise<SealedContent> {
      opener.log.push(bytes)
      await opener.gate
      if (opener.fail !== null) throw opener.fail
      return openSealed(parseEnvelope(bytes), { address, key: sealing })
    },
  }
  return opener
}
