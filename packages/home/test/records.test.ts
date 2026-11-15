import { serializeRecord } from '@usebag/core'
import { generateEdgeKeys, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { newestAccept, ownRecord } from '../src/index.ts'
import { acceptFrom, client, FakeRelay, publishAt } from './support.ts'

// An identity's own records at the relays, each checked by the core.

const R1 = 'https://r1.example'
const R2 = 'https://r2.example'

describe('newestAccept and ownRecord', () => {
  it('is null when no relay holds one, else the newest of them', async () => {
    const net = new FakeRelay()
    const { signing } = generateEdgeKeys(systemRng)
    expect(await newestAccept(client(net), [R1, R2], signing.address)).toBeNull()
    await publishAt(net, acceptFrom(signing, [signing.address], 10), R1)
    await publishAt(net, acceptFrom(signing, [signing.address], 20), R2)
    expect((await newestAccept(client(net), [R1, R2], signing.address))?.iat).toBe(20)
    expect((await newestAccept(client(net), [R2, R1], signing.address))?.iat).toBe(20)
    expect(await ownRecord(client(net), R1, signing.address, 'address')).toBeNull()
  })

  it("refuses another signer's record served for this one (bad-record)", async () => {
    const net = new FakeRelay()
    const own = generateEdgeKeys(systemRng).signing
    const other = generateEdgeKeys(systemRng).signing
    net.records.set(
      `${R1} ${own.address} accept-from`,
      serializeRecord(acceptFrom(other, [other.address], 1)),
    )
    await expect(newestAccept(client(net), [R1], own.address)).rejects.toThrow(
      `bad-record: ${R1} answered the accept-from record of ${other.address} for the accept-from record of ${own.address}`,
    )
  })
})
