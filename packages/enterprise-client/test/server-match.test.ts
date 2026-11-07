import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { type CanonicalValue, canonical, preimageDigest, toHex, verifyPreimage } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { bindNonce, reportedHash } from '../src/layer-auth.ts'

// The client's vectors (test/fixtures/bag-ent-auth.json) against the instance that verifies them, without the
// instance's code: its agent-contract vectors (test/fixtures/agent-contract-vectors.json, copied as the instance pins
// them) are all among the client's, the client's nonce and hash functions reproduce them, an independent sha256 of
// each preimage's canonical bytes gives its digest, and the strict check takes every positive signature and refuses
// every negative one. A change on either side that splits them fails here.

const read = (name: string) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'))
const V = read('bag-ent-auth.json')
const CONTRACT = read('agent-contract-vectors.json')
type Relays = { url: string; last_subscribed_at: number }[]
type Signed = { name: string; address: string; preimage: CanonicalValue[]; sig: string; sha256?: string }
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex')

describe('the client vectors and the instance contract', () => {
  it("holds every agent-contract vector of the instance, by the client's functions and by plain sha256", () => {
    expect(CONTRACT.bind_nonce.length).toBeGreaterThan(0)
    for (const c of CONTRACT.bind_nonce as { secret: string; nonce: string }[]) {
      expect(bindNonce(c.secret)).toBe(c.nonce)
      expect(sha256(`bag-ent/bind-nonce/1\n${c.secret}`)).toBe(c.nonce)
      expect(V.bind_nonce.cases).toContainEqual({ secret: c.secret, bind_nonce: c.nonce })
    }
    expect(CONTRACT.reported_hash.length).toBeGreaterThan(0)
    for (const c of CONTRACT.reported_hash as {
      reported_relays: Relays
      canonical: string
      hash: string
    }[]) {
      expect(canonical(c.reported_relays.map((r) => [r.url, r.last_subscribed_at]))).toBe(c.canonical)
      expect(reportedHash(c.reported_relays)).toBe(c.hash)
      expect(sha256(c.canonical)).toBe(c.hash)
      expect(V.reported_hash.cases).toContainEqual({
        reported_relays: c.reported_relays,
        reported_hash: c.hash,
      })
    }
  })

  it('reproduces every nonce, hash and digest of the client vectors independently', () => {
    for (const c of V.bind_nonce.cases as { secret: string; bind_nonce: string }[])
      expect(sha256(`bag-ent/bind-nonce/1\n${c.secret}`)).toBe(c.bind_nonce)
    for (const c of V.reported_hash.cases as { reported_relays: Relays; reported_hash: string }[])
      expect(sha256(canonical(c.reported_relays.map((r) => [r.url, r.last_subscribed_at])))).toBe(
        c.reported_hash,
      )
    for (const c of V.positive.cases as Signed[]) {
      expect(sha256(canonical(c.preimage)), c.name).toBe(c.sha256)
      expect(toHex(preimageDigest(c.preimage)), c.name).toBe(c.sha256)
    }
  })

  it('the strict check takes every positive signature and refuses every negative one', () => {
    for (const c of V.positive.cases as Signed[])
      expect(verifyPreimage(c.address, c.preimage, c.sig), c.name).toBe(true)
    const negative = V.negative.cases as Signed[]
    expect(negative.length).toBeGreaterThan(10)
    for (const c of negative) expect(verifyPreimage(c.address, c.preimage, c.sig), c.name).toBe(false)
  })
})
