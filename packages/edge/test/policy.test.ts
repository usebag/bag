import { codingEvaluator } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Audit } from '../src/audit.ts'
import { Policy, typeMatches } from '../src/policy.ts'
import { Resolver } from '../src/resolver.ts'
import { FakeClock, FakeRecords, MemoryAuditSink, P, T0 } from './support/fixtures.ts'

function resolver(): Resolver {
  const clock = new FakeClock()
  return new Resolver({
    store: new SqliteStore(':memory:'),
    source: new FakeRecords(),
    clock,
    audit: new Audit(new MemoryAuditSink(), clock),
    relays: [],
  })
}

describe('Policy (spec/SPEC.md §9.5)', () => {
  it('matches accepted types: exact, "<prefix>.*" and "*"', () => {
    expect(typeMatches('chat.v1', 'chat.v1')).toBe(true)
    expect(typeMatches('chat.v1', 'chat.v2')).toBe(false)
    expect(typeMatches('coding.*', 'coding.task.v1')).toBe(true)
    expect(typeMatches('coding.*', 'coding')).toBe(false)
    expect(typeMatches('coding.*', 'codingx.task')).toBe(false)
    expect(typeMatches('*', 'anything')).toBe(true)
  })

  it('takes a trusted root as a domain with an optional key, or an address, and nothing else', () => {
    const r = resolver()
    const good = [
      { domain: 'acme.test' },
      { domain: 'acme.test', key: P.org.address },
      { address: P.carol.address },
    ]
    expect(() => new Policy({ roots: good, types: [] }, r)).not.toThrow()
    const bad = [
      {},
      { address: 'carol' },
      { address: P.carol.address, key: P.org.address },
      { domain: 'acme.test', address: P.carol.address },
      { domain: 'acme.test', key: 'org' },
    ]
    for (const root of bad) {
      expect(() => new Policy({ roots: [root], types: [] }, r), JSON.stringify(root)).toThrow(
        'policy: a trusted root',
      )
    }
  })

  it('accepts only configured types, and evaluates caveats with the honored evaluators only', () => {
    const p = new Policy({ roots: [], types: ['chat.*'], evaluators: [codingEvaluator] }, resolver())
    expect(p.acceptsType('chat.v1')).toBe(true)
    expect(p.acceptsType('coding.v1')).toBe(false)
    const sealed = { type: 'coding.task', thread: { id: 'a'.repeat(64), prev: [] }, body: {} }
    const ctx = { from: P.carol.address, to: [P.bob.address], ts: T0, root: P.carol.address, sealed }
    expect(p.caveats(['type=coding.*'], ctx)).toEqual({ ok: true })
    expect(new Policy({ roots: [], types: [] }, resolver()).caveats(['type=coding.*'], ctx)).toEqual({
      ok: false,
      code: 'unknown-caveat',
      caveat: 'type=coding.*',
    })
  })

  it('rejects an untrusted root when it trusts no domain, and admits a trusted key with no hops', async () => {
    const p = new Policy({ roots: [{ address: P.carol.address }], types: [] }, resolver())
    await expect(
      p.admit({ root: P.mallory.address, principal: P.mallory.address, caveats: [] }, []),
    ).rejects.toMatchObject({
      code: 'untrusted-root',
    })
    await expect(
      p.admit({ root: P.carol.address, principal: P.carol.address, caveats: [] }, []),
    ).resolves.toBeUndefined()
  })
})
