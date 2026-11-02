import { describe, expect, it } from 'vitest'
import * as edge from '../src/index.ts'

describe('@usebag/edge public API', () => {
  it('names its package', () => {
    expect(edge.packageName()).toBe('@usebag/edge')
  })

  it('exports the Edge, its services, the adapters and the audit check', () => {
    for (const name of [
      'Edge',
      'Sender',
      'Receiver',
      'Resolver',
      'Policy',
      'Router',
      'Audit',
      'SqliteStore',
      'FsKeyStore',
      'FsAuditSink',
      'createRelayClient',
      'createHttpRelay',
      'createWsSubscriber',
      'createRecordSource',
      'webSocketFactory',
      'systemClock',
      'systemRng',
      'verifyAuditLog',
      'readAuditLines',
      'generateEdgeKeys',
      'RelayError',
      'EdgeError',
      'RelayGuard',
      'checkName',
      'digitsMatch',
      'MAX_DIGIT_TRIES',
      'classifyAddress',
      'acquireLock',
      'readAuditAnchor',
      'checkAuditAnchor',
      'retryWait',
      'TRANSIENT_CODES',
      'REFUSALS',
      'resubscribeDelay',
      'GuardRefused',
      'txtDns',
      'systemDns',
      'httpGet',
    ]) {
      expect(edge, name).toHaveProperty(name)
    }
  })

  it('reads the system clock in whole seconds and draws fresh bytes from the system rng', () => {
    const now = edge.systemClock.now()
    expect(Number.isSafeInteger(now)).toBe(true)
    expect(Math.abs(now - Date.now() / 1000)).toBeLessThan(2)
    const a = edge.systemRng.bytes(32)
    expect(a).toHaveLength(32)
    expect(edge.systemRng.bytes(32)).not.toEqual(a)
  })
})
