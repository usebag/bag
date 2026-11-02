import { describe, expect, it } from 'vitest'
import * as edge from '../src/index.ts'

describe('@usebag/edge exports the custody port, its two custodies and the home', () => {
  it('names each by its export', () => {
    for (const name of [
      'FsKeyStore',
      'KeychainCustody',
      'HomeCustody',
      'runSecurity',
      'createSecurityRunner',
      'securityEnv',
      'SECURITY_PATH',
      'SECURITY_TIMEOUT_MS',
    ]) {
      expect(edge, name).toHaveProperty(name)
    }
    expect([edge.SECURITY_PATH, edge.SECURITY_TIMEOUT_MS]).toEqual(['/usr/bin/security', 300_000])
  })
})
