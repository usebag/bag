import { httpGet, systemClock, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import * as client from '../src/index.ts'

describe('@usebag/enterprise-client: the public API', () => {
  it('names its package', () => {
    expect(client.packageName()).toBe('@usebag/enterprise-client')
  })

  it('resolves its workspace dependencies through the package names', () => {
    expect(client.dependsOn()).toEqual(['@usebag/core', '@usebag/edge'])
  })

  it('exports the flow, the connect code, the records, the home, the ports and the MCP server by name', () => {
    expect(Object.keys(client).sort()).toEqual([
      'ACCEPT_MAX_BYTES',
      'ACCEPT_TTL',
      'ADDRESS_TTL',
      'AGENT_PATHS',
      'AGENT_TAGS',
      'CLOCKS',
      'CONNECT_CODE',
      'ENTERPRISE_RECORD_PATH',
      'EnterpriseError',
      'MAX_SOURCED_ROOTS',
      'MCP_TOOLS',
      'RESERVED_LABELS',
      'VERSION',
      'agentRecords',
      'bareOrigin',
      'bindNonce',
      'bindPreimage',
      'call',
      'chainPath',
      'chainText',
      'connect',
      'connectCodeOf',
      'createMcpServer',
      'defaultName',
      'dependsOn',
      'discoverInstance',
      'enterpriseDeps',
      'enterpriseDir',
      'enterpriseStatus',
      'fingerprint',
      'guardOrigin',
      'isLoopbackOrigin',
      'layerNonce',
      'lockPath',
      'outcomeLine',
      'ownerOnly',
      'packageName',
      'parseConnectCode',
      'pinnedInstance',
      'publishAgentRecords',
      'readPending',
      'readRecordsCopy',
      'readSession',
      'readTrustFile',
      'recordsDue',
      'recordsPath',
      'refreshDue',
      'refreshPreimage',
      'report',
      'reportedHash',
      'sayRelayFailures',
      'secureHome',
      'serveMcp',
      'signIn',
      'signInSecrets',
      'signInThroughAgent',
      'signOut',
      'statePreimage',
      'syncSourcedTrust',
      'systemPorts',
      'tick',
      'writeJson',
    ])
  })

  it("the version is the build's, else source", () => {
    expect(client.VERSION).toBe('source')
  })
})

describe('the ports', () => {
  it("systemPorts: the process's clock, CSPRNG, fetch and guarded GET, under the env given, with no relays", async () => {
    const env = { AC_HOME: '/nowhere' }
    const p = client.systemPorts(env)
    expect(p.env).toBe(env)
    expect([p.clock, p.rng, p.fetch, p.net.get]).toEqual([systemClock, systemRng, globalThis.fetch, httpGet])
    expect(typeof p.net.txt).toBe('function')
    expect(typeof p.net.guard.connectTo).toBe('function')
    expect(p.relays).toBeUndefined()
    await expect(p.sleep(1)).resolves.toBeUndefined()
    // A loopback URL never reaches DNS: the guard refuses it.
    await expect(p.net.guard.connectTo('https://127.0.0.1/')).rejects.toThrow()
  })

  it('enterpriseDeps: the ports, the home, the lines and the code source; relays only when given', async () => {
    const p = client.systemPorts({})
    const lines: string[] = []
    const d = client.enterpriseDeps(
      p,
      '/home/x/.bag',
      (l) => lines.push(l),
      async () => 'pasted',
    )
    expect([d.home, d.env, d.clock, d.rng, d.fetch, d.net, d.sleep]).toEqual([
      '/home/x/.bag',
      p.env,
      p.clock,
      p.rng,
      p.fetch,
      p.net,
      p.sleep,
    ])
    d.say('a line')
    expect([lines, await d.readCode()]).toEqual([['a line'], 'pasted'])
    expect('relays' in d).toBe(false)
    const relays = { publish: async () => ({}) as never }
    expect(
      client.enterpriseDeps(
        { ...p, relays },
        '/h',
        () => {},
        async () => null,
      ).relays,
    ).toBe(relays)
  })
})
