import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { writeTrustFile as enterpriseWrite } from '@usebag/enterprise-client'
import { PROFILES as homeProfiles, relayUrl as homeRelayUrl, writeTrustFile as homeWrite } from '@usebag/home'
import { afterAll, describe, expect, it } from 'vitest'
import { relayUrl } from '../src/args.ts'
import { PROFILES } from '../src/commands/inbox.ts'

// packages/home keeps its own copies of what it may not import from the enterprise client or the command line: they
// must stay the same, byte for byte and answer for answer.

const root = mkdtempSync(join(tmpdir(), 'home-copies-'))
afterAll(() => rmSync(root, { recursive: true, force: true }))

/** The message relayUrl refuses `text` with. */
function refusal(text: string): string {
  try {
    relayUrl(text)
  } catch (e) {
    return (e as Error).message
  }
  throw new Error(`relayUrl took ${text}`)
}

describe("home's copies", () => {
  it("writes the trust file as the enterprise client's writer does, provenance kept", () => {
    const roots = {
      'ed25519:00': { added_at: 1 },
      'domain:example.com': { added_at: 2, source: 'org:example.com', granted_by: null, granted_at: 3 },
    }
    const [a, b] = [join(root, 'a'), join(root, 'b')]
    for (const d of [a, b]) mkdirSync(d, { mode: 0o700 })
    homeWrite(a, roots)
    enterpriseWrite(b, roots)
    expect(readFileSync(join(a, 'trust.json'))).toEqual(readFileSync(join(b, 'trust.json')))
    expect(statSync(join(a, 'trust.json')).mode & 0o777).toBe(statSync(join(b, 'trust.json')).mode & 0o777)
  })

  it('checks profiles with the very map inbox --honor reads, and relay URLs as the arguments do', () => {
    expect(PROFILES).toBe(homeProfiles)
    for (const url of ['https://r1.example/', 'http://localhost:8080//', 'https://r.example/path']) {
      expect(homeRelayUrl(url)).toBe(relayUrl(url))
    }
    for (const bad of ['nope', 'ftp://r.example']) expect(() => homeRelayUrl(bad)).toThrow(refusal(bad))
  })
})
