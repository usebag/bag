import { execFile } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { signingKeyFromSeed } from '@usebag/core'
import { describe, expect, it, onTestFinished } from 'vitest'
import { acceptFrom, DEFAULT_RELAY_CMD, type Party, party, until } from '../harness.ts'
import { envelope, events, post, publishRecords, spawnRelay } from './support.ts'

// K1-K2: the probe mailbox (probe.rs:36-92). The release ac-relay on 127.0.0.1
// from AC_RELAY_CMD, driven once as `ac-relay probe <url> --key <file>` so the real probe publishes its own
// accept-from (roots = itself, probe.rs:48). An outsider's chain rooted at the outsider's key cannot reach the probe
// mailbox; the probe's accept-from record is, by design, world-readable (http.rs:151-162). The probe key lives in a
// throwaway temp dir, never a real home directory, and its seed is never printed by any assertion.

/** `ac-relay probe <url> --key <file>`: its exit code, stdout and stderr. */
function runProbe(
  url: string,
  keyFile: string,
): Promise<{ readonly code: number; readonly out: string; readonly err: string }> {
  const cmd = process.env.AC_RELAY_CMD || DEFAULT_RELAY_CMD
  return new Promise((resolve) => {
    execFile(cmd, ['probe', url, '--key', keyFile], { timeout: 30_000 }, (error, out, err) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : -1
      resolve({ code, out, err })
    })
  })
}

/** The probe's address, derived from the seed the probe wrote (64 hex), without printing it. */
function probeAddress(keyFile: string): string {
  const hex = readFileSync(keyFile, 'utf8').trim()
  const seed = Uint8Array.from((hex.match(/../g) ?? []).map((b) => Number.parseInt(b, 16)))
  return signingKeyFromSeed(seed).address
}

/** A throwaway key directory for a probe, removed at the test's end. */
function probeKeyFile(): string {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), 'bag-probe-r3-'))
  onTestFinished(() => {
    if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
  })
  return join(dir, 'probe.key')
}

describe('K: the probe mailbox (probe.rs:36-92)', () => {
  it('K1 an outsider chain rooted at its own key, addressed to the probe mailbox, is 403 root-not-accepted; V1 a lawful message to a real mailbox delivers', async () => {
    const relay = await spawnRelay('k1')
    const keyFile = probeKeyFile()
    const run = await runProbe(relay.url, keyFile)
    expect(run.code, `probe stderr: ${run.err}`).toBe(0)
    expect(run.out).toMatch(/^probe ok [0-9a-f]{64}\n$/)
    const probeAddr = probeAddress(keyFile)

    // V1: a lawful message to a mailbox that admits every root is delivered.
    const alice = party('alice')
    const bob = party('bob')
    expect(await publishRecords(relay.url, [acceptFrom(bob, ['*'])])).toEqual([200])
    const lawful = await post(relay.url, envelope(alice, [bob]).bytes)
    expect(lawful.status).toBe(200)
    expect((lawful.body as { delivered?: number }).delivered).toBe(1)

    // The attack: an outsider's self-rooted chain addressed to the probe mailbox.
    const outsider = party('outsider')
    const probeTo: Party = { ...party('probe-seal'), address: probeAddr }
    const attack = await post(relay.url, envelope(outsider, [probeTo]).bytes)
    console.log(`K1 measure: outsider -> probe mailbox: ${attack.status} ${JSON.stringify(attack.body)}`)
    expect(attack.status).toBe(403)
    expect(attack.body).toEqual({ error: 'root-not-accepted' })
    await until('the refusal is logged', () =>
      events(relay).some((e) => e.event === 'publish-refused' && e.code === 'root-not-accepted'),
    )
  })

  it('K2 (measure) GET /v0/fetch/record/<probe-address>/accept-from with no auth returns 200 with the public record (http.rs:151-162)', async () => {
    const relay = await spawnRelay('k2')
    const keyFile = probeKeyFile()
    const run = await runProbe(relay.url, keyFile)
    expect(run.code, `probe stderr: ${run.err}`).toBe(0)
    const probeAddr = probeAddress(keyFile)

    const res = await fetch(`${relay.url}/v0/fetch/record/${probeAddr}/accept-from`)
    const body = (await res.json()) as { kind?: string; owner?: string; roots?: unknown }
    console.log(
      `K2 measure: unauthenticated record fetch -> ${res.status}, kind=${body.kind}, roots=${JSON.stringify(body.roots)}`,
    )
    expect(res.status).toBe(200)
    expect(body.kind).toBe('accept-from')
    expect(body.owner).toBe(probeAddr)
  })
})
