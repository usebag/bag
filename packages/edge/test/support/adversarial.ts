import { mkdtempSync, rmSync } from 'node:fs'
import { Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SUITE, toHex } from '@usebag/core'
import { onTestFinished, vi } from 'vitest'
import { generateEdgeKeys } from '../../src/edge.ts'
import type { EdgeKeys } from '../../src/ports.ts'
import { seededRng } from './fixtures.ts'

// Shared helpers of the adversarial local-side tests: a scratch directory removed when the
// test finishes, identities whose keys come from a seeded rng, and an occurrence count that never prints what it
// looks for. A failing assertion on a count shows a number, so no seed reaches a test report.

/** A fresh directory under AC_TEST_TMP (else the system's), removed when the current test finishes. */
export function scratch(prefix: string): string {
  const dir = mkdtempSync(join(process.env.AC_TEST_TMP || tmpdir(), `bag-adv-${prefix}-`))
  onTestFinished(() => {
    if (process.env.AC_KEEP_TMP !== '1') rmSync(dir, { recursive: true, force: true })
  })
  return dir
}

/** An identity for one test: keys from a seeded rng, and the secret forms a test searches for. */
export interface Identity {
  readonly keys: EdgeKeys
  readonly address: string
  /** The signing seed and the sealing private key, as lowercase hex. */
  readonly secrets: readonly string[]
  /** The key file's JSON text, exactly as FsKeyStore writes it. */
  readonly keyFile: string
}

export function identity(label: string): Identity {
  const keys = generateEdgeKeys(seededRng(`adversarial:${label}`))
  const sign = toHex(keys.signing.exportSeed())
  const seal = toHex(keys.sealing.exportSeed())
  return {
    keys,
    address: keys.signing.address,
    secrets: [sign, seal],
    keyFile: JSON.stringify({ suite: SUITE, sign_seed: sign, seal_priv: seal }),
  }
}

/** How many times the needles occur in the text, in total (a number, so a failure prints no secret). */
export function occurrences(text: string, needles: readonly string[]): number {
  let n = 0
  for (const needle of needles) {
    if (needle === '') continue
    for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) n++
  }
  return n
}

/**
 * No socket while the current test runs. Every `net.Socket.prototype.connect` (what node:http, undici's
 * fetch and node:tls call to open a TCP connection) and every global `fetch` is refused with a throw, before any
 * packet, and counted; the spies are restored when the test finishes. A test that must never reach the network (E1:
 * relays a record names on 100.64.0.0/10, 240.0.0.0/4 and the other special ranges) asserts the count is 0.
 */
export function noSockets(): { attempts(): number } {
  let attempts = 0
  const refuse = (what: string): Error => {
    attempts++
    return new Error(`no-socket guard: a ${what} was attempted inside a no-socket test`)
  }
  const connect = vi.spyOn(Socket.prototype, 'connect').mockImplementation((() => {
    throw refuse('socket connect')
  }) as unknown as Socket['connect'])
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    throw refuse('fetch')
  })
  onTestFinished(() => {
    connect.mockRestore()
    fetch.mockRestore()
  })
  return { attempts: () => attempts }
}
