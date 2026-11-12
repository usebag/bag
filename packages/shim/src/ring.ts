// A ring from the service turned into what the host's waiter reads. On a service connection the shim writes
// <home>/run/shim/<host pid>.ring for every host kind, beside the .bound file (channel.ts), and never moves the
// identity's doorbell (<home>/state/<name>/doorbell): that file is per identity, so moving it would wake every window
// bound to the identity, not the one speaking window the service chose (the coordinator's ruling, 2026-11-12). The
// CLI lane's wake hook (Claude Code, Codex) and omp's wake extension wake from this file while a .bound file exists;
// with no .bound file (the per-folder stdio mode, the rollback) nothing changes. Shape:
// {"v":1,"n":<sequence>,"as":"omp","unread":3,"speaking":true,"at":"<the service's at>","shim":<shim pid>}, 0600,
// written beside and renamed over, removed at exit only while it names this shim. Reader rules: packages/shim/README.md.
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** An identity label the shim will put in a file: the key names the CLI accepts, never a separator or a dot name. */
export const LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/** Whether a label is one the shim takes. */
export const isLabel = (label: string): boolean => LABEL.test(label) && label !== '.' && label !== '..'

/** One ring as the shim passes it on: the service's members and the shim's own sequence number. */
export interface Ring {
  readonly n: number
  readonly as: string
  readonly unread: number | null
  readonly speaking: boolean
  readonly at: string | null
}

export const ringOf = (home: string, hostPid: number): string => join(home, 'run', 'shim', `${hostPid}.ring`)

/** Writes the ring file (the directory is the channel's, made 0700 by writeBound or the channel). */
export function writeRing(home: string, hostPid: number, shimPid: number, ring: Ring): void {
  const file = ringOf(home, hostPid)
  const tmp = `${file}.${shimPid}.tmp`
  writeFileSync(tmp, JSON.stringify({ v: 1, ...ring, shim: shimPid }), { mode: 0o600 })
  renameSync(tmp, file)
}

/** Removes the ring file only while it still names this shim (a newer shim of the same host may own it). */
export function removeRing(home: string, hostPid: number, shimPid: number): void {
  const file = ringOf(home, hostPid)
  try {
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { shim?: unknown }
    if (doc.shim === shimPid) rmSync(file, { force: true })
  } catch {}
}
