import { AcError, isAddress, signHop, verifyChain } from '@usebag/core'
import { list, parse, req, str, UsageError } from '../args.ts'
import { readChain, writeChain } from '../chain.ts'
import { homeDir, loadKeys } from '../home.ts'
import type { Io } from '../io.ts'

/** An --exp value at `now`: Unix seconds, or +<seconds> from now; UsageError for anything else. */
export function expiry(text: string, now: number): number {
  const m = /^(\+?)([1-9][0-9]*)$/.exec(text)
  const n = Number(m?.[2])
  if (m === null || !Number.isSafeInteger(n)) {
    throw new UsageError(`--exp is <unix seconds> or +<seconds>, not ${JSON.stringify(text)}`)
  }
  return m[1] === '+' ? now + n : n
}

/**
 * delegate --from <name> --to <address> [--caveat <caveat>...] --exp <unix seconds|+seconds> [--chain <in.json>]
 * --out <chain.json> [--dir <home>]: one hop signed by the identity <name> (the issuer) to <address> (the subject),
 * under the caveats it adds, until the expiry (spec/SPEC.md §6.1), appended to the chain in --chain when given. The
 * whole chain is verified for the subject now (§6.2), so an issuer that is not the last subject is chain-broken, an
 * expiry after the previous hop's is exp-not-monotone, and an expiry already past is hop-expired. Writes the chain
 * and prints the subject, then `root <address> hops <n> exp <seconds> caveats <JSON list>`: the effective caveats.
 * Never prints key material.
 */
export function delegate(args: readonly string[], io: Io): number {
  const p = parse(args, {
    positionals: [],
    options: {
      from: { type: 'string' },
      to: { type: 'string' },
      caveat: { type: 'string', multiple: true },
      exp: { type: 'string' },
      chain: { type: 'string' },
      out: { type: 'string' },
      dir: { type: 'string' },
    },
    required: ['from', 'to', 'exp', 'out'],
  })
  const sub = req(p, 'to')
  if (!isAddress(sub)) throw new AcError('bad-address', `--to ${JSON.stringify(sub)}`)
  const now = io.clock.now()
  const exp = expiry(req(p, 'exp'), now)
  const issuer = loadKeys(io, homeDir(io, str(p, 'dir')), req(p, 'from')).signing
  const file = str(p, 'chain')
  const before = file === undefined ? [] : readChain(file)
  const chain = [...before, signHop(issuer, sub, list(p, 'caveat'), exp)]
  const { root, caveats } = verifyChain(chain, sub, now)
  writeChain(req(p, 'out'), chain)
  io.out(sub)
  io.out(`root ${root} hops ${chain.length} exp ${exp} caveats ${JSON.stringify(caveats)}`)
  return 0
}
