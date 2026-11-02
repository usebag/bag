import { flag, parse, str, UsageError } from '../args.ts'
import { homeDir } from '../home.ts'
import type { Io } from '../io.ts'
import { NameBook } from '../names.ts'

const DIR = { dir: { type: 'string' } } as const

/**
 * name add <name> <address> [--replace] | name list | name forget <name>, each with [--dir <home>]: the home's name
 * book, <home>/names.json (names.ts). add prints "<name> <address>"; list prints one "<name> <address>" per name,
 * sorted, each followed by a "  former <address> replaced <unix>" line per former address; forget prints nothing. A
 * name is local: it is resolved by send --to and shown by inbox, and never sent on the wire.
 */
export function name(args: readonly string[], io: Io): number {
  const [verb, ...rest] = args
  if (verb === 'add') {
    const p = parse(rest, {
      positionals: ['name', 'address'],
      options: { replace: { type: 'boolean' }, ...DIR },
    })
    const [n, address] = p.positionals as [string, string]
    const book = NameBook.load(homeDir(io, str(p, 'dir')))
    book.add(n, address, io.clock.now(), flag(p, 'replace'))
    book.save()
    io.out(`${n} ${address}`)
  } else if (verb === 'list') {
    const p = parse(rest, { positionals: [], options: DIR })
    for (const [n, e] of NameBook.load(homeDir(io, str(p, 'dir'))).list()) {
      io.out(`${n} ${e.address}`)
      for (const f of e.previous ?? []) io.out(`  former ${f.address} replaced ${f.replaced_at}`)
    }
  } else if (verb === 'forget') {
    const p = parse(rest, { positionals: ['name'], options: DIR })
    const book = NameBook.load(homeDir(io, str(p, 'dir')))
    book.forget(p.positionals[0] as string)
    book.save()
  } else {
    throw new UsageError(
      'name add <name> <address> [--replace] | name list | name forget <name>, each [--dir <home>]',
    )
  }
  return 0
}
