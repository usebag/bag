import { writeFileSync } from 'node:fs'
import { registerHooks } from 'node:module'

// The loaded-set tracer, loaded with `node --import` before the scripted session (loaded-session.ts): it records every
// module the process resolves from a node_modules directory, by import and by require (module.registerHooks covers
// both), and writes the URLs, one per line, to the file AC_LOADED_OUT names when the process exits.

const out = process.env.AC_LOADED_OUT
const seen = new Set<string>()

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context)
    if (resolved.url.includes('/node_modules/')) seen.add(resolved.url)
    return resolved
  },
})

process.on('exit', () => {
  if (out !== undefined) writeFileSync(out, [...seen].sort().join('\n'))
})
