// bag-shim: the thin stdio MCP server a host starts (Claude Code, Codex, omp); it forwards everything to the bag
// service over <home>/run/service.sock (docs/bag-service.md). `bag-shim hook` is the typed-word hook (run.ts).
import { run } from './run.ts'

const code = await run({
  argv: process.argv.slice(2),
  env: process.env,
  cwd: process.cwd(),
  pid: process.pid,
  ppid: process.ppid,
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  signals: process,
})
process.exitCode = code
