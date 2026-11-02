// The A2A bridge as a process: node packages/a2a/src/main.ts --as <key name> --relay <url> --agent <address> (run.ts).
import { runBridge } from './run.ts'

const stopped = new Promise<unknown>((resolve) => {
  process.once('SIGINT', resolve)
  process.once('SIGTERM', resolve)
})
const io = { out: console.log, err: console.error }
process.exitCode = await runBridge(process.argv.slice(2), io, { env: process.env, stopped })
