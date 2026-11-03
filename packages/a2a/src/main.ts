// The A2A bridge as a process: node packages/a2a/src/main.ts --as <key name> --relay <url> --agent <address> (run.ts).
// Behind a proxy it first runs itself again with NODE_USE_ENV_PROXY=1 (the edge's proxy.ts).
import { useEnvProxy } from '@usebag/edge'
import { runBridge } from './run.ts'

const hint = useEnvProxy()
if (hint !== null) console.error(hint)
const stopped = new Promise<unknown>((resolve) => {
  process.once('SIGINT', resolve)
  process.once('SIGTERM', resolve)
})
const io = { out: console.log, err: console.error }
process.exitCode = await runBridge(process.argv.slice(2), io, { env: process.env, stopped, fetch })
