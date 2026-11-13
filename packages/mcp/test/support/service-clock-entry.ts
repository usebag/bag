// A test-only entry of the bag service, never in packages/*/src and never in the bundle or the packed package
// (scripts/check-test-seams.mjs holds both at zero): the real entry (src/main.ts) with the service's clock moved ahead
// by BAG_TEST_CLOCK_OFFSET_S seconds, read once at launch. W1's legs launch this file in place of bag-mcp.js to prove
// the 24-hour cooling and the 7-day expiry of a local pair request (decision 104) without waiting: a restart with a
// larger offset moves the service on, and the requests persist across it. The product code reads no such variable.
import { activateTestZone, useEnvProxy } from '@usebag/edge'
import { processIo, serve } from '../../src/server.ts'

useEnvProxy()
activateTestZone(process.env, (line) => process.stderr.write(`${line}\n`))
const offset = Number(process.env.BAG_TEST_CLOCK_OFFSET_S ?? '0')
if (!Number.isSafeInteger(offset)) throw new Error('BAG_TEST_CLOCK_OFFSET_S is whole seconds')
const io = processIo()
process.exitCode = await serve({ ...io, clock: { now: () => io.clock.now() + offset } })
