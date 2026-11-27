// The shim's parts, for the bundle (packages/bag) and the tests.
export { postUnbind, postUse, typedName, UNBIND_WORD, USE_WORD } from './channel.ts'
export { hostKind } from './host.ts'
export { run, type ShimIo } from './run.ts'
export { Shim, type ShimDeps } from './shim.ts'
export { CONTRACT } from './wire.ts'
