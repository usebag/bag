// Who holds an identity moved to packages/home, which the MCP server shares; the command line's modules read it here.
export {
  describeHolder,
  type Holder,
  holder,
  lockHolder,
  type Procs,
  refuseWhileHeld,
  servers,
} from '@usebag/home'
