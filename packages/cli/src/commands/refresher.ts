import { join, resolve } from 'node:path'
import {
  type EnterpriseDeps,
  type EnterprisePorts,
  enterpriseDeps,
  systemPorts,
} from '@usebag/enterprise-client'
import type { Io } from '../io.ts'
import { stableMains } from '../packaged.ts'
import { crontabLine, launchdJob } from './keep-schedule.ts'

// The CLI's side of a bag enterprise session (the work is @usebag/enterprise-client's): its ports over this io, and the
// hourly job a person installs, which runs `bag status`, the refresher's tick. launchd runs a calendar job missed asleep
// at the next wake; cron does not catch up, so it is the weaker of the two.

/** The enterprise client's ports over the io: the process's network, guard and wait unless a test passes its own. */
export function enterprisePorts(io: Io): EnterprisePorts {
  const system = systemPorts(io.env)
  const own = { clock: io.clock, rng: io.rng, fetch: io.fetch, net: io.enterpriseNet ?? system.net }
  const relays = io.enterpriseRelays === undefined ? {} : { relays: io.enterpriseRelays }
  return { ...system, ...own, sleep: io.sleep ?? system.sleep, ...relays }
}

/** The flow's deps over the io: lines to stdout, the console code from BAG_ORG_CODE, else one line of stdin. */
export function deps(io: Io, home: string): EnterpriseDeps {
  const code = async () => io.env.BAG_ORG_CODE ?? (await io.readLine())
  return enterpriseDeps(enterprisePorts(io), home, (line) => io.out(line), code)
}

/** The hourly job that runs `bag status --dir <home>`, the refresher's tick, as a launchd job or a crontab line. */
export function refresherJob(home: string, plist: boolean): string {
  const dir = resolve(home)
  const [run, log] = [['status', '--dir', dir], join(dir, 'enterprise', 'refresh.log')]
  const { cli } = stableMains(dir)
  return plist ? launchdJob('bag.refresh', run, log, cli, null) : crontabLine(run, log, cli, null)
}
