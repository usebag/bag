import { randomInt } from 'node:crypto'
import { shq } from '../args.ts'
import { CLI_MAIN } from '../entries.ts'

// A person's own background `record keep` (the last-mile rulings, section 1): the text of a launchd job or a crontab
// line, on stdout. Nothing here writes a job, and nothing touches launchd or cron: the person's one line does.

/** Four runs a day, 6 hours apart (a job must run every 11), at a minute drawn so that jobs do not align. null: hourly. */
const HOURS: readonly number[] | null = [2, 8, 14, 20]
const MINUTE = randomInt(60)

const xml = (s: string): string => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')

/**
 * A launchd job that runs `args` of the CLI at `main` (record.ts passes packaged.ts's stable entry) at HOURS, and at load. StartCalendarInterval, not StartInterval: launchd.plist(5) says
 * a calendar interval missed asleep runs at the next wake, once, and that an interval missed asleep is missed.
 */
export function launchdJob(
  label: string,
  args: readonly string[],
  log: string,
  main = CLI_MAIN,
  hours = HOURS,
): string {
  const argv = [process.execPath, main, ...args].map((a) => `    <string>${xml(a)}</string>`)
  const at = (h: number | null) => (h === null ? '' : `<key>Hour</key><integer>${h}</integer>`)
  const when = (hours ?? [null]).map(
    (h) => `    <dict>${at(h)}<key>Minute</key><integer>${MINUTE}</integer></dict>`,
  )
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    `  <key>Label</key><string>${xml(label)}</string>`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    ...argv,
    '  </array>',
    '  <key>StartCalendarInterval</key>',
    '  <array>',
    ...when,
    '  </array>',
    '  <key>RunAtLoad</key><true/>',
    `  <key>StandardOutPath</key><string>${xml(log)}</string>`,
    `  <key>StandardErrorPath</key><string>${xml(log)}</string>`,
    '</dict>',
    '</plist>',
  ].join('\n')
}

/**
 * The crontab line that runs `args` of the CLI at `main` at HOURS. A run the machine sleeps through is skipped: cron
 * does not catch up.
 */
export function crontabLine(args: readonly string[], log: string, main = CLI_MAIN, hours = HOURS): string {
  const argv = [process.execPath, main, ...args].map(shq).join(' ')
  return `${MINUTE} ${hours?.join(',') ?? '*'} * * * ${argv} >> ${shq(log)} 2>&1`.replaceAll('%', '\\%')
}
