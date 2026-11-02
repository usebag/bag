import { randomInt } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { shq } from '../args.ts'

// A person's own background `record keep` (the last-mile rulings, section 1): the text of a launchd job or a crontab
// line, on stdout. Nothing here writes a job, and nothing touches launchd or cron: the person's one line does.

const CLI_MAIN = fileURLToPath(new URL('../main.ts', import.meta.url))
/** Four runs a day, 6 hours apart (a job must run every 11), at a minute drawn so that jobs do not align. */
const HOURS = [2, 8, 14, 20]
const MINUTE = randomInt(60)

const xml = (s: string): string => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')

/**
 * A launchd job that runs `args` at HOURS, and at load. StartCalendarInterval, not StartInterval: launchd.plist(5) says
 * a calendar interval missed asleep runs at the next wake, once, and that an interval missed asleep is missed.
 */
export function launchdJob(label: string, args: readonly string[], log: string): string {
  const argv = [process.execPath, CLI_MAIN, ...args].map((a) => `    <string>${xml(a)}</string>`)
  const when = HOURS.map(
    (h) =>
      `    <dict><key>Hour</key><integer>${h}</integer><key>Minute</key><integer>${MINUTE}</integer></dict>`,
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

/** The crontab line that runs `args` at HOURS. A run the machine sleeps through is skipped: cron does not catch up. */
export function crontabLine(args: readonly string[], log: string): string {
  const argv = [process.execPath, CLI_MAIN, ...args].map(shq).join(' ')
  return `${MINUTE} ${HOURS.join(',')} * * * ${argv} >> ${shq(log)} 2>&1`.replaceAll('%', '\\%')
}
