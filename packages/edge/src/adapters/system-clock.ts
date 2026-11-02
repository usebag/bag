import { randomBytes } from 'node:crypto'
import type { Clock, Rng } from '../ports.ts'

/** The system clock, in whole Unix seconds. */
export const systemClock: Clock = { now: () => Math.floor(Date.now() / 1000) }

/** The system CSPRNG (node:crypto randomBytes). */
export const systemRng: Rng = { bytes: (length) => new Uint8Array(randomBytes(length)) }
