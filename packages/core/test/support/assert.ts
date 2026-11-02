import { expect } from 'vitest'
import { AcError, type AcErrorCode } from '../../src/errors.ts'

/** Runs fn, expects it to throw an AcError with `code`, and returns the error. */
export function expectAcError(fn: () => unknown, code: AcErrorCode): AcError {
  let caught: unknown
  try {
    fn()
  } catch (e) {
    caught = e
  }
  expect(caught, `expected AcError ${code}`).toBeInstanceOf(AcError)
  expect((caught as AcError).code).toBe(code)
  return caught as AcError
}

/** Runs fn: 'ok', or the code of the AcError it throws (any other error propagates). */
export function outcome(fn: () => unknown): string {
  try {
    fn()
    return 'ok'
  } catch (e) {
    if (e instanceof AcError) return e.code
    throw e
  }
}
