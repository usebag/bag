import { describe, expect, it } from 'vitest'
import { auditDetail } from '../src/tools.ts'

// status(id) reads its own audit log's publish lines for the local send's detail (deliveryOfId): a line whose detail
// is not a JSON object must read as no detail, never throw (a throw there was a tool error for the whole status call).
describe('auditDetail: an audit line detail as an object, {} for anything else', () => {
  it('reads an object, and none, a non-JSON detail and JSON that is not an object as {}', () => {
    expect(auditDetail('{"delivery":"delivered-local","spooled":1}')).toEqual({
      delivery: 'delivered-local',
      spooled: 1,
    })
    for (const odd of [
      null,
      '',
      'not json',
      '{"delivery":',
      'null',
      '7',
      '"delivered-local"',
      '[{"delivery":1}]',
    ])
      expect(auditDetail(odd)).toEqual({})
  })
})
