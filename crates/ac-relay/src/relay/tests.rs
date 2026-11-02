use super::{Rejection, status};
use crate::store::StoreError;
use ac_core::Code;

#[test]
fn every_code_has_its_appendix_a_status() {
    let want = [
        (
            400,
            &[
                Code::BadHex,
                Code::BadAddress,
                Code::BadJson,
                Code::BadShape,
                Code::BadVersion,
                Code::BadSuite,
                Code::BadRecord,
            ][..],
        ),
        (413, &[Code::EnvelopeTooLarge, Code::BodyTooLarge]),
        (401, &[Code::BadAuth]),
        (
            403,
            &[
                Code::NotHosted,
                Code::RootNotAccepted,
                Code::TooLargeForMailbox,
                Code::NotAuthorized,
                Code::Revoked,
            ],
        ),
        (404, &[Code::NotFound]),
        (409, &[Code::StaleRecord]),
        (429, &[Code::RateLimited]),
        (500, &[Code::Internal]),
        (503, &[Code::ResolveFailed, Code::StoreFull]),
        (
            422,
            &[
                Code::TooManyRecipients,
                Code::BadId,
                Code::BadSig,
                Code::StaleTs,
                Code::FutureTs,
                Code::TooManyHops,
                Code::BadHop,
                Code::TooManyCaveats,
                Code::CaveatTooLong,
                Code::ChainBroken,
                Code::ChainNotToSender,
                Code::ExpNotMonotone,
                Code::HopExpired,
                Code::BadHopSig,
                Code::TooManyRelays,
                Code::TooManyRevoked,
                Code::BadRecordSig,
                Code::FutureIat,
                Code::RecordExpired,
                Code::BadRotation,
            ],
        ),
    ];
    for (s, codes) in want {
        for c in codes {
            assert_eq!(status(*c), s, "{c}");
            assert_eq!(Rejection::new(*c).status, s, "{c}");
        }
    }
}

#[test]
fn a_fetch_proof_out_of_time_is_401_and_a_store_failure_500() {
    assert_eq!(Rejection::at_fetch(Code::StaleTs).status, 401);
    assert_eq!(Rejection::at_fetch(Code::FutureTs).status, 401);
    assert_eq!(Rejection::at_fetch(Code::NotFound).status, 404);
    let r = Rejection::from(StoreError("disk".into()));
    assert_eq!((r.status, r.code, r.error()), (500, None, "internal"));
    assert_eq!(Rejection::from(Code::BadId).error(), "bad-id");
}
