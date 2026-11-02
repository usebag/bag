//! The pairing rendezvous: an optional fourth call family,
//! `pair`, beside publish, subscribe and fetch. `POST /v0/pair/open`, signed by I, stores a short reach blob,
//! `{"inviter", "invitation", "relays"}` (the inviter's address, the invitation identity I's, which requests are sealed
//! to, and where both are reached), for a `ttl` of 1 to 600 s, under a nameplate, answered as a decimal string;
//! `GET /v0/pair/claim/{N}` answers `{"inviter", "invitation", "relays", "exp"}` until `exp`, or 404 `no-nameplate`,
//! and a claim does not consume it. The words of the code and the key they seed never reach the relay.
//!
//! A nameplate is the shortest free number: three digits (100 to 999) while one is free, then four, and so on, the
//! relay starting at a random place within the length, so that the numbers open do not tell how many are. An open
//! nameplate is never reused, and one invitation has at most one open nameplate: a second open of it is 409
//! `stale-record`, so that whoever claims a nameplate cannot shadow it with another. Everything lives in memory and
//! starts empty when the relay starts: an expired nameplate is gone at once, and the sweeper frees its memory.
//!
//! The limits (§4): an open counts against its client address's publish allowance (step 3a of the publish order); a
//! client address holds at most [`OPEN_PER_IP`] open nameplates, the relay [`MAX_OPEN`] (then 503 `store-full`); a
//! claim takes a token of its client address's bucket, [`CLAIM_RATE`] a second up to [`CLAIM_BURST`]; a publish that
//! delivers to an open nameplate's invitation, a pairing request, takes at step 8 a token of the nameplate's bucket,
//! [`REQUEST_RATE`] a second up to [`REQUEST_BURST`] across client addresses, and counts against the nameplate and its
//! client address, [`REQUESTS_PER_IP`] at most (429 `rate-limited`).

use crate::http::{AppState, error_response};
use crate::metrics::{METRICS, PAIR_CLAIMS, RATE_LIMITED};
use crate::net::bucket;
use crate::ratelimit::{Limit, Refused};
use crate::relay::{Rejection, Relay};
use ac_core::canonical::Value as Signed;
use ac_core::records::{MAX_RELAYS, is_relay_url};
use ac_core::{Address, Code, hash, hex, json, keys};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequest as _, Path, Request, State};
use axum::http::StatusCode;
use axum::http::header::CONNECTION;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The longest `ttl` of an open nameplate, in seconds.
pub const MAX_TTL: u64 = 600;
/// The cap on the reach blob of an open's body, in bytes (the body may carry 256 more for its signature).
pub const MAX_BLOB: usize = 512;
/// The most nameplates open at once.
pub const MAX_OPEN: usize = 10_000;
/// The most nameplates one client address holds open at once.
pub const OPEN_PER_IP: usize = 16;
/// The claims a second one client address's bucket refills.
pub const CLAIM_RATE: u64 = 5;
/// The most claims one client address's bucket holds.
pub const CLAIM_BURST: u64 = 10;
/// The pairing requests a second one open nameplate's bucket refills, across client addresses (2026-10-30:
/// a rate, not a total one could use up, so that guesses cannot burn a peer's invitation).
pub const REQUEST_RATE: u64 = 1;
/// The most pairing requests one open nameplate's bucket holds: a ceremony's first request always finds a token.
pub const REQUEST_BURST: u64 = 5;
/// The most pairing requests to one open nameplate from one client address over its `ttl`.
pub const REQUESTS_PER_IP: u32 = 10;

/// An open's body, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    /// The inviter's address.
    pub inviter: String,
    /// I's address, which the requests are sent to.
    pub invitation: String,
    /// Where both are reached.
    pub relays: Vec<String>,
    /// Seconds until it expires.
    pub ttl: u64,
}

/// A token bucket: its tokens and the second they were counted.
#[derive(Debug, Clone, Copy)]
struct Bucket(u64, u64);

impl Bucket {
    /// Refills it at `rate` a second up to `burst` by `now`: whether it holds a token.
    fn refill(&mut self, now: u64, rate: u64, burst: u64) -> bool {
        let tokens = self.0.saturating_add(now.saturating_sub(self.1).saturating_mul(rate));
        *self = Bucket(tokens.min(burst), now.max(self.1));
        self.0 > 0
    }
}

struct Open {
    opening: Opening,
    exp: u64,
    by: IpAddr,
    requests: Bucket,
    from: HashMap<IpAddr, u32>,
}

/// The open nameplates and the claim buckets.
#[derive(Default)]
pub struct Pairs(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    open: HashMap<u64, Open>,
    by_invitation: HashMap<String, u64>,
    claims: HashMap<IpAddr, Bucket>,
}

impl Pairs {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a nameplate for `opening` at `now`, from client address `ip`, the search starting at `start`: the
    /// nameplate and its `exp`; or 409 `stale-record` when its invitation has an open nameplate, 429 `rate-limited`
    /// when `ip` holds [`OPEN_PER_IP`], 503 `store-full` at [`MAX_OPEN`].
    pub(crate) fn open(
        &self,
        now: u64,
        ip: IpAddr,
        opening: Opening,
        start: u64,
    ) -> Result<(u64, u64), Rejection> {
        let mut inner = self.inner();
        inner.sweep(now);
        let ip = bucket(ip);
        if inner.by_invitation.contains_key(&opening.invitation) {
            return Err(Code::StaleRecord.into());
        }
        let held: Vec<u64> = inner.open.values().filter(|o| o.by == ip).map(|o| o.exp - now).collect();
        if held.len() >= OPEN_PER_IP {
            let retry_after = held.into_iter().min().unwrap_or(1).max(1);
            return Err(Rejection { retry_after: Some(retry_after), ..Code::RateLimited.into() });
        }
        let Some(n) = inner.free(start) else {
            return Err(Rejection { retry_after: Some(MAX_TTL), ..Code::StoreFull.into() });
        };
        let exp = now + opening.ttl;
        inner.by_invitation.insert(opening.invitation.clone(), n);
        let requests = Bucket(REQUEST_BURST, now);
        inner.open.insert(n, Open { opening, exp, by: ip, requests, from: HashMap::new() });
        Ok((n, exp))
    }

    /// The reach blob of nameplate `n` at `now` for client address `ip`, after a token of its bucket: `Ok(None)` when
    /// no nameplate `n` is open, and the seconds to wait when the bucket is empty. Each is counted ([`PAIR_CLAIMS`]).
    pub(crate) fn claim(&self, now: u64, ip: IpAddr, n: Option<u64>) -> Result<Option<Value>, u64> {
        let (mut inner, key) = (self.inner(), bucket(ip));
        // At most MAX_OPEN client addresses have a bucket; a new one waits for the sweep to free some.
        if inner.claims.len() >= MAX_OPEN && !inner.claims.contains_key(&key) {
            METRICS.count(PAIR_CLAIMS, "result", Code::RateLimited.as_str());
            return Err(1);
        }
        let tokens = inner.claims.entry(key).or_insert(Bucket(CLAIM_BURST, now));
        if !tokens.refill(now, CLAIM_RATE, CLAIM_BURST) {
            METRICS.count(PAIR_CLAIMS, "result", Code::RateLimited.as_str());
            return Err(1);
        }
        tokens.0 -= 1;
        let open = n.and_then(|n| inner.open.get(&n)).filter(|o| o.exp > now);
        METRICS.count(PAIR_CLAIMS, "result", if open.is_some() { "ok" } else { "no-nameplate" });
        Ok(open.map(|o| {
            let o = (&o.opening, o.exp);
            json!({"inviter": o.0.inviter, "invitation": o.0.invitation, "relays": o.0.relays, "exp": o.1})
        }))
    }

    /// Counts a publish from client address `ip` delivered to `to` at `now` against each open nameplate among them,
    /// or refuses it with [`Limit::Pairing`] and counts nothing.
    pub(crate) fn request<'a>(
        &self,
        now: u64,
        ip: IpAddr,
        to: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<u64>, Refused> {
        let (mut inner, ip) = (self.inner(), bucket(ip));
        let mut hit: Vec<u64> = to.into_iter().filter_map(|a| inner.by_invitation.get(a).copied()).collect();
        hit.retain(|n| inner.open.get(n).is_some_and(|o| o.exp > now));
        for n in &hit {
            let o = inner.open.get_mut(n).expect("an open nameplate");
            if o.from.get(&ip).is_some_and(|sent| *sent >= REQUESTS_PER_IP) {
                return Err(Refused { limit: Limit::Pairing, retry_after: o.exp.saturating_sub(now).max(1) });
            }
            if !o.requests.refill(now, REQUEST_RATE, REQUEST_BURST) {
                return Err(Refused { limit: Limit::Pairing, retry_after: 1 });
            }
        }
        for n in &hit {
            let o = inner.open.get_mut(n).expect("an open nameplate");
            o.requests.0 -= 1;
            *o.from.entry(ip).or_default() += 1;
        }
        Ok(hit)
    }

    /// Forgets the nameplates expired at `now` and the claim buckets full again: how many nameplates.
    pub(crate) fn sweep(&self, now: u64) -> usize {
        self.inner().sweep(now)
    }

    /// How many nameplates are open at `now`.
    pub(crate) fn open_at(&self, now: u64) -> usize {
        self.inner().open.values().filter(|o| o.exp > now).count()
    }
}

impl Inner {
    /// The first free nameplate of the shortest length with one, from `start` within that length; none at
    /// [`MAX_OPEN`].
    fn free(&self, start: u64) -> Option<u64> {
        if self.open.len() >= MAX_OPEN {
            return None;
        }
        let (mut low, mut span) = (100, 900);
        loop {
            let found =
                (0..span).map(|i| low + (start % span + i) % span).find(|n| !self.open.contains_key(n));
            if found.is_some() {
                return found;
            }
            (low, span) = (low * 10, span * 10);
        }
    }

    fn sweep(&mut self, now: u64) -> usize {
        let gone: Vec<u64> = self.open.iter().filter(|(_, o)| o.exp <= now).map(|(n, _)| *n).collect();
        for n in &gone {
            let o = self.open.remove(n).expect("listed");
            self.by_invitation.remove(&o.opening.invitation);
        }
        let full = CLAIM_BURST.div_ceil(CLAIM_RATE);
        self.claims.retain(|_, b| now.saturating_sub(b.1) < full);
        gone.len()
    }
}

/// Checks an open's body: `inviter` and `invitation` (addresses), `relays` (1 to 8 relay URLs, each once), `ttl` and
/// `sig`, I's signature over `["ac/pair-open/1", inviter, invitation, relays, ttl]` (no one
/// opens a nameplate for a mailbox whose key they do not hold); at most [`MAX_BLOB`] bytes and 256 for the signature.
/// Else 413 `body-too-large`, 400 `bad-json`, `bad-shape` or `bad-hex`, 422 `bad-sig`.
pub(crate) fn parse_open(body: &[u8]) -> Result<Opening, Rejection> {
    if body.len() > MAX_BLOB + 256 {
        return Err(Code::BodyTooLarge.into());
    }
    let value = ac_core::json::parse(body)?;
    let shape = || Rejection::from(Code::BadShape);
    let object = value.as_object().ok_or_else(shape)?;
    if object.keys().any(|k| !matches!(k.as_str(), "inviter" | "invitation" | "relays" | "ttl" | "sig")) {
        return Err(shape());
    }
    let address = |key: &str| {
        let text = object.get(key).and_then(Value::as_str).ok_or_else(shape)?;
        Address::parse(text).map_err(|_| shape())
    };
    let (inviter, invitation) = (address("inviter")?, address("invitation")?);
    let relays = object.get("relays").and_then(Value::as_array).ok_or_else(shape)?;
    let relays: Vec<String> = relays
        .iter()
        .map(|u| u.as_str().filter(|s| is_relay_url(s)).map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(shape)?;
    let ttl = object.get("ttl").and_then(Value::as_u64).ok_or_else(shape)?;
    let repeated = relays.iter().enumerate().any(|(i, r)| relays[..i].contains(r));
    if relays.is_empty() || relays.len() > MAX_RELAYS || repeated || !(1..=MAX_TTL).contains(&ttl) {
        return Err(shape());
    }
    let sig = hex::decode_array::<64>(&json::hex_field(object.get("sig"), Some(64))?)?;
    let listed = Signed::Array(relays.iter().map(|r| Signed::from(r.as_str())).collect());
    let (i, v) = (Signed::from(inviter.as_str()), Signed::from(invitation.as_str()));
    let preimage = Signed::Array(vec![Signed::from("ac/pair-open/1"), i, v, listed, Signed::Int(ttl)]);
    if !keys::verify(&invitation, &hash::digest(&preimage)?, &sig) {
        return Err(Code::BadSig.into());
    }
    let (inviter, invitation) = (inviter.to_string(), invitation.to_string());
    Ok(Opening { inviter, invitation, relays, ttl })
}

/// A claim's nameplate: digits with no leading zero, at least three and at most nine; none for anything else.
#[must_use]
pub fn parse_nameplate(text: &str) -> Option<u64> {
    let digits =
        (3..=9).contains(&text.len()) && text.bytes().all(|c| c.is_ascii_digit()) && !text.starts_with('0');
    digits.then(|| text.parse().ok()).flatten()
}

impl Relay {
    /// An open: the client address's publish allowance (429 `rate-limited`), the body, then a nameplate.
    pub(crate) fn pair_open(&self, body: &[u8], ip: IpAddr) -> Result<(u64, u64), Rejection> {
        let now = self.now();
        self.limit_address(now, ip)?;
        let opening = parse_open(body)?;
        let mut seed = [0_u8; 8];
        let start = getrandom::fill(&mut seed).map_or(0, |()| u64::from_le_bytes(seed));
        self.pairs.open(now, ip, opening, start)
    }
}

/// `POST /v0/pair/open`.
pub(crate) async fn open(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let ip = state.relay.client(peer, request.headers());
    let shown = state.relay.config.front.log_ip.show(ip);
    // As a publish's: the body within the body timeout, or a 408 and the connection closed.
    let read = tokio::time::timeout(state.relay.config.body_timeout, Bytes::from_request(request, &state));
    let body: Result<Bytes, Rejection> = match read.await {
        Err(_) => {
            METRICS.count("ac_relay_pair_opens_total", "result", "body-timeout");
            return (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response();
        }
        Ok(Err(e)) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(Code::BodyTooLarge.into()),
        Ok(read) => Ok(read.unwrap_or_default()),
    };
    match body.and_then(|body| state.relay.pair_open(&body, ip)) {
        Ok((n, exp)) => {
            tracing::info!(event = "pair-open", nameplate = n, exp, ip = %shown);
            METRICS.count("ac_relay_pair_opens_total", "result", "ok");
            axum::Json(json!({"nameplate": n.to_string()})).into_response()
        }
        Err(r) => {
            tracing::info!(event = "pair-refused", status = r.status, code = r.error(), ip = %shown);
            METRICS.count("ac_relay_pair_opens_total", "result", r.error());
            METRICS.refused("pair-open", r.code);
            error_response(r)
        }
    }
}

/// `GET /v0/pair/claim/{N}`.
pub(crate) async fn claim(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    text: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Response {
    let ip = state.relay.client(peer, &headers);
    let shown = state.relay.config.front.log_ip.show(ip);
    let n = text.ok().and_then(|Path(text)| parse_nameplate(&text));
    match state.relay.pairs.claim(state.relay.now(), ip, n) {
        Ok(Some(blob)) => axum::Json(blob).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, axum::Json(json!({"error": "no-nameplate"}))).into_response(),
        Err(retry_after) => {
            METRICS.count(RATE_LIMITED, "limit", "pair-claim");
            tracing::info!(event = "rate-limited", limit = "pair-claim", ip = %shown, retry_after);
            error_response(Rejection { retry_after: Some(retry_after), ..Code::RateLimited.into() })
        }
    }
}

#[cfg(test)]
mod tests;
