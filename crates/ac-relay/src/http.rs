//! The HTTP side: one router for publish, both fetch shapes, health, the abuse contact, the pairing rendezvous
//! (src/pair.rs) and the WebSocket upgrade.
//!
//! Every error answer is `{"error": "<code>"}` with the status the call gives that code ([`Rejection`]); a 429
//! also carries `Retry-After`. A publish whose body does not arrive within the body timeout is answered 408 with no
//! body and the connection closed. A fetch by id answers the exact stored bytes with [`RECEIVED_AT`], the
//! second the relay stored them. Logs name ids, codes, addresses and cursors, never envelope or record
//! bytes; each publish and subscribe line names the client as `--log-ip` says, behind a trusted proxy the one its
//! header names ([`crate::net::Front`]).

use crate::auth::FetchHeaders;
use crate::metrics::METRICS;
use crate::net::client_ip;
use crate::relay::{Published, Rejection, Relay};
use crate::server::Admission;
use crate::store::StoredEnvelope;
use ac_core::Code;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest as _, Path, Request, State};
use axum::http::header::{CONNECTION, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// The header of a fetch's answer that names when the relay stored the envelope, in Unix seconds (spec/SPEC.md
/// §8.3): the edge judges live delivery at it.
pub const RECEIVED_AT: HeaderName = HeaderName::from_static("ac-received-at");

/// The counters of publishes, of fetches by id and of record fetches, by `result`: `ok` (for a publish `stored`,
/// `duplicate` or `record`, and `body-timeout` for a body that did not arrive) or the code.
const PUBLISHES: &str = "ac_relay_publishes_total";
const FETCHES: &str = "ac_relay_fetches_total";
const RECORD_FETCHES: &str = "ac_relay_record_fetches_total";

/// What every handler can reach.
#[derive(Clone)]
pub struct AppState {
    /// The relay.
    pub relay: Arc<Relay>,
    /// Becomes true when the relay is shutting down.
    pub stop: watch::Receiver<bool>,
    /// Held by each subscriber's task; shutdown waits until every clone is dropped.
    pub tracker: mpsc::Sender<()>,
}

/// The relay's routes.
pub fn router(state: AppState) -> Router {
    let limit = state.relay.config.body_limit;
    Router::new()
        .route("/v0/publish", post(publish))
        .route("/v0/fetch/{id}", get(fetch))
        .route("/v0/fetch/record/{address}/{kind}", get(fetch_record))
        .route("/v0/health", get(health))
        .route("/v0/abuse", get(abuse))
        .route("/v0/subscribe", get(subscribe))
        .route("/v0/pair/open", post(crate::pair::open))
        .route("/v0/pair/claim/{n}", get(crate::pair::claim))
        .fallback(not_found)
        .layer(axum::middleware::from_fn(crate::metrics::time))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

/// The JSON error answer for a rejection: `{"error": code}`, and `Retry-After` for a 429.
#[must_use]
pub fn error_response(r: Rejection) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut answer = serde_json::json!({"error": r.error()});
    if let Some(cap) = r.max_envelope_bytes {
        answer["max_envelope_bytes"] = cap.into();
    }
    let mut response = (status, json(&answer)).into_response();
    if let Some(seconds) = r.retry_after {
        response.headers_mut().insert(RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}

fn json(value: &serde_json::Value) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    ([(CONTENT_TYPE, "application/json")], value.to_string())
}

fn exact_bytes(bytes: Vec<u8>) -> Response {
    ([(CONTENT_TYPE, "application/json")], bytes).into_response()
}

fn stamped_bytes(stored: StoredEnvelope) -> Response {
    let mut response = exact_bytes(stored.bytes);
    response.headers_mut().insert(RECEIVED_AT, HeaderValue::from(stored.received_at));
    response
}

impl Relay {
    /// The client of a call from `peer` ([`crate::net::Front::client`]), its network counted in the day's.
    pub(crate) fn client(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let ip = self.config.front.client(peer, headers);
        METRICS.client(self.now(), ip);
        ip
    }
}

async fn publish(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let ip = state.relay.client(peer, request.headers());
    let shown = state.relay.config.front.log_ip.show(ip);
    // The body must arrive within the body timeout: a 408 with no body, and the connection closed.
    let wait = state.relay.config.body_timeout;
    let body = match tokio::time::timeout(wait, Bytes::from_request(request, &state)).await {
        Err(_) => {
            tracing::info!(event = "publish-refused", status = 408, reason = "body-timeout", ip = %shown);
            METRICS.count(PUBLISHES, "result", "body-timeout");
            return (StatusCode::REQUEST_TIMEOUT, [(CONNECTION, "close")]).into_response();
        }
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            let code =
                if e.status() == StatusCode::PAYLOAD_TOO_LARGE { Code::BodyTooLarge } else { Code::BadJson };
            tracing::info!(event = "publish-refused", status = e.status().as_u16(), code = %code, ip = %shown);
            METRICS.count(PUBLISHES, "result", code.as_str());
            return error_response(Rejection::new(code));
        }
    };
    match state.relay.publish_resolving(&body, ip).await {
        Ok(Published::Envelope { id, duplicate, delivered, from, root }) => {
            tracing::info!(event = "publish", id = %id, from = %from, root = %root, duplicate, delivered, ip = %shown);
            METRICS.count(PUBLISHES, "result", if duplicate { "duplicate" } else { "stored" });
            METRICS.add("ac_relay_deliveries_total", "", "", u64::try_from(delivered).unwrap_or(u64::MAX));
            let answer =
                serde_json::json!({"ok": true, "id": id, "duplicate": duplicate, "delivered": delivered});
            (StatusCode::OK, json(&answer)).into_response()
        }
        Ok(Published::Record { kind, signer, iat, valid_until }) => {
            tracing::info!(event = "publish-record", kind = kind.as_str(), signer = %signer, iat, ip = %shown);
            METRICS.count(PUBLISHES, "result", "record");
            let answer = serde_json::json!({"ok": true, "kind": kind.as_str(), "signer": signer, "iat": iat,
                "valid_until": valid_until});
            (StatusCode::OK, json(&answer)).into_response()
        }
        Err(r) => {
            tracing::info!(event = "publish-refused", status = r.status, code = r.error(), ip = %shown);
            METRICS.count(PUBLISHES, "result", r.error());
            METRICS.refused("envelope", r.code);
            error_response(r)
        }
    }
}

/// The client's fetch window, before a fetch verifies a signature or reads the store (`--fetch-per-ip`).
fn limit_fetch(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> Result<(), Rejection> {
    let relay = &state.relay;
    relay.limit_fetch(relay.now(), relay.client(peer, headers))
}

/// A fetch's answer, counted under `family` by its code, or `ok`.
fn fetched(family: &'static str, answer: Result<Response, Rejection>) -> Response {
    METRICS.count(family, "result", answer.as_ref().map_or_else(Rejection::error, |_| "ok"));
    answer.unwrap_or_else(error_response)
}

async fn fetch(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    id: Result<Path<String>, axum::extract::rejection::PathRejection>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = limit_fetch(&state, peer, &headers) {
        return fetched(FETCHES, Err(r));
    }
    let Ok(Path(id)) = id else {
        return fetched(FETCHES, Err(Rejection::new(Code::BadHex)));
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let request = FetchHeaders {
        signer: header("ac-signer"),
        ts: header("ac-ts"),
        sig: header("ac-sig"),
        auth: header("ac-auth"),
    };
    let answer = match state.relay.fetch(&id, &request) {
        Ok(stored) => {
            tracing::info!(event = "fetch", id = %id, signer = request.signer);
            Ok(stamped_bytes(stored))
        }
        Err(r) => {
            tracing::info!(event = "fetch-refused", id = %id, status = r.status, code = r.error(), signer = request.signer);
            METRICS.refused("fetch", r.code);
            Err(r)
        }
    };
    fetched(FETCHES, answer)
}

async fn fetch_record(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    path: Result<Path<(String, String)>, axum::extract::rejection::PathRejection>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = limit_fetch(&state, peer, &headers) {
        return fetched(RECORD_FETCHES, Err(r));
    }
    let Ok(Path((address, kind))) = path else {
        return fetched(RECORD_FETCHES, Err(Rejection::new(Code::BadAddress)));
    };
    fetched(RECORD_FETCHES, state.relay.fetch_record(&address, &kind).map(exact_bytes))
}

async fn health(State(state): State<AppState>) -> Response {
    let answer = serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "now": state.relay.now(),
        "url": state.relay.config.url, "max_envelope_bytes": state.relay.config.max_envelope_bytes});
    (StatusCode::OK, json(&answer)).into_response()
}

/// The operator's abuse contact (`--abuse-contact`): `{"contact"}`, or 404 `not-found` when none is set.
async fn abuse(State(state): State<AppState>) -> Response {
    let Some(contact) = &state.relay.config.abuse_contact else { return not_found().await };
    (StatusCode::OK, json(&serde_json::json!({"contact": contact}))).into_response()
}

async fn subscribe(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(admission): Extension<Admission>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Response {
    let Ok(upgrade) = upgrade else {
        return error_response(Rejection::new(Code::BadShape));
    };
    let limit = state.relay.config.body_limit;
    let ip = state.relay.client(peer, &headers);
    // A trusted proxy's socket counts under its client. A direct client's connection has its place already, and
    // its subscriptions stop short of the cap. Either way one with no place is refused after the upgrade.
    let trusted = state.relay.config.front.trusts(client_ip(peer));
    let slot = if trusted { admission.take(ip) } else { admission.subscription(ip) };
    let log_ip = state.relay.config.front.log_ip;
    let upgrade = upgrade.read_buffer_size(crate::ws::READ_BUFFER);
    upgrade.max_message_size(limit).max_frame_size(limit).on_upgrade(move |mut socket| async move {
        if slot.is_none() {
            crate::ws::at_limit(&mut socket).await;
            return;
        }
        crate::ws::serve(socket, state.relay, state.stop, state.tracker, ip).await;
        // The socket and, for a direct client, its connection with the place are dropped by now; a trusted
        // proxy's client place is dropped just below. Both held a place under `bucket(ip)` (a direct client's
        // is the server task's `Conn._slot`, freed with the socket; a proxied client's is `slot`, taken
        // above, and a direct client's `slot` is its place under the subscription limit), so `held` counts it
        // freed. The one gap: a 101 whose upgrade never runs (the client gone
        // before `on_upgrade`) frees its place in the server task's drop of the connection and writes no
        // closed line. A refused subscription held no place and writes none, nor do plain HTTP connections.
        drop(slot);
        tracing::info!(event = "connection-closed", ip = %log_ip.show(ip), held = admission.held(ip));
    })
}

pub(crate) async fn not_found() -> Response {
    error_response(Rejection::new(Code::NotFound))
}
