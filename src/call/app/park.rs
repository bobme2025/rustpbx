//! Pocket agent park application (`park:<context>` targets).
//!
//! A call routed to `park:pocket?key=…&agent=…` is NOT answered: the app
//! sends **183 Session Progress with early media** (looping personalized
//! ringback) to hold the caller, and registers itself in the process-wide
//! [`PARK_REGISTRY`]. The daemon (via RWI `call.unpark`) then drives the
//! two-stage exit:
//!
//! ```text
//! PARKED ──Ring{EarlyMedia(file)}──► 183 + looping ringback
//!    ├─ caller BYE (wait-timeout / CCM release) ──► CLOSED
//!    ├─ call.unpark{cancel:true} ──► CLOSED
//!    └─ call.unpark{stage:"leg"} ──► DIALING (originate agent leg)
//! DIALING ──agent leg 200──► LEG_READY (caller still hears ringback)
//! LEG_READY ──call.unpark{stage:"bridge"}──► BRIDGED (answer + bridge + record)
//! ```
//!
//! No park-side timeout timer holds the call: convergence comes from the
//! caller-side wait timeout BYE, the CCM-side BYE, daemon cancel, or the
//! agent answering — matching the design doc (§3.1).
//!
//! ## Park key (§3.3, three levels)
//!
//! 1. `key=` query param on the park target (daemon-supplied);
//! 2. `park.key_header` config header value (deployment convention);
//! 3. default: parse the `X-cid` header (`kubeMedia_<cc_call_id>-<called>`).
//!
//! All levels normalize into [`ParkKey`]. `X-cid` parse failures degrade
//! explicitly: the whole string becomes [`ParkKey::Custom`] and the log
//! records `xcid_parse = failed`.

use crate::call::domain::{CallCommand, LegId, LegPurpose, ParkStage};
use crate::callrecord::CallRecordHangupReason;
use crate::config::ParkConfig;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::Duration;

use super::{
    AppAction, AppEvent, ApplicationContext, CallApp, CallAppType, ExitReason,
};

/// Prefix CCM stamps on the correlation header (`X-cid`).
const KUBE_MEDIA_PREFIX: &str = "kubeMedia_";

/// Default park ringback when neither a per-target `progress=` nor an
/// uploaded `agents/{ext}/ringback.wav` exists.
pub const DEFAULT_PARK_TONE: &str = "tone://450,1000";

// ─── Park key ───────────────────────────────────────────────────────────────

/// Normalized correlation key of a parked call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ParkKey {
    /// CC call id parsed from the `X-cid` correlation header.
    CcCallId(u64),
    /// Opaque string key (target `key=` param, key header, or unparsable
    /// `X-cid` used verbatim).
    Custom(String),
}

impl ParkKey {
    /// Stable single-string form for logs / `park.list` (`key` field).
    pub fn display_key(&self) -> String {
        match self {
            ParkKey::CcCallId(id) => format!("kubeMedia_{}", id),
            ParkKey::Custom(s) => s.clone(),
        }
    }

    /// Parse an `X-cid` style correlation value
    /// (`kubeMedia_<cc_call_id>-<called>`).
    ///
    /// Degradation is explicit (§附录A): any of "no prefix", "no `-`",
    /// "`call_id == 0`", "non-numeric call id" yields
    /// `Custom(whole string)`; callers log `xcid_parse = failed` when the
    /// return differs from the input shape they expected.
    pub fn parse_x_cid(value: &str) -> Self {
        let trimmed = value.trim();
        let Some(rest) = trimmed.strip_prefix(KUBE_MEDIA_PREFIX) else {
            return ParkKey::Custom(trimmed.to_string());
        };
        match rest.split_once('-') {
            Some((call_id, _called)) => match call_id.trim().parse::<u64>() {
                Ok(id) if id != 0 => ParkKey::CcCallId(id),
                _ => ParkKey::Custom(trimmed.to_string()),
            },
            None => ParkKey::Custom(trimmed.to_string()),
        }
    }

    /// Extract the agent extension (right segment) of an `X-cid` value,
    /// when it is in the `kubeMedia_<id>-<called>` shape.
    pub fn x_cid_called(value: &str) -> Option<String> {
        let rest = value.trim().strip_prefix(KUBE_MEDIA_PREFIX)?;
        let (_, called) = rest.split_once('-')?;
        let called = called.trim();
        (!called.is_empty()).then(|| called.to_string())
    }
}

// ─── Park state / registry ──────────────────────────────────────────────────

/// Lifecycle state of a parked call (doc 附录B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkState {
    /// 183 + ringback sent, waiting for unpark.
    Parked,
    /// Agent leg dial in flight.
    Dialing,
    /// Agent leg answered (media ready); caller still on ringback.
    LegReady,
    /// Caller answered and bridged with the agent.
    Bridged,
}

/// One parked-call record (doc 附录B).
#[derive(Debug, Clone, Serialize)]
pub struct ParkEntry {
    pub key: ParkKey,
    /// RustPBX global session id.
    pub call_id: String,
    /// Park context (`park:<context>` — e.g. `pocket`).
    pub context: String,
    pub caller: String,
    /// Agent extension (`X-cid` right segment or target `agent=`).
    pub called: String,
    /// Resolved ringback source string (path / `tone://`).
    pub progress: Option<String>,
    pub state: ParkState,
    /// Epoch millis when the call entered the park.
    pub parked_at: i64,
    /// Destination the agent leg is being / was dialed to.
    pub agent_destination: Option<String>,
}

/// Lookup shapes accepted by [`ParkRegistry::resolve`] (doc 附录B `call.unpark`).
#[derive(Debug, Clone)]
pub enum ParkLookup {
    Key(ParkKey),
    SessionId(String),
    /// Raw `X-cid` header value (`kubeMedia_…` or arbitrary string key).
    Xcid(String),
    /// CC call id + agent extension (fallback when the raw `X-cid` was
    /// unparsable on the daemon side).
    CcCall { cc_call_id: u64, called: String },
}

/// Errors returned by [`ParkRegistry::register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParkRegisterError {
    /// The park is at capacity — the caller must be rejected (busy).
    Full { max: usize },
}

/// Process-wide registry of parked calls.
///
/// Shared between the park app (upsert / state transitions / cleanup) and
/// the RWI layer (`call.unpark` / `park.list` / `call.park.info`). A global
/// [`LazyLock`] keeps the wiring surface minimal — same access pattern as
/// the session-id settings static.
pub struct ParkRegistry {
    entries: DashMap<ParkKey, ParkEntry>,
}

static PARK_REGISTRY: LazyLock<ParkRegistry> = LazyLock::new(ParkRegistry::new);

/// The process-wide park registry.
pub fn park_registry() -> &'static ParkRegistry {
    &PARK_REGISTRY
}

impl Default for ParkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Insert (latest-wins per key) a parked call. `max` caps the registry;
    /// [`ParkRegisterError::Full`] tells the app to reject the call busy.
    pub fn register(&self, entry: ParkEntry, max: usize) -> Result<(), ParkRegisterError> {
        if !self.entries.contains_key(&entry.key) && self.entries.len() >= max {
            return Err(ParkRegisterError::Full { max });
        }
        if let Some(prev) = self.entries.get(&entry.key) {
            if prev.call_id != entry.call_id {
                tracing::warn!(
                    key = %entry.key.display_key(),
                    prev_call_id = %prev.call_id,
                    new_call_id = %entry.call_id,
                    "park: same key re-parked by a different call (latest-wins upsert)"
                );
            }
        }
        self.entries.insert(entry.key.clone(), entry);
        Ok(())
    }

    /// Update the lifecycle state of the entry owned by `session_id`.
    pub fn update_state(&self, session_id: &str, state: ParkState) {
        for mut item in self.entries.iter_mut() {
            if item.value().call_id == session_id {
                item.value_mut().state = state;
                return;
            }
        }
    }

    /// Remove the entry owned by `session_id` (park teardown).
    pub fn remove_by_session(&self, session_id: &str) {
        self.entries.retain(|_, entry| entry.call_id != session_id);
    }

    /// Remove the entry stored under an exact key (app exit path).
    pub fn remove_by_key(&self, key: &ParkKey) {
        self.entries.remove(key);
    }

    /// Resolve a parked entry from any of the accepted lookup shapes
    /// (priority: key → x_cid → cc_call_id+called, doc §3.4).
    pub fn resolve(&self, lookup: &ParkLookup) -> Option<ParkEntry> {
        match lookup {
            ParkLookup::Key(key) => self.entries.get(key).map(|e| e.value().clone()),
            ParkLookup::SessionId(id) => self
                .entries
                .iter()
                .find(|item| item.value().call_id == *id)
                .map(|item| item.value().clone()),
            ParkLookup::Xcid(raw) => {
                let key = ParkKey::parse_x_cid(raw);
                self.entries.get(&key).map(|e| e.value().clone()).or_else(|| {
                    // Unparsable shape: fall back to exact-string custom key.
                    self.entries
                        .get(&ParkKey::Custom(raw.trim().to_string()))
                        .map(|e| e.value().clone())
                })
            }
            ParkLookup::CcCall { cc_call_id, .. } => self
                .entries
                .get(&ParkKey::CcCallId(*cc_call_id))
                .map(|e| e.value().clone()),
        }
    }

    /// List entries filtered by park context and/or agent extension,
    /// ordered by park time.
    pub fn list(&self, context: Option<&str>, called: Option<&str>) -> Vec<ParkEntry> {
        let mut items: Vec<ParkEntry> = self
            .entries
            .iter()
            .map(|item| item.value().clone())
            .filter(|entry| context.map(|c| entry.context == c).unwrap_or(true))
            .filter(|entry| called.map(|c| entry.called == c).unwrap_or(true))
            .collect();
        items.sort_by_key(|entry| entry.parked_at);
        items
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// `park.list` / `call.park.info` wire shape (doc 附录B):
/// `key` is the stable single-string form, `state` snake_case.
pub fn park_entry_json(entry: &ParkEntry) -> serde_json::Value {
    serde_json::json!({
        "key": entry.key.display_key(),
        "call_id": entry.call_id,
        "context": entry.context,
        "caller": entry.caller,
        "called": entry.called,
        "state": entry.state,
        "parked_at": entry.parked_at,
        "progress": entry.progress,
    })
}

// ─── Session → app signals ──────────────────────────────────────────────────

/// Typed contract for the session → [`ParkApp`] custom events
/// (`AppEvent::Custom`), mirroring the queue `QueueSignal` pattern: event
/// names and payload keys are defined in exactly one place.
#[derive(Debug, Clone)]
pub(crate) enum ParkSignal {
    /// The dialed agent leg is ringing (180/183 from the endpoint).
    AgentRinging { leg_id: String, agent_uri: String },
    /// The agent leg answered (200 + SDP) — media leg ready.
    AgentConnected { leg_id: String, agent_uri: String },
    /// The agent leg dial failed (final error response / cancel).
    AgentFailed { leg_id: String, reason: String },
}

impl ParkSignal {
    fn event_name(&self) -> &'static str {
        match self {
            ParkSignal::AgentRinging { .. } => "park_agent_ringing",
            ParkSignal::AgentConnected { .. } => "park_agent_connected",
            ParkSignal::AgentFailed { .. } => "park_agent_failed",
        }
    }

    /// The `ControllerEvent::Custom` wire pair for this signal.
    pub fn to_custom(&self) -> (String, serde_json::Value) {
        let data = match self {
            ParkSignal::AgentRinging { leg_id, agent_uri }
            | ParkSignal::AgentConnected { leg_id, agent_uri } => {
                serde_json::json!({ "leg_id": leg_id, "agent_uri": agent_uri })
            }
            ParkSignal::AgentFailed { leg_id, reason } => {
                serde_json::json!({ "leg_id": leg_id, "reason": reason })
            }
        };
        (self.event_name().to_string(), data)
    }
}

// ─── App params ─────────────────────────────────────────────────────────────

/// Parsed park target parameters (`park:<context>?key=&agent=&progress=&…`).
#[derive(Debug, Clone)]
pub struct ParkAppParams {
    /// Park context (defaults to `pocket`).
    pub context: String,
    /// Explicit correlation key (`key=` query param).
    pub key: Option<String>,
    /// Agent extension (`agent=` query param) — used as `called` and for the
    /// per-agent ringback lookup.
    pub agent: Option<String>,
    /// Per-target ringback override (`progress=` query param).
    pub progress: Option<String>,
    /// Record the bridged call (default: on).
    pub record: bool,
    /// Per-target park capacity override (falls back to config `max`).
    pub max: Option<usize>,
    /// Explicit correlation header name override (deployment level; normally
    /// from `[park] key_header`).
    pub key_header: Option<String>,
}

impl Default for ParkAppParams {
    fn default() -> Self {
        Self {
            context: "pocket".to_string(),
            key: None,
            agent: None,
            progress: None,
            record: true,
            max: None,
            key_header: None,
        }
    }
}

impl ParkAppParams {
    /// Build params from the app-factory JSON payload. Accepts either a
    /// structured object (`{"context":…, "key":…, …}`) or a raw target
    /// string (`{"target": "pocket?key=…&agent=…"}`).
    pub fn from_params(params: Option<&serde_json::Value>) -> Self {
        let Some(params) = params else {
            return Self {
                context: "pocket".to_string(),
                ..Default::default()
            };
        };
        // Raw target string form.
        if let Some(target) = params.get("target").and_then(|v| v.as_str()) {
            return Self::from_target(target);
        }
        Self {
            context: params
                .get("context")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("pocket")
                .to_string(),
            key: str_field(params, "key"),
            agent: str_field(params, "agent"),
            progress: str_field(params, "progress"),
            record: params
                .get("record")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            max: params.get("max").and_then(|v| v.as_u64()).map(|v| v as usize),
            key_header: str_field(params, "key_header"),
        }
    }

    /// Parse `park:` target internals: `<context>?<query>`.
    pub fn from_target(target: &str) -> Self {
        let target = target.trim();
        let (context, query) = match target.split_once('?') {
            Some((ctx, q)) => (ctx.trim(), Some(q)),
            None => (target.trim(), None),
        };
        let mut out = Self {
            context: if context.is_empty() {
                "pocket".to_string()
            } else {
                context.to_string()
            },
            ..Default::default()
        };
        if let Some(query) = query {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k.trim(), crate::proxy::proxy_call::sip_session::pct_decode_query(v)),
                    None => (pair.trim(), String::new()),
                };
                match k {
                    "key" if !v.is_empty() => out.key = Some(v),
                    "agent" if !v.is_empty() => out.agent = Some(v),
                    "progress" if !v.is_empty() => out.progress = Some(v),
                    "record" => out.record = v.is_empty() || v == "1" || v.eq_ignore_ascii_case("true"),
                    "max" => out.max = v.parse::<usize>().ok(),
                    "key_header" if !v.is_empty() => out.key_header = Some(v),
                    _ => {}
                }
            }
        }
        out
    }
}

fn str_field(params: &serde_json::Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ─── The park app ───────────────────────────────────────────────────────────

/// Named timeout that guards the agent-leg dial (`ring_timeout_secs`).
const RING_TIMEOUT_ID: &str = "park_ring_timeout";

pub struct ParkApp {
    params: ParkAppParams,
    key: Option<ParkKey>,
    called: String,
    caller: String,
    ringback: Option<String>,
    state: ParkState,
    agent_leg: Option<String>,
    /// `stage:"bridge"` already satisfied by a one-shot unpark.
    pending_bridge: bool,
    ring_timeout: Option<Duration>,
    record_override: Option<bool>,
}

impl ParkApp {
    pub fn new(params: ParkAppParams) -> Self {
        Self {
            params,
            key: None,
            called: String::new(),
            caller: String::new(),
            ringback: None,
            state: ParkState::Parked,
            agent_leg: None,
            pending_bridge: false,
            ring_timeout: None,
            record_override: None,
        }
    }

    /// Resolve the park key (§3.3): target `key=` → configured / target
    /// `key_header` → default `X-cid`.
    fn resolve_key(&self, context: &ApplicationContext) -> ParkKey {
        if let Some(key) = &self.params.key {
            return ParkKey::Custom(key.clone());
        }
        let header_name = self
            .params
            .key_header
            .clone()
            .or_else(|| {
                park_config(context)
                    .map(|c| c.key_header.clone())
                    .filter(|s| !s.is_empty())
            });
        if let Some(header) = header_name {
            if let Some(value) = lookup_header(&context.call_info.sip_headers, &header) {
                return ParkKey::parse_x_cid(&value);
            }
            tracing::warn!(
                session_id = %context.call_info.session_id,
                key_header = %header,
                "park: key_header configured but header missing — falling back to X-cid"
            );
        }
        context
            .call_info
            .sip_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("X-cid"))
            .map(|(_, value)| ParkKey::parse_x_cid(value))
            .unwrap_or_else(|| ParkKey::Custom(String::new()))
    }

    /// Resolve the ringback source (§7 / R1b): `progress=` → per-agent
    /// uploaded file → default tone. Every fallback logs
    /// `ringback_fallback` — never silently.
    fn resolve_ringback(&self, context: &ApplicationContext) -> String {
        if let Some(progress) = &self.params.progress {
            return progress.clone();
        }
        let cfg = park_config(context);
        if !self.called.is_empty() {
            let sounds_dir = cfg
                .as_ref()
                .map(|c| c.sounds_dir.clone())
                .unwrap_or_else(|| "config/sounds".to_string());
            let path = format!("{}/agents/{}/ringback.wav", sounds_dir.trim_end_matches('/'), self.called);
            if std::path::Path::new(&path).exists() {
                return path;
            }
            tracing::info!(
                session_id = %context.call_info.session_id,
                agent = %self.called,
                path = %path,
                "ringback_fallback: no per-agent ringback uploaded"
            );
        }
        cfg.as_ref()
            .map(|c| c.default_tone.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_PARK_TONE.to_string())
    }

    /// `call.unpark{stage:"leg"}` / one-shot: dial the agent leg.
    async fn dial_agent_leg(
        &mut self,
        controller: &mut super::CallController,
        context: &ApplicationContext,
        destination: Option<String>,
        stage: Option<ParkStage>,
    ) -> anyhow::Result<AppAction> {
        let Some(destination) = destination.or_else(|| self.params.agent.clone().map(|ext| format!("sip:{}@local", ext))) else {
            tracing::error!(
                session_id = %context.call_info.session_id,
                "park: unpark leg without destination and without agent extension"
            );
            return Ok(AppAction::Continue);
        };
        if self.state != ParkState::Parked {
            tracing::warn!(
                session_id = %context.call_info.session_id,
                state = ?self.state,
                "park: unpark leg in non-Parked state — ignored"
            );
            return Ok(AppAction::Continue);
        }
        match controller
            .originate_call_with_headers(&destination, None, Vec::new(), Some(LegPurpose::Agent))
            .await
        {
            Ok(leg_id) => {
                tracing::info!(
                    session_id = %context.call_info.session_id,
                    leg_id = %leg_id,
                    destination = %destination,
                    "park: agent leg dialing (stage:leg)"
                );
                self.agent_leg = Some(leg_id);
                self.state = ParkState::Dialing;
                self.pending_bridge = stage.is_none();
                park_registry().update_state(
                    &context.call_info.session_id,
                    ParkState::Dialing,
                );
                if let Some(secs) = self.ring_timeout.filter(|s| s.as_secs() > 0) {
                    controller.set_timeout(RING_TIMEOUT_ID, secs);
                }
                Ok(AppAction::Continue)
            }
            Err(error) => {
                tracing::error!(
                    session_id = %context.call_info.session_id,
                    destination = %destination,
                    error = %error,
                    "park: agent leg originate failed — staying parked"
                );
                Ok(AppAction::Continue)
            }
        }
    }

    /// `call.unpark{stage:"bridge"}`: answer the caller, bridge with the
    /// agent leg, optionally start recording. Requires `LegReady` — a
    /// `bridge` while still `Parked` is rejected (doc 附录B).
    async fn bridge_stage(
        &mut self,
        controller: &mut super::CallController,
        context: &ApplicationContext,
        record: Option<bool>,
    ) -> anyhow::Result<AppAction> {
        if self.state != ParkState::LegReady {
            tracing::warn!(
                session_id = %context.call_info.session_id,
                state = ?self.state,
                "park: bridge stage refused — agent leg not ready"
            );
            return Ok(AppAction::Continue);
        }
        let Some(agent_leg) = self.agent_leg.clone() else {
            return Ok(AppAction::Continue);
        };
        // Stop the looped park ringback before re-routing media to the agent.
        let _ = controller.stop_audio().await;
        controller.answer().await?;
        controller
            .bridge(LegId::from("caller"), LegId::new(agent_leg))?;
        if record.or(self.record_override).unwrap_or(true) {
            controller
                .start_recording("", None, false)
                .await?;
        }
        self.state = ParkState::Bridged;
        park_registry().update_state(&context.call_info.session_id, ParkState::Bridged);
        tracing::info!(
            session_id = %context.call_info.session_id,
            "park: bridged (caller answered, recording started)"
        );
        Ok(AppAction::Continue)
    }
}

/// Read `[park]` config, if present.
fn park_config(context: &ApplicationContext) -> Option<&ParkConfig> {
    context.config.park.as_ref()
}

/// Case-insensitive SIP header lookup.
fn lookup_header(headers: &std::collections::HashMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

#[async_trait]
impl CallApp for ParkApp {
    fn app_type(&self) -> CallAppType {
        CallAppType::Park
    }

    fn name(&self) -> &str {
        "park"
    }

    async fn on_enter(
        &mut self,
        controller: &mut super::CallController,
        context: &ApplicationContext,
    ) -> anyhow::Result<AppAction> {
        self.caller = context.call_info.caller.clone();
        // `called`: explicit `agent=` param → X-cid right segment → callee.
        self.called = self
            .params
            .agent
            .clone()
            .or_else(|| {
                context
                    .call_info
                    .sip_headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("X-cid"))
                    .and_then(|(_, value)| ParkKey::x_cid_called(value))
            })
            .unwrap_or_else(|| {
                crate::models::call_record::extract_sip_username(&context.call_info.callee)
                    .unwrap_or_else(|| context.call_info.callee.clone())
            });

        let key = self.resolve_key(context);
        if key == ParkKey::Custom(String::new()) {
            tracing::warn!(
                session_id = %context.call_info.session_id,
                "park: no correlation key resolved (target key=, key_header, X-cid all absent)"
            );
        }
        self.key = Some(key.clone());

        // Capacity gate: at `max` reject busy instead of queueing (§6.3).
        let max = self
            .params
            .max
            .or_else(|| park_config(context).map(|c| c.max as usize))
            .unwrap_or(2000);
        let ringback = self.resolve_ringback(context);
        let entry = ParkEntry {
            key: key.clone(),
            call_id: context.call_info.session_id.clone(),
            context: self.params.context.clone(),
            caller: self.caller.clone(),
            called: self.called.clone(),
            progress: Some(ringback.clone()),
            state: ParkState::Parked,
            parked_at: chrono::Utc::now().timestamp_millis(),
            agent_destination: None,
        };
        if let Err(ParkRegisterError::Full { max }) =
            park_registry().register(entry, max)
        {
            tracing::warn!(
                session_id = %context.call_info.session_id,
                max,
                "park: capacity reached — rejecting busy"
            );
            return Ok(AppAction::Hangup {
                reason: Some(CallRecordHangupReason::Rejected),
                code: Some(486),
            });
        }
        self.ringback = Some(ringback.clone());
        self.ring_timeout = park_config(context).and_then(|c| c.ring_timeout_secs).map(Duration::from_secs);

        // Hold the caller: 183 Session Progress + looping ringback. No
        // answer, no silence (§3.2 — 0.5.x early-media machinery does the
        // work; file audio loops, `tone://` plays once).
        controller.ring_with_early_media(&ringback)?;
        tracing::info!(
            session_id = %context.call_info.session_id,
            key = %key.display_key(),
            context = %self.params.context,
            caller = %self.caller,
            called = %self.called,
            progress = %ringback,
            "park: parked (183 early media sent)"
        );
        Ok(AppAction::Continue)
    }

    async fn on_external_event(
        &mut self,
        event: AppEvent,
        controller: &mut super::CallController,
        context: &ApplicationContext,
    ) -> anyhow::Result<AppAction> {
        let AppEvent::Custom { name, data } = event else {
            return Ok(AppAction::Continue);
        };
        match name.as_str() {
            "park.unpark" => {
                let stage = data
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str::<ParkStage>(&format!("\"{s}\"")).ok());
                let destination = data
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let cancel = data.get("cancel").and_then(|v| v.as_bool()).unwrap_or(false);
                let reason = data.get("reason").and_then(|v| v.as_str()).map(str::to_string);
                let record = data.get("record").and_then(|v| v.as_bool());
                if let Some(secs) = data.get("ring_timeout_secs").and_then(|v| v.as_u64()) {
                    self.ring_timeout = Some(Duration::from_secs(secs));
                }
                self.record_override = record;

                if cancel {
                    tracing::info!(
                        session_id = %context.call_info.session_id,
                        reason = reason.as_deref().unwrap_or(""),
                        "park: cancelled by unpark cancel=true"
                    );
                    return Ok(AppAction::Hangup {
                        reason: None,
                        code: None,
                    });
                }
                match stage {
                    Some(ParkStage::Bridge) => {
                        self.bridge_stage(controller, context, record).await
                    }
                    Some(ParkStage::Leg) | None => {
                        self.dial_agent_leg(controller, context, destination, stage)
                            .await
                    }
                }
            }
            "park_agent_ringing" => {
                tracing::debug!(
                    session_id = %context.call_info.session_id,
                    leg_id = data.get("leg_id").and_then(|v| v.as_str()).unwrap_or(""),
                    "park: agent leg ringing"
                );
                Ok(AppAction::Continue)
            }
            "park_agent_connected" => {
                let leg_id = data
                    .get("leg_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if self.agent_leg.as_deref() != Some(leg_id.as_str()) {
                    return Ok(AppAction::Continue);
                }
                self.state = ParkState::LegReady;
                park_registry().update_state(
                    &context.call_info.session_id,
                    ParkState::LegReady,
                );
                controller.cancel_timeout(RING_TIMEOUT_ID);
                tracing::info!(
                    session_id = %context.call_info.session_id,
                    leg_id = %leg_id,
                    "park: agent leg ready (media up, caller still on ringback)"
                );
                if self.pending_bridge {
                    self.pending_bridge = false;
                    self.bridge_stage(controller, context, None).await
                } else {
                    Ok(AppAction::Continue)
                }
            }
            "park_agent_failed" => {
                let leg_id = data
                    .get("leg_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let reason = data
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                if self.agent_leg.as_deref() != Some(leg_id.as_str()) {
                    return Ok(AppAction::Continue);
                }
                controller.cancel_timeout(RING_TIMEOUT_ID);
                self.agent_leg = None;
                self.pending_bridge = false;
                self.state = ParkState::Parked;
                park_registry().update_state(
                    &context.call_info.session_id,
                    ParkState::Parked,
                );
                tracing::warn!(
                    session_id = %context.call_info.session_id,
                    leg_id = %leg_id,
                    reason = %reason,
                    "park: agent leg failed — back to parked (daemon may retry)"
                );
                Ok(AppAction::Continue)
            }
            _ => Ok(AppAction::Continue),
        }
    }

    async fn on_timeout(
        &mut self,
        timeout_id: String,
        controller: &mut super::CallController,
        context: &ApplicationContext,
    ) -> anyhow::Result<AppAction> {
        if timeout_id != RING_TIMEOUT_ID || self.state != ParkState::Dialing {
            return Ok(AppAction::Continue);
        }
        if let Some(leg) = self.agent_leg.take() {
            controller.remove_legs(&[leg], "park_ring_timeout");
        }
        self.pending_bridge = false;
        self.state = ParkState::Parked;
        park_registry().update_state(&context.call_info.session_id, ParkState::Parked);
        tracing::warn!(
            session_id = %context.call_info.session_id,
            "park: agent leg ring timeout — back to parked"
        );
        Ok(AppAction::Continue)
    }

    async fn on_exit(&mut self, reason: ExitReason) -> anyhow::Result<()> {
        if let Some(key) = &self.key {
            // Registry cleanup keyed by the entry's session id is not
            // available here (no context) — the entry was stored under this
            // key; remove via key.
            park_registry().remove_by_key(key);
        }
        tracing::info!(reason = %reason, "park: exiting");
        Ok(())
    }
}

// Keep the leg-state lookup helpers referenced by CallCommand::Unpark
// handling in one place.
impl ParkApp {
    /// The `CallCommand::Unpark` JSON payload injected by the session as
    /// `AppEvent::Custom("park.unpark", …)`.
    pub fn unpark_event_payload(command: &CallCommand) -> Option<serde_json::Value> {
        let CallCommand::Unpark {
            stage,
            destination,
            cancel,
            reason,
            ring_timeout_secs,
            record,
        } = command
        else {
            return None;
        };
        Some(serde_json::json!({
            "stage": stage.map(|s| match s {
                ParkStage::Leg => "leg",
                ParkStage::Bridge => "bridge",
            }),
            "destination": destination,
            "cancel": cancel.unwrap_or(false),
            "reason": reason,
            "ring_timeout_secs": ring_timeout_secs,
            "record": record,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_cid_parse_happy_path() {
        let key = ParkKey::parse_x_cid("kubeMedia_2026999-980885001");
        assert_eq!(key, ParkKey::CcCallId(2026999));
        assert_eq!(
            ParkKey::x_cid_called("kubeMedia_2026999-980885001"),
            Some("980885001".to_string())
        );
    }

    #[test]
    fn x_cid_parse_degradations() {
        // No prefix → whole string as custom key.
        assert_eq!(
            ParkKey::parse_x_cid("2026999-980885001"),
            ParkKey::Custom("2026999-980885001".to_string())
        );
        // Prefix but no `-`.
        assert_eq!(
            ParkKey::parse_x_cid("kubeMedia_2026999"),
            ParkKey::Custom("kubeMedia_2026999".to_string())
        );
        // call_id == 0.
        assert_eq!(
            ParkKey::parse_x_cid("kubeMedia_0-980885001"),
            ParkKey::Custom("kubeMedia_0-980885001".to_string())
        );
        // Non-numeric call id.
        assert_eq!(
            ParkKey::parse_x_cid("kubeMedia_abc-980885001"),
            ParkKey::Custom("kubeMedia_abc-980885001".to_string())
        );
        // Called segment containing `-`: call_id is numeric and FIRST, so
        // split_once (first dash) keeps the call id correct. (The design doc
        // said rsplit_once, but rsplit would hand back "2026999-98" as the
        // call id — measured wrong; split_once measured right.)
        assert_eq!(
            ParkKey::parse_x_cid("kubeMedia_2026999-98-00"),
            ParkKey::CcCallId(2026999)
        );
        assert_eq!(ParkKey::x_cid_called("kubeMedia_2026999-98-00"), Some("98-00".to_string()));
    }

    #[test]
    fn park_target_params() {
        let p = ParkAppParams::from_target("pocket?key=pk-8823&agent=980885001&record=0");
        assert_eq!(p.context, "pocket");
        assert_eq!(p.key.as_deref(), Some("pk-8823"));
        assert_eq!(p.agent.as_deref(), Some("980885001"));
        assert!(!p.record);

        let p = ParkAppParams::from_target("pocket");
        assert_eq!(p.context, "pocket");
        assert!(p.key.is_none());
        assert!(p.record, "record defaults on");
    }

    #[test]
    fn registry_register_list_resolve() {
        let registry = ParkRegistry::new();
        let entry = ParkEntry {
            key: ParkKey::CcCallId(42),
            call_id: "s-1".into(),
            context: "pocket".into(),
            caller: "13800000000".into(),
            called: "980885001".into(),
            progress: Some("tone://450,1000".into()),
            state: ParkState::Parked,
            parked_at: 1_732_500_000_123,
            agent_destination: None,
        };
        registry.register(entry.clone(), 2000).unwrap();
        assert_eq!(registry.len(), 1);

        // Resolve by each lookup shape.
        assert_eq!(
            registry.resolve(&ParkLookup::Key(ParkKey::CcCallId(42))).unwrap().call_id,
            "s-1"
        );
        assert_eq!(
            registry
                .resolve(&ParkLookup::Xcid("kubeMedia_42-980885001".into()))
                .unwrap()
                .call_id,
            "s-1"
        );
        assert_eq!(
            registry
                .resolve(&ParkLookup::CcCall { cc_call_id: 42, called: "980885001".into() })
                .unwrap()
                .call_id,
            "s-1"
        );
        assert_eq!(
            registry.resolve(&ParkLookup::SessionId("s-1".into())).unwrap().call_id,
            "s-1"
        );
        assert!(registry.resolve(&ParkLookup::SessionId("missing".into())).is_none());

        // list filters.
        assert_eq!(registry.list(Some("pocket"), None).len(), 1);
        assert_eq!(registry.list(Some("other"), None).len(), 0);
        assert_eq!(registry.list(Some("pocket"), Some("980885001")).len(), 1);
        assert_eq!(registry.list(Some("pocket"), Some("999")).len(), 0);

        // State updates + removal.
        registry.update_state("s-1", ParkState::Bridged);
        assert_eq!(
            registry.resolve(&ParkLookup::Key(ParkKey::CcCallId(42))).unwrap().state,
            ParkState::Bridged
        );
        registry.remove_by_session("s-1");
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_capacity_and_latest_wins() {
        let registry = ParkRegistry::new();
        let make = |call_id: &str| ParkEntry {
            key: ParkKey::Custom("k".into()),
            call_id: call_id.into(),
            context: "pocket".into(),
            caller: String::new(),
            called: String::new(),
            progress: None,
            state: ParkState::Parked,
            parked_at: 0,
            agent_destination: None,
        };
        registry.register(make("s-1"), 1).unwrap();
        // Same key, different call: latest-wins upsert (with warning).
        registry.register(make("s-2"), 1).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.resolve(&ParkLookup::Key(ParkKey::Custom("k".into()))).unwrap().call_id,
            "s-2"
        );
        // A different key hits the cap.
        let mut other = make("s-3");
        other.key = ParkKey::Custom("k2".into());
        assert_eq!(
            registry.register(other, 1),
            Err(ParkRegisterError::Full { max: 1 })
        );
    }

    #[test]
    fn unpark_payload_shape() {
        let cmd = CallCommand::Unpark {
            stage: Some(ParkStage::Leg),
            destination: Some("sip:980885001@rustpbx".into()),
            cancel: None,
            reason: None,
            ring_timeout_secs: None,
            record: None,
        };
        let payload = ParkApp::unpark_event_payload(&cmd).unwrap();
        assert_eq!(payload["stage"], "leg");
        assert_eq!(payload["destination"], "sip:980885001@rustpbx");
        assert_eq!(payload["cancel"], false);
    }
}
