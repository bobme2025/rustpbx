//! Park console handlers — per-agent ringback management (design doc §7 / R1c).
//!
//! Ringback files live at `{sounds_dir}/agents/{ext}/ringback.wav`; `ext` is
//! digits-only. Upload reuses the queue console audio-import validation chain
//! (SSRF guard, wav/mp3 whitelist, size cap, payload header check) with the
//! destination constrained to the per-agent park subdirectory, so a park
//! target without `progress=` picks the file up through the app's
//! three-level ringback resolution.

use crate::console::{ConsoleState, middleware::AuthRequired};
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router as AxumRouter,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

/// Subdirectory under the sounds root holding per-agent ringback.
const AGENTS_SUBDIR: &str = "agents";
/// Fixed ringback file name inside the per-agent directory.
const RINGBACK_NAME: &str = "ringback.wav";

pub fn urls() -> AxumRouter<Arc<ConsoleState>> {
    AxumRouter::new()
        .route("/park/agents/{ext}/ringback", post(upload_ringback))
        .route("/park/agents/{ext}/ringback", get(serve_ringback))
        .route("/park/agents/{ext}/ringback", delete(delete_ringback))
        .route("/park/agents/ringback", get(list_ringbacks))
}

pub fn api_urls() -> AxumRouter<Arc<ConsoleState>> {
    AxumRouter::new()
        .route("/park/agents/{ext}/ringback", post(upload_ringback))
        .route("/park/agents/{ext}/ringback", get(serve_ringback))
        .route("/park/agents/{ext}/ringback", delete(delete_ringback))
        .route("/park/agents/ringback", get(list_ringbacks))
}

/// The sounds root: `[park] sounds_dir` when set, else the queue console
/// layout (`config/sounds` first, `sounds` fallback).
fn sounds_dir(state: &ConsoleState) -> PathBuf {
    if let Some(park) = state.config().park.as_ref()
        && !park.sounds_dir.trim().is_empty()
    {
        return PathBuf::from(park.sounds_dir.trim());
    }
    if PathBuf::from("config/sounds").exists() {
        PathBuf::from("config/sounds")
    } else {
        PathBuf::from("sounds")
    }
}

/// Validate the agent extension: digits only (doc §7: `ext` 仅数字).
fn valid_ext(ext: &str) -> bool {
    !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit())
}

/// The per-agent ringback path, or an error response for an invalid ext.
fn ringback_path(state: &ConsoleState, ext: &str) -> Result<PathBuf, Response> {
    if !valid_ext(ext) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Agent extension must be digits only" })),
        )
            .into_response());
    }
    Ok(sounds_dir(state)
        .join(AGENTS_SUBDIR)
        .join(ext)
        .join(RINGBACK_NAME))
}

/// POST `/park/agents/{ext}/ringback` — import a ringback from an http(s)
/// URL into `agents/{ext}/ringback.wav`.
///
/// Body: `{"url": "https://…/ring.wav"}`. The chain mirrors the queue
/// console audio import: scheme check → SSRF guard → extension whitelist →
/// size-capped download → payload validation (content-type + file header).
async fn upload_ringback(
    State(state): State<Arc<ConsoleState>>,
    AuthRequired(_): AuthRequired,
    AxumPath(ext): AxumPath<String>,
    Json(payload): Json<Value>,
) -> Response {
    let url = match payload.get("url").and_then(|v| v.as_str()) {
        Some(u) => u.trim().to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": "Missing 'url' field." })),
            )
                .into_response();
        }
    };
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "URL must start with http:// or https://" })),
        )
            .into_response();
    }
    // SSRF guard: never fetch internal/private addresses.
    if !crate::utils::is_url_ssrf_safe(&url) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "URL points to a private or internal address" })),
        )
            .into_response();
    }
    // Extension whitelist on the URL basename.
    let url_basename = url
        .split('/')
        .last()
        .unwrap_or("audio.wav")
        .split('?')
        .next()
        .unwrap_or("audio.wav");
    let url_ext = std::path::Path::new(url_basename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if url_ext != "wav" && url_ext != "mp3" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "URL must point to a .wav or .mp3 file" })),
        )
            .into_response();
    }

    let dest_path = match ringback_path(&state, &ext) {
        Ok(path) => path,
        Err(response) => return response,
    };

    // Size-capped download (30s timeout, `max_audio_download_bytes` cap).
    let opts =
        crate::http_util::HttpFetchOptions::new().with_timeout(std::time::Duration::from_secs(30));
    match crate::http_util::fetch_audio_bytes(
        state.http_client(),
        reqwest::Method::GET,
        &url,
        &opts,
        state.config().max_audio_download_bytes,
    )
    .await
    {
        Ok((bytes, headers)) => {
            let content_type = headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // Payload validation: content-type + magic-header + ext checks.
            if let Err(msg) = crate::utils::validate_audio_payload(&bytes, content_type, url_basename)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "status": "error", "message": msg })),
                )
                    .into_response();
            }
            if let Some(parent) = dest_path.parent()
                && let Err(e) = tokio::fs::create_dir_all(parent).await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "status": "error", "message": format!("Failed to create agent dir: {}", e) })),
                )
                    .into_response();
            }
            if let Err(e) = tokio::fs::write(&dest_path, &bytes).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "status": "error", "message": format!("Failed to save file: {}", e) })),
                )
                    .into_response();
            }
            let relative_path = format!(
                "{}/{}/{}/{}",
                sounds_dir(&state).display(),
                AGENTS_SUBDIR,
                ext,
                RINGBACK_NAME
            );
            tracing::info!(agent = %ext, path = %relative_path, "park: agent ringback uploaded");
            Json(json!({
                "status": "ok",
                "path": relative_path,
                "agent": ext,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "status": "error", "message": format!("Download failed: {}", e) })),
        )
            .into_response(),
    }
}

/// GET `/park/agents/{ext}/ringback` — serve the stored ringback file.
async fn serve_ringback(
    State(state): State<Arc<ConsoleState>>,
    AxumPath(ext): AxumPath<String>,
) -> Response {
    let full_path = match ringback_path(&state, &ext) {
        Ok(path) => path,
        Err(response) => return response,
    };
    // Traversal guard: canonical path must stay under the sounds root.
    let sounds_root = sounds_dir(&state);
    let canonical = match full_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    if !canonical.starts_with(&sounds_root.canonicalize().unwrap_or_else(|_| sounds_root.clone())) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    match tokio::fs::read(&full_path).await {
        Ok(bytes) => Response::builder()
            .header(header::CONTENT_TYPE, "audio/wav")
            .body(axum::body::Body::from(bytes))
            .unwrap(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

/// DELETE `/park/agents/{ext}/ringback` — remove the per-agent ringback
/// (falls back to the default tone on the next park entry).
async fn delete_ringback(
    State(state): State<Arc<ConsoleState>>,
    AuthRequired(_): AuthRequired,
    AxumPath(ext): AxumPath<String>,
) -> Response {
    let full_path = match ringback_path(&state, &ext) {
        Ok(path) => path,
        Err(response) => return response,
    };
    match tokio::fs::remove_file(&full_path).await {
        Ok(()) => {
            tracing::info!(agent = %ext, "park: agent ringback deleted");
            Json(json!({ "status": "ok", "agent": ext })).into_response()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Json(json!({ "status": "ok", "agent": ext, "note": "already absent" })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to delete: {}", e) })),
        )
            .into_response(),
    }
}

/// GET `/park/agents/ringback` — list agents that have an uploaded ringback.
async fn list_ringbacks(State(state): State<Arc<ConsoleState>>) -> Response {
    let agents_dir = sounds_dir(&state).join(AGENTS_SUBDIR);
    let mut agents = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&agents_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if !valid_ext(&name) {
                continue;
            }
            if entry.path().join(RINGBACK_NAME).is_file() {
                agents.push(name);
            }
        }
    }    agents.sort();
    Json(json!({ "status": "ok", "agents": agents })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_validation() {
        assert!(valid_ext("980885001"));
        assert!(valid_ext("1001"));
        assert!(!valid_ext(""));
        assert!(!valid_ext("a1001"));
        assert!(!valid_ext("1001/../etc"));
        assert!(!valid_ext("1001/2002"));
        assert!(!valid_ext("10 01"));
    }
}
