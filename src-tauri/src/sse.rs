//! SSE 클라이언트 (Phase 3): backend 의 /nodes/events 를 구독해 실시간 nudge.
//!
//! `data: change` 한 줄 받을 때마다 Tauri 이벤트 "remote-change" emit → JS 가
//! 즉시 delta(/changes) 가져옴. polling 은 fallback 으로 유지.
//!
//! Rust 측에서 도는 이유: 브라우저 EventSource 는 Authorization 헤더를 못 붙임.
//! reqwest streaming + Bearer 로 해결. 끊기면 백오프 재연결, 로그아웃 시 stop.
//! 401 이면 oauth 모듈의 직렬화된 refresh 로 새 토큰을 받아 즉시 재연결하고,
//! refresh 가 `auth_expired` 면 "auth-expired" 이벤트를 emit 하고 멈춘다.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tauri::{AppHandle, Emitter};

// 세대 카운터: stop() 또는 새 connect 시 증가시켜 옛 루프를 스스로 종료시킴.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ACTIVE: Mutex<Option<u64>> = Mutex::new(None);

enum SseError {
    /// 401: access token 만료/거부. 갱신 후 재연결.
    Unauthorized,
    Other(String),
}

/// 유효한 access token (oauth 모듈의 직렬화된 refresh 를 거친다: SSE 가 따로 refresh 하지 않음).
async fn fresh_token(stale: Option<String>) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || crate::oauth::access_token_blocking(stale.as_deref()))
        .await
        .map_err(|e| format!("join: {e}"))?
}

fn is_current(gen: u64) -> bool {
    ACTIVE.lock().unwrap().map(|g| g == gen).unwrap_or(false)
}

async fn run(app: AppHandle, url: String, initial_token: String, company: String, gen: u64) {
    let mut backoff = 1u64;
    let mut token = initial_token;
    let mut first = true;
    loop {
        if !is_current(gen) {
            return; // 새 세대/중지됨
        }
        // 재연결마다 최신 토큰: 연결이 오래 살아 있던 사이 만료됐을 수 있다 (캐시가 유효하면 그대로).
        if !first {
            match fresh_token(None).await {
                Ok(t) => token = t,
                Err(e) if crate::oauth::is_auth_expired(&e) => {
                    eprintln!("[sse] 세션 만료: 중지: {e}");
                    let _ = app.emit("auth-expired", e);
                    return;
                }
                Err(e) => eprintln!("[sse] 토큰 확보 실패 (기존 토큰으로 시도): {e}"),
            }
        }
        first = false;
        match connect_once(&app, &url, &token, &company, gen).await {
            Ok(()) => {
                // 정상 종료(서버가 닫음): 즉시 재연결 시도
                backoff = 1;
            }
            Err(SseError::Unauthorized) => {
                // 401: 이 토큰은 거부됨(stale). 직렬화된 refresh 로 새 토큰 받아 바로 재연결.
                match fresh_token(Some(token.clone())).await {
                    Ok(t) if t != token => {
                        token = t;
                        first = true; // 방금 받은 토큰으로 바로 연결
                        continue;
                    }
                    Ok(_) => eprintln!("[sse] 401 이 계속됨: {backoff}s 후 재시도"),
                    Err(e) if crate::oauth::is_auth_expired(&e) => {
                        eprintln!("[sse] 세션 만료: 중지: {e}");
                        let _ = app.emit("auth-expired", e);
                        return;
                    }
                    Err(e) => eprintln!("[sse] 401 후 refresh 실패: {e}: {backoff}s 후 재시도"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
            Err(SseError::Other(e)) => {
                eprintln!("[sse] 연결 오류: {e}: {backoff}s 후 재시도");
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30); // 지수 백오프, 최대 30s
            }
        }
    }
}

async fn connect_once(
    app: &AppHandle,
    url: &str,
    token: &str,
    company: &str,
    gen: u64,
) -> Result<(), SseError> {
    use futures_util::StreamExt;

    let res = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .header("X-Active-Company-Id", urlencoding::encode(company).as_ref())
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| SseError::Other(format!("GET: {e}")))?;
    if res.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(SseError::Unauthorized);
    }
    if !res.status().is_success() {
        return Err(SseError::Other(format!("status {}", res.status())));
    }

    let mut stream = res.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        if !is_current(gen) {
            return Ok(()); // 중지
        }
        let bytes = chunk.map_err(|e| SseError::Other(format!("stream: {e}")))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        // SSE 이벤트는 빈 줄로 구분: "data:" 라인이 있으면 nudge
        while let Some(pos) = buf.find("\n\n") {
            let event: String = buf.drain(..pos + 2).collect();
            if event.lines().any(|l| l.starts_with("data:")) {
                let _ = app.emit("remote-change", ());
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn sse_connect(app: AppHandle, url: String, token: String, company: String) {
    let gen = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    *ACTIVE.lock().unwrap() = Some(gen);
    tauri::async_runtime::spawn(run(app, url, token, company, gen));
}

#[tauri::command]
pub fn sse_disconnect() {
    *ACTIVE.lock().unwrap() = None; // 다음 체크에서 루프 종료
}
