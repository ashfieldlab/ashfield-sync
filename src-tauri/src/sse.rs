//! SSE 클라이언트 (Phase 3) — backend 의 /nodes/events 를 구독해 실시간 nudge.
//!
//! `data: change` 한 줄 받을 때마다 Tauri 이벤트 "remote-change" emit → JS 가
//! 즉시 delta(/changes) 가져옴. polling 은 fallback 으로 유지.
//!
//! Rust 측에서 도는 이유: 브라우저 EventSource 는 Authorization 헤더를 못 붙임.
//! reqwest streaming + Bearer 로 해결. 끊기면 백오프 재연결, 로그아웃 시 stop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tauri::{AppHandle, Emitter};

// 세대 카운터 — stop() 또는 새 connect 시 증가시켜 옛 루프를 스스로 종료시킴.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ACTIVE: Mutex<Option<u64>> = Mutex::new(None);

async fn run(app: AppHandle, url: String, token: String, company: String, gen: u64) {
    let mut backoff = 1u64;
    loop {
        if ACTIVE.lock().unwrap().map(|g| g != gen).unwrap_or(true) {
            return; // 새 세대/중지됨
        }
        match connect_once(&app, &url, &token, &company, gen).await {
            Ok(()) => {
                // 정상 종료(서버가 닫음) — 즉시 재연결 시도
                backoff = 1;
            }
            Err(e) => {
                eprintln!("[sse] 연결 오류: {e} — {backoff}s 후 재시도");
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
) -> Result<(), String> {
    use futures_util::StreamExt;

    let res = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .header("X-Active-Company-Id", urlencoding::encode(company).as_ref())
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| format!("GET: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("status {}", res.status()));
    }

    let mut stream = res.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        if ACTIVE.lock().unwrap().map(|g| g != gen).unwrap_or(true) {
            return Ok(()); // 중지
        }
        let bytes = chunk.map_err(|e| format!("stream: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        // SSE 이벤트는 빈 줄로 구분 — "data:" 라인이 있으면 nudge
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
