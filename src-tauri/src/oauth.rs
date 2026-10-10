//! OAuth 2.1 + PKCE: Ashfield 계정 서버(OIDC 제공자) 로그인.
//!
//! - 로그인: 시스템 브라우저 → 계정 서버 authorize → loopback callback
//!   (`http://127.0.0.1:1421/oauth/callback`) → token 교환
//! - 엔드포인트는 `${ACCOUNT_URL}/.well-known/openid-configuration` 에서 읽는다
//!   (실패 시 계약상 기본 경로 `/api/auth/oauth2/*` 로 fallback)
//! - authorize, token, refresh 모두 `resource=<DRIVE_RESOURCE>`: 이게 있어야 access token 이
//!   JWT(aud ∋ DRIVE_RESOURCE)로 나와 Drive 백엔드가 JWKS 로 검증할 수 있다
//! - refresh_token 은 OS keychain (Windows Credential Manager) 에 보관
//! - refresh_token 은 **회전**한다: 갱신마다 새 값 저장, 옛 값을 다시 쓰면 패밀리 전체가 폐기됨.
//!   그래서 갱신은 프로세스 전체에서 이 모듈 한 곳(`SESSION` 락)으로 직렬화한다.
//!   JS(API 401), SSE 재연결, VFS hydrate 스레드가 모두 여기로 온다 (single-flight).
//!
//! 계약: ashfield-account/docs/adr/0001-account-server-contract.md, 원 결정 ADR-0015.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const KEYRING_SERVICE: &str = "ashfield-sync";
pub(crate) const KEYRING_USERNAME: &str = "refresh_token";

/// 계약 §2: 이 클라이언트에 허용된 scope 전부. `offline_access` 가 있어야 refresh_token 이 나온다.
pub(crate) const SCOPES: &str = "openid profile email offline_access";
/// 만료 이만큼 전이면 캐시된 access token 을 버리고 갱신 (시계 오차와 전송 지연 여유).
const EXPIRY_SKEW: Duration = Duration::from_secs(60);
/// 로그인 창에서 사용자를 기다리는 최대 시간.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
/// refresh 가 재로그인 외엔 방법이 없을 때 에러 문자열 앞에 붙는 표식: JS/SSE 가 이걸로 판별.
pub(crate) const AUTH_EXPIRED: &str = "auth_expired";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// 계정 서버 URL = OIDC issuer (끝 슬래시 없음). 예: http://localhost:3300
    pub issuer: String,
    pub client_id: String,
    pub redirect_port: u16,
    /// RFC 8707 resource: Drive 의 public URL (= access token `aud`). 예: http://localhost:3200
    pub resource: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// 디스커버리
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Endpoints {
    pub issuer: String,
    pub authorization: String,
    pub token: String,
    pub revocation: String,
}

impl Endpoints {
    /// 디스커버리 실패 시: 계약 §1 의 고정 경로.
    pub(crate) fn fallback(issuer: &str) -> Self {
        let iss = issuer.trim_end_matches('/');
        Self {
            issuer: iss.to_string(),
            authorization: format!("{iss}/api/auth/oauth2/authorize"),
            token: format!("{iss}/api/auth/oauth2/token"),
            revocation: format!("{iss}/api/auth/oauth2/revoke"),
        }
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
}

static ENDPOINTS: Mutex<Option<Endpoints>> = Mutex::new(None);
static CONFIG: Mutex<Option<OAuthConfig>> = Mutex::new(None);

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// 디스커버리 문서에서 엔드포인트: 성공한 결과만 프로세스 동안 캐시.
fn endpoints(config: &OAuthConfig) -> Endpoints {
    let issuer = config.issuer.trim_end_matches('/').to_string();
    if let Some(ep) = ENDPOINTS.lock().unwrap().as_ref() {
        if ep.issuer == issuer {
            return ep.clone();
        }
    }
    let fallback = Endpoints::fallback(&issuer);
    let url = format!("{issuer}/.well-known/openid-configuration");
    let fetched = http()
        .get(&url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json::<Discovery>());
    match fetched {
        Ok(d) => {
            if let Some(found) = d.issuer.as_deref() {
                if found.trim_end_matches('/') != issuer {
                    eprintln!("[oauth] discovery issuer 불일치: {found} != {issuer}");
                }
            }
            let ep = Endpoints {
                issuer: issuer.clone(),
                authorization: d.authorization_endpoint.unwrap_or(fallback.authorization),
                token: d.token_endpoint.unwrap_or(fallback.token),
                revocation: d.revocation_endpoint.unwrap_or(fallback.revocation),
            };
            *ENDPOINTS.lock().unwrap() = Some(ep.clone());
            ep
        }
        Err(e) => {
            eprintln!("[oauth] discovery 실패 ({url}): {e}: 기본 경로 사용");
            fallback
        }
    }
}

fn remember_config(config: &OAuthConfig) {
    *CONFIG.lock().unwrap() = Some(config.clone());
}

fn stored_config() -> Result<OAuthConfig> {
    CONFIG
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("oauth 설정 없음: 로그인/refresh 가 먼저 호출돼야 함"))
}

// ---------------------------------------------------------------------------
// PKCE, authorize URL
// ---------------------------------------------------------------------------

fn random_url_safe(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

pub(crate) fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn pkce_pair() -> (String, String) {
    let verifier = random_url_safe(64); // 86자: RFC 7636 의 43..128 범위
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub(crate) fn redirect_uri(port: u16) -> String {
    // 등록된 값과 정확히 일치해야 한다 (계약 §2). 리스너도 127.0.0.1 에만 bind.
    format!("http://127.0.0.1:{port}/oauth/callback")
}

pub(crate) struct AuthorizeParams<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
    pub resource: &'a str,
}

/// ashfield-account/scripts/oidc-flow-check.ts 와 같은 파라미터.
pub(crate) fn build_authorize_url(endpoint: &str, p: &AuthorizeParams) -> Result<String> {
    let mut url = url::Url::parse(endpoint).context("authorization_endpoint URL")?;
    url.query_pairs_mut()
        .clear()
        .append_pair("response_type", "code")
        .append_pair("client_id", p.client_id)
        .append_pair("redirect_uri", p.redirect_uri)
        .append_pair("scope", SCOPES)
        .append_pair("state", p.state)
        .append_pair("nonce", p.nonce)
        .append_pair("code_challenge", p.code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", p.resource);
    Ok(url.into())
}

/// id_token payload 의 nonce (서명 검증 없이: token 엔드포인트에서 TLS 로 직접 받은 값,
/// API 호출엔 안 씀. 리플레이된 code 로 얻은 토큰 섞임만 막는 용도).
fn id_token_nonce(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("nonce")?.as_str().map(str::to_string)
}

// ---------------------------------------------------------------------------
// 세션: access token 캐시 + 현재 refresh token. 이 락이 곧 refresh 직렬화 락.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct Session {
    pub access_token: String,
    pub expires_at: Instant,
    /// 가장 최근에 받은 refresh token. keychain 쓰기가 실패해도 이 프로세스에선 이걸 쓴다.
    pub refresh_token: Option<String>,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

/// 캐시된 access token 을 그대로 줘도 되나?
/// - 만료 전(여유 포함)이어야 하고
/// - 호출자가 "이 토큰은 거부됐다"(stale)고 알려준 바로 그 토큰이 아니어야 한다.
///   (stale 과 다르면 = 그 사이 다른 호출자가 이미 갱신함 → 재사용, 중복 refresh 안 함)
pub(crate) fn can_reuse(cached: &Session, stale: Option<&str>, now: Instant) -> bool {
    cached.expires_at > now + EXPIRY_SKEW && stale != Some(cached.access_token.as_str())
}

pub(crate) enum RefreshError {
    /// invalid_grant 등: 저장된 refresh token 은 죽었다. 재로그인 필요.
    Expired(String),
    /// 네트워크, 5xx 등: 토큰은 살아 있을 수 있음. 나중에 재시도.
    Transient(String),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::Expired(m) => write!(f, "{AUTH_EXPIRED}: {m}"),
            RefreshError::Transient(m) => write!(f, "{m}"),
        }
    }
}

/// 유효한 access token 을 돌려준다. 필요할 때만, 그리고 한 번에 하나만 refresh.
///
/// `slot` 락을 refresh 네트워크 요청 동안 쥐고 있으므로 동시 호출자는 기다렸다가
/// 갱신된 결과를 재사용한다. `do_refresh(현재 refresh_token)` 은 새 세션을 돌려준다.
pub(crate) fn get_or_refresh<F>(
    slot: &Mutex<Option<Session>>,
    stale: Option<&str>,
    do_refresh: F,
) -> Result<Session, RefreshError>
where
    F: FnOnce(Option<String>) -> Result<Session, RefreshError>,
{
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.as_ref() {
        if can_reuse(cached, stale, Instant::now()) {
            return Ok(cached.clone());
        }
    }
    let current_refresh = guard.as_ref().and_then(|s| s.refresh_token.clone());
    match do_refresh(current_refresh) {
        Ok(next) => {
            *guard = Some(next.clone());
            Ok(next)
        }
        Err(e) => {
            if matches!(e, RefreshError::Expired(_)) {
                *guard = None;
            }
            Err(e)
        }
    }
}

fn keyring_entry() -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, KEYRING_USERNAME).context("keyring entry")
}

fn store_refresh(token: &str) {
    match keyring_entry().and_then(|e| e.set_password(token).map_err(Into::into)) {
        Ok(()) => {}
        // 옛 값은 서버에서 이미 무효: 메모리의 새 값으로 이 세션은 계속 간다.
        Err(e) => eprintln!("[oauth] keychain 에 새 refresh_token 저장 실패: {e}"),
    }
}

fn session_from(token: TokenResponse, previous_refresh: Option<String>) -> Session {
    let ttl = token.expires_in.unwrap_or(900);
    // 회전: 새 refresh 가 오면 그걸로 교체 (계약상 항상 온다). 안 오면 옛 것 유지.
    let refresh = token.refresh_token.or(previous_refresh);
    if let Some(rt) = refresh.as_deref() {
        store_refresh(rt);
    }
    Session {
        access_token: token.access_token,
        expires_at: Instant::now() + Duration::from_secs(ttl),
        refresh_token: refresh,
    }
}

/// 실제 refresh_token grant (blocking). `SESSION` 락 안에서만 호출된다.
fn refresh_grant(config: &OAuthConfig, current: Option<String>) -> Result<Session, RefreshError> {
    let refresh = match current {
        Some(rt) => rt,
        None => keyring_entry()
            .and_then(|e| e.get_password().map_err(Into::into))
            .map_err(|_| RefreshError::Expired("저장된 refresh_token 없음".into()))?,
    };
    let ep = endpoints(config);
    let res = http()
        .post(&ep.token)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", config.client_id.as_str()),
            ("refresh_token", refresh.as_str()),
            ("resource", config.resource.as_str()),
        ])
        .send()
        .map_err(|e| RefreshError::Transient(format!("refresh POST: {e}")))?;
    let status = res.status();
    if !status.is_success() {
        let body = res.text().unwrap_or_default();
        let code = serde_json::from_str::<OAuthErrorBody>(&body)
            .ok()
            .and_then(|b| b.error)
            .unwrap_or_default();
        // 400 invalid_grant = 만료, 폐기, 재사용 감지(패밀리 폐기). 401 invalid_client 도 복구 불가.
        if status.as_u16() == 400 || status.as_u16() == 401 || code == "invalid_grant" {
            if let Ok(e) = keyring_entry() {
                let _ = e.delete_credential();
            }
            return Err(RefreshError::Expired(format!("refresh {status}: {body}")));
        }
        return Err(RefreshError::Transient(format!("refresh {status}: {body}")));
    }
    let token: TokenResponse = res
        .json()
        .map_err(|e| RefreshError::Transient(format!("parse refresh response: {e}")))?;
    Ok(session_from(token, Some(refresh)))
}

/// 다른 모듈(SSE, VFS)용: 유효한 access token (blocking; async 에선 spawn_blocking 으로).
/// `stale` = 방금 401 받은 토큰 (있으면 그건 재사용하지 않음).
pub(crate) fn access_token_blocking(stale: Option<&str>) -> Result<String, String> {
    let config = stored_config().map_err(|e| e.to_string())?;
    get_or_refresh(&SESSION, stale, |rt| refresh_grant(&config, rt))
        .map(|s| s.access_token)
        .map_err(|e| e.to_string())
}

pub(crate) fn is_auth_expired(err: &str) -> bool {
    err.starts_with(AUTH_EXPIRED)
}

// ---------------------------------------------------------------------------
// 로그인
// ---------------------------------------------------------------------------

fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) -> Result<()> {
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Ashfield Sync</title>\
         <style>body{{font-family:system-ui;padding:48px;text-align:center}}</style></head>\
         <body>{}</body></html>",
        body
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// loopback 에서 `/oauth/callback` 요청을 기다려 code 를 돌려준다 (state, iss 확인).
fn wait_for_callback(listener: TcpListener, state: &str, issuer: &str) -> Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(anyhow!("로그인 시간 초과 (5분): 다시 시도하세요"));
                }
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        let target = request_line.split_whitespace().nth(1).unwrap_or("");
        let parsed = match url::Url::parse(&format!("http://127.0.0.1{target}")) {
            Ok(u) => u,
            Err(_) => continue,
        };
        if parsed.path() != "/oauth/callback" {
            // favicon 등: 무시하고 계속 기다림
            let _ = respond(&mut stream, "404 Not Found", "");
            continue;
        }
        let query: HashMap<_, _> = parsed.query_pairs().collect();
        if query.get("state").map(|s| s.as_ref()) != Some(state) {
            let _ = respond(&mut stream, "400 Bad Request", "<h2>state 불일치</h2>");
            return Err(anyhow!("state mismatch"));
        }
        if let Some(err) = query.get("error") {
            let desc = query.get("error_description").map(|c| c.as_ref()).unwrap_or("");
            let _ = respond(
                &mut stream,
                "200 OK",
                &format!(
                    "<h2>인증 실패</h2><p>{}: {}</p>",
                    html_escape(err),
                    html_escape(desc)
                ),
            );
            return Err(anyhow!("authorize error: {} {}", err, desc));
        }
        // RFC 9207: 다른 IdP 가 보낸 응답 섞임(mix-up) 방지
        if let Some(iss) = query.get("iss") {
            if iss.trim_end_matches('/') != issuer {
                let _ = respond(&mut stream, "400 Bad Request", "<h2>issuer 불일치</h2>");
                return Err(anyhow!("iss mismatch: {iss} != {issuer}"));
            }
        }
        let code = query
            .get("code")
            .ok_or_else(|| anyhow!("code missing"))?
            .to_string();
        respond(
            &mut stream,
            "200 OK",
            "<h2>로그인 완료</h2><p>이 창을 닫고 Ashfield Sync 로 돌아가세요.</p>",
        )?;
        return Ok(code);
    }
}

fn login_blocking(config: OAuthConfig) -> Result<TokenSet> {
    remember_config(&config);
    let ep = endpoints(&config);
    let (verifier, challenge) = pkce_pair();
    let state = random_url_safe(16);
    let nonce = random_url_safe(16);
    let redirect_uri = redirect_uri(config.redirect_port);

    // 1. loopback 먼저 listen: 브라우저가 callback 보내기 전에
    let listener = TcpListener::bind(("127.0.0.1", config.redirect_port)).context(format!(
        "포트 {} bind 실패: 다른 앱(또는 진행 중인 로그인)이 사용 중일 수 있음",
        config.redirect_port
    ))?;

    // 2. 브라우저 열기
    let authorize_url = build_authorize_url(
        &ep.authorization,
        &AuthorizeParams {
            client_id: &config.client_id,
            redirect_uri: &redirect_uri,
            state: &state,
            nonce: &nonce,
            code_challenge: &challenge,
            resource: &config.resource,
        },
    )?;
    webbrowser::open(&authorize_url).context("시스템 브라우저 열기 실패")?;

    // 3. callback
    let code = wait_for_callback(listener, &state, &ep.issuer)?;

    // 4. code 교환 (public client: body 에 client_id, secret 없음)
    let res = http()
        .post(&ep.token)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", config.client_id.as_str()),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("resource", config.resource.as_str()),
        ])
        .send()
        .context("POST token endpoint")?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().unwrap_or_default();
        return Err(anyhow!("token exchange {}: {}", status, body));
    }
    let token: TokenResponse = res.json().context("parse token response")?;
    if token.refresh_token.is_none() {
        eprintln!("[oauth] refresh_token 없음: offline_access scope 가 허용됐는지 확인");
    }
    if let Some(idt) = token.id_token.as_deref() {
        if id_token_nonce(idt).as_deref() != Some(nonce.as_str()) {
            return Err(anyhow!("id_token nonce 불일치"));
        }
    }
    let id_token = token.id_token.clone();

    // 5. 세션과 keychain 교체: refresh 락 안에서 (진행 중 refresh 가 옛 값으로 덮지 않게)
    let mut guard = SESSION.lock().unwrap_or_else(|p| p.into_inner());
    let session = session_from(token, None);
    let out = TokenSet {
        access_token: session.access_token.clone(),
        expires_in: session.expires_at.saturating_duration_since(Instant::now()).as_secs(),
        id_token,
    };
    *guard = Some(session);
    Ok(out)
}

fn refresh_blocking(config: OAuthConfig, stale: Option<String>) -> Result<TokenSet, String> {
    remember_config(&config);
    let s = get_or_refresh(&SESSION, stale.as_deref(), |rt| refresh_grant(&config, rt))
        .map_err(|e| e.to_string())?;
    Ok(TokenSet {
        access_token: s.access_token,
        expires_in: s.expires_at.saturating_duration_since(Instant::now()).as_secs(),
        id_token: None,
    })
}

fn logout_blocking(config: OAuthConfig) -> Result<()> {
    let ep = endpoints(&config);
    // 락을 쥐고: 진행 중 refresh 가 끝난 뒤의 최신 refresh_token 을 폐기한다.
    let mut guard = SESSION.lock().unwrap_or_else(|p| p.into_inner());
    let entry = keyring_entry()?;
    let refresh = guard
        .as_ref()
        .and_then(|s| s.refresh_token.clone())
        .or_else(|| entry.get_password().ok());
    if let Some(rt) = refresh {
        // RFC 7009: 실패해도 로컬 정리는 진행 (계정 홈 '연결된 앱'에서도 해제 가능)
        let res = http()
            .post(&ep.revocation)
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("token", rt.as_str()),
                ("token_type_hint", "refresh_token"),
            ])
            .send();
        match res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => eprintln!("[oauth] revoke {}", r.status()),
            Err(e) => eprintln!("[oauth] revoke 실패: {e}"),
        }
    }
    *guard = None;
    let _ = entry.delete_credential();
    Ok(())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("oauth task join: {e}"))?
}

#[tauri::command]
pub async fn oauth_login(config: OAuthConfig) -> Result<TokenSet, String> {
    blocking(move || login_blocking(config).map_err(|e| e.to_string())).await
}

/// `stale` = 방금 401 받은 access token (JS 가 넘김). 그 사이 누가 이미 갱신했으면
/// refresh 없이 캐시된 새 토큰을 준다. 실패 메시지가 `auth_expired:` 로 시작하면 재로그인.
#[tauri::command]
pub async fn oauth_refresh(
    config: OAuthConfig,
    stale: Option<String>,
) -> Result<TokenSet, String> {
    blocking(move || refresh_blocking(config, stale)).await
}

#[tauri::command]
pub async fn oauth_logout(config: OAuthConfig) -> Result<(), String> {
    blocking(move || logout_blocking(config).map_err(|e| e.to_string())).await
}

#[tauri::command]
pub fn oauth_has_stored_refresh() -> bool {
    keyring_entry()
        .and_then(|e| e.get_password().map_err(Into::into))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn pkce_s256_challenge() {
        // 기대값은 독립 계산: base64url(sha256(verifier)) without padding (python hashlib)
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r7wW1gFWFOEjXk"),
            "bwWFMyPfdG9qreDhH2lmftFx_dFeLDalzcT1gb_j68g"
        );
        let (v, c) = pkce_pair();
        assert!((43..=128).contains(&v.len()));
        assert_eq!(pkce_challenge(&v), c);
    }

    #[test]
    fn authorize_url_matches_contract() {
        let ep = Endpoints::fallback("http://localhost:3300/");
        assert_eq!(ep.authorization, "http://localhost:3300/api/auth/oauth2/authorize");
        assert_eq!(ep.token, "http://localhost:3300/api/auth/oauth2/token");
        assert_eq!(ep.revocation, "http://localhost:3300/api/auth/oauth2/revoke");
        let redirect = redirect_uri(1421);
        assert_eq!(redirect, "http://127.0.0.1:1421/oauth/callback");
        let s = build_authorize_url(
            &ep.authorization,
            &AuthorizeParams {
                client_id: "ashfield-sync",
                redirect_uri: &redirect,
                state: "st",
                nonce: "no",
                code_challenge: "ch",
                resource: "http://localhost:3200",
            },
        )
        .unwrap();
        let u = url::Url::parse(&s).unwrap();
        assert_eq!(u.path(), "/api/auth/oauth2/authorize");
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "ashfield-sync");
        assert_eq!(q["redirect_uri"], "http://127.0.0.1:1421/oauth/callback");
        assert_eq!(q["scope"], "openid profile email offline_access");
        assert_eq!(q["state"], "st");
        assert_eq!(q["nonce"], "no");
        assert_eq!(q["code_challenge"], "ch");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["resource"], "http://localhost:3200");
    }

    #[test]
    fn id_token_nonce_is_read() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"nonce":"abc","sub":"x"}"#);
        assert_eq!(id_token_nonce(&format!("h.{payload}.s")).as_deref(), Some("abc"));
        assert_eq!(id_token_nonce("garbage"), None);
    }

    fn session(tok: &str, rt: &str, ttl: u64) -> Session {
        Session {
            access_token: tok.into(),
            expires_at: Instant::now() + Duration::from_secs(ttl),
            refresh_token: Some(rt.into()),
        }
    }

    #[test]
    fn reuse_rules() {
        let now = Instant::now();
        let s = session("a1", "r1", 900);
        assert!(can_reuse(&s, None, now));
        assert!(can_reuse(&s, Some("old"), now)); // 이미 누가 갱신함
        assert!(!can_reuse(&s, Some("a1"), now)); // 바로 이 토큰이 거부됨
        assert!(!can_reuse(&session("a1", "r1", 30), None, now)); // 곧 만료
    }

    /// SSE 재연결, polling, UI, VFS 가 동시에 401 → refresh 는 딱 한 번, 모두 같은 새 토큰.
    #[test]
    fn concurrent_refresh_is_single_flight_and_rotates() {
        let slot = Arc::new(Mutex::new(Some(session("a0", "r0", 900))));
        let calls = Arc::new(AtomicUsize::new(0));
        let used_refresh = Arc::new(Mutex::new(Vec::<String>::new()));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (slot, calls, used) = (slot.clone(), calls.clone(), used_refresh.clone());
                std::thread::spawn(move || {
                    get_or_refresh(&slot, Some("a0"), |rt| {
                        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                        used.lock().unwrap().push(rt.clone().unwrap());
                        std::thread::sleep(Duration::from_millis(50));
                        Ok(session(&format!("a{n}"), &format!("r{n}"), 900))
                    })
                    .ok()
                    .map(|s| s.access_token)
                })
            })
            .collect();
        let tokens: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(tokens.iter().all(|t| t.as_deref() == Some("a1")));
        assert_eq!(*used_refresh.lock().unwrap(), vec!["r0".to_string()]);
        // 다음 refresh 는 회전된 새 refresh_token 을 써야 한다
        let s = get_or_refresh(&slot, Some("a1"), |rt| {
            assert_eq!(rt.as_deref(), Some("r1"));
            Ok(session("a2", "r2", 900))
        })
        .ok()
        .unwrap();
        assert_eq!(s.access_token, "a2");
    }

    #[test]
    fn expired_refresh_clears_session_transient_keeps_it() {
        let slot = Mutex::new(Some(session("a0", "r0", 900)));
        let r = get_or_refresh(&slot, Some("a0"), |_| Err(RefreshError::Transient("net".into())));
        assert!(r.is_err());
        assert!(slot.lock().unwrap().is_some());
        let r = get_or_refresh(&slot, Some("a0"), |_| Err(RefreshError::Expired("bad".into())));
        assert!(is_auth_expired(&r.err().unwrap().to_string()));
        assert!(slot.lock().unwrap().is_none());
    }
}
