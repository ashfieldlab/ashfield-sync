//! OAuth + PKCE flow for Keycloak SSO.
//!
//! - 로그인: 시스템 브라우저 → Keycloak → loopback callback → token exchange
//! - refresh_token 은 OS keychain (Windows Credential Manager) 에 보관
//! - access_token 만료 시 background refresh
//!
//! ADR-0015 참조.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const KEYRING_SERVICE: &str = "ashfield-sync";
pub(crate) const KEYRING_USERNAME: &str = "refresh_token";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    id_token: Option<String>,
}

fn random_url_safe(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

fn pkce_pair() -> (String, String) {
    let verifier = random_url_safe(64);
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn keyring_entry() -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, KEYRING_USERNAME).context("keyring entry")
}

async fn exchange_code(
    config: &OAuthConfig,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse> {
    let token_url = format!("{}/protocol/openid-connect/token", config.issuer);
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", config.client_id.as_str()),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
    ];
    let res = reqwest::Client::new()
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .context("POST token endpoint")?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(anyhow!("token exchange {}: {}", status, body));
    }
    res.json::<TokenResponse>()
        .await
        .context("parse token response")
}

fn respond(stream: &mut std::net::TcpStream, body: &str) -> Result<()> {
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Ashfield Sync</title>\
         <style>body{{font-family:system-ui;padding:48px;text-align:center}}</style></head>\
         <body>{}</body></html>",
        body
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

async fn login_inner(config: OAuthConfig) -> Result<TokenSet> {
    let (verifier, challenge) = pkce_pair();
    let state = random_url_safe(16);
    let redirect_uri = format!("http://localhost:{}/oauth/callback", config.redirect_port);

    // 1. loopback server 먼저 띄움 — 브라우저가 callback 보내기 전에 listen 상태
    let listener = TcpListener::bind(("127.0.0.1", config.redirect_port)).context(format!(
        "포트 {} bind 실패 — 다른 앱이 사용 중일 수 있음",
        config.redirect_port
    ))?;

    // 2. authorize URL 만들고 브라우저 열기
    let authorize_url = format!(
        "{}/protocol/openid-connect/auth?response_type=code&client_id={}&redirect_uri={}\
         &scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        config.issuer,
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode("openid profile email"),
        state,
        challenge,
    );
    webbrowser::open(&authorize_url).context("시스템 브라우저 열기 실패")?;

    // 3. callback 기다림 (blocking accept — tokio task 안)
    let state_for_cb = state.clone();
    let code = tokio::task::spawn_blocking(move || {
        // wait_for_callback 은 async 이지만 std TcpListener 사용 — sync 부분만 추출
        let (mut stream, _) = listener.accept()?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(300)))
            .ok();
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(anyhow!("invalid callback request line"));
        }
        let parsed = url::Url::parse(&format!("http://localhost{}", parts[1]))?;
        let query: HashMap<_, _> = parsed.query_pairs().collect();
        if let Some(err) = query.get("error") {
            let desc = query
                .get("error_description")
                .map(|c| c.as_ref())
                .unwrap_or("");
            let _ = respond(
                &mut stream,
                &format!("<h2>인증 실패</h2><p>{}: {}</p>", err, desc),
            );
            return Err(anyhow!("authorize error: {} {}", err, desc));
        }
        let code = query
            .get("code")
            .ok_or_else(|| anyhow!("code missing"))?
            .to_string();
        let returned_state = query
            .get("state")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if returned_state != state_for_cb {
            let _ = respond(&mut stream, "<h2>state mismatch</h2>");
            return Err(anyhow!("state mismatch"));
        }
        respond(
            &mut stream,
            "<h2>로그인 완료</h2><p>이 창을 닫고 데스크톱 앱으로 돌아가세요.</p>",
        )?;
        Ok::<String, anyhow::Error>(code)
    })
    .await
    .context("callback task join")??;

    // 4. token 교환
    let token = exchange_code(&config, &code, &verifier, &redirect_uri).await?;

    // 5. refresh_token 을 OS keychain 에 보관
    let entry = keyring_entry()?;
    entry
        .set_password(&token.refresh_token)
        .context("keyring set")?;

    Ok(TokenSet {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        id_token: token.id_token,
    })
}

async fn refresh_inner(config: OAuthConfig) -> Result<TokenSet> {
    let entry = keyring_entry()?;
    let refresh = entry.get_password().context("저장된 refresh_token 없음")?;

    let token_url = format!("{}/protocol/openid-connect/token", config.issuer);
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", config.client_id.as_str()),
        ("refresh_token", refresh.as_str()),
    ];
    let res = reqwest::Client::new()
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .context("refresh POST")?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        // refresh 거부 — 저장된 token 폐기
        let _ = entry.delete_credential();
        return Err(anyhow!("refresh failed {}: {}", status, body));
    }
    let token: TokenResponse = res.json().await.context("parse refresh response")?;
    // Keycloak 의 refresh token rotation — 새 refresh 가 와도, 안 와도 안전하게 갱신
    entry
        .set_password(&token.refresh_token)
        .context("keyring update")?;
    Ok(TokenSet {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_in: token.expires_in,
        id_token: token.id_token,
    })
}

async fn logout_inner(config: OAuthConfig) -> Result<()> {
    let entry = keyring_entry()?;
    if let Ok(refresh) = entry.get_password() {
        // Keycloak end-session — refresh_token 즉시 폐기
        let logout_url = format!("{}/protocol/openid-connect/logout", config.issuer);
        let params = [
            ("client_id", config.client_id.as_str()),
            ("refresh_token", refresh.as_str()),
        ];
        let _ = reqwest::Client::new()
            .post(&logout_url)
            .form(&params)
            .send()
            .await;
    }
    let _ = entry.delete_credential();
    Ok(())
}

#[tauri::command]
pub async fn oauth_login(config: OAuthConfig) -> Result<TokenSet, String> {
    login_inner(config).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn oauth_refresh(config: OAuthConfig) -> Result<TokenSet, String> {
    refresh_inner(config).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn oauth_logout(config: OAuthConfig) -> Result<(), String> {
    logout_inner(config).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn oauth_has_stored_refresh() -> bool {
    keyring_entry()
        .and_then(|e| e.get_password().map_err(Into::into))
        .is_ok()
}
