/**
 * OAuth (PKCE) flow — Tauri Rust 측의 oauth.rs 와 1:1 짝.
 *
 * - 첫 로그인: invoke('oauth_login') → 시스템 브라우저 → loopback callback → tokens
 * - 자동 재로그인: invoke('oauth_has_stored_refresh') + invoke('oauth_refresh')
 * - 로그아웃: invoke('oauth_logout') — keychain + Keycloak end-session
 *
 * refresh_token 은 Rust 측이 OS keychain 에 보관 — JS 메모리/디스크에 노출 X.
 */

import { invoke } from "@tauri-apps/api/core"

import { env } from "./config"

export interface TokenSet {
  access_token: string
  refresh_token: string
  expires_in: number
  id_token?: string | null
}

function oauthConfig() {
  return {
    issuer: env.oauth.issuer,
    client_id: env.oauth.clientId,
    redirect_port: env.oauth.redirectPort,
  }
}

export async function oauthLogin(): Promise<TokenSet> {
  return invoke<TokenSet>("oauth_login", { config: oauthConfig() })
}

export async function oauthRefresh(): Promise<TokenSet> {
  return invoke<TokenSet>("oauth_refresh", { config: oauthConfig() })
}

export async function oauthLogout(): Promise<void> {
  await invoke("oauth_logout", { config: oauthConfig() })
}

export async function oauthHasStoredRefresh(): Promise<boolean> {
  return invoke<boolean>("oauth_has_stored_refresh")
}
