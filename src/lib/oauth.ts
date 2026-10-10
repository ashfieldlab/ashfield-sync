/**
 * OAuth 2.1 (PKCE): Ashfield 계정 서버. Tauri Rust 측의 oauth.rs 와 1:1 짝.
 *
 * - 첫 로그인: invoke('oauth_login') → 시스템 브라우저 → 계정 서버 → loopback callback → tokens
 * - 자동 재로그인/갱신: invoke('oauth_has_stored_refresh') + invoke('oauth_refresh')
 * - 로그아웃: invoke('oauth_logout'): refresh_token 을 revocation_endpoint 로 폐기 + keychain 삭제
 *
 * refresh_token 은 Rust 측이 OS keychain 에 보관하고 JS 로는 넘기지 않는다.
 * refresh_token 은 회전(rotation)하므로 갱신은 Rust 한 곳에서 직렬화된다.
 * JS, SSE, VFS 가 동시에 갱신을 요청해도 실제 refresh 요청은 한 번.
 */

import { invoke } from "@tauri-apps/api/core"

import { env } from "./config"

export interface TokenSet {
  access_token: string
  expires_in: number
  id_token?: string | null
}

/** Rust 가 재로그인이 필요할 때(invalid_grant, 저장된 토큰 없음) 붙이는 에러 접두어 */
export const AUTH_EXPIRED = "auth_expired"

export function isAuthExpired(err: unknown): boolean {
  return String(err).startsWith(AUTH_EXPIRED)
}

function oauthConfig() {
  return {
    issuer: env.oauth.issuer,
    client_id: env.oauth.clientId,
    redirect_port: env.oauth.redirectPort,
    resource: env.oauth.resource,
  }
}

export async function oauthLogin(): Promise<TokenSet> {
  return invoke<TokenSet>("oauth_login", { config: oauthConfig() })
}

/**
 * 유효한 access token. `stale` = 방금 401 을 받은 토큰: 그 사이 다른 쪽(SSE, VFS)이
 * 이미 갱신했으면 refresh 없이 새 토큰을 돌려받는다.
 */
export async function oauthRefresh(stale: string | null = null): Promise<TokenSet> {
  return invoke<TokenSet>("oauth_refresh", { config: oauthConfig(), stale })
}

export async function oauthLogout(): Promise<void> {
  await invoke("oauth_logout", { config: oauthConfig() })
}

export async function oauthHasStoredRefresh(): Promise<boolean> {
  return invoke<boolean>("oauth_has_stored_refresh")
}
