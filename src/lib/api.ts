/**
 * Ashfield Drive backend API client.
 *
 * OAuth (PKCE) 인증: access_token 은 메모리에만, refresh 는 Rust keychain.
 * X-Active-Company-Id 헤더 자동 첨부: 한글 회사 ID 면 percent-encode.
 *
 * 401 처리: 등록된 refresh handler 를 single-flight 로 한 번 호출 후 재시도.
 * (계정 서버 access_token TTL 15분: 만료가 일상이라 자동 갱신 필수.
 *  refresh_token 회전 때문에 실제 refresh 는 Rust oauth.rs 가 프로세스 전체에서 직렬화.)
 *
 * Tauri 의 native fetch (Rust reqwest) 사용: WebView 의 브라우저 fetch 가
 * 아니라 OS 레벨 HTTP. CORS 가 적용되지 않아 dev (localhost:1420) 에서도
 * 운영 서버(VITE_API_URL)로 직접 호출 가능. 운영 빌드에서도 동일하게 동작.
 */

import { fetch } from "@tauri-apps/plugin-http"

import { env } from "./config"

let _token: string | null = null
let _activeCompanyId: string | null = null

// 401 시 호출할 갱신 함수: oauth 모듈이 부팅 때 주입 (순환 import 회피).
// 인자 = 401 을 받은 토큰(stale). 성공 시 내부에서 setToken 까지 끝내야 함.
let _refreshHandler: ((stale: string | null) => Promise<void>) | null = null
// single-flight: 동시 401 여러 개가 떠도 refresh 는 한 번만.
let _refreshInFlight: Promise<void> | null = null

export function setToken(token: string | null): void {
  _token = token
}

export function setActiveCompany(companyId: string | null): void {
  _activeCompanyId = companyId
}

export function hasToken(): boolean {
  return _token !== null && _token.length > 0
}

export function getToken(): string | null {
  return _token
}

export function setRefreshHandler(handler: ((stale: string | null) => Promise<void>) | null): void {
  _refreshHandler = handler
}

async function runRefreshOnce(stale: string | null): Promise<void> {
  if (!_refreshHandler) throw new Error("no refresh handler")
  if (!_refreshInFlight) {
    _refreshInFlight = _refreshHandler(stale).finally(() => {
      _refreshInFlight = null
    })
  }
  return _refreshInFlight
}

export class ApiError extends Error {
  status: number
  body: unknown

  constructor(status: number, body: unknown, message: string) {
    super(message)
    this.status = status
    this.body = body
  }
}

interface ApiOptions extends Omit<RequestInit, "body"> {
  body?: unknown
  /** If-Match 헤더: sync 의 optimistic locking */
  ifMatch?: string
  /** 이 호출만 다른 회사로: 전 회사 순회 (bootstrap/polling) 용 */
  companyId?: string
}

async function doFetch(path: string, options: ApiOptions): Promise<Response> {
  const { body, ifMatch, companyId, headers: initHeaders, ...rest } = options
  const url = path.startsWith("http") ? path : `${env.apiUrl}${path}`

  const headers = new Headers(initHeaders)
  if (!headers.has("Content-Type") && body !== undefined) {
    headers.set("Content-Type", "application/json")
  }
  if (_token) {
    headers.set("Authorization", `Bearer ${_token}`)
  }
  const effectiveCompany = companyId ?? _activeCompanyId
  if (effectiveCompany) {
    // backend 가 percent-encoded 한글 회사 ID 도 unquote 처리 (CalDAV 패턴 동일).
    headers.set("X-Active-Company-Id", encodeURIComponent(effectiveCompany))
  }
  if (ifMatch) {
    headers.set("If-Match", ifMatch)
  }

  return fetch(url, {
    ...rest,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export async function api<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const sentWith = _token
  let res = await doFetch(path, options)

  // access_token 만료: refresh 한 번 후 재시도. refresh 자체가 실패하면
  // (revoked / 만료) 원래 401 을 그대로 던져 호출측이 로그인 화면으로 보냄.
  if (res.status === 401 && _refreshHandler) {
    try {
      // 요청 뒤에 이미 다른 호출이 토큰을 바꿨으면 refresh 없이 새 토큰으로 재시도만.
      if (_token === sentWith) await runRefreshOnce(sentWith)
      res = await doFetch(path, options)
    } catch {
      // refresh 실패: 아래에서 원래 401 throw
    }
  }

  if (!res.ok) {
    let errBody: unknown = null
    try {
      errBody = await res.json()
    } catch {
      errBody = await res.text()
    }
    throw new ApiError(res.status, errBody, `HTTP ${res.status} ${res.statusText}`)
  }
  if (res.status === 204) return null as T
  return (await res.json()) as T
}
