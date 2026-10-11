/**
 * 접속 설정 단일 source.
 *
 * 서버 주소는 실행 중에 정한다: 사용자가 로그인 화면에서 Drive 주소를 입력하면
 * `${drive}/api/client-config` 에서 계정 서버 주소를 받아 settings 에 저장한다.
 *
 * - driveUrl   Drive 공개 주소. API base(`/api/v1/*`, BFF 가 Bearer 통과)이자 OAuth `resource`
 *              (= access token 의 `aud`, Drive 백엔드 AUTH_AUDIENCE).
 * - accountUrl Ashfield 계정 서버 = OIDC issuer. 엔드포인트는 디스커버리에서 읽음.
 *
 * 빌드 시점 값(`import.meta.env`)은 여기서만 읽는다: 로그인 화면 기본값과 OAuth 클라이언트 정보.
 */

import { fetch } from "@tauri-apps/plugin-http"

function optional(key: string): string | undefined {
  const v = import.meta.env[key] as string | undefined
  return v && v.trim() ? v.trim() : undefined
}

const strip = (u: string) => u.replace(/\/+$/, "")

export interface Server {
  driveUrl: string
  accountUrl: string
}

/** 로그인 화면의 Drive 주소 기본값 (로컬 dev: .env 의 http://localhost:3200) */
export const defaultDriveUrl = optional("VITE_DRIVE_URL") ?? ""

export const oauthClient = {
  clientId: optional("VITE_OAUTH_CLIENT_ID") ?? "ashfield-sync",
  // 계정 서버에 등록된 redirect_uri = http://127.0.0.1:<port>/oauth/callback (정확히 일치)
  redirectPort: Number(optional("VITE_OAUTH_REDIRECT_PORT") ?? 1421),
} as const

let current: Server | null = null

export function setServer(s: Server | null): void {
  current = s
}

export function server(): Server {
  if (!current) throw new Error("서버 주소가 설정되지 않았습니다")
  return current
}

/** 사용자 입력 → Drive origin. 스킴이 없으면 https, localhost 는 http. */
export function normalizeDriveUrl(input: string): string {
  const raw = input.trim()
  if (!raw) throw new Error("Drive 주소를 입력하세요")
  const withScheme = /^https?:\/\//i.test(raw)
    ? raw
    : `${/^(localhost|127\.0\.0\.1)(:|$)/.test(raw) ? "http" : "https"}://${raw}`
  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    throw new Error("올바른 주소가 아닙니다")
  }
  return strip(url.origin)
}

/** Drive 주소로 접속 정보 조회. drive_url 은 서버가 아는 공개 주소(resource 와 일치해야 함)를 따른다. */
export async function discoverServer(driveInput: string): Promise<Server> {
  const base = normalizeDriveUrl(driveInput)
  let res: Response
  try {
    res = await fetch(`${base}/api/client-config`, { method: "GET" })
  } catch (err) {
    throw new Error(`서버에 연결할 수 없습니다: ${base} (${String(err)})`)
  }
  if (!res.ok) throw new Error(`Ashfield Drive 서버가 아닙니다: ${base} (HTTP ${res.status})`)
  const body = (await res.json()) as { account_url?: string; drive_url?: string }
  if (!body.account_url || !body.drive_url) throw new Error(`Ashfield Drive 서버가 아닙니다: ${base}`)
  return { driveUrl: strip(body.drive_url), accountUrl: strip(body.account_url) }
}
