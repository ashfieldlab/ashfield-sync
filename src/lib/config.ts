/**
 * 환경변수 단일 source. (Vite: 빌드 시점에 박힘)
 *
 * `import.meta.env` 직접 접근 금지: 여기 거쳐서 가져오기.
 *
 * - ACCOUNT_URL    Ashfield 계정 서버 = OIDC issuer. 엔드포인트는 디스커버리에서 읽음.
 * - DRIVE_URL      Drive **API base** (백엔드). 로컬 dev 8200.
 * - DRIVE_RESOURCE OAuth `resource` = access token 의 `aud`. 계정 서버에 ashfield-sync 의
 *                  resource 로 등록된 Drive **public URL**(계정 서버 쪽 DRIVE_URL, 로컬 3200)과
 *                  정확히 같아야 하고, Drive 백엔드의 AUTH_AUDIENCE 도 이 값이다.
 *                  API base 와 다를 수 있어 별도 설정.
 */

function optional(key: string): string | undefined {
  const v = import.meta.env[key] as string | undefined
  return v && v.trim() ? v.trim() : undefined
}

const strip = (u: string) => u.replace(/\/+$/, "")

const accountUrl = strip(optional("VITE_ACCOUNT_URL") ?? "http://localhost:3300")
// VITE_API_URL: 옛 이름 (하위 호환)
const driveUrl = strip(optional("VITE_DRIVE_URL") ?? optional("VITE_API_URL") ?? "http://localhost:8200")
const driveResource = strip(optional("VITE_DRIVE_RESOURCE") ?? "http://localhost:3200")

export const env = {
  /** Drive API base: 모든 /api/v1 호출 */
  apiUrl: driveUrl,
  accountUrl,
  oauth: {
    issuer: accountUrl,
    clientId: optional("VITE_OAUTH_CLIENT_ID") ?? "ashfield-sync",
    // 계정 서버에 등록된 redirect_uri = http://127.0.0.1:<port>/oauth/callback (정확히 일치)
    redirectPort: Number(optional("VITE_OAUTH_REDIRECT_PORT") ?? 1421),
    resource: driveResource,
  },
} as const
