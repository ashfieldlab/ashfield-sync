/**
 * 환경변수 단일 source.
 *
 * `import.meta.env` 직접 접근 금지 — 여기 거쳐서 가져오기.
 */

function required(key: string): string {
  const v = import.meta.env[key]
  if (!v) throw new Error(`Missing env var: ${key}`)
  return v as string
}

export const env = {
  apiUrl: required("VITE_API_URL").replace(/\/$/, ""),
  oauth: {
    issuer: required("VITE_OAUTH_ISSUER").replace(/\/$/, ""),
    clientId: required("VITE_OAUTH_CLIENT_ID"),
    redirectPort: Number(import.meta.env.VITE_OAUTH_REDIRECT_PORT ?? 1421),
  },
} as const
