/**
 * Backend 응답 타입: OpenAPI 자동생성 스키마(api-schema.ts)에서 파생 (ADR-0015).
 *
 * 갱신: backend 의 스펙을 openapi.json 으로 떠 두고 `npm run gen:api` 재실행.
 * backend API 가 바뀌면 여기서 컴파일 에러로 잡힌다 (손으로 적던 drift 방지).
 *
 * MeResponse 만 예외: backend 의 /me 가 명시 스키마 없는 dict 반환이라 수기 유지.
 */

import type { components } from "./api-schema"

type Schemas = components["schemas"]

export type NodeKind = NodeResponse["kind"]
export type NodeScope = NodeResponse["scope"]
export type NodeStatus = NodeResponse["status"]

export type NodeResponse = Schemas["NodeResponse"]
export type TreeResponse = Schemas["TreeResponse"]
export type NodeChange = Schemas["NodeChange"]
export type ChangesResponse = Schemas["ChangesResponse"]
export type DownloadUrlResponse = Schemas["DownloadUrlResponse"]
export type UploadUrlResponse = Schemas["UploadUrlResponse"]

// /me 는 backend 가 dict 반환 → openapi 에 named schema 없음. 수기 유지.
export interface MeResponse {
  sub: string
  name: string | null
  email: string
  // backend 는 JWT 의 groups claim 을 그대로 회사 목록으로 반환: 필드명 'groups'.
  groups: string[]
  roles: string[]
  is_system_admin: boolean
  company_roles: Record<string, string>
}
