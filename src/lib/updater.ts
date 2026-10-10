/**
 * 자동 업데이트 — Tauri updater (minisign 서명 검증, Authenticode 무관).
 *
 * tauri.conf.json 의 plugins.updater.endpoints 에서 latest.json 을 받아
 * 현재 버전보다 높으면 다운로드 → 서명 검증 → 설치 → 재시작.
 *
 * endpoint 가 아직 없으면(404 등) check() 가 조용히 null/throw — 호출측이 무시.
 */

import { check } from "@tauri-apps/plugin-updater"
import { relaunch } from "@tauri-apps/plugin-process"

export interface UpdateInfo {
  version: string
  notes?: string
}

/** 업데이트 있으면 정보 반환, 없으면 null. 네트워크/endpoint 오류는 throw. */
export async function checkForUpdate(): Promise<{ info: UpdateInfo; apply: () => Promise<void> } | null> {
  const update = await check()
  if (!update) return null
  return {
    info: { version: update.version, notes: update.body ?? undefined },
    apply: async () => {
      await update.downloadAndInstall()
      await relaunch()
    },
  }
}
