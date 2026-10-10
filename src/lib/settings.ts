/**
 * 앱 설정: tauri-plugin-store 기반 (settings.json).
 *
 * 실제 파일: %APPDATA%\<bundle-id>\settings.json: Windows 의 앱별 설정
 * 표준 위치. 비밀 아님 (refresh_token 은 Rust keychain 별도).
 *
 * 키:
 *   syncRoot           sync 폴더 위치 (default ~\Ashfield)
 *   excludedCompanies  opt-out 회사 목록 (default 빈 배열 = 전체 sync)
 *   lastSyncByCompany  회사별 delta polling 의 since 기준 (ISO): 회사마다
 *                      변경 스트림이 독립이라 단일 시각으로는 안 됨
 */

import { homeDir, join } from "@tauri-apps/api/path"
import { load, type Store } from "@tauri-apps/plugin-store"

export interface Settings {
  syncRoot: string
  excludedCompanies: string[]
}

let _store: Store | null = null

async function store(): Promise<Store> {
  if (!_store) {
    _store = await load("settings.json", { autoSave: true, defaults: {} })
  }
  return _store
}

export async function defaultSyncRoot(): Promise<string> {
  return join(await homeDir(), "Ashfield")
}

export async function getSettings(): Promise<Settings> {
  const s = await store()
  return {
    syncRoot: (await s.get<string>("syncRoot")) ?? (await defaultSyncRoot()),
    excludedCompanies: (await s.get<string[]>("excludedCompanies")) ?? [],
  }
}

// 전체 초기화: 모든 설정 키 삭제 (폴더/제외/온보딩/lastSync). 다음 로그인이
// 첫 실행처럼 동작. refresh_token(keychain) 은 별개: 로그아웃이 처리.
export async function resetSettings(): Promise<void> {
  const s = await store()
  await s.clear()
  await s.save()
}

export async function setSyncRoot(path: string): Promise<void> {
  const s = await store()
  await s.set("syncRoot", path)
}

export async function getOnboarded(): Promise<boolean> {
  const s = await store()
  return (await s.get<boolean>("onboarded")) ?? false
}

export async function setOnboarded(v: boolean): Promise<void> {
  const s = await store()
  await s.set("onboarded", v)
}

export async function setExcludedCompanies(companies: string[]): Promise<void> {
  const s = await store()
  await s.set("excludedCompanies", companies)
}

export async function getLastSync(companyId: string): Promise<string | null> {
  const s = await store()
  const map = (await s.get<Record<string, string>>("lastSyncByCompany")) ?? {}
  return map[companyId] ?? null
}

export async function setLastSync(companyId: string, iso: string): Promise<void> {
  const s = await store()
  const map = (await s.get<Record<string, string>>("lastSyncByCompany")) ?? {}
  map[companyId] = iso
  await s.set("lastSyncByCompany", map)
}
