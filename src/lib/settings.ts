/**
 * 앱 설정: tauri-plugin-store 기반 (settings.json).
 *
 * 실제 파일: 앱별 설정 표준 위치의 settings.json (Windows %APPDATA%\<bundle-id>,
 * Linux ~/.config/<bundle-id>). 비밀 아님 (refresh_token 은 Rust keychain 별도).
 *
 * 키:
 *   server             접속 서버 {driveUrl, accountUrl} (로그인 화면에서 입력, config.ts)
 *   syncRoot           sync 폴더 위치 (default ~/Ashfield)
 *   excludedWorkspaces  opt-out 워크스페이스 목록 (default 빈 배열 = 전체 sync)
 *   lastSyncByWorkspace  워크스페이스별 delta polling 의 since 기준 (ISO): 워크스페이스마다
 *                      변경 스트림이 독립이라 단일 시각으로는 안 됨
 */

import { homeDir, join } from "@tauri-apps/api/path"
import { load, type Store } from "@tauri-apps/plugin-store"

import type { Server } from "./config"

export interface Settings {
  syncRoot: string
  excludedWorkspaces: string[]
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
    excludedWorkspaces: (await s.get<string[]>("excludedWorkspaces")) ?? [],
  }
}

// 전체 초기화: 모든 설정 키 삭제 (폴더/제외/온보딩/lastSync). 다음 로그인이
// 첫 실행처럼 동작. refresh_token(keychain) 은 별개: 로그아웃이 처리.
export async function resetSettings(): Promise<void> {
  const s = await store()
  await s.clear()
  await s.save()
}

export async function getSavedServer(): Promise<Server | null> {
  const s = await store()
  return (await s.get<Server>("server")) ?? null
}

export async function saveServer(server: Server): Promise<void> {
  const s = await store()
  await s.set("server", server)
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

export async function setExcludedWorkspaces(workspaces: string[]): Promise<void> {
  const s = await store()
  await s.set("excludedWorkspaces", workspaces)
}

export async function getLastSync(workspaceId: string): Promise<string | null> {
  const s = await store()
  const map = (await s.get<Record<string, string>>("lastSyncByWorkspace")) ?? {}
  return map[workspaceId] ?? null
}

export async function setLastSync(workspaceId: string, iso: string): Promise<void> {
  const s = await store()
  const map = (await s.get<Record<string, string>>("lastSyncByWorkspace")) ?? {}
  map[workspaceId] = iso
  await s.set("lastSyncByWorkspace", map)
}
