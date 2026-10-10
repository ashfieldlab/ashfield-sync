/**
 * 싱크용 E2E 세션 (ADR-0016, V5): 웹과 동일한 봉투 암호화로 vault 이름/내용 복호화.
 *
 * webview(React) 라 웹의 crypto.ts 를 그대로 재사용. 개인키 + vault_key 캐시는
 * 메모리에만 (새로고침/재시작 시 휘발 → 재잠금해제).
 *
 * V5a: 이름 복호화 (구조 유지). V5b: 파일 내용 복호화(hydrate)는 Rust 연동.
 */

import { api } from "../api"
import * as c from "./crypto"

interface KeyBundle {
  salt: string
  public_key: string
  enc_private_key: string
  enc_private_key_recovery: string
}

let _privateKey: CryptoKey | null = null
// (workspace|vaultNodeId) → vault_key
const _vaultKeys = new Map<string, CryptoKey>()

export function isUnlocked(): boolean {
  return _privateKey !== null
}

export function lock(): void {
  _privateKey = null
  _vaultKeys.clear()
}

async function getMyKeys(): Promise<KeyBundle | null> {
  try {
    return await api<KeyBundle>("/api/v1/e2e/keys/me")
  } catch {
    return null // 미설정
  }
}

/** 비밀번호(또는 복구코드)로 개인키 복원 → 메모리. */
export async function unlock(password: string, useRecovery = false): Promise<void> {
  const bundle = await getMyKeys()
  if (!bundle) throw new Error("E2E 키 미설정 (웹에서 보안 폴더 먼저 설정)")
  const kek = await c.deriveKek(password, c.fromB64(bundle.salt))
  const enc = useRecovery ? bundle.enc_private_key_recovery : bundle.enc_private_key
  try {
    _privateKey = await c.importPrivateKeyEncrypted(enc, kek)
  } catch {
    _privateKey = null
    throw new Error("비밀번호가 올바르지 않습니다")
  }
}

/** vault_key 확보: 워크스페이스별로 wrapped 받아 개인키로 unwrap 후 캐시. */
async function getVaultKey(workspace: string, vaultNodeId: string): Promise<CryptoKey | null> {
  const cacheKey = `${workspace}|${vaultNodeId}`
  const cached = _vaultKeys.get(cacheKey)
  if (cached) return cached
  if (!_privateKey) return null
  let wrapped: string
  try {
    const r = await api<{ node_id: string; wrapped_vault_key: string }>(
      `/api/v1/e2e/vaults/${vaultNodeId}/key`,
      { workspaceId: workspace },
    )
    wrapped = r.wrapped_vault_key
  } catch {
    return null // 비멤버 등
  }
  const vk = await c.unwrapKeyRsa(wrapped, _privateKey)
  _vaultKeys.set(cacheKey, vk)
  return vk
}

/**
 * vault 파일 DEK 를 풀어 raw(base64) 로 반환 (V5b). Rust hydrate 가 사전 적재해
 * 복호화에 씀. wrapped_dek 를 vault_key 로 unwrap → raw 32B → base64. 실패 시 null.
 */
export async function exportDek(
  workspace: string,
  vaultNodeId: string,
  wrappedDek: string,
): Promise<string | null> {
  const vk = await getVaultKey(workspace, vaultNodeId)
  if (!vk) return null
  try {
    const dek = await c.unwrapKeyAes(wrappedDek, vk)
    const raw = await crypto.subtle.exportKey("raw", dek)
    return c.toB64(new Uint8Array(raw))
  } catch {
    return null
  }
}

/**
 * 업로드용 새 DEK 발급 (V5c). 파일마다 새 DEK 생성 → raw(base64, Rust 암호화용)
 * + vault_key 로 wrap(서버 저장용) 반환. 실패(비멤버/잠김) 시 null.
 */
export async function makeUploadKey(
  workspace: string,
  vaultNodeId: string,
): Promise<{ rawB64: string; wrapped: string } | null> {
  const vk = await getVaultKey(workspace, vaultNodeId)
  if (!vk) return null
  const dek = await c.generateAesKey()
  const raw = await crypto.subtle.exportKey("raw", dek)
  return { rawB64: c.toB64(new Uint8Array(raw)), wrapped: await c.wrapKeyAes(dek, vk) }
}

/** vault 파일/폴더명 암호화 (V5c, 생성·이름변경용). 실패 시 null. */
export async function encryptName(
  workspace: string,
  vaultNodeId: string,
  name: string,
): Promise<string | null> {
  const vk = await getVaultKey(workspace, vaultNodeId)
  if (!vk) return null
  try {
    return await c.aesEncryptText(vk, name)
  } catch {
    return null
  }
}

/** vault 파일/폴더명 복호화. 실패 시 null. */
export async function decryptName(
  workspace: string,
  vaultNodeId: string,
  encryptedName: string,
): Promise<string | null> {
  const vk = await getVaultKey(workspace, vaultNodeId)
  if (!vk) return null
  try {
    return await c.aesDecryptText(vk, encryptedName)
  } catch {
    return null
  }
}
