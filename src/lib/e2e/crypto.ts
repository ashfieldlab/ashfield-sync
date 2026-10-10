/**
 * E2E 암호화 코어 (ADR-0016): 봉투 암호화 원시 연산.
 *
 * 전부 브라우저 WebCrypto + hash-wasm(argon2id). 평문/키 평문은 이 모듈을 거쳐
 * 메모리에서만 존재: 서버로 나가는 건 항상 암호문/wrap 된 키.
 *
 * 키 체인: 비밀번호 ─argon2id(salt)→ KEK ─AES→ 개인키 ─RSA→ vault_key ─AES→ {파일명,DEK} ─AES→ 파일
 *
 * 알고리즘:
 *   - KDF: Argon2id (m=64MB, t=3, p=4)       : 비밀번호/복구코드 → 32B
 *   - 키쌍: RSA-OAEP 4096 / SHA-256          : 개인키, vault_key, DEK wrap
 *   - 대칭: AES-GCM 256 (12B IV, 16B tag)    : 개인키/파일/파일명 암호화
 */

import { argon2id } from "hash-wasm"

const enc = new TextEncoder()
const dec = new TextDecoder()

// TS 5.7 의 Uint8Array<ArrayBufferLike> 와 WebCrypto 의 BufferSource 마찰 해소.
// 우리 바이트는 전부 ArrayBuffer 기반이라 안전한 캐스트.
const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource

const ARGON = { parallelism: 4, iterations: 3, memorySize: 64 * 1024 } // 64MB

// ---------------------------------------------------------------------------
// base64 (서버 전송용): 표준 base64, URL-safe 아님
// ---------------------------------------------------------------------------
export function toB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let s = ""
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function fromB64(b64: string): Uint8Array {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

// base64url: 파일명용. 표준 base64 의 `/` `+` `=` 는 Windows 경로/URL 에서
// 문제라 `_` `-` 로 치환하고 패딩 제거. 암호화된 파일/폴더명에만 사용.
export function toB64url(buf: ArrayBuffer | Uint8Array): string {
  return toB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function fromB64url(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/")
  while (b64.length % 4) b64 += "="
  return fromB64(b64)
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

// ---------------------------------------------------------------------------
// KEK: 비밀번호/복구코드에서 AES-GCM 키 유도 (Argon2id)
// ---------------------------------------------------------------------------
export function newSalt(): Uint8Array {
  return randomBytes(16)
}

export async function deriveKek(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = await argon2id({
    password,
    salt,
    ...ARGON,
    hashLength: 32,
    outputType: "binary", // Uint8Array(32)
  })
  return crypto.subtle.importKey("raw", bs(raw), "AES-GCM", false, ["encrypt", "decrypt"])
}

// ---------------------------------------------------------------------------
// AES-GCM: 범용 대칭 암복호. 출력 = base64(iv(12) + ciphertext+tag)
// ---------------------------------------------------------------------------
export async function aesEncrypt(key: CryptoKey, data: Uint8Array): Promise<string> {
  const iv = randomBytes(12)
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(iv) }, key, bs(data))
  const out = new Uint8Array(iv.length + ct.byteLength)
  out.set(iv, 0)
  out.set(new Uint8Array(ct), iv.length)
  return toB64(out)
}

export async function aesDecrypt(key: CryptoKey, b64: string): Promise<Uint8Array> {
  const buf = fromB64(b64)
  const iv = buf.slice(0, 12)
  const ct = buf.slice(12)
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bs(iv) }, key, bs(ct))
  return new Uint8Array(pt)
}

// 파일/폴더명 암복호: 출력은 base64url (파일시스템과 경로 안전, `/` `+` `=` 없음).
// 표준 base64 면 `/` 가 경로 구분자로 오인돼 싱크 placeholder 경로가 깨진다.
export async function aesEncryptText(key: CryptoKey, text: string): Promise<string> {
  const iv = randomBytes(12)
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(iv) }, key, bs(enc.encode(text)))
  const out = new Uint8Array(iv.length + ct.byteLength)
  out.set(iv, 0)
  out.set(new Uint8Array(ct), iv.length)
  return toB64url(out)
}

export async function aesDecryptText(key: CryptoKey, b64url: string): Promise<string> {
  const buf = fromB64url(b64url)
  const iv = buf.slice(0, 12)
  const ct = buf.slice(12)
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bs(iv) }, key, bs(ct))
  return dec.decode(pt)
}

// ---------------------------------------------------------------------------
// RSA-OAEP 키쌍: 개인키는 AES 로 잠가 저장, 공개키는 평문
// ---------------------------------------------------------------------------
export async function generateKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
  )
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toB64(await crypto.subtle.exportKey("spki", key))
}

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    bs(fromB64(b64)),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["wrapKey", "encrypt"],
  )
}

/** 개인키(PKCS8)를 KEK 로 AES-GCM 암호화 → base64 */
export async function exportPrivateKeyEncrypted(key: CryptoKey, kek: CryptoKey): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key)
  return aesEncrypt(kek, new Uint8Array(pkcs8))
}

/** KEK 로 풀어 개인키 CryptoKey 복원 */
export async function importPrivateKeyEncrypted(b64: string, kek: CryptoKey): Promise<CryptoKey> {
  const pkcs8 = await aesDecrypt(kek, b64)
  return crypto.subtle.importKey(
    "pkcs8",
    bs(pkcs8),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["unwrapKey", "decrypt"],
  )
}

// ---------------------------------------------------------------------------
// vault_key / DEK: AES-GCM 키. RSA(공개키)로 wrap, RSA(개인키)로 unwrap
// ---------------------------------------------------------------------------
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ])
}

/** AES 키(vault_key 또는 DEK)를 RSA 공개키로 wrap → base64 */
export async function wrapKeyRsa(key: CryptoKey, publicKey: CryptoKey): Promise<string> {
  const wrapped = await crypto.subtle.wrapKey("raw", key, publicKey, { name: "RSA-OAEP" })
  return toB64(wrapped)
}

/** RSA 개인키로 unwrap → AES-GCM CryptoKey */
export async function unwrapKeyRsa(b64: string, privateKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    bs(fromB64(b64)),
    privateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  )
}

/** DEK 를 vault_key(AES) 로 wrap → base64. (AES-KW 대신 AES-GCM raw 암호화) */
export async function wrapKeyAes(dek: CryptoKey, vaultKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", dek)
  return aesEncrypt(vaultKey, new Uint8Array(raw))
}

/** vault_key 로 wrapped DEK 풀기 → AES-GCM CryptoKey */
export async function unwrapKeyAes(b64: string, vaultKey: CryptoKey): Promise<CryptoKey> {
  const raw = await aesDecrypt(vaultKey, b64)
  return crypto.subtle.importKey("raw", bs(raw), "AES-GCM", true, ["encrypt", "decrypt"])
}

// ---------------------------------------------------------------------------
// 복구 코드: 사람이 보관할 고엔트로피 문자열 (group-of-4)
// ---------------------------------------------------------------------------
export function generateRecoveryCode(): string {
  const bytes = randomBytes(20) // 160bit
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 혼동 문자(0/O/1/I) 제외
  let s = ""
  for (const b of bytes) s += alphabet[b % alphabet.length]
  return s.match(/.{1,4}/g)!.join("-") // XXXX-XXXX-...
}
