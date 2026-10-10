import { useEffect, useRef, useState } from "react"

import { invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { open as openDialog } from "@tauri-apps/plugin-dialog"
import { openPath } from "@tauri-apps/plugin-opener"

import { api, ApiError, getToken, setActiveCompany, setRefreshHandler, setToken } from "./lib/api"
import { env } from "./lib/config"
import {
  oauthHasStoredRefresh,
  oauthLogin,
  oauthLogout,
  oauthRefresh,
} from "./lib/oauth"
import { checkForUpdate } from "./lib/updater"
import * as e2e from "./lib/e2e/session"
import {
  getLastSync,
  getOnboarded,
  getSettings,
  resetSettings,
  setExcludedCompanies,
  setLastSync,
  setOnboarded,
  setSyncRoot,
  type Settings,
} from "./lib/settings"
import type { ChangesResponse, MeResponse, NodeKind, NodeResponse, TreeResponse } from "./lib/types"

import "./App.css"
import ashfieldMark from "./assets/ashfield-mark.svg"

interface AppState {
  me: MeResponse | null
  activeCompany: string | null
  nodes: NodeResponse[]
  loading: boolean
  error: string | null
}

const INITIAL_STATE: AppState = {
  me: null,
  activeCompany: null,
  nodes: [],
  loading: false,
  error: null,
}

const SCOPES = ["personal", "shared"] as const
type Scope = (typeof SCOPES)[number]

// 보안 폴더(vault) 파일 상한 — whole-file AES-GCM 이라 평문+암호문을 통째 메모리에
// 올리고(~2배), 매 저장마다 전체를 재암호화·재업로드한다. 대용량은 비효율·메모리
// 위험이라 거부. 문서 용도 기준 200MB. (비-vault 파일엔 적용 안 됨)
const VAULT_MAX_BYTES = 200 * 1024 * 1024

// settle — 업로드 직전 파일이 아직 쓰이는 중인지(반쪽 상태) 확인. stat 을 잠깐 간격
// 두고 두 번 찍어 size/mtime 이 그대로면 "쓰기 끝남" 으로 본다. 계속 변하면 상한까지
// 재시도(backoff) 후, 상한 도달 시엔 현재 상태로 업로드(무한 대기 방지).
const SETTLE_MAX_ATTEMPTS = 4
const SETTLE_BASE_MS = 500

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

interface LocalChange {
  kind: "create" | "modify" | "delete" | "rename"
  path: string
  oldPath: string | null
  isDir: boolean
}

// 커스텀 타이틀바 — OS chrome(decorations:false) 대신 직접 그림.
// data-tauri-drag-region 영역으로 창 이동, 버튼으로 최소화/최대화/닫기.
function TitleBar() {
  const win = getCurrentWindow()
  return (
    <div className="titlebar" data-tauri-drag-region>
      <div className="titlebar-brand" data-tauri-drag-region>
        <img className="titlebar-logo" src={ashfieldMark} alt="Ashfield" draggable={false} />
        Ashfield Sync
      </div>
      <div className="titlebar-controls">
        <button className="tb-btn" aria-label="최소화" onClick={() => void win.minimize()}>
          <svg width="11" height="11" viewBox="0 0 11 11"><rect x="1" y="5" width="9" height="1" fill="currentColor" /></svg>
        </button>
        <button className="tb-btn tb-close" aria-label="닫기" onClick={() => void win.close()}>
          <svg width="11" height="11" viewBox="0 0 11 11"><path d="M1 1 L10 10 M10 1 L1 10" stroke="currentColor" strokeWidth="1.1" /></svg>
        </button>
      </div>
    </div>
  )
}

// Windows 경로 비교 정규화 — 구분자 통일 + 끝 슬래시 제거 + 소문자 (대소문자 무시)
function normPath(p: string): string {
  return p.replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase()
}
function baseName(p: string): string {
  return p.replace(/\\+$/, "").split("\\").pop() ?? p
}
function dirName(p: string): string {
  const parts = p.replace(/\\+$/, "").split("\\")
  parts.pop()
  return parts.join("\\")
}

// Windows 파일명 불가 문자 — 암호화된(base64) 파일명 등은 placeholder 못 만듦.
// 그런 노드는 싱크에서 skip (E2E 복호화는 V5 별도). 안 그러면 populate 실패.
function isSyncableName(name: string): boolean {
  return name.length > 0 && !/[/\\:*?"<>|]/.test(name)
}

function scopeLabel(sc: Scope): string {
  return sc === "personal" ? "내 파일" : "회사 공유"
}

function App() {
  const [state, setState] = useState<AppState>(INITIAL_STATE)
  const [booting, setBooting] = useState(true)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [pollStatus, setPollStatus] = useState<string | null>(null)
  const [onboarding, setOnboarding] = useState(false) // 첫 실행 마법사 표시
  const [updateMsg, setUpdateMsg] = useState<string | null>(null)
  // E2E 보안 폴더 잠금해제 (V5) — 해제돼야 vault 구조/이름 복호화
  const [e2eUnlocked, setE2eUnlocked] = useState(false)
  const [e2eModal, setE2eModal] = useState(false)
  const [e2ePw, setE2ePw] = useState("")
  const [e2eErr, setE2eErr] = useState<string | null>(null)
  // F1 — 감지된 로컬 변경 (최근 것 우선, 최대 20개). 업로드는 F2.
  // 동기화 폴더(루트)를 탐색기로 — 싱크 앱의 핵심 동작.
  async function openSyncFolder() {
    const stg = settings ?? (await getSettings())
    if (!stg?.syncRoot) return
    try {
      await openPath(stg.syncRoot)
    } catch (err) {
      console.warn("[ui] 폴더 열기 실패", err)
    }
  }

  // 탐색기에 반영된 (company|scope) → {baseDir, nodeId→{경로,etag}}.
  // polling diff 의 기준 — 삭제/이동/내용수정 감지.
  const vfsMapRef = useRef<
    Map<
      string,
      { baseDir: string; entries: Map<string, { path: string; etag: string | null; kind: NodeKind }> }
    >
  >(new Map())

  // F2 — 절대경로(정규화) → node. 로컬 변경을 backend 호출로 옮길 때 사용.
  const pathIndexRef = useRef<
    Map<string, { nodeId: string; etag: string | null; companyId: string; scope: Scope; kind: NodeKind; size?: number | null; mtimeMs?: number | null }>
  >(new Map())
  // 로컬 변경 처리 직렬화 — 이벤트 동시 도착 시 race 방지
  const queueRef = useRef<Promise<void>>(Promise.resolve())
  // coalescing — 같은 파일의 modify 가 이미 큐에서 대기 중인 경로 집합. 대기분은
  // 처리 시점에 파일을 다시 stat 해 최신을 올리므로, 중복 이벤트는 버려 헛 업로드를 막는다.
  const pendingModifyRef = useRef<Set<string>>(new Set())
  // SSE nudge 가 호출할 즉시-poll 함수 (polling effect 가 최신본 주입)
  const pollNowRef = useRef<null | (() => Promise<void>)>(null)
  // 활성 회사 — refresh handler(stale closure)가 SSE 재연결에 참조
  const activeCompanyRef = useRef<string | null>(null)
  // 전 회사·스코프 누적 DEK (node_id → raw base64). vfs_set_deks 가 맵 전체를
  // 교체하므로 scope 별 호출이 서로 덮어쓰지 않도록 여기 병합해 통째로 푸시.
  const deksRef = useRef<Record<string, string>>({})
  // vault 루트 로컬경로(소문자) → {회사, vault 노드 id}. 이 아래의 로컬 변경은
  // 암호화 업로드 경로(V5c)로 처리 — 평문이 서버로 새지 않도록.
  const vaultRootsRef = useRef<Map<string, { company: string; vaultNodeId: string }>>(new Map())

  // 부팅 — 401 자동 refresh handler 주입 + 저장된 refresh_token 있으면 자동 로그인
  useEffect(() => {
    // 갱신은 Rust 가 직렬화(single-flight) — SSE·VFS 도 같은 캐시를 쓰므로 SSE 재연결 불필요
    // (SSE 는 401 이면 스스로 새 토큰을 받아 재연결한다).
    setRefreshHandler(async (stale) => {
      const tokens = await oauthRefresh(stale)
      setToken(tokens.access_token)
    })
    void (async () => {
      try {
        setSettings(await getSettings())
        const stored = await oauthHasStoredRefresh()
        if (!stored) return
        const tokens = await oauthRefresh()
        setToken(tokens.access_token)
        const me = await loadMe()
        if (me) {
          if (await getOnboarded()) void bootstrapVfs(me)
          else setOnboarding(true)
        }
      } catch (err) {
        // refresh 실패 (revoked / 만료) — 로그인 화면으로
        console.warn("[boot] refresh failed", err)
      } finally {
        setBooting(false)
      }
    })()
    return () => setRefreshHandler(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 로컬 변경 이벤트 수신 (F1) — Rust watcher 가 emit → 업로드 큐로. 결과는 활동 피드에.
  useEffect(() => {
    const unlisten = listen<LocalChange>("local-change", (ev) => {
      enqueueChange(ev.payload)
    })
    return () => {
      void unlisten.then((fn) => fn())
    }
  }, [])

  // SSE nudge 수신 — 1초 디바운스 후 즉시 poll (commit 직후 정합성 확보).
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | null = null
    const unlisten = listen("remote-change", () => {
      if (timer) clearTimeout(timer)
      timer = setTimeout(() => void pollNowRef.current?.(), 1000)
    })
    return () => {
      if (timer) clearTimeout(timer)
      void unlisten.then((fn) => fn())
    }
  }, [])

  // SSE 가 401 후 refresh 까지 실패(refresh_token 만료·폐기·재사용 감지) — 세션 만료, 로그인 화면으로.
  useEffect(() => {
    const unlisten = listen<string>("auth-expired", (ev) => {
      console.warn("[auth] expired", ev.payload)
      setToken(null)
      setActiveCompany(null)
      setState({ ...INITIAL_STATE, error: "세션이 만료되었습니다. Ashfield 계정으로 다시 로그인해주세요." })
    })
    return () => {
      void unlisten.then((fn) => fn())
    }
  }, [])

  // 활성 회사 바뀌면 SSE 재연결 (그 회사 변경을 구독) + ref 갱신.
  useEffect(() => {
    activeCompanyRef.current = state.activeCompany
    if (state.me && state.activeCompany) connectSse(state.activeCompany)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.activeCompany])

  // 부팅 시 1회 업데이트 확인 — 있으면 안내 (적용은 사용자 클릭). 실패는 무시.
  useEffect(() => {
    void (async () => {
      try {
        const up = await checkForUpdate()
        if (up) setUpdateMsg(`새 버전 ${up.info.version} 사용 가능`)
      } catch {
        // endpoint 미구성/네트워크 — 조용히 무시
      }
    })()
  }, [])

  async function handleApplyUpdate() {
    try {
      const up = await checkForUpdate()
      if (!up) {
        setUpdateMsg("최신 버전입니다")
        return
      }
      setUpdateMsg(`업데이트 ${up.info.version} 설치 중...`)
      await up.apply() // 다운로드 → 서명 검증 → 설치 → 재시작
    } catch (err) {
      setUpdateMsg(`업데이트 확인 실패: ${String(err)}`)
    }
  }

  // opt-out 모델 — 기본 전체 sync, 제외 목록에 있는 회사만 빠짐
  function syncedCompanies(me: MeResponse, excluded: string[]): string[] {
    return me.groups.filter((g) => !excluded.includes(g))
  }

  // -------------------------------------------------------------------------
  // VFS — 로그인하면 자동: register → connect → 전 회사 placeholder 반영
  // -------------------------------------------------------------------------

  // 싱크는 전체 서브트리(모든 깊이)를 한 번에 — recursive=true. (웹은 한 단계)
  async function fetchTree(company: string, sc: Scope): Promise<NodeResponse[]> {
    const tree = await api<TreeResponse>(
      `/api/v1/nodes/tree?scope=${sc}&recursive=true`,
      { companyId: company },
    )
    return tree.nodes
  }

  // vault 자손(암호화 내용) 의 node id 집합 — 싱크는 복호화 못 하니 통째 skip.
  // vault 루트 폴더 자신은 평문명이라 유지(빈 폴더로 보임). 복호화는 V5.
  function computeVaultContentIds(nodes: NodeResponse[], vaultIds: Set<string>): Set<string> {
    const byId = new Map(nodes.map((n) => [n.id, n]))
    const skip = new Set<string>()
    for (const n of nodes) {
      let cur = n.parent_id ? byId.get(n.parent_id) : undefined
      while (cur) {
        if (vaultIds.has(cur.id)) {
          skip.add(n.id)
          break
        }
        cur = cur.parent_id ? byId.get(cur.parent_id) : undefined
      }
    }
    return skip
  }

  // 표시 이름 resolver — vault 항목은 복호화본(nameOverrides), 그 외는 원본.
  // 경로 구성에 조상 이름도 쓰므로 모든 곳에서 이걸 거쳐야 nested 가 맞음.
  type NameOf = (n: NodeResponse) => string

  // tree 평탄화 → vfs_populate payload. parent_id 사슬로 각 노드의 상대 경로 계산.
  function buildVfsPayload(
    nodes: NodeResponse[],
    companyId: string,
    skipIds: Set<string>,
    nameOf: NameOf,
    contentIds: Set<string>,
  ) {
    const byId = new Map(nodes.map((n) => [n.id, n]))
    function relDir(n: NodeResponse): string {
      const parts: string[] = []
      let cur = n.parent_id ? byId.get(n.parent_id) : undefined
      while (cur) {
        parts.unshift(nameOf(cur))
        cur = cur.parent_id ? byId.get(cur.parent_id) : undefined
      }
      return parts.join("\\")
    }
    const syncable = (n: NodeResponse) =>
      !skipIds.has(n.id) &&
      isSyncableName(nameOf(n)) &&
      !relDir(n).split("\\").some((seg) => seg && !isSyncableName(seg))
    const dirs = nodes
      .filter((n) => n.kind === "folder" && syncable(n))
      .map((n) => (relDir(n) ? `${relDir(n)}\\${nameOf(n)}` : nameOf(n)))
    const files = nodes
      .filter((n) => n.kind === "file" && syncable(n))
      .map((n) => ({
        relativeDir: relDir(n),
        name: nameOf(n),
        nodeId: n.id,
        companyId,
        // vault 파일은 평문 크기(암호문-28: iv12+tag16) 로 placeholder 생성 —
        // hydrate 가 복호화한 평문 길이와 일치해야 OS 가 잘림으로 보지 않음.
        size: contentIds.has(n.id)
          ? Math.max(0, (n.size_bytes ?? 28) - 28)
          : (n.size_bytes ?? 0),
        mtimeMs: new Date(n.updated_at).getTime(),
      }))
    return { dirs, files }
  }

  // node ID → {전체 경로, etag, kind} — polling diff 용 (파일+폴더 둘 다 추적).
  function buildVfsEntries(
    nodes: NodeResponse[],
    baseDir: string,
    skipIds: Set<string>,
    nameOf: NameOf,
  ) {
    const pathOf = fullPathOf(nodes, baseDir, nameOf)
    const okPath = (n: NodeResponse) =>
      !skipIds.has(n.id) &&
      pathOf(n)
        .slice(baseDir.length + 1)
        .split("\\")
        .every((seg) => isSyncableName(seg))
    return new Map(
      nodes
        .filter(okPath)
        .map((n) => [n.id, { path: pathOf(n), etag: n.etag, kind: n.kind }]),
    )
  }

  // tree 의 각 노드 절대경로 — folder/file 공통
  function fullPathOf(nodes: NodeResponse[], baseDir: string, nameOf: NameOf) {
    const byId = new Map(nodes.map((n) => [n.id, n]))
    return (n: NodeResponse): string => {
      const parts: string[] = [nameOf(n)]
      let cur = n.parent_id ? byId.get(n.parent_id) : undefined
      while (cur) {
        parts.unshift(nameOf(cur))
        cur = cur.parent_id ? byId.get(cur.parent_id) : undefined
      }
      return `${baseDir}\\${parts.join("\\")}`
    }
  }

  // path → node 역방향 인덱스 갱신 (F2 업로드용). 해당 company|scope 만 교체.
  function rebuildPathIndex(
    company: string,
    sc: Scope,
    nodes: NodeResponse[],
    baseDir: string,
    nameOf: NameOf,
  ) {
    for (const [k, v] of pathIndexRef.current) {
      if (v.companyId === company && v.scope === sc) pathIndexRef.current.delete(k)
    }
    const pathOf = fullPathOf(nodes, baseDir, nameOf)
    for (const n of nodes) {
      pathIndexRef.current.set(normPath(pathOf(n)), {
        nodeId: n.id,
        etag: n.etag,
        companyId: company,
        scope: sc,
        kind: n.kind,
        // 변경 감지 기준값 — 하이드레이트된 로컬 파일의 size/mtime 은 서버 값과
        // 일치(placeholder mtime = updated_at). 헛 modify(ADS 등) 걸러냄.
        size: n.kind === "file" ? (n.size_bytes ?? null) : null,
        mtimeMs: n.updated_at ? new Date(n.updated_at).getTime() : null,
      })
    }
  }

  // 탐색기 반영 — diff(삭제/이동/수정) 후 populate (신규 생성, 기존 skip)
  // prune=true 는 startup bootstrap 에서만 — desired 강제 수렴은 재시작 시 1회.
  // polling/SSE sync 는 prune 생략(기존 diff 만): vault 안에서 막 만든 미업로드
  // 로컬 파일이 서버 반영 전에 prune 으로 날아가는 레이스 방지.
  async function syncVfs(company: string, sc: Scope, nodes: NodeResponse[], prune = false) {
    const stg = await getSettings()
    const key = `${company}|${sc}`
    const baseDir = `${stg.syncRoot}\\${company}\\${scopeLabel(sc)}`
    // vault 내용 처리:
    //   잠금해제됨 → 이름 복호화해 구조 그대로 표시 (복호화 실패분만 skip)
    //   잠김       → 내용 통째 skip (vault 루트만 빈 채로)
    let vaultIds = new Set<string>()
    try {
      const vaults = await api<{ node_id: string }[]>("/api/v1/e2e/vaults", {
        companyId: company,
      })
      vaultIds = new Set(vaults.map((v) => v.node_id))
    } catch {
      /* e2e 미설정 등 — vault 없음 */
    }
    const byId = new Map(nodes.map((n) => [n.id, n]))
    const vaultRootOf = (n: NodeResponse): string | null => {
      let cur = n.parent_id ? byId.get(n.parent_id) : undefined
      while (cur) {
        if (vaultIds.has(cur.id)) return cur.id
        cur = cur.parent_id ? byId.get(cur.parent_id) : undefined
      }
      return null
    }
    const contentIds = computeVaultContentIds(nodes, vaultIds)
    const nameOverrides = new Map<string, string>()
    const skipIds = new Set<string>()
    // node_id → raw DEK(base64) — hydrate 복호화용. unlock 시에만 채움.
    const deks: Record<string, string> = {}
    if (e2e.isUnlocked()) {
      for (const n of nodes) {
        if (!contentIds.has(n.id)) continue
        const vroot = vaultRootOf(n)
        const dec = vroot ? await e2e.decryptName(company, vroot, n.name) : null
        if (dec) nameOverrides.set(n.id, dec)
        else {
          skipIds.add(n.id) // 복호화 실패 — 표시 불가
          continue
        }
        // 파일이면 DEK 도 풀어 Rust 에 넘길 준비 (폴더는 wrapped_dek 없음)
        const wrappedDek = (n as { wrapped_dek?: string | null }).wrapped_dek
        if (n.kind === "file" && vroot && wrappedDek) {
          const raw = await e2e.exportDek(company, vroot, wrappedDek)
          if (raw) deks[n.id] = raw
        }
      }
    } else {
      for (const id of contentIds) skipIds.add(id) // 잠김 — 내용 숨김
    }
    const nameOf: NameOf = (n) => nameOverrides.get(n.id) ?? n.name

    const next = buildVfsEntries(nodes, baseDir, skipIds, nameOf)

    const existing = vfsMapRef.current.get(key)
    if (existing) {
      const staleFiles: string[] = []
      const staleDirs: string[] = []
      for (const [id, old] of existing.entries) {
        const nu = next.get(id)
        // 삭제/이동(rename) 이면 stale. 파일은 내용수정(etag)도 stale.
        const changed =
          !nu ||
          nu.path !== old.path ||
          (old.kind === "file" && nu.etag !== old.etag)
        if (changed) (old.kind === "folder" ? staleDirs : staleFiles).push(old.path)
      }
      if (staleFiles.length > 0) {
        await invoke<number>("vfs_delete", { paths: staleFiles })
      }
      // 폴더는 통째 제거 (remove_dir_all — 하위 placeholder 같이 정리)
      for (const dir of staleDirs) {
        try {
          await invoke("vfs_remove_dir", { path: dir })
        } catch (err) {
          console.warn("[sync] 폴더 제거 실패", dir, err)
        }
      }
    }

    // 이번 스코프의 DEK 를 누적 맵에 병합 후 Rust 에 통째 푸시 (hydrate 사전 적재).
    if (Object.keys(deks).length > 0) {
      Object.assign(deksRef.current, deks)
      try {
        await invoke("vfs_set_deks", { deks: deksRef.current })
      } catch (err) {
        console.warn("[sync] set_deks", err)
      }
    }

    const { dirs, files } = buildVfsPayload(nodes, company, skipIds, nameOf, contentIds)
    await invoke<number>("vfs_populate", { baseDir, dirs, files })

    // vault 루트 로컬경로 기록 — 암호화 업로드 디스패치(V5c)와 prune 공용.
    const pathOf = fullPathOf(nodes, baseDir, nameOf)
    for (const vid of vaultIds) {
      const vnode = byId.get(vid)
      if (vnode) {
        vaultRootsRef.current.set(pathOf(vnode).toLowerCase(), {
          company,
          vaultNodeId: vid,
        })
      }
    }

    // vault 폴더는 desired 상태로 강제 수렴(prune) — 재시작/이름변경/잠금토글로
    // 남은 잔재 placeholder 정리. startup(prune=true) 에서만, vault 한정.
    // allowed = 그 vault 안의 next 경로(파일+중간폴더). 잠김이면 next 에 내용
    // 없어 allowed 비어있음 → vault 내용 전부 제거(루트만 남김).
    if (prune) {
      for (const vid of vaultIds) {
        const vnode = byId.get(vid)
        if (!vnode) continue
        const vaultPath = pathOf(vnode)
        const allowed = [...next.values()]
          .map((e) => e.path)
          .filter((p) => p.toLowerCase().startsWith(vaultPath.toLowerCase() + "\\"))
        try {
          await invoke("vfs_prune", { dir: vaultPath, allowed })
        } catch (err) {
          console.warn("[sync] prune", vaultPath, err)
        }
      }
    }

    vfsMapRef.current.set(key, { baseDir, entries: next })
    rebuildPathIndex(company, sc, nodes, baseDir, nameOf)
  }

  async function bootstrapCompany(company: string) {
    for (const sc of SCOPES) {
      try {
        const nodes = await fetchTree(company, sc)
        await syncVfs(company, sc, nodes, true) // startup = prune 1회
      } catch (err) {
        console.warn("[vfs] bootstrap", company, sc, err)
      }
    }
    // delta polling 의 baseline — 방금 전체 tree 를 반영했으니 지금부터 추적
    if (!(await getLastSync(company))) {
      await setLastSync(company, new Date().toISOString())
    }
  }

  // 전 회사 재동기화 — E2E 잠금해제 직후 vault 이름을 복호화해 다시 깔기 위함.
  async function resyncAll() {
    if (!state.me) return
    const stg = await getSettings()
    for (const company of syncedCompanies(state.me, stg.excludedCompanies)) {
      for (const sc of SCOPES) {
        try {
          await syncVfs(company, sc, await fetchTree(company, sc), true) // 잠금토글 = prune
        } catch (err) {
          console.warn("[vfs] resync", company, sc, err)
        }
      }
    }
  }

  async function handleE2EUnlock() {
    setE2eErr(null)
    try {
      await e2e.unlock(e2ePw)
      setE2eUnlocked(true)
      setE2eModal(false)
      setE2ePw("")
      await resyncAll() // vault 이름 복호화해 구조 다시 표시
      setPollStatus("보안 폴더 잠금해제 — 내용 표시됨")
    } catch (err) {
      setE2eErr(err instanceof Error ? err.message : String(err))
    }
  }

  // 다시 잠금 — 메모리의 키·DEK 를 폐기하고 vault 내용을 탐색기에서 다시 숨긴다.
  async function handleE2ELock() {
    e2e.lock() // E2E 키 메모리 폐기
    deksRef.current = {} // Rust 측 DEK 폐기 (복호화 불가 상태로)
    try {
      await invoke("vfs_set_deks", { deks: {} })
    } catch (err) {
      console.warn("[e2e] lock set_deks clear", err)
    }
    setE2eUnlocked(false)
    await resyncAll() // vault 이름 복호화 불가 → 내용 다시 숨김(prune)
    setPollStatus("보안 폴더 잠금")
  }

  // -------------------------------------------------------------------------
  // F2 — 로컬 변경을 backend 로 업로드 (직렬 처리)
  // -------------------------------------------------------------------------

  // 절대경로 → {company, scope, baseDir}. sync 대상 밖이면 null.
  async function parsePath(absPath: string) {
    const stg = await getSettings()
    const root = normPath(stg.syncRoot)
    if (!normPath(absPath).startsWith(root + "\\")) return null
    const rest = absPath.slice(stg.syncRoot.length).replace(/^\\+/, "")
    const segs = rest.split("\\")
    if (segs.length < 2) return null
    const [company, scopeSeg] = segs
    const scope: Scope | null =
      scopeSeg === "내 파일" ? "personal" : scopeSeg === "회사 공유" ? "shared" : null
    if (!scope) return null
    if (stg.excludedCompanies.includes(company)) return null
    return { company, scope, baseDir: `${stg.syncRoot}\\${company}\\${scopeSeg}` }
  }

  // 부모 폴더 절대경로 → parent_id (baseDir 직속이면 null)
  function resolveParentId(parentDir: string, baseDir: string): string | null {
    if (normPath(parentDir) === normPath(baseDir)) return null
    return pathIndexRef.current.get(normPath(parentDir))?.nodeId ?? null
  }

  function indexPut(path: string, e: { nodeId: string; etag: string | null; companyId: string; scope: Scope; kind: NodeKind; size?: number | null; mtimeMs?: number | null }) {
    pathIndexRef.current.set(normPath(path), e)
  }

  // 업로드 후 vfsMapRef 의 etag/경로도 갱신 — 다음 poll diff 가 같은 파일을
  // "원격 변경" 으로 오인해 로컬 파일을 placeholder 로 되돌리는 thrash 방지.
  function syncEntryAfterUpload(company: string, sc: Scope, nodeId: string, path: string, etag: string | null) {
    const m = vfsMapRef.current.get(`${company}|${sc}`)
    if (m) m.entries.set(nodeId, { path, etag, kind: "file" })
  }

  // 대용량 (50MB+) — part_size 단위로 잘라 각 파트 PUT, ETag 수집.
  async function uploadParts(
    nodeId: string,
    path: string,
    size: number,
    partSize: number,
    company: string,
  ): Promise<{ PartNumber: number; ETag: string }[]> {
    const count = Math.ceil(size / partSize)
    const parts: { PartNumber: number; ETag: string }[] = []
    for (let i = 1; i <= count; i++) {
      const offset = (i - 1) * partSize
      const length = Math.min(partSize, size - offset)
      const { url } = await api<{ url: string }>(
        `/api/v1/nodes/${nodeId}/parts/${i}/url`,
        { method: "POST", companyId: company },
      )
      const etag = await invoke<string>("vfs_put_file_part", { path, url, offset, length })
      parts.push({ PartNumber: i, ETag: etag })
      setPollStatus(`업로드 중 ${baseName(path)} (${i}/${count})`)
    }
    return parts
  }

  async function uploadNewFile(path: string, ctx: { company: string; scope: Scope; baseDir: string }) {
    // 업로드한 로컬 size/mtime — 이후 modify 가 진짜 변경인지 판정하는 기준값.
    const st = await invoke<{ size: number; mtimeMs: number; dehydrated: boolean }>("vfs_file_stat", { path })
    const size = st.size
    const parentId = resolveParentId(dirName(path), ctx.baseDir)
    const up = await api<{ node_id: string; upload_url?: string; multipart?: boolean; part_size?: number }>(
      "/api/v1/nodes/upload-url",
      {
        method: "POST",
        companyId: ctx.company,
        body: { name: baseName(path), parent_id: parentId, size, scope: ctx.scope, mime: null },
      },
    )
    if (up.multipart && up.part_size) {
      const parts = await uploadParts(up.node_id, path, size, up.part_size, ctx.company)
      const node = await api<NodeResponse>(`/api/v1/nodes/${up.node_id}/complete-multipart`, {
        method: "POST",
        companyId: ctx.company,
        body: { parts },
      })
      indexPut(path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: "file", size: st.size, mtimeMs: st.mtimeMs })
      syncEntryAfterUpload(ctx.company, ctx.scope, node.id, path, node.etag)
      return
    }
    if (!up.upload_url) return
    await invoke("vfs_put_file", { path, url: up.upload_url })
    const node = await api<NodeResponse>(`/api/v1/nodes/${up.node_id}/complete`, {
      method: "POST",
      companyId: ctx.company,
    })
    indexPut(path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: "file", size: st.size, mtimeMs: st.mtimeMs })
    syncEntryAfterUpload(ctx.company, ctx.scope, node.id, path, node.etag)
  }

  // 412 충돌 — 로컬 버전을 "foo (충돌본 날짜 PC명).ext" 로 복사해 새 파일로 업로드.
  // 원본은 건드리지 않음 — 다음 poll 이 서버 버전으로 되돌림.
  async function handleConflict(path: string, ctx: { company: string; scope: Scope; baseDir: string }) {
    const date = new Date().toISOString().slice(0, 10) // YYYY-MM-DD
    try {
      const conflictPath = await invoke<string>("vfs_make_conflict_copy", { path, date })
      await uploadNewFile(conflictPath, ctx)
      setPollStatus(`충돌 — 사본 생성: ${baseName(conflictPath)}`)
    } catch (err) {
      console.warn("[f2] 충돌 사본 실패", err)
      setPollStatus(`충돌 처리 실패: ${baseName(path)}`)
    }
  }

  // E2E vault 파일을 암호화해 업로드 (V5c). 신규(entry=null)면 upload-url +
  // 암호화된 이름, 기존이면 overwrite-url. 둘 다 wrapped_dek 동봉. 평문은 Rust
  // 가 temp 로 암호화한 뒤 기존 업로드 머신(single/multipart)으로 그 temp 를 전송.
  async function uploadVaultFile(
    path: string,
    ctx: { company: string; scope: Scope; baseDir: string },
    vroot: { company: string; vaultNodeId: string },
    entry: { nodeId: string; etag: string | null; companyId: string; scope: Scope; kind: NodeKind } | null,
  ) {
    // whole-file 암호화라 평문/암호문을 통째 메모리에 올림(~2배). 대용량은 메모리
    // 블로업 + 매 저장 전체 재업로드로 비효율 → 상한 초과 시 거부(편집은 웹/소형화 안내).
    const plainSize = await invoke<number>("vfs_file_size", { path })
    if (plainSize > VAULT_MAX_BYTES) {
      const mb = Math.round(VAULT_MAX_BYTES / (1024 * 1024))
      setPollStatus(`보안 폴더는 ${mb}MB 이하만 — 너무 큼: ${baseName(path)}`)
      return
    }
    const key = await e2e.makeUploadKey(ctx.company, vroot.vaultNodeId)
    if (!key) {
      setPollStatus(`보안 폴더 키 없음 — 업로드 보류: ${baseName(path)}`)
      return
    }
    const tempPath = await invoke<string>("vfs_encrypt_to_temp", { src: path, dek: key.rawB64 })
    try {
      const ctSize = await invoke<number>("vfs_file_size", { path: tempPath })
      if (entry) {
        // 기존 파일 덮어쓰기 — wrapped_dek 은 overwrite-url 에서 pending 으로 들어가
        // overwrite-complete 시 승격된다 (백엔드).
        let ov: { upload_url?: string; multipart?: boolean; part_size?: number }
        try {
          ov = await api<{ upload_url?: string; multipart?: boolean; part_size?: number }>(`/api/v1/nodes/${entry.nodeId}/overwrite-url`, {
            method: "POST",
            companyId: ctx.company,
            ifMatch: entry.etag ?? undefined,
            body: { size: ctSize, mime: null, wrapped_dek: key.wrapped },
          })
        } catch (err) {
          if (err instanceof ApiError && err.status === 412) {
            // 동시 수정 — vault 는 평문 충돌사본을 만들 수 없으므로 서버 버전 우선.
            // 다음 poll 의 syncVfs 가 로컬을 서버 버전으로 되돌린다.
            setPollStatus(`보안 폴더 충돌 — 서버 버전 우선: ${baseName(path)}`)
            return
          }
          throw err
        }
        let node: NodeResponse
        if (ov.multipart && ov.part_size) {
          const parts = await uploadParts(entry.nodeId, tempPath, ctSize, ov.part_size, ctx.company)
          node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}/overwrite-complete`, {
            method: "POST",
            companyId: ctx.company,
            body: { parts },
          })
        } else {
          if (!ov.upload_url) return
          await invoke("vfs_put_file", { path: tempPath, url: ov.upload_url })
          node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}/overwrite-complete`, {
            method: "POST",
            companyId: ctx.company,
            body: {},
          })
        }
        entry.etag = node.etag
        syncEntryAfterUpload(ctx.company, ctx.scope, entry.nodeId, path, node.etag)
        deksRef.current[entry.nodeId] = key.rawB64 // 즉시 재열기 위해 DEK 갱신
        await invoke("vfs_set_deks", { deks: deksRef.current })
        setPollStatus(`보안 업로드: ${baseName(path)}`)
      } else {
        // 신규 파일 — 이름도 암호화해 전송. wrapped_dek 은 upload-url 본문에.
        const encName = await e2e.encryptName(ctx.company, vroot.vaultNodeId, baseName(path))
        if (!encName) return
        const parentId = resolveParentId(dirName(path), ctx.baseDir)
        const up = await api<{ node_id: string; upload_url?: string; multipart?: boolean; part_size?: number }>(
          "/api/v1/nodes/upload-url",
          {
            method: "POST",
            companyId: ctx.company,
            body: {
              name: encName,
              parent_id: parentId,
              size: ctSize,
              scope: ctx.scope,
              mime: null,
              wrapped_dek: key.wrapped,
            },
          },
        )
        let node: NodeResponse
        if (up.multipart && up.part_size) {
          const parts = await uploadParts(up.node_id, tempPath, ctSize, up.part_size, ctx.company)
          node = await api<NodeResponse>(`/api/v1/nodes/${up.node_id}/complete-multipart`, {
            method: "POST",
            companyId: ctx.company,
            body: { parts },
          })
        } else {
          if (!up.upload_url) return
          await invoke("vfs_put_file", { path: tempPath, url: up.upload_url })
          node = await api<NodeResponse>(`/api/v1/nodes/${up.node_id}/complete`, {
            method: "POST",
            companyId: ctx.company,
            body: {},
          })
        }
        indexPut(path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: "file" })
        syncEntryAfterUpload(ctx.company, ctx.scope, node.id, path, node.etag)
        deksRef.current[node.id] = key.rawB64
        await invoke("vfs_set_deks", { deks: deksRef.current })
        setPollStatus(`보안 업로드(신규): ${baseName(path)}`)
      }
    } finally {
      // temp 암호문 정리 (best-effort) — OS temp 라 watcher 무관.
      try {
        await invoke("vfs_delete", { paths: [tempPath] })
      } catch {
        /* 무시 */
      }
    }
  }

  // vault 소속 로컬 변경 처리 (V5c) — 내용/이름을 암호화해 반영.
  async function processVaultChange(
    change: LocalChange,
    vroot: { company: string; vaultNodeId: string },
  ) {
    const ctx = await parsePath(change.path)
    if (!ctx) return
    if (!e2e.isUnlocked()) {
      setPollStatus(`보안 폴더 잠김 — 변경 보류: ${baseName(change.path)}`)
      return
    }

    if (change.kind === "create") {
      if (change.isDir) {
        const encName = await e2e.encryptName(ctx.company, vroot.vaultNodeId, baseName(change.path))
        if (!encName) return
        const parentId = resolveParentId(dirName(change.path), ctx.baseDir)
        const node = await api<NodeResponse>("/api/v1/nodes", {
          method: "POST",
          companyId: ctx.company,
          body: { name: encName, parent_id: parentId, scope: ctx.scope },
        })
        indexPut(change.path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: "folder" })
        return
      }
      await uploadVaultFile(change.path, ctx, vroot, null)
      return
    }

    if (change.kind === "modify") {
      if (change.isDir) return
      const entry = pathIndexRef.current.get(normPath(change.path))
      await uploadVaultFile(change.path, ctx, vroot, entry ?? null)
      return
    }

    if (change.kind === "delete") {
      const entry = pathIndexRef.current.get(normPath(change.path))
      if (!entry) return
      await api(`/api/v1/nodes/${entry.nodeId}`, { method: "DELETE", companyId: ctx.company })
      pathIndexRef.current.delete(normPath(change.path))
      vfsMapRef.current.get(`${ctx.company}|${ctx.scope}`)?.entries.delete(entry.nodeId)
      delete deksRef.current[entry.nodeId]
      return
    }

    if (change.kind === "rename" && change.oldPath) {
      // vault 경계를 넘는 이동은 암호화 요구가 달라져 미지원 — 보류.
      const oldRoot = vaultRootFor(change.oldPath)
      const newRoot = vaultRootFor(change.path)
      if (!oldRoot || !newRoot || oldRoot.vaultNodeId !== newRoot.vaultNodeId) {
        setPollStatus(`보안 폴더 경계를 넘는 이동은 싱크 미지원: ${baseName(change.path)}`)
        return
      }
      const entry = pathIndexRef.current.get(normPath(change.oldPath))
      if (!entry) return
      const encName = await e2e.encryptName(ctx.company, vroot.vaultNodeId, baseName(change.path))
      if (!encName) return
      const newParentId = resolveParentId(dirName(change.path), ctx.baseDir)
      const node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}`, {
        method: "PATCH",
        companyId: ctx.company,
        body: { name: encName, parent_id: newParentId },
      })
      pathIndexRef.current.delete(normPath(change.oldPath))
      indexPut(change.path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: entry.kind })
      syncEntryAfterUpload(ctx.company, ctx.scope, entry.nodeId, change.path, node.etag)
    }
  }

  // 경로가 어느 vault 소속인지 — 매칭되면 {회사, vault 노드}. 아니면 null.
  function vaultRootFor(p: string | null | undefined): { company: string; vaultNodeId: string } | null {
    if (!p) return null
    const lower = p.toLowerCase()
    for (const [root, info] of vaultRootsRef.current) {
      if (lower === root || lower.startsWith(root + "\\")) return info
    }
    return null
  }

  async function processLocalChange(change: LocalChange) {
    // E2E vault 내용은 평문이 아니라 암호화해서 올려야 함 (V5c). vault 소속이면
    // 전용 경로로 분기 — 평문이 서버로 새지 않도록.
    const vroot = vaultRootFor(change.path) ?? vaultRootFor(change.oldPath)
    if (vroot) {
      await processVaultChange(change, vroot)
      return
    }

    const ctx = await parsePath(change.kind === "rename" ? change.path : change.path)
    if (!ctx) return // sync 대상 밖

    if (change.kind === "create") {
      if (change.isDir) {
        // 폴더 생성 — parent 밑에 새 folder node
        const parentId = resolveParentId(dirName(change.path), ctx.baseDir)
        const node = await api<NodeResponse>("/api/v1/nodes", {
          method: "POST",
          companyId: ctx.company,
          body: { name: baseName(change.path), parent_id: parentId, scope: ctx.scope },
        })
        indexPut(change.path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: "folder" })
        return
      }
      await uploadNewFile(change.path, ctx)
      return
    }

    if (change.kind === "modify") {
      if (change.isDir) return
      const entry = pathIndexRef.current.get(normPath(change.path))
      if (!entry) {
        // 아직 모르는 파일 — 신규로 처리
        await uploadNewFile(change.path, ctx)
        return
      }
      // 내용이 실제로 바뀌었는지 메타데이터로 확인 (내용 안 읽음 → 대용량 안전).
      // Zone.Identifier(ADS) 변경·실행·재하이드레이션 등은 modify 를 내지만
      // 내용/크기/mtime 은 그대로 → 에코 업로드 방지.
      let st = await invoke<{ size: number; mtimeMs: number; dehydrated: boolean }>("vfs_file_stat", { path: change.path })
      // placeholder(내용 미다운) 는 로컬 편집 자체가 불가 → 무조건 skip.
      if (st.dehydrated) return
      // size 동일 + mtime 동일(2s 허용, 서버 updated_at ↔ 로컬 mtime 반올림 흡수) → 불변.
      if (
        entry.size != null && st.size === entry.size &&
        entry.mtimeMs != null && Math.abs(st.mtimeMs - entry.mtimeMs) < 2000
      ) return
      // settle — 아직 쓰이는 중이면(대용량 복사·청크 기록) 반쪽 파일을 올릴 수 있어,
      // 잠깐 간격을 두고 size/mtime 이 멈출 때까지 재확인한다. 상한까지도 계속 변하면
      // 이번엔 건너뛴다 — 쓰기가 멈추면 debouncer 의 trailing 이벤트가 최신본을 다시 올린다.
      let settled = false
      for (let attempt = 1; attempt <= SETTLE_MAX_ATTEMPTS; attempt++) {
        await sleep(Math.min(SETTLE_BASE_MS * attempt, 2000))
        const again = await invoke<{ size: number; mtimeMs: number; dehydrated: boolean }>("vfs_file_stat", { path: change.path })
        if (again.size === st.size && again.mtimeMs === st.mtimeMs) {
          settled = true
          break
        }
        st = again // 아직 변함 → 최신으로 갱신 후 재확인
      }
      if (!settled) return
      const size = st.size
      try {
        const ov = await api<{ upload_url?: string; multipart?: boolean; part_size?: number }>(
          `/api/v1/nodes/${entry.nodeId}/overwrite-url`,
          { method: "POST", companyId: ctx.company, ifMatch: entry.etag ?? undefined, body: { size, mime: null } },
        )
        let node: NodeResponse
        if (ov.multipart && ov.part_size) {
          const parts = await uploadParts(entry.nodeId, change.path, size, ov.part_size, ctx.company)
          node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}/overwrite-complete`, {
            method: "POST",
            companyId: ctx.company,
            body: { parts },
          })
        } else {
          if (!ov.upload_url) return
          await invoke("vfs_put_file", { path: change.path, url: ov.upload_url })
          node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}/overwrite-complete`, {
            method: "POST",
            companyId: ctx.company,
            body: {},
          })
        }
        entry.etag = node.etag
        entry.size = st.size // 업로드한 로컬 기준값 갱신 — 다음 헛 modify 는 skip
        entry.mtimeMs = st.mtimeMs
        syncEntryAfterUpload(ctx.company, ctx.scope, entry.nodeId, change.path, node.etag)
        setPollStatus(`업로드 반영: ${baseName(change.path)} (${node.size_bytes}B)`)
      } catch (err) {
        if (err instanceof ApiError && err.status === 412) {
          // 동시 수정 충돌 — 내 로컬 버전을 충돌 사본으로 보존 후 업로드.
          // 원본 경로는 서버 버전이 이김 — 다음 poll 의 syncVfs 가 stale 로
          // 판정해 원본을 서버 버전(placeholder)으로 되돌림.
          await handleConflict(change.path, ctx)
          return
        }
        throw err
      }
      return
    }

    if (change.kind === "delete") {
      const entry = pathIndexRef.current.get(normPath(change.path))
      if (!entry) return
      await api(`/api/v1/nodes/${entry.nodeId}`, { method: "DELETE", companyId: ctx.company })
      pathIndexRef.current.delete(normPath(change.path))
      vfsMapRef.current.get(`${ctx.company}|${ctx.scope}`)?.entries.delete(entry.nodeId)
      return
    }

    if (change.kind === "rename" && change.oldPath) {
      const entry = pathIndexRef.current.get(normPath(change.oldPath))
      if (!entry) return
      const newParentId = resolveParentId(dirName(change.path), ctx.baseDir)
      const node = await api<NodeResponse>(`/api/v1/nodes/${entry.nodeId}`, {
        method: "PATCH",
        companyId: ctx.company,
        body: { name: baseName(change.path), parent_id: newParentId },
      })
      pathIndexRef.current.delete(normPath(change.oldPath))
      indexPut(change.path, { nodeId: node.id, etag: node.etag, companyId: ctx.company, scope: ctx.scope, kind: entry.kind })
      syncEntryAfterUpload(ctx.company, ctx.scope, entry.nodeId, change.path, node.etag)
    }
  }

  function enqueueChange(change: LocalChange) {
    // coalescing — 파일 modify 는 같은 경로가 이미 대기 중이면 버린다(처리 시점에 최신
    // 을 다시 읽어 올리므로 중간 버전 반복 업로드가 낭비). create/delete/rename 은
    // 순서·의미가 있어 묶지 않는다.
    const coalesceKey =
      change.kind === "modify" && !change.isDir ? normPath(change.path) : null
    if (coalesceKey !== null) {
      if (pendingModifyRef.current.has(coalesceKey)) return
      pendingModifyRef.current.add(coalesceKey)
    }
    queueRef.current = queueRef.current
      .then(() => {
        // 처리 시작 시점에 대기 표시 해제 → 이후 도착하는 변경은 다시 큐에 들어온다.
        if (coalesceKey !== null) pendingModifyRef.current.delete(coalesceKey)
        return processLocalChange(change)
      })
      .catch((err) => {
        console.warn("[f2] 처리 실패", change, err)
        const detail = err instanceof ApiError ? `${err.status} ${JSON.stringify(err.body)}` : String(err)
        setPollStatus(`업로드 실패: ${baseName(change.path)} — ${detail}`)
      })
  }

  async function bootstrapVfs(me: MeResponse) {
    const stg = await getSettings()
    try {
      await invoke("vfs_register", { syncRoot: stg.syncRoot })
    } catch (err) {
      console.warn("[vfs] register", err)
    }
    try {
      await invoke("vfs_connect", {
        syncRoot: stg.syncRoot,
        // 토큰은 Rust oauth 모듈의 공용 캐시에서 (로그인/refresh 가 설정을 이미 넘김)
        config: { apiUrl: env.apiUrl },
      })
    } catch (err) {
      console.warn("[vfs] connect", err)
    }
    for (const company of syncedCompanies(me, stg.excludedCompanies)) {
      await bootstrapCompany(company)
    }
    // 로컬 변경 감지 시작 — placeholder 다 깔린 뒤라야 초기 create 폭주를 피함
    try {
      await invoke("watcher_start", { root: stg.syncRoot })
    } catch (err) {
      console.warn("[watcher] start", err)
    }
    // SSE 실시간 nudge 시작 (활성/첫 회사 기준). polling 은 fallback 으로 유지.
    connectSse(syncedCompanies(me, stg.excludedCompanies)[0] ?? null)
    setPollStatus(`탐색기 동기화 준비 완료 · ${new Date().toLocaleTimeString()}`)
  }

  // SSE 연결 — 활성 회사의 node 변경 nudge 구독. 토큰은 현재 access_token.
  // 회사/토큰 바뀌면 재호출 — Rust 쪽이 세대 카운터로 옛 연결 정리.
  function connectSse(company: string | null) {
    const token = getToken()
    if (!company || !token) return
    void invoke("sse_connect", {
      url: `${env.apiUrl}/api/v1/nodes/events`,
      token,
      company,
    }).catch((err) => console.warn("[sse] connect", err))
  }

  // -------------------------------------------------------------------------
  // Delta polling — 1분 주기, sync 대상 전 회사 순회 (ADR-0015 결정 7)
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!state.me) return
    const me = state.me

    async function pollAll() {
      const stg = await getSettings()
      let applied = 0
      for (const company of syncedCompanies(me, stg.excludedCompanies)) {
        try {
          const since = await getLastSync(company)
          if (!since) {
            await setLastSync(company, new Date().toISOString())
            continue
          }
          const res = await api<ChangesResponse>(
            `/api/v1/nodes/changes?since=${encodeURIComponent(since)}`,
            { companyId: company },
          )
          if (res.changes.length > 0) {
            for (const sc of SCOPES) {
              const nodes = await fetchTree(company, sc)
              await syncVfs(company, sc, nodes)
            }
            applied += res.changes.length
          }
          await setLastSync(company, res.server_time)
        } catch (err) {
          console.warn("[poll]", company, err)
        }
      }
      setPollStatus(
        applied > 0
          ? `${applied}건 변경 반영 · ${new Date().toLocaleTimeString()}`
          : `변경 없음 · ${new Date().toLocaleTimeString()}`,
      )
    }

    pollNowRef.current = pollAll // SSE nudge 가 호출
    void pollAll()
    const id = setInterval(() => void pollAll(), 60_000)
    return () => {
      clearInterval(id)
      pollNowRef.current = null
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.me])

  // -------------------------------------------------------------------------
  // 화면용 데이터 로드
  // -------------------------------------------------------------------------

  async function loadMe(): Promise<MeResponse | null> {
    setState((s) => ({ ...s, loading: true, error: null }))
    try {
      const me = await api<MeResponse>("/api/v1/me")
      const excluded = (await getSettings()).excludedCompanies
      const initialCompany = syncedCompanies(me, excluded)[0] ?? null
      if (initialCompany) setActiveCompany(initialCompany)
      setState({
        me,
        activeCompany: initialCompany,
        nodes: [],
        loading: false,
        error: null,
      })
      return me
    } catch (err) {
      // 401 = 자동 refresh 까지 실패 (revoked / SSO 종료) — 세션 만료, 로그인 화면으로
      if (err instanceof ApiError && err.status === 401) {
        setToken(null)
        setActiveCompany(null)
        setState({ ...INITIAL_STATE, error: "세션이 만료되었습니다. 다시 로그인해주세요." })
        return null
      }
      const msg = err instanceof ApiError ? `${err.status}: ${JSON.stringify(err.body)}` : String(err)
      setState((s) => ({ ...s, loading: false, error: msg }))
      return null
    }
  }

  // -------------------------------------------------------------------------
  // 사용자 액션
  // -------------------------------------------------------------------------

  async function handleLogin() {
    setState((s) => ({ ...s, loading: true, error: null }))
    try {
      const tokens = await oauthLogin()
      setToken(tokens.access_token)
      const me = await loadMe()
      if (me) {
        if (await getOnboarded()) void bootstrapVfs(me)
        else setOnboarding(true)
      }
    } catch (err) {
      setState((s) => ({ ...s, loading: false, error: String(err) }))
    }
  }

  // 온보딩 — 폴더만 확인하고 동기화 시작 (opt-out 이라 회사 선택 안 물음)
  async function handleOnboardingFolder() {
    const picked = await openDialog({
      directory: true,
      defaultPath: settings?.syncRoot,
      title: "동기화 폴더 선택",
    })
    if (typeof picked !== "string") return
    await setSyncRoot(picked)
    setSettings((s) => (s ? { ...s, syncRoot: picked } : s))
  }

  async function handleStartSync() {
    if (!state.me) return
    await setOnboarded(true)
    setOnboarding(false)
    void bootstrapVfs(state.me)
  }

  async function handleLogout() {
    try {
      await invoke("sse_disconnect")
    } catch (err) {
      console.warn("[sse] disconnect", err)
    }
    try {
      await invoke("watcher_stop")
    } catch (err) {
      console.warn("[watcher] stop", err)
    }
    try {
      await invoke("vfs_disconnect")
    } catch (err) {
      console.warn("[vfs] disconnect", err)
    }
    try {
      await oauthLogout()
    } catch (err) {
      console.warn("[logout]", err)
    }
    vfsMapRef.current.clear()
    pathIndexRef.current.clear()
    e2e.lock() // E2E 키 메모리 폐기
    deksRef.current = {} // Rust 측 DEK 도 폐기 (잠금 = 복호화 불가)
    try {
      await invoke("vfs_set_deks", { deks: {} })
    } catch (err) {
      console.warn("[logout] set_deks clear", err)
    }
    setE2eUnlocked(false)
    setToken(null)
    setActiveCompany(null)
    setState(INITIAL_STATE)
  }

  // 온보딩 다시 보기 — onboarded 만 끄고 로그아웃 → 다음 로그인이 마법사 표시
  async function handleReplayOnboarding() {
    await setOnboarded(false)
    await handleLogout()
  }

  // 전체 초기화 — 이 PC 에서 동기화 해제 + 로컬 폴더 정리 + 설정 리셋 + 로그아웃.
  // (서버 파일은 그대로 — 로컬은 placeholder/캐시라 안전.) OneDrive '연결 해제' 격.
  async function handleResetAll() {
    const root = (await getSettings()).syncRoot
    // 1) 동기화 중단 (콜백/감시 먼저 끔)
    try { await invoke("sse_disconnect") } catch { /* noop */ }
    try { await invoke("watcher_stop") } catch { /* noop */ }
    try { await invoke("vfs_disconnect") } catch { /* noop */ }
    // 2) sync root 등록 해제 → OS cloud-provider 보호 풀림
    try { await invoke("vfs_unregister", { syncRoot: root }) } catch (err) { console.warn("[reset] unregister", err) }
    // 3) 로컬 폴더 통째 삭제 (이제 보호 풀려 삭제 가능)
    try { await invoke("vfs_remove_dir", { path: root }) } catch (err) { console.warn("[reset] remove", err) }
    // 4) 설정 리셋
    await resetSettings()
    setSettings(await getSettings())
    // 5) refresh_token 폐기(계정 서버 revoke) + keychain 삭제 + 상태 초기화
    try { await oauthLogout() } catch { /* noop */ }
    vfsMapRef.current.clear()
    pathIndexRef.current.clear()
    setToken(null)
    setActiveCompany(null)
    setState(INITIAL_STATE)
  }

  async function handleChangeSyncRoot() {
    if (!settings || !state.me) return
    const picked = await openDialog({
      directory: true,
      defaultPath: settings.syncRoot,
      title: "동기화 폴더 선택",
    })
    if (typeof picked !== "string") return

    // 옛 위치: 연결 끊고 등록 해제 (파일은 남겨둠 — 사용자가 정리)
    try {
      await invoke("vfs_disconnect")
    } catch { /* 연결 안 됐을 수 있음 */ }
    try {
      await invoke("vfs_unregister", { syncRoot: settings.syncRoot })
    } catch (err) {
      console.warn("[vfs] unregister old", err)
    }

    await setSyncRoot(picked)
    setSettings((s) => (s ? { ...s, syncRoot: picked } : s))
    vfsMapRef.current.clear()
    void bootstrapVfs(state.me)
  }

  async function handleToggleExclude(companyId: string) {
    if (!settings || !state.me) return
    const turningOff = !settings.excludedCompanies.includes(companyId)
    const excluded = turningOff
      ? [...settings.excludedCompanies, companyId]
      : settings.excludedCompanies.filter((c) => c !== companyId)
    await setExcludedCompanies(excluded)
    setSettings({ ...settings, excludedCompanies: excluded })

    if (turningOff) {
      // 제외 — 탐색기에서 회사 폴더 정리 (서버 원본은 그대로)
      try {
        await invoke("vfs_remove_dir", { path: `${settings.syncRoot}\\${companyId}` })
      } catch (err) {
        console.warn("[vfs] remove dir", err)
      }
      for (const sc of SCOPES) vfsMapRef.current.delete(`${companyId}|${sc}`)

      // 활성 회사가 방금 제외됐으면 남은 회사 중 첫 번째로 전환
      if (state.activeCompany === companyId) {
        const next = syncedCompanies(state.me, excluded)[0] ?? null
        setState((s) => ({ ...s, activeCompany: next, nodes: [] }))
        if (next) setActiveCompany(next) // SSE/API 컨텍스트만 갱신
      }
    } else {
      // 다시 포함 — 그 회사만 placeholder 재구축
      void bootstrapCompany(companyId)
    }
  }

  // -------------------------------------------------------------------------
  // 렌더
  // -------------------------------------------------------------------------

  if (booting) {
    return (
      <>
        <TitleBar />
        <main className="container">
          <p>불러오는 중...</p>
        </main>
      </>
    )
  }

  if (!state.me) {
    return (
      <>
        <TitleBar />
        <main className="container">
          <h1>Ashfield</h1>
          <p className="subtitle">백엔드: <code>{env.apiUrl}</code></p>
          <div className="login">
            <p style={{ fontSize: "13px", color: "#666", marginBottom: "16px" }}>
              아래 버튼을 누르면 브라우저가 열려 Ashfield 계정으로 로그인합니다.
            </p>
            <button onClick={handleLogin} disabled={state.loading}>
              {state.loading ? "로그인 중..." : "Ashfield 계정으로 로그인"}
            </button>
          </div>
          {state.error && <pre className="error">{state.error}</pre>}
        </main>
      </>
    )
  }

  if (onboarding && settings) {
    return (
      <>
        <TitleBar />
        <main className="container">
          <h1>환영합니다 👋</h1>
          <p className="subtitle">{state.me.email} 님, 동기화를 시작할 준비가 거의 끝났어요.</p>
          <div className="login" style={{ maxWidth: 620 }}>
            <p style={{ fontSize: "14px", marginBottom: "4px", fontWeight: 600 }}>동기화 폴더</p>
            <p style={{ fontSize: "13px", color: "#666", marginBottom: "10px" }}>
              소속된 모든 회사의 파일이 이 폴더 아래에 나타납니다. 파일은 열 때
              자동으로 내려받고(클라우드 아이콘), 편집하면 자동으로 올라갑니다.
            </p>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "18px" }}>
              <code style={{ flex: 1, fontSize: "13px", background: "#f1f3f7", padding: "8px 10px", borderRadius: 6 }}>
                {settings.syncRoot}
              </code>
              <button onClick={() => void handleOnboardingFolder()}>변경</button>
            </div>
            <p style={{ fontSize: "12px", color: "#888", marginBottom: "16px" }}>
              특정 회사는 나중에 설정에서 제외할 수 있습니다.
            </p>
            <button onClick={() => void handleStartSync()}>동기화 시작</button>
          </div>
          {state.error && <pre className="error">{state.error}</pre>}
        </main>
      </>
    )
  }

  return (
    <>
      <TitleBar />
      <main className="container">
      <header className="app-header">
        <div>
          <small>{state.me.email}</small>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          {!e2eUnlocked ? (
            <button onClick={() => { setE2eErr(null); setE2eModal(true) }}>🔒 보안 해제</button>
          ) : (
            <button onClick={() => void handleE2ELock()} title="보안 폴더를 다시 잠급니다">🔓 보안 잠금</button>
          )}
          <button onClick={() => setShowSettings(true)}>설정</button>
          <button onClick={handleLogout}>로그아웃</button>
        </div>
      </header>

      {e2eModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.3)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }} onClick={() => setE2eModal(false)}>
          <div style={{ background: "#fff", borderRadius: 8, padding: 20, width: 360 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginTop: 0 }}>🔒 보안 해제</h3>
            <p style={{ fontSize: 13, color: "#666" }}>웹에서 설정한 암호화 비밀번호를 입력하면 보안 폴더 내용이 표시됩니다.</p>
            <div style={{ background: "#fef3c7", border: "1px solid #fcd34d", borderRadius: 6, padding: "10px 12px", marginBottom: 12, fontSize: 12, color: "#92400e", lineHeight: 1.6 }}>
              <strong>참고</strong>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                <li>비밀번호와 복구코드를 <strong>모두 분실하면 복구할 수 없습니다.</strong> 관리자도 복구가 불가능합니다.</li>
                <li>보안 폴더는 문서용입니다. 대용량 영상·이미지는 처리가 느릴 수 있습니다.</li>
                <li>큰 파일은 처음 열 때 전체를 내려받습니다. 미리보기·썸네일은 제공되지 않습니다.</li>
              </ul>
            </div>
            <input
              type="password"
              value={e2ePw}
              onChange={(e) => setE2ePw(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void handleE2EUnlock() }}
              placeholder="암호화 비밀번호"
              style={{ width: "100%", padding: "8px", marginBottom: 10, boxSizing: "border-box" }}
              autoFocus
            />
            {e2eErr && <p style={{ color: "#b91c1c", fontSize: 12 }}>{e2eErr}</p>}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button onClick={() => setE2eModal(false)}>취소</button>
              <button onClick={() => void handleE2EUnlock()}>해제</button>
            </div>
          </div>
        </div>
      )}

      {showSettings && settings && (
        <div
          style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.3)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}
          onClick={() => setShowSettings(false)}
        >
          <div
            className="settings"
            style={{ background: "#fff", borderRadius: 8, padding: 20, width: 440, maxHeight: "82vh", overflowY: "auto" }}
            onClick={(e) => e.stopPropagation()}
          >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
            <h3 style={{ margin: 0 }}>설정</h3>
            <button onClick={() => setShowSettings(false)} aria-label="닫기">✕</button>
          </div>
          <div style={{ marginBottom: "14px" }}>
            <strong>동기화 폴더</strong>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "6px" }}>
              <code style={{ flex: 1, minWidth: 0, fontSize: "13px", color: "#555", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{settings.syncRoot}</code>
              <button onClick={handleChangeSyncRoot} style={{ flexShrink: 0 }}>변경</button>
            </div>
          </div>
          <div>
            <strong>회사별 동기화</strong>
            <p style={{ fontSize: "12px", color: "#666", margin: "4px 0 8px" }}>
              기본은 모든 회사가 동기화됩니다. 끄면 탐색기에서 해당 회사 폴더가 제거됩니다.
            </p>
            {state.me.groups.map((c) => {
              const excluded = settings.excludedCompanies.includes(c)
              return (
                <label key={c} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "2px 0", opacity: excluded ? 0.5 : 1 }}>
                  <input
                    type="checkbox"
                    checked={!excluded}
                    onChange={() => void handleToggleExclude(c)}
                  />
                  {c}
                </label>
              )
            })}
          </div>
          <div style={{ borderTop: "1px solid #eee", marginTop: "14px", paddingTop: "14px" }}>
            <strong>업데이트</strong>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "8px", flexWrap: "wrap" }}>
              <button onClick={() => void handleApplyUpdate()}>업데이트 확인</button>
              {updateMsg && <span style={{ fontSize: "12px", color: "#666" }}>{updateMsg}</span>}
            </div>
          </div>
          <div style={{ borderTop: "1px solid #eee", marginTop: "14px", paddingTop: "14px" }}>
            <strong>초기화</strong>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "8px", flexWrap: "wrap" }}>
              <button onClick={() => void handleReplayOnboarding()}>온보딩 다시 보기</button>
              <button
                onClick={() => { if (confirm("이 PC의 동기화를 해제하고 로컬 동기화 폴더를 삭제합니다.\n서버에 있는 파일은 그대로 유지됩니다.\n계속할까요?")) void handleResetAll() }}
                style={{ color: "#b91c1c" }}
              >
                전체 초기화
              </button>
            </div>
          </div>
          </div>
        </div>
      )}

      {updateMsg && !showSettings && (
        <div style={{ background: "#eef6ff", border: "1px solid #b6d8f7", borderRadius: 8, padding: "8px 12px", margin: "8px 0", fontSize: "13px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>{updateMsg}</span>
          <button onClick={() => void handleApplyUpdate()}>지금 업데이트</button>
        </div>
      )}


      {state.loading && <p>불러오는 중...</p>}
      {state.error && <pre className="error">{state.error}</pre>}

      {/* 동기화 상태 카드 + 폴더 열기 — 싱크 앱의 핵심 동작은 탐색기로 가는 것 */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, border: "1px solid #e3e7ef", borderRadius: 10, padding: "12px 16px", margin: "12px 0", background: "#fff" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
          <span style={{ fontSize: 22 }}>{state.error ? "⚠️" : "✅"}</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 600 }}>{state.error ? "동기화 오류" : "동기화 정상"}</div>
            <div style={{ fontSize: 12, color: "#888", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{pollStatus ?? "준비 중…"}</div>
          </div>
        </div>
        <button onClick={() => void openSyncFolder()} style={{ whiteSpace: "nowrap" }}>📂 동기화 폴더 열기</button>
      </div>
      </main>
    </>
  )
}

export default App
