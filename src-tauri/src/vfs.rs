//! Windows Cloud Files API (Files On-Demand VFS).
//!
//! E1: sync root 등록/해제 — 폴더를 OS 의 "cloud provider 영역" 으로.
//! E2+: placeholder 생성, hydration callback (후속 chunk).
//!
//! Windows 전용 — 다른 OS 에선 stub 이 명시적 에러 반환.
//! 참고: Microsoft CloudMirror sample + ADR-0015.

use serde::Deserialize;

/// JS 가 보내는 placeholder 파일 메타 — node tree 의 평탄화 결과.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceholderFile {
    /// base_dir 기준 상대 폴더 ("" = base 바로 아래, "a\\b" 등)
    pub relative_dir: String,
    pub name: String,
    /// backend node id — hydration callback 에서 어떤 파일인지 식별 (FileIdentity)
    pub node_id: String,
    /// 회사 ID — download-url 호출의 X-Active-Company-Id (FileIdentity 에 함께 인코딩)
    pub company_id: String,
    pub size: i64,
    /// epoch millis (UTC) — updated_at
    pub mtime_ms: i64,
}

/// hydration 이 backend 를 부를 때 쓰는 설정 — vfs_connect 가 주입.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectConfig {
    pub api_url: String,
}

#[cfg(windows)]
mod imp {
    use std::sync::{Mutex, OnceLock};

    use windows::core::{GUID, HSTRING, PCWSTR};
    use windows::Win32::Foundation::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
    use windows::Win32::Storage::CloudFilters::{
        CfConnectSyncRoot, CfCreatePlaceholders, CfDisconnectSyncRoot, CfExecute,
        CfRegisterSyncRoot, CfUnregisterSyncRoot, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
        CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_FETCH_DATA, CF_CALLBACK_TYPE_NONE,
        CF_CONNECTION_KEY, CF_CONNECT_FLAG_NONE, CF_CREATE_FLAG_NONE, CF_HYDRATION_POLICY,
        CF_HYDRATION_POLICY_FULL, CF_HYDRATION_POLICY_MODIFIER_NONE, CF_OPERATION_INFO,
        CF_OPERATION_PARAMETERS, CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CF_OPERATION_TYPE_TRANSFER_DATA, CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        CF_PLACEHOLDER_CREATE_INFO, CF_POPULATION_POLICY, CF_POPULATION_POLICY_ALWAYS_FULL,
        CF_POPULATION_POLICY_MODIFIER_NONE, CF_REGISTER_FLAG_NONE, CF_SYNC_POLICIES,
        CF_SYNC_REGISTRATION,
    };
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

    use super::{ConnectConfig, PlaceholderFile};

    // ---------------------------------------------------------------------
    // Hydration 컨텍스트 — callback (OS 스레드) 이 backend 호출에 필요한 것들.
    // OnceLock: 첫 connect 시 설정. access_token 은 oauth 모듈의 공용 캐시에서 받는다
    // (refresh_token 회전 — VFS 가 따로 refresh 하면 JS/SSE 와 경쟁해 패밀리가 폐기된다).
    // ---------------------------------------------------------------------
    struct HydrationCtx {
        config: ConnectConfig,
    }

    static CTX: OnceLock<HydrationCtx> = OnceLock::new();
    static CONNECTION: Mutex<Option<i64>> = Mutex::new(None);

    // E2E vault 파일 복호화용 DEK (ADR-0016 V5b). node_id → raw 32B AES-256 키.
    // JS 가 잠금해제 시 wrapped_dek 을 풀어 raw 로 밀어넣음(vfs_set_deks). 잠김/
    // 로그아웃 시 비움. hydrate 콜백(OS 스레드)은 JS 를 await 할 수 없으므로 사전
    // 적재 필수. 키 존재 = 그 파일은 복호화 대상.
    static DEKS: Mutex<Option<std::collections::HashMap<String, Vec<u8>>>> = Mutex::new(None);

    pub fn set_deks(map: std::collections::HashMap<String, Vec<u8>>) {
        *DEKS.lock().unwrap() = Some(map);
    }

    fn dek_for(node_id: &str) -> Option<Vec<u8>> {
        DEKS.lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(node_id).cloned())
    }

    /// whole-file AES-256-GCM 복호화. 입력 = [iv(12)][ciphertext][tag(16)]
    /// (웹 crypto.ts aesEncrypt 출력의 raw 바이트). 출력 = 평문.
    fn aes_gcm_decrypt(dek: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        if dek.len() != 32 {
            return Err(format!("DEK 길이 오류: {}", dek.len()));
        }
        if data.len() < 12 + 16 {
            return Err(format!("암호문 너무 짧음: {}B", data.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(dek);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&data[..12]); // iv
        // data[12..] = ciphertext || tag — aes-gcm 의 detached-less decrypt 입력
        cipher
            .decrypt(nonce, &data[12..])
            .map_err(|_| "AES-GCM 복호화 실패 (tag 불일치 — 키/내용 무결성)".to_string())
    }

    #[derive(serde::Deserialize)]
    struct DownloadUrlRes {
        url: String,
    }

    /// 유효한 access token (blocking — worker 스레드 전용). refresh 는 oauth 모듈이 직렬화.
    fn get_access_token(stale: Option<&str>) -> Result<String, String> {
        crate::oauth::access_token_blocking(stale)
    }

    // ---------------------------------------------------------------------
    // FETCH_DATA callback — OS 가 placeholder 첫 접근 시 호출.
    // 즉시 반환해야 하므로 다운로드는 worker 스레드에서.
    // ---------------------------------------------------------------------
    unsafe extern "system" fn on_fetch_data(
        info: *const CF_CALLBACK_INFO,
        _params: *const CF_CALLBACK_PARAMETERS,
    ) {
        let info = &*info;
        let identity = std::slice::from_raw_parts(
            info.FileIdentity as *const u8,
            info.FileIdentityLength as usize,
        )
        .to_vec();
        let connection_key = info.ConnectionKey;
        let transfer_key = info.TransferKey;
        let request_key = info.RequestKey;
        let file_size = info.FileSize;

        // hydrate 는 CfExecute 로 파일에 내용을 쓴다 → watcher 가 modify 로 잡음.
        // 그 경로를 self-write 로 등록해 업로드 무한루프를 막는다.
        // PCWSTR deref 는 null 이면 access violation — 반드시 가드.
        let read_pcwstr = |p: windows::core::PCWSTR| -> String {
            if p.is_null() {
                String::new()
            } else {
                // SAFETY: Win32 가 null-terminate 보장. null 만 위에서 걸렀음.
                p.to_string().unwrap_or_default()
            }
        };
        let full_path = format!(
            "{}{}",
            read_pcwstr(info.VolumeDosName),
            read_pcwstr(info.NormalizedPath)
        );
        if !full_path.is_empty() {
            crate::watcher::self_write_begin(std::path::Path::new(&full_path));
        }

        let log_path = full_path.clone();
        std::thread::spawn(move || {
            let result =
                hydrate(identity, connection_key, transfer_key, request_key, file_size);
            // 완료(성공/실패 무관) — 유예만 남기고 self-write 억제 해제.
            // 다운로드가 오래 걸려도 그 사이 쓰기 이벤트는 begin~end 로 계속 무시됨.
            if !log_path.is_empty() {
                crate::watcher::self_write_end(std::path::Path::new(&log_path));
            }
            if let Err(e) = result {
                eprintln!("[vfs] hydrate 실패 [{log_path}]: {e}");
                // 실패 통지 — OS 가 응용에 에러 반환, 탐색기 hang 방지
                transfer_error(connection_key, transfer_key, request_key, file_size);
            }
        });
    }

    fn transfer_chunk(
        connection_key: CF_CONNECTION_KEY,
        transfer_key: i64,
        request_key: i64,
        buf: &[u8],
        offset: i64,
        ok: bool,
    ) -> Result<(), String> {
        let op_info = CF_OPERATION_INFO {
            StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
            Type: CF_OPERATION_TYPE_TRANSFER_DATA,
            ConnectionKey: connection_key,
            TransferKey: transfer_key,
            CorrelationVector: std::ptr::null(),
            SyncStatus: std::ptr::null(),
            RequestKey: request_key,
        };
        let mut op_params = CF_OPERATION_PARAMETERS::default();
        op_params.ParamSize = std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32;
        unsafe {
            op_params.Anonymous.TransferData.CompletionStatus =
                if ok { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL };
            op_params.Anonymous.TransferData.Buffer = if buf.is_empty() {
                std::ptr::null()
            } else {
                buf.as_ptr() as *const _
            };
            op_params.Anonymous.TransferData.Offset = offset;
            op_params.Anonymous.TransferData.Length = buf.len() as i64;
            op_params.Anonymous.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
            CfExecute(&op_info, &mut op_params).map_err(|e| format!("CfExecute: {e}"))
        }
    }

    fn transfer_error(
        connection_key: CF_CONNECTION_KEY,
        transfer_key: i64,
        request_key: i64,
        file_size: i64,
    ) {
        // 에러 통지 — Length 는 전체 요청 범위
        let op_info = CF_OPERATION_INFO {
            StructSize: std::mem::size_of::<CF_OPERATION_INFO>() as u32,
            Type: CF_OPERATION_TYPE_TRANSFER_DATA,
            ConnectionKey: connection_key,
            TransferKey: transfer_key,
            CorrelationVector: std::ptr::null(),
            SyncStatus: std::ptr::null(),
            RequestKey: request_key,
        };
        let mut op_params = CF_OPERATION_PARAMETERS::default();
        op_params.ParamSize = std::mem::size_of::<CF_OPERATION_PARAMETERS>() as u32;
        unsafe {
            op_params.Anonymous.TransferData.CompletionStatus = STATUS_UNSUCCESSFUL;
            op_params.Anonymous.TransferData.Buffer = std::ptr::null();
            op_params.Anonymous.TransferData.Offset = 0;
            op_params.Anonymous.TransferData.Length = file_size;
            op_params.Anonymous.TransferData.Flags = CF_OPERATION_TRANSFER_DATA_FLAG_NONE;
            let _ = CfExecute(&op_info, &mut op_params);
        }
    }

    /// 다운로드 + OS 로 전달. 1MB 단위 스트리밍 — 큰 파일도 메모리 안 부풂.
    fn hydrate(
        identity: Vec<u8>,
        connection_key: CF_CONNECTION_KEY,
        transfer_key: i64,
        request_key: i64,
        _file_size: i64,
    ) -> Result<(), String> {
        let ctx = CTX.get().ok_or("vfs_connect 안 됨")?;
        let identity = String::from_utf8(identity).map_err(|_| "identity utf8 아님")?;
        let (company, node_id) = identity
            .split_once('\n')
            .ok_or("identity 형식 오류 (재 populate 필요 — 옛 placeholder)")?;

        let client = reqwest::blocking::Client::new();

        // 1. presigned URL — 401 이면 토큰 갱신 후 한 번 재시도
        let download_url = |token: &str| {
            client
                .post(format!(
                    "{}/api/v1/nodes/{}/download-url",
                    ctx.config.api_url, node_id
                ))
                .bearer_auth(token)
                .header("X-Active-Company-Id", urlencoding::encode(company).as_ref())
                .send()
                .map_err(|e| format!("download-url POST: {e}"))
        };
        let token = get_access_token(None)?;
        let mut res = download_url(&token)?;
        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            let token = get_access_token(Some(&token))?;
            res = download_url(&token)?;
        }
        if !res.status().is_success() {
            return Err(format!("download-url {}", res.status()));
        }
        let dl: DownloadUrlRes = res.json().map_err(|e| format!("parse: {e}"))?;

        // 2. S3 GET
        let mut resp = client
            .get(&dl.url)
            .send()
            .map_err(|e| format!("S3 GET: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("S3 {}", resp.status()));
        }

        const CHUNK: usize = 1024 * 1024; // 4KB 정렬 배수 필수 (마지막 chunk 제외)

        // 2-E. E2E vault 파일 — whole-file AES-GCM 은 부분 복호화 불가.
        // 전체 암호문을 메모리에 받아 한 번에 복호화 후, 평문을 1MB 단위 전달.
        // placeholder FileSize 는 평문 크기(size_bytes-28)로 만들어 둠 → 길이 일치.
        if let Some(dek) = dek_for(node_id) {
            let body = resp.bytes().map_err(|e| format!("S3 body: {e}"))?;
            let plain = aes_gcm_decrypt(&dek, &body)?;
            let mut offset = 0usize;
            if plain.is_empty() {
                // 0바이트 평문 — 빈 전송으로 완료 통지
                transfer_chunk(connection_key, transfer_key, request_key, &[], 0, true)?;
            }
            while offset < plain.len() {
                let end = (offset + CHUNK).min(plain.len());
                transfer_chunk(
                    connection_key,
                    transfer_key,
                    request_key,
                    &plain[offset..end],
                    offset as i64,
                    true,
                )?;
                offset = end;
            }
            return Ok(());
        }

        // 2-N. 일반(비암호화) 파일 — 스트리밍 1MB 단위 CfExecute
        use std::io::Read;
        let mut buf = vec![0u8; CHUNK];
        let mut filled = 0usize;
        let mut offset: i64 = 0;
        loop {
            let n = resp
                .read(&mut buf[filled..])
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                if filled > 0 {
                    transfer_chunk(connection_key, transfer_key, request_key, &buf[..filled], offset, true)?;
                } else if offset == 0 {
                    // 0바이트 파일 — 아무것도 전송 안 하면 placeholder 가 dehydrated(x)로
                    // 남는다. 빈 전송으로 완료 통지 (vault 0바이트 경로와 동일).
                    transfer_chunk(connection_key, transfer_key, request_key, &[], 0, true)?;
                }
                break;
            }
            filled += n;
            if filled == CHUNK {
                transfer_chunk(connection_key, transfer_key, request_key, &buf, offset, true)?;
                offset += CHUNK as i64;
                filled = 0;
            }
        }
        Ok(())
    }

    // FETCH_DATA 만 등록 — 테이블은 connect 동안 유효해야 하므로 static.
    static CALLBACK_TABLE: [CF_CALLBACK_REGISTRATION; 2] = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(on_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NONE,
            Callback: None,
        },
    ];

    pub fn connect(sync_root: &str, config: ConnectConfig) -> Result<(), String> {
        // 이미 이 프로세스가 연결돼 있으면 멱등 — 재연결 안 함 (dev HMR 재호출).
        // 같은 프로세스라 callback 테이블도 동일하므로 hydration 정상.
        if CONNECTION.lock().unwrap().is_some() {
            return Ok(());
        }
        let _ = CTX.set(HydrationCtx { config });
        let path = HSTRING::from(sync_root);
        let result = unsafe {
            CfConnectSyncRoot(
                PCWSTR(path.as_ptr()),
                CALLBACK_TABLE.as_ptr(),
                None,
                CF_CONNECT_FLAG_NONE,
            )
        };
        match result {
            Ok(key) => {
                *CONNECTION.lock().unwrap() = Some(key.0);
                Ok(())
            }
            // 0x8007017A = 이미 다른(이전 프로세스) 연결이 살아있음. 우리 callback
            // 으로는 못 잡지만 재연결 불가 — 일단 통과시키고 다음 재시작에서 정리.
            Err(e) if e.code().0 as u32 == 0x8007_017A => {
                eprintln!("[vfs] sync root 이미 연결됨 (이전 세션 잔존) — 통과");
                Ok(())
            }
            Err(e) => Err(format!("CfConnectSyncRoot 실패: {e}")),
        }
    }

    pub fn disconnect() -> Result<(), String> {
        if let Some(raw) = CONNECTION.lock().unwrap().take() {
            unsafe { CfDisconnectSyncRoot(CF_CONNECTION_KEY(raw)) }
                .map_err(|e| format!("CfDisconnectSyncRoot 실패: {e}"))?;
        }
        Ok(())
    }

    // Provider 식별자 — 한 번 정하면 불변 (재설치 후에도 같은 sync root 인식).
    // uuidgen 으로 생성한 고정값.
    const PROVIDER_ID: GUID = GUID::from_u128(0x6f1a5c7e_3b2d_4e8a_9c0f_d41b82a7e519);

    pub fn register(sync_root: &str) -> Result<(), String> {
        std::fs::create_dir_all(sync_root)
            .map_err(|e| format!("sync 폴더 생성 실패: {e}"))?;

        let provider_name = HSTRING::from("Ashfield Sync");
        let provider_version = HSTRING::from(env!("CARGO_PKG_VERSION"));
        let path = HSTRING::from(sync_root);

        let registration = CF_SYNC_REGISTRATION {
            StructSize: std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: PCWSTR(provider_name.as_ptr()),
            ProviderVersion: PCWSTR(provider_version.as_ptr()),
            ProviderId: PROVIDER_ID,
            ..Default::default()
        };

        let policies = CF_SYNC_POLICIES {
            StructSize: std::mem::size_of::<CF_SYNC_POLICIES>() as u32,
            // 첫 접근 시 파일 전체 다운로드 (스트리밍 부분 hydrate 는 추후)
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_FULL,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
            },
            // placeholder 는 전부 우리가 만들어 둠 (OS 가 탐색 시점 요청 안 함)
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_ALWAYS_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            ..Default::default()
        };

        unsafe {
            CfRegisterSyncRoot(
                PCWSTR(path.as_ptr()),
                &registration,
                &policies,
                CF_REGISTER_FLAG_NONE,
            )
        }
        .map_err(|e| format!("CfRegisterSyncRoot 실패: {e}"))
    }

    pub fn unregister(sync_root: &str) -> Result<(), String> {
        // CfUnregisterSyncRoot 는 경로 실존 필수 (없으면 0x80070002) — 폴더가
        // 먼저 지워졌어도 등록 해제는 가능해야 하므로 임시 재생성.
        std::fs::create_dir_all(sync_root).ok();
        let path = HSTRING::from(sync_root);
        unsafe { CfUnregisterSyncRoot(PCWSTR(path.as_ptr())) }
            .map_err(|e| format!("CfUnregisterSyncRoot 실패: {e}"))
    }

    /// epoch millis → Windows FILETIME (100ns 단위, 1601-01-01 기준)
    fn filetime(ms: i64) -> i64 {
        ms * 10_000 + 116_444_736_000_000_000
    }

    pub fn populate(
        base_dir: &str,
        dirs: &[String],
        files: &[PlaceholderFile],
    ) -> Result<u32, String> {
        // 0. base_dir 자체 — 회사/영역 폴더. 루트 바로 아래 파일만 있으면
        //    dirs 가 비어서 이 폴더가 안 만들어지는 사고 (0x80070003)
        crate::watcher::mark_self_write(std::path::Path::new(base_dir));
        std::fs::create_dir_all(base_dir)
            .map_err(|e| format!("base 폴더 생성 실패 {base_dir}: {e}"))?;

        // 1. 폴더는 일반 디렉토리로 (placeholder 디렉토리는 Phase 2 검토).
        //    self-write 등록 필수 — 안 그러면 watcher 가 우리 폴더 생성을 사용자
        //    생성으로 오인해 서버에 또 올리고 → 이름 충돌 "(2)","(3)"... 무한 증식.
        for d in dirs {
            let dir_path = std::path::Path::new(base_dir).join(d)
;
            crate::watcher::mark_self_write(&dir_path);
            std::fs::create_dir_all(&dir_path)
                .map_err(|e| format!("폴더 생성 실패 {d}: {e}"))?;
        }

        // 2. 파일 placeholder — 같은 부모 폴더끼리 묶어 CfCreatePlaceholders 호출
        use std::collections::HashMap;
        let mut by_dir: HashMap<&str, Vec<&PlaceholderFile>> = HashMap::new()
;
        for f in files {
            // 이미 디스크에 있으면 skip — 재실행 idempotent
            let full = std::path::Path::new(base_dir)
                .join(&f.relative_dir)
                .join(&f.name);
            if full.exists() {
                continue;
            }
            // placeholder 생성도 watcher 가 create 로 잡음 → 사용자 신규로 오인 방지
            crate::watcher::mark_self_write(&full);
            by_dir.entry(f.relative_dir.as_str()).or_default().push(f);
        }

        let mut created: u32 = 0;
        for (rel_dir, group) in by_dir {
            let parent = std::path::Path::new(base_dir).join(rel_dir);
            let parent_h = HSTRING::from(parent.to_string_lossy().as_ref());

            // wide string / identity 버퍼는 CfCreatePlaceholders 호출까지 살아있어야 함
            let names: Vec<HSTRING> = group.iter().map(|f| HSTRING::from(f.name.as_str())).collect();
            // FileIdentity = "회사ID\n노드ID" — hydration 의 download-url 호출에 둘 다 필요
            let identities: Vec<String> = group
                .iter()
                .map(|f| format!("{}\n{}", f.company_id, f.node_id))
                .collect();

            let mut entries: Vec<CF_PLACEHOLDER_CREATE_INFO> = group
                .iter()
                .zip(names.iter())
                .zip(identities.iter())
                .map(|((f, name), identity)| {
                    let mut info = CF_PLACEHOLDER_CREATE_INFO::default();
                    info.RelativeFileName = PCWSTR(name.as_ptr());
                    info.FileIdentity = identity.as_ptr() as *const _;
                    info.FileIdentityLength = identity.len() as u32;
                    info.FsMetadata.FileSize = f.size;
                    info.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL.0;
                    info.FsMetadata.BasicInfo.CreationTime = filetime(f.mtime_ms);
                    info.FsMetadata.BasicInfo.LastWriteTime = filetime(f.mtime_ms);
                    info.FsMetadata.BasicInfo.LastAccessTime = filetime(f.mtime_ms);
                    info.FsMetadata.BasicInfo.ChangeTime = filetime(f.mtime_ms);
                    info.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
                    info
                })
                .collect();

            let mut processed: u32 = 0;
            unsafe {
                CfCreatePlaceholders(
                    PCWSTR(parent_h.as_ptr()),
                    &mut entries,
                    CF_CREATE_FLAG_NONE,
                    Some(&mut processed as *mut u32),
                )
            }
            .map_err(|e| format!("CfCreatePlaceholders 실패 ({rel_dir}): {e}"))?;
            created += processed;
        }
        Ok(created)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{ConnectConfig, PlaceholderFile};

    pub fn register(_sync_root: &str) -> Result<(), String> {
        Err("Cloud Files API 는 Windows 전용".into())
    }
    pub fn unregister(_sync_root: &str) -> Result<(), String> {
        Err("Cloud Files API 는 Windows 전용".into())
    }
    pub fn populate(
        _base_dir: &str,
        _dirs: &[String],
        _files: &[PlaceholderFile],
    ) -> Result<u32, String> {
        Err("Cloud Files API 는 Windows 전용".into())
    }
    pub fn connect(_sync_root: &str, _config: ConnectConfig) -> Result<(), String> {
        Err("Cloud Files API 는 Windows 전용".into())
    }
    pub fn disconnect() -> Result<(), String> {
        Err("Cloud Files API 는 Windows 전용".into())
    }
    pub fn set_deks(_map: std::collections::HashMap<String, Vec<u8>>) {}
}

#[tauri::command]
pub fn vfs_register(sync_root: String) -> Result<(), String> {
    imp::register(&sync_root)
}

#[tauri::command]
pub fn vfs_unregister(sync_root: String) -> Result<(), String> {
    imp::unregister(&sync_root)
}

#[tauri::command]
pub fn vfs_populate(
    base_dir: String,
    dirs: Vec<String>,
    files: Vec<PlaceholderFile>,
) -> Result<u32, String> {
    imp::populate(&base_dir, &dirs, &files)
}

/// E2E vault DEK 등록 (ADR-0016 V5b). deks: node_id → base64(raw 32B AES 키).
/// JS 가 잠금해제 시 wrapped_dek 을 vault_key 로 풀어 raw 로 보냄. 매 호출이
/// 맵 전체를 교체 — 잠김/로그아웃 시 빈 맵을 보내 폐기. hydrate 콜백이 사전
/// 적재된 키로 즉시 복호화하도록 함.
#[tauri::command]
pub fn vfs_set_deks(deks: std::collections::HashMap<String, String>) -> Result<(), String> {
    use base64::Engine;
    let mut map = std::collections::HashMap::with_capacity(deks.len());
    for (node_id, b64) in deks {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| format!("dek base64 ({node_id}): {e}"))?;
        map.insert(node_id, raw);
    }
    imp::set_deks(map);
    Ok(())
}

/// E2E vault 업로드용 암호화 (ADR-0016 V5c). src 평문을 raw DEK(base64) 로
/// whole-file AES-256-GCM 암호화해 OS temp 에 [iv(12)][ct][tag(16)] 로 쓰고
/// 그 경로를 반환. (웹 crypto.ts aesEncrypt 와 동일 포맷.) 이후 기존 업로드
/// 머신(vfs_put_file / vfs_put_file_part)이 이 temp 를 그대로 올린다.
/// 호출측이 업로드 후 vfs_delete 로 temp 정리. 플랫폼 무관(파일IO+crypto).
#[tauri::command]
pub fn vfs_encrypt_to_temp(src: String, dek: String) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use base64::Engine;
    use rand::RngCore;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(dek.as_bytes())
        .map_err(|e| format!("dek base64: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("DEK 길이 오류: {}", raw.len()));
    }
    let plain = std::fs::read(&src).map_err(|e| format!("읽기 {src}: {e}"))?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw));
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_ref())
        .map_err(|_| "AES-GCM 암호화 실패".to_string())?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct); // ct = ciphertext || tag

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("ashfieldvault-{:016x}.bin", rand::random::<u64>()));
    std::fs::write(&tmp, &out).map_err(|e| format!("temp 쓰기: {e}"))?;
    Ok(tmp.to_string_lossy().into_owned())
}

/// 회사 폴더 통째 제거 — sync 제외 toggle 시. 없으면 무시.
#[tauri::command]
pub fn vfs_remove_dir(path: String) -> Result<(), String> {
    // 우리(reconcile) 의 삭제 — watcher 가 delete 로 잡아 서버 삭제로 되돌리지
    // 않도록 self-write 등록.
    crate::watcher::mark_self_write(std::path::Path::new(&path));
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("폴더 제거 실패 {path}: {e}")),
    }
}

/// dir 안에서 allowed 에 없는 항목 전부 제거 (재귀). desired 상태로 강제 수렴.
/// vault 폴더 한정 사용 — 재시작/이름변경/잠금토글로 남은 잔재 placeholder 정리.
/// allowed 에는 살릴 파일+중간 폴더 경로가 모두 들어와야 함 (소문자 비교).
#[tauri::command]
pub fn vfs_prune(dir: String, allowed: Vec<String>) -> Result<u32, String> {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    let root = Path::new(&dir);
    if !root.exists() {
        return Ok(0);
    }
    let allow: HashSet<String> = allowed.iter().map(|p| p.to_lowercase()).collect();

    // allowed 에 없는 경로 수집 (제거 대상). allowed 인 폴더는 안으로 재귀.
    fn walk(d: &Path, allow: &HashSet<String>, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(d) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let key = p.to_string_lossy().to_lowercase();
            if allow.contains(&key) {
                if p.is_dir() {
                    walk(&p, allow, out); // 살릴 폴더 — 안쪽 계속 검사
                }
            } else {
                out.push(p); // 제거 대상 (폴더면 통째)
            }
        }
    }
    let mut victims: Vec<PathBuf> = Vec::new();
    walk(root, &allow, &mut victims);

    let mut removed = 0u32;
    for p in &victims {
        crate::watcher::mark_self_write(p);
        let r = if p.is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
        if r.is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// 로컬 파일 삭제 (placeholder 든 hydrate 된 파일이든 일반 삭제로 동작).
/// 없는 파일은 무시 — polling diff 가 중복 호출해도 안전.
/// 우리의 reconcile 삭제이므로 self-write 등록 — watcher 가 잡아 서버 삭제로
/// 되돌리는 사고 방지 (서버→로컬 삭제가 로컬→서버 삭제로 바운스).
#[tauri::command]
pub fn vfs_delete(paths: Vec<String>) -> Result<u32, String> {
    let mut removed = 0u32;
    for p in &paths {
        crate::watcher::mark_self_write(std::path::Path::new(p));
        match std::fs::remove_file(p) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("삭제 실패 {p}: {e}")),
        }
    }
    Ok(removed)
}

/// 충돌 사본 생성 — 412(동시 수정) 시 로컬 버전을 별도 파일로 보존.
/// `foo.docx` → `foo (충돌본 {date} {hostname}).docx`. self-write 등록 후 복사
/// (watcher 의 create 무시 — JS 가 명시적으로 업로드). 생성 경로 반환.
#[tauri::command]
pub fn vfs_make_conflict_copy(path: String, date: String) -> Result<String, String> {
    let src = std::path::Path::new(&path);
    let parent = src.parent().ok_or("parent 없음")?;
    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("file stem 없음")?;
    let ext = src.extension().and_then(|s| s.to_str());
    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into());
    let new_name = match ext {
        Some(e) => format!("{stem} (충돌본 {date} {host}).{e}"),
        None => format!("{stem} (충돌본 {date} {host})"),
    };
    let dst = parent.join(&new_name);
    crate::watcher::mark_self_write(&dst);
    std::fs::copy(src, &dst).map_err(|e| format!("충돌 사본 복사 실패: {e}"))?;
    Ok(dst.to_string_lossy().to_string())
}

#[tauri::command]
pub fn vfs_connect(sync_root: String, config: ConnectConfig) -> Result<(), String> {
    imp::connect(&sync_root, config)
}

#[tauri::command]
pub fn vfs_disconnect() -> Result<(), String> {
    imp::disconnect()
}

/// 로컬 파일 메타데이터 — modify 이벤트가 진짜 내용 변경인지 판정용.
/// 내용을 읽지 않으므로 대용량(수십 GB)도 즉시, placeholder 도 하이드레이트 안 함.
///   - size/mtime 이 직전 동기화 값과 같으면 내용 불변 → 에코(ADS 변경 등) skip.
///   - dehydrated(placeholder) 면 로컬 편집이 불가능하므로 무조건 skip.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileStat {
    size: u64,
    mtime_ms: i64,
    dehydrated: bool,
}

#[cfg(windows)]
fn is_dehydrated(md: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // placeholder(내용 미다운): 원격 회수 대상 or offline 속성.
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    md.file_attributes() & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE) != 0
}

#[cfg(not(windows))]
fn is_dehydrated(_md: &std::fs::Metadata) -> bool {
    false
}

#[tauri::command]
pub fn vfs_file_stat(path: String) -> Result<FileStat, String> {
    // metadata()/attributes 는 placeholder 도 하이드레이트 없이 조회 가능.
    let md = std::fs::metadata(&path).map_err(|e| format!("stat {path}: {e}"))?;
    let mtime_ms = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Ok(FileStat {
        size: md.len(),
        mtime_ms,
        dehydrated: is_dehydrated(&md),
    })
}

/// 로컬 파일 크기 (upload-url 요청 전 size 산정).
#[tauri::command]
pub fn vfs_file_size(path: String) -> Result<u64, String> {
    std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("stat {path}: {e}"))
}

/// 로컬 파일을 presigned PUT URL 로 업로드 (F2, 단일 PUT — 50MB 미만).
/// content_type 미지정 (backend 가 mime=null 로 서명 → Content-Type 헤더 불요).
#[tauri::command]
pub async fn vfs_put_file(path: String, url: String) -> Result<(), String> {
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("read {path}: {e}"))?;
    let res = reqwest::Client::new()
        .put(&url)
        .body(bytes)
        .send()
        .await
        .map_err(|e| format!("PUT: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("S3 PUT {}", res.status()));
    }
    Ok(())
}

/// 대용량 업로드 (A) — 파일의 [offset, offset+length) 범위를 읽어 파트 PUT.
/// S3 가 응답 헤더로 준 ETag 반환 (complete-multipart 의 parts 에 필요).
#[tauri::command]
pub async fn vfs_put_file_part(
    path: String,
    url: String,
    offset: u64,
    length: u64,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(&path)
        .await
        .map_err(|e| format!("open {path}: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("seek: {e}"))?;
    let mut buf = vec![0u8; length as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("read part: {e}"))?;

    let res = reqwest::Client::new()
        .put(&url)
        .body(buf)
        .send()
        .await
        .map_err(|e| format!("part PUT: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("S3 part PUT {}", res.status()));
    }
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .ok_or("응답에 ETag 없음")?
        .to_string();
    Ok(etag)
}
