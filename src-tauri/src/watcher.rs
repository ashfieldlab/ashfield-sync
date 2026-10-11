//! 로컬 변경 감지 (F1).
//!
//! sync 폴더를 파일시스템 watcher 로 감시 → 사용자 변경을 JS 로 emit.
//! F1 은 감지/보고만. 실제 업로드는 F2.
//!
//! 핵심 난관: "누가 바꿨나" 구별:
//!   - 우리가 hydrate 로 쓴 것  → 무시 (안 그러면 업로드 무한루프)
//!   - placeholder 메타만 (내용 0) → 무시
//!   - 사용자가 hydrate 된 파일 수정/신규/삭제 → emit
//!
//! hydrate 자기변경 회피: vfs 가 hydrate 직전 경로를 SELF_WRITES 에 등록 →
//! 그 경로 이벤트는 잠깐 무시. (단순, 견고. 더 정밀히는 Cloud Files API 의
//! placeholder 상태 비트를 보지만 Phase 2 후반 과제.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use notify::{RecursiveMode, Watcher};
use notify_debouncer_full::new_debouncer;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

// hydrate 등 "우리가 쓰는 중" 인 경로 → 만료 시각. 그 경로 이벤트는 무시.
// 키는 정규화 문자열: Windows 의 `\\?\` verbatim 접두와 대소문자 차이로 매치가
// 빗나가면 억제가 통째로 실패하므로(에코 업로드) norm() 으로 통일한다.
static SELF_WRITES: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

// hydration 진행 중 상한: 완료 훅(self_write_end)이 유실돼도 이 시간 뒤엔 억제
// 해제(스톨, 크래시 시 무한 억제 방지).
const HYDRATE_MAX: Duration = Duration::from_secs(300);
// 완료 후 유예: 마지막 쓰기의 500ms 디바운스 + 지연 이벤트 흡수.
const SELF_WRITE_GRACE: Duration = Duration::from_secs(3);

/// 경로 정규화: `\\?\` verbatim 접두 제거 + 소문자화(Windows 는 대소문자 무시 FS).
fn norm(path: &Path) -> String {
    let s = path.to_string_lossy();
    fold_case(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

/// 경로 비교용 대소문자 접기: Windows 만. Linux 는 대소문자를 구분한다.
pub fn fold_case(s: &str) -> String {
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// 빠른 self-write(placeholder 생성, 삭제, rename 등): 이후 몇 초간 그 경로 무시.
pub fn mark_self_write(path: &Path) {
    let mut guard = SELF_WRITES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(norm(path), Instant::now() + Duration::from_secs(10));
}

/// hydration 쓰기 시작 직전 호출: 완료(self_write_end)까지 길게 억제.
/// 다운로드가 10초 넘게 걸려도(대용량, 느린 회선) 완료 이벤트가 새지 않게 한다.
pub fn self_write_begin(path: &Path) {
    let mut guard = SELF_WRITES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(norm(path), Instant::now() + HYDRATE_MAX);
}

/// hydration 완료(성공/실패 무관) 후 호출: 유예 시간만 남기고 곧 만료.
pub fn self_write_end(path: &Path) {
    let mut guard = SELF_WRITES.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        map.insert(norm(path), Instant::now() + SELF_WRITE_GRACE);
    }
}

/// 편집기와 OS 가 만드는 임시/잠금 파일: sync 대상 아님.
fn is_ignored(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.starts_with("~$")                    // Office 잠금 파일
        || name.starts_with(".~lock.")        // LibreOffice
        || name.ends_with(".tmp")
        || name.ends_with(".swp")             // vim
        || name.ends_with(".crdownload")      // 브라우저 다운로드 중
        || name.ends_with(".part")            // 부분 다운로드
        || name == ".DS_Store"
        || name == "Thumbs.db"
}

fn is_self_write(path: &Path) -> bool {
    let mut guard = SELF_WRITES.lock().unwrap();
    let Some(map) = guard.as_mut() else {
        return false;
    };
    let now = Instant::now();
    map.retain(|_, expiry| *expiry > now); // 만료분 청소
    map.contains_key(&norm(path))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalChange {
    /// create | modify | delete | rename
    pub kind: String,
    pub path: String,
    /// rename 의 이전 경로 (있을 때만)
    pub old_path: Option<String>,
    pub is_dir: bool,
}

static WATCHER: Mutex<Option<Box<dyn std::any::Any + Send>>> = Mutex::new(None);

pub fn start(app: AppHandle, root: &str) -> Result<(), String> {
    use notify::event::{EventKind, ModifyKind, RenameMode};
    use notify_debouncer_full::DebouncedEvent;

    let root_path = PathBuf::from(root);
    if !root_path.exists() {
        return Err(format!("watch 대상 폴더 없음: {root}"));
    }

    let app_for_cb = app.clone();
    // 500ms 디바운스: 편집기가 한 저장에 여러 write 이벤트를 내는 것을 묶음
    let mut debouncer = new_debouncer(
        Duration::from_millis(500),
        None,
        move |result: Result<Vec<DebouncedEvent>, Vec<notify::Error>>| {
            let Ok(events) = result else { return };
            for ev in events {
                let kind = match ev.event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => "rename",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                // rename(Both) 은 paths = [from, to]
                let (path, old_path) = if kind == "rename" && ev.event.paths.len() >= 2 {
                    (
                        ev.event.paths[1].clone(),
                        Some(ev.event.paths[0].clone()),
                    )
                } else {
                    match ev.event.paths.first() {
                        Some(p) => (p.clone(), None),
                        None => continue,
                    }
                };

                if is_self_write(&path) {
                    continue; // 우리가 hydrate 로 쓴 것: 무시
                }
                if is_ignored(&path) {
                    continue; // 편집기 임시파일 등
                }

                let is_dir = path.is_dir();
                // 폴더의 modify 는 자식 변경의 부수효과 (mtime 갱신): 업로드 대상 아님.
                // 폴더는 create/delete/rename 만 의미 있음.
                if is_dir && kind == "modify" {
                    continue;
                }

                let change = LocalChange {
                    kind: kind.to_string(),
                    path: path.to_string_lossy().to_string(),
                    old_path: old_path.map(|p| p.to_string_lossy().to_string()),
                    is_dir,
                };
                let _ = app_for_cb.emit("local-change", change);
            }
        },
    )
    .map_err(|e| format!("debouncer 생성 실패: {e}"))?;

    debouncer
        .watcher()
        .watch(&root_path, RecursiveMode::Recursive)
        .map_err(|e| format!("watch 실패: {e}"))?;

    // debouncer 를 살려둠 (drop 되면 감시 중단)
    *WATCHER.lock().unwrap() = Some(Box::new(debouncer));
    Ok(())
}

pub fn stop() {
    *WATCHER.lock().unwrap() = None; // drop → 감시 중단
}

#[tauri::command]
pub fn watcher_start(app: AppHandle, root: String) -> Result<(), String> {
    start(app, &root)
}

#[tauri::command]
pub fn watcher_stop() {
    stop()
}
